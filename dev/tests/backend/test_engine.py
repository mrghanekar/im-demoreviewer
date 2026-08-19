"""Tests for the check execution engine."""

import pytest

from backend.core.engine import CheckEngine
from backend.core.models import (
    CheckResult,
    CheckStatus,
    Category,
    Severity,
    ServiceCategory,
)
from backend.checks.base import BaseCheck


class MockPassingCheck(BaseCheck):
    """A mock check that always passes (no findings)."""
    id = "MOCK-PASS"
    title = "Mock Passing Check"
    description = "Always passes"
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "MOCK"
    service_category = ServiceCategory.SECURITY

    async def execute(self, project_id, gcloud_runner):
        return []


class MockFailingCheck(BaseCheck):
    """A mock check that always finds an issue."""
    id = "MOCK-FAIL"
    title = "Mock Failing Check"
    description = "Always fails"
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "MOCK"
    service_category = ServiceCategory.SECURITY

    async def execute(self, project_id, gcloud_runner):
        return [
            CheckResult(
                check_id=self.id,
                title=self.title,
                severity=self.severity,
                category=self.category,
                service=self.service,
                resource_name=f"projects/{project_id}/mock-resource",
                current_state="Bad state",
                recommended_state="Good state",
                fix_command="gcloud mock fix",
                project_id=project_id,
            )
        ]


class MockErrorCheck(BaseCheck):
    """A mock check that raises an exception."""
    id = "MOCK-ERR"
    title = "Mock Error Check"
    description = "Always errors"
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "MOCK"
    service_category = ServiceCategory.SECURITY

    async def execute(self, project_id, gcloud_runner):
        raise RuntimeError("Simulated check failure")


@pytest.mark.asyncio
class TestCheckEngine:
    """Tests for CheckEngine execution."""

    @pytest.fixture
    def engine(self, mock_gcloud_runner):
        return CheckEngine(
            gcloud_runner=mock_gcloud_runner,
            max_concurrent=5,
        )

    async def test_run_single_passing_check(self, engine):
        check = MockPassingCheck()
        from backend.core.models import CheckExecution
        execution = CheckExecution(
            check_id=check.id,
            check_title=check.title,
            service_category=check.service_category,
        )
        engine._scan_id = "test-scan"

        findings = await engine._run_single_check(check, "test-project", execution)

        assert len(findings) == 0
        assert execution.status == CheckStatus.PASSED

    async def test_run_single_failing_check(self, engine):
        check = MockFailingCheck()
        from backend.core.models import CheckExecution
        execution = CheckExecution(
            check_id=check.id,
            check_title=check.title,
            service_category=check.service_category,
        )
        engine._scan_id = "test-scan"

        findings = await engine._run_single_check(check, "test-project", execution)

        assert len(findings) == 1
        assert findings[0].check_id == "MOCK-FAIL"
        assert execution.status == CheckStatus.FAILED

    async def test_erroring_check_is_isolated(self, engine):
        check = MockErrorCheck()
        from backend.core.models import CheckExecution
        execution = CheckExecution(
            check_id=check.id,
            check_title=check.title,
            service_category=check.service_category,
        )
        engine._scan_id = "test-scan"

        findings = await engine._run_single_check(check, "test-project", execution)

        assert len(findings) == 0
        assert execution.status == CheckStatus.ERRORED
        assert "Simulated" in execution.error_message

    async def test_summary_computation(self, engine):
        from backend.core.models import Finding, CheckExecution

        findings = [
            Finding(
                id="f1", scan_id="s1", check_id="T1", title="T",
                severity=Severity.CRITICAL, category=Category.SECURITY,
                service="GCS", resource_name="r",
            ),
            Finding(
                id="f2", scan_id="s1", check_id="T2", title="T",
                severity=Severity.HIGH, category=Category.RELIABILITY,
                service="GKE", resource_name="r",
            ),
        ]

        executions = [
            CheckExecution(check_id="T1", check_title="T", service_category=ServiceCategory.GCS, status=CheckStatus.FAILED),
            CheckExecution(check_id="T2", check_title="T", service_category=ServiceCategory.GKE, status=CheckStatus.FAILED),
            CheckExecution(check_id="T3", check_title="T", service_category=ServiceCategory.IAM, status=CheckStatus.PASSED),
        ]

        summary = engine._compute_summary(findings, executions, 10.5)

        assert summary.total_findings == 2
        assert summary.by_severity["critical"] == 1
        assert summary.by_severity["high"] == 1
        assert summary.checks_passed == 1
        assert summary.checks_failed == 2
        assert summary.scan_duration_seconds == 10.5
