"""A check that couldn't read the project must not report the project clean.

Nearly every check body ends in `except Exception: return findings`, so a 403
on `projects get-iam-policy` used to surface as PASSED — the engine only ever
saw an empty list. The engine now watches the gcloud boundary directly and
refuses to record a pass the check didn't earn.
"""

import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from backend.checks.base import BaseCheck
from backend.core.engine import CheckEngine
from backend.core.exceptions import GcloudError, ServiceNotEnabledError
from backend.core.models import (
    Category,
    CheckExecution,
    CheckResult,
    CheckStatus,
    ServiceCategory,
    Severity,
)


def _denied(command="gcloud projects get-iam-policy p"):
    return GcloudError(
        command,
        1,
        "ERROR: (gcloud) PERMISSION_DENIED: Permission "
        "'resourcemanager.projects.getIamPolicy' denied on resource",
    )


class _SwallowingCheck(BaseCheck):
    """The prevailing shape across the catalog: catch everything, return []."""

    id = "MOCK-SWALLOW"
    title = "Swallows its own errors"
    description = "Representative of ~200 real checks"
    severity = Severity.CRITICAL
    category = Category.SECURITY
    service = "MOCK"
    service_category = ServiceCategory.IAM

    async def execute(self, project_id, gcloud_runner):
        findings = []
        try:
            await gcloud_runner.run("gcloud projects get-iam-policy p --format=json")
        except Exception:
            pass
        return findings


class _PartialCheck(BaseCheck):
    """Reads two resources; one succeeds, one is denied."""

    id = "MOCK-PARTIAL"
    title = "Partially blind"
    description = "Finds something but cannot see everything"
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "MOCK"
    service_category = ServiceCategory.IAM

    async def execute(self, project_id, gcloud_runner):
        findings = []
        for command in ("gcloud a", "gcloud b"):
            try:
                await gcloud_runner.run(command)
            except Exception:
                continue
            findings.append(CheckResult(
                check_id=self.id, title=self.title, severity=self.severity,
                category=self.category, service=self.service,
                resource_name="r", project_id=project_id,
                current_state="bad", recommended_state="good", fix_command="",
            ))
        return findings


class _NotFoundCheck(BaseCheck):
    """Probes speculatively; NOT_FOUND is an expected, meaningless outcome."""

    id = "MOCK-PROBE"
    title = "Speculative probe"
    description = "Walks locations that mostly hold nothing"
    severity = Severity.LOW
    category = Category.SECURITY
    service = "MOCK"
    service_category = ServiceCategory.SECURITY

    async def execute(self, project_id, gcloud_runner):
        try:
            await gcloud_runner.run("gcloud kms keyrings list --location=antarctica")
        except Exception:
            pass
        return []


def _execution(check):
    return CheckExecution(
        check_id=check.id,
        check_title=check.title,
        service_category=check.service_category,
    )


def _engine(run_side_effect):
    runner = MagicMock()
    runner.run = AsyncMock(side_effect=run_side_effect)
    engine = CheckEngine(gcloud_runner=runner, max_concurrent=2)
    engine._scan_id = "test-scan"
    # run_checks() normally stamps this; the storm window is measured from it.
    engine._scan_start_time = time.monotonic()
    return engine


@pytest.mark.asyncio
class TestPermissionDeniedIsNotAPass:
    async def test_swallowed_403_reports_errored(self):
        engine = _engine(_denied())
        check = _SwallowingCheck()
        execution = _execution(check)

        findings = await engine._run_single_check(check, "test-project", execution)

        assert findings == []
        assert execution.status == CheckStatus.ERRORED, (
            "a check that was denied read access reported the project clean"
        )
        assert "not a pass" in execution.error_message
        assert "PERMISSION_DENIED" in execution.error_message

    async def test_swallowed_403_feeds_the_storm_guard(self):
        """The 403-storm short-circuit was unreachable for swallowing checks."""
        engine = _engine(_denied())
        for _ in range(CheckEngine.PERMISSION_STORM_THRESHOLD):
            check = _SwallowingCheck()
            await engine._run_single_check(check, "test-project", _execution(check))

        assert engine._scan_aborted is True
        assert "no read permission" in engine._abort_reason

    async def test_successful_check_still_passes(self):
        engine = _engine(None)
        engine.gcloud_runner.run = AsyncMock(return_value={"bindings": []})
        check = _SwallowingCheck()
        execution = _execution(check)

        await engine._run_single_check(check, "test-project", execution)

        assert execution.status == CheckStatus.PASSED
        assert execution.error_message == ""

    async def test_partial_result_keeps_findings_but_flags_incompleteness(self):
        calls = {"n": 0}

        async def half_denied(command, *a, **kw):
            calls["n"] += 1
            if calls["n"] == 1:
                raise _denied(command)
            return {}

        engine = _engine(None)
        engine.gcloud_runner.run = AsyncMock(side_effect=half_denied)
        check = _PartialCheck()
        execution = _execution(check)

        findings = await engine._run_single_check(check, "test-project", execution)

        assert len(findings) == 1
        assert execution.status == CheckStatus.FAILED
        assert "Partial result" in execution.error_message

    async def test_speculative_not_found_does_not_escalate(self):
        """NOT_FOUND while probing is normal and proves nothing either way."""
        engine = _engine(GcloudError("gcloud kms keyrings list", 1, "NOT_FOUND: location"))
        check = _NotFoundCheck()
        execution = _execution(check)

        await engine._run_single_check(check, "test-project", execution)

        assert execution.status == CheckStatus.PASSED
        assert engine._permission_denied_count == 0


@pytest.mark.asyncio
class TestServiceNotEnabledIsSkipped:
    async def test_swallowed_service_disabled_reports_skipped(self):
        engine = _engine(ServiceNotEnabledError("cloudkms.googleapis.com"))
        check = _SwallowingCheck()
        execution = _execution(check)

        await engine._run_single_check(check, "test-project", execution)

        assert execution.status == CheckStatus.SKIPPED
        assert "cloudkms.googleapis.com" in execution.error_message

    async def test_disabled_api_does_not_count_toward_the_storm_guard(self):
        engine = _engine(ServiceNotEnabledError("cloudkms.googleapis.com"))
        for _ in range(CheckEngine.PERMISSION_STORM_THRESHOLD + 2):
            check = _SwallowingCheck()
            await engine._run_single_check(check, "test-project", _execution(check))

        assert engine._scan_aborted is False


@pytest.mark.asyncio
class TestRealCatalogChecks:
    """The mocks above model the pattern; these are the shipped checks."""

    @pytest.mark.parametrize(
        "check_path",
        [
            "backend.checks.iam.role_bindings:PrimitiveRolesInUse",
            "backend.checks.networking.network_checks:OpenFirewallSSH",
            "backend.checks.gcs.bucket_security:PublicBucket",
        ],
    )
    async def test_denied_catalog_check_does_not_report_passed(self, check_path):
        import importlib

        module_name, class_name = check_path.split(":")
        check = getattr(importlib.import_module(module_name), class_name)()

        engine = _engine(_denied())
        execution = _execution(check)

        findings = await engine._run_single_check(check, "test-project", execution)

        assert findings == []
        assert execution.status == CheckStatus.ERRORED, (
            f"{check.id} told the operator the project was clean after a 403"
        )


@pytest.mark.asyncio
class TestProbeTransparency:
    async def test_probe_forwards_arbitrary_runner_attributes(self):
        """Checks reach past .run() — the wrapper must not hide the runner."""
        from backend.core.engine import _RunnerProbe

        runner = MagicMock()
        runner.run = AsyncMock(return_value=[])
        runner.some_helper = "value"
        probe = _RunnerProbe(runner)

        assert probe.some_helper == "value"

    async def test_probe_passes_kwargs_through(self):
        from backend.core.engine import _RunnerProbe

        runner = MagicMock()
        runner.run = AsyncMock(return_value="raw")
        probe = _RunnerProbe(runner)

        result = await probe.run("gcloud x", parse_json=False)

        assert result == "raw"
        runner.run.assert_awaited_once_with("gcloud x", parse_json=False)
        assert probe.succeeded == 1
        assert probe.errors == []
