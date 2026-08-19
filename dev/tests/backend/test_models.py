"""Tests for core data models."""

import pytest
from backend.core.models import (
    CheckResult,
    ScanRequest,
    Severity,
    Category,
    ServiceCategory,
)


class TestScanRequest:
    """Tests for scan request validation."""

    def test_valid_project_request(self):
        req = ScanRequest(scope="project", target_id="my-project")
        assert req.scope == "project"
        assert req.target_id == "my-project"
        assert len(req.categories) == len(ServiceCategory)

    def test_valid_org_request(self):
        req = ScanRequest(scope="org", target_id="123456789")
        assert req.scope == "org"

    def test_invalid_scope_rejected(self):
        with pytest.raises(Exception):
            ScanRequest(scope="invalid", target_id="test")

    def test_empty_target_rejected(self):
        with pytest.raises(Exception):
            ScanRequest(scope="project", target_id="")

    def test_custom_categories(self):
        req = ScanRequest(
            scope="project",
            target_id="my-project",
            categories=[ServiceCategory.GKE, ServiceCategory.IAM],
        )
        assert len(req.categories) == 2


class TestCheckResult:
    """Tests for check result model."""

    def test_minimal_result(self):
        result = CheckResult(
            check_id="GCS-001",
            title="Test finding",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            service="GCS",
            resource_name="gs://bucket",
        )
        assert result.check_id == "GCS-001"
        assert result.fix_command == ""
        assert result.references == []

    def test_full_result(self, sample_check_result):
        assert sample_check_result.check_id == "GCS-001"
        assert sample_check_result.severity == Severity.CRITICAL
        assert len(sample_check_result.references) > 0
        assert sample_check_result.fix_command != ""
