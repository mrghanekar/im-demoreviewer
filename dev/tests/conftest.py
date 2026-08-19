"""Shared test fixtures for the Democratized Reviewer."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from backend.core.gcloud_runner import GcloudRunner
from backend.core.scanner import ScanStore, Scanner
from backend.core.engine import CheckEngine
from backend.core.models import (
    Category,
    CheckResult,
    Finding,
    Scan,
    ScanRequest,
    ScanStatus,
    ScanSummary,
    Severity,
    ServiceCategory,
)


# ---------------------------------------------------------------------------
# GCloud Runner Mock
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_gcloud_runner():
    """A GcloudRunner mock that returns empty results by default."""
    runner = MagicMock(spec=GcloudRunner)
    runner.run = AsyncMock(return_value=[])
    runner.run_long = AsyncMock(return_value=[])
    runner.get_active_account = AsyncMock(return_value={"account": "test-sa@test-project.iam.gserviceaccount.com", "status": "ACTIVE"})
    runner.get_current_project = AsyncMock(return_value="test-project")
    runner.gcloud_available = True
    runner.clear_cache = MagicMock()
    return runner


# ---------------------------------------------------------------------------
# Engine & Scanner
# ---------------------------------------------------------------------------

@pytest.fixture
def scan_store():
    """A fresh in-memory scan store."""
    return ScanStore()


@pytest.fixture
def check_engine(mock_gcloud_runner):
    """A CheckEngine with mocked dependencies."""
    return CheckEngine(
        gcloud_runner=mock_gcloud_runner,
        max_concurrent=5,
    )


@pytest.fixture
def scanner(scan_store, mock_gcloud_runner):
    """A Scanner with mocked dependencies."""
    return Scanner(
        store=scan_store,
        gcloud_runner=mock_gcloud_runner,
    )


# ---------------------------------------------------------------------------
# Sample Data Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_scan_request():
    """A sample scan request for testing."""
    return ScanRequest(
        scope="project",
        target_id="test-project",
        categories=[ServiceCategory.IAM, ServiceCategory.GCS],
    )


@pytest.fixture
def sample_check_result():
    """A sample CheckResult for testing."""
    return CheckResult(
        check_id="GCS-001",
        title="Bucket is publicly accessible",
        description="The bucket allows public access.",
        severity=Severity.CRITICAL,
        category=Category.SECURITY,
        service="GCS",
        resource_name="gs://test-bucket",
        resource_link="https://console.cloud.google.com/storage/browser/test-bucket",
        project_id="test-project",
        current_state="Public access is enabled",
        recommended_state="Disable public access",
        fix_command="gcloud storage buckets update gs://test-bucket --no-public-access",
        references=["https://cloud.google.com/storage/docs/public-access-prevention"],
    )


@pytest.fixture
def sample_finding(sample_check_result):
    """A sample Finding for testing."""
    return Finding(
        id="scan001-0001",
        scan_id="scan001",
        **sample_check_result.model_dump(),
    )


@pytest.fixture
def sample_scan():
    """A sample completed Scan for testing."""
    return Scan(
        id="scan001",
        scope="project",
        target_id="test-project",
        status=ScanStatus.COMPLETED,
        categories=[ServiceCategory.IAM, ServiceCategory.GCS],
        summary=ScanSummary(
            total_findings=5,
            by_severity={"critical": 1, "high": 2, "medium": 1, "low": 1, "info": 0},
            by_category={"security": 3, "reliability": 1, "performance": 0, "cost": 1, "operations": 0},
            checks_passed=10,
            checks_failed=5,
            checks_errored=0,
            checks_skipped=0,
            scan_duration_seconds=42.5,
        ),
    )
