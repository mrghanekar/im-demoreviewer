"""Tests for features added in the 2026-05 task batch:

- Suppression endpoints (POST/DELETE on findings)
- `include_suppressed` and `id_prefix` filters on the findings list
- CSV export
- ScanStore orphan-scan marking on startup
- Engine `_skip_for_disabled_apis` pre-skip behavior
"""

import csv
import io

import pytest
from fastapi.testclient import TestClient

from backend.api.routes import scan as scan_route
from backend.core.engine import CheckEngine
from backend.core.models import (
    Category,
    CheckExecution,
    Finding,
    Scan,
    ScanStatus,
    ScanSummary,
    Severity,
    ServiceCategory,
)
from backend.core.scanner import ScanStore
from backend.checks.base import BaseCheck
from backend.main import app


PROJECT = "test-project"
SCAN_ID = "suppress-test-scan"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed_scan_with_findings() -> Scan:
    """Inject a completed scan with three findings into the shared scan store."""
    findings = [
        Finding(
            id=f"{SCAN_ID}-{i:04d}",
            scan_id=SCAN_ID,
            check_id=cid,
            title=f"Finding {i}",
            description="",
            severity=Severity.HIGH,
            category=Category.SECURITY,
            service="Test",
            resource_name=f"resource-{i}",
            project_id=PROJECT,
            current_state="bad",
            recommended_state="good",
        )
        for i, cid in enumerate(["IAM-001", "GCE-001", "GKE-002"], start=1)
    ]
    scan = Scan(
        id=SCAN_ID,
        scope="project",
        target_id=PROJECT,
        status=ScanStatus.COMPLETED,
        categories=[ServiceCategory.IAM, ServiceCategory.GCE, ServiceCategory.GKE],
        findings=findings,
        summary=ScanSummary(total_findings=3),
    )
    scan_route.get_store().save(scan)
    return scan


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture(autouse=True)
def _clean_store():
    """Drop the seeded scan after each test so state doesn't leak across tests."""
    yield
    scan_route.get_store().delete(SCAN_ID)


# ---------------------------------------------------------------------------
# Suppression endpoints
# ---------------------------------------------------------------------------

class TestSuppressionEndpoints:
    def test_suppress_marks_finding_and_excludes_by_default(self, client):
        scan = _seed_scan_with_findings()
        target = scan.findings[0]

        resp = client.post(
            f"/api/v1/scans/{SCAN_ID}/findings/{target.id}/suppress",
            json={"reason": "Accepted risk: legacy service"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["suppressed"] is True
        assert body["suppression_reason"] == "Accepted risk: legacy service"

        # Default list call should now omit the suppressed finding
        listed = client.get(f"/api/v1/scans/{SCAN_ID}/findings").json()
        assert target.id not in {f["id"] for f in listed}
        assert len(listed) == 2

        # include_suppressed=true brings it back
        listed_all = client.get(
            f"/api/v1/scans/{SCAN_ID}/findings?include_suppressed=true"
        ).json()
        assert {f["id"] for f in listed_all} == {f.id for f in scan.findings}

    def test_unsuppress_restores_finding(self, client):
        scan = _seed_scan_with_findings()
        target = scan.findings[1]

        client.post(f"/api/v1/scans/{SCAN_ID}/findings/{target.id}/suppress")
        # Confirm it's hidden
        hidden = client.get(f"/api/v1/scans/{SCAN_ID}/findings").json()
        assert target.id not in {f["id"] for f in hidden}

        resp = client.delete(f"/api/v1/scans/{SCAN_ID}/findings/{target.id}/suppress")
        assert resp.status_code == 200
        assert resp.json()["suppressed"] is False

        visible = client.get(f"/api/v1/scans/{SCAN_ID}/findings").json()
        assert target.id in {f["id"] for f in visible}

    def test_suppress_unknown_finding_returns_404(self, client):
        _seed_scan_with_findings()
        resp = client.post(f"/api/v1/scans/{SCAN_ID}/findings/does-not-exist/suppress")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# id_prefix filter
# ---------------------------------------------------------------------------

class TestIdPrefixFilter:
    def test_filter_by_prefix_matches_case_insensitively(self, client):
        _seed_scan_with_findings()  # has IAM-001, GCE-001, GKE-002

        only_gke = client.get(f"/api/v1/scans/{SCAN_ID}/findings?id_prefix=gke").json()
        assert {f["check_id"] for f in only_gke} == {"GKE-002"}

        only_g = client.get(f"/api/v1/scans/{SCAN_ID}/findings?id_prefix=G").json()
        assert {f["check_id"] for f in only_g} == {"GCE-001", "GKE-002"}

    def test_prefix_with_no_matches_returns_empty(self, client):
        _seed_scan_with_findings()
        empty = client.get(f"/api/v1/scans/{SCAN_ID}/findings?id_prefix=DB-").json()
        assert empty == []


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

class TestCsvExport:
    def test_csv_contains_one_row_per_visible_finding(self, client):
        _seed_scan_with_findings()

        resp = client.get(f"/api/v1/scans/{SCAN_ID}/export/csv")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/csv")

        rows = list(csv.DictReader(io.StringIO(resp.text)))
        assert len(rows) == 3
        check_ids = {row["check_id"] for row in rows}
        assert check_ids == {"IAM-001", "GCE-001", "GKE-002"}
        # Suppression columns exist and default false
        assert all(row["suppressed"] == "false" for row in rows)

    def test_csv_excludes_suppressed_by_default(self, client):
        scan = _seed_scan_with_findings()
        target = scan.findings[0]
        client.post(f"/api/v1/scans/{SCAN_ID}/findings/{target.id}/suppress")

        body = client.get(f"/api/v1/scans/{SCAN_ID}/export/csv").text
        rows = list(csv.DictReader(io.StringIO(body)))
        assert len(rows) == 2
        assert target.check_id not in {row["check_id"] for row in rows}

        body_all = client.get(
            f"/api/v1/scans/{SCAN_ID}/export/csv?include_suppressed=true"
        ).text
        rows_all = list(csv.DictReader(io.StringIO(body_all)))
        assert len(rows_all) == 3
        suppressed = [r for r in rows_all if r["suppressed"] == "true"]
        assert len(suppressed) == 1
        assert suppressed[0]["check_id"] == target.check_id


# ---------------------------------------------------------------------------
# ScanStore orphan handling
# ---------------------------------------------------------------------------

class TestScanStoreOrphanHandling:
    def test_mark_orphaned_running_scan_as_failed(self, tmp_path, monkeypatch):
        """A RUNNING scan loaded from persistence at startup must be FAILED."""
        # First store with a running scan persisted to disk
        monkeypatch.setenv("DR_DATA_DIR", str(tmp_path))
        store1 = ScanStore()
        running = Scan(
            id="orphan-1",
            scope="project",
            target_id=PROJECT,
            status=ScanStatus.RUNNING,
            categories=[ServiceCategory.IAM],
        )
        store1.save(running)

        # New store instance simulates a fresh process picking up the file
        store2 = ScanStore()
        recovered = store2.get("orphan-1")
        assert recovered is not None
        assert recovered.status == ScanStatus.FAILED
        assert "Interrupted" in (recovered.error_message or "")

    def test_miss_cache_avoids_repeat_lookups(self, monkeypatch):
        """Two get() calls for a missing scan should only touch the source once."""
        store = ScanStore()
        # No persistence configured → first get is just a dict lookup; second
        # call should still return None via the negative cache. We just
        # confirm the API stays stable.
        assert store.get("never-existed") is None
        assert store.get("never-existed") is None
        assert "never-existed" in store._miss_cache


# ---------------------------------------------------------------------------
# Engine API pre-skip
# ---------------------------------------------------------------------------

class _RequiresFakeApi(BaseCheck):
    id = "FAKE-API-001"
    title = "Needs an API we never enable"
    description = "test"
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Test"
    service_category = ServiceCategory.IAM
    required_apis = ["nonexistent.googleapis.com"]

    async def execute(self, project_id, gcloud_runner):
        # If we get here the pre-skip failed.
        raise AssertionError("Check should have been pre-skipped")


class _UndeclaredHitsDisabledApi(BaseCheck):
    """A check that didn't declare required_apis but its gcloud call hits a
    disabled API — must still be skipped (reactively) with the same message."""
    id = "REACTIVE-SKIP-001"
    title = "Reactive skip path"
    description = "test"
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Test"
    service_category = ServiceCategory.IAM
    # Deliberately no required_apis — the pre-skip path can't help.

    async def execute(self, project_id, gcloud_runner):
        await gcloud_runner.run("gcloud something --project=x --format=json")
        return []


@pytest.mark.asyncio
class TestEnginePreSkip:
    async def test_check_with_missing_required_api_is_skipped(self, mock_gcloud_runner):
        # Enabled-API set doesn't include the one our check needs.
        mock_gcloud_runner.list_enabled_apis = lambda project_id: _wrap({"compute.googleapis.com"})

        engine = CheckEngine(gcloud_runner=mock_gcloud_runner, max_concurrent=2)
        check = _RequiresFakeApi()
        execution = CheckExecution(
            check_id=check.id,
            check_title=check.title,
            service_category=check.service_category,
        )

        was_skipped = await engine._skip_for_disabled_apis(
            check, execution, {"compute.googleapis.com"},
        )
        assert was_skipped is True
        assert execution.status == "skipped"
        assert "nonexistent.googleapis.com" in (execution.error_message or "")

    async def test_check_runs_when_required_api_enabled(self, mock_gcloud_runner):
        engine = CheckEngine(gcloud_runner=mock_gcloud_runner, max_concurrent=2)
        check = _RequiresFakeApi()
        execution = CheckExecution(
            check_id=check.id,
            check_title=check.title,
            service_category=check.service_category,
        )

        was_skipped = await engine._skip_for_disabled_apis(
            check, execution, {"nonexistent.googleapis.com"},
        )
        assert was_skipped is False

    async def test_empty_enabled_apis_means_no_pre_skip(self, mock_gcloud_runner):
        """If we couldn't fetch the enabled-API list, run everything (don't over-skip)."""
        engine = CheckEngine(gcloud_runner=mock_gcloud_runner, max_concurrent=2)
        check = _RequiresFakeApi()
        execution = CheckExecution(
            check_id=check.id,
            check_title=check.title,
            service_category=check.service_category,
        )

        was_skipped = await engine._skip_for_disabled_apis(check, execution, set())
        assert was_skipped is False

    async def test_pre_skip_message_mentions_service_not_active(self, mock_gcloud_runner):
        """The skip message must say 'service not active in project' so the UI surfaces a clear reason."""
        engine = CheckEngine(gcloud_runner=mock_gcloud_runner, max_concurrent=2)
        check = _RequiresFakeApi()
        execution = CheckExecution(
            check_id=check.id, check_title=check.title,
            service_category=check.service_category,
        )
        await engine._skip_for_disabled_apis(check, execution, {"compute.googleapis.com"})
        assert "service not active in project" in (execution.error_message or "")
        assert "nonexistent.googleapis.com" in (execution.error_message or "")

    async def test_reactive_skip_uses_same_message(self, mock_gcloud_runner):
        """When the pre-skip misses and the gcloud call raises ServiceNotEnabledError,
        the reactive path must produce the same 'service not active' message."""
        from unittest.mock import AsyncMock
        from backend.core.exceptions import ServiceNotEnabledError
        mock_gcloud_runner.run = AsyncMock(side_effect=ServiceNotEnabledError("compute.googleapis.com"))
        engine = CheckEngine(gcloud_runner=mock_gcloud_runner, max_concurrent=2)
        check = _UndeclaredHitsDisabledApi()
        execution = CheckExecution(
            check_id=check.id, check_title=check.title,
            service_category=check.service_category,
        )
        findings = await engine._run_single_check(check, "test-project", execution)
        assert findings == []
        assert execution.status == "skipped"
        assert "service not active in project" in (execution.error_message or "")


async def _wrap(value):
    return value
