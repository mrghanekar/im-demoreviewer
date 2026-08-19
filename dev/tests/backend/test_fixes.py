"""Tests for the F1–F4 fix batch:

- F1: Finding IDs stay globally unique when the scanner runs projects in parallel
- F2: Intermediate save fires after each project completes
- F3: WebSocket cleanup_scan_state drops bus entries
- F4: Suppress endpoint returns without waiting on the GCS save
"""

import asyncio
import time
from unittest.mock import MagicMock

import pytest

from backend.api.routes import websocket as ws_route
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
from backend.core.scanner import Scanner
from backend.checks.base import BaseCheck


# ---------------------------------------------------------------------------
# F1: Finding-ID uniqueness across parallel projects
# ---------------------------------------------------------------------------

class _ThreeFindings(BaseCheck):
    id = "PAR-TEST-001"
    title = "Three findings per run"
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "TEST"
    service_category = ServiceCategory.IAM

    async def execute(self, project_id, gcloud_runner):
        return [
            CheckResult(
                check_id=self.id, title=self.title, severity=self.severity,
                category=self.category, service=self.service,
                resource_name=f"r-{i}-{project_id}", project_id=project_id,
                current_state="bad", recommended_state="good",
            )
            for i in range(3)
        ]


@pytest.mark.asyncio
async def test_parallel_projects_produce_unique_finding_ids(monkeypatch, scan_store, mock_gcloud_runner):
    """Two engines run concurrently must NOT both mint scan-0001 etc."""
    scanner = Scanner(store=scan_store, gcloud_runner=mock_gcloud_runner)

    # Bypass the real registry — every project gets exactly _ThreeFindings.
    monkeypatch.setattr(
        "backend.core.engine.get_checks_by_service",
        lambda _cat: [_ThreeFindings()],
    )

    scan = await scanner.create_scan(ScanRequest(
        scope="org", target_id="123456",
        categories=[ServiceCategory.IAM],
        specific_projects=["proj-a", "proj-b", "proj-c"],
    ))

    result = await scanner.run_scan(scan.id)
    assert result is not None
    assert result.status == ScanStatus.COMPLETED
    ids = [f.id for f in result.findings]
    assert len(ids) == 9  # 3 projects × 3 findings
    assert len(set(ids)) == 9, f"Finding IDs collided: {sorted(ids)}"


# ---------------------------------------------------------------------------
# F2: Intermediate save fires per project
# ---------------------------------------------------------------------------

class _Saves(MagicMock):
    """A spy that wraps a real store so we can count save() calls."""
    pass


@pytest.mark.asyncio
async def test_intermediate_save_fires_per_project(monkeypatch, scan_store, mock_gcloud_runner):
    # Count durable writes, not save(): the scanner persists off the event loop
    # via register() + persist(), so persist is where "did this project's work
    # survive an instance rotation?" is actually decided.
    save_calls = []
    original_persist = scan_store.persist

    def counting_persist(scan):
        save_calls.append(scan.id)
        original_persist(scan)

    scan_store.persist = counting_persist  # type: ignore[method-assign]

    scanner = Scanner(store=scan_store, gcloud_runner=mock_gcloud_runner)
    monkeypatch.setattr(
        "backend.core.engine.get_checks_by_service",
        lambda _cat: [_ThreeFindings()],
    )

    scan = await scanner.create_scan(ScanRequest(
        scope="org", target_id="123456",
        categories=[ServiceCategory.IAM],
        specific_projects=["project-one", "project-two"],
    ))

    await scanner.run_scan(scan.id)

    # Expected saves: create_scan (1) + per-scan setup (1: projects_scanned) +
    # 2 intermediate saves (one per project) + 2 finalization saves at end (5+).
    # Minimum check: there should be ≥ 2 saves AFTER scan starts (i.e. one per
    # completed project) — was only 1 final save pre-F2.
    saves_during_scan = [s for s in save_calls if s == scan.id]
    # Without F2 this would equal ~3 (create + projects_scanned + final).
    # With F2 it should be at least 4 (add 2 per-project saves; some overlap
    # with the final save).
    assert len(saves_during_scan) >= 4, (
        f"Expected intermediate saves per project, got {len(saves_during_scan)}"
    )


# ---------------------------------------------------------------------------
# F3: WebSocket cleanup_scan_state drops bus entries
# ---------------------------------------------------------------------------

def test_cleanup_scan_state_removes_token():
    scan_id = "cleanup-test-1"
    ws_route.generate_scan_token(scan_id)
    assert scan_id in ws_route._scan_tokens

    ws_route.cleanup_scan_state(scan_id)
    assert scan_id not in ws_route._scan_tokens


def test_cleanup_scan_state_is_idempotent():
    # Calling twice on an unknown scan must not raise.
    ws_route.cleanup_scan_state("never-existed")
    ws_route.cleanup_scan_state("never-existed")


def test_scan_token_cache_evicts_oldest_at_cap(monkeypatch):
    """When _MAX_TOKENS is exceeded, the oldest entry is evicted (LRU)."""
    monkeypatch.setattr(ws_route, "_MAX_TOKENS", 3)
    # Reset the OrderedDict so prior tests don't pollute.
    ws_route._scan_tokens.clear()
    for i in range(5):
        ws_route.generate_scan_token(f"scan-{i}")
    # Only the last 3 should remain
    assert list(ws_route._scan_tokens.keys()) == ["scan-2", "scan-3", "scan-4"]


@pytest.mark.asyncio
async def test_scanner_calls_cleanup_on_completion(monkeypatch, scan_store, mock_gcloud_runner):
    """After a scan completes, its token must be removed from the bus state."""
    scan_id_holder = {}

    def tracking_generate(scan_id):
        scan_id_holder["id"] = scan_id
        return ws_route.generate_scan_token(scan_id)

    scanner = Scanner(store=scan_store, gcloud_runner=mock_gcloud_runner)
    monkeypatch.setattr(
        "backend.core.engine.get_checks_by_service",
        lambda _cat: [],  # No checks → empty scan, but still terminal
    )

    scan = await scanner.create_scan(ScanRequest(
        scope="project", target_id="proj-x", categories=[ServiceCategory.IAM],
    ))
    tracking_generate(scan.id)
    assert scan.id in ws_route._scan_tokens

    await scanner.run_scan(scan.id)

    # Scanner._cleanup_bus_state should have fired on scan_completed
    assert scan.id not in ws_route._scan_tokens


# ---------------------------------------------------------------------------
# F4: Suppress endpoint returns without waiting on the GCS save
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_engine_aborts_on_permission_storm(monkeypatch, mock_gcloud_runner):
    """When the SA has no perms on a target, the engine should short-circuit
    after PERMISSION_STORM_THRESHOLD 403s within PERMISSION_STORM_WINDOW_SECONDS
    and fast-path remaining checks to SKIPPED instead of letting them all time
    out individually."""
    from backend.core.engine import CheckEngine
    from backend.core.models import ServiceCategory, Severity, Category

    class _PermDeniedCheck(BaseCheck):
        """Simulates a check whose gcloud call hits PERMISSION_DENIED."""
        severity = Severity.HIGH
        category = Category.SECURITY
        service = "Test"
        service_category = ServiceCategory.IAM

        async def execute(self, project_id, gcloud_runner):
            raise PermissionError("PERMISSION_DENIED: Required permission missing for projects/X")

    # Tighten the threshold so the test runs fast.
    monkeypatch.setattr(CheckEngine, "PERMISSION_STORM_THRESHOLD", 3)

    # 20 fake permission-denied checks — only the first 3 should ERROR; the
    # rest should be SKIPPED via the storm short-circuit.
    checks = []
    for i in range(20):
        c = type(f"Denied{i}", (_PermDeniedCheck,), {"id": f"DEN-{i:03d}", "title": f"denied {i}"})()
        checks.append(c)

    monkeypatch.setattr(
        "backend.core.engine.get_checks_by_service",
        lambda _cat: checks,
    )

    engine = CheckEngine(gcloud_runner=mock_gcloud_runner, max_concurrent=1)
    findings, executions, _summary = await engine.run_checks(
        scan_id="storm-test", project_id="locked-down",
        categories=[ServiceCategory.IAM],
    )

    assert findings == []
    statuses = [e.status for e in executions]
    errored = statuses.count("errored")
    skipped = statuses.count("skipped")
    # First few are ERROR (triggering the storm), rest SKIPPED.
    assert errored >= 3, f"Expected at least 3 ERRORED before short-circuit, got {errored}"
    assert skipped > 0, "Storm short-circuit didn't fast-path any checks to SKIPPED"
    # The aborted-skipped error_message should reference the storm.
    aborted_msgs = [e.error_message for e in executions if e.status == "skipped" and e.error_message]
    assert any("Aborted" in m and "permission" in m.lower() for m in aborted_msgs), \
        f"Expected an 'Aborted: ... permission' message, got: {aborted_msgs[:3]}"


@pytest.mark.asyncio
async def test_suppress_endpoint_does_not_block_on_save(monkeypatch):
    """suppress_finding must return immediately even if store.save is slow."""
    from backend.api.routes.scan import suppress_finding, SuppressionRequest

    # A fake store whose save() simulates a slow GCS write.
    save_delay = 0.5
    save_completed = asyncio.Event()

    class SlowStore:
        def __init__(self):
            self._scan = Scan(
                id="slow-1", scope="project", target_id="p",
                status=ScanStatus.COMPLETED,
                categories=[ServiceCategory.IAM],
                findings=[Finding(
                    id="slow-1-0001", scan_id="slow-1",
                    check_id="X-1", title="t", severity=Severity.HIGH,
                    category=Category.SECURITY, service="s",
                    resource_name="r", project_id="p",
                    current_state="", recommended_state="",
                )],
                summary=ScanSummary(total_findings=1),
            )

        def get(self, _id):
            return self._scan

        def save(self, _scan):
            time.sleep(save_delay)
            save_completed.set()

    store = SlowStore()
    start = time.monotonic()
    result = await suppress_finding(
        scan_id="slow-1", finding_id="slow-1-0001",
        payload=SuppressionRequest(reason="test"),
        store=store,  # type: ignore[arg-type]
    )
    elapsed = time.monotonic() - start

    # Must return much faster than the simulated save delay.
    assert elapsed < save_delay / 2, f"suppress blocked on save: {elapsed:.3f}s"
    assert result.suppressed is True
    # And the background save must eventually complete.
    await asyncio.wait_for(save_completed.wait(), timeout=2.0)
