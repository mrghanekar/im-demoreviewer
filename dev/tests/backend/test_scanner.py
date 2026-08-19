"""Tests for the Scanner orchestrator.

Covers: per-scan event callback isolation, duration accounting, run_scan
returning None for unknown IDs, and final summary correctness.
"""

import asyncio

import pytest

from backend.core.engine import CheckEngine
from backend.core.models import (
    Category,
    CheckResult,
    Severity,
    ScanRequest,
    ScanStatus,
    ServiceCategory,
)
from backend.core.scanner import Scanner
from backend.checks.base import BaseCheck


class _AlwaysFails(BaseCheck):
    id = "TEST-FAIL"
    title = "Always fails"
    description = "fail"
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "TEST"
    service_category = ServiceCategory.IAM

    async def execute(self, project_id, gcloud_runner):
        return [CheckResult(
            check_id=self.id, title=self.title, severity=self.severity,
            category=self.category, service=self.service,
            resource_name=f"projects/{project_id}", project_id=project_id,
            current_state="bad", recommended_state="good",
        )]


@pytest.mark.asyncio
class TestScanner:
    async def test_run_scan_unknown_id_returns_none(self, scanner):
        result = await scanner.run_scan("not-a-real-scan-id")
        assert result is None

    async def test_per_scan_callback_isolation(self, monkeypatch, scan_store, mock_gcloud_runner):
        """Two concurrent scans must not collide on the scanner.on_event slot."""
        scanner = Scanner(store=scan_store, gcloud_runner=mock_gcloud_runner)

        # Stub the engine so we don't depend on the real check registry
        async def fake_run_checks(scan_id, project_id, categories):
            return [], [], None
        monkeypatch.setattr(CheckEngine, "run_checks", lambda self, **kw: fake_run_checks(**kw))

        scan_a = await scanner.create_scan(ScanRequest(scope="project", target_id="proj-a"))
        scan_b = await scanner.create_scan(ScanRequest(scope="project", target_id="proj-b"))

        events_a: list[str] = []
        events_b: list[str] = []

        await asyncio.gather(
            scanner.run_scan(scan_a.id, on_event=lambda e: events_a.append(e["event_type"])),
            scanner.run_scan(scan_b.id, on_event=lambda e: events_b.append(e["event_type"])),
        )

        # Each scan must have received its own scan_started and scan_completed events
        assert "scan_started" in events_a
        assert "scan_completed" in events_a
        assert "scan_started" in events_b
        assert "scan_completed" in events_b

    async def test_duration_is_recorded(self, monkeypatch, scan_store, mock_gcloud_runner):
        scanner = Scanner(store=scan_store, gcloud_runner=mock_gcloud_runner)

        async def slow_run(scan_id, project_id, categories):
            await asyncio.sleep(0.05)
            return [], [], None
        monkeypatch.setattr(CheckEngine, "run_checks", lambda self, **kw: slow_run(**kw))

        scan = await scanner.create_scan(ScanRequest(scope="project", target_id="proj-x"))
        finished = await scanner.run_scan(scan.id)

        assert finished is not None
        assert finished.status == ScanStatus.COMPLETED
        # Duration must be > 0 — the old aggregator zeroed it out
        assert finished.summary.scan_duration_seconds > 0.0

    async def test_full_uuid_id(self, scanner):
        scan = await scanner.create_scan(ScanRequest(scope="project", target_id="proj-x"))
        # Old code truncated to 8 chars; new code keeps full UUID
        assert len(scan.id) >= 32

    async def test_org_scope_with_non_numeric_id_falls_back(self, scanner, mock_gcloud_runner):
        # Non-numeric org IDs should be treated as a single target, not enumerated
        result = await scanner._enumerate_org_projects("not-numeric")
        assert result == ["not-numeric"]
