"""Cancellation and off-loop persistence.

`cancel_scan` used to flip a status field and nothing else: every check kept
running, kept spawning gcloud subprocesses and kept burning quota, and when the
scan finished it overwrote CANCELLED with COMPLETED. Separately, persistence
ran the synchronous GCS client inline, so a large save froze heartbeats and
every other scan in the process.
"""

import asyncio
import time

import pytest

from backend.checks.base import BaseCheck
from backend.core.models import (
    Category,
    CheckResult,
    ScanRequest,
    ScanStatus,
    ServiceCategory,
    Severity,
)
from backend.core.scanner import Scanner


class _SlowCheck(BaseCheck):
    """Long enough to still be running when the cancel lands."""

    id = "CANCEL-TEST-001"
    title = "Slow check"
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "TEST"
    service_category = ServiceCategory.IAM

    started = 0
    finished = 0

    async def execute(self, project_id, gcloud_runner):
        type(self).started += 1
        await asyncio.sleep(5)
        type(self).finished += 1
        return [CheckResult(
            check_id=self.id, title=self.title, severity=self.severity,
            category=self.category, service=self.service,
            resource_name="r", project_id=project_id,
            current_state="bad", recommended_state="good",
        )]


@pytest.fixture(autouse=True)
def _reset_counters():
    _SlowCheck.started = 0
    _SlowCheck.finished = 0
    yield


@pytest.fixture
def slow_scanner(monkeypatch, scan_store, mock_gcloud_runner):
    monkeypatch.setattr(
        "backend.core.engine.get_checks_by_service",
        lambda _cat: [_SlowCheck()],
    )
    return Scanner(store=scan_store, gcloud_runner=mock_gcloud_runner)


@pytest.mark.asyncio
class TestCancellationStopsWork:
    async def test_cancel_actually_stops_the_running_checks(self, slow_scanner):
        scan = await slow_scanner.create_scan(ScanRequest(
            scope="project", target_id="test-project",
            categories=[ServiceCategory.IAM],
        ))

        task = asyncio.create_task(slow_scanner.run_scan(scan.id))
        # Let the engine get as far as launching the check.
        while _SlowCheck.started == 0:
            await asyncio.sleep(0.01)

        result = await slow_scanner.cancel_scan(scan.id)
        assert result is not None
        assert result.status == ScanStatus.CANCELLED

        with pytest.raises(asyncio.CancelledError):
            await task

        assert _SlowCheck.finished == 0, (
            "checks kept running after cancel — the scan is still burning quota"
        )

    async def test_cancelled_scan_is_not_reported_completed(self, slow_scanner):
        scan = await slow_scanner.create_scan(ScanRequest(
            scope="project", target_id="test-project",
            categories=[ServiceCategory.IAM],
        ))

        task = asyncio.create_task(slow_scanner.run_scan(scan.id))
        while _SlowCheck.started == 0:
            await asyncio.sleep(0.01)
        await slow_scanner.cancel_scan(scan.id)
        with pytest.raises(asyncio.CancelledError):
            await task

        assert slow_scanner.store.get(scan.id).status == ScanStatus.CANCELLED

    async def test_task_handle_is_released_after_the_scan(self, slow_scanner):
        scan = await slow_scanner.create_scan(ScanRequest(
            scope="project", target_id="test-project",
            categories=[ServiceCategory.IAM],
        ))
        task = asyncio.create_task(slow_scanner.run_scan(scan.id))
        while _SlowCheck.started == 0:
            await asyncio.sleep(0.01)
        assert scan.id in slow_scanner._running

        await slow_scanner.cancel_scan(scan.id)
        with pytest.raises(asyncio.CancelledError):
            await task

        assert scan.id not in slow_scanner._running
        assert scan.id not in slow_scanner._save_locks

    async def test_cancelling_an_unknown_scan_returns_none(self, slow_scanner):
        assert await slow_scanner.cancel_scan("no-such-scan") is None

    async def test_cancelling_a_finished_scan_is_a_no_op(
        self, monkeypatch, scan_store, mock_gcloud_runner
    ):
        monkeypatch.setattr(
            "backend.core.engine.get_checks_by_service", lambda _cat: []
        )
        scanner = Scanner(store=scan_store, gcloud_runner=mock_gcloud_runner)
        scan = await scanner.create_scan(ScanRequest(
            scope="project", target_id="test-project",
            categories=[ServiceCategory.IAM],
        ))
        await scanner.run_scan(scan.id)

        result = await scanner.cancel_scan(scan.id)

        assert result.status == ScanStatus.COMPLETED


@pytest.mark.asyncio
class TestPersistenceDoesNotBlockTheLoop:
    async def test_slow_persist_does_not_stall_the_event_loop(
        self, monkeypatch, scan_store, mock_gcloud_runner
    ):
        """A 300ms GCS write must not freeze heartbeats for 300ms."""
        def slow_persist(scan):
            time.sleep(0.3)

        scan_store.persist = slow_persist  # type: ignore[method-assign]
        scanner = Scanner(store=scan_store, gcloud_runner=mock_gcloud_runner)
        scan = await scanner.create_scan(ScanRequest(
            scope="project", target_id="test-project",
            categories=[ServiceCategory.IAM],
        ))

        ticks = 0

        async def heartbeat():
            nonlocal ticks
            while True:
                await asyncio.sleep(0.02)
                ticks += 1

        beat = asyncio.create_task(heartbeat())
        await scanner._save_async(scan)
        beat.cancel()

        assert ticks >= 5, (
            f"loop only ticked {ticks}x during a 300ms save — it was blocked"
        )

    async def test_live_object_stays_canonical_in_the_store(
        self, scan_store, mock_gcloud_runner
    ):
        """persist() gets a snapshot; the store must still hand back the live object."""
        scanner = Scanner(store=scan_store, gcloud_runner=mock_gcloud_runner)
        scan = await scanner.create_scan(ScanRequest(
            scope="project", target_id="test-project",
            categories=[ServiceCategory.IAM],
        ))

        await scanner._save_async(scan)

        assert scan_store.get(scan.id) is scan

    async def test_concurrent_saves_are_serialised_per_scan(
        self, scan_store, mock_gcloud_runner
    ):
        overlapping = []
        in_flight = 0

        def tracking_persist(_scan):
            nonlocal in_flight
            in_flight += 1
            overlapping.append(in_flight)
            time.sleep(0.05)
            in_flight -= 1

        scan_store.persist = tracking_persist  # type: ignore[method-assign]
        scanner = Scanner(store=scan_store, gcloud_runner=mock_gcloud_runner)
        scan = await scanner.create_scan(ScanRequest(
            scope="project", target_id="test-project",
            categories=[ServiceCategory.IAM],
        ))

        await asyncio.gather(*(scanner._save_async(scan) for _ in range(4)))

        assert max(overlapping) == 1, (
            "two writers uploaded the same scan at once — last-writer-wins "
            "silently drops findings"
        )
