"""Unit tests for Billing checks (BIL-001 through BIL-010)."""

import pytest
from unittest.mock import AsyncMock

from backend.checks.billing.billing_checks import (
    NoBudgetAlerts,
    UnusedDisks,
    UnusedStaticIPs,
    OldSnapshots,
    NoCommittedUseDiscounts,
    IdleVMs,
    OversizedVMs,
    NoLabelsOnResources,
    StandardStorageForInfrequentData,
    BillingExportNotConfigured,
)


@pytest.fixture
def runner():
    return AsyncMock()


# ---- BIL-001 ----

@pytest.mark.asyncio
async def test_no_budget_alerts(runner):
    runner.run.return_value = []
    check = NoBudgetAlerts()
    results = await check.execute("proj-1", runner)
    assert len(results) == 1
    assert results[0].severity == "high"


@pytest.mark.asyncio
async def test_budget_alerts_present(runner):
    # BIL-001 makes two calls: 1) describe project (dict with billingAccountName)
    # 2) list budgets (list). When the second call returns a non-empty list,
    # there's nothing to flag.
    async def fake_run(cmd, **kwargs):
        if "billing projects describe" in cmd:
            return {"billingAccountName": "billingAccounts/123"}
        if "budgets list" in cmd:
            return [{"name": "billingAccounts/123/budgets/b1"}]
        return []
    runner.run = AsyncMock(side_effect=fake_run)
    check = NoBudgetAlerts()
    results = await check.execute("proj-1", runner)
    assert len(results) == 0


# ---- BIL-002 ----

@pytest.mark.asyncio
async def test_unused_disk(runner):
    runner.run.return_value = [
        {"name": "orphan-disk", "zone": "https://z/zones/us-central1-a", "sizeGb": "50", "users": []},
    ]
    check = UnusedDisks()
    results = await check.execute("proj-1", runner)
    assert len(results) == 1
    assert "gcloud compute disks delete" in results[0].fix_command


@pytest.mark.asyncio
async def test_attached_disk(runner):
    runner.run.return_value = [
        {"name": "used-disk", "zone": "https://z/zones/us-central1-a", "sizeGb": "50", "users": ["instances/vm1"]},
    ]
    check = UnusedDisks()
    results = await check.execute("proj-1", runner)
    assert len(results) == 0


# ---- BIL-003 ----

@pytest.mark.asyncio
async def test_unused_static_ip(runner):
    runner.run.return_value = [
        {"name": "old-ip", "region": "https://r/regions/us-central1", "status": "RESERVED"},
    ]
    check = UnusedStaticIPs()
    results = await check.execute("proj-1", runner)
    assert len(results) == 1


@pytest.mark.asyncio
async def test_used_static_ip(runner):
    runner.run.return_value = [
        {"name": "used-ip", "region": "https://r/regions/us-central1", "status": "IN_USE"},
    ]
    check = UnusedStaticIPs()
    results = await check.execute("proj-1", runner)
    assert len(results) == 0


# ---- BIL-004 ----

@pytest.mark.asyncio
async def test_old_snapshot(runner):
    runner.run.return_value = [
        {"name": "old-snap", "creationTimestamp": "2024-01-01T00:00:00Z", "storageBytes": 1073741824},
    ]
    check = OldSnapshots()
    results = await check.execute("proj-1", runner)
    assert len(results) == 1


@pytest.mark.asyncio
async def test_recent_snapshot(runner):
    from datetime import datetime, timezone, timedelta
    recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    runner.run.return_value = [
        {"name": "recent-snap", "creationTimestamp": recent, "storageBytes": 1073741824},
    ]
    check = OldSnapshots()
    results = await check.execute("proj-1", runner)
    assert len(results) == 0


# ---- BIL-005 ----

@pytest.mark.asyncio
async def test_no_cuds(runner):
    runner.run.side_effect = [
        [],  # no commitments
        [{"name": "vm1"}, {"name": "vm2"}, {"name": "vm3"}],  # 3+ instances
    ]
    check = NoCommittedUseDiscounts()
    results = await check.execute("proj-1", runner)
    assert len(results) == 1


# ---- BIL-006 ----

@pytest.mark.asyncio
async def test_idle_vms(runner):
    runner.run.return_value = [
        {
            "description": "Idle VM detected",
            "content": {"operationGroups": [{"operations": [{"resource": "instances/idle-vm"}]}]},
        }
    ]
    check = IdleVMs()
    results = await check.execute("proj-1", runner)
    assert len(results) == 1


# ---- BIL-007 ----

@pytest.mark.asyncio
async def test_oversized_vms(runner):
    runner.run.return_value = [
        {
            "description": "Consider downsizing to e2-medium",
            "content": {"operationGroups": [{"operations": [{"resource": "instances/big-vm"}]}]},
        }
    ]
    check = OversizedVMs()
    results = await check.execute("proj-1", runner)
    assert len(results) == 1


# ---- BIL-008 ----

@pytest.mark.asyncio
async def test_no_labels(runner):
    runner.run.return_value = [
        {"name": "vm-no-labels", "labels": {}},
        {"name": "vm-with-labels", "labels": {"team": "backend"}},
    ]
    check = NoLabelsOnResources()
    results = await check.execute("proj-1", runner)
    assert len(results) == 1
    assert "1 compute" in results[0].current_state


# ---- BIL-009 ----

@pytest.mark.asyncio
async def test_standard_storage_no_lifecycle(runner):
    runner.run.return_value = [
        {"name": "archive-bucket", "storageClass": "STANDARD", "lifecycle": {}},
    ]
    check = StandardStorageForInfrequentData()
    results = await check.execute("proj-1", runner)
    assert len(results) == 1


@pytest.mark.asyncio
async def test_standard_storage_with_lifecycle(runner):
    runner.run.return_value = [
        {"name": "managed-bucket", "storageClass": "STANDARD", "lifecycle": {"rule": [{"action": {"type": "SetStorageClass"}}]}},
    ]
    check = StandardStorageForInfrequentData()
    results = await check.execute("proj-1", runner)
    assert len(results) == 0


# ---- BIL-010 ----

@pytest.mark.asyncio
async def test_billing_export_info(runner):
    check = BillingExportNotConfigured()
    results = await check.execute("proj-1", runner)
    assert len(results) == 1
    assert results[0].severity == "info"
