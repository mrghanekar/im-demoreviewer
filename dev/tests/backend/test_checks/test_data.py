"""Unit tests for Data Services checks (DATA-001 through DATA-010)."""

import pytest
from unittest.mock import AsyncMock

from backend.checks.data.data_checks import (
    BQDatasetNoDefaultCMEK,
    BQDatasetPublicAccess,
    BQTableExpiration,
    PubSubDLQ,
    PubSubNoExpiration,
    PubSubNoEncryption,
    DataflowNoRegionRestriction,
    DataprocNoAutoScaling,
    BQAuditLogging,
    DataCatalogNotUsed,
)


@pytest.fixture
def runner():
    return AsyncMock()


# ---- DATA-001 ----

@pytest.mark.asyncio
async def test_bq_no_cmek_flagged(runner):
    runner.run.side_effect = [
        [{"datasetReference": {"datasetId": "my_dataset"}}],
        {"defaultEncryptionConfiguration": {}},
    ]
    check = BQDatasetNoDefaultCMEK()
    results = await check.execute("proj-1", runner)
    assert len(results) == 1
    assert results[0].check_id == "DATA-001"


@pytest.mark.asyncio
async def test_bq_cmek_pass(runner):
    runner.run.side_effect = [
        [{"datasetReference": {"datasetId": "my_dataset"}}],
        {"defaultEncryptionConfiguration": {"kmsKeyName": "projects/p/locations/l/keyRings/k/cryptoKeys/key1"}},
    ]
    check = BQDatasetNoDefaultCMEK()
    results = await check.execute("proj-1", runner)
    assert len(results) == 0


# ---- DATA-002 ----

@pytest.mark.asyncio
async def test_bq_public_access_flagged(runner):
    runner.run.side_effect = [
        [{"datasetReference": {"datasetId": "pub_ds"}}],
        {"access": [{"role": "READER", "specialGroup": "allUsers"}]},
    ]
    check = BQDatasetPublicAccess()
    results = await check.execute("proj-1", runner)
    assert len(results) == 1
    assert results[0].severity == "critical"


@pytest.mark.asyncio
async def test_bq_no_public_access(runner):
    runner.run.side_effect = [
        [{"datasetReference": {"datasetId": "priv_ds"}}],
        {"access": [{"role": "WRITER", "userByEmail": "user@corp.com"}]},
    ]
    check = BQDatasetPublicAccess()
    results = await check.execute("proj-1", runner)
    assert len(results) == 0


# ---- DATA-003 ----

@pytest.mark.asyncio
async def test_bq_table_expiration_missing(runner):
    runner.run.side_effect = [
        [{"datasetReference": {"datasetId": "staging"}}],
        {},
    ]
    check = BQTableExpiration()
    results = await check.execute("proj-1", runner)
    assert len(results) == 1


# ---- DATA-004 ----

@pytest.mark.asyncio
async def test_pubsub_no_dlq(runner):
    runner.run.return_value = [{"name": "projects/p/subscriptions/sub-1", "deadLetterPolicy": {}}]
    check = PubSubDLQ()
    results = await check.execute("proj-1", runner)
    assert len(results) == 1


@pytest.mark.asyncio
async def test_pubsub_with_dlq(runner):
    runner.run.return_value = [
        {"name": "projects/p/subscriptions/sub-1", "deadLetterPolicy": {"deadLetterTopic": "projects/p/topics/dlq"}}
    ]
    check = PubSubDLQ()
    results = await check.execute("proj-1", runner)
    assert len(results) == 0


# ---- DATA-005 ----

@pytest.mark.asyncio
async def test_pubsub_no_expiration(runner):
    runner.run.return_value = [{"name": "projects/p/subscriptions/sub-1"}]
    check = PubSubNoExpiration()
    results = await check.execute("proj-1", runner)
    assert len(results) == 1


# ---- DATA-006 ----

@pytest.mark.asyncio
async def test_pubsub_no_cmek(runner):
    runner.run.return_value = [{"name": "projects/p/topics/t1"}]
    check = PubSubNoEncryption()
    results = await check.execute("proj-1", runner)
    assert len(results) == 1


# ---- DATA-007 ----

@pytest.mark.asyncio
async def test_dataflow_default_region(runner):
    runner.run.return_value = [{"name": "my-job", "location": "us-central1"}]
    check = DataflowNoRegionRestriction()
    results = await check.execute("proj-1", runner)
    assert len(results) == 1


@pytest.mark.asyncio
async def test_dataflow_specific_region(runner):
    runner.run.return_value = [{"name": "my-job", "location": "europe-west1"}]
    check = DataflowNoRegionRestriction()
    results = await check.execute("proj-1", runner)
    assert len(results) == 0


# ---- DATA-008 ----

@pytest.mark.asyncio
async def test_dataproc_no_autoscaling(runner):
    runner.run.return_value = [{"clusterName": "spark-cluster", "config": {"autoscalingConfig": {}}}]
    check = DataprocNoAutoScaling()
    results = await check.execute("proj-1", runner)
    assert len(results) == 1


# ---- DATA-009 ----

@pytest.mark.asyncio
async def test_bq_audit_logging_missing(runner):
    runner.run.return_value = {"auditConfigs": []}
    check = BQAuditLogging()
    results = await check.execute("proj-1", runner)
    assert len(results) == 1


@pytest.mark.asyncio
async def test_bq_audit_logging_present(runner):
    runner.run.return_value = {"auditConfigs": [{"service": "bigquery.googleapis.com", "auditLogConfigs": []}]}
    check = BQAuditLogging()
    results = await check.execute("proj-1", runner)
    assert len(results) == 0


# ---- DATA-010 ----

@pytest.mark.asyncio
async def test_data_catalog_not_enabled(runner):
    runner.run.return_value = []
    check = DataCatalogNotUsed()
    results = await check.execute("proj-1", runner)
    assert len(results) == 1
    assert "gcloud services enable" in results[0].fix_command
