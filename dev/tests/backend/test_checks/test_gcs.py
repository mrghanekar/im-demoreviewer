"""Tests for GCS check modules."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from backend.checks.gcs.bucket_security import (
    PublicBucket,
    UniformBucketAccess,
    BucketNotCMEK,
    VersioningNotEnabled,
    NoLifecyclePolicy,
    BucketLoggingNotEnabled,
)

PROJECT = "test-project"


@pytest.fixture
def runner():
    r = MagicMock()
    r.run = AsyncMock(return_value=[])
    return r


# ---- GCS-001: Public Bucket ----

@pytest.mark.asyncio
class TestPublicBucket:

    async def test_finds_public_bucket(self, runner):
        async def mock_run(cmd, **kwargs):
            if "buckets list" in cmd:
                return [{"name": "my-public-bucket"}]
            if "get-iam-policy" in cmd:
                return {"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]}
            return []
        runner.run = AsyncMock(side_effect=mock_run)

        check = PublicBucket()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert "my-public-bucket" in findings[0].resource_name

    async def test_passes_private_bucket(self, runner):
        async def mock_run(cmd, **kwargs):
            if "buckets list" in cmd:
                return [{"name": "my-private-bucket"}]
            if "get-iam-policy" in cmd:
                return {"bindings": [{"role": "roles/storage.admin", "members": ["user:admin@corp.com"]}]}
            return []
        runner.run = AsyncMock(side_effect=mock_run)

        check = PublicBucket()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


# ---- GCS-002: Uniform Bucket Access ----

@pytest.mark.asyncio
class TestUniformBucketAccess:

    async def test_finds_non_uniform(self, runner):
        runner.run = AsyncMock(return_value=[{
            "name": "legacy-bucket",
            "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": False}},
        }])
        check = UniformBucketAccess()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1

    async def test_passes_uniform(self, runner):
        runner.run = AsyncMock(return_value=[{
            "name": "modern-bucket",
            "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}},
        }])
        check = UniformBucketAccess()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


# ---- GCS-003: CMEK ----

@pytest.mark.asyncio
class TestBucketNotCMEK:

    async def test_finds_non_cmek_bucket(self, runner):
        runner.run = AsyncMock(return_value=[{"name": "default-enc-bucket"}])
        check = BucketNotCMEK()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    async def test_passes_cmek_bucket(self, runner):
        runner.run = AsyncMock(return_value=[{
            "name": "cmek-bucket",
            "encryption": {"defaultKmsKeyName": "projects/p/locations/l/keyRings/kr/cryptoKeys/k"},
        }])
        check = BucketNotCMEK()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


# ---- GCS-004: Versioning ----

@pytest.mark.asyncio
class TestVersioningNotEnabled:

    async def test_finds_no_versioning(self, runner):
        runner.run = AsyncMock(return_value=[{"name": "no-ver-bucket", "versioning": {}}])
        check = VersioningNotEnabled()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1

    async def test_passes_versioned_bucket(self, runner):
        runner.run = AsyncMock(return_value=[{"name": "ver-bucket", "versioning": {"enabled": True}}])
        check = VersioningNotEnabled()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


# ---- GCS-005: Lifecycle ----

@pytest.mark.asyncio
class TestNoLifecyclePolicy:

    async def test_finds_no_lifecycle(self, runner):
        runner.run = AsyncMock(return_value=[{"name": "no-lc-bucket", "lifecycle": {}}])
        check = NoLifecyclePolicy()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1

    async def test_passes_with_lifecycle(self, runner):
        runner.run = AsyncMock(return_value=[{
            "name": "lc-bucket",
            "lifecycle": {"rule": [{"action": {"type": "Delete"}, "condition": {"age": 365}}]},
        }])
        check = NoLifecyclePolicy()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


# ---- GCS-006: Logging ----

@pytest.mark.asyncio
class TestBucketLoggingNotEnabled:

    async def test_finds_no_logging(self, runner):
        runner.run = AsyncMock(return_value=[{"name": "no-log-bucket"}])
        check = BucketLoggingNotEnabled()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1

    async def test_passes_with_logging(self, runner):
        runner.run = AsyncMock(return_value=[{
            "name": "logged-bucket",
            "logging": {"logBucket": "gs://log-sink-bucket"},
        }])
        check = BucketLoggingNotEnabled()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0
