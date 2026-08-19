"""Tests for Secret Manager check modules (SM-001 through SM-007).

Note: the checks live in backend/checks/secrets/secret_manager.py (the
package directory is named "secrets", not "secret_manager").
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from backend.checks.secrets.secret_manager import (
    SecretAutomaticReplicationGlobal,
    SecretLastUpdatedLongAgo,
    SecretManyVersions,
    SecretNoCMEK,
    SecretNoLabels,
    SecretNoRotation,
    SecretPublicAccess,
)

PROJECT = "test-project"


@pytest.fixture
def runner():
    r = MagicMock()
    r.run = AsyncMock(return_value=[])
    return r


@pytest.mark.asyncio
class TestSecretNoRotation:

    async def test_flags_secret_without_rotation(self, runner):
        runner.run.return_value = [{
            "name": f"projects/{PROJECT}/secrets/db-password",
            "createTime": "2023-01-01T00:00:00Z",
            "replication": {"automatic": {}},
            # no "rotation" key at all
        }]
        check = SecretNoRotation()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "SM-001"
        assert findings[0].severity == "medium"
        assert findings[0].resource_name == "secrets/db-password"

    async def test_flags_secret_with_empty_rotation_period(self, runner):
        runner.run.return_value = [{
            "name": f"projects/{PROJECT}/secrets/api-key",
            "rotation": {},  # present but no rotationPeriod
        }]
        check = SecretNoRotation()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1

    async def test_passes_secret_with_rotation_configured(self, runner):
        runner.run.return_value = [{
            "name": f"projects/{PROJECT}/secrets/db-password",
            # rotationPeriod is a Duration, serialized as a string (e.g. "2592000s")
            "rotation": {"nextRotationTime": "2026-09-18T00:00:00Z", "rotationPeriod": "2592000s"},
        }]
        check = SecretNoRotation()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0

    async def test_no_secrets_no_findings(self, runner):
        runner.run.return_value = []
        check = SecretNoRotation()
        findings = await check.execute(PROJECT, runner)
        assert findings == []

    async def test_list_secrets_exception_is_swallowed(self, runner):
        # _list_secrets() catches exceptions internally and returns [].
        runner.run = AsyncMock(side_effect=Exception("PERMISSION_DENIED"))
        check = SecretNoRotation()
        findings = await check.execute(PROJECT, runner)
        assert findings == []


@pytest.mark.asyncio
class TestSecretPublicAccess:

    async def test_flags_allusers_binding(self, runner):
        runner.run.side_effect = [
            # 1. secrets list
            [{"name": f"projects/{PROJECT}/secrets/api-key"}],
            # 2. get-iam-policy
            {
                "bindings": [
                    {"role": "roles/secretmanager.secretAccessor", "members": ["allUsers"]},
                ],
                "etag": "BwYqx2X8p3E=",
            },
        ]
        check = SecretPublicAccess()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "SM-002"
        assert findings[0].severity == "critical"
        assert findings[0].resource_name == "secrets/api-key"
        assert "allUsers" in findings[0].current_state

    async def test_flags_allauthenticatedusers_binding(self, runner):
        runner.run.side_effect = [
            [{"name": f"projects/{PROJECT}/secrets/token"}],
            {
                "bindings": [
                    {"role": "roles/secretmanager.secretAccessor", "members": ["allAuthenticatedUsers"]},
                ],
            },
        ]
        check = SecretPublicAccess()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1

    async def test_passes_scoped_iam_policy(self, runner):
        runner.run.side_effect = [
            [{"name": f"projects/{PROJECT}/secrets/db-password"}],
            {
                "bindings": [
                    {
                        "role": "roles/secretmanager.secretAccessor",
                        "members": ["user:alice@example.com", "serviceAccount:svc@p.iam.gserviceaccount.com"],
                    },
                ],
            },
        ]
        check = SecretPublicAccess()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0

    async def test_get_iam_policy_failure_is_skipped(self, runner):
        runner.run.side_effect = [
            [{"name": f"projects/{PROJECT}/secrets/db-password"}],
            Exception("secret not found"),
        ]
        check = SecretPublicAccess()
        findings = await check.execute(PROJECT, runner)
        assert findings == []


@pytest.mark.asyncio
class TestSecretNoCMEK:

    async def test_flags_automatic_replication_without_cmek(self, runner):
        runner.run.return_value = [{
            "name": f"projects/{PROJECT}/secrets/db-password",
            "replication": {"automatic": {}},
        }]
        check = SecretNoCMEK()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "SM-003"
        assert findings[0].severity == "low"

    async def test_passes_automatic_replication_with_cmek(self, runner):
        runner.run.return_value = [{
            "name": f"projects/{PROJECT}/secrets/db-password",
            "replication": {
                "automatic": {
                    "customerManagedEncryption": {
                        "kmsKeyName": "projects/p/locations/global/keyRings/kr/cryptoKeys/k",
                    },
                },
            },
        }]
        check = SecretNoCMEK()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0

    async def test_passes_user_managed_replication_with_cmek(self, runner):
        runner.run.return_value = [{
            "name": f"projects/{PROJECT}/secrets/db-password",
            "replication": {
                "userManaged": {
                    "replicas": [
                        {
                            "location": "us-central1",
                            "customerManagedEncryption": {
                                "kmsKeyName": "projects/p/locations/us-central1/keyRings/kr/cryptoKeys/k",
                            },
                        },
                    ],
                },
            },
        }]
        check = SecretNoCMEK()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0

    async def test_flags_user_managed_replication_without_cmek(self, runner):
        runner.run.return_value = [{
            "name": f"projects/{PROJECT}/secrets/db-password",
            "replication": {
                "userManaged": {
                    "replicas": [{"location": "us-central1"}],
                },
            },
        }]
        check = SecretNoCMEK()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1


@pytest.mark.asyncio
class TestSecretAutomaticReplicationGlobal:

    async def test_flags_automatic_replication(self, runner):
        runner.run.return_value = [{
            "name": f"projects/{PROJECT}/secrets/db-password",
            "replication": {"automatic": {}},
        }]
        check = SecretAutomaticReplicationGlobal()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "SM-004"
        assert findings[0].resource_name == "secrets/db-password"

    async def test_passes_user_managed_replication(self, runner):
        runner.run.return_value = [{
            "name": f"projects/{PROJECT}/secrets/db-password",
            "replication": {"userManaged": {"replicas": [{"location": "us-central1"}]}},
        }]
        check = SecretAutomaticReplicationGlobal()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


@pytest.mark.asyncio
class TestSecretManyVersions:

    async def test_flags_when_enabled_versions_above_threshold(self, runner):
        # THRESHOLD is 10 -> 11 ENABLED versions must trigger.
        versions = [{"name": f".../versions/{i}", "state": "ENABLED"} for i in range(1, 12)]
        runner.run.side_effect = [
            [{"name": f"projects/{PROJECT}/secrets/db-password"}],
            versions,
        ]
        check = SecretManyVersions()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "SM-005"
        assert "11 enabled versions" in findings[0].current_state

    async def test_passes_at_exact_threshold_boundary(self, runner):
        # Exactly 10 ENABLED versions: condition is "> THRESHOLD", not ">=".
        versions = [{"name": f".../versions/{i}", "state": "ENABLED"} for i in range(1, 11)]
        runner.run.side_effect = [
            [{"name": f"projects/{PROJECT}/secrets/db-password"}],
            versions,
        ]
        check = SecretManyVersions()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0

    async def test_disabled_and_destroyed_versions_not_counted(self, runner):
        versions = (
            [{"name": f".../versions/{i}", "state": "ENABLED"} for i in range(1, 4)]
            + [{"name": f".../versions/{i}", "state": "DISABLED"} for i in range(4, 10)]
            + [{"name": ".../versions/10", "state": "DESTROYED"}]
        )
        runner.run.side_effect = [
            [{"name": f"projects/{PROJECT}/secrets/db-password"}],
            versions,
        ]
        check = SecretManyVersions()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0

    async def test_versions_list_failure_is_skipped(self, runner):
        runner.run.side_effect = [
            [{"name": f"projects/{PROJECT}/secrets/db-password"}],
            Exception("boom"),
        ]
        check = SecretManyVersions()
        findings = await check.execute(PROJECT, runner)
        assert findings == []


@pytest.mark.asyncio
class TestSecretLastUpdatedLongAgo:

    async def test_flags_stale_secret_past_one_year(self, runner):
        old = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat().replace("+00:00", "Z")
        runner.run.side_effect = [
            [{"name": f"projects/{PROJECT}/secrets/legacy-key", "createTime": old}],
            [],  # no versions returned -> falls back to createTime
        ]
        check = SecretLastUpdatedLongAgo()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "SM-006"
        assert findings[0].severity == "medium"
        assert findings[0].resource_name == "secrets/legacy-key"

    async def test_passes_secret_created_recently(self, runner):
        recent = (datetime.now(timezone.utc) - timedelta(days=364)).isoformat().replace("+00:00", "Z")
        runner.run.side_effect = [
            [{"name": f"projects/{PROJECT}/secrets/new-key", "createTime": recent}],
        ]
        check = SecretLastUpdatedLongAgo()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0

    async def test_passes_old_secret_with_recent_version(self, runner):
        # Secret metadata is old, but a fresh version means it was effectively rotated.
        old = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat().replace("+00:00", "Z")
        recent_version = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat().replace("+00:00", "Z")
        runner.run.side_effect = [
            [{"name": f"projects/{PROJECT}/secrets/legacy-key", "createTime": old}],
            [{"name": ".../versions/2", "state": "ENABLED", "createTime": recent_version}],
        ]
        check = SecretLastUpdatedLongAgo()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0

    async def test_skips_secret_with_missing_create_time(self, runner):
        runner.run.return_value = [{"name": f"projects/{PROJECT}/secrets/weird-key"}]
        check = SecretLastUpdatedLongAgo()
        findings = await check.execute(PROJECT, runner)
        assert findings == []


@pytest.mark.asyncio
class TestSecretNoLabels:

    async def test_flags_secret_with_no_labels(self, runner):
        runner.run.return_value = [{
            "name": f"projects/{PROJECT}/secrets/db-password",
            "labels": {},
        }]
        check = SecretNoLabels()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "SM-007"
        assert "none" in findings[0].current_state

    async def test_flags_secret_with_unrelated_labels(self, runner):
        runner.run.return_value = [{
            "name": f"projects/{PROJECT}/secrets/db-password",
            "labels": {"cost-center": "1234"},
        }]
        check = SecretNoLabels()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1

    async def test_passes_secret_with_team_label(self, runner):
        runner.run.return_value = [{
            "name": f"projects/{PROJECT}/secrets/db-password",
            "labels": {"team": "payments"},
        }]
        check = SecretNoLabels()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0

    async def test_passes_secret_with_owner_label(self, runner):
        runner.run.return_value = [{
            "name": f"projects/{PROJECT}/secrets/db-password",
            "labels": {"owner": "sre-team"},
        }]
        check = SecretNoLabels()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0
