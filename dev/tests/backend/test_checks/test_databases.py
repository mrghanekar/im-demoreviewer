"""Tests for Cloud SQL / database check modules (DB-001 through DB-016).

Fixtures use the shape returned by `gcloud sql instances list --format=json`.
Note that several numeric-looking settings fields (dataDiskSizeGb,
settingsVersion) come back from the real API as STRINGS (int64-as-string),
even though none of the checks below currently branch on those fields.
They're kept as strings here for realism.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from backend.checks.databases.cloudsql_checks import (
    CloudSQLIAMAuthDisabled,
    SQLAuditLogging,
    SQLAuthNetworks,
    SQLDeletionProtection,
    SQLMaintenanceWindow,
    SQLNoAutomatedBackups,
    SQLNoCMEK,
    SQLNoHA,
    SQLNoPointInTimeRecovery,
    SQLNoReadReplica,
    SQLNoSSL,
    SQLOldVersion,
    SQLPasswordPolicy,
    SQLPublicIP,
    SQLQueryInsightsDisabled,
    SQLStorageAutoResize,
)

PROJECT = "test-project"


@pytest.fixture
def runner():
    r = MagicMock()
    r.run = AsyncMock(return_value=[])
    return r


def make_instance(**overrides):
    """A baseline, fully-compliant Cloud SQL instance in `instances list` shape."""
    instance = {
        "backendType": "SECOND_GEN",
        "connectionName": "test-project:us-central1:db-1",
        "databaseVersion": "POSTGRES_14",
        "gceZone": "us-central1-a",
        "instanceType": "CLOUD_SQL_INSTANCE",
        "ipAddresses": [
            {"ipAddress": "10.1.2.3", "type": "PRIVATE"},
        ],
        "kind": "sql#instance",
        "name": "db-1",
        "project": "test-project",
        "region": "us-central1",
        "diskEncryptionConfiguration": {
            "kind": "sql#diskEncryptionConfiguration",
            "kmsKeyName": "projects/test-project/locations/us-central1/keyRings/kr/cryptoKeys/ck",
        },
        "settings": {
            "activationPolicy": "ALWAYS",
            "availabilityType": "REGIONAL",
            "backupConfiguration": {
                "enabled": True,
                "kind": "sql#backupConfiguration",
                "pointInTimeRecoveryEnabled": True,
                "startTime": "03:00",
                "transactionLogRetentionDays": 7,
            },
            "dataDiskSizeGb": "10",  # int64-as-string, as returned by the real API
            "dataDiskType": "PD_SSD",
            "databaseFlags": [
                {"name": "cloudsql.enable_pgaudit", "value": "on"},
                {"name": "cloudsql.iam_authentication", "value": "on"},
            ],
            "insightsConfig": {"queryInsightsEnabled": True},
            "ipConfiguration": {
                "authorizedNetworks": [],
                "ipv4Enabled": False,
                "requireSsl": True,
            },
            "kind": "sql#settings",
            "maintenanceWindow": {"day": 7, "hour": 3, "kind": "sql#maintenanceWindow"},
            "passwordValidationPolicy": {
                "enablePasswordPolicy": True,
                "minLength": 12,
            },
            "pricingPlan": "PER_USE",
            "settingsVersion": "5",  # int64-as-string, as returned by the real API
            "storageAutoResize": True,
            "tier": "db-custom-2-8192",
        },
        "state": "RUNNABLE",
    }
    instance.update(overrides)
    return instance


@pytest.mark.asyncio
class TestSQLPublicIP:
    """DB-001"""

    async def test_flags_instance_with_public_primary_ip(self, runner):
        instance = make_instance(
            ipAddresses=[
                {"ipAddress": "34.123.45.67", "type": "PRIMARY"},
                {"ipAddress": "10.1.2.3", "type": "PRIVATE"},
            ]
        )
        runner.run.return_value = [instance]
        check = SQLPublicIP()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "DB-001"
        assert findings[0].severity == "critical"
        assert findings[0].resource_name == "sql/db-1"
        assert "34.123.45.67" in findings[0].current_state

    async def test_passes_instance_with_only_private_ip(self, runner):
        instance = make_instance(ipAddresses=[{"ipAddress": "10.1.2.3", "type": "PRIVATE"}])
        runner.run.return_value = [instance]
        findings = await SQLPublicIP().execute(PROJECT, runner)
        assert findings == []

    async def test_handles_non_list_result(self, runner):
        # e.g. gcloud returning an error object instead of a JSON array
        runner.run.return_value = {"error": "PERMISSION_DENIED"}
        findings = await SQLPublicIP().execute(PROJECT, runner)
        assert findings == []


@pytest.mark.asyncio
class TestSQLNoSSL:
    """DB-002"""

    async def test_flags_when_ssl_not_required(self, runner):
        instance = make_instance()
        instance["settings"]["ipConfiguration"] = {
            "authorizedNetworks": [],
            "ipv4Enabled": True,
            "requireSsl": False,
        }
        runner.run.return_value = [instance]
        findings = await SQLNoSSL().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "DB-002"
        assert findings[0].severity == "high"
        assert findings[0].resource_name == "sql/db-1"

    async def test_passes_when_require_ssl_true(self, runner):
        instance = make_instance()  # requireSsl True in baseline
        runner.run.return_value = [instance]
        findings = await SQLNoSSL().execute(PROJECT, runner)
        assert findings == []

    async def test_passes_when_ssl_mode_encrypted_only(self, runner):
        instance = make_instance()
        instance["settings"]["ipConfiguration"] = {
            "authorizedNetworks": [],
            "requireSsl": False,
            "sslMode": "ENCRYPTED_ONLY",
        }
        runner.run.return_value = [instance]
        findings = await SQLNoSSL().execute(PROJECT, runner)
        assert findings == []

    async def test_passes_when_client_certificate_required(self, runner):
        """The strictest sslMode used to be reported as "SSL not required"."""
        instance = make_instance()
        instance["settings"]["ipConfiguration"] = {
            "authorizedNetworks": [],
            "requireSsl": False,
            "sslMode": "TRUSTED_CLIENT_CERTIFICATE_REQUIRED",
        }
        runner.run.return_value = [instance]
        findings = await SQLNoSSL().execute(PROJECT, runner)
        assert findings == []

    async def test_flags_allow_unencrypted_ssl_mode(self, runner):
        instance = make_instance()
        instance["settings"]["ipConfiguration"] = {
            "authorizedNetworks": [],
            "requireSsl": False,
            "sslMode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED",
        }
        runner.run.return_value = [instance]
        findings = await SQLNoSSL().execute(PROJECT, runner)
        assert len(findings) == 1


@pytest.mark.asyncio
class TestSQLNoAutomatedBackups:
    """DB-003"""

    async def test_flags_when_backups_disabled(self, runner):
        instance = make_instance()
        instance["settings"]["backupConfiguration"]["enabled"] = False
        runner.run.return_value = [instance]
        findings = await SQLNoAutomatedBackups().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "DB-003"
        assert findings[0].severity == "high"
        assert findings[0].resource_name == "sql/db-1"

    async def test_passes_when_backups_enabled(self, runner):
        runner.run.return_value = [make_instance()]
        findings = await SQLNoAutomatedBackups().execute(PROJECT, runner)
        assert findings == []


@pytest.mark.asyncio
class TestSQLNoHA:
    """DB-004"""

    async def test_flags_zonal_primary_instance(self, runner):
        instance = make_instance()
        instance["settings"]["availabilityType"] = "ZONAL"
        runner.run.return_value = [instance]
        findings = await SQLNoHA().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "DB-004"
        assert findings[0].resource_name == "sql/db-1"
        assert "ZONAL" in findings[0].current_state

    async def test_passes_regional_primary_instance(self, runner):
        runner.run.return_value = [make_instance()]  # REGIONAL in baseline
        findings = await SQLNoHA().execute(PROJECT, runner)
        assert findings == []

    async def test_ignores_read_replica_even_if_zonal(self, runner):
        replica = make_instance(name="db-1-replica", instanceType="READ_REPLICA_INSTANCE")
        replica["settings"]["availabilityType"] = "ZONAL"
        runner.run.return_value = [replica]
        findings = await SQLNoHA().execute(PROJECT, runner)
        assert findings == []


@pytest.mark.asyncio
class TestSQLAuthNetworks:
    """DB-005"""

    async def test_flags_open_authorized_network(self, runner):
        instance = make_instance()
        instance["settings"]["ipConfiguration"]["authorizedNetworks"] = [
            {"name": "open", "value": "0.0.0.0/0"}
        ]
        runner.run.return_value = [instance]
        findings = await SQLAuthNetworks().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "DB-005"
        assert findings[0].severity == "critical"
        assert findings[0].resource_name == "sql/db-1"

    async def test_passes_restricted_authorized_network(self, runner):
        instance = make_instance()
        instance["settings"]["ipConfiguration"]["authorizedNetworks"] = [
            {"name": "office", "value": "203.0.113.0/24"}
        ]
        runner.run.return_value = [instance]
        findings = await SQLAuthNetworks().execute(PROJECT, runner)
        assert findings == []

    async def test_passes_no_authorized_networks(self, runner):
        runner.run.return_value = [make_instance()]  # empty list in baseline
        findings = await SQLAuthNetworks().execute(PROJECT, runner)
        assert findings == []


@pytest.mark.asyncio
class TestSQLNoPointInTimeRecovery:
    """DB-006"""

    async def test_flags_backups_enabled_but_no_pitr(self, runner):
        instance = make_instance()
        instance["settings"]["backupConfiguration"]["pointInTimeRecoveryEnabled"] = False
        runner.run.return_value = [instance]
        findings = await SQLNoPointInTimeRecovery().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "DB-006"
        assert findings[0].resource_name == "sql/db-1"

    async def test_passes_when_pitr_enabled(self, runner):
        runner.run.return_value = [make_instance()]  # pointInTimeRecoveryEnabled True
        findings = await SQLNoPointInTimeRecovery().execute(PROJECT, runner)
        assert findings == []

    async def test_no_finding_when_backups_disabled(self, runner):
        # Current behaviour: PITR is only evaluated when backups are enabled at all;
        # DB-003 (SQLNoAutomatedBackups) is responsible for flagging the disabled-backups
        # case, so DB-006 intentionally stays silent here to avoid double-reporting.
        instance = make_instance()
        instance["settings"]["backupConfiguration"]["enabled"] = False
        instance["settings"]["backupConfiguration"]["pointInTimeRecoveryEnabled"] = False
        runner.run.return_value = [instance]
        findings = await SQLNoPointInTimeRecovery().execute(PROJECT, runner)
        assert findings == []


@pytest.mark.asyncio
class TestSQLMaintenanceWindow:
    """DB-007"""

    async def test_flags_missing_maintenance_window(self, runner):
        instance = make_instance()
        instance["settings"]["maintenanceWindow"] = {}
        runner.run.return_value = [instance]
        findings = await SQLMaintenanceWindow().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "DB-007"
        assert findings[0].resource_name == "sql/db-1"

    async def test_passes_when_maintenance_window_set(self, runner):
        runner.run.return_value = [make_instance()]
        findings = await SQLMaintenanceWindow().execute(PROJECT, runner)
        assert findings == []


@pytest.mark.asyncio
class TestSQLOldVersion:
    """DB-008"""

    async def test_flags_old_mysql_version(self, runner):
        instance = make_instance(databaseVersion="MYSQL_5_7")
        runner.run.return_value = [instance]
        findings = await SQLOldVersion().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "DB-008"
        assert "MYSQL_5_7" in findings[0].current_state
        assert findings[0].resource_name == "sql/db-1"

    async def test_passes_current_version(self, runner):
        runner.run.return_value = [make_instance(databaseVersion="POSTGRES_15")]
        findings = await SQLOldVersion().execute(PROJECT, runner)
        assert findings == []


@pytest.mark.asyncio
class TestSQLNoCMEK:
    """DB-009"""

    async def test_flags_google_managed_encryption(self, runner):
        instance = make_instance()
        del instance["diskEncryptionConfiguration"]
        runner.run.return_value = [instance]
        findings = await SQLNoCMEK().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "DB-009"
        assert findings[0].resource_name == "sql/db-1"

    async def test_passes_with_cmek_key(self, runner):
        runner.run.return_value = [make_instance()]
        findings = await SQLNoCMEK().execute(PROJECT, runner)
        assert findings == []


@pytest.mark.asyncio
class TestSQLQueryInsightsDisabled:
    """DB-010"""

    async def test_flags_disabled_query_insights(self, runner):
        instance = make_instance()
        instance["settings"]["insightsConfig"] = {"queryInsightsEnabled": False}
        runner.run.return_value = [instance]
        findings = await SQLQueryInsightsDisabled().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "DB-010"
        assert findings[0].resource_name == "sql/db-1"

    async def test_passes_enabled_query_insights(self, runner):
        runner.run.return_value = [make_instance()]
        findings = await SQLQueryInsightsDisabled().execute(PROJECT, runner)
        assert findings == []


@pytest.mark.asyncio
class TestSQLNoReadReplica:
    """DB-011"""

    async def test_flags_primary_without_replica(self, runner):
        runner.run.return_value = [make_instance()]
        findings = await SQLNoReadReplica().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "DB-011"
        assert findings[0].resource_name == "sql/db-1"

    async def test_passes_primary_with_replica(self, runner):
        primary = make_instance()
        replica = make_instance(
            name="db-1-replica",
            instanceType="READ_REPLICA_INSTANCE",
            masterInstanceName="db-1",
        )
        runner.run.return_value = [primary, replica]
        findings = await SQLNoReadReplica().execute(PROJECT, runner)
        assert findings == []


@pytest.mark.asyncio
class TestSQLStorageAutoResize:
    """DB-012"""

    async def test_flags_auto_resize_disabled(self, runner):
        instance = make_instance()
        instance["settings"]["storageAutoResize"] = False
        runner.run.return_value = [instance]
        findings = await SQLStorageAutoResize().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "DB-012"
        assert findings[0].resource_name == "sql/db-1"

    async def test_passes_auto_resize_enabled(self, runner):
        runner.run.return_value = [make_instance()]
        findings = await SQLStorageAutoResize().execute(PROJECT, runner)
        assert findings == []


@pytest.mark.asyncio
class TestSQLPasswordPolicy:
    """DB-013"""

    async def test_flags_missing_password_policy(self, runner):
        instance = make_instance()
        instance["settings"]["passwordValidationPolicy"] = {}
        runner.run.return_value = [instance]
        findings = await SQLPasswordPolicy().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "DB-013"
        assert findings[0].resource_name == "sql/db-1"

    async def test_passes_password_policy_enabled(self, runner):
        runner.run.return_value = [make_instance()]
        findings = await SQLPasswordPolicy().execute(PROJECT, runner)
        assert findings == []


@pytest.mark.asyncio
class TestSQLAuditLogging:
    """DB-014"""

    async def test_flags_postgres_without_pgaudit(self, runner):
        instance = make_instance(databaseVersion="POSTGRES_14")
        instance["settings"]["databaseFlags"] = []
        runner.run.return_value = [instance]
        findings = await SQLAuditLogging().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "DB-014"
        assert "pgAudit" in findings[0].current_state
        assert findings[0].resource_name == "sql/db-1"

    async def test_passes_postgres_with_pgaudit_on(self, runner):
        runner.run.return_value = [make_instance()]  # pgaudit=on in baseline
        findings = await SQLAuditLogging().execute(PROJECT, runner)
        assert findings == []

    async def test_flags_mysql_without_audit_log(self, runner):
        instance = make_instance(databaseVersion="MYSQL_8_0")
        instance["settings"]["databaseFlags"] = []
        runner.run.return_value = [instance]
        findings = await SQLAuditLogging().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "DB-014"
        assert "MySQL" in findings[0].current_state

    async def test_passes_mysql_with_audit_log_on(self, runner):
        # NOTE: MySQL's audit_log flag value is the upper-case enum "ON" (unlike
        # Postgres's lower-case "on" for cloudsql.enable_pgaudit) -- this matches
        # the real Cloud SQL database flag semantics for each engine.
        instance = make_instance(databaseVersion="MYSQL_8_0")
        instance["settings"]["databaseFlags"] = [{"name": "audit_log", "value": "ON"}]
        runner.run.return_value = [instance]
        findings = await SQLAuditLogging().execute(PROJECT, runner)
        assert findings == []


@pytest.mark.asyncio
class TestSQLDeletionProtection:
    """DB-015"""

    async def test_flags_deletion_protection_disabled(self, runner):
        instance = make_instance()
        instance["settings"]["deletionProtectionEnabled"] = False
        runner.run.return_value = [instance]
        findings = await SQLDeletionProtection().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "DB-015"
        assert findings[0].resource_name == "sql/db-1"

    async def test_passes_deletion_protection_enabled(self, runner):
        instance = make_instance()
        instance["settings"]["deletionProtectionEnabled"] = True
        runner.run.return_value = [instance]
        findings = await SQLDeletionProtection().execute(PROJECT, runner)
        assert findings == []


@pytest.mark.asyncio
class TestCloudSQLIAMAuthDisabled:
    """DB-016"""

    async def test_flags_iam_auth_not_on(self, runner):
        instance = make_instance()
        instance["settings"]["databaseFlags"] = [
            {"name": "cloudsql.enable_pgaudit", "value": "on"},
        ]
        runner.run.return_value = [instance]
        findings = await CloudSQLIAMAuthDisabled().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "DB-016"
        assert findings[0].resource_name == "sql/db-1"

    async def test_passes_iam_auth_on(self, runner):
        runner.run.return_value = [make_instance()]  # cloudsql.iam_authentication=on in baseline
        findings = await CloudSQLIAMAuthDisabled().execute(PROJECT, runner)
        assert findings == []

    async def test_no_instances_returns_empty(self, runner):
        runner.run.return_value = []
        findings = await CloudSQLIAMAuthDisabled().execute(PROJECT, runner)
        assert findings == []
