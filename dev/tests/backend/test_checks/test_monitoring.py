"""Tests for Monitoring check modules (MON-002 through MON-012).

MON-001 and MON-007 were retired in favor of IAM-013 / BIL-001 respectively
(see comments in monitoring_checks.py), so this module covers the 10
remaining checks: MON-002, 003, 004, 005, 006, 008, 009, 010, 011, 012.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from backend.checks.monitoring.monitoring_checks import (
    CustomDashboardsNotConfigured,
    ErrorReportingNotUsed,
    LogRetentionDefault,
    LogSinksNotConfigured,
    NoAlertPolicies,
    NoNotificationChannels,
    NoSLOsDefined,
    PublicLogSink,
    TraceNotEnabled,
    UptimeChecksNotConfigured,
)

PROJECT = "test-project"


@pytest.fixture
def runner():
    r = MagicMock()
    r.run = AsyncMock(return_value=[])
    return r


@pytest.mark.asyncio
class TestNoAlertPolicies:

    async def test_flags_no_policies(self, runner):
        runner.run.return_value = []
        check = NoAlertPolicies()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "MON-002"
        assert findings[0].severity == "high"
        assert findings[0].resource_name == f"projects/{PROJECT}"

    async def test_passes_with_policies(self, runner):
        runner.run.return_value = [{"name": f"projects/{PROJECT}/alertPolicies/123", "displayName": "High CPU"}]
        check = NoAlertPolicies()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0

    async def test_api_error_still_flags_as_unverified(self, runner):
        runner.run = AsyncMock(side_effect=Exception("alpha API not available"))
        check = NoAlertPolicies()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert "Could not verify" in findings[0].current_state


@pytest.mark.asyncio
class TestNoNotificationChannels:

    async def test_flags_no_channels(self, runner):
        runner.run.return_value = []
        check = NoNotificationChannels()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "MON-003"
        assert findings[0].severity == "medium"

    async def test_passes_with_channels(self, runner):
        runner.run.return_value = [{"name": f"projects/{PROJECT}/notificationChannels/1", "type": "email"}]
        check = NoNotificationChannels()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0

    async def test_api_error_still_flags_as_unverified(self, runner):
        runner.run = AsyncMock(side_effect=Exception("boom"))
        check = NoNotificationChannels()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert "Could not verify" in findings[0].current_state


@pytest.mark.asyncio
class TestLogSinksNotConfigured:

    async def test_flags_when_only_default_sinks_exist(self, runner):
        runner.run.return_value = [
            {"name": "_Default", "destination": f"logging.googleapis.com/projects/{PROJECT}/logs"},
            {"name": "_Required", "destination": f"logging.googleapis.com/projects/{PROJECT}/logs"},
        ]
        check = LogSinksNotConfigured()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "MON-004"
        assert findings[0].severity == "medium"

    async def test_passes_with_a_custom_sink(self, runner):
        runner.run.return_value = [
            {"name": "_Default", "destination": "logging.googleapis.com/..."},
            {"name": "export-to-bq", "destination": f"bigquery.googleapis.com/projects/{PROJECT}/datasets/audit"},
        ]
        check = LogSinksNotConfigured()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0

    async def test_flags_no_sinks_at_all(self, runner):
        runner.run.return_value = []
        check = LogSinksNotConfigured()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1

    async def test_api_error_returns_no_findings(self, runner):
        # Unlike MON-002/003, MON-004 logs and swallows the error silently.
        runner.run = AsyncMock(side_effect=Exception("boom"))
        check = LogSinksNotConfigured()
        findings = await check.execute(PROJECT, runner)
        assert findings == []


@pytest.mark.asyncio
class TestUptimeChecksNotConfigured:

    async def test_flags_no_uptime_checks(self, runner):
        runner.run.return_value = []
        check = UptimeChecksNotConfigured()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "MON-005"
        assert findings[0].severity == "low"

    async def test_passes_with_uptime_checks(self, runner):
        runner.run.return_value = [{"name": f"projects/{PROJECT}/uptimeCheckConfigs/1", "displayName": "homepage"}]
        check = UptimeChecksNotConfigured()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0

    async def test_api_error_is_silently_ignored(self, runner):
        # UptimeChecks (unlike Alert Policies/Notification Channels) treats
        # "API unavailable" as "nothing to report", not as a finding.
        runner.run = AsyncMock(side_effect=Exception("uptime API not enabled"))
        check = UptimeChecksNotConfigured()
        findings = await check.execute(PROJECT, runner)
        assert findings == []


@pytest.mark.asyncio
class TestLogRetentionDefault:
    """MON-006. Compliance note: compliance_refs tags this check as CERT_IN
    evidence, but CERT-In's log retention requirement is 180 days while
    THRESHOLD_DAYS here is 90 (see final report for details). Tests assert
    against the check's own THRESHOLD_DAYS rather than hard-coding a number,
    so they stay correct regardless of which value is "right".
    """

    async def test_flags_bucket_below_threshold(self, runner):
        check = LogRetentionDefault()
        runner.run.return_value = [{
            "name": f"projects/{PROJECT}/locations/global/buckets/_Default",
            "retentionDays": check.THRESHOLD_DAYS - 1,
        }]
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "MON-006"
        assert findings[0].severity == "medium"
        assert findings[0].resource_name == "logging-buckets/_Default"

    async def test_passes_bucket_at_exact_threshold(self, runner):
        # Boundary: condition is "days < THRESHOLD_DAYS", so being exactly at
        # threshold must NOT be flagged.
        check = LogRetentionDefault()
        runner.run.return_value = [{
            "name": f"projects/{PROJECT}/locations/global/buckets/_Default",
            "retentionDays": check.THRESHOLD_DAYS,
        }]
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0

    async def test_flags_bucket_with_missing_retention_days(self, runner):
        # retentionDays absent -> code defaults to 30, which is below any
        # sane threshold.
        check = LogRetentionDefault()
        runner.run.return_value = [{
            "name": f"projects/{PROJECT}/locations/global/buckets/custom-bucket",
        }]
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert "retentionDays=30" in findings[0].current_state

    async def test_no_findings_when_buckets_list_fails(self, runner):
        runner.run = AsyncMock(side_effect=Exception("boom"))
        check = LogRetentionDefault()
        findings = await check.execute(PROJECT, runner)
        assert findings == []


@pytest.mark.asyncio
class TestCustomDashboardsNotConfigured:

    async def test_flags_no_dashboards(self, runner):
        runner.run.return_value = []
        check = CustomDashboardsNotConfigured()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "MON-008"
        assert findings[0].severity == "low"

    async def test_passes_with_dashboards(self, runner):
        runner.run.return_value = [{"name": f"projects/{PROJECT}/dashboards/1", "displayName": "Overview"}]
        check = CustomDashboardsNotConfigured()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0

    async def test_api_error_is_silently_ignored(self, runner):
        runner.run = AsyncMock(side_effect=Exception("dashboards API unavailable"))
        check = CustomDashboardsNotConfigured()
        findings = await check.execute(PROJECT, runner)
        assert findings == []


@pytest.mark.asyncio
class TestErrorReportingNotUsed:

    async def test_flags_when_api_not_enabled(self, runner):
        runner.run.return_value = []
        check = ErrorReportingNotUsed()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "MON-009"
        assert findings[0].severity == "low"
        assert "clouderrorreporting.googleapis.com" in findings[0].fix_command

    async def test_passes_when_api_enabled(self, runner):
        runner.run.return_value = [{
            "config": {"name": "clouderrorreporting.googleapis.com"},
            "state": "ENABLED",
        }]
        check = ErrorReportingNotUsed()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0

    async def test_api_error_is_silently_ignored(self, runner):
        runner.run = AsyncMock(side_effect=Exception("boom"))
        check = ErrorReportingNotUsed()
        findings = await check.execute(PROJECT, runner)
        assert findings == []


@pytest.mark.asyncio
class TestTraceNotEnabled:

    async def test_flags_when_api_not_enabled(self, runner):
        runner.run.return_value = []
        check = TraceNotEnabled()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "MON-010"
        assert findings[0].severity == "low"
        assert "cloudtrace.googleapis.com" in findings[0].fix_command

    async def test_passes_when_api_enabled(self, runner):
        runner.run.return_value = [{
            "config": {"name": "cloudtrace.googleapis.com"},
            "state": "ENABLED",
        }]
        check = TraceNotEnabled()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0

    async def test_api_error_is_silently_ignored(self, runner):
        runner.run = AsyncMock(side_effect=Exception("boom"))
        check = TraceNotEnabled()
        findings = await check.execute(PROJECT, runner)
        assert findings == []


@pytest.mark.asyncio
class TestNoSLOsDefined:

    async def test_flags_when_no_services_monitored(self, runner):
        runner.run.return_value = []  # no monitoring services at all
        check = NoSLOsDefined()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "MON-011"
        assert findings[0].severity == "low"

    async def test_flags_when_service_has_no_slos(self, runner):
        runner.run.side_effect = [
            [{"name": f"projects/{PROJECT}/services/checkout-svc"}],
            [],  # no SLOs for that service
        ]
        check = NoSLOsDefined()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1

    async def test_passes_when_a_service_has_slos(self, runner):
        runner.run.side_effect = [
            [{"name": f"projects/{PROJECT}/services/checkout-svc"}],
            [{"name": f"projects/{PROJECT}/services/checkout-svc/serviceLevelObjectives/availability"}],
        ]
        check = NoSLOsDefined()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0

    async def test_services_list_failure_returns_no_findings(self, runner):
        runner.run = AsyncMock(side_effect=Exception("monitoring services API error"))
        check = NoSLOsDefined()
        findings = await check.execute(PROJECT, runner)
        assert findings == []


@pytest.mark.asyncio
class TestPublicLogSink:
    """MON-012.

    A GCS bucket name is global and encodes no project, so the check has to
    ask which buckets the scanned project owns rather than pattern-match the
    destination string. Each test therefore feeds two responses: the sink
    list, then the project's bucket list.
    """

    async def test_flags_bucket_the_project_does_not_own(self, runner):
        runner.run.side_effect = [
            [{
                "name": "vendor-export-sink",
                "destination": "storage.googleapis.com/acmecorp-security-vendor-bucket",
            }],
            [{"name": "central-audit-logs-bucket"}],
        ]
        findings = await PublicLogSink().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "MON-012"
        assert findings[0].severity == "high"
        assert findings[0].resource_name == "sinks/vendor-export-sink"

    async def test_ignores_non_gcs_destinations(self, runner):
        # Scope is GCS-only per the check title; the bucket list is never
        # fetched, so a single response is all the check consumes.
        runner.run.return_value = [{
            "name": "bq-export-sink",
            "destination": "bigquery.googleapis.com/projects/some-other-project/datasets/audit",
        }]
        findings = await PublicLogSink().execute(PROJECT, runner)
        assert len(findings) == 0

    async def test_same_project_bucket_is_not_flagged(self, runner):
        """The bucket name shares nothing with the project ID, and is fine.

        This is the common case, and the previous substring heuristic
        reported every one of them as a HIGH-severity external sink.
        """
        runner.run.side_effect = [
            [{
                "name": "internal-audit-export",
                "destination": "storage.googleapis.com/central-audit-logs-bucket",
            }],
            [{"name": "central-audit-logs-bucket"}, {"name": "other-bucket"}],
        ]
        findings = await PublicLogSink().execute(PROJECT, runner)
        assert len(findings) == 0

    async def test_storage_api_resource_form_is_understood(self, runner):
        """Sinks are also seen carrying the Storage API's own resource name."""
        runner.run.side_effect = [
            [{
                "name": "internal-audit-export",
                "destination": "storage.googleapis.com/projects/_/buckets/central-audit-logs-bucket",
            }],
            [{"name": "central-audit-logs-bucket"}],
        ]
        findings = await PublicLogSink().execute(PROJECT, runner)
        assert len(findings) == 0

    async def test_unlistable_buckets_report_nothing(self, runner):
        """Without the bucket list, own and external are indistinguishable."""
        runner.run.side_effect = [
            [{
                "name": "internal-audit-export",
                "destination": "storage.googleapis.com/central-audit-logs-bucket",
            }],
            Exception("storage.buckets.list denied"),
        ]
        findings = await PublicLogSink().execute(PROJECT, runner)
        assert findings == []
