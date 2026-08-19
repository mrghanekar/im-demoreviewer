"""Monitoring, logging, and alerting checks.

Checks: MON-001 through MON-010
"""

import logging
from typing import Any

from backend.checks.base import BaseCheck
from backend.core.models import Category, CheckResult, Severity, ServiceCategory

logger = logging.getLogger(__name__)


# MON-001 (AuditLogsDisabled) removed — IAM-013 (DataAccessAuditLogsDisabled in
# backend/checks/iam/role_bindings.py) is the canonical check. MON-001 fired
# when `auditConfigs` was entirely empty, which is a strict subset of when
# IAM-013 fires (any sensitive service missing DATA_READ/DATA_WRITE).


class NoAlertPolicies(BaseCheck):
    id = "MON-002"
    title = "No alerting policies configured"
    description = "Alerting policies notify on critical conditions like high CPU, errors, or downtime."
    severity = Severity.HIGH
    category = Category.OPERATIONS
    service = "Monitoring"
    service_category = ServiceCategory.MONITORING
    gcloud_command = "gcloud alpha monitoring policies list --project={project_id} --format=json"
    references = ["https://cloud.google.com/monitoring/alerts"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            policies = await gcloud_runner.run(f"gcloud alpha monitoring policies list --project={project_id} --format=json")
            if not isinstance(policies, list) or len(policies) == 0:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"projects/{project_id}", project_id=project_id,
                    resource_link=self.console_link("monitoring", project_id),
                    current_state="No alerting policies configured",
                    recommended_state="Create alerting policies for critical metrics",
                    fix_command="", references=self.references,
                ))
        except Exception as e:
            logger.debug("MON-002: %s", e)
            findings.append(CheckResult(
                check_id=self.id, title=self.title, description=self.description,
                severity=self.severity, category=self.category, service=self.service,
                resource_name=f"projects/{project_id}", project_id=project_id,
                resource_link=self.console_link("monitoring", project_id),
                current_state="Could not verify alerting policies",
                recommended_state="Configure alerting policies via Cloud Console or Terraform",
                fix_command="", references=self.references,
            ))
        return findings


class NoNotificationChannels(BaseCheck):
    id = "MON-003"
    title = "No notification channels configured"
    description = "Without notification channels, alerts have nowhere to send notifications."
    severity = Severity.MEDIUM
    category = Category.OPERATIONS
    service = "Monitoring"
    service_category = ServiceCategory.MONITORING
    references = ["https://cloud.google.com/monitoring/support/notification-options"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            channels = await gcloud_runner.run(f"gcloud alpha monitoring channels list --project={project_id} --format=json")
            if not isinstance(channels, list) or len(channels) == 0:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"projects/{project_id}", project_id=project_id,
                    resource_link=self.console_link("monitoring", project_id),
                    current_state="No notification channels configured",
                    recommended_state="Set up email, Slack, or PagerDuty notification channels",
                    fix_command="", references=self.references,
                ))
        except Exception:
            findings.append(CheckResult(
                check_id=self.id, title=self.title, description=self.description,
                severity=self.severity, category=self.category, service=self.service,
                resource_name=f"projects/{project_id}", project_id=project_id,
                current_state="Could not verify notification channels",
                recommended_state="Configure notification channels via Cloud Console",
                fix_command="", references=self.references,
            ))
        return findings


class LogSinksNotConfigured(BaseCheck):
    id = "MON-004"
    title = "No log sinks configured"
    description = "Log sinks export logs to BigQuery, GCS, or Pub/Sub for long-term retention."
    severity = Severity.MEDIUM
    category = Category.OPERATIONS
    service = "Monitoring"
    service_category = ServiceCategory.MONITORING
    gcloud_command = "gcloud logging sinks list --project={project_id} --format=json"
    references = ["https://cloud.google.com/logging/docs/export"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            sinks = await gcloud_runner.run(f"gcloud logging sinks list --project={project_id} --format=json")
            if not isinstance(sinks, list):
                return []
            # Filter out default sinks
            custom_sinks = [s for s in sinks if not s.get("name", "").startswith("_")]
            if len(custom_sinks) == 0:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"projects/{project_id}", project_id=project_id,
                    resource_link=self.console_link("logging", project_id),
                    current_state="No custom log sinks configured",
                    recommended_state="Configure log sinks for long-term log retention and analysis",
                    fix_command="", references=self.references,
                ))
        except Exception as e:
            logger.error("MON-004 failed: %s", e)
        return findings


class UptimeChecksNotConfigured(BaseCheck):
    id = "MON-005"
    title = "No uptime checks configured"
    description = "Uptime checks monitor the availability of external endpoints."
    severity = Severity.LOW
    category = Category.RELIABILITY
    service = "Monitoring"
    service_category = ServiceCategory.MONITORING
    references = ["https://cloud.google.com/monitoring/uptime-checks"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            checks = await gcloud_runner.run(f"gcloud alpha monitoring uptime list-configs --project={project_id} --format=json")
            if not isinstance(checks, list) or len(checks) == 0:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"projects/{project_id}", project_id=project_id,
                    resource_link=self.console_link("monitoring", project_id),
                    current_state="No uptime checks configured",
                    recommended_state="Set up uptime checks for public-facing services",
                    fix_command="", references=self.references,
                ))
        except Exception:
            pass  # Uptime checks API may not be available
        return findings


class LogRetentionDefault(BaseCheck):
    id = "MON-006"
    title = "Log bucket retention below recommended threshold"
    description = (
        "Most compliance frameworks (SOC2, PCI-DSS, HIPAA) require 90+ days of audit-log retention. "
        "The Cloud Logging default is 30 days. Override THRESHOLD_DAYS for stricter regimes."
    )
    severity = Severity.MEDIUM
    category = Category.OPERATIONS
    service = "Monitoring"
    service_category = ServiceCategory.MONITORING
    references = ["https://cloud.google.com/logging/docs/storage"]

    # Compliance threshold — buckets retaining fewer days than this are flagged.
    THRESHOLD_DAYS = 90

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            buckets = await gcloud_runner.run(
                f"gcloud logging buckets list --location=global --project={project_id} --format=json"
            )
        except Exception as e:
            logger.debug("MON-006: %s", e)
            return findings
        for b in (buckets if isinstance(buckets, list) else []):
            days = b.get("retentionDays", 30)
            bucket_name = b.get("name", "").split("/")[-1]
            if days < self.THRESHOLD_DAYS:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"logging-buckets/{bucket_name}", project_id=project_id,
                    resource_link=self.console_link("logging", project_id),
                    current_state=f"retentionDays={days} (below threshold of {self.THRESHOLD_DAYS})",
                    recommended_state=f"Increase retention to >= {self.THRESHOLD_DAYS} days for audit-style logs",
                    fix_command="", references=self.references,
                ))
        return findings


# MON-007 (BudgetAlertsNotSet) removed — BIL-001 (NoBudgetAlerts in
# backend/checks/billing/billing_checks.py) is the canonical check; same logic
# but lives in the cost category alongside the rest of the budget tooling.


class CustomDashboardsNotConfigured(BaseCheck):
    id = "MON-008"
    title = "No custom monitoring dashboards"
    description = "Custom dashboards provide at-a-glance visibility into application health."
    severity = Severity.LOW
    category = Category.OPERATIONS
    service = "Monitoring"
    service_category = ServiceCategory.MONITORING
    references = ["https://cloud.google.com/monitoring/dashboards"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            dashboards = await gcloud_runner.run(f"gcloud monitoring dashboards list --project={project_id} --format=json")
            if not isinstance(dashboards, list) or len(dashboards) == 0:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"projects/{project_id}", project_id=project_id,
                    resource_link=self.console_link("monitoring", project_id),
                    current_state="No custom monitoring dashboards configured",
                    recommended_state="Create dashboards for key application and infrastructure metrics",
                    fix_command="", references=self.references,
                ))
        except Exception:
            pass  # Dashboards API may not be available via gcloud
        return findings


class ErrorReportingNotUsed(BaseCheck):
    id = "MON-009"
    title = "Error Reporting not enabled"
    description = "Error Reporting aggregates and tracks application errors automatically."
    severity = Severity.LOW
    category = Category.OPERATIONS
    service = "Monitoring"
    service_category = ServiceCategory.MONITORING
    fix_command_template = "gcloud services enable clouderrorreporting.googleapis.com --project={project_id}"
    references = ["https://cloud.google.com/error-reporting/docs/setup/compute-engine"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            services = await gcloud_runner.run(
                f"gcloud services list --project={project_id} --format=json --filter=name:clouderrorreporting.googleapis.com"
            )
            if not isinstance(services, list) or len(services) == 0:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"projects/{project_id}", project_id=project_id,
                    current_state="Error Reporting API is not enabled",
                    recommended_state="Enable Error Reporting for automatic error aggregation",
                    fix_command=self.build_fix_command(project_id=project_id),
                    references=self.references,
                ))
        except Exception as e:
            logger.debug("MON-009: %s", e)
        return findings


class TraceNotEnabled(BaseCheck):
    id = "MON-010"
    title = "Cloud Trace not enabled"
    description = "Cloud Trace collects latency data from distributed applications."
    severity = Severity.LOW
    category = Category.PERFORMANCE
    service = "Monitoring"
    service_category = ServiceCategory.MONITORING
    fix_command_template = "gcloud services enable cloudtrace.googleapis.com --project={project_id}"
    references = ["https://cloud.google.com/trace/docs/overview"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            services = await gcloud_runner.run(
                f"gcloud services list --project={project_id} --format=json --filter=name:cloudtrace.googleapis.com"
            )
            if not isinstance(services, list) or len(services) == 0:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"projects/{project_id}", project_id=project_id,
                    current_state="Cloud Trace API is not enabled",
                    recommended_state="Enable Cloud Trace for distributed tracing",
                    fix_command=self.build_fix_command(project_id=project_id),
                    references=self.references,
                ))
        except Exception as e:
            logger.debug("MON-010: %s", e)
        return findings


# ---------------------------------------------------------------------------
# Additional Monitoring checks (2026-05 catalog expansion)
# ---------------------------------------------------------------------------


class NoSLOsDefined(BaseCheck):
    id = "MON-011"
    title = "No SLOs defined for any monitored service"
    description = "SLOs give measurable reliability targets and enable burn-rate alerting."
    severity = Severity.LOW
    category = Category.RELIABILITY
    service = "Monitoring"
    service_category = ServiceCategory.MONITORING
    references = ["https://cloud.google.com/monitoring/slo"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            services = await gcloud_runner.run(
                f"gcloud monitoring services list --project={project_id} --format=json"
            )
        except Exception:
            return findings
        any_slo = False
        for s in (services if isinstance(services, list) else []):
            svc_id = s.get("name", "").split("/")[-1]
            try:
                slos = await gcloud_runner.run(
                    f"gcloud monitoring slos list --service={svc_id} --project={project_id} --format=json"
                )
            except Exception:
                continue
            if isinstance(slos, list) and len(slos) > 0:
                any_slo = True
                break
        if not any_slo:
            findings.append(CheckResult(
                check_id=self.id, title=self.title, description=self.description,
                severity=self.severity, category=self.category, service=self.service,
                resource_name=f"projects/{project_id}", project_id=project_id,
                current_state="No SLOs defined",
                recommended_state="Define SLOs and burn-rate alerts for user-facing services",
                fix_command="", references=self.references,
            ))
        return findings


class PublicLogSink(BaseCheck):
    id = "MON-012"
    title = "Log sink writes to an external GCS destination"
    description = "Sinks to other-project buckets can leak audit data if not access-controlled."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Monitoring"
    service_category = ServiceCategory.MONITORING
    references = ["https://cloud.google.com/logging/docs/export/configure_export_v2"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            sinks = await gcloud_runner.run(
                f"gcloud logging sinks list --project={project_id} --format=json"
            )
        except Exception:
            return findings
        for s in (sinks if isinstance(sinks, list) else []):
            dest = s.get("destination", "")
            if dest.startswith("storage.googleapis.com/") and project_id not in dest:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"sinks/{s.get('name')}", project_id=project_id,
                    current_state=f"Sink writes to external destination: {dest}",
                    recommended_state="Verify destination is owned by your org and access-controlled",
                    fix_command="", references=self.references,
                ))
        return findings


import sys as _sys  # noqa: E402
from backend.checks._module_helpers import apply_required_apis as _apply  # noqa: E402
# Monitoring checks need both monitoring and logging APIs
_apply(_sys.modules[__name__], ["monitoring.googleapis.com", "logging.googleapis.com"])
