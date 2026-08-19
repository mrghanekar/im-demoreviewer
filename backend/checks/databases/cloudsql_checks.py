"""Cloud SQL and database checks.

Checks: DB-001 through DB-015
"""

import logging
from typing import Any, ClassVar

from backend.checks.base import BaseCheck
from backend.core.models import Category, CheckResult, Severity, ServiceCategory

logger = logging.getLogger(__name__)


class SQLPublicIP(BaseCheck):
    id = "DB-001"
    title = "Cloud SQL instance has public IP"
    description = "Public IPs on database instances expose them to internet attacks."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    service = "CloudSQL"
    service_category = ServiceCategory.DATABASES
    gcloud_command = "gcloud sql instances list --project={project_id} --format=json"
    fix_command_template = "gcloud sql instances patch {name} --no-assign-ip --project={project_id}"
    references = ["https://cloud.google.com/sql/docs/mysql/configure-private-ip"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"CIS_GCP_V3": ["6.5"], "ISO_27001": ["A.8.20", "A.8.22"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await gcloud_runner.run(f"gcloud sql instances list --project={project_id} --format=json")
            if not isinstance(instances, list):
                return []
            for i in instances:
                name = i.get("name", "")
                ip_addrs = i.get("ipAddresses", [])
                for ip in ip_addrs:
                    if ip.get("type") == "PRIMARY":
                        findings.append(CheckResult(
                            check_id=self.id, title=self.title, description=self.description,
                            severity=self.severity, category=self.category, service=self.service,
                            resource_name=f"sql/{name}", project_id=project_id,
                            resource_link=self.console_link("cloudsql", project_id, name=name),
                            current_state=f"Public IP: {ip.get('ipAddress', 'unknown')}",
                            recommended_state="Use private IP only with Cloud SQL Auth Proxy",
                            fix_command=self.build_fix_command(name=name, project_id=project_id),
                            references=self.references,
                        ))
                        break
        except Exception as e:
            logger.error("DB-001 failed: %s", e)
        return findings


class SQLNoSSL(BaseCheck):
    id = "DB-002"
    title = "Cloud SQL SSL/TLS not enforced"
    description = "Without enforced SSL, database connections may be unencrypted."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "CloudSQL"
    service_category = ServiceCategory.DATABASES
    fix_command_template = "gcloud sql instances patch {name} --require-ssl --project={project_id}"
    references = ["https://cloud.google.com/sql/docs/mysql/configure-ssl-instance"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"CIS_GCP_V3": ["6.4"], "ISO_27001": ["A.8.24", "A.8.21"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await gcloud_runner.run(f"gcloud sql instances list --project={project_id} --format=json")
            if not isinstance(instances, list):
                return []
            for i in instances:
                name = i.get("name", "")
                settings = i.get("settings", {})
                ip_config = settings.get("ipConfiguration", {})
                if not ip_config.get("requireSsl", False) and not ip_config.get("sslMode", "") == "ENCRYPTED_ONLY":
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"sql/{name}", project_id=project_id,
                        resource_link=self.console_link("cloudsql", project_id, name=name),
                        current_state="SSL/TLS is not required for connections",
                        recommended_state="Enforce SSL for all database connections",
                        fix_command=self.build_fix_command(name=name, project_id=project_id),
                        references=self.references,
                    ))
        except Exception as e:
            logger.error("DB-002 failed: %s", e)
        return findings


class SQLNoAutomatedBackups(BaseCheck):
    id = "DB-003"
    title = "Automated backups not enabled"
    description = "Without automated backups, data loss from failures cannot be recovered."
    severity = Severity.HIGH
    category = Category.RELIABILITY
    service = "CloudSQL"
    service_category = ServiceCategory.DATABASES
    fix_command_template = "gcloud sql instances patch {name} --backup-start-time=02:00 --project={project_id}"
    references = ["https://cloud.google.com/sql/docs/mysql/backup-recovery/backing-up"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"CIS_GCP_V3": ["6.7"], "ISO_27001": ["A.8.13"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await gcloud_runner.run(f"gcloud sql instances list --project={project_id} --format=json")
            if not isinstance(instances, list):
                return []
            for i in instances:
                name = i.get("name", "")
                settings = i.get("settings", {})
                backup = settings.get("backupConfiguration", {})
                if not backup.get("enabled", False):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"sql/{name}", project_id=project_id,
                        resource_link=self.console_link("cloudsql", project_id, name=name),
                        current_state="Automated backups are disabled",
                        recommended_state="Enable daily automated backups",
                        fix_command=self.build_fix_command(name=name, project_id=project_id),
                        references=self.references,
                    ))
        except Exception as e:
            logger.error("DB-003 failed: %s", e)
        return findings


class SQLNoHA(BaseCheck):
    id = "DB-004"
    title = "Cloud SQL high availability not configured"
    description = "Without HA (regional), a zone failure causes database downtime."
    severity = Severity.HIGH
    category = Category.RELIABILITY
    service = "CloudSQL"
    service_category = ServiceCategory.DATABASES
    references = ["https://cloud.google.com/sql/docs/mysql/high-availability"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.14", "A.5.30"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await gcloud_runner.run(f"gcloud sql instances list --project={project_id} --format=json")
            if not isinstance(instances, list):
                return []
            for i in instances:
                name = i.get("name", "")
                settings = i.get("settings", {})
                availability = settings.get("availabilityType", "")
                if i.get("instanceType") == "CLOUD_SQL_INSTANCE" and availability != "REGIONAL":
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"sql/{name}", project_id=project_id,
                        resource_link=self.console_link("cloudsql", project_id, name=name),
                        current_state=f"Availability type: {availability or 'ZONAL'}",
                        recommended_state="Configure REGIONAL availability for automatic failover",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.error("DB-004 failed: %s", e)
        return findings


class SQLAuthNetworks(BaseCheck):
    id = "DB-005"
    title = "Authorized networks include 0.0.0.0/0"
    description = "Allowing all IPs in authorized networks defeats network-level access control."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    service = "CloudSQL"
    service_category = ServiceCategory.DATABASES
    references = ["https://cloud.google.com/sql/docs/mysql/authorize-networks"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"CIS_GCP_V3": ["6.6"], "ISO_27001": ["A.8.20", "A.8.22"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await gcloud_runner.run(f"gcloud sql instances list --project={project_id} --format=json")
            if not isinstance(instances, list):
                return []
            for i in instances:
                name = i.get("name", "")
                settings = i.get("settings", {})
                ip_config = settings.get("ipConfiguration", {})
                auth_networks = ip_config.get("authorizedNetworks", [])
                for net in auth_networks:
                    cidr = net.get("value", "")
                    if cidr == "0.0.0.0/0":
                        findings.append(CheckResult(
                            check_id=self.id, title=self.title, description=self.description,
                            severity=self.severity, category=self.category, service=self.service,
                            resource_name=f"sql/{name}", project_id=project_id,
                            resource_link=self.console_link("cloudsql", project_id, name=name),
                            current_state="Authorized networks include 0.0.0.0/0 (all IPs)",
                            recommended_state="Restrict to specific CIDR ranges or use private IP",
                            fix_command="", references=self.references,
                        ))
                        break
        except Exception as e:
            logger.error("DB-005 failed: %s", e)
        return findings


class SQLNoPointInTimeRecovery(BaseCheck):
    id = "DB-006"
    title = "Point-in-time recovery not enabled"
    description = "PITR enables recovery to any point in time using binary logs."
    severity = Severity.MEDIUM
    category = Category.RELIABILITY
    service = "CloudSQL"
    service_category = ServiceCategory.DATABASES
    references = ["https://cloud.google.com/sql/docs/mysql/backup-recovery/pitr"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.13", "A.5.29"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await gcloud_runner.run(f"gcloud sql instances list --project={project_id} --format=json")
            if not isinstance(instances, list):
                return []
            for i in instances:
                name = i.get("name", "")
                settings = i.get("settings", {})
                backup = settings.get("backupConfiguration", {})
                if backup.get("enabled", False) and not backup.get("pointInTimeRecoveryEnabled", False):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"sql/{name}", project_id=project_id,
                        resource_link=self.console_link("cloudsql", project_id, name=name),
                        current_state="Point-in-time recovery is not enabled",
                        recommended_state="Enable PITR for granular recovery capability",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.error("DB-006 failed: %s", e)
        return findings


class SQLMaintenanceWindow(BaseCheck):
    id = "DB-007"
    title = "No maintenance window configured for Cloud SQL"
    description = "A maintenance window controls when Cloud SQL performs updates."
    severity = Severity.LOW
    category = Category.OPERATIONS
    service = "CloudSQL"
    service_category = ServiceCategory.DATABASES
    references = ["https://cloud.google.com/sql/docs/mysql/set-maintenance-window"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await gcloud_runner.run(f"gcloud sql instances list --project={project_id} --format=json")
            if not isinstance(instances, list):
                return []
            for i in instances:
                name = i.get("name", "")
                settings = i.get("settings", {})
                mw = settings.get("maintenanceWindow", {})
                if not mw or mw.get("day") is None:
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"sql/{name}", project_id=project_id,
                        resource_link=self.console_link("cloudsql", project_id, name=name),
                        current_state="No maintenance window configured",
                        recommended_state="Set a maintenance window during off-peak hours",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.error("DB-007 failed: %s", e)
        return findings


class SQLOldVersion(BaseCheck):
    id = "DB-008"
    title = "Cloud SQL running outdated database version"
    description = "Older database versions may lack security patches and performance improvements."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "CloudSQL"
    service_category = ServiceCategory.DATABASES
    references = ["https://cloud.google.com/sql/docs/mysql/db-versions"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.8"]}

    OLD_VERSIONS = {"MYSQL_5_6", "MYSQL_5_7", "POSTGRES_9_6", "POSTGRES_10", "POSTGRES_11", "SQLSERVER_2017_STANDARD"}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await gcloud_runner.run(f"gcloud sql instances list --project={project_id} --format=json")
            if not isinstance(instances, list):
                return []
            for i in instances:
                name = i.get("name", "")
                version = i.get("databaseVersion", "")
                if version in self.OLD_VERSIONS:
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"sql/{name}", project_id=project_id,
                        resource_link=self.console_link("cloudsql", project_id, name=name),
                        current_state=f"Running {version} (outdated)",
                        recommended_state="Upgrade to a currently supported database version",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.error("DB-008 failed: %s", e)
        return findings


class SQLNoCMEK(BaseCheck):
    id = "DB-009"
    title = "Cloud SQL not encrypted with CMEK"
    description = "Cloud SQL instances use Google-managed keys by default. Use CMEK for sensitive data."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "CloudSQL"
    service_category = ServiceCategory.DATABASES
    references = ["https://cloud.google.com/sql/docs/mysql/cmek"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.24"], "DPDP": ["8(5)"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await gcloud_runner.run(f"gcloud sql instances list --project={project_id} --format=json")
            if not isinstance(instances, list):
                return []
            for i in instances:
                name = i.get("name", "")
                enc = i.get("diskEncryptionConfiguration", {})
                if not enc or not enc.get("kmsKeyName"):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"sql/{name}", project_id=project_id,
                        resource_link=self.console_link("cloudsql", project_id, name=name),
                        current_state="Using Google-managed encryption",
                        recommended_state="Configure CMEK encryption for compliance requirements",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.error("DB-009 failed: %s", e)
        return findings


class SQLQueryInsightsDisabled(BaseCheck):
    id = "DB-010"
    title = "Query Insights not enabled"
    description = "Query Insights helps identify and fix slow queries for better performance."
    severity = Severity.LOW
    category = Category.PERFORMANCE
    service = "CloudSQL"
    service_category = ServiceCategory.DATABASES
    references = ["https://cloud.google.com/sql/docs/mysql/using-query-insights"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await gcloud_runner.run(f"gcloud sql instances list --project={project_id} --format=json")
            if not isinstance(instances, list):
                return []
            for i in instances:
                name = i.get("name", "")
                settings = i.get("settings", {})
                insights = settings.get("insightsConfig", {})
                if not insights.get("queryInsightsEnabled", False):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"sql/{name}", project_id=project_id,
                        resource_link=self.console_link("cloudsql", project_id, name=name),
                        current_state="Query Insights is not enabled",
                        recommended_state="Enable Query Insights for query performance monitoring",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.error("DB-010 failed: %s", e)
        return findings


class SQLNoReadReplica(BaseCheck):
    id = "DB-011"
    title = "No read replicas configured"
    description = "Read replicas offload read traffic and provide cross-region redundancy."
    severity = Severity.LOW
    category = Category.PERFORMANCE
    service = "CloudSQL"
    service_category = ServiceCategory.DATABASES
    references = ["https://cloud.google.com/sql/docs/mysql/replication"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await gcloud_runner.run(f"gcloud sql instances list --project={project_id} --format=json")
            if not isinstance(instances, list):
                return []
            primary_instances = [i for i in instances if i.get("instanceType") == "CLOUD_SQL_INSTANCE"]
            replicas = {i.get("masterInstanceName") for i in instances if i.get("instanceType") == "READ_REPLICA_INSTANCE"}
            for i in primary_instances:
                name = i.get("name", "")
                if name not in replicas:
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"sql/{name}", project_id=project_id,
                        resource_link=self.console_link("cloudsql", project_id, name=name),
                        current_state="No read replicas configured for this instance",
                        recommended_state="Add read replicas for high-read workloads and DR",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.error("DB-011 failed: %s", e)
        return findings


class SQLStorageAutoResize(BaseCheck):
    id = "DB-012"
    title = "Storage auto-resize not enabled"
    description = "Without auto-resize, the instance can run out of storage causing downtime."
    severity = Severity.MEDIUM
    category = Category.RELIABILITY
    service = "CloudSQL"
    service_category = ServiceCategory.DATABASES
    references = ["https://cloud.google.com/sql/docs/mysql/instance-settings#automatic-storage-increase-2ndgen"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.6"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await gcloud_runner.run(f"gcloud sql instances list --project={project_id} --format=json")
            if not isinstance(instances, list):
                return []
            for i in instances:
                name = i.get("name", "")
                settings = i.get("settings", {})
                if not settings.get("storageAutoResize", False):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"sql/{name}", project_id=project_id,
                        resource_link=self.console_link("cloudsql", project_id, name=name),
                        current_state="Storage auto-resize is disabled",
                        recommended_state="Enable auto-resize to prevent storage-related outages",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.error("DB-012 failed: %s", e)
        return findings


class SQLPasswordPolicy(BaseCheck):
    id = "DB-013"
    title = "No password policy configured"
    description = "Password policies enforce complexity and rotation for database users."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "CloudSQL"
    service_category = ServiceCategory.DATABASES
    references = ["https://cloud.google.com/sql/docs/mysql/built-in-authentication"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.5.17", "A.8.5"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await gcloud_runner.run(f"gcloud sql instances list --project={project_id} --format=json")
            if not isinstance(instances, list):
                return []
            for i in instances:
                name = i.get("name", "")
                settings = i.get("settings", {})
                pp = settings.get("passwordValidationPolicy", {})
                if not pp or not pp.get("enablePasswordPolicy", False):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"sql/{name}", project_id=project_id,
                        resource_link=self.console_link("cloudsql", project_id, name=name),
                        current_state="No password policy configured",
                        recommended_state="Enable password policy with complexity and length requirements",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.error("DB-013 failed: %s", e)
        return findings


class SQLAuditLogging(BaseCheck):
    id = "DB-014"
    title = "Database audit logging not enabled"
    description = "Audit logs track all database operations for security monitoring."
    severity = Severity.MEDIUM
    category = Category.OPERATIONS
    service = "CloudSQL"
    service_category = ServiceCategory.DATABASES
    references = ["https://cloud.google.com/sql/docs/mysql/pg-audit"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.15"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await gcloud_runner.run(f"gcloud sql instances list --project={project_id} --format=json")
            if not isinstance(instances, list):
                return []
            for i in instances:
                name = i.get("name", "")
                version = i.get("databaseVersion", "")
                settings = i.get("settings", {})
                db_flags = settings.get("databaseFlags", [])
                flag_names = {f.get("name", ""): f.get("value", "") for f in db_flags}
                if "POSTGRES" in version and flag_names.get("cloudsql.enable_pgaudit") != "on":
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"sql/{name}", project_id=project_id,
                        resource_link=self.console_link("cloudsql", project_id, name=name),
                        current_state="pgAudit extension is not enabled",
                        recommended_state="Enable pgAudit for PostgreSQL audit logging",
                        fix_command="", references=self.references,
                    ))
                elif "MYSQL" in version and flag_names.get("audit_log") != "ON":
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"sql/{name}", project_id=project_id,
                        resource_link=self.console_link("cloudsql", project_id, name=name),
                        current_state="MySQL audit logging is not enabled",
                        recommended_state="Enable audit logging for security monitoring",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.error("DB-014 failed: %s", e)
        return findings


class SQLDeletionProtection(BaseCheck):
    id = "DB-015"
    title = "Cloud SQL deletion protection not enabled"
    description = "Deletion protection prevents accidental instance deletion."
    severity = Severity.MEDIUM
    category = Category.RELIABILITY
    service = "CloudSQL"
    service_category = ServiceCategory.DATABASES
    fix_command_template = "gcloud sql instances patch {name} --deletion-protection --project={project_id}"
    references = ["https://cloud.google.com/sql/docs/mysql/deletion-protection"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.10"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await gcloud_runner.run(f"gcloud sql instances list --project={project_id} --format=json")
            if not isinstance(instances, list):
                return []
            for i in instances:
                name = i.get("name", "")
                settings = i.get("settings", {})
                if not settings.get("deletionProtectionEnabled", False):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"sql/{name}", project_id=project_id,
                        resource_link=self.console_link("cloudsql", project_id, name=name),
                        current_state="Deletion protection is not enabled",
                        recommended_state="Enable deletion protection for production instances",
                        fix_command=self.build_fix_command(name=name, project_id=project_id),
                        references=self.references,
                    ))
        except Exception as e:
            logger.error("DB-015 failed: %s", e)
        return findings


# ---------------------------------------------------------------------------
# Additional Cloud SQL checks (2026-05 catalog expansion)
# ---------------------------------------------------------------------------


async def _list_sql_instances(gcloud_runner: Any, project_id: str) -> list[dict]:
    try:
        instances = await gcloud_runner.run(
            f"gcloud sql instances list --project={project_id} --format=json"
        )
        return instances if isinstance(instances, list) else []
    except Exception as e:
        logger.debug("Cloud SQL list failed: %s", e)
        return []


class CloudSQLIAMAuthDisabled(BaseCheck):
    id = "DB-016"
    title = "Cloud SQL IAM database authentication not enabled"
    description = "IAM DB auth grants DB access via IAM principals instead of static passwords."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "Cloud SQL"
    service_category = ServiceCategory.DATABASES
    references = ["https://cloud.google.com/sql/docs/postgres/authentication"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.5", "A.5.16"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for i in await _list_sql_instances(gcloud_runner, project_id):
            name = i.get("name", "")
            flags = {f.get("name"): f.get("value") for f in i.get("settings", {}).get("databaseFlags", [])}
            if flags.get("cloudsql.iam_authentication") != "on":
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"sql/{name}", project_id=project_id,
                    current_state="cloudsql.iam_authentication flag not 'on'",
                    recommended_state="Set --database-flags=cloudsql.iam_authentication=on",
                    fix_command=f"gcloud sql instances patch {name} --database-flags=cloudsql.iam_authentication=on --project={project_id}",
                    references=self.references,
                ))
        return findings


class CloudSQLNoPasswordPolicy(BaseCheck):
    id = "DB-017"
    title = "Cloud SQL instance has no password validation policy"
    description = "Password policy enforces complexity/length/reuse rules for built-in DB users."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "Cloud SQL"
    service_category = ServiceCategory.DATABASES
    references = ["https://cloud.google.com/sql/docs/postgres/built-in-authentication"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.5.17", "A.8.5"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for i in await _list_sql_instances(gcloud_runner, project_id):
            name = i.get("name", "")
            pol = i.get("settings", {}).get("passwordValidationPolicy", {})
            if not pol or not pol.get("enablePasswordPolicy"):
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"sql/{name}", project_id=project_id,
                    current_state="No password validation policy configured",
                    recommended_state="Enable password policy with min-length, complexity, reuse-interval",
                    fix_command="", references=self.references,
                ))
        return findings


import sys as _sys  # noqa: E402
from backend.checks._module_helpers import apply_required_apis as _apply  # noqa: E402
_apply(_sys.modules[__name__], ["sqladmin.googleapis.com"])
