"""Data services checks for BigQuery, Pub/Sub, Dataflow, and Dataproc.

Checks: DATA-001 through DATA-010
"""

import logging
from typing import Any

from backend.checks.base import BaseCheck
from backend.core.models import Category, CheckResult, Severity, ServiceCategory

logger = logging.getLogger(__name__)


class BQDatasetNoDefaultCMEK(BaseCheck):
    id = "DATA-001"
    title = "BigQuery dataset not encrypted with CMEK"
    description = "BigQuery datasets use Google-managed encryption by default. Use CMEK for sensitive data."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "BigQuery"
    service_category = ServiceCategory.DATA
    gcloud_command = "bq ls --project_id={project_id} --format=json"
    references = ["https://cloud.google.com/bigquery/docs/customer-managed-encryption"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            datasets = await gcloud_runner.run(f"bq ls --project_id={project_id} --format=json")
            if not isinstance(datasets, list):
                return []
            for ds in datasets:
                ds_ref = ds.get("datasetReference", {})
                ds_id = ds_ref.get("datasetId", "")
                if not ds_id:
                    continue
                try:
                    detail = await gcloud_runner.run(f"bq show --format=json {project_id}:{ds_id}")
                    if isinstance(detail, dict):
                        enc = detail.get("defaultEncryptionConfiguration", {})
                        if not enc or not enc.get("kmsKeyName"):
                            findings.append(CheckResult(
                                check_id=self.id, title=self.title, description=self.description,
                                severity=self.severity, category=self.category, service=self.service,
                                resource_name=f"bigquery/{ds_id}", project_id=project_id,
                                resource_link=self.console_link("bigquery_dataset", project_id, name=ds_id),
                                current_state="Using Google-managed encryption (default)",
                                recommended_state="Configure CMEK default encryption for sensitive datasets",
                                fix_command="", references=self.references,
                            ))
                except Exception:
                    pass
        except Exception as e:
            logger.debug("DATA-001: %s", e)
        return findings


class BQDatasetPublicAccess(BaseCheck):
    id = "DATA-002"
    title = "BigQuery dataset has public access"
    description = "BigQuery datasets accessible to allUsers or allAuthenticatedUsers expose data publicly."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    service = "BigQuery"
    service_category = ServiceCategory.DATA
    references = ["https://cloud.google.com/bigquery/docs/dataset-access-controls"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            datasets = await gcloud_runner.run(f"bq ls --project_id={project_id} --format=json")
            if not isinstance(datasets, list):
                return []
            for ds in datasets:
                ds_ref = ds.get("datasetReference", {})
                ds_id = ds_ref.get("datasetId", "")
                if not ds_id:
                    continue
                try:
                    detail = await gcloud_runner.run(f"bq show --format=json {project_id}:{ds_id}")
                    if isinstance(detail, dict):
                        access = detail.get("access", [])
                        for entry in access:
                            special_group = entry.get("specialGroup", "")
                            if special_group in ("allAuthenticatedUsers", "projectReaders", "allUsers"):
                                if special_group == "allUsers" or special_group == "allAuthenticatedUsers":
                                    findings.append(CheckResult(
                                        check_id=self.id, title=self.title, description=self.description,
                                        severity=self.severity, category=self.category, service=self.service,
                                        resource_name=f"bigquery/{ds_id}", project_id=project_id,
                                        resource_link=self.console_link("bigquery_dataset", project_id, name=ds_id),
                                        current_state=f"Dataset has {special_group} access with role '{entry.get('role', 'unknown')}'",
                                        recommended_state="Remove public access from dataset",
                                        fix_command="", references=self.references,
                                    ))
                                    break
                except Exception:
                    pass
        except Exception as e:
            logger.debug("DATA-002: %s", e)
        return findings


class BQTableExpiration(BaseCheck):
    id = "DATA-003"
    title = "BigQuery dataset has no default table expiration"
    description = "Without table expiration, tables accumulate indefinitely increasing storage costs."
    severity = Severity.LOW
    category = Category.COST
    service = "BigQuery"
    service_category = ServiceCategory.DATA
    references = ["https://cloud.google.com/bigquery/docs/updating-datasets#table-expiration"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            datasets = await gcloud_runner.run(f"bq ls --project_id={project_id} --format=json")
            if not isinstance(datasets, list):
                return []
            for ds in datasets:
                ds_ref = ds.get("datasetReference", {})
                ds_id = ds_ref.get("datasetId", "")
                if not ds_id:
                    continue
                try:
                    detail = await gcloud_runner.run(f"bq show --format=json {project_id}:{ds_id}")
                    if isinstance(detail, dict):
                        exp = detail.get("defaultTableExpirationMs")
                        if not exp:
                            findings.append(CheckResult(
                                check_id=self.id, title=self.title, description=self.description,
                                severity=self.severity, category=self.category, service=self.service,
                                resource_name=f"bigquery/{ds_id}", project_id=project_id,
                                resource_link=self.console_link("bigquery_dataset", project_id, name=ds_id),
                                current_state="No default table expiration set",
                                recommended_state="Set default table expiration for temporary/staging datasets",
                                fix_command="", references=self.references,
                            ))
                except Exception:
                    pass
        except Exception as e:
            logger.debug("DATA-003: %s", e)
        return findings


class PubSubDLQ(BaseCheck):
    id = "DATA-004"
    title = "Pub/Sub subscription has no dead-letter topic"
    description = "Without a dead-letter topic, undeliverable messages are lost after max retries."
    severity = Severity.MEDIUM
    category = Category.RELIABILITY
    service = "PubSub"
    service_category = ServiceCategory.DATA
    gcloud_command = "gcloud pubsub subscriptions list --project={project_id} --format=json"
    references = ["https://cloud.google.com/pubsub/docs/dead-letter-topics"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            subs = await gcloud_runner.run(f"gcloud pubsub subscriptions list --project={project_id} --format=json")
            if not isinstance(subs, list):
                return []
            for sub in subs:
                name = sub.get("name", "").split("/")[-1]
                dlp = sub.get("deadLetterPolicy", {})
                if not dlp or not dlp.get("deadLetterTopic"):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"subscriptions/{name}", project_id=project_id,
                        resource_link=self.console_link("pubsub_topic", project_id, name=name),
                        current_state=f"Subscription '{name}' has no dead-letter topic",
                        recommended_state="Configure dead-letter topic for failed message handling",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.debug("DATA-004: %s", e)
        return findings


class PubSubNoExpiration(BaseCheck):
    id = "DATA-005"
    title = "Pub/Sub subscription has no expiration"
    description = "Subscriptions without expiration policy accumulate backlog and incur costs."
    severity = Severity.LOW
    category = Category.COST
    service = "PubSub"
    service_category = ServiceCategory.DATA
    references = ["https://cloud.google.com/pubsub/docs/subscription-properties#expiration"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            subs = await gcloud_runner.run(f"gcloud pubsub subscriptions list --project={project_id} --format=json")
            if not isinstance(subs, list):
                return []
            for sub in subs:
                name = sub.get("name", "").split("/")[-1]
                exp = sub.get("expirationPolicy", {})
                if not exp or not exp.get("ttl"):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"subscriptions/{name}", project_id=project_id,
                        current_state=f"Subscription '{name}' has no expiration policy",
                        recommended_state="Set expiration policy to auto-delete inactive subscriptions",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.debug("DATA-005: %s", e)
        return findings


class PubSubNoEncryption(BaseCheck):
    id = "DATA-006"
    title = "Pub/Sub topic not encrypted with CMEK"
    description = "Pub/Sub topics use Google-managed keys by default. Use CMEK for sensitive messages."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "PubSub"
    service_category = ServiceCategory.DATA
    references = ["https://cloud.google.com/pubsub/docs/encryption"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            topics = await gcloud_runner.run(f"gcloud pubsub topics list --project={project_id} --format=json")
            if not isinstance(topics, list):
                return []
            for topic in topics:
                name = topic.get("name", "").split("/")[-1]
                kms_key = topic.get("kmsKeyName", "")
                if not kms_key:
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"topics/{name}", project_id=project_id,
                        resource_link=self.console_link("pubsub_topic", project_id, name=name),
                        current_state="Using Google-managed encryption",
                        recommended_state="Configure CMEK for sensitive message topics",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.debug("DATA-006: %s", e)
        return findings


class DataflowNoRegionRestriction(BaseCheck):
    id = "DATA-007"
    title = "Dataflow jobs running in default region"
    description = "Dataflow jobs should run in specific regions for data residency and latency."
    severity = Severity.LOW
    category = Category.OPERATIONS
    service = "Dataflow"
    service_category = ServiceCategory.DATA
    references = ["https://cloud.google.com/dataflow/docs/concepts/regional-endpoints"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            jobs = await gcloud_runner.run(f"gcloud dataflow jobs list --project={project_id} --format=json --status=active")
            if not isinstance(jobs, list):
                return []
            for job in jobs:
                name = job.get("name", "")
                location = job.get("location", "")
                if location == "us-central1":  # Default region
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"dataflow/{name}", project_id=project_id,
                        current_state=f"Job '{name}' running in default region: {location}",
                        recommended_state="Specify a region closer to data sources/sinks",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.debug("DATA-007: %s", e)
        return findings


class DataprocNoAutoScaling(BaseCheck):
    id = "DATA-008"
    title = "Dataproc cluster without autoscaling"
    description = "Autoscaling on Dataproc adjusts workers based on workload for cost optimization."
    severity = Severity.MEDIUM
    category = Category.COST
    service = "Dataproc"
    service_category = ServiceCategory.DATA
    references = ["https://cloud.google.com/dataproc/docs/concepts/configuring-clusters/autoscaling"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            clusters = await gcloud_runner.run(f"gcloud dataproc clusters list --project={project_id} --region=- --format=json")
            if not isinstance(clusters, list):
                return []
            for c in clusters:
                name = c.get("clusterName", "")
                config = c.get("config", {})
                autoscaling = config.get("autoscalingConfig", {})
                if not autoscaling or not autoscaling.get("policyUri"):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"dataproc/{name}", project_id=project_id,
                        current_state=f"Cluster '{name}' has no autoscaling policy",
                        recommended_state="Configure autoscaling policy to optimize worker count",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.debug("DATA-008: %s", e)
        return findings


class BQAuditLogging(BaseCheck):
    id = "DATA-009"
    title = "BigQuery audit logging not fully enabled"
    description = "Full audit logging for BigQuery tracks all query and data access activity."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "BigQuery"
    service_category = ServiceCategory.DATA
    references = ["https://cloud.google.com/bigquery/docs/reference/auditlogs"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            policy = await gcloud_runner.run(f"gcloud projects get-iam-policy {project_id} --format=json")
            if not isinstance(policy, dict):
                return []
            audit_configs = policy.get("auditConfigs", [])
            bq_audit = [c for c in audit_configs if c.get("service") == "bigquery.googleapis.com"]
            if not bq_audit:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"projects/{project_id}", project_id=project_id,
                    current_state="BigQuery data access audit logging is not explicitly configured",
                    recommended_state="Enable DATA_READ and DATA_WRITE audit logs for BigQuery",
                    fix_command="", references=self.references,
                ))
        except Exception as e:
            logger.debug("DATA-009: %s", e)
        return findings


class DataCatalogNotUsed(BaseCheck):
    id = "DATA-010"
    title = "Data Catalog not enabled for data governance"
    description = "Data Catalog provides metadata management and data discovery for governance."
    severity = Severity.LOW
    category = Category.OPERATIONS
    service = "DataCatalog"
    service_category = ServiceCategory.DATA
    fix_command_template = "gcloud services enable datacatalog.googleapis.com --project={project_id}"
    references = ["https://cloud.google.com/data-catalog/docs/overview"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            services = await gcloud_runner.run(
                f"gcloud services list --project={project_id} --format=json --filter=name:datacatalog.googleapis.com"
            )
            if not isinstance(services, list) or len(services) == 0:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"projects/{project_id}", project_id=project_id,
                    current_state="Data Catalog API is not enabled",
                    recommended_state="Enable Data Catalog for data governance and discovery",
                    fix_command=self.build_fix_command(project_id=project_id),
                    references=self.references,
                ))
        except Exception as e:
            logger.debug("DATA-010: %s", e)
        return findings


# ---------------------------------------------------------------------------
# Additional Data Services checks (2026-05 catalog expansion)
# ---------------------------------------------------------------------------


class BigQueryLargeTableNoPartition(BaseCheck):
    id = "DATA-011"
    title = "BigQuery table > 10 GB has no partitioning"
    description = "Unpartitioned large tables scan more data per query — bad for cost and performance."
    severity = Severity.MEDIUM
    category = Category.COST
    service = "BigQuery"
    service_category = ServiceCategory.DATA
    references = ["https://cloud.google.com/bigquery/docs/partitioned-tables"]

    THRESHOLD_BYTES = 10 * 1024 * 1024 * 1024  # 10 GB

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            datasets = await gcloud_runner.run(
                f"bq ls --project_id={project_id} --format=json"
            )
        except Exception:
            return findings
        for ds in (datasets if isinstance(datasets, list) else []):
            ds_id = ds.get("datasetReference", {}).get("datasetId") or ds.get("id", "").split(":")[-1]
            if not ds_id:
                continue
            try:
                tables = await gcloud_runner.run(
                    f"bq ls --project_id={project_id} --format=json {ds_id}"
                )
            except Exception:
                continue
            for t in (tables if isinstance(tables, list) else []):
                tbl_id = t.get("tableReference", {}).get("tableId") or t.get("id", "").split(".")[-1]
                if not tbl_id or t.get("type") != "TABLE":
                    continue
                try:
                    info = await gcloud_runner.run(
                        f"bq show --project_id={project_id} --format=json {ds_id}.{tbl_id}"
                    )
                except Exception:
                    continue
                if not isinstance(info, dict):
                    continue
                size = int(info.get("numBytes", "0") or 0)
                has_partition = bool(info.get("timePartitioning") or info.get("rangePartitioning"))
                if size > self.THRESHOLD_BYTES and not has_partition:
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"{ds_id}.{tbl_id}", project_id=project_id,
                        current_state=f"Table is {size / 1024 / 1024 / 1024:.1f} GB, no partitioning",
                        recommended_state="Add time-based or range-based partitioning",
                        fix_command="", references=self.references,
                    ))
        return findings


class DataprocPublicCluster(BaseCheck):
    id = "DATA-012"
    title = "Dataproc cluster has public IPs (no --no-address)"
    description = "Dataproc workers with public IPs expand attack surface; use internal IPs + Cloud NAT."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Dataproc"
    service_category = ServiceCategory.DATA
    references = ["https://cloud.google.com/dataproc/docs/concepts/configuring-clusters/internal-ip"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            clusters = await gcloud_runner.run(
                f"gcloud dataproc clusters list --region=- --project={project_id} --format=json"
            )
        except Exception:
            return findings
        for c in (clusters if isinstance(clusters, list) else []):
            name = c.get("clusterName", "") or c.get("name", "")
            gce_cfg = c.get("config", {}).get("gceClusterConfig", {})
            if not gce_cfg.get("internalIpOnly"):
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"dataproc/{name}", project_id=project_id,
                    current_state="Cluster has public IPs (internalIpOnly=false)",
                    recommended_state="Recreate with --no-address (internalIpOnly=true)",
                    fix_command="", references=self.references,
                ))
        return findings


class PubSubNoSchema(BaseCheck):
    id = "DATA-013"
    title = "Pub/Sub topic has no schema attached"
    description = "Schemas validate message structure and prevent malformed-payload incidents."
    severity = Severity.LOW
    category = Category.RELIABILITY
    service = "Pub/Sub"
    service_category = ServiceCategory.DATA
    references = ["https://cloud.google.com/pubsub/docs/schemas"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            topics = await gcloud_runner.run(
                f"gcloud pubsub topics list --project={project_id} --format=json"
            )
        except Exception:
            return findings
        for t in (topics if isinstance(topics, list) else []):
            name = t.get("name", "").split("/")[-1]
            schema = t.get("schemaSettings", {}).get("schema")
            if not schema:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"topics/{name}", project_id=project_id,
                    current_state="No schemaSettings configured",
                    recommended_state="Attach a Pub/Sub schema (Avro or Protobuf)",
                    fix_command="", references=self.references,
                ))
        return findings


import sys as _sys  # noqa: E402
from backend.checks._module_helpers import apply_required_apis_by_id as _apply  # noqa: E402
_apply(_sys.modules[__name__], {
    "DATA-001": ["bigquery.googleapis.com"],
    "DATA-002": ["bigquery.googleapis.com"],
    "DATA-003": ["bigquery.googleapis.com"],
    "DATA-004": ["pubsub.googleapis.com"],
    "DATA-005": ["pubsub.googleapis.com"],
    "DATA-006": ["pubsub.googleapis.com"],
    "DATA-007": ["dataflow.googleapis.com"],
    "DATA-008": ["dataproc.googleapis.com"],
    "DATA-009": ["cloudresourcemanager.googleapis.com"],
    # DATA-010 detects whether Data Catalog itself is enabled — must NOT require
    # datacatalog.googleapis.com, only serviceusage to perform the lookup.
    "DATA-010": ["serviceusage.googleapis.com"],
    "DATA-011": ["bigquery.googleapis.com"],
    "DATA-012": ["dataproc.googleapis.com"],
    "DATA-013": ["pubsub.googleapis.com"],
})
