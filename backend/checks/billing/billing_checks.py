"""Billing and cost optimization checks.

Checks: BIL-001 through BIL-010
"""

import logging
from typing import Any, ClassVar

from backend.checks.base import BaseCheck
from backend.core.models import Category, CheckResult, Severity, ServiceCategory

logger = logging.getLogger(__name__)


async def _zones_in_use(project_id: str, gcloud_runner: Any) -> list[str]:
    """Zones that actually contain instances in this project.

    `gcloud recommender recommendations list` requires a concrete location —
    passing `--location=-` errors out, and because the failure was swallowed
    the recommender-backed checks never produced a finding. Querying only the
    zones in use keeps the fan-out proportional to the project.
    """
    try:
        instances = await gcloud_runner.run(
            f"gcloud compute instances list --project={project_id} "
            f"--format='value(zone)'",
            parse_json=False,
        )
    except Exception as e:
        logger.debug("Could not enumerate zones for %s: %s", project_id, e)
        return []

    if isinstance(instances, str):
        raw = instances.split("\n")
    elif isinstance(instances, list):
        raw = [str(i) for i in instances]
    else:
        return []

    return sorted({z.strip().split("/")[-1] for z in raw if z and z.strip()})


async def _recommendations(
    project_id: str, gcloud_runner: Any, recommender: str, check_id: str
) -> list[dict]:
    """Collect recommendations across every zone the project uses."""
    results: list[dict] = []
    for zone in await _zones_in_use(project_id, gcloud_runner):
        try:
            recs = await gcloud_runner.run(
                f"gcloud recommender recommendations list "
                f"--recommender={recommender} "
                f"--project={project_id} --location={zone} --format=json"
            )
        except Exception as e:
            logger.debug("%s: no recommendations for zone %s: %s", check_id, zone, e)
            continue
        if isinstance(recs, list):
            results.extend(r for r in recs if isinstance(r, dict))
    return results


class NoBudgetAlerts(BaseCheck):
    id = "BIL-001"
    title = "No billing budget alerts configured"
    description = "Budget alerts prevent unexpected cost overruns by notifying at defined thresholds."
    severity = Severity.HIGH
    category = Category.COST
    service = "Billing"
    service_category = ServiceCategory.BILLING
    references = ["https://cloud.google.com/billing/docs/how-to/budgets"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.16"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            # First, find the billing account for this project
            billing_info = await gcloud_runner.run(f"gcloud beta billing projects describe {project_id} --format=json")
            if not isinstance(billing_info, dict) or "billingAccountName" not in billing_info:
                raise ValueError("Could not find billing account for project")
            
            ba_id = billing_info["billingAccountName"].split("/")[-1]
            budgets = await gcloud_runner.run(f"gcloud billing budgets list --billing-account={ba_id} --format=json")
            
            if not isinstance(budgets, list) or len(budgets) == 0:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"projects/{project_id}", project_id=project_id,
                    resource_link=self.console_link("billing", project_id),
                    current_state="No billing budget alerts configured",
                    recommended_state="Create budgets at 50%, 80%, and 100% of expected spend",
                    fix_command="", references=self.references,
                ))
        except Exception:
            findings.append(CheckResult(
                check_id=self.id, title=self.title, description=self.description,
                severity=self.severity, category=self.category, service=self.service,
                resource_name=f"projects/{project_id}", project_id=project_id,
                resource_link=self.console_link("billing", project_id),
                current_state="Could not verify budgets (may need billing admin permissions)",
                recommended_state="Configure budget alerts via Cloud Console Billing",
                fix_command="", references=self.references,
            ))
        return findings


class UnusedDisks(BaseCheck):
    id = "BIL-002"
    title = "Unused persistent disks (not attached)"
    description = "Unattached disks incur storage charges without serving any workload."
    severity = Severity.MEDIUM
    category = Category.COST
    service = "Billing"
    service_category = ServiceCategory.BILLING
    fix_command_template = "gcloud compute disks delete {name} --zone={zone} --project={project_id} --quiet"
    references = ["https://cloud.google.com/compute/docs/disks"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            disks = await gcloud_runner.run(f"gcloud compute disks list --project={project_id} --format=json")
            if not isinstance(disks, list):
                return []
            for d in disks:
                name = d.get("name", "")
                zone = d.get("zone", "").split("/")[-1] if d.get("zone") else ""
                users = d.get("users", [])
                size_gb = d.get("sizeGb", "?")
                if not users:
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"disks/{name} ({zone})", project_id=project_id,
                        current_state=f"Disk '{name}' ({size_gb} GB) is not attached to any instance",
                        recommended_state="Delete unused disks or create a snapshot and then delete",
                        fix_command=self.build_fix_command(name=name, zone=zone, project_id=project_id),
                        references=self.references,
                    ))
        except Exception as e:
            logger.error("BIL-002 failed: %s", e)
        return findings


class UnusedStaticIPs(BaseCheck):
    id = "BIL-003"
    title = "Unused static external IP addresses"
    description = "Reserved but unassigned static IPs cost ~$7.30/month each."
    severity = Severity.MEDIUM
    category = Category.COST
    service = "Billing"
    service_category = ServiceCategory.BILLING
    fix_command_template = "gcloud compute addresses delete {name} --region={region} --project={project_id} --quiet"
    references = ["https://cloud.google.com/vpc/network-pricing#ipaddress"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            addrs = await gcloud_runner.run(f"gcloud compute addresses list --project={project_id} --format=json")
            if not isinstance(addrs, list):
                return []
            for a in addrs:
                name = a.get("name", "")
                region = a.get("region", "").split("/")[-1] if a.get("region") else "global"
                status = a.get("status", "")
                if status == "RESERVED":
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"addresses/{name} ({region})", project_id=project_id,
                        current_state=f"Static IP '{name}' is reserved but not in use (~$7.30/month)",
                        recommended_state="Release unused static IPs",
                        fix_command=self.build_fix_command(name=name, region=region, project_id=project_id),
                        references=self.references,
                    ))
        except Exception as e:
            logger.error("BIL-003 failed: %s", e)
        return findings


class OldSnapshots(BaseCheck):
    id = "BIL-004"
    title = "Old disk snapshots (>90 days)"
    description = "Old snapshots may no longer be needed and accumulate storage costs."
    severity = Severity.LOW
    category = Category.COST
    service = "Billing"
    service_category = ServiceCategory.BILLING
    references = ["https://cloud.google.com/compute/docs/disks/create-snapshots"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            from datetime import datetime, timezone, timedelta
            snapshots = await gcloud_runner.run(f"gcloud compute snapshots list --project={project_id} --format=json")
            if not isinstance(snapshots, list):
                return []
            threshold = datetime.now(timezone.utc) - timedelta(days=90)
            for s in snapshots:
                name = s.get("name", "")
                created = s.get("creationTimestamp", "")
                if not created:
                    continue
                try:
                    created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                    if created_dt < threshold:
                        age_days = (datetime.now(timezone.utc) - created_dt).days
                        # The Compute API JSON-encodes int64 fields as strings
                        # ("storageBytes": "10737418240"), so dividing directly
                        # raised TypeError into the enclosing handler and every
                        # old snapshot was silently skipped.
                        try:
                            size_gb = int(s.get("storageBytes") or 0) / (1024**3)
                        except (TypeError, ValueError):
                            size_gb = 0.0
                        findings.append(CheckResult(
                            check_id=self.id, title=self.title, description=self.description,
                            severity=self.severity, category=self.category, service=self.service,
                            resource_name=f"snapshots/{name}", project_id=project_id,
                            current_state=f"Snapshot is {age_days} days old ({size_gb:.1f} GB)",
                            recommended_state="Review and delete old snapshots no longer needed",
                            fix_command="", references=self.references,
                        ))
                except (ValueError, TypeError):
                    continue
        except Exception as e:
            logger.debug("BIL-004: %s", e)
        return findings


class NoCommittedUseDiscounts(BaseCheck):
    id = "BIL-005"
    title = "No committed use discounts (CUDs) configured"
    description = "CUDs provide 1-year or 3-year discounts of up to 57% for predictable workloads."
    severity = Severity.MEDIUM
    category = Category.COST
    service = "Billing"
    service_category = ServiceCategory.BILLING
    references = ["https://cloud.google.com/compute/docs/instances/committed-use-discounts-overview"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            commitments = await gcloud_runner.run(f"gcloud compute commitments list --project={project_id} --format=json")
            if not isinstance(commitments, list) or len(commitments) == 0:
                # Only flag if there are running instances
                instances = await gcloud_runner.run(f"gcloud compute instances list --project={project_id} --format=json")
                if isinstance(instances, list) and len(instances) > 2:
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"projects/{project_id}", project_id=project_id,
                        resource_link=self.console_link("billing", project_id),
                        current_state=f"No CUDs with {len(instances)} running instances",
                        recommended_state="Consider 1-year or 3-year CUDs for stable workloads (up to 57% savings)",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.debug("BIL-005: %s", e)
        return findings


class IdleVMs(BaseCheck):
    id = "BIL-006"
    title = "Potentially idle VM instances"
    description = "Instances with very low CPU utilization may be idle and wasting resources."
    severity = Severity.MEDIUM
    category = Category.COST
    service = "Billing"
    service_category = ServiceCategory.BILLING
    references = ["https://cloud.google.com/compute/docs/instances/viewing-and-applying-idle-vm-recommendations"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            recs = await _recommendations(
                project_id,
                gcloud_runner,
                "google.compute.instance.IdleResourceRecommender",
                self.id,
            )
            if isinstance(recs, list):
                for rec in recs:
                    desc = rec.get("description", "Idle VM detected")
                    resource = rec.get("content", {}).get("operationGroups", [{}])[0].get("operations", [{}])[0].get("resource", "")
                    instance_name = resource.split("/")[-1] if resource else "unknown"
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"instances/{instance_name}", project_id=project_id,
                        current_state=desc,
                        recommended_state="Stop or delete idle instances, or resize to smaller type",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.debug("BIL-006: %s", e)
        return findings


class OversizedVMs(BaseCheck):
    id = "BIL-007"
    title = "Oversized VM instances (right-sizing opportunity)"
    description = "Instances may be over-provisioned based on actual resource usage."
    severity = Severity.LOW
    category = Category.COST
    service = "Billing"
    service_category = ServiceCategory.BILLING
    references = ["https://cloud.google.com/compute/docs/instances/apply-machine-type-recommendations-for-instances"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            recs = await _recommendations(
                project_id,
                gcloud_runner,
                "google.compute.instance.MachineTypeRecommender",
                self.id,
            )
            if isinstance(recs, list):
                for rec in recs:
                    desc = rec.get("description", "Right-sizing opportunity")
                    resource = rec.get("content", {}).get("operationGroups", [{}])[0].get("operations", [{}])[0].get("resource", "")
                    instance_name = resource.split("/")[-1] if resource else "unknown"
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"instances/{instance_name}", project_id=project_id,
                        current_state=desc,
                        recommended_state="Resize to recommended machine type for cost savings",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.debug("BIL-007: %s", e)
        return findings


class NoLabelsOnResources(BaseCheck):
    id = "BIL-008"
    title = "Resources without cost-allocation labels"
    description = "Labels enable cost attribution and chargeback across teams and projects."
    severity = Severity.LOW
    category = Category.COST
    service = "Billing"
    service_category = ServiceCategory.BILLING
    references = ["https://cloud.google.com/resource-manager/docs/creating-managing-labels"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await gcloud_runner.run(f"gcloud compute instances list --project={project_id} --format=json")
            if not isinstance(instances, list):
                return []
            unlabeled = 0
            for i in instances:
                labels = i.get("labels", {})
                if not labels:
                    unlabeled += 1
            if unlabeled > 0:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"projects/{project_id}", project_id=project_id,
                    current_state=f"{unlabeled} compute instance(s) have no labels for cost attribution",
                    recommended_state="Add labels (team, environment, cost-center) to all resources",
                    fix_command="", references=self.references,
                ))
        except Exception as e:
            logger.debug("BIL-008: %s", e)
        return findings


class StandardStorageForInfrequentData(BaseCheck):
    id = "BIL-009"
    title = "Standard storage class used for infrequently-accessed data"
    description = "Nearline, Coldline, or Archive storage classes are cheaper for data accessed less than monthly."
    severity = Severity.LOW
    category = Category.COST
    service = "Billing"
    service_category = ServiceCategory.BILLING
    references = ["https://cloud.google.com/storage/docs/storage-classes"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            buckets = await gcloud_runner.run(f"gcloud storage buckets list --project={project_id} --format=json")
            if not isinstance(buckets, list):
                return []
            for b in buckets:
                name = b.get("name", "") or b.get("metadata", {}).get("name", "")
                storage_class = b.get("storageClass", "") or b.get("metadata", {}).get("storageClass", "")
                lifecycle = b.get("lifecycle", {}) or b.get("metadata", {}).get("lifecycle", {})
                rules = lifecycle.get("rule", [])
                if not name:
                    continue
                if storage_class and storage_class.upper() == "STANDARD" and not rules:
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"gs://{name}", project_id=project_id,
                        resource_link=self.console_link("gcs_bucket", project_id, name=name),
                        current_state="Bucket uses STANDARD class with no lifecycle transitions",
                        recommended_state="Add lifecycle rules to transition to Nearline/Coldline for older data",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.debug("BIL-009: %s", e)
        return findings


class BillingExportNotConfigured(BaseCheck):
    id = "BIL-010"
    title = "Billing export to BigQuery not configured"
    description = "Exporting billing data to BigQuery enables detailed cost analysis and custom reports."
    severity = Severity.MEDIUM
    category = Category.COST
    service = "Billing"
    service_category = ServiceCategory.BILLING
    references = ["https://cloud.google.com/billing/docs/how-to/export-data-bigquery"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        # This is informational — we can't easily check billing export via gcloud
        return [CheckResult(
            check_id=self.id, title=self.title, description=self.description,
            severity=Severity.INFO, category=self.category, service=self.service,
            resource_name=f"projects/{project_id}", project_id=project_id,
            resource_link=self.console_link("billing", project_id),
            current_state="Verify billing export to BigQuery is configured",
            recommended_state="Enable billing export to BigQuery for cost analysis and reporting",
            fix_command="", references=self.references,
        )]


# ---------------------------------------------------------------------------
# Additional Billing checks (2026-05 catalog expansion)
# ---------------------------------------------------------------------------


class BigQueryNoPhysicalBilling(BaseCheck):
    id = "BIL-011"
    title = "BigQuery dataset using LOGICAL storage billing (consider PHYSICAL for compressed-heavy data)"
    description = "PHYSICAL storage billing can be cheaper for compressible workloads."
    severity = Severity.INFO
    category = Category.COST
    service = "Billing"
    service_category = ServiceCategory.BILLING
    references = ["https://cloud.google.com/bigquery/docs/datasets-intro#dataset_storage_billing_models"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {}

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
                info = await gcloud_runner.run(
                    f"bq show --project_id={project_id} --format=json {ds_id}"
                )
            except Exception:
                continue
            if not isinstance(info, dict):
                continue
            model = info.get("storageBillingModel", "LOGICAL")
            if model != "PHYSICAL":
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"bq/{ds_id}", project_id=project_id,
                    current_state=f"storageBillingModel={model}",
                    recommended_state="Evaluate PHYSICAL billing for compressible datasets",
                    fix_command="", references=self.references,
                ))
        return findings


class IdleGKENodePool(BaseCheck):
    id = "BIL-012"
    title = "GKE node pool has fixed size and may be idle"
    description = "Fixed-size pools that aren't using autoscaling cost money even when no workloads are scheduled."
    severity = Severity.LOW
    category = Category.COST
    service = "Billing"
    service_category = ServiceCategory.BILLING
    references = ["https://cloud.google.com/kubernetes-engine/docs/concepts/cluster-autoscaler"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            clusters = await gcloud_runner.run(
                f"gcloud container clusters list --project={project_id} --format=json"
            )
        except Exception:
            return findings
        for c in (clusters if isinstance(clusters, list) else []):
            cname = c.get("name", "")
            for pool in c.get("nodePools", []):
                pname = pool.get("name", "")
                autoscaling = pool.get("autoscaling", {})
                if not autoscaling.get("enabled"):
                    initial = pool.get("initialNodeCount", 0)
                    if initial >= 3:
                        findings.append(CheckResult(
                            check_id=self.id, title=self.title, description=self.description,
                            severity=self.severity, category=self.category, service=self.service,
                            resource_name=f"clusters/{cname}/node-pools/{pname}", project_id=project_id,
                            current_state=f"Fixed pool of {initial} nodes (no autoscaling)",
                            recommended_state="Enable autoscaling with sensible min/max",
                            fix_command="", references=self.references,
                        ))
        return findings


# BIL-010 is informational-only and always returns a single finding regardless of
# enabled APIs, so it has no required_apis entry.
import sys as _sys  # noqa: E402
from backend.checks._module_helpers import apply_required_apis_by_id as _apply  # noqa: E402
_apply(_sys.modules[__name__], {
    "BIL-001": ["cloudbilling.googleapis.com"],
    "BIL-002": ["compute.googleapis.com"],
    "BIL-003": ["compute.googleapis.com"],
    "BIL-004": ["compute.googleapis.com"],
    "BIL-005": ["compute.googleapis.com"],
    "BIL-006": ["recommender.googleapis.com"],
    "BIL-007": ["recommender.googleapis.com"],
    "BIL-008": ["compute.googleapis.com"],
    "BIL-009": ["storage.googleapis.com"],
    "BIL-011": ["bigquery.googleapis.com"],
    "BIL-012": ["container.googleapis.com"],
})
