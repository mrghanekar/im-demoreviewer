"""AlloyDB checks.

Checks: ADB-001 through ADB-005.

AlloyDB is Google's Postgres-compatible managed DB; same risk surface as
Cloud SQL (public IP, missing backups, no CMEK, deletion protection) so we
mirror the DB-* shape per-service.
"""

import logging
from typing import Any, ClassVar

from backend.checks.base import BaseCheck
from backend.core.models import Category, CheckResult, Severity, ServiceCategory

logger = logging.getLogger(__name__)


async def _list_clusters(gcloud_runner: Any, project_id: str) -> list[dict]:
    """Discover AlloyDB clusters across all regions in one call."""
    return await gcloud_runner.list(
        f"gcloud alloydb clusters list --region=- --project={project_id} --format=json"
    )


def _cluster_region(c: dict) -> str:
    """Extract region from a cluster's full name (projects/.../locations/REGION/clusters/...)."""
    name = c.get("name", "")
    parts = name.split("/")
    if len(parts) >= 4 and parts[2] == "locations":
        return parts[3]
    return ""


def _cluster_id(c: dict) -> str:
    return c.get("name", "").split("/")[-1]


class AlloyDBNoAutomatedBackups(BaseCheck):
    id = "ADB-001"
    title = "AlloyDB cluster has no automated backup policy"
    description = "Without an automated backup policy, point-in-time recovery is impossible after data loss."
    severity = Severity.HIGH
    category = Category.RELIABILITY
    service = "AlloyDB"
    service_category = ServiceCategory.ALLOYDB
    references = ["https://cloud.google.com/alloydb/docs/backup/overview"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.13"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for c in await _list_clusters(gcloud_runner, project_id):
            policy = c.get("automatedBackupPolicy", {})
            if not policy.get("enabled"):
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"alloydb/{_cluster_id(c)}", project_id=project_id,
                    current_state="automatedBackupPolicy.enabled is false or unset",
                    recommended_state="Enable automated backups with daily schedule + 14d retention",
                    fix_command="", references=self.references,
                ))
        return findings


class AlloyDBNoDeletionProtection(BaseCheck):
    id = "ADB-002"
    title = "AlloyDB cluster has no deletion protection"
    description = "Deletion protection prevents accidental DROP CLUSTER on production data."
    severity = Severity.HIGH
    category = Category.RELIABILITY
    service = "AlloyDB"
    service_category = ServiceCategory.ALLOYDB
    references = ["https://cloud.google.com/alloydb/docs/cluster-delete-protect"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.10"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for c in await _list_clusters(gcloud_runner, project_id):
            if not c.get("deletionProtection"):
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"alloydb/{_cluster_id(c)}", project_id=project_id,
                    current_state="deletionProtection=false",
                    recommended_state="Set --deletion-protection on production clusters",
                    fix_command=f"gcloud alloydb clusters update {_cluster_id(c)} --region={_cluster_region(c)} --project={project_id} --deletion-protection",
                    references=self.references,
                ))
        return findings


class AlloyDBNoCMEK(BaseCheck):
    id = "ADB-003"
    title = "AlloyDB cluster not encrypted with CMEK"
    description = "Google-managed encryption is the default; CMEK is required by some regulated workloads."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "AlloyDB"
    service_category = ServiceCategory.ALLOYDB
    references = ["https://cloud.google.com/alloydb/docs/cmek"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.24"], "DPDP": ["8(5)"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for c in await _list_clusters(gcloud_runner, project_id):
            enc = c.get("encryptionConfig", {}) or {}
            if not enc.get("kmsKeyName"):
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"alloydb/{_cluster_id(c)}", project_id=project_id,
                    current_state="No kmsKeyName configured (Google-managed encryption)",
                    recommended_state="Configure --kms-key for CMEK on regulated clusters",
                    fix_command="", references=self.references,
                ))
        return findings


class AlloyDBPublicIP(BaseCheck):
    id = "ADB-004"
    title = "AlloyDB cluster has a public IP endpoint"
    description = "AlloyDB clusters should be reachable only via Private Service Connect or VPC peering."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "AlloyDB"
    service_category = ServiceCategory.ALLOYDB
    references = ["https://cloud.google.com/alloydb/docs/connect-public-ip"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.20", "A.8.22"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for c in await _list_clusters(gcloud_runner, project_id):
            network_cfg = c.get("networkConfig", {}) or {}
            # When publicIpEnabled is true OR a public IP address is allocated,
            # surface the cluster as internet-reachable.
            psc = c.get("pscConfig", {}) or {}
            if network_cfg.get("publicIpEnabled") or not psc.get("pscEnabled"):
                instances = c.get("primaryInstance", {}) or {}
                if instances.get("publicIpEnabled") or network_cfg.get("publicIpEnabled"):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"alloydb/{_cluster_id(c)}", project_id=project_id,
                        current_state="Cluster instance has publicIpEnabled or no PSC enforcement",
                        recommended_state="Disable public IP and use Private Service Connect",
                        fix_command="", references=self.references,
                    ))
        return findings


class AlloyDBNoContinuousBackup(BaseCheck):
    id = "ADB-005"
    title = "AlloyDB cluster has no continuous backup (point-in-time recovery)"
    description = "Continuous backup is required for PITR — without it you can only restore to last automated backup."
    severity = Severity.MEDIUM
    category = Category.RELIABILITY
    service = "AlloyDB"
    service_category = ServiceCategory.ALLOYDB
    references = ["https://cloud.google.com/alloydb/docs/backup/continuous-backup-overview"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.13", "A.5.29"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for c in await _list_clusters(gcloud_runner, project_id):
            cb = c.get("continuousBackupConfig", {}) or {}
            if not cb.get("enabled"):
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"alloydb/{_cluster_id(c)}", project_id=project_id,
                    current_state="continuousBackupConfig.enabled is false or unset",
                    recommended_state="Enable continuous backup for PITR recovery",
                    fix_command="", references=self.references,
                ))
        return findings


import sys as _sys  # noqa: E402
from backend.checks._module_helpers import apply_required_apis as _apply  # noqa: E402
_apply(_sys.modules[__name__], ["alloydb.googleapis.com"])
