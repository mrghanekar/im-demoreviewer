"""GKE cluster security, reliability, and performance checks.

Checks: GKE-001 through GKE-010
"""

import logging
from typing import Any

from backend.checks.base import BaseCheck
from backend.core.models import Category, CheckResult, Severity, ServiceCategory

logger = logging.getLogger(__name__)


class GKELegacyAuth(BaseCheck):
    id = "GKE-001"
    title = "Legacy ABAC authorization enabled"
    description = "Legacy ABAC should be disabled in favor of RBAC for fine-grained access control."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    service = "GKE"
    service_category = ServiceCategory.GKE
    gcloud_command = "gcloud container clusters list --project={project_id} --format=json"
    fix_command_template = "gcloud container clusters update {name} --no-enable-legacy-authorization --zone={zone} --project={project_id}"
    references = ["https://cloud.google.com/kubernetes-engine/docs/how-to/role-based-access-control"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            clusters = await gcloud_runner.run(f"gcloud container clusters list --project={project_id} --format=json")
            if not isinstance(clusters, list):
                return []
            for c in clusters:
                name = c.get("name", "")
                zone = c.get("zone", "") or c.get("location", "")
                if c.get("legacyAbac", {}).get("enabled", False):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"clusters/{name}", project_id=project_id,
                        resource_link=self.console_link("gke_cluster", project_id, name=name, location=zone),
                        current_state="Legacy ABAC authorization is enabled",
                        recommended_state="Disable legacy ABAC and use RBAC",
                        fix_command=self.build_fix_command(name=name, zone=zone, project_id=project_id),
                        references=self.references,
                    ))
        except Exception as e:
            logger.error("GKE-001 failed: %s", e)
        return findings


class GKENetworkPolicy(BaseCheck):
    id = "GKE-002"
    title = "Network policy not enabled on cluster"
    description = "Network policies control pod-to-pod communication and limit lateral movement."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "GKE"
    service_category = ServiceCategory.GKE
    fix_command_template = "gcloud container clusters update {name} --enable-network-policy --zone={zone} --project={project_id}"
    references = ["https://cloud.google.com/kubernetes-engine/docs/how-to/network-policy"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            clusters = await gcloud_runner.run(f"gcloud container clusters list --project={project_id} --format=json")
            if not isinstance(clusters, list):
                return []
            for c in clusters:
                name = c.get("name", "")
                zone = c.get("zone", "") or c.get("location", "")
                np = c.get("networkPolicy", {})
                if not np or not np.get("enabled", False):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"clusters/{name}", project_id=project_id,
                        resource_link=self.console_link("gke_cluster", project_id, name=name, location=zone),
                        current_state="Network policy enforcement is disabled",
                        recommended_state="Enable Calico network policy enforcement",
                        fix_command=self.build_fix_command(name=name, zone=zone, project_id=project_id),
                        references=self.references,
                    ))
        except Exception as e:
            logger.error("GKE-002 failed: %s", e)
        return findings


class GKEWorkloadIdentity(BaseCheck):
    id = "GKE-003"
    title = "Workload Identity not enabled on cluster"
    description = "Workload Identity is the recommended way for workloads to access GCP APIs securely."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "GKE"
    service_category = ServiceCategory.GKE
    fix_command_template = "gcloud container clusters update {name} --workload-pool={project_id}.svc.id.goog --zone={zone} --project={project_id}"
    references = ["https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            clusters = await gcloud_runner.run(f"gcloud container clusters list --project={project_id} --format=json")
            if not isinstance(clusters, list):
                return []
            for c in clusters:
                name = c.get("name", "")
                zone = c.get("zone", "") or c.get("location", "")
                wid = c.get("workloadIdentityConfig", {})
                if not wid or not wid.get("workloadPool"):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"clusters/{name}", project_id=project_id,
                        resource_link=self.console_link("gke_cluster", project_id, name=name, location=zone),
                        current_state="Workload Identity is not configured",
                        recommended_state="Enable Workload Identity for secure GCP API access from pods",
                        fix_command=self.build_fix_command(name=name, zone=zone, project_id=project_id),
                        references=self.references,
                    ))
        except Exception as e:
            logger.error("GKE-003 failed: %s", e)
        return findings


class GKEShieldedNodes(BaseCheck):
    id = "GKE-004"
    title = "Shielded GKE Nodes not enabled"
    description = "Shielded nodes verify node identity and integrity using vTPM and Secure Boot."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "GKE"
    service_category = ServiceCategory.GKE
    fix_command_template = "gcloud container clusters update {name} --enable-shielded-nodes --zone={zone} --project={project_id}"
    references = ["https://cloud.google.com/kubernetes-engine/docs/how-to/shielded-gke-nodes"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            clusters = await gcloud_runner.run(f"gcloud container clusters list --project={project_id} --format=json")
            if not isinstance(clusters, list):
                return []
            for c in clusters:
                name = c.get("name", "")
                zone = c.get("zone", "") or c.get("location", "")
                if not c.get("shieldedNodes", {}).get("enabled", False):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"clusters/{name}", project_id=project_id,
                        resource_link=self.console_link("gke_cluster", project_id, name=name, location=zone),
                        current_state="Shielded GKE Nodes are not enabled",
                        recommended_state="Enable Shielded Nodes for verified boot and node integrity",
                        fix_command=self.build_fix_command(name=name, zone=zone, project_id=project_id),
                        references=self.references,
                    ))
        except Exception as e:
            logger.error("GKE-004 failed: %s", e)
        return findings


class GKEPrivateCluster(BaseCheck):
    id = "GKE-005"
    title = "Cluster not configured as private"
    description = "Private clusters prevent nodes from having public IP addresses, reducing attack surface."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "GKE"
    service_category = ServiceCategory.GKE
    references = ["https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            clusters = await gcloud_runner.run(f"gcloud container clusters list --project={project_id} --format=json")
            if not isinstance(clusters, list):
                return []
            for c in clusters:
                name = c.get("name", "")
                zone = c.get("zone", "") or c.get("location", "")
                pc = c.get("privateClusterConfig", {})
                if not pc or not pc.get("enablePrivateNodes", False):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"clusters/{name}", project_id=project_id,
                        resource_link=self.console_link("gke_cluster", project_id, name=name, location=zone),
                        current_state="Cluster nodes have public IP addresses",
                        recommended_state="Configure as private cluster to remove public IPs from nodes",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.error("GKE-005 failed: %s", e)
        return findings


class GKEAutoUpgrade(BaseCheck):
    id = "GKE-006"
    title = "Node auto-upgrade not enabled"
    description = "Auto-upgrade keeps nodes on supported and patched Kubernetes versions."
    severity = Severity.HIGH
    category = Category.RELIABILITY
    service = "GKE"
    service_category = ServiceCategory.GKE
    references = ["https://cloud.google.com/kubernetes-engine/docs/how-to/node-auto-upgrades"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            clusters = await gcloud_runner.run(f"gcloud container clusters list --project={project_id} --format=json")
            if not isinstance(clusters, list):
                return []
            for c in clusters:
                name = c.get("name", "")
                zone = c.get("zone", "") or c.get("location", "")
                for np in c.get("nodePools", []):
                    np_name = np.get("name", "")
                    mgmt = np.get("management", {})
                    if not mgmt.get("autoUpgrade", False):
                        findings.append(CheckResult(
                            check_id=self.id, title=self.title, description=self.description,
                            severity=self.severity, category=self.category, service=self.service,
                            resource_name=f"clusters/{name}/nodePools/{np_name}", project_id=project_id,
                            resource_link=self.console_link("gke_cluster", project_id, name=name, location=zone),
                            current_state=f"Auto-upgrade disabled on node pool '{np_name}'",
                            recommended_state="Enable auto-upgrade on all node pools",
                            fix_command="", references=self.references,
                        ))
        except Exception as e:
            logger.error("GKE-006 failed: %s", e)
        return findings


class GKEAutoRepair(BaseCheck):
    id = "GKE-007"
    title = "Node auto-repair not enabled"
    description = "Auto-repair automatically fixes unhealthy nodes to maintain cluster reliability."
    severity = Severity.MEDIUM
    category = Category.RELIABILITY
    service = "GKE"
    service_category = ServiceCategory.GKE
    references = ["https://cloud.google.com/kubernetes-engine/docs/how-to/node-auto-repair"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            clusters = await gcloud_runner.run(f"gcloud container clusters list --project={project_id} --format=json")
            if not isinstance(clusters, list):
                return []
            for c in clusters:
                name = c.get("name", "")
                zone = c.get("zone", "") or c.get("location", "")
                for np in c.get("nodePools", []):
                    np_name = np.get("name", "")
                    mgmt = np.get("management", {})
                    if not mgmt.get("autoRepair", False):
                        findings.append(CheckResult(
                            check_id=self.id, title=self.title, description=self.description,
                            severity=self.severity, category=self.category, service=self.service,
                            resource_name=f"clusters/{name}/nodePools/{np_name}", project_id=project_id,
                            resource_link=self.console_link("gke_cluster", project_id, name=name, location=zone),
                            current_state=f"Auto-repair disabled on node pool '{np_name}'",
                            recommended_state="Enable auto-repair to automatically fix unhealthy nodes",
                            fix_command="", references=self.references,
                        ))
        except Exception as e:
            logger.error("GKE-007 failed: %s", e)
        return findings


class GKEBinaryAuthorization(BaseCheck):
    id = "GKE-008"
    title = "Binary Authorization not enabled"
    description = "Binary Authorization ensures only trusted container images are deployed."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "GKE"
    service_category = ServiceCategory.GKE
    references = ["https://cloud.google.com/binary-authorization/docs/overview"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            clusters = await gcloud_runner.run(f"gcloud container clusters list --project={project_id} --format=json")
            if not isinstance(clusters, list):
                return []
            for c in clusters:
                name = c.get("name", "")
                zone = c.get("zone", "") or c.get("location", "")
                ba = c.get("binaryAuthorization", {})
                if not ba or not ba.get("enabled", False):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"clusters/{name}", project_id=project_id,
                        resource_link=self.console_link("gke_cluster", project_id, name=name, location=zone),
                        current_state="Binary Authorization is not enabled",
                        recommended_state="Enable Binary Authorization for deploy-time security",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.error("GKE-008 failed: %s", e)
        return findings


class GKEIntraNodeVisibility(BaseCheck):
    id = "GKE-009"
    title = "Intranode visibility not enabled"
    description = "Intranode visibility exposes pod-to-pod traffic to VPC flow logs for monitoring."
    severity = Severity.LOW
    category = Category.OPERATIONS
    service = "GKE"
    service_category = ServiceCategory.GKE
    references = ["https://cloud.google.com/kubernetes-engine/docs/how-to/intranode-visibility"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            clusters = await gcloud_runner.run(f"gcloud container clusters list --project={project_id} --format=json")
            if not isinstance(clusters, list):
                return []
            for c in clusters:
                name = c.get("name", "")
                zone = c.get("zone", "") or c.get("location", "")
                nc = c.get("networkConfig", {})
                if not nc.get("enableIntraNodeVisibility", False):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"clusters/{name}", project_id=project_id,
                        resource_link=self.console_link("gke_cluster", project_id, name=name, location=zone),
                        current_state="Intranode visibility is disabled",
                        recommended_state="Enable intranode visibility for pod traffic flow logs",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.error("GKE-009 failed: %s", e)
        return findings


class GKEClusterLogging(BaseCheck):
    id = "GKE-010"
    title = "Cloud Logging not enabled for cluster"
    description = "Cluster logging should be enabled for audit trails and troubleshooting."
    severity = Severity.HIGH
    category = Category.OPERATIONS
    service = "GKE"
    service_category = ServiceCategory.GKE
    references = ["https://cloud.google.com/kubernetes-engine/docs/how-to/logging"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            clusters = await gcloud_runner.run(f"gcloud container clusters list --project={project_id} --format=json")
            if not isinstance(clusters, list):
                return []
            for c in clusters:
                name = c.get("name", "")
                zone = c.get("zone", "") or c.get("location", "")
                ls = c.get("loggingService", "")
                if ls == "none" or not ls:
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"clusters/{name}", project_id=project_id,
                        resource_link=self.console_link("gke_cluster", project_id, name=name, location=zone),
                        current_state=f"Logging service: '{ls or 'none'}'",
                        recommended_state="Enable Cloud Logging (logging.googleapis.com/kubernetes)",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.error("GKE-010 failed: %s", e)
        return findings


# ---------------------------------------------------------------------------
# Additional GKE checks (2026-05 catalog expansion)
# ---------------------------------------------------------------------------


async def _list_gke_clusters(gcloud_runner: Any, project_id: str) -> list[dict]:
    try:
        c = await gcloud_runner.run(
            f"gcloud container clusters list --project={project_id} --format=json"
        )
        return c if isinstance(c, list) else []
    except Exception as e:
        logger.debug("GKE clusters list failed: %s", e)
        return []


DEPRECATED_K8S_MINORS = {"1.26", "1.27", "1.28"}


class GKEDeprecatedKubernetesVersion(BaseCheck):
    id = "GKE-021"
    title = "GKE cluster runs on a deprecated Kubernetes minor version"
    description = "Old K8s minors stop receiving security patches and may be force-upgraded."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "GKE"
    service_category = ServiceCategory.GKE
    references = ["https://cloud.google.com/kubernetes-engine/docs/release-notes"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for c in await _list_gke_clusters(gcloud_runner, project_id):
            name = c.get("name", "")
            version = c.get("currentMasterVersion", "")
            minor = ".".join(version.split(".")[:2]) if version else ""
            if minor in DEPRECATED_K8S_MINORS:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"clusters/{name}", project_id=project_id,
                    current_state=f"Master version: {version} (minor {minor} deprecated)",
                    recommended_state="Upgrade to a supported minor version",
                    fix_command="", references=self.references,
                ))
        return findings


class GKEBackupNotEnabled(BaseCheck):
    id = "GKE-022"
    title = "Backup for GKE add-on not enabled"
    description = "Backup for GKE provides workload-aware backup/restore for cluster resources + PVs."
    severity = Severity.MEDIUM
    category = Category.RELIABILITY
    service = "GKE"
    service_category = ServiceCategory.GKE
    references = ["https://cloud.google.com/kubernetes-engine/docs/add-on/backup-for-gke/concepts/backup-for-gke"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for c in await _list_gke_clusters(gcloud_runner, project_id):
            name = c.get("name", "")
            bfg = c.get("addonsConfig", {}).get("gkeBackupAgentConfig", {})
            if not bfg.get("enabled"):
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"clusters/{name}", project_id=project_id,
                    current_state="Backup for GKE add-on disabled",
                    recommended_state="Enable the gke-backup add-on and create backup plans",
                    fix_command="", references=self.references,
                ))
        return findings


class GKEAutopilotRecommendation(BaseCheck):
    id = "GKE-023"
    title = "GKE cluster is Standard (consider Autopilot for hardened defaults)"
    description = "Autopilot enforces Pod Security Standards by default and shifts node-mgmt risk to Google."
    severity = Severity.INFO
    category = Category.SECURITY
    service = "GKE"
    service_category = ServiceCategory.GKE
    references = ["https://cloud.google.com/kubernetes-engine/docs/concepts/autopilot-overview"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for c in await _list_gke_clusters(gcloud_runner, project_id):
            name = c.get("name", "")
            if not c.get("autopilot", {}).get("enabled"):
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"clusters/{name}", project_id=project_id,
                    current_state="Standard GKE cluster (not Autopilot)",
                    recommended_state="Consider Autopilot for new clusters — hardened defaults",
                    fix_command="", references=self.references,
                ))
        return findings


import sys as _sys  # noqa: E402
from backend.checks._module_helpers import apply_required_apis as _apply  # noqa: E402
_apply(_sys.modules[__name__], ["container.googleapis.com"])
