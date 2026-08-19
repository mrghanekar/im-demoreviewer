"""GKE node pool and additional cluster checks.

Checks: GKE-011 through GKE-020
"""

import logging
from typing import Any

from backend.checks.base import BaseCheck
from backend.core.models import Category, CheckResult, Severity, ServiceCategory

logger = logging.getLogger(__name__)


class GKEClusterMonitoring(BaseCheck):
    id = "GKE-011"
    title = "Cloud Monitoring not enabled for cluster"
    description = "Cluster monitoring provides metrics for nodes, pods, and control plane."
    severity = Severity.HIGH
    category = Category.OPERATIONS
    service = "GKE"
    service_category = ServiceCategory.GKE
    references = ["https://cloud.google.com/kubernetes-engine/docs/how-to/monitoring"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            clusters = await gcloud_runner.run(f"gcloud container clusters list --project={project_id} --format=json")
            if not isinstance(clusters, list):
                return []
            for c in clusters:
                name = c.get("name", "")
                zone = c.get("zone", "") or c.get("location", "")
                ms = c.get("monitoringService", "")
                if ms == "none" or not ms:
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"clusters/{name}", project_id=project_id,
                        resource_link=self.console_link("gke_cluster", project_id, name=name, location=zone),
                        current_state=f"Monitoring service: '{ms or 'none'}'",
                        recommended_state="Enable Cloud Monitoring (monitoring.googleapis.com/kubernetes)",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.error("GKE-011 failed: %s", e)
        return findings


class GKENodeAutoScaling(BaseCheck):
    id = "GKE-012"
    title = "Node pool autoscaling not enabled"
    description = "Autoscaling adjusts node count based on workload demand for cost and reliability."
    severity = Severity.MEDIUM
    category = Category.COST
    service = "GKE"
    service_category = ServiceCategory.GKE
    references = ["https://cloud.google.com/kubernetes-engine/docs/concepts/cluster-autoscaler"]

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
                    autoscaling = np.get("autoscaling", {})
                    if not autoscaling.get("enabled", False):
                        findings.append(CheckResult(
                            check_id=self.id, title=self.title, description=self.description,
                            severity=self.severity, category=self.category, service=self.service,
                            resource_name=f"clusters/{name}/nodePools/{np_name}", project_id=project_id,
                            resource_link=self.console_link("gke_cluster", project_id, name=name, location=zone),
                            current_state=f"Autoscaling disabled on node pool '{np_name}'",
                            recommended_state="Enable cluster autoscaler for dynamic workload scaling",
                            fix_command="", references=self.references,
                        ))
        except Exception as e:
            logger.error("GKE-012 failed: %s", e)
        return findings


class GKECosNodeImage(BaseCheck):
    id = "GKE-013"
    title = "Node pool not using COS image type"
    description = "Container-Optimized OS (COS) is hardened and minimal, reducing attack surface."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "GKE"
    service_category = ServiceCategory.GKE
    references = ["https://cloud.google.com/container-optimized-os/docs/concepts/features-and-benefits"]

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
                    img = np.get("config", {}).get("imageType", "")
                    if img and img.upper() not in ("COS_CONTAINERD", "COS"):
                        findings.append(CheckResult(
                            check_id=self.id, title=self.title, description=self.description,
                            severity=self.severity, category=self.category, service=self.service,
                            resource_name=f"clusters/{name}/nodePools/{np_name}", project_id=project_id,
                            resource_link=self.console_link("gke_cluster", project_id, name=name, location=zone),
                            current_state=f"Image type: {img}",
                            recommended_state="Use COS_CONTAINERD for hardened container runtime",
                            fix_command="", references=self.references,
                        ))
        except Exception as e:
            logger.error("GKE-013 failed: %s", e)
        return findings


class GKEMasterAuthorizedNetworks(BaseCheck):
    id = "GKE-014"
    title = "Master authorized networks not configured"
    description = "Restricting access to the cluster master endpoint reduces exposure to attacks."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "GKE"
    service_category = ServiceCategory.GKE
    references = ["https://cloud.google.com/kubernetes-engine/docs/how-to/authorized-networks"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            clusters = await gcloud_runner.run(f"gcloud container clusters list --project={project_id} --format=json")
            if not isinstance(clusters, list):
                return []
            for c in clusters:
                name = c.get("name", "")
                zone = c.get("zone", "") or c.get("location", "")
                ma = c.get("masterAuthorizedNetworksConfig", {})
                if not ma or not ma.get("enabled", False):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"clusters/{name}", project_id=project_id,
                        resource_link=self.console_link("gke_cluster", project_id, name=name, location=zone),
                        current_state="Master authorized networks not configured",
                        recommended_state="Restrict master access to trusted CIDR ranges",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.error("GKE-014 failed: %s", e)
        return findings


class GKEPodSecurityPolicy(BaseCheck):
    id = "GKE-015"
    title = "Pod Security Standards not enforced"
    description = "Pod Security Standards (PSS) restrict pod privilege escalation and host access."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "GKE"
    service_category = ServiceCategory.GKE
    references = ["https://cloud.google.com/kubernetes-engine/docs/how-to/podsecurityadmission"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        # This is informational — PSS enforcement needs namespace-level config
        findings: list[CheckResult] = []
        try:
            clusters = await gcloud_runner.run(f"gcloud container clusters list --project={project_id} --format=json")
            if not isinstance(clusters, list):
                return []
            for c in clusters:
                name = c.get("name", "")
                zone = c.get("zone", "") or c.get("location", "")
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=Severity.INFO, category=self.category, service=self.service,
                    resource_name=f"clusters/{name}", project_id=project_id,
                    resource_link=self.console_link("gke_cluster", project_id, name=name, location=zone),
                    current_state="Verify Pod Security Standards are enforced at namespace level",
                    recommended_state="Apply baseline or restricted PSS profiles to all namespaces",
                    fix_command="", references=self.references,
                ))
        except Exception as e:
            logger.error("GKE-015 failed: %s", e)
        return findings


class GKEVPCNative(BaseCheck):
    id = "GKE-016"
    title = "Cluster not using VPC-native mode"
    description = "VPC-native clusters use alias IP ranges for pods, enabling better networking integration."
    severity = Severity.MEDIUM
    category = Category.PERFORMANCE
    service = "GKE"
    service_category = ServiceCategory.GKE
    references = ["https://cloud.google.com/kubernetes-engine/docs/how-to/alias-ips"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            clusters = await gcloud_runner.run(f"gcloud container clusters list --project={project_id} --format=json")
            if not isinstance(clusters, list):
                return []
            for c in clusters:
                name = c.get("name", "")
                zone = c.get("zone", "") or c.get("location", "")
                ip_alloc = c.get("ipAllocationPolicy", {})
                if not ip_alloc.get("useIpAliases", False):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"clusters/{name}", project_id=project_id,
                        resource_link=self.console_link("gke_cluster", project_id, name=name, location=zone),
                        current_state="Cluster is using routes-based networking (legacy)",
                        recommended_state="Use VPC-native mode with alias IPs",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.error("GKE-016 failed: %s", e)
        return findings


class GKEDatabaseEncryption(BaseCheck):
    id = "GKE-017"
    title = "Application-layer secrets encryption not enabled"
    description = "Encrypts etcd secrets with a Cloud KMS key for defense in depth."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "GKE"
    service_category = ServiceCategory.GKE
    references = ["https://cloud.google.com/kubernetes-engine/docs/how-to/encrypting-secrets"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            clusters = await gcloud_runner.run(f"gcloud container clusters list --project={project_id} --format=json")
            if not isinstance(clusters, list):
                return []
            for c in clusters:
                name = c.get("name", "")
                zone = c.get("zone", "") or c.get("location", "")
                de = c.get("databaseEncryption", {})
                if not de or de.get("state") != "ENCRYPTED":
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"clusters/{name}", project_id=project_id,
                        resource_link=self.console_link("gke_cluster", project_id, name=name, location=zone),
                        current_state="Application-layer secrets encryption is not enabled",
                        recommended_state="Enable with a Cloud KMS key for etcd encryption",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.error("GKE-017 failed: %s", e)
        return findings


class GKEReleasChannel(BaseCheck):
    id = "GKE-018"
    title = "Cluster not enrolled in a release channel"
    description = "Release channels provide automated version management and stability guarantees."
    severity = Severity.MEDIUM
    category = Category.RELIABILITY
    service = "GKE"
    service_category = ServiceCategory.GKE
    references = ["https://cloud.google.com/kubernetes-engine/docs/concepts/release-channels"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            clusters = await gcloud_runner.run(f"gcloud container clusters list --project={project_id} --format=json")
            if not isinstance(clusters, list):
                return []
            for c in clusters:
                name = c.get("name", "")
                zone = c.get("zone", "") or c.get("location", "")
                rc = c.get("releaseChannel", {})
                if not rc or rc.get("channel") == "UNSPECIFIED":
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"clusters/{name}", project_id=project_id,
                        resource_link=self.console_link("gke_cluster", project_id, name=name, location=zone),
                        current_state="Cluster not enrolled in any release channel",
                        recommended_state="Enroll in REGULAR or STABLE release channel",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.error("GKE-018 failed: %s", e)
        return findings


class GKEMaintenanceWindow(BaseCheck):
    id = "GKE-019"
    title = "No maintenance window configured"
    description = "A maintenance window controls when GKE can perform upgrades and maintenance."
    severity = Severity.LOW
    category = Category.OPERATIONS
    service = "GKE"
    service_category = ServiceCategory.GKE
    references = ["https://cloud.google.com/kubernetes-engine/docs/how-to/maintenance-windows-and-exclusions"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            clusters = await gcloud_runner.run(f"gcloud container clusters list --project={project_id} --format=json")
            if not isinstance(clusters, list):
                return []
            for c in clusters:
                name = c.get("name", "")
                zone = c.get("zone", "") or c.get("location", "")
                mp = c.get("maintenancePolicy", {})
                if not mp or not mp.get("window"):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"clusters/{name}", project_id=project_id,
                        resource_link=self.console_link("gke_cluster", project_id, name=name, location=zone),
                        current_state="No maintenance window configured",
                        recommended_state="Set a maintenance window during off-peak hours",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.error("GKE-019 failed: %s", e)
        return findings


class GKEVerticalPodAutoscaler(BaseCheck):
    id = "GKE-020"
    title = "Vertical Pod Autoscaler not enabled"
    description = "VPA recommends and automatically adjusts CPU/memory requests for optimal sizing."
    severity = Severity.LOW
    category = Category.COST
    service = "GKE"
    service_category = ServiceCategory.GKE
    references = ["https://cloud.google.com/kubernetes-engine/docs/concepts/verticalpodautoscaler"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            clusters = await gcloud_runner.run(f"gcloud container clusters list --project={project_id} --format=json")
            if not isinstance(clusters, list):
                return []
            for c in clusters:
                name = c.get("name", "")
                zone = c.get("zone", "") or c.get("location", "")
                vpa = c.get("verticalPodAutoscaling", {})
                if not vpa.get("enabled", False):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"clusters/{name}", project_id=project_id,
                        resource_link=self.console_link("gke_cluster", project_id, name=name, location=zone),
                        current_state="Vertical Pod Autoscaler is not enabled",
                        recommended_state="Enable VPA for right-sizing pod resource requests",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.error("GKE-020 failed: %s", e)
        return findings


import sys as _sys  # noqa: E402
from backend.checks._module_helpers import apply_required_apis as _apply  # noqa: E402
_apply(_sys.modules[__name__], ["container.googleapis.com"])
