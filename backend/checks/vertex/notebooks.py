"""Vertex AI Workbench notebook checks.

Checks: VTX-001, VTX-002
"""

import logging
from typing import Any, ClassVar

from backend.checks.base import BaseCheck
from backend.core.models import Category, CheckResult, Severity, ServiceCategory

logger = logging.getLogger(__name__)


class NotebookPublicIP(BaseCheck):
    id = "VTX-001"
    title = "Vertex AI Workbench notebook has public IP"
    description = "Notebooks with public IPs are exposed to the internet, increasing data exfiltration risk."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Vertex AI"
    service_category = ServiceCategory.VERTEX_AI
    references = ["https://cloud.google.com/vertex-ai/docs/workbench/instances/configure-network"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.20"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            # Try global listing first, fallback to us-central1 if it fails
            try:
                instances = await gcloud_runner.run(f"gcloud notebooks instances list --location=- --project={project_id} --format=json")
            except Exception:
                instances = await gcloud_runner.run(f"gcloud notebooks instances list --location=us-central1 --project={project_id} --format=json")
            
            if isinstance(instances, list):
                for i in instances:
                    name = i.get("name", "").split("/")[-1]
                    # 'noPublicIp' is True if public IP is disabled.
                    no_public_ip = i.get("noPublicIp", False)
                    if not no_public_ip:
                        findings.append(CheckResult(
                            check_id=self.id, title=self.title, description=self.description,
                            severity=self.severity, category=self.category, service=self.service,
                            resource_name=f"notebooks/{name}", project_id=project_id,
                            resource_link=f"https://console.cloud.google.com/vertex-ai/workbench/instances?project={project_id}",
                            current_state="Notebook instance has public IP enabled",
                            recommended_state="Disable public IP and use Private Service Connect or Private Google Access",
                            fix_command="", references=self.references,
                        ))
        except Exception as e:
            logger.error("VTX-001 failed: %s", e)
        return findings


class NotebookDefaultSA(BaseCheck):
    id = "VTX-002"
    title = "Notebook using default Compute Engine service account"
    description = "The default Compute Engine SA has broad Editor permissions. Use a custom SA for notebooks."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Vertex AI"
    service_category = ServiceCategory.VERTEX_AI
    references = ["https://cloud.google.com/vertex-ai/docs/general/custom-service-account"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.2", "A.8.3"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await gcloud_runner.run(f"gcloud notebooks instances list --location=- --project={project_id} --format=json")
            if isinstance(instances, list):
                for i in instances:
                    name = i.get("name", "").split("/")[-1]
                    email = i.get("serviceAccount", "")
                    if not email or email.endswith("-compute@developer.gserviceaccount.com"):
                        findings.append(CheckResult(
                            check_id=self.id, title=self.title, description=self.description,
                            severity=self.severity, category=self.category, service=self.service,
                            resource_name=f"notebooks/{name}", project_id=project_id,
                            resource_link=f"https://console.cloud.google.com/vertex-ai/workbench/instances?project={project_id}",
                            current_state=f"Using default SA: {email}",
                            recommended_state="Configure a custom service account with minimal IAM roles",
                            fix_command="", references=self.references,
                        ))
        except Exception as e:
            logger.error("VTX-002 failed: %s", e)
        return findings


# ---------------------------------------------------------------------------
# Additional Vertex AI checks (2026-05 catalog expansion)
# ---------------------------------------------------------------------------


class WorkbenchNoIdleShutdown(BaseCheck):
    id = "VTX-005"
    title = "Vertex AI Workbench instance has no idle shutdown"
    description = "Workbench instances without idle shutdown can run 24/7 with no users connected."
    severity = Severity.MEDIUM
    category = Category.COST
    service = "Vertex AI"
    service_category = ServiceCategory.VERTEX_AI
    references = ["https://cloud.google.com/vertex-ai/docs/workbench/instances/idle-shutdown"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await gcloud_runner.run(
                f"gcloud workbench instances list --location=- --project={project_id} --format=json"
            )
        except Exception:
            return findings
        for i in (instances if isinstance(instances, list) else []):
            name = i.get("name", "").split("/")[-1]
            metadata = i.get("gceSetup", {}).get("metadata", {}) or {}
            if metadata.get("idle-timeout-seconds") in (None, "0", ""):
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"workbench/{name}", project_id=project_id,
                    current_state="No idle-timeout-seconds metadata",
                    recommended_state="Set idle-timeout-seconds (e.g. 3600 = 1 hour)",
                    fix_command="", references=self.references,
                ))
        return findings


class VertexEndpointNoCMEK(BaseCheck):
    id = "VTX-006"
    title = "Vertex AI model endpoint not encrypted with CMEK"
    description = "For regulated data, endpoints should use customer-managed encryption keys."
    severity = Severity.LOW
    category = Category.SECURITY
    service = "Vertex AI"
    service_category = ServiceCategory.VERTEX_AI
    references = ["https://cloud.google.com/vertex-ai/docs/general/cmek"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.24"], "DPDP": ["8(5)"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            endpoints = await gcloud_runner.run(
                f"gcloud ai endpoints list --region=- --project={project_id} --format=json"
            )
        except Exception:
            return findings
        for ep in (endpoints if isinstance(endpoints, list) else []):
            name = ep.get("name", "").split("/")[-1]
            if not ep.get("encryptionSpec", {}).get("kmsKeyName"):
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"endpoints/{name}", project_id=project_id,
                    current_state="No CMEK key configured",
                    recommended_state="Recreate endpoint with --kms-key-name",
                    fix_command="", references=self.references,
                ))
        return findings


class VertexTrainingJobPublicIP(BaseCheck):
    id = "VTX-007"
    title = "Vertex AI custom training job has public IP"
    description = "Training jobs should run on private workers (no external IP)."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "Vertex AI"
    service_category = ServiceCategory.VERTEX_AI
    references = ["https://cloud.google.com/vertex-ai/docs/training/private-ip-network-access"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.20", "A.8.22"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            jobs = await gcloud_runner.run(
                f"gcloud ai custom-jobs list --region=- --project={project_id} --format=json"
            )
        except Exception:
            return findings
        for j in (jobs if isinstance(jobs, list) else []):
            name = j.get("name", "").split("/")[-1]
            if not j.get("jobSpec", {}).get("network"):
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"custom-jobs/{name}", project_id=project_id,
                    current_state="Job has no private network configured",
                    recommended_state="Set --network to peer the training job into your VPC",
                    fix_command="", references=self.references,
                ))
        return findings


import sys as _sys  # noqa: E402
from backend.checks._module_helpers import apply_required_apis as _apply  # noqa: E402
_apply(_sys.modules[__name__], ["aiplatform.googleapis.com"])
