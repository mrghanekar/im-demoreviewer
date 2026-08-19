"""Vertex AI Endpoint checks.

Checks: VTX-003, VTX-004
"""

import logging
from typing import Any, ClassVar

from backend.checks.base import BaseCheck
from backend.core.models import Category, CheckResult, Severity, ServiceCategory

logger = logging.getLogger(__name__)


class ModelEndpointPublic(BaseCheck):
    id = "VTX-003"
    title = "Vertex AI Model Endpoint is publicly accessible"
    description = "Endpoints should typically be deployed to a private VPC for security."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "Vertex AI"
    service_category = ServiceCategory.VERTEX_AI
    references = ["https://cloud.google.com/vertex-ai/docs/general/deployment-resource-pools"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.20", "A.8.21"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            # Try global listing first, fallback to us-central1 if it fails
            try:
                endpoints = await gcloud_runner.run(f"gcloud ai endpoints list --region=- --project={project_id} --format=json")
            except Exception:
                endpoints = await gcloud_runner.run(f"gcloud ai endpoints list --region=us-central1 --project={project_id} --format=json")
            
            if isinstance(endpoints, list):
                for e in endpoints:
                    name = e.get("displayName", "")
                    # If `network` is not set, it is a public endpoint (IAM protected)
                    network = e.get("network")
                    if not network:
                        findings.append(CheckResult(
                            check_id=self.id, title=self.title, description=self.description,
                            severity=self.severity, category=self.category, service=self.service,
                            resource_name=f"endpoints/{name}", project_id=project_id,
                            resource_link=f"https://console.cloud.google.com/vertex-ai/online-prediction/endpoints?project={project_id}",
                            current_state="Endpoint is accessible via public internet (IAM protected)",
                            recommended_state="Deploy to a VPC (Private Service Connect) for internal-only access",
                            fix_command="", references=self.references,
                        ))
        except Exception as e:
            logger.error("VTX-003 failed: %s", e)
        return findings


class VectorSearchPublic(BaseCheck):
    id = "VTX-004"
    title = "Vector Search Index Endpoint is public"
    description = "Vector Search endpoints should be deployed to a VPC for security."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Vertex AI"
    service_category = ServiceCategory.VERTEX_AI
    references = ["https://cloud.google.com/vertex-ai/docs/vector-search/deploy-index-public"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.20", "A.8.21"], "DPDP": ["8(5)"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            # Try global listing first, fallback to us-central1 if it fails
            try:
                endpoints = await gcloud_runner.run(f"gcloud ai index-endpoints list --region=- --project={project_id} --format=json")
            except Exception:
                endpoints = await gcloud_runner.run(f"gcloud ai index-endpoints list --region=us-central1 --project={project_id} --format=json")
            
            if isinstance(endpoints, list):
                for e in endpoints:
                    name = e.get("displayName", "")
                    public = e.get("publicEndpointEnabled", False)
                    # Vector Search added public endpoint support recently.
                    if public:
                        findings.append(CheckResult(
                            check_id=self.id, title=self.title, description=self.description,
                            severity=self.severity, category=self.category, service=self.service,
                            resource_name=f"index-endpoints/{name}", project_id=project_id,
                            resource_link=f"https://console.cloud.google.com/vertex-ai/matching-engine/index-endpoints?project={project_id}",
                            current_state="Vector Search endpoint has public IP enabled",
                            recommended_state="Disable public endpoint and use VPC peering",
                            fix_command="", references=self.references,
                        ))
        except Exception as e:
            logger.error("VTX-004 failed: %s", e)
        return findings


import sys as _sys  # noqa: E402
from backend.checks._module_helpers import apply_required_apis as _apply  # noqa: E402
_apply(_sys.modules[__name__], ["aiplatform.googleapis.com"])
