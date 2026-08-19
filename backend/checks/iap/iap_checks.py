"""Identity-Aware Proxy (IAP) checks.

Checks: IAP-001 through IAP-003
"""

import logging
from typing import Any, ClassVar

from backend.checks.base import BaseCheck
from backend.core.models import Category, CheckResult, Severity, ServiceCategory

logger = logging.getLogger(__name__)


class IAPNoBrand(BaseCheck):
    id = "IAP-001"
    title = "No OAuth brand configured (IAP unusable)"
    description = "IAP requires an OAuth consent screen 'brand' before it can secure resources."
    severity = Severity.LOW
    category = Category.SECURITY
    service = "IAP"
    service_category = ServiceCategory.IAP
    references = ["https://cloud.google.com/iap/docs/programmatic-oauth-clients"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            brands = await gcloud_runner.run(
                f"gcloud iap oauth-brands list --project={project_id} --format=json"
            )
        except Exception as e:
            logger.debug("IAP brands list failed: %s", e)
            return findings
        if not isinstance(brands, list) or len(brands) == 0:
            findings.append(CheckResult(
                check_id=self.id, title=self.title, description=self.description,
                severity=self.severity, category=self.category, service=self.service,
                resource_name=f"projects/{project_id}", project_id=project_id,
                current_state="No OAuth brand configured",
                recommended_state="Create a brand so IAP can be used to gate access",
                fix_command="", references=self.references,
            ))
        return findings


class IAPLoadBalancersWithoutIAP(BaseCheck):
    id = "IAP-002"
    title = "External HTTPS load balancer backend service has IAP disabled"
    description = "Public-facing backend services should be considered for IAP-gated access."
    severity = Severity.LOW
    category = Category.SECURITY
    service = "IAP"
    service_category = ServiceCategory.IAP
    references = ["https://cloud.google.com/iap/docs/enabling-compute-howto"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.5.15", "A.8.5", "A.8.21"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            backends = await gcloud_runner.run(
                f"gcloud compute backend-services list --project={project_id} --format=json"
            )
        except Exception:
            return findings
        for b in (backends if isinstance(backends, list) else []):
            name = b.get("name", "")
            iap = b.get("iap", {})
            if not iap.get("enabled"):
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"backend-services/{name}", project_id=project_id,
                    current_state="IAP not enabled on backend service",
                    recommended_state="Enable IAP if this backend serves internal/SSO users",
                    fix_command="", references=self.references,
                ))
        return findings


class IAPAppEngineNotProtected(BaseCheck):
    id = "IAP-003"
    title = "App Engine app exists but IAP is not enabled"
    description = "App Engine apps should be considered for IAP-gated access."
    severity = Severity.LOW
    category = Category.SECURITY
    service = "IAP"
    service_category = ServiceCategory.IAP
    references = ["https://cloud.google.com/iap/docs/app-engine-quickstart"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.5.15", "A.8.5"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            app = await gcloud_runner.run(
                f"gcloud app describe --project={project_id} --format=json"
            )
        except Exception:
            return findings
        if not isinstance(app, dict) or not app.get("id"):
            return findings
        # Check IAP settings for the app
        try:
            settings = await gcloud_runner.run(
                f"gcloud iap settings get --resource-type=app-engine --project={project_id} --format=json"
            )
            enabled = isinstance(settings, dict) and settings.get("accessSettings", {}).get("oauthSettings")
        except Exception:
            enabled = False
        if not enabled:
            findings.append(CheckResult(
                check_id=self.id, title=self.title, description=self.description,
                severity=self.severity, category=self.category, service=self.service,
                resource_name=f"appengine/{app.get('id')}", project_id=project_id,
                current_state="App Engine app exists but IAP appears disabled",
                recommended_state="Enable IAP for App Engine if internal-only",
                fix_command="", references=self.references,
            ))
        return findings


import sys as _sys  # noqa: E402
from backend.checks._module_helpers import apply_required_apis as _apply  # noqa: E402
_apply(_sys.modules[__name__], ["iap.googleapis.com"])
