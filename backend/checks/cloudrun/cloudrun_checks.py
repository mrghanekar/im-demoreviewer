"""Cloud Run service checks.

Checks: CR-001 through CR-008
"""

import logging
from typing import Any

from backend.checks.base import BaseCheck
from backend.core.models import Category, CheckResult, Severity, ServiceCategory

logger = logging.getLogger(__name__)

LIST_CMD = "gcloud run services list --project={project_id} --platform=managed --format=json"


async def _list_services(gcloud_runner: Any, project_id: str) -> list[dict]:
    try:
        services = await gcloud_runner.run(LIST_CMD.format(project_id=project_id))
        return services if isinstance(services, list) else []
    except Exception as e:
        logger.debug("Cloud Run list failed: %s", e)
        return []


def _service_name(svc: dict) -> str:
    return svc.get("metadata", {}).get("name", "") or svc.get("name", "")


def _region(svc: dict) -> str:
    return svc.get("metadata", {}).get("labels", {}).get("cloud.googleapis.com/location", "")


class CloudRunPublicAccess(BaseCheck):
    id = "CR-001"
    title = "Cloud Run service allows unauthenticated (public) access"
    description = "Service has allUsers granted roles/run.invoker, exposing it to the internet."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Cloud Run"
    service_category = ServiceCategory.CLOUD_RUN
    fix_command_template = "gcloud run services remove-iam-policy-binding {name} --member=allUsers --role=roles/run.invoker --region={region} --project={project_id}"
    references = ["https://cloud.google.com/run/docs/authenticating/overview"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for svc in await _list_services(gcloud_runner, project_id):
            name = _service_name(svc)
            region = _region(svc) or "REGION"
            if not name:
                continue
            try:
                policy = await gcloud_runner.run(
                    f"gcloud run services get-iam-policy {name} --region={region} --project={project_id} --format=json"
                )
            except Exception:
                continue
            if not isinstance(policy, dict):
                continue
            for binding in policy.get("bindings", []):
                if binding.get("role") == "roles/run.invoker" and "allUsers" in binding.get("members", []):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"services/{name}", project_id=project_id,
                        current_state="allUsers has roles/run.invoker — service is public",
                        recommended_state="Restrict invoker to specific principals or use IAP",
                        fix_command=self.build_fix_command(name=name, region=region, project_id=project_id),
                        references=self.references,
                    ))
        return findings


class CloudRunPlaintextSecrets(BaseCheck):
    id = "CR-002"
    title = "Cloud Run service has secret-looking values in plaintext env vars"
    description = "Env vars matching SECRET/PASSWORD/TOKEN/KEY naming patterns should come from Secret Manager."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Cloud Run"
    service_category = ServiceCategory.CLOUD_RUN
    references = ["https://cloud.google.com/run/docs/configuring/secrets"]

    SECRET_PATTERNS = ("SECRET", "PASSWORD", "PASSWD", "TOKEN", "API_KEY", "PRIVATE_KEY", "CREDENTIALS")

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for svc in await _list_services(gcloud_runner, project_id):
            name = _service_name(svc)
            if not name:
                continue
            containers = svc.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
            suspicious: list[str] = []
            for c in containers:
                for env in c.get("env", []):
                    env_name = env.get("name", "")
                    has_value = "value" in env and env["value"]
                    has_secret_ref = bool(env.get("valueFrom", {}).get("secretKeyRef"))
                    if has_value and not has_secret_ref:
                        if any(p in env_name.upper() for p in self.SECRET_PATTERNS):
                            suspicious.append(env_name)
            if suspicious:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"services/{name}", project_id=project_id,
                    current_state=f"Env vars in plaintext that look secret: {', '.join(suspicious[:5])}",
                    recommended_state="Mount via --set-secrets from Secret Manager",
                    fix_command="", references=self.references,
                ))
        return findings


class CloudRunNoVPCConnector(BaseCheck):
    id = "CR-003"
    title = "Cloud Run service has no VPC connector"
    description = "Services that talk to private resources should egress through a Serverless VPC connector."
    severity = Severity.LOW
    category = Category.OPERATIONS
    service = "Cloud Run"
    service_category = ServiceCategory.CLOUD_RUN
    references = ["https://cloud.google.com/run/docs/configuring/connecting-vpc"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for svc in await _list_services(gcloud_runner, project_id):
            name = _service_name(svc)
            if not name:
                continue
            annotations = svc.get("spec", {}).get("template", {}).get("metadata", {}).get("annotations", {})
            if not annotations.get("run.googleapis.com/vpc-access-connector"):
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"services/{name}", project_id=project_id,
                    current_state="No VPC connector attached — service egresses to public internet",
                    recommended_state="Attach a Serverless VPC connector if reaching private resources",
                    fix_command="", references=self.references,
                ))
        return findings


class CloudRunUnboundedMaxInstances(BaseCheck):
    id = "CR-004"
    title = "Cloud Run service has no max-instances cap"
    description = "Unbounded scaling lets a traffic spike or runaway loop run up unlimited cost."
    severity = Severity.MEDIUM
    category = Category.COST
    service = "Cloud Run"
    service_category = ServiceCategory.CLOUD_RUN
    references = ["https://cloud.google.com/run/docs/configuring/max-instances"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for svc in await _list_services(gcloud_runner, project_id):
            name = _service_name(svc)
            if not name:
                continue
            annotations = svc.get("spec", {}).get("template", {}).get("metadata", {}).get("annotations", {})
            max_inst = annotations.get("autoscaling.knative.dev/maxScale")
            if not max_inst or int(max_inst) >= 1000:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"services/{name}", project_id=project_id,
                    current_state=f"maxScale={max_inst or 'unset (defaults to 1000)'}",
                    recommended_state="Set a sensible max-instances based on capacity planning",
                    fix_command="", references=self.references,
                ))
        return findings


class CloudRunNoMinInstances(BaseCheck):
    id = "CR-005"
    title = "Cloud Run service has no min-instances (cold starts on each request burst)"
    description = "Critical user-facing services should keep at least one warm instance."
    severity = Severity.LOW
    category = Category.PERFORMANCE
    service = "Cloud Run"
    service_category = ServiceCategory.CLOUD_RUN
    references = ["https://cloud.google.com/run/docs/configuring/min-instances"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for svc in await _list_services(gcloud_runner, project_id):
            name = _service_name(svc)
            if not name:
                continue
            annotations = svc.get("spec", {}).get("template", {}).get("metadata", {}).get("annotations", {})
            min_inst = annotations.get("autoscaling.knative.dev/minScale", "0")
            if min_inst == "0":
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"services/{name}", project_id=project_id,
                    current_state="minScale=0 — first request after idle pays cold-start latency",
                    recommended_state="Set min-instances >= 1 for latency-sensitive services",
                    fix_command="", references=self.references,
                ))
        return findings


class CloudRunDefaultServiceAccount(BaseCheck):
    id = "CR-006"
    title = "Cloud Run service runs as default compute service account"
    description = "Default compute SA has broad project-wide permissions; use a dedicated SA."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Cloud Run"
    service_category = ServiceCategory.CLOUD_RUN
    references = ["https://cloud.google.com/run/docs/securing/service-identity"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for svc in await _list_services(gcloud_runner, project_id):
            name = _service_name(svc)
            if not name:
                continue
            spec = svc.get("spec", {}).get("template", {}).get("spec", {})
            sa = spec.get("serviceAccountName", "") or ""
            if not sa or sa.endswith("-compute@developer.gserviceaccount.com"):
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"services/{name}", project_id=project_id,
                    current_state=f"serviceAccountName={sa or '(default compute SA)'}",
                    recommended_state="Create a least-privilege SA and attach it to the service",
                    fix_command="", references=self.references,
                ))
        return findings


class CloudRunNoCMEK(BaseCheck):
    id = "CR-007"
    title = "Cloud Run service not encrypted with CMEK"
    description = "Service revisions can be encrypted with a customer-managed Cloud KMS key."
    severity = Severity.LOW
    category = Category.SECURITY
    service = "Cloud Run"
    service_category = ServiceCategory.CLOUD_RUN
    references = ["https://cloud.google.com/run/docs/securing/using-cmek"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for svc in await _list_services(gcloud_runner, project_id):
            name = _service_name(svc)
            if not name:
                continue
            annotations = svc.get("spec", {}).get("template", {}).get("metadata", {}).get("annotations", {})
            if not annotations.get("run.googleapis.com/encryption-key"):
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"services/{name}", project_id=project_id,
                    current_state="Using Google-managed encryption (default)",
                    recommended_state="Set --encryption-key to a Cloud KMS key for CMEK",
                    fix_command="", references=self.references,
                ))
        return findings


class CloudRunIngressAllAllowed(BaseCheck):
    id = "CR-008"
    title = "Cloud Run service ingress is 'all' (public network reachable)"
    description = "Setting ingress to 'internal' or 'internal-and-cloud-load-balancing' prevents direct public hits."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "Cloud Run"
    service_category = ServiceCategory.CLOUD_RUN
    references = ["https://cloud.google.com/run/docs/securing/ingress"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for svc in await _list_services(gcloud_runner, project_id):
            name = _service_name(svc)
            if not name:
                continue
            ingress = svc.get("metadata", {}).get("annotations", {}).get("run.googleapis.com/ingress", "all")
            if ingress == "all":
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"services/{name}", project_id=project_id,
                    current_state="Ingress is 'all' — service is reachable from any source",
                    recommended_state="Set ingress to 'internal' or 'internal-and-cloud-load-balancing'",
                    fix_command="", references=self.references,
                ))
        return findings


# Required APIs for every check in this module (engine pre-skip)
import sys as _sys  # noqa: E402
from backend.checks._module_helpers import apply_required_apis as _apply  # noqa: E402
_apply(_sys.modules[__name__], ["run.googleapis.com"])
