"""Cloud Functions (Gen2) checks.

Checks: FN-001 through FN-006
"""

import logging
from typing import Any, ClassVar

from backend.checks.base import BaseCheck
from backend.core.models import Category, CheckResult, Severity, ServiceCategory

logger = logging.getLogger(__name__)

# Deprecated/EOL runtimes as of 2026 (best-effort heuristic)
DEPRECATED_RUNTIMES = {
    "nodejs10", "nodejs12", "nodejs14", "nodejs16",
    "python37", "python38", "python39",
    "go111", "go113", "go116",
    "ruby25", "ruby26", "ruby27",
    "php74", "php81",
    "java8", "java11",
    "dotnet3",
}


async def _list_functions(gcloud_runner: Any, project_id: str) -> list[dict]:
    try:
        fns = await gcloud_runner.run(
            f"gcloud functions list --project={project_id} --format=json"
        )
        return fns if isinstance(fns, list) else []
    except Exception as e:
        logger.debug("Cloud Functions list failed: %s", e)
        return []


def _fn_name(fn: dict) -> str:
    return fn.get("name", "").split("/")[-1]


def _fn_region(fn: dict) -> str:
    parts = fn.get("name", "").split("/")
    if "locations" in parts:
        return parts[parts.index("locations") + 1]
    return ""


class FunctionsPublicAccess(BaseCheck):
    id = "FN-001"
    title = "Cloud Function is publicly invokable (allUsers)"
    description = "Function allows unauthenticated invocation by allUsers."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Cloud Functions"
    service_category = ServiceCategory.CLOUD_FUNCTIONS
    references = ["https://cloud.google.com/functions/docs/securing/managing-access-iam"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.5.15", "A.8.20", "A.8.21"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for fn in await _list_functions(gcloud_runner, project_id):
            name = _fn_name(fn)
            region = _fn_region(fn) or "REGION"
            try:
                policy = await gcloud_runner.run(
                    f"gcloud functions get-iam-policy {name} --region={region} --project={project_id} --format=json"
                )
            except Exception:
                continue
            if not isinstance(policy, dict):
                continue
            for binding in policy.get("bindings", []):
                if "allUsers" in binding.get("members", []) and "invoker" in binding.get("role", ""):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"functions/{name}", project_id=project_id,
                        current_state=f"allUsers has {binding.get('role')} — public invocation",
                        recommended_state="Remove allUsers and grant invoker to specific principals",
                        fix_command="", references=self.references,
                    ))
                    break
        return findings


class FunctionsPlaintextSecrets(BaseCheck):
    id = "FN-002"
    title = "Cloud Function has secret-looking env vars in plaintext"
    description = "Use --set-secrets to mount Secret Manager values instead of plaintext env vars."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Cloud Functions"
    service_category = ServiceCategory.CLOUD_FUNCTIONS
    references = ["https://cloud.google.com/functions/docs/configuring/secrets"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.5.17", "A.8.24"]}

    SECRET_PATTERNS = ("SECRET", "PASSWORD", "PASSWD", "TOKEN", "API_KEY", "PRIVATE_KEY", "CREDENTIALS")

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for fn in await _list_functions(gcloud_runner, project_id):
            name = _fn_name(fn)
            env_vars = (
                fn.get("buildConfig", {}).get("environmentVariables", {})
                or fn.get("serviceConfig", {}).get("environmentVariables", {})
                or {}
            )
            suspicious = [k for k in env_vars if any(p in k.upper() for p in self.SECRET_PATTERNS)]
            if suspicious:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"functions/{name}", project_id=project_id,
                    current_state=f"Plaintext env vars: {', '.join(suspicious[:5])}",
                    recommended_state="Mount via --set-secrets from Secret Manager",
                    fix_command="", references=self.references,
                ))
        return findings


class FunctionsDeprecatedRuntime(BaseCheck):
    id = "FN-003"
    title = "Cloud Function uses deprecated/EOL runtime"
    description = "Old language runtimes stop receiving security patches."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Cloud Functions"
    service_category = ServiceCategory.CLOUD_FUNCTIONS
    references = ["https://cloud.google.com/functions/docs/runtime-support"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.8"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for fn in await _list_functions(gcloud_runner, project_id):
            name = _fn_name(fn)
            runtime = fn.get("buildConfig", {}).get("runtime", "") or fn.get("runtime", "")
            if runtime in DEPRECATED_RUNTIMES:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"functions/{name}", project_id=project_id,
                    current_state=f"Runtime: {runtime} (deprecated)",
                    recommended_state="Upgrade to a supported runtime version",
                    fix_command="", references=self.references,
                ))
        return findings


class FunctionsDefaultServiceAccount(BaseCheck):
    id = "FN-004"
    title = "Cloud Function uses default compute service account"
    description = "Default compute SA has broad permissions; functions should use a dedicated SA."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Cloud Functions"
    service_category = ServiceCategory.CLOUD_FUNCTIONS
    references = ["https://cloud.google.com/functions/docs/securing/function-identity"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.2", "A.8.3"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for fn in await _list_functions(gcloud_runner, project_id):
            name = _fn_name(fn)
            sa = fn.get("serviceConfig", {}).get("serviceAccountEmail", "")
            if not sa or sa.endswith("-compute@developer.gserviceaccount.com"):
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"functions/{name}", project_id=project_id,
                    current_state=f"SA: {sa or '(default compute)'}",
                    recommended_state="Use a dedicated least-privilege SA",
                    fix_command="", references=self.references,
                ))
        return findings


class FunctionsNoVPCConnector(BaseCheck):
    id = "FN-005"
    title = "Cloud Function has no VPC connector"
    description = "Functions reaching private resources should egress through a Serverless VPC connector."
    severity = Severity.LOW
    category = Category.OPERATIONS
    service = "Cloud Functions"
    service_category = ServiceCategory.CLOUD_FUNCTIONS
    references = ["https://cloud.google.com/functions/docs/networking/connecting-vpc"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.22"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for fn in await _list_functions(gcloud_runner, project_id):
            name = _fn_name(fn)
            vpc = fn.get("serviceConfig", {}).get("vpcConnector")
            if not vpc:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"functions/{name}", project_id=project_id,
                    current_state="No VPC connector configured",
                    recommended_state="Attach a Serverless VPC connector if reaching private resources",
                    fix_command="", references=self.references,
                ))
        return findings


class FunctionsUnboundedMaxInstances(BaseCheck):
    id = "FN-006"
    title = "Cloud Function has no max-instances cap"
    description = "Unbounded scaling can cause runaway cost and downstream overload."
    severity = Severity.MEDIUM
    category = Category.COST
    service = "Cloud Functions"
    service_category = ServiceCategory.CLOUD_FUNCTIONS
    references = ["https://cloud.google.com/functions/docs/configuring/max-instances"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for fn in await _list_functions(gcloud_runner, project_id):
            name = _fn_name(fn)
            cfg = fn.get("serviceConfig", {})
            max_inst = cfg.get("maxInstanceCount")
            if max_inst in (None, 0) or (isinstance(max_inst, int) and max_inst >= 1000):
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"functions/{name}", project_id=project_id,
                    current_state=f"maxInstanceCount={max_inst or 'unset'}",
                    recommended_state="Set a sensible max-instances based on capacity planning",
                    fix_command="", references=self.references,
                ))
        return findings


import sys as _sys  # noqa: E402
from backend.checks._module_helpers import apply_required_apis as _apply  # noqa: E402
_apply(_sys.modules[__name__], ["cloudfunctions.googleapis.com"])
