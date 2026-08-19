"""App Engine checks.

Checks: AE-001 through AE-005.

App Engine Standard/Flex still hosts production workloads at many orgs. Most
common posture issues mirror Cloud Functions: deprecated runtime, default SA,
public access without auth, missing IAP.
"""

import logging
from typing import Any

from backend.checks.base import BaseCheck
from backend.core.models import Category, CheckResult, Severity, ServiceCategory

logger = logging.getLogger(__name__)


# Runtimes Google has marked deprecated or beyond their support window.
# Bump when new EOL announcements land; current list reflects late-2025 deprecations.
_DEPRECATED_RUNTIMES = {
    "python27", "python37", "python38",
    "nodejs8", "nodejs10", "nodejs12", "nodejs14",
    "go111", "go112", "go113", "go114",
    "java8",
    "php55", "php72", "php73",
    "ruby25", "ruby26",
}


async def _list_services(gcloud_runner: Any, project_id: str) -> list[dict]:
    return await gcloud_runner.list(
        f"gcloud app services list --project={project_id} --format=json"
    )


async def _list_versions(gcloud_runner: Any, project_id: str, service: str) -> list[dict]:
    return await gcloud_runner.list(
        f"gcloud app versions list --service={service} --project={project_id} --format=json"
    )


class AppEngineDeprecatedRuntime(BaseCheck):
    id = "AE-001"
    title = "App Engine version uses a deprecated/EOL runtime"
    description = "Deprecated runtimes don't get security patches; Google eventually shuts them down."
    severity = Severity.HIGH
    category = Category.OPERATIONS
    service = "App Engine"
    service_category = ServiceCategory.APP_ENGINE
    references = ["https://cloud.google.com/appengine/docs/standard/lifecycle/support-schedule"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for svc in await _list_services(gcloud_runner, project_id):
            svc_id = svc.get("id") or svc.get("name", "").split("/")[-1]
            if not svc_id:
                continue
            for v in await _list_versions(gcloud_runner, project_id, svc_id):
                runtime = v.get("runtime", "")
                if runtime in _DEPRECATED_RUNTIMES:
                    v_id = v.get("id") or v.get("name", "").split("/")[-1]
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"appengine/{svc_id}/versions/{v_id}", project_id=project_id,
                        current_state=f"runtime={runtime} (deprecated)",
                        recommended_state="Migrate to a supported runtime (see references)",
                        fix_command="", references=self.references,
                    ))
        return findings


class AppEngineDefaultServiceAccount(BaseCheck):
    id = "AE-002"
    title = "App Engine version uses the default App Engine service account"
    description = "Default SA has Editor on the project — over-permissioned for typical workloads."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "App Engine"
    service_category = ServiceCategory.APP_ENGINE
    references = ["https://cloud.google.com/appengine/docs/standard/python3/service-account"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        default_sa = f"{project_id}@appspot.gserviceaccount.com"
        for svc in await _list_services(gcloud_runner, project_id):
            svc_id = svc.get("id") or svc.get("name", "").split("/")[-1]
            if not svc_id:
                continue
            for v in await _list_versions(gcloud_runner, project_id, svc_id):
                sa = v.get("serviceAccount", "")
                if not sa or sa == default_sa:
                    v_id = v.get("id") or v.get("name", "").split("/")[-1]
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"appengine/{svc_id}/versions/{v_id}", project_id=project_id,
                        current_state=f"serviceAccount={sa or '<default>'}",
                        recommended_state="Create a dedicated SA with least-privilege roles for each version",
                        fix_command="", references=self.references,
                    ))
        return findings


class AppEnginePlaintextSecrets(BaseCheck):
    id = "AE-003"
    title = "App Engine version has secret-looking env vars in plaintext"
    description = "Pass secrets via Secret Manager references, not envVariables."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "App Engine"
    service_category = ServiceCategory.APP_ENGINE
    references = ["https://cloud.google.com/secret-manager/docs/access-control"]

    _SECRET_KEYS = ("password", "secret", "token", "key", "credential", "api_key", "apikey")

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for svc in await _list_services(gcloud_runner, project_id):
            svc_id = svc.get("id") or svc.get("name", "").split("/")[-1]
            if not svc_id:
                continue
            for v in await _list_versions(gcloud_runner, project_id, svc_id):
                env = v.get("envVariables", {}) or {}
                hits = [k for k in env if any(s in k.lower() for s in self._SECRET_KEYS)]
                if hits:
                    v_id = v.get("id") or v.get("name", "").split("/")[-1]
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"appengine/{svc_id}/versions/{v_id}", project_id=project_id,
                        current_state=f"Secret-looking env keys: {', '.join(hits[:5])}",
                        recommended_state="Move to Secret Manager and reference via Workload Identity",
                        fix_command="", references=self.references,
                    ))
        return findings


class AppEngineNoIAP(BaseCheck):
    id = "AE-004"
    title = "App Engine app does not have IAP protecting it"
    description = "Without IAP, App Engine apps are publicly reachable unless code enforces auth."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "App Engine"
    service_category = ServiceCategory.APP_ENGINE
    references = ["https://cloud.google.com/iap/docs/app-engine-quickstart"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        # If there are no App Engine services at all, IAP isn't applicable.
        services = await _list_services(gcloud_runner, project_id)
        if not services:
            return findings
        try:
            app = await gcloud_runner.run(
                f"gcloud app describe --project={project_id} --format=json"
            )
        except Exception as e:
            logger.debug("AE-004: could not describe app: %s", e)
            return findings
        iap = (app or {}).get("iap", {}) if isinstance(app, dict) else {}
        if not iap.get("enabled"):
            findings.append(CheckResult(
                check_id=self.id, title=self.title, description=self.description,
                severity=self.severity, category=self.category, service=self.service,
                resource_name=f"projects/{project_id}/appengine", project_id=project_id,
                current_state="App Engine app has iap.enabled=false",
                recommended_state="Enable IAP and grant roles/iap.httpsResourceAccessor to permitted users",
                fix_command="", references=self.references,
            ))
        return findings


class AppEngineTrafficSplitOnDeprecated(BaseCheck):
    id = "AE-005"
    title = "App Engine traffic split sends requests to a deprecated-runtime version"
    description = "Traffic to a deprecated-runtime version means production code runs on an unsupported platform."
    severity = Severity.HIGH
    category = Category.OPERATIONS
    service = "App Engine"
    service_category = ServiceCategory.APP_ENGINE
    references = ["https://cloud.google.com/appengine/docs/standard/splitting-traffic"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for svc in await _list_services(gcloud_runner, project_id):
            svc_id = svc.get("id") or svc.get("name", "").split("/")[-1]
            if not svc_id:
                continue
            split = (svc.get("split", {}) or {}).get("allocations", {})
            if not split:
                continue
            versions = {
                v.get("id") or v.get("name", "").split("/")[-1]: v.get("runtime", "")
                for v in await _list_versions(gcloud_runner, project_id, svc_id)
            }
            for version_id, share in split.items():
                if share and share > 0 and versions.get(version_id) in _DEPRECATED_RUNTIMES:
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"appengine/{svc_id}", project_id=project_id,
                        current_state=f"{int(share * 100)}% of traffic on version {version_id} (runtime {versions[version_id]})",
                        recommended_state="Migrate the version to a supported runtime before shifting more traffic",
                        fix_command="", references=self.references,
                    ))
        return findings


import sys as _sys  # noqa: E402
from backend.checks._module_helpers import apply_required_apis as _apply  # noqa: E402
_apply(_sys.modules[__name__], ["appengine.googleapis.com"])
