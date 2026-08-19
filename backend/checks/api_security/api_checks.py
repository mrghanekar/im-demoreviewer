"""API & API-key security checks.

Checks: API-001 through API-006

API-007 ("no rate limiting / quota override on a public API") was considered
and deliberately not shipped: absence of Apigee is not evidence that rate
limiting is absent (API Gateway quotas, Cloud Armor rate-based rules and
app-level limits are all invisible to that heuristic), and the condition it
would fire on is already covered by API-006. Shipping it would double-report
the same posture with a noisier justification.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar

from backend.checks.base import BaseCheck
from backend.core.compliance import CIS_GCP_V3, ISO_27001
from backend.core.models import Category, CheckResult, ServiceCategory, Severity

logger = logging.getLogger(__name__)

# Client-side restriction keys an API key can carry. A key with none of these
# AND no apiTargets is completely unrestricted.
_CLIENT_RESTRICTION_KEYS = (
    "browserKeyRestrictions",
    "serverKeyRestrictions",
    "androidKeyRestrictions",
    "iosKeyRestrictions",
)

_CREDENTIALS_CONSOLE = "https://console.cloud.google.com/apis/credentials?project={project_id}"
_API_GATEWAY_CONSOLE = "https://console.cloud.google.com/api-gateway?project={project_id}"


async def _list_api_keys(gcloud_runner: Any, project_id: str) -> list[dict]:
    try:
        keys = await gcloud_runner.run(
            f"gcloud services api-keys list --project={project_id} --format=json"
        )
        return [k for k in keys if isinstance(k, dict)] if isinstance(keys, list) else []
    except Exception as e:
        logger.debug("API keys list failed: %s", e)
        return []


async def _list_enabled_services(gcloud_runner: Any, project_id: str) -> set[str]:
    """Return the set of enabled service names, e.g. {'run.googleapis.com', ...}."""
    try:
        services = await gcloud_runner.run(
            f"gcloud services list --enabled --project={project_id} --format=json"
        )
    except Exception as e:
        logger.debug("Enabled services list failed: %s", e)
        return set()
    enabled: set[str] = set()
    for s in (services if isinstance(services, list) else []):
        if not isinstance(s, dict):
            continue
        name = s.get("config", {}).get("name") or s.get("name", "").split("/")[-1]
        if name:
            enabled.add(name)
    return enabled


def _key_id(key: dict) -> str:
    return key.get("name", "").split("/")[-1] or key.get("uid", "")


def _key_label(key: dict) -> str:
    return key.get("displayName") or _key_id(key)


class UnrestrictedAPIKey(BaseCheck):
    id = "API-001"
    title = "API key has no restrictions at all"
    description = (
        "An API key without any restrictions (no API targets and no browser/server/"
        "Android/iOS client restriction) can be used by anyone who obtains it, from "
        "anywhere, against every API enabled in the project."
    )
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "API Keys"
    service_category = ServiceCategory.API_SECURITY
    gcloud_command = "gcloud services api-keys list --project={project_id} --format=json"
    fix_command_template = (
        "gcloud services api-keys update {key_id} "
        "--api-target=service=SERVICE_TO_ALLOW.googleapis.com --project={project_id}"
    )
    references: ClassVar[list[str]] = [
        "https://cloud.google.com/docs/authentication/api-keys",
        "https://cloud.google.com/docs/authentication/api-keys-best-practices",
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {
        CIS_GCP_V3: ["1.12", "1.13"],
        ISO_27001: ["A.5.15", "A.8.3"],
    }

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for key in await _list_api_keys(gcloud_runner, project_id):
            restrictions = key.get("restrictions") or {}
            has_api_targets = bool(restrictions.get("apiTargets"))
            has_client_restriction = any(restrictions.get(k) for k in _CLIENT_RESTRICTION_KEYS)
            if not has_api_targets and not has_client_restriction:
                key_id = _key_id(key)
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"apikeys/{key_id}",
                    resource_link=_CREDENTIALS_CONSOLE.format(project_id=project_id),
                    project_id=project_id,
                    current_state=f"API key '{_key_label(key)}' has no restrictions",
                    recommended_state="Add API target restrictions and a client (referrer/IP/app) restriction",
                    fix_command=self.build_fix_command(key_id=key_id, project_id=project_id),
                    references=self.references,
                ))
        return findings


class APIKeyNoAPITargets(BaseCheck):
    id = "API-002"
    title = "API key is not restricted to specific APIs"
    description = (
        "The key has a client restriction but no API target restrictions "
        "(restrictions.apiTargets), so it can call every API enabled in the project "
        "instead of only the APIs the application actually needs."
    )
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "API Keys"
    service_category = ServiceCategory.API_SECURITY
    gcloud_command = "gcloud services api-keys list --project={project_id} --format=json"
    fix_command_template = (
        "gcloud services api-keys update {key_id} "
        "--api-target=service=SERVICE_TO_ALLOW.googleapis.com --project={project_id}"
    )
    references: ClassVar[list[str]] = [
        "https://cloud.google.com/docs/authentication/api-keys",
        "https://cloud.google.com/docs/authentication/api-keys-best-practices",
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {
        CIS_GCP_V3: ["1.12"],
        ISO_27001: ["A.8.3"],
    }

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for key in await _list_api_keys(gcloud_runner, project_id):
            restrictions = key.get("restrictions") or {}
            has_api_targets = bool(restrictions.get("apiTargets"))
            has_client_restriction = any(restrictions.get(k) for k in _CLIENT_RESTRICTION_KEYS)
            # A key with no restrictions at all is API-001's finding; don't double-report.
            if has_client_restriction and not has_api_targets:
                key_id = _key_id(key)
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"apikeys/{key_id}",
                    resource_link=_CREDENTIALS_CONSOLE.format(project_id=project_id),
                    project_id=project_id,
                    current_state=f"API key '{_key_label(key)}' has no API target restrictions",
                    recommended_state="Restrict the key to only the APIs the application needs",
                    fix_command=self.build_fix_command(key_id=key_id, project_id=project_id),
                    references=self.references,
                ))
        return findings


class APIKeyWildcardReferrer(BaseCheck):
    id = "API-003"
    title = "API key browser restriction allows any referrer"
    description = (
        "The key's browser restriction allows the wildcard referrer '*' (or '*.*'), "
        "which any site can send — an allow-anything referrer is not a restriction."
    )
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "API Keys"
    service_category = ServiceCategory.API_SECURITY
    gcloud_command = "gcloud services api-keys list --project={project_id} --format=json"
    fix_command_template = (
        "gcloud services api-keys update {key_id} "
        "--allowed-referrers=https://YOUR-DOMAIN.example/* --project={project_id}"
    )
    references: ClassVar[list[str]] = [
        "https://cloud.google.com/docs/authentication/api-keys-best-practices",
        "https://cloud.google.com/docs/authentication/api-keys",
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {
        CIS_GCP_V3: ["1.13"],
        ISO_27001: ["A.5.15"],
    }

    WILDCARD_REFERRERS = ("*", "*.*")

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for key in await _list_api_keys(gcloud_runner, project_id):
            restrictions = key.get("restrictions") or {}
            referrers = restrictions.get("browserKeyRestrictions", {}).get("allowedReferrers", [])
            wildcards = [r for r in referrers if r in self.WILDCARD_REFERRERS]
            if wildcards:
                key_id = _key_id(key)
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"apikeys/{key_id}",
                    resource_link=_CREDENTIALS_CONSOLE.format(project_id=project_id),
                    project_id=project_id,
                    current_state=(
                        f"API key '{_key_label(key)}' allows wildcard referrer(s): "
                        f"{', '.join(wildcards)}"
                    ),
                    recommended_state="Allow only the specific HTTPS referrers your site uses",
                    fix_command=self.build_fix_command(key_id=key_id, project_id=project_id),
                    references=self.references,
                ))
        return findings


class APIKeyNotRotated(BaseCheck):
    id = "API-004"
    title = "Long-lived API key has never been rotated"
    description = (
        "The key was created over a year ago. API keys do not expire; old keys spread "
        "through source code, configs and browser caches and should be rotated "
        "(CIS recommends every 90 days)."
    )
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "API Keys"
    service_category = ServiceCategory.API_SECURITY
    gcloud_command = "gcloud services api-keys list --project={project_id} --format=json"
    fix_command_template = (
        "gcloud services api-keys delete {key_id} --project={project_id}"
    )
    references: ClassVar[list[str]] = [
        "https://cloud.google.com/docs/authentication/api-keys-best-practices",
        "https://cloud.google.com/docs/authentication/api-keys",
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {
        CIS_GCP_V3: ["1.14"],
        ISO_27001: ["A.5.17"],
    }

    MAX_AGE_DAYS = 365

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        threshold = datetime.now(timezone.utc) - timedelta(days=self.MAX_AGE_DAYS)
        for key in await _list_api_keys(gcloud_runner, project_id):
            created = key.get("createTime", "")
            if not isinstance(created, str) or not created:
                continue
            try:
                created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
            except ValueError:
                logger.debug("Unparseable createTime %r on key %s", created, _key_id(key))
                continue
            if created_dt.tzinfo is None:
                created_dt = created_dt.replace(tzinfo=timezone.utc)
            if created_dt < threshold:
                key_id = _key_id(key)
                age_days = (datetime.now(timezone.utc) - created_dt).days
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"apikeys/{key_id}",
                    resource_link=_CREDENTIALS_CONSOLE.format(project_id=project_id),
                    project_id=project_id,
                    current_state=f"API key '{_key_label(key)}' is {age_days} days old",
                    recommended_state="Create a replacement key, migrate clients, then delete this key",
                    fix_command=self.build_fix_command(key_id=key_id, project_id=project_id),
                    references=self.references,
                ))
        return findings


class APIGatewayUnauthenticatedConfig(BaseCheck):
    """Flag ACTIVE API Gateway gateways with no attached API config.

    Scope note: the OpenAPI document that defines a config's security
    (securityDefinitions / x-google-audiences) is only retrievable by
    downloading and decoding the full config document, which is impractical
    with a small, shlex-safe command set. This check therefore sees only the
    gateway inventory: it flags an ACTIVE gateway that serves traffic with no
    API config attached at all (nothing defines authentication for it), but it
    CANNOT verify that an attached config actually requires authentication —
    review the config's securityDefinitions manually for that.
    """

    id = "API-005"
    title = "API Gateway is active without an API config defining security"
    description = (
        "An ACTIVE gateway with no attached API config has no OpenAPI security "
        "definition governing it, so nothing enforces authentication for requests "
        "reaching its default hostname."
    )
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "API Gateway"
    service_category = ServiceCategory.API_SECURITY
    gcloud_command = "gcloud api-gateway gateways list --project={project_id} --format=json"
    fix_command_template = (
        "gcloud api-gateway gateways update {gateway} --location={location} "
        "--api-config=API_CONFIG_WITH_SECURITY --api=API_ID --project={project_id}"
    )
    references: ClassVar[list[str]] = [
        "https://cloud.google.com/api-gateway/docs/authentication-method",
        "https://cloud.google.com/api-gateway/docs/authenticate-service-account",
    ]
    required_apis: ClassVar[list[str]] = ["apigateway.googleapis.com"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {
        ISO_27001: ["A.8.21", "A.8.26"],
    }

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            gateways = await gcloud_runner.run(
                f"gcloud api-gateway gateways list --project={project_id} --format=json"
            )
        except Exception as e:
            logger.debug("API Gateway gateways list failed: %s", e)
            return findings
        for gw in (gateways if isinstance(gateways, list) else []):
            if not isinstance(gw, dict):
                continue
            if gw.get("state") != "ACTIVE":
                continue
            if gw.get("apiConfig"):
                continue
            # name: projects/{p}/locations/{loc}/gateways/{gw}
            parts = gw.get("name", "").split("/")
            gateway = parts[-1] if parts else ""
            location = parts[3] if len(parts) > 3 else ""
            findings.append(CheckResult(
                check_id=self.id, title=self.title, description=self.description,
                severity=self.severity, category=self.category, service=self.service,
                resource_name=f"gateways/{gateway}",
                resource_link=_API_GATEWAY_CONSOLE.format(project_id=project_id),
                project_id=project_id,
                current_state=(
                    f"Gateway '{gateway}' is ACTIVE"
                    + (f" at {gw['defaultHostname']}" if gw.get("defaultHostname") else "")
                    + " with no API config attached"
                ),
                recommended_state="Attach an API config whose OpenAPI spec defines security requirements",
                fix_command=self.build_fix_command(
                    gateway=gateway, location=location, project_id=project_id
                ),
                references=self.references,
            ))
        return findings


class NoAPIGatewayInFrontOfPublicServices(BaseCheck):
    """Posture advisory: public serverless services with no API management layer.

    Reports once per project when Cloud Run services with public ingress (or a
    serving App Engine app without IAP) exist but neither API Gateway nor
    Apigee is enabled. This is a posture signal, not a vulnerability: a
    front-door gateway centralises authentication, quotas and monitoring for
    exposed APIs.
    """

    id = "API-006"
    title = "Public services are exposed without an API Gateway or Apigee front door"
    description = (
        "The project serves public Cloud Run / App Engine endpoints but has neither "
        "apigateway.googleapis.com nor apigee.googleapis.com enabled. Consider putting "
        "an API management layer in front of externally consumed APIs for centralised "
        "authentication, rate limiting and observability."
    )
    severity = Severity.LOW
    category = Category.SECURITY
    service = "API Gateway"
    service_category = ServiceCategory.API_SECURITY
    gcloud_command = "gcloud services list --enabled --project={project_id} --format=json"
    fix_command_template = (
        "gcloud services enable apigateway.googleapis.com --project={project_id}"
    )
    references: ClassVar[list[str]] = [
        "https://cloud.google.com/api-gateway/docs",
        "https://cloud.google.com/apigee/docs",
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {
        ISO_27001: ["A.8.21", "A.8.26"],
    }

    # Ingress values that keep a Cloud Run service off the public internet.
    _NON_PUBLIC_INGRESS = ("internal", "internal-and-cloud-load-balancing")

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        enabled = await _list_enabled_services(gcloud_runner, project_id)
        if not enabled:
            return []
        if "apigateway.googleapis.com" in enabled or "apigee.googleapis.com" in enabled:
            return []

        public: list[str] = []
        if "run.googleapis.com" in enabled:
            try:
                services = await gcloud_runner.run(
                    f"gcloud run services list --project={project_id} --format=json"
                )
            except Exception as e:
                logger.debug("Cloud Run services list failed: %s", e)
                services = []
            for svc in (services if isinstance(services, list) else []):
                if not isinstance(svc, dict):
                    continue
                metadata = svc.get("metadata", {})
                annotations = metadata.get("annotations", {}) or {}
                # Missing ingress annotation defaults to public ("all").
                ingress = annotations.get("run.googleapis.com/ingress", "all")
                if ingress not in self._NON_PUBLIC_INGRESS:
                    public.append(f"run.googleapis.com/{metadata.get('name', 'unknown')}")

        if "appengine.googleapis.com" in enabled:
            try:
                app = await gcloud_runner.run(
                    f"gcloud app describe --project={project_id} --format=json"
                )
            except Exception as e:
                logger.debug("App Engine describe failed: %s", e)
                app = None
            if (
                isinstance(app, dict)
                and app.get("id")
                and app.get("servingStatus") == "SERVING"
                and not app.get("iap", {}).get("enabled")
            ):
                public.append(f"appengine/{app.get('id')}")

        if not public:
            return []
        return [CheckResult(
            check_id=self.id, title=self.title, description=self.description,
            severity=self.severity, category=self.category, service=self.service,
            resource_name=f"projects/{project_id}",
            resource_link=_API_GATEWAY_CONSOLE.format(project_id=project_id),
            project_id=project_id,
            current_state=(
                f"{len(public)} publicly reachable service(s) with no API management "
                f"layer enabled: {', '.join(sorted(public))}"
            ),
            recommended_state=(
                "Front externally consumed APIs with API Gateway or Apigee, or restrict "
                "ingress if they are not meant to be public"
            ),
            fix_command=self.build_fix_command(project_id=project_id),
            references=self.references,
        )]


import sys as _sys

from backend.checks._module_helpers import (
    apply_required_apis_by_id as _apply,
)

_apply(_sys.modules[__name__], {
    "API-001": ["apikeys.googleapis.com"],
    "API-002": ["apikeys.googleapis.com"],
    "API-003": ["apikeys.googleapis.com"],
    "API-004": ["apikeys.googleapis.com"],
    # API-005 declares apigateway.googleapis.com on the class.
    # API-006 intentionally has no required_apis: it must run precisely when the
    # gateway APIs are NOT enabled, and `gcloud services list` needs no
    # project-level API beyond Service Usage.
})
