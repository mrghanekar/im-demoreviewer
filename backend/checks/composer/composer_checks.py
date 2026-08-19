"""Cloud Composer (managed Airflow) checks.

Checks: CMP-001 through CMP-004
"""

import logging
from typing import Any

from backend.checks.base import BaseCheck
from backend.core.models import Category, CheckResult, Severity, ServiceCategory

logger = logging.getLogger(__name__)


async def _list_environments(gcloud_runner: Any, project_id: str) -> list[dict]:
    try:
        envs = await gcloud_runner.run(
            f"gcloud composer environments list --locations=- --project={project_id} --format=json"
        )
        return envs if isinstance(envs, list) else []
    except Exception as e:
        logger.debug("Composer environments list failed: %s", e)
        return []


def _env_name(e: dict) -> str:
    return e.get("name", "").split("/")[-1]


class ComposerPublicEndpoint(BaseCheck):
    id = "CMP-001"
    title = "Composer environment has a public Airflow web server"
    description = "Restrict Airflow web access to private IPs or known CIDRs."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Composer"
    service_category = ServiceCategory.COMPOSER
    references = ["https://cloud.google.com/composer/docs/composer-2/configure-private-ip"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for env in await _list_environments(gcloud_runner, project_id):
            name = _env_name(env)
            cfg = env.get("config", {})
            private = cfg.get("privateEnvironmentConfig", {})
            if not private.get("enablePrivateEnvironment"):
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"composer/{name}", project_id=project_id,
                    current_state="Public environment (privateEnvironment disabled)",
                    recommended_state="Recreate as a private-IP environment",
                    fix_command="", references=self.references,
                ))
        return findings


class ComposerNoCMEK(BaseCheck):
    id = "CMP-002"
    title = "Composer environment not encrypted with CMEK"
    description = "CMEK lets you control the encryption key lifecycle for Composer's underlying GKE/GCS resources."
    severity = Severity.LOW
    category = Category.SECURITY
    service = "Composer"
    service_category = ServiceCategory.COMPOSER
    references = ["https://cloud.google.com/composer/docs/composer-2/configure-cmek-encryption"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for env in await _list_environments(gcloud_runner, project_id):
            name = _env_name(env)
            cmek = env.get("config", {}).get("encryptionConfig", {}).get("kmsKeyName")
            if not cmek:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"composer/{name}", project_id=project_id,
                    current_state="Using Google-managed encryption",
                    recommended_state="Recreate with --kms-key for CMEK",
                    fix_command="", references=self.references,
                ))
        return findings


class ComposerDeprecatedImage(BaseCheck):
    id = "CMP-003"
    title = "Composer environment runs on a deprecated image"
    description = "Composer 1.x is EOL; use Composer 2 or 3 with current Airflow versions."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Composer"
    service_category = ServiceCategory.COMPOSER
    references = ["https://cloud.google.com/composer/docs/concepts/versioning/composer-versions"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for env in await _list_environments(gcloud_runner, project_id):
            name = _env_name(env)
            image = env.get("config", {}).get("softwareConfig", {}).get("imageVersion", "")
            if image.startswith("composer-1"):
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"composer/{name}", project_id=project_id,
                    current_state=f"Image: {image} (Composer 1.x — EOL)",
                    recommended_state="Migrate to Composer 2 or 3",
                    fix_command="", references=self.references,
                ))
        return findings


class ComposerDefaultNetwork(BaseCheck):
    id = "CMP-004"
    title = "Composer environment uses the default VPC network"
    description = "Production Composer environments should run in a dedicated VPC with restricted firewall rules."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "Composer"
    service_category = ServiceCategory.COMPOSER
    references = ["https://cloud.google.com/composer/docs/composer-2/configure-shared-vpc"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for env in await _list_environments(gcloud_runner, project_id):
            name = _env_name(env)
            net = env.get("config", {}).get("nodeConfig", {}).get("network", "")
            if net.endswith("/default") or net == "default":
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"composer/{name}", project_id=project_id,
                    current_state=f"Network: {net}",
                    recommended_state="Use a dedicated VPC for the environment",
                    fix_command="", references=self.references,
                ))
        return findings


import sys as _sys  # noqa: E402
from backend.checks._module_helpers import apply_required_apis as _apply  # noqa: E402
_apply(_sys.modules[__name__], ["composer.googleapis.com"])
