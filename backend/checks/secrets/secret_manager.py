"""Secret Manager checks.

Checks: SM-001 through SM-007
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Any

from backend.checks.base import BaseCheck
from backend.core.models import Category, CheckResult, Severity, ServiceCategory

logger = logging.getLogger(__name__)


async def _list_secrets(gcloud_runner: Any, project_id: str) -> list[dict]:
    try:
        secrets = await gcloud_runner.run(
            f"gcloud secrets list --project={project_id} --format=json"
        )
        return secrets if isinstance(secrets, list) else []
    except Exception as e:
        logger.debug("Secret Manager list failed: %s", e)
        return []


def _secret_id(s: dict) -> str:
    return s.get("name", "").split("/")[-1]


class SecretNoRotation(BaseCheck):
    id = "SM-001"
    title = "Secret has no automatic rotation configured"
    description = "Long-lived secrets should be rotated; configure --next-rotation-time and --rotation-period."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "Secret Manager"
    service_category = ServiceCategory.SECRET_MANAGER
    fix_command_template = "gcloud secrets update {name} --next-rotation-time=$(date -d '+30 days' --iso-8601=seconds) --rotation-period=2592000s --project={project_id}"
    references = ["https://cloud.google.com/secret-manager/docs/rotation-recommendations"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for s in await _list_secrets(gcloud_runner, project_id):
            name = _secret_id(s)
            rotation = s.get("rotation", {})
            if not rotation or not rotation.get("rotationPeriod"):
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"secrets/{name}", project_id=project_id,
                    current_state="No rotation policy configured",
                    recommended_state="Configure rotation period and topic",
                    fix_command=self.build_fix_command(name=name, project_id=project_id),
                    references=self.references,
                ))
        return findings


class SecretPublicAccess(BaseCheck):
    id = "SM-002"
    title = "Secret IAM grants allUsers or allAuthenticatedUsers"
    description = "Public access to a secret defeats the purpose of using Secret Manager."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    service = "Secret Manager"
    service_category = ServiceCategory.SECRET_MANAGER
    references = ["https://cloud.google.com/secret-manager/docs/access-control"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for s in await _list_secrets(gcloud_runner, project_id):
            name = _secret_id(s)
            try:
                policy = await gcloud_runner.run(
                    f"gcloud secrets get-iam-policy {name} --project={project_id} --format=json"
                )
            except Exception:
                continue
            if not isinstance(policy, dict):
                continue
            for binding in policy.get("bindings", []):
                for member in binding.get("members", []):
                    if member in ("allUsers", "allAuthenticatedUsers"):
                        findings.append(CheckResult(
                            check_id=self.id, title=self.title, description=self.description,
                            severity=self.severity, category=self.category, service=self.service,
                            resource_name=f"secrets/{name}", project_id=project_id,
                            current_state=f"'{member}' has role '{binding.get('role')}'",
                            recommended_state="Restrict access to specific principals",
                            fix_command="", references=self.references,
                        ))
        return findings


class SecretNoCMEK(BaseCheck):
    id = "SM-003"
    title = "Secret not encrypted with CMEK"
    description = "Sensitive secrets benefit from customer-managed encryption keys."
    severity = Severity.LOW
    category = Category.SECURITY
    service = "Secret Manager"
    service_category = ServiceCategory.SECRET_MANAGER
    references = ["https://cloud.google.com/secret-manager/docs/cmek"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for s in await _list_secrets(gcloud_runner, project_id):
            name = _secret_id(s)
            replication = s.get("replication", {})
            has_cmek = False
            for r in (replication.get("userManaged", {}).get("replicas", []) or []):
                if r.get("customerManagedEncryption", {}).get("kmsKeyName"):
                    has_cmek = True
                    break
            if replication.get("automatic", {}).get("customerManagedEncryption", {}).get("kmsKeyName"):
                has_cmek = True
            if not has_cmek:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"secrets/{name}", project_id=project_id,
                    current_state="Using Google-managed encryption",
                    recommended_state="Configure CMEK on the secret",
                    fix_command="", references=self.references,
                ))
        return findings


class SecretAutomaticReplicationGlobal(BaseCheck):
    id = "SM-004"
    title = "Secret uses automatic (global) replication"
    description = "Compliance often requires data residency; use user-managed replication to specific regions."
    severity = Severity.LOW
    category = Category.SECURITY
    service = "Secret Manager"
    service_category = ServiceCategory.SECRET_MANAGER
    references = ["https://cloud.google.com/secret-manager/docs/locations"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for s in await _list_secrets(gcloud_runner, project_id):
            name = _secret_id(s)
            if "automatic" in s.get("replication", {}):
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"secrets/{name}", project_id=project_id,
                    current_state="Automatic global replication",
                    recommended_state="Switch to user-managed replication with explicit regions",
                    fix_command="", references=self.references,
                ))
        return findings


class SecretManyVersions(BaseCheck):
    id = "SM-005"
    title = "Secret has many enabled versions (clean up old material)"
    description = "Old enabled versions are still readable and increase blast radius if a service is compromised."
    severity = Severity.LOW
    category = Category.SECURITY
    service = "Secret Manager"
    service_category = ServiceCategory.SECRET_MANAGER
    references = ["https://cloud.google.com/secret-manager/docs/managing-secret-versions"]

    THRESHOLD = 10

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for s in await _list_secrets(gcloud_runner, project_id):
            name = _secret_id(s)
            try:
                versions = await gcloud_runner.run(
                    f"gcloud secrets versions list {name} --project={project_id} --format=json"
                )
            except Exception:
                continue
            if not isinstance(versions, list):
                continue
            enabled = [v for v in versions if v.get("state") == "ENABLED"]
            if len(enabled) > self.THRESHOLD:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"secrets/{name}", project_id=project_id,
                    current_state=f"{len(enabled)} enabled versions",
                    recommended_state="Disable or destroy old versions you no longer need",
                    fix_command="", references=self.references,
                ))
        return findings


class SecretLastUpdatedLongAgo(BaseCheck):
    id = "SM-006"
    title = "Secret has not been updated in over 1 year"
    description = "Static secrets older than a year are a strong signal that rotation has lapsed."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "Secret Manager"
    service_category = ServiceCategory.SECRET_MANAGER
    references = ["https://cloud.google.com/secret-manager/docs/rotation-recommendations"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        threshold = datetime.now(timezone.utc) - timedelta(days=365)
        for s in await _list_secrets(gcloud_runner, project_id):
            name = _secret_id(s)
            created = s.get("createTime", "")
            if not created:
                continue
            try:
                created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
            except ValueError:
                continue
            if created_dt < threshold:
                # Check if there's a recent version
                try:
                    versions = await gcloud_runner.run(
                        f"gcloud secrets versions list {name} --project={project_id} --format=json"
                    )
                except Exception:
                    versions = []
                latest_ts = created_dt
                for v in (versions if isinstance(versions, list) else []):
                    ct = v.get("createTime", "")
                    if ct:
                        try:
                            dt = datetime.fromisoformat(ct.replace("Z", "+00:00"))
                            latest_ts = max(latest_ts, dt)
                        except ValueError:
                            pass
                if latest_ts < threshold:
                    age = (datetime.now(timezone.utc) - latest_ts).days
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"secrets/{name}", project_id=project_id,
                        current_state=f"Latest version is {age} days old",
                        recommended_state="Rotate the secret value",
                        fix_command="", references=self.references,
                    ))
        return findings


class SecretNoLabels(BaseCheck):
    id = "SM-007"
    title = "Secret has no owner/environment labels"
    description = "Labels are required to attribute ownership of secrets in a multi-team project."
    severity = Severity.LOW
    category = Category.OPERATIONS
    service = "Secret Manager"
    service_category = ServiceCategory.SECRET_MANAGER
    references = ["https://cloud.google.com/resource-manager/docs/creating-managing-labels"]

    REQUIRED_LABELS = ("owner", "env", "environment", "team")

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for s in await _list_secrets(gcloud_runner, project_id):
            name = _secret_id(s)
            labels = s.get("labels", {}) or {}
            if not any(label_key in labels for label_key in self.REQUIRED_LABELS):
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"secrets/{name}", project_id=project_id,
                    current_state=f"Labels: {list(labels.keys()) or 'none'}",
                    recommended_state="Add owner/env labels for accountability",
                    fix_command="", references=self.references,
                ))
        return findings


import sys as _sys  # noqa: E402
from backend.checks._module_helpers import apply_required_apis as _apply  # noqa: E402
_apply(_sys.modules[__name__], ["secretmanager.googleapis.com"])
