"""Cloud Run Jobs checks.

Checks: CRJ-001 through CRJ-003.

Cloud Run Jobs are distinct from Cloud Run Services (CR-*). Jobs have their
own SA, max-retries policy, and timeout. Common posture issues: default SA,
no retry policy, and plaintext secrets — mirroring CR-* but on the
`gcloud run jobs` surface.
"""

import logging
from typing import Any, ClassVar

from backend.checks.base import BaseCheck
from backend.core.models import Category, CheckResult, Severity, ServiceCategory

logger = logging.getLogger(__name__)


async def _list_jobs(gcloud_runner: Any, project_id: str) -> list[dict]:
    return await gcloud_runner.list(
        f"gcloud run jobs list --region=- --project={project_id} --format=json"
    )


def _job_id(j: dict) -> str:
    return j.get("metadata", {}).get("name") or j.get("name", "").split("/")[-1]


def _job_region(j: dict) -> str:
    # name = projects/.../locations/REGION/jobs/...
    parts = j.get("name", "").split("/")
    if len(parts) >= 4 and parts[2] == "locations":
        return parts[3]
    return ""


def _execution_template(j: dict) -> dict:
    """Cloud Run Jobs nest spec under template.spec.template — drill down."""
    return ((j.get("spec", {}) or {}).get("template", {}) or {}).get("spec", {}) or {}


class CloudRunJobDefaultServiceAccount(BaseCheck):
    id = "CRJ-001"
    title = "Cloud Run Job runs as the default Compute Engine service account"
    description = "Default Compute SA has Editor on the project — over-permissioned for batch workloads."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Cloud Run Jobs"
    service_category = ServiceCategory.CLOUD_RUN_JOBS
    references = ["https://cloud.google.com/run/docs/configuring/service-accounts"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.2", "A.8.3"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for j in await _list_jobs(gcloud_runner, project_id):
            spec = _execution_template(j)
            template_spec = (spec.get("template", {}) or {}).get("spec", {}) or spec
            sa = template_spec.get("serviceAccountName") or template_spec.get("serviceAccount", "")
            # Default if missing or matches the well-known default SA email
            if not sa or sa.endswith("-compute@developer.gserviceaccount.com"):
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"jobs/{_job_id(j)}", project_id=project_id,
                    current_state=f"serviceAccountName={sa or '<default Compute SA>'}",
                    recommended_state="Assign a dedicated SA with least-privilege roles",
                    fix_command=(
                        f"gcloud run jobs update {_job_id(j)} "
                        f"--region={_job_region(j) or 'REGION'} "
                        f"--project={project_id} --service-account=DEDICATED_SA_EMAIL"
                    ),
                    references=self.references,
                ))
        return findings


class CloudRunJobNoRetryPolicy(BaseCheck):
    id = "CRJ-002"
    title = "Cloud Run Job has zero retries (max-retries=0)"
    description = "A flaky run with no retry fails the whole job — typically you want at least 1 retry for transient errors."
    severity = Severity.LOW
    category = Category.RELIABILITY
    service = "Cloud Run Jobs"
    service_category = ServiceCategory.CLOUD_RUN_JOBS
    references = ["https://cloud.google.com/run/docs/configuring/max-retries"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for j in await _list_jobs(gcloud_runner, project_id):
            template_spec = (_execution_template(j).get("template", {}) or {}).get("spec", {}) or {}
            # maxRetries is on the execution template (under spec.template.spec)
            max_retries = template_spec.get("maxRetries")
            if max_retries == 0:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"jobs/{_job_id(j)}", project_id=project_id,
                    current_state="maxRetries=0 — no retry on transient failure",
                    recommended_state="Set --max-retries to at least 1 (or 3 for noisy networks)",
                    fix_command=(
                        f"gcloud run jobs update {_job_id(j)} "
                        f"--region={_job_region(j) or 'REGION'} "
                        f"--project={project_id} --max-retries=3"
                    ),
                    references=self.references,
                ))
        return findings


class CloudRunJobPlaintextSecrets(BaseCheck):
    id = "CRJ-003"
    title = "Cloud Run Job has secret-looking values in plaintext env vars"
    description = "Pass secrets via --set-secrets (Secret Manager references), not --set-env-vars."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Cloud Run Jobs"
    service_category = ServiceCategory.CLOUD_RUN_JOBS
    references = ["https://cloud.google.com/run/docs/configuring/secrets"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.5.17", "A.8.24"]}

    _SECRET_KEYS = ("password", "secret", "token", "key", "credential", "api_key", "apikey")

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for j in await _list_jobs(gcloud_runner, project_id):
            template_spec = (_execution_template(j).get("template", {}) or {}).get("spec", {}) or {}
            for container in template_spec.get("containers", []):
                env_vars = container.get("env", []) or []
                # Only flag literal values, not valueFrom (Secret Manager) refs.
                hits = [
                    e.get("name", "")
                    for e in env_vars
                    if e.get("value") and not e.get("valueFrom")
                    and any(s in (e.get("name", "") or "").lower() for s in self._SECRET_KEYS)
                ]
                if hits:
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"jobs/{_job_id(j)}", project_id=project_id,
                        current_state=f"Secret-looking env keys with plaintext value: {', '.join(hits[:5])}",
                        recommended_state="Replace with --set-secrets=ENV_NAME=secret-name:latest",
                        fix_command="", references=self.references,
                    ))
                    break
        return findings


import sys as _sys  # noqa: E402
from backend.checks._module_helpers import apply_required_apis as _apply  # noqa: E402
_apply(_sys.modules[__name__], ["run.googleapis.com"])
