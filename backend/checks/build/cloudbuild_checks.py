"""Cloud Build checks.

Checks: CB-001 through CB-005
"""

import logging
from typing import Any

from backend.checks.base import BaseCheck
from backend.core.models import Category, CheckResult, Severity, ServiceCategory

logger = logging.getLogger(__name__)


async def _list_triggers(gcloud_runner: Any, project_id: str) -> list[dict]:
    try:
        triggers = await gcloud_runner.run(
            f"gcloud builds triggers list --project={project_id} --format=json"
        )
        return triggers if isinstance(triggers, list) else []
    except Exception as e:
        logger.debug("Cloud Build triggers list failed: %s", e)
        return []


def _trigger_name(t: dict) -> str:
    return t.get("name", "") or t.get("id", "")


class TriggerUntrustedForkNoApproval(BaseCheck):
    id = "CB-001"
    title = "Cloud Build trigger runs on PRs from forks without approval"
    description = "Triggers that auto-run on external-fork pull requests can execute attacker code with build SA privileges."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    service = "Cloud Build"
    service_category = ServiceCategory.CLOUD_BUILD
    references = ["https://cloud.google.com/build/docs/automating-builds/github/build-repos-from-github#approving_pull_requests_from_forks"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for t in await _list_triggers(gcloud_runner, project_id):
            name = _trigger_name(t)
            github = t.get("github", {})
            pr = github.get("pullRequest", {})
            if pr and not t.get("approvalConfig", {}).get("approvalRequired"):
                # Comment-control = none-or-OWNER means external PRs run without comment gate
                comment_control = pr.get("commentControl", "COMMENTS_DISABLED")
                if comment_control in ("COMMENTS_DISABLED", "COMMENTS_ENABLED"):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"triggers/{name}", project_id=project_id,
                        current_state=f"PR trigger commentControl={comment_control}, approval not required",
                        recommended_state="Require manual approval or set commentControl=COMMENTS_ENABLED_FOR_EXTERNAL_CONTRIBUTORS_ONLY",
                        fix_command="", references=self.references,
                    ))
        return findings


class TriggerDefaultServiceAccount(BaseCheck):
    id = "CB-002"
    title = "Cloud Build trigger uses default Cloud Build service account"
    description = "The default Cloud Build SA has broad project-wide permissions; pin a custom SA."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Cloud Build"
    service_category = ServiceCategory.CLOUD_BUILD
    references = ["https://cloud.google.com/build/docs/securing-builds/configure-user-specified-service-accounts"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for t in await _list_triggers(gcloud_runner, project_id):
            name = _trigger_name(t)
            sa = t.get("serviceAccount", "")
            if not sa:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"triggers/{name}", project_id=project_id,
                    current_state="Trigger has no custom serviceAccount (uses default Cloud Build SA)",
                    recommended_state="Pin a least-privilege custom SA via --service-account",
                    fix_command="", references=self.references,
                ))
        return findings


class TriggerNoApprovalGate(BaseCheck):
    id = "CB-003"
    title = "Production-named Cloud Build trigger has no approval gate"
    description = "Triggers that look like prod/release should require manual approval before running."
    severity = Severity.HIGH
    category = Category.OPERATIONS
    service = "Cloud Build"
    service_category = ServiceCategory.CLOUD_BUILD
    references = ["https://cloud.google.com/build/docs/automating-builds/approve-build-from-trigger"]

    PROD_KEYWORDS = ("prod", "release", "deploy")

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for t in await _list_triggers(gcloud_runner, project_id):
            name = _trigger_name(t).lower()
            looks_prod = any(k in name for k in self.PROD_KEYWORDS)
            approval_required = t.get("approvalConfig", {}).get("approvalRequired", False)
            if looks_prod and not approval_required:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"triggers/{_trigger_name(t)}", project_id=project_id,
                    current_state="Production-named trigger has no approval gate",
                    recommended_state="Require manual approval via approvalConfig.approvalRequired",
                    fix_command="", references=self.references,
                ))
        return findings


class TriggerNoSubstitutionsValidation(BaseCheck):
    id = "CB-004"
    title = "Cloud Build trigger allows arbitrary substitution overrides at run time"
    description = "When users can pass arbitrary substitution overrides, they can change what the trigger does."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "Cloud Build"
    service_category = ServiceCategory.CLOUD_BUILD
    references = ["https://cloud.google.com/build/docs/configuring-builds/substitute-variable-values"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for t in await _list_triggers(gcloud_runner, project_id):
            name = _trigger_name(t)
            # The flag lives at build.options.substitutionOption; PERMISSIVE means overrides accepted
            opt = t.get("build", {}).get("options", {}).get("substitutionOption", "")
            if opt and opt.upper() != "MUST_MATCH":
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"triggers/{name}", project_id=project_id,
                    current_state=f"substitutionOption={opt}",
                    recommended_state="Set build.options.substitutionOption to MUST_MATCH",
                    fix_command="", references=self.references,
                ))
        return findings


class PublicWorkerPool(BaseCheck):
    id = "CB-005"
    title = "Cloud Build trigger uses public worker pool (no private pool)"
    description = "Builds that need network isolation should run in a Private Worker Pool, not the public default."
    severity = Severity.LOW
    category = Category.SECURITY
    service = "Cloud Build"
    service_category = ServiceCategory.CLOUD_BUILD
    references = ["https://cloud.google.com/build/docs/private-pools/private-pools-overview"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for t in await _list_triggers(gcloud_runner, project_id):
            name = _trigger_name(t)
            pool = t.get("build", {}).get("options", {}).get("pool", {}).get("name")
            if not pool:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"triggers/{name}", project_id=project_id,
                    current_state="No private worker pool configured",
                    recommended_state="Run in a Private Worker Pool for sensitive builds",
                    fix_command="", references=self.references,
                ))
        return findings


import sys as _sys  # noqa: E402
from backend.checks._module_helpers import apply_required_apis as _apply  # noqa: E402
_apply(_sys.modules[__name__], ["cloudbuild.googleapis.com"])
