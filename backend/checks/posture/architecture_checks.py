"""Org/architecture-level posture checks.

These look at project-level guardrails and metadata that signal architectural
maturity, rather than checking individual resources.

Checks: POST-001 through POST-005
"""

import logging
from typing import Any, ClassVar

from backend.checks.base import BaseCheck
from backend.core.models import Category, CheckResult, Severity, ServiceCategory

logger = logging.getLogger(__name__)


# Org policy constraints that every prod project should consider setting.
# iam.allowedPolicyMemberDomains is intentionally excluded — SEC-001 owns that
# specific constraint and would otherwise double-fire alongside POST-001.
RECOMMENDED_CONSTRAINTS = (
    "iam.disableServiceAccountKeyCreation",
    "iam.disableServiceAccountKeyUpload",
    "compute.vmExternalIpAccess",
    "compute.skipDefaultNetworkCreation",
    "storage.uniformBucketLevelAccess",
    "storage.publicAccessPrevention",
    "sql.restrictPublicIp",
    "compute.requireOsLogin",
    "compute.requireShieldedVm",
)


class MissingRecommendedOrgPolicies(BaseCheck):
    id = "POST-001"
    title = "Recommended org policies not set on project"
    description = (
        "Org policies are foundational guardrails. A project missing the common set "
        "(iam.allowedPolicyMemberDomains, compute.vmExternalIpAccess, etc.) lacks defence-in-depth."
    )
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "Posture"
    service_category = ServiceCategory.POSTURE
    references = ["https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.5.23", "A.8.9"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            policies = await gcloud_runner.run(
                f"gcloud org-policies list --project={project_id} --format=json"
            )
        except Exception as e:
            logger.debug("POST-001: %s", e)
            return findings
        configured = set()
        for p in (policies if isinstance(policies, list) else []):
            name = p.get("name", "") or p.get("constraint", "")
            # name looks like 'projects/.../policies/iam.allowedPolicyMemberDomains'
            constraint = name.split("/")[-1]
            configured.add(constraint)
        missing = [c for c in RECOMMENDED_CONSTRAINTS if c not in configured]
        if missing:
            findings.append(CheckResult(
                check_id=self.id, title=self.title, description=self.description,
                severity=self.severity, category=self.category, service=self.service,
                resource_name=f"projects/{project_id}", project_id=project_id,
                current_state=f"Missing constraints ({len(missing)}): {', '.join(missing[:5])}{'…' if len(missing) > 5 else ''}",
                recommended_state="Set the recommended org policies at the org or project level",
                fix_command="", references=self.references,
            ))
        return findings


class ProjectDirectlyUnderOrgNoFolder(BaseCheck):
    id = "POST-002"
    title = "Project sits directly under the organization (no folder)"
    description = "Folder taxonomy (env, team, domain) is needed for IAM inheritance and cost allocation at scale."
    severity = Severity.INFO
    category = Category.OPERATIONS
    service = "Posture"
    service_category = ServiceCategory.POSTURE
    references = ["https://cloud.google.com/resource-manager/docs/cloud-platform-resource-hierarchy"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            meta = await gcloud_runner.run(
                f"gcloud projects describe {project_id} --format=json"
            )
        except Exception:
            return findings
        parent = (meta or {}).get("parent", {}) if isinstance(meta, dict) else {}
        if parent.get("type") == "organization":
            findings.append(CheckResult(
                check_id=self.id, title=self.title, description=self.description,
                severity=self.severity, category=self.category, service=self.service,
                resource_name=f"projects/{project_id}", project_id=project_id,
                current_state="Parent is organization (no intermediate folder)",
                recommended_state="Group projects under folders by environment/team/domain",
                fix_command="", references=self.references,
            ))
        return findings


class AssetFeedNotConfigured(BaseCheck):
    id = "POST-003"
    title = "Cloud Asset Inventory feed not configured"
    description = "Asset feeds push resource-change events to Pub/Sub — foundational for drift detection."
    severity = Severity.LOW
    category = Category.OPERATIONS
    service = "Posture"
    service_category = ServiceCategory.POSTURE
    references = ["https://cloud.google.com/asset-inventory/docs/monitoring-asset-changes"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.9", "A.8.16"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            feeds = await gcloud_runner.run(
                f"gcloud asset feeds list --project={project_id} --format=json"
            )
        except Exception:
            return findings
        if not isinstance(feeds, list) or len(feeds) == 0:
            findings.append(CheckResult(
                check_id=self.id, title=self.title, description=self.description,
                severity=self.severity, category=self.category, service=self.service,
                resource_name=f"projects/{project_id}", project_id=project_id,
                current_state="No Cloud Asset Inventory feeds configured",
                recommended_state="Configure a feed for IAM/Compute/Storage changes",
                fix_command="", references=self.references,
            ))
        return findings


class RecommenderInsightsUnactioned(BaseCheck):
    id = "POST-004"
    title = "Active Recommender insights are unactioned"
    description = "Google's Recommender surfaces IAM/security/cost insights via ML. Acting on them is high-ROI."
    severity = Severity.LOW
    category = Category.OPERATIONS
    service = "Posture"
    service_category = ServiceCategory.POSTURE
    references = ["https://cloud.google.com/recommender/docs/overview"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {}

    KEY_RECOMMENDERS = (
        "google.iam.policy.Recommender",
        "google.compute.instance.MachineTypeRecommender",
        "google.compute.disk.IdleResourceRecommender",
    )

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        total = 0
        for rec in self.KEY_RECOMMENDERS:
            try:
                # The Recommender API expects --location=global for project-scoped recommenders
                recs = await gcloud_runner.run(
                    f"gcloud recommender recommendations list --project={project_id} "
                    f"--location=global --recommender={rec} --format=json"
                )
            except Exception:
                continue
            if isinstance(recs, list):
                total += len([r for r in recs if r.get("stateInfo", {}).get("state") == "ACTIVE"])
        if total > 0:
            findings.append(CheckResult(
                check_id=self.id, title=self.title, description=self.description,
                severity=self.severity, category=self.category, service=self.service,
                resource_name=f"projects/{project_id}", project_id=project_id,
                current_state=f"{total} active Recommender insights unactioned (IAM/Compute)",
                recommended_state="Review and apply or dismiss recommendations",
                fix_command="", references=self.references,
            ))
        return findings


# POST-005 (SCCNotEnabled) removed — SEC-003 (SCCNotEnabled in
# backend/checks/security/org_policies.py) is the canonical check (HIGH severity
# vs POST-005's INFO; same gcloud query).


# Canonical "does this service have anything in it?" probe per API. Only
# services where listing the primary resource is cheap (one gcloud call) and
# unambiguous appear here. Adding entries is safe — false positives are bounded
# by being LOW severity and the per-API context message.
#
# Skipped on purpose:
# - serviceusage / cloudresourcemanager / iam / logging / monitoring: foundational,
#   always have implicit usage.
# - cloudbilling / billing: project-level not the right scope.
# - aiplatform / vertex: too many sub-resources to probe with one call.
_API_TO_PROBE: tuple[tuple[str, str, str], ...] = (
    ("compute.googleapis.com",      "compute",       "gcloud compute instances list --project={p} --format=json"),
    ("container.googleapis.com",    "GKE",           "gcloud container clusters list --project={p} --format=json"),
    ("sqladmin.googleapis.com",     "Cloud SQL",     "gcloud sql instances list --project={p} --format=json"),
    ("bigquery.googleapis.com",     "BigQuery",      "bq ls --project_id={p} --format=json"),
    ("pubsub.googleapis.com",       "Pub/Sub",       "gcloud pubsub topics list --project={p} --format=json"),
    ("cloudkms.googleapis.com",     "Cloud KMS",     "gcloud kms keyrings list --location=global --project={p} --format=json"),
    ("secretmanager.googleapis.com","Secret Manager","gcloud secrets list --project={p} --format=json"),
    ("cloudfunctions.googleapis.com","Cloud Functions","gcloud functions list --project={p} --format=json"),
    ("run.googleapis.com",          "Cloud Run",     "gcloud run services list --region=- --project={p} --format=json"),
    ("composer.googleapis.com",     "Composer",      "gcloud composer environments list --locations=- --project={p} --format=json"),
    ("spanner.googleapis.com",      "Spanner",       "gcloud spanner instances list --project={p} --format=json"),
    ("redis.googleapis.com",        "Memorystore",   "gcloud redis instances list --region=- --project={p} --format=json"),
    ("dataflow.googleapis.com",     "Dataflow",      "gcloud dataflow jobs list --project={p} --status=all --format=json"),
    ("dataproc.googleapis.com",     "Dataproc",      "gcloud dataproc clusters list --region=- --project={p} --format=json"),
    ("firestore.googleapis.com",    "Firestore",     "gcloud firestore databases list --project={p} --format=json"),
    ("appengine.googleapis.com",    "App Engine",    "gcloud app services list --project={p} --format=json"),
    ("alloydb.googleapis.com",      "AlloyDB",       "gcloud alloydb clusters list --region=- --project={p} --format=json"),
)


class EnabledApisWithNoResources(BaseCheck):
    """POST-006: APIs enabled on the project but no resources of that service exist.

    Enabling an API expands the IAM surface (more services to lock down) and
    occasionally incurs baseline cost. If you don't actually use the service,
    disable it. This check is intentionally conservative: it only inspects a
    curated list of APIs with one canonical resource list each, so it won't
    fire for "indirect" usages (e.g. an API used by another service internally).
    """

    id = "POST-006"
    title = "API enabled with no resources detected"
    description = (
        "The API is enabled on the project but a canonical resource list returned zero "
        "items. Either disable the API to shrink attack surface, or confirm the service "
        "is in use (Workflows / on-demand jobs may briefly look empty)."
    )
    severity = Severity.LOW
    category = Category.COST
    service = "Posture"
    service_category = ServiceCategory.POSTURE
    references = [
        "https://cloud.google.com/service-usage/docs/disable-service",
        "https://cloud.google.com/iam/docs/best-practices-service-accounts#disable-unused",
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.9"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []

        # Re-use the engine's cached enabled-API list when present; otherwise
        # ask gcloud directly. Note: list_enabled_apis returns set() on failure,
        # which is the "skip cleanly" signal — drop the check in that case.
        try:
            enabled = await gcloud_runner.list_enabled_apis(project_id)
        except Exception as e:
            logger.debug("POST-006: could not list enabled APIs: %s", e)
            return findings
        if not enabled:
            return findings

        for api, label, probe in _API_TO_PROBE:
            if api not in enabled:
                continue
            try:
                resources = await gcloud_runner.list(probe.format(p=project_id))
            except Exception as e:
                # Don't false-positive on permission / quota errors — those are
                # not the same as "no resources".
                logger.debug("POST-006: probe for %s failed (%s); skipping", api, e)
                continue
            # bq's empty response is special — it returns an error code rather
            # than [], but gcloud_runner.list() already collapses both to [].
            if isinstance(resources, list) and len(resources) == 0:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"projects/{project_id}/services/{api}", project_id=project_id,
                    current_state=f"{api} ({label}) is enabled but has zero resources",
                    recommended_state=(
                        f"Either disable the API (`gcloud services disable {api} --project={project_id}`) "
                        f"if you're sure it's unused, or document why you're keeping it enabled."
                    ),
                    fix_command=f"gcloud services disable {api} --project={project_id} --force",
                    references=self.references,
                ))
        return findings


import sys as _sys  # noqa: E402
from backend.checks._module_helpers import apply_required_apis_by_id as _apply  # noqa: E402
_apply(_sys.modules[__name__], {
    "POST-001": ["orgpolicy.googleapis.com"],
    "POST-002": ["cloudresourcemanager.googleapis.com"],
    "POST-003": ["cloudasset.googleapis.com"],
    "POST-004": ["recommender.googleapis.com"],
    # POST-006 reads the enabled-API list from serviceusage and probes other
    # services on demand. The probes themselves are gated by their own APIs
    # being enabled (otherwise the probe just fails cleanly and we skip).
    "POST-006": ["serviceusage.googleapis.com"],
})
