"""Artifact Registry checks.

Checks: AR-001 through AR-006

AR-007 (Binary Authorization not enforced) is intentionally absent: the
catalog already covers it as SEC-013 (project-level Binary Authorization
policy in dryrun) and GKE-level Binary Authorization in the GKE module.
"""

import logging
import sys
from typing import Any, ClassVar

from backend.checks._module_helpers import apply_required_apis
from backend.checks.base import BaseCheck
from backend.core.models import Category, CheckResult, ServiceCategory, Severity

logger = logging.getLogger(__name__)

PUBLIC_MEMBERS = ("allUsers", "allAuthenticatedUsers")


async def _list_repositories(gcloud_runner: Any, project_id: str) -> list[dict]:
    """All Artifact Registry repositories in a project.

    Repo ``name`` is a full resource path
    (``projects/p/locations/us-central1/repositories/my-repo``); use
    :func:`_repo_location_and_id` to take it apart.
    """
    try:
        repos = await gcloud_runner.run(
            f"gcloud artifacts repositories list --project={project_id} --format=json"
        )
    except Exception as e:
        logger.debug("Artifact Registry repositories list failed: %s", e)
        return []
    if not isinstance(repos, list):
        return []
    return [r for r in repos if isinstance(r, dict)]


def _repo_location_and_id(repo: dict) -> tuple[str, str]:
    """Parse (location, repo_id) from a repo's full resource name.

    Mirrors the path handling in
    backend/checks/security/org_policies.py::_kms_keys — index 3 is the
    location and index 5 the repository ID. Returns ("", "") for short or
    malformed names so callers can skip them without raising.
    """
    parts = repo.get("name", "").split("/")
    if len(parts) < 6:
        return "", ""
    return parts[3], parts[5]


class RepositoryPublicAccess(BaseCheck):
    """AR-001: Repository IAM policy grants access to the internet."""

    id = "AR-001"
    title = "Artifact Registry repository is publicly accessible"
    description = (
        "The repository IAM policy grants allUsers or allAuthenticatedUsers a "
        "role. Anyone on the internet (or any Google account) can pull — and "
        "with writer roles push — artifacts, exposing proprietary code and "
        "enabling supply-chain poisoning."
    )
    severity = Severity.CRITICAL
    category = Category.SECURITY
    service = "Artifact Registry"
    service_category = ServiceCategory.ARTIFACT_REGISTRY
    gcloud_command = (
        "gcloud artifacts repositories get-iam-policy {repo} "
        "--location={location} --project={project_id} --format=json"
    )
    fix_command_template = (
        "gcloud artifacts repositories remove-iam-policy-binding {repo} "
        "--location={location} --member={member} --role={role} "
        "--project={project_id}"
    )
    references: ClassVar[list[str]] = [
        "https://cloud.google.com/artifact-registry/docs/access-control",
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {
        "CIS_GCP_V3": ["5.2"],
        "ISO_27001": ["A.8.3"],
    }

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for repo in await _list_repositories(gcloud_runner, project_id):
            location, repo_id = _repo_location_and_id(repo)
            if not location or not repo_id:
                continue
            try:
                policy = await gcloud_runner.run(
                    f"gcloud artifacts repositories get-iam-policy {repo_id} "
                    f"--location={location} --project={project_id} --format=json"
                )
            except Exception as e:
                logger.debug("get-iam-policy failed for %s: %s", repo_id, e)
                continue
            if not isinstance(policy, dict):
                continue
            for binding in policy.get("bindings", []):
                if not isinstance(binding, dict):
                    continue
                role = binding.get("role", "")
                for member in binding.get("members", []):
                    if member in PUBLIC_MEMBERS:
                        findings.append(CheckResult(
                            check_id=self.id, title=self.title,
                            description=self.description,
                            severity=self.severity, category=self.category,
                            service=self.service,
                            resource_name=f"repositories/{repo_id}",
                            project_id=project_id,
                            current_state=f"'{member}' has role '{role}'",
                            recommended_state=(
                                "Grant repository roles to specific principals only"
                            ),
                            fix_command=self.build_fix_command(
                                repo=repo_id, location=location, member=member,
                                role=role, project_id=project_id,
                            ),
                            references=self.references,
                        ))
        return findings


class VulnerabilityScanningDisabled(BaseCheck):
    """AR-002: Docker repos exist but the Container Scanning API is off."""

    id = "AR-002"
    title = "Container vulnerability scanning not enabled"
    description = (
        "The project stores Docker images in Artifact Registry but the "
        "Container Scanning API (containerscanning.googleapis.com) is not "
        "enabled, so pushed images are never scanned for known "
        "vulnerabilities — an unscanned-images gap."
    )
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Artifact Registry"
    service_category = ServiceCategory.ARTIFACT_REGISTRY
    gcloud_command = (
        "gcloud services list --enabled --project={project_id} --format=json"
    )
    fix_command_template = (
        "gcloud services enable containerscanning.googleapis.com "
        "--project={project_id}"
    )
    references: ClassVar[list[str]] = [
        "https://cloud.google.com/artifact-analysis/docs/scan-os-automatically",
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {
        "CIS_GCP_V3": ["5.1"],
        "ISO_27001": ["A.8.8"],
    }

    SCANNING_API = "containerscanning.googleapis.com"

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        repos = await _list_repositories(gcloud_runner, project_id)
        docker_repos = [r for r in repos if r.get("format") == "DOCKER"]
        if not docker_repos:
            return []
        try:
            services = await gcloud_runner.run(
                f"gcloud services list --enabled --project={project_id} --format=json"
            )
        except Exception as e:
            logger.debug("services list failed: %s", e)
            return []
        if not isinstance(services, list):
            return []
        for svc in services:
            if not isinstance(svc, dict):
                continue
            # Enabled-service entries carry the API name both as
            # config.name and as a projects/N/services/... resource path.
            if (
                svc.get("config", {}).get("name") == self.SCANNING_API
                or svc.get("name", "").endswith(f"/{self.SCANNING_API}")
            ):
                return []
        return [CheckResult(
            check_id=self.id, title=self.title, description=self.description,
            severity=self.severity, category=self.category, service=self.service,
            resource_name=f"projects/{project_id}", project_id=project_id,
            current_state=(
                f"{len(docker_repos)} Docker repositories present but "
                f"{self.SCANNING_API} is disabled"
            ),
            recommended_state="Enable the Container Scanning API",
            fix_command=self.build_fix_command(project_id=project_id),
            references=self.references,
        )]


class RepositoryNoCMEK(BaseCheck):
    """AR-003: Repository uses Google-managed encryption, not CMEK.

    Severity LOW: Artifact Registry data is always encrypted at rest with
    Google-managed keys by default, so the absence of a customer-managed key
    is a data-governance preference (key custody, rotation control, audit of
    key use) rather than an exposure. Flag it as advice, not as a hole.
    """

    id = "AR-003"
    title = "Repository not encrypted with a customer-managed key (CMEK)"
    description = (
        "The repository relies on Google-managed encryption (kmsKeyName is "
        "empty). Encryption at rest is still on by default; organisations "
        "that require custody of key material and key-use auditing should "
        "create repositories with a Cloud KMS key. CMEK can only be set at "
        "repository creation time."
    )
    severity = Severity.LOW
    category = Category.SECURITY
    service = "Artifact Registry"
    service_category = ServiceCategory.ARTIFACT_REGISTRY
    gcloud_command = (
        "gcloud artifacts repositories list --project={project_id} --format=json"
    )
    fix_command_template = (
        "gcloud artifacts repositories create {repo}-cmek "
        "--repository-format={format} --location={location} "
        "--kms-key=KMS_KEY_RESOURCE_NAME --project={project_id}"
    )
    references: ClassVar[list[str]] = [
        "https://cloud.google.com/artifact-registry/docs/cmek",
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.8.24"],
    }

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for repo in await _list_repositories(gcloud_runner, project_id):
            location, repo_id = _repo_location_and_id(repo)
            if not repo_id:
                continue
            if repo.get("kmsKeyName"):
                continue
            findings.append(CheckResult(
                check_id=self.id, title=self.title, description=self.description,
                severity=self.severity, category=self.category,
                service=self.service,
                resource_name=f"repositories/{repo_id}", project_id=project_id,
                current_state="Google-managed encryption (no kmsKeyName)",
                recommended_state=(
                    "Recreate the repository with --kms-key if CMEK is a "
                    "governance requirement"
                ),
                fix_command=self.build_fix_command(
                    repo=repo_id, location=location,
                    format=repo.get("format", "docker").lower(),
                    project_id=project_id,
                ),
                references=self.references,
            ))
        return findings


class RepositoryNoCleanupPolicy(BaseCheck):
    """AR-004: Standard repository accumulates artifacts with no cleanup."""

    id = "AR-004"
    title = "No cleanup policy on Artifact Registry repository"
    description = (
        "The repository has no cleanup policies, so old images and package "
        "versions accumulate without bound and storage cost grows with every "
        "push. Configure cleanup policies to delete stale versions (or keep "
        "only the most recent N)."
    )
    severity = Severity.LOW
    category = Category.COST
    service = "Artifact Registry"
    service_category = ServiceCategory.ARTIFACT_REGISTRY
    gcloud_command = (
        "gcloud artifacts repositories list --project={project_id} --format=json"
    )
    fix_command_template = (
        "gcloud artifacts repositories set-cleanup-policies {repo} "
        "--location={location} --policy=POLICY_FILE.json --project={project_id}"
    )
    references: ClassVar[list[str]] = [
        "https://cloud.google.com/artifact-registry/docs/repositories/cleanup-policy",
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.8.10"],
    }

    # Cleanup policies apply to standard repositories that store versioned
    # artifacts; remote (cache) and virtual repositories are excluded.
    APPLICABLE_FORMATS = (
        "DOCKER", "MAVEN", "NPM", "PYTHON", "APT", "YUM", "GO", "GENERIC",
    )

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for repo in await _list_repositories(gcloud_runner, project_id):
            location, repo_id = _repo_location_and_id(repo)
            if not repo_id:
                continue
            if repo.get("mode", "STANDARD_REPOSITORY") != "STANDARD_REPOSITORY":
                continue
            if repo.get("format") not in self.APPLICABLE_FORMATS:
                continue
            # cleanupPolicyDryRun says nothing about whether policies exist;
            # only the presence of cleanupPolicies matters here.
            if repo.get("cleanupPolicies"):
                continue
            findings.append(CheckResult(
                check_id=self.id, title=self.title, description=self.description,
                severity=self.severity, category=self.category,
                service=self.service,
                resource_name=f"repositories/{repo_id}", project_id=project_id,
                current_state="No cleanup policies configured",
                recommended_state=(
                    "Set cleanup policies to delete stale versions or keep "
                    "the most recent N"
                ),
                fix_command=self.build_fix_command(
                    repo=repo_id, location=location, project_id=project_id,
                ),
                references=self.references,
            ))
        return findings


class ImagesWithCriticalVulnerabilities(BaseCheck):
    """AR-005: Stored images carry critical/high vulnerability findings.

    The declared severity is the worst case: findings escalate to CRITICAL
    when any CRITICAL CVE is counted, and are HIGH otherwise.
    """

    id = "AR-005"
    title = "Critical or high vulnerabilities found in stored container images"
    description = (
        "Vulnerability scan results for images in this repository report "
        "CRITICAL or HIGH severity CVEs. Rebuild the images on patched base "
        "images and remove or block the vulnerable versions."
    )
    severity = Severity.CRITICAL
    category = Category.SECURITY
    service = "Artifact Registry"
    service_category = ServiceCategory.ARTIFACT_REGISTRY
    gcloud_command = (
        "gcloud artifacts docker images list "
        "{location}-docker.pkg.dev/{project_id}/{repo} "
        "--show-occurrences --format=json"
    )
    references: ClassVar[list[str]] = [
        "https://cloud.google.com/artifact-analysis/docs/scan-os-automatically",
        "https://cloud.google.com/artifact-analysis/docs/metadata-storage",
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.8.8"],
    }

    # `docker images list --show-occurrences` is slow and verbose; cap the
    # number of repositories inspected per project.
    MAX_REPOS = 10

    @staticmethod
    def _count(counts: dict, key: str) -> int:
        """Vulnerability count as int; the API may emit int64 as a string."""
        try:
            return int(counts.get(key, 0) or 0)
        except (TypeError, ValueError):
            return 0

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        repos = await _list_repositories(gcloud_runner, project_id)
        docker_repos = []
        for repo in repos:
            location, repo_id = _repo_location_and_id(repo)
            if repo.get("format") == "DOCKER" and location and repo_id:
                docker_repos.append((location, repo_id))

        capped = len(docker_repos) > self.MAX_REPOS
        cap_note = (
            f" (inspected first {self.MAX_REPOS} of {len(docker_repos)} "
            f"Docker repositories)"
            if capped else ""
        )
        for location, repo_id in docker_repos[:self.MAX_REPOS]:
            try:
                images = await gcloud_runner.run(
                    f"gcloud artifacts docker images list "
                    f"{location}-docker.pkg.dev/{project_id}/{repo_id} "
                    f"--show-occurrences --format=json"
                )
            except Exception as e:
                logger.debug("docker images list failed for %s: %s", repo_id, e)
                continue
            if not isinstance(images, list):
                continue
            critical = 0
            high = 0
            affected = 0
            for img in images:
                if not isinstance(img, dict):
                    continue
                counts = img.get("vulnerability_counts")
                if not isinstance(counts, dict):
                    continue
                c = self._count(counts, "CRITICAL")
                h = self._count(counts, "HIGH")
                if c or h:
                    affected += 1
                critical += c
                high += h
            if critical or high:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title,
                    description=self.description,
                    severity=Severity.CRITICAL if critical else Severity.HIGH,
                    category=self.category, service=self.service,
                    resource_name=f"repositories/{repo_id}",
                    project_id=project_id,
                    current_state=(
                        f"{affected} image(s) with {critical} CRITICAL and "
                        f"{high} HIGH vulnerabilities{cap_note}"
                    ),
                    recommended_state=(
                        "Rebuild on patched base images and delete or block "
                        "vulnerable versions"
                    ),
                    fix_command="", references=self.references,
                ))
        return findings


class LegacyContainerRegistryInUse(BaseCheck):
    """AR-006: Deprecated Container Registry (gcr.io) still holds images."""

    id = "AR-006"
    title = "Legacy Container Registry (gcr.io) still in use"
    description = (
        "Container Registry is deprecated and lacks Artifact Registry's "
        "per-repository IAM, CMEK, cleanup policies and regional controls. "
        "Migrate gcr.io images to Artifact Registry."
    )
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "Artifact Registry"
    service_category = ServiceCategory.ARTIFACT_REGISTRY
    required_apis: ClassVar[list[str]] = ["containerregistry.googleapis.com"]
    gcloud_command = (
        "gcloud container images list --project={project_id} --format=json"
    )
    fix_command_template = (
        "gcloud artifacts docker upgrade migrate "
        "--projects={project_id}"
    )
    references: ClassVar[list[str]] = [
        "https://cloud.google.com/artifact-registry/docs/transition/transition-from-gcr",
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.8.8"],
    }

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        try:
            images = await gcloud_runner.run(
                f"gcloud container images list --project={project_id} --format=json"
            )
        except Exception as e:
            logger.debug("container images list failed: %s", e)
            return []
        if not isinstance(images, list) or not images:
            return []
        names = [
            i.get("name", "") for i in images if isinstance(i, dict) and i.get("name")
        ]
        sample = ", ".join(names[:5])
        return [CheckResult(
            check_id=self.id, title=self.title, description=self.description,
            severity=self.severity, category=self.category, service=self.service,
            resource_name=f"gcr.io/{project_id}", project_id=project_id,
            current_state=(
                f"{len(images)} image path(s) in legacy Container Registry"
                + (f": {sample}" if sample else "")
            ),
            recommended_state="Migrate images to Artifact Registry",
            fix_command=self.build_fix_command(project_id=project_id),
            references=self.references,
        )]


apply_required_apis(sys.modules[__name__], ["artifactregistry.googleapis.com"])
