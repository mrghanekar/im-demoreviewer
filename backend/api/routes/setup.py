"""Setup and configuration API routes.

Provides endpoints for the setup wizard: service account info,
project listing, IAM validation, and check catalog.
"""

import logging
import re

from fastapi import APIRouter, HTTPException, Query

from backend.checks.registry import get_check_catalog
from backend.config import settings
from backend.core.gcloud_runner import GcloudRunner, GcloudError, GcloudNotFoundError
from backend.api.middleware.validation import validate_project_id
from backend.core.models import (
    CheckCatalogEntry,
    OrganizationInfo,
    ProjectInfo,
    RoleValidation,
    ServiceAccountInfo,
)

# Allowed GCS locations for bucket creation
VALID_GCS_LOCATIONS = frozenset({
    "us", "eu", "asia",
    "us-central1", "us-east1", "us-east4", "us-east5", "us-south1", "us-west1",
    "us-west2", "us-west3", "us-west4",
    "europe-central2", "europe-north1", "europe-southwest1", "europe-west1",
    "europe-west2", "europe-west3", "europe-west4", "europe-west6", "europe-west8",
    "europe-west9", "europe-west10", "europe-west12",
    "asia-east1", "asia-east2", "asia-northeast1", "asia-northeast2",
    "asia-northeast3", "asia-south1", "asia-south2", "asia-southeast1",
    "asia-southeast2",
    "australia-southeast1", "australia-southeast2",
    "me-central1", "me-central2", "me-west1",
    "northamerica-northeast1", "northamerica-northeast2",
    "southamerica-east1", "southamerica-west1",
    "africa-south1",
})

# Regex for validating GCS bucket names (3-63 chars, lowercase, digits, hyphens, dots)
BUCKET_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$")

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/setup", tags=["setup"])

# Shared gcloud runner
_gcloud = GcloudRunner()

# Required roles for scanning
REQUIRED_PROJECT_ROLES = [
    "roles/viewer",
    "roles/iam.securityReviewer",
    "roles/cloudasset.viewer",
]

def _require_project_id(project_id: str) -> str:
    """Validate a project ID or reject the request.

    Every value reaching GcloudRunner is interpolated into a shell command,
    so unvalidated project IDs are a command-injection sink.
    """
    cleaned = validate_project_id(project_id)
    if not cleaned:
        raise HTTPException(
            status_code=422, detail=f"Invalid project ID: '{project_id}'"
        )
    return cleaned


REQUIRED_ORG_ROLES = [
    "roles/resourcemanager.organizationViewer",
    "roles/resourcemanager.folderViewer",
    "roles/browser",
]


@router.get("/service-account", response_model=ServiceAccountInfo)
async def get_service_account() -> ServiceAccountInfo:
    """Get information about the currently active service account."""
    try:
        account_info = await _gcloud.get_active_account()
        
        # Prefer configured target_id, fallback to gcloud current project
        project_id = settings.target_id or await _gcloud.get_current_project()

        email = account_info.get("account", "")
        account_type = (
            "serviceAccount"
            if email.endswith(".iam.gserviceaccount.com") or email.endswith(".gserviceaccount.com")
            else "user"
        )

        return ServiceAccountInfo(
            email=email,
            project_id=project_id,
            default_org_id=settings.default_org_id,
            account_type=account_type,
            is_active=bool(email),
        )
    except GcloudNotFoundError:
        return ServiceAccountInfo(
            email="",
            project_id="",
            account_type="",
            is_active=False,
        )
    except Exception as e:
        logger.error("Failed to get service account info: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/projects", response_model=list[ProjectInfo])
async def list_projects(
    org_id: str | None = Query(None, description="Filter projects by organization ID"),
) -> list[ProjectInfo]:
    """List accessible GCP projects.
    
    If org_id is provided, lists only projects under that organization.
    """
    try:
        cmd = "gcloud projects list --format=json"
        if org_id:
            if not org_id.strip().isdigit():
                raise HTTPException(status_code=422, detail="Organization ID must be numeric")
            cmd = f"gcloud projects list --filter=parent.id={org_id.strip()} --format=json"

        projects = await _gcloud.run(cmd, use_cache=False)

        if not isinstance(projects, list):
            return []

        return [
            ProjectInfo(
                project_id=p.get("projectId", ""),
                name=p.get("name", ""),
                project_number=str(p.get("projectNumber", "")),
                state=p.get("lifecycleState", ""),
                parent_type=p.get("parent", {}).get("type", "") if isinstance(p.get("parent"), dict) else "",
                parent_id=p.get("parent", {}).get("id", "") if isinstance(p.get("parent"), dict) else "",
            )
            for p in projects
            if p.get("lifecycleState") == "ACTIVE"
        ]
    except GcloudNotFoundError:
        raise HTTPException(status_code=503, detail="gcloud CLI not available")
    except GcloudError as e:
        logger.error("Failed to list projects: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/organizations", response_model=list[OrganizationInfo])
async def list_organizations() -> list[OrganizationInfo]:
    """List accessible GCP organizations."""
    try:
        orgs = await _gcloud.run("gcloud organizations list --format=json", use_cache=False)

        if not isinstance(orgs, list):
            logger.warning("gcloud organizations list returned non-list: %s", orgs)
            return []

        logger.info("Found %d organizations", len(orgs))
        return [
            OrganizationInfo(
                org_id=o.get("name", "").replace("organizations/", ""),
                display_name=o.get("displayName", ""),
                state=o.get("lifecycleState", ""),
            )
            for o in orgs
        ]
    except GcloudNotFoundError:
        raise HTTPException(status_code=503, detail="gcloud CLI not available")
    except GcloudError as e:
        logger.error("Failed to list organizations: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/validate", response_model=RoleValidation)
async def validate_permissions(
    project_id: str = Query(..., description="GCP project ID to validate against"),
    scope: str = Query("project", pattern=r"^(org|project)$", description="Scan scope"),
) -> RoleValidation:
    """Validate that the service account has required IAM roles.

    Checks the IAM policy for the given project and reports which
    required roles are granted and which are missing.
    """
    project_id = _require_project_id(project_id)

    try:
        # Get current account email
        account_info = await _gcloud.get_active_account()
        email = account_info.get("account", "")
        if not email:
            return RoleValidation(
                valid=False,
                missing_roles=REQUIRED_PROJECT_ROLES,
                grant_commands=[
                    f"gcloud projects add-iam-policy-binding {project_id} "
                    f"--member='serviceAccount:YOUR_SA_EMAIL' --role='{role}'"
                    for role in REQUIRED_PROJECT_ROLES
                ],
            )

        # Determine member prefix
        member_prefix = "serviceAccount" if email.endswith(".gserviceaccount.com") else "user"
        member = f"{member_prefix}:{email}"

        # Get IAM policy
        policy = await _gcloud.run(
            f"gcloud projects get-iam-policy {project_id} --format=json",
            use_cache=False,
        )

        # Extract roles for this member
        granted_roles: list[str] = []
        if isinstance(policy, dict):
            for binding in policy.get("bindings", []):
                if member in binding.get("members", []):
                    granted_roles.append(binding.get("role", ""))

        # Check required roles
        required = list(REQUIRED_PROJECT_ROLES)
        if scope == "org":
            required.extend(REQUIRED_ORG_ROLES)

        missing_roles = [r for r in required if r not in granted_roles]

        # Generate grant commands for missing roles
        grant_commands = [
            f"gcloud projects add-iam-policy-binding {project_id} "
            f"--member='{member}' --role='{role}'"
            for role in missing_roles
        ]

        return RoleValidation(
            valid=len(missing_roles) == 0,
            granted_roles=granted_roles,
            missing_roles=missing_roles,
            grant_commands=grant_commands,
        )

    except GcloudNotFoundError:
        raise HTTPException(status_code=503, detail="gcloud CLI not available")
    except GcloudError as e:
        logger.error("Failed to validate permissions: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/checks/catalog", response_model=list[CheckCatalogEntry])
async def get_checks_catalog() -> list[CheckCatalogEntry]:
    """List all available checks in the catalog."""
    catalog = get_check_catalog()
    return [CheckCatalogEntry(**entry) for entry in catalog]


@router.get("/validate-scan-target")
async def validate_scan_target(
    project: str = Query(..., description="GCP project ID to scan"),
) -> dict:
    """Pre-flight: can the SA actually read this project?

    The wizard hits this BEFORE letting the user kick off a scan. If the SA
    lacks viewer perms on the target project (the most common cause of stuck
    scans), we surface the exact gcloud command to fix it instead of letting
    them start a scan that will silently 403 200 times.

    Returns:
        {
          "ok": bool,
          "project": str,
          "checks": [{"name": str, "passed": bool, "detail": str}, ...],
          "suggested_command": str  # gcloud command to grant missing roles
        }
    """
    cleaned = validate_project_id(project)
    if not cleaned:
        raise HTTPException(status_code=422, detail=f"Invalid project ID: '{project}'")
    target = cleaned

    results: list[dict] = []
    sa_email = settings.sa_email or ""

    # Probe 1: project metadata read (roles/viewer or roles/browser)
    try:
        await _gcloud.run(
            f"gcloud projects describe {target} --format=json",
            use_cache=False,
        )
        results.append({"name": "projects.describe", "passed": True, "detail": "ok"})
    except GcloudError as e:
        results.append({
            "name": "projects.describe",
            "passed": False,
            "detail": str(e)[:300],
        })
    except GcloudNotFoundError:
        raise HTTPException(status_code=503, detail="gcloud CLI not available")

    # Probe 2: enabled-API listing (the engine's first scan call)
    try:
        await _gcloud.run(
            f"gcloud services list --enabled --project={target} --format=json",
            use_cache=False,
        )
        results.append({"name": "services.list", "passed": True, "detail": "ok"})
    except GcloudError as e:
        results.append({
            "name": "services.list",
            "passed": False,
            "detail": str(e)[:300],
        })

    all_ok = all(r["passed"] for r in results)

    # Suggested fix command: deliberately matches setup.sh's --grant-on logic.
    # Emit a single-line gcloud per role (no for-loop, no backslash line
    # continuations) so partial copy-paste from Cloud Shell still runs cleanly.
    suggested = ""
    if not all_ok and sa_email:
        roles_list = [
            "roles/viewer",
            "roles/iam.securityReviewer",
            "roles/cloudasset.viewer",
            "roles/orgpolicy.policyViewer",
            "roles/recommender.viewer",
        ]
        lines = [f"# Easiest:  ./setup.sh --grant-on {target}", "# Or run these five one-liners:"]
        lines.extend(
            f"gcloud projects add-iam-policy-binding {target} --member=serviceAccount:{sa_email} --role={role} --condition=None --quiet"
            for role in roles_list
        )
        suggested = "\n".join(lines)

    return {
        "ok": all_ok,
        "project": target,
        "sa_email": sa_email,
        "checks": results,
        "suggested_command": suggested,
    }


@router.get("/buckets", response_model=list[str])
async def list_buckets(
    project_id: str | None = Query(None, description="GCP project ID"),
) -> list[str]:
    """List GCS buckets in the project."""
    try:
        cmd = "gcloud storage buckets list --format='value(name)'"
        if project_id:
            cleaned = validate_project_id(project_id)
            if not cleaned:
                raise HTTPException(status_code=422, detail="Invalid project ID format")
            cmd += f" --project={cleaned}"

        buckets = await _gcloud.run(cmd, parse_json=False, use_cache=False)
        if not buckets:
            return []

        return [b.strip().replace("gs://", "") for b in buckets.strip().split("\n") if b.strip()]
    except GcloudError as e:
        logger.error("Failed to list buckets: %s", e)
        raise HTTPException(status_code=500, detail="Failed to list buckets")


@router.post("/buckets", response_model=dict)
async def create_bucket(
    name: str = Query(..., description="Bucket name"),
    project_id: str | None = Query(None, description="GCP project ID"),
    location: str = Query("us-central1", description="Bucket location"),
) -> dict:
    """Create a new GCS bucket."""
    try:
        # Validate bucket name
        if not name or not BUCKET_NAME_RE.match(name.strip().lower()):
            raise HTTPException(status_code=400, detail="Invalid bucket name. Must be 3-63 chars, lowercase alphanumeric, hyphens, dots.")

        # Validate location against allowlist
        if location.strip().lower() not in VALID_GCS_LOCATIONS:
            raise HTTPException(status_code=400, detail=f"Invalid location '{location}'. Must be a valid GCS region.")

        # Validate project_id if provided
        cleaned_project = None
        if project_id:
            cleaned_project = validate_project_id(project_id)
            if not cleaned_project:
                raise HTTPException(status_code=422, detail="Invalid project ID format")

        cmd = f"gcloud storage buckets create gs://{name.strip().lower()} --location={location.strip().lower()} --uniform-bucket-level-access"
        if cleaned_project:
            cmd += f" --project={cleaned_project}"

        await _gcloud.run(cmd, parse_json=False, use_cache=False)
        return {"status": "created", "name": name.strip().lower()}
    except HTTPException:
        raise
    except GcloudError as e:
        logger.error("Failed to create bucket: %s", e)
        raise HTTPException(status_code=500, detail="Failed to create bucket")
