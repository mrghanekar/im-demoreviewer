"""Pydantic models for the Democratized Reviewer.

All data structures used across the application are defined here.
These models are shared between API responses, the check engine, and storage.
"""

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(StrEnum):
    """Finding severity level."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(StrEnum):
    """Best-practice category for a finding."""
    SECURITY = "security"
    RELIABILITY = "reliability"
    PERFORMANCE = "performance"
    COST = "cost"
    OPERATIONS = "operations"


class ServiceCategory(StrEnum):
    """GCP service category for check modules."""
    GKE = "gke"
    GCE = "gce"
    GCS = "gcs"
    DATABASES = "databases"
    SECURITY = "security"
    NETWORKING = "networking"
    IAM = "iam"
    DATA = "data"
    MONITORING = "monitoring"
    BILLING = "billing"
    VERTEX_AI = "vertex_ai"
    # New categories (2026-05)
    CLOUD_RUN = "cloud_run"
    CLOUD_FUNCTIONS = "cloud_functions"
    SECRET_MANAGER = "secret_manager"
    CLOUD_BUILD = "cloud_build"
    MEMORYSTORE = "memorystore"
    FIRESTORE = "firestore"
    SPANNER = "spanner"
    IAP = "iap"
    COMPOSER = "composer"
    POSTURE = "posture"  # Org-level architecture posture checks
    # G6 additions (post-audit catalog gaps)
    ALLOYDB = "alloydb"
    APP_ENGINE = "app_engine"
    CLOUD_RUN_JOBS = "cloud_run_jobs"
    # Audit-coverage additions (2026-08)
    API_SECURITY = "api_security"
    ARTIFACT_REGISTRY = "artifact_registry"
    PATCH_MANAGEMENT = "patch_management"
    COMPLIANCE = "compliance"


class ScanStatus(StrEnum):
    """Lifecycle status of a scan."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class CheckStatus(StrEnum):
    """Execution status of an individual check."""
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    ERRORED = "errored"
    SKIPPED = "skipped"


class CostAnalysisStatus(StrEnum):
    """Lifecycle status of an on-demand cost analysis run."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# Check Result (produced by individual checks)
# ---------------------------------------------------------------------------

class CheckResult(BaseModel):
    """A single finding produced by a check against a resource.
    
    This is the output of a check's execute() method. One check can
    produce zero or more CheckResults (zero means the resource is compliant).
    """
    model_config = ConfigDict(populate_by_name=True)

    check_id: str = Field(..., description="Check identifier, e.g. GKE-001")
    title: str = Field(..., description="Human-readable finding title")
    description: str = Field(default="", description="Detailed explanation")
    severity: Severity = Field(..., description="Finding severity")
    category: Category = Field(..., description="Best-practice category")
    service: str = Field(..., description="GCP service, e.g. GKE, GCE")
    resource_name: str = Field(..., description="Full GCP resource path or name")
    resource_link: str = Field(default="", description="Cloud Console URL for the resource")
    project_id: str = Field(default="", description="GCP project containing the resource")
    current_state: str = Field(default="", description="Description of current (non-compliant) state")
    recommended_state: str = Field(default="", description="Description of recommended state")
    fix_command: str = Field(default="", description="gcloud command to fix the issue")
    references: list[str] = Field(default_factory=list, description="Documentation URLs")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata about the finding"
    )
    # Optional cost / waste hint. Populated only when the math is obvious
    # (e.g. unused disk size × per-GB list price) or when Google's Recommender
    # gives us its own projection. Null/0 means "we don't have a credible
    # number" — never fabricated. UI shows a $/mo chip when > 0.
    estimated_monthly_cost_usd: float | None = Field(
        default=None,
        description="Estimated monthly waste in USD; null when unknown",
    )
    cost_basis: str = Field(
        default="",
        description="One-line explanation of how the cost was computed",
    )


# ---------------------------------------------------------------------------
# Finding (stored result with scan context)
# ---------------------------------------------------------------------------

class Finding(CheckResult):
    """A finding stored in scan results, extending CheckResult with scan context."""

    id: str = Field(..., description="Unique finding ID within the scan")
    scan_id: str = Field(..., description="Parent scan ID")
    discovered_at: datetime = Field(default_factory=_utcnow)
    suppressed: bool = Field(
        default=False,
        description="When true, the finding is hidden from default views and excluded from counts.",
    )
    suppression_reason: str = Field(
        default="",
        description="Optional free-text note attached when the finding was suppressed.",
    )


# ---------------------------------------------------------------------------
# Check Execution Tracking
# ---------------------------------------------------------------------------

class CheckExecution(BaseModel):
    """Tracks the execution of a single check during a scan."""

    check_id: str
    check_title: str
    service_category: ServiceCategory
    status: CheckStatus = CheckStatus.PENDING
    findings_count: int = 0
    error_message: str = ""
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_ms: int = 0


# ---------------------------------------------------------------------------
# Scan Summary
# ---------------------------------------------------------------------------

def compute_health_score(by_severity: dict[str, int]) -> tuple[int, str]:
    """Return (score 0-100, letter grade A-F) from a severity histogram.

    Formula per PLAN.md §4.3 — Critical worth 10 points, High 5, Medium 2,
    Low 0.5. Info doesn't deduct. Score floored at 0. Letter grade:
    A 90+, B 80+, C 70+, D 60+, F otherwise.
    """
    deduction = (
        by_severity.get("critical", 0) * 10
        + by_severity.get("high", 0) * 5
        + by_severity.get("medium", 0) * 2
        + by_severity.get("low", 0) * 0.5
    )
    score = max(0, int(round(100 - deduction)))
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"
    return score, grade


class ScanSummary(BaseModel):
    """Aggregated statistics for a completed scan."""

    total_findings: int = 0
    by_severity: dict[str, int] = Field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
    })
    by_category: dict[str, int] = Field(default_factory=lambda: {
        "security": 0, "reliability": 0, "performance": 0, "cost": 0, "operations": 0
    })
    by_service: dict[str, int] = Field(default_factory=dict)
    checks_passed: int = 0
    checks_failed: int = 0
    checks_errored: int = 0
    checks_skipped: int = 0
    scan_duration_seconds: float = 0.0
    health_score: int = Field(default=100, description="0-100 weighted score; see compute_health_score")
    health_grade: str = Field(default="A", description="Letter grade A-F derived from health_score")
    estimated_monthly_waste_usd: float = Field(
        default=0.0,
        description="Sum of estimated_monthly_cost_usd across non-suppressed findings",
    )


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    """Request body to start a new scan."""

    scope: str = Field(..., pattern=r"^(org|project)$", description="Scan scope: org or project")
    target_id: str = Field(..., min_length=1, description="Organization ID or Project ID")
    categories: list[ServiceCategory] = Field(
        default_factory=lambda: list(ServiceCategory),
        description="Service categories to scan (default: all)"
    )
    specific_projects: list[str] = Field(
        default_factory=list,
        description="Specific project IDs to scan (if scope is org)"
    )

    @field_validator("specific_projects")
    @classmethod
    def _validate_specific_projects(cls, values: list[str]) -> list[str]:
        """Reject malformed project IDs.

        These bypass the org-scope enumeration guard in Scanner._enumerate_org_projects
        and are interpolated directly into gcloud shell commands by every check.
        """
        from backend.api.middleware.validation import validate_project_id

        cleaned: list[str] = []
        for value in values:
            valid = validate_project_id(value)
            if not valid:
                raise ValueError(f"Invalid project ID: {value!r}")
            cleaned.append(valid)
        return cleaned


class CostAnalysis(BaseModel):
    """Result of an on-demand Gemini-powered cost analysis for a scan.

    Populated by the /cost-analysis endpoint, which sends every finding
    with a resource attached to Gemini (grounded with Google Search) and
    asks for a per-resource monthly $ figure with citations. The model's
    output is written back here AND patched onto each Finding's
    estimated_monthly_cost_usd / cost_basis so the existing CSV/HTML
    exports pick it up automatically.
    """

    status: CostAnalysisStatus = CostAnalysisStatus.PENDING
    model: str = Field(default="", description="Gemini model that ran the analysis")
    started_at: datetime | None = None
    completed_at: datetime | None = None
    total_monthly_usd: float = 0.0
    findings_count: int = 0
    costed_count: int = Field(
        default=0,
        description="Findings that came back with a non-zero monthly cost",
    )
    grounding_sources: list[str] = Field(
        default_factory=list,
        description="cloud.google.com URLs Gemini cited for pricing",
    )
    notes: str = Field(
        default="",
        description="Short Gemini-generated summary of the analysis",
    )
    error_message: str = ""


class Scan(BaseModel):
    """Represents a scan session with its full lifecycle."""

    id: str = Field(..., description="Unique scan identifier")
    scope: str = Field(..., description="org or project")
    target_id: str = Field(..., description="Organization ID or Project ID")
    status: ScanStatus = ScanStatus.PENDING
    categories: list[ServiceCategory] = Field(default_factory=list)
    specific_projects: list[str] = Field(default_factory=list)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    summary: ScanSummary = Field(default_factory=ScanSummary)
    findings: list[Finding] = Field(default_factory=list)
    check_executions: list[CheckExecution] = Field(default_factory=list)
    projects_scanned: list[str] = Field(default_factory=list)
    error_message: str = ""
    scan_token: str = Field(default="", description="Access token for WebSocket streaming (only returned on scan creation)")
    gcloud_version: str = Field(default="", description="gcloud SDK version that ran this scan; helps spot field-rename drift")
    keep_forever: bool = Field(default=False, description="When true, the GCS 90-day lifecycle rule should not delete this scan")
    cost_analysis: CostAnalysis | None = Field(
        default=None,
        description="Result of the on-demand Gemini cost analysis; null until requested",
    )


# ---------------------------------------------------------------------------
# Setup & Validation
# ---------------------------------------------------------------------------

class ServiceAccountInfo(BaseModel):
    """Information about the active service account."""

    email: str = ""
    project_id: str = ""
    default_org_id: str = ""
    account_type: str = ""  # "serviceAccount" or "user"
    is_active: bool = False


class RoleValidation(BaseModel):
    """Result of pre-flight IAM role validation."""

    valid: bool = False
    granted_roles: list[str] = Field(default_factory=list)
    missing_roles: list[str] = Field(default_factory=list)
    grant_commands: list[str] = Field(default_factory=list)


class ProjectInfo(BaseModel):
    """Basic GCP project information."""

    project_id: str
    name: str = ""
    project_number: str = ""
    state: str = ""
    parent_type: str = ""
    parent_id: str = ""


class OrganizationInfo(BaseModel):
    """Basic GCP organization information."""

    org_id: str
    display_name: str = ""
    state: str = ""


# ---------------------------------------------------------------------------
# API Responses
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "ok"
    version: str = ""
    app_name: str = ""
    checks_loaded: int = 0
    environment: str = "local"
    gemini_enabled: bool = Field(
        default=True,
        description="Whether the deploy opted in to Vertex AI features (Explain + Cost Saving). Drives UI gating.",
    )
    service_name: str = Field(
        default="",
        description="Cloud Run service name (K_SERVICE). Empty when running locally.",
    )
    region: str = Field(
        default="",
        description="Region this revision was deployed to, from DR_REGION. Empty when unknown; the UI then omits --region from the log command rather than guessing.",
    )


class CheckCatalogEntry(BaseModel):
    """A check in the catalog listing."""

    id: str
    title: str
    description: str
    severity: Severity
    category: Category
    service: str
    service_category: ServiceCategory
    compliance_refs: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Control IDs this check provides evidence for, keyed by framework.",
    )


# ---------------------------------------------------------------------------
# WebSocket Events
# ---------------------------------------------------------------------------

class ScanEvent(BaseModel):
    """Real-time event emitted during a scan via WebSocket."""

    event_type: str = Field(..., description="Event type: check_started, check_completed, finding_discovered, scan_completed, scan_failed, log")
    scan_id: str
    timestamp: datetime = Field(default_factory=_utcnow)
    data: dict[str, Any] = Field(default_factory=dict)

