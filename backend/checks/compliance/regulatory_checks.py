"""Regulatory compliance checks — CERT-In Directions (2022) and DPDP Act 2023.

Checks: REG-001 through REG-007 (REG-006 deliberately not shipped — see below).

These checks exist to produce audit evidence lines for the Indian regulatory
frameworks in :mod:`backend.core.compliance`, plus the estate-inventory gap.
Wording discipline matters here: every finding describes a *configuration
observation* the tool made, never a legal conclusion. Whether a given
configuration satisfies the CERT-In Directions or the DPDP Act for a specific
organisation is a determination for that organisation's counsel and auditor.

Relationship to MON-006 (log-bucket retention below 90 days): MON-006 is the
general operational baseline shared by SOC2/PCI-style regimes. REG-001 is the
CERT-In evidence line — a different threshold (180 days, from Direction VI's
"rolling period of 180 days") grouped under CERT_IN in the compliance report.
A 30-day bucket fires both, by design, because they answer different audit
questions ("are you near industry baseline?" vs "can you evidence the CERT-In
direction?").

REG-006 (audit logging not configured for all services) is deliberately NOT
implemented: IAM-013 (DataAccessAuditLogsDisabled in
backend/checks/iam/role_bindings.py) is the canonical data-access audit-log
check, with service-specific coverage in DATA-016 (BigQuery) and the Cloud SQL
audit check. Shipping REG-006 would double-report the same auditConfigs
condition — the exact duplicate-check problem MON-001/MON-007/POST-005 were
removed for.
"""

import logging
import re
from typing import Any, ClassVar

from backend.checks.base import BaseCheck
from backend.config import settings
from backend.core.compliance import CERT_IN, DPDP, ISO_27001
from backend.core.models import Category, CheckResult, ServiceCategory, Severity

logger = logging.getLogger(__name__)

# The rolling log-retention period required by CERT-In Direction No.
# 20(3)/2022-CERT-In (28 April 2022), clause (iv)/"VI" in this catalog.
CERT_IN_RETENTION_DAYS = 180

# GCP regions physically located in India.
INDIA_REGIONS = ("asia-south1", "asia-south2")

CERT_IN_DIRECTIONS_URL = "https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf"
DPDP_ACT_URL = "https://www.meity.gov.in/content/digital-personal-data-protection-act-2023"

_ZONE_RE = re.compile(r"^[a-z]+-[a-z]+\d+-[a-z]$")


async def _list_log_buckets(project_id: str, gcloud_runner: Any) -> list[dict]:
    """List Cloud Logging buckets across every location of a project.

    Unlike the KMS surface (see ``_kms_keyrings`` in
    backend/checks/security/org_policies.py), the Logging API accepts a
    list-all-locations call: ``gcloud logging buckets list`` with no
    ``--location`` flag enumerates every location. The explicit ``-`` wildcard
    is never passed. If the all-locations call fails, fall back to
    ``--location=global``, where the ``_Default`` and ``_Required`` buckets
    live unless deliberately relocated.
    """
    try:
        buckets = await gcloud_runner.run(
            f"gcloud logging buckets list --project={project_id} --format=json"
        )
        if isinstance(buckets, list):
            return [b for b in buckets if isinstance(b, dict)]
    except Exception as e:
        logger.debug("logging buckets all-location list failed: %s", e)
    try:
        buckets = await gcloud_runner.run(
            f"gcloud logging buckets list --location=global --project={project_id} --format=json"
        )
    except Exception as e:
        logger.debug("logging buckets global list failed: %s", e)
        return []
    if not isinstance(buckets, list):
        return []
    return [b for b in buckets if isinstance(b, dict)]


def _bucket_id(bucket: dict) -> str:
    """Short bucket ID, e.g. '_Default', from the full resource name."""
    return bucket.get("name", "").rsplit("/", 1)[-1]


def _bucket_location(bucket: dict) -> str:
    """Location parsed from 'projects/p/locations/<loc>/buckets/<id>'."""
    name = bucket.get("name", "")
    parts = name.split("/")
    if "locations" in parts:
        idx = parts.index("locations")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return bucket.get("location", "")


def _is_active(bucket: dict) -> bool:
    # Buckets pending deletion (DELETE_REQUESTED) are not retention evidence
    # either way; only ACTIVE buckets are assessed.
    return bucket.get("lifecycleState", "ACTIVE") == "ACTIVE"


class LogRetentionBelowCertIn(BaseCheck):
    """REG-001: Log bucket retention below the CERT-In 180-day direction.

    Distinct from MON-006 (90-day general baseline): this check evidences the
    CERT-In direction specifically — 180-day threshold, CERT_IN grouping — so
    an assessor can pull one line for Direction VI instead of re-deriving it
    from a generic retention finding.
    """

    id = "REG-001"
    title = "Log bucket retention below the CERT-In 180-day requirement"
    description = (
        "CERT-In Direction No. 20(3)/2022-CERT-In (28 April 2022) requires ICT "
        "system logs to be maintained for a rolling period of 180 days. This "
        "Cloud Logging bucket is ACTIVE with a retention period shorter than "
        "180 days, so logs age out before the direction's retention window "
        "elapses. The tool observed the bucket configuration only; whether the "
        "direction applies to this workload is an organisational determination."
    )
    severity = Severity.HIGH
    category = Category.OPERATIONS
    service = "Compliance"
    service_category = ServiceCategory.COMPLIANCE
    required_apis: ClassVar[list[str]] = ["logging.googleapis.com"]
    gcloud_command = "gcloud logging buckets list --location=global --project={project_id} --format=json"
    fix_command_template = (
        "gcloud logging buckets update {bucket_id} --location={location} "
        f"--retention-days={CERT_IN_RETENTION_DAYS} --project={{project_id}}"
    )
    references: ClassVar[list[str]] = [
        CERT_IN_DIRECTIONS_URL,
        "https://cloud.google.com/logging/docs/buckets#custom-retention",
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {CERT_IN: ["VI"], ISO_27001: ["A.8.15"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for bucket in await _list_log_buckets(project_id, gcloud_runner):
            if not _is_active(bucket):
                continue
            days = bucket.get("retentionDays", 30)  # Cloud Logging default is 30
            if not isinstance(days, (int, float)) or days >= CERT_IN_RETENTION_DAYS:
                continue
            bucket_id = _bucket_id(bucket)
            location = _bucket_location(bucket)
            findings.append(CheckResult(
                check_id=self.id, title=self.title, description=self.description,
                severity=self.severity, category=self.category, service=self.service,
                resource_name=bucket.get("name", f"projects/{project_id}/buckets/{bucket_id}"),
                project_id=project_id,
                resource_link=self.console_link("logging", project_id),
                current_state=(
                    f"retentionDays={int(days)} — below the 180-day rolling log-retention "
                    "period required by CERT-In Direction No. 20(3)/2022-CERT-In"
                ),
                recommended_state=(
                    f"Set retention to >= {CERT_IN_RETENTION_DAYS} days on this bucket "
                    "(or route the logs to a bucket that retains them for 180+ days)"
                ),
                fix_command=self.build_fix_command(
                    bucket_id=bucket_id, location=location, project_id=project_id,
                ),
                references=self.references,
                metadata={"retention_days": days, "location": location, "locked": bucket.get("locked", False)},
            ))
        return findings


class LogRetentionNotLocked(BaseCheck):
    """REG-002: Bucket meets 180 days but the retention policy is not locked.

    Retention that an editor can shorten after an incident is not retention
    evidence. Only buckets that already meet the 180-day period are flagged —
    a short-retention bucket is REG-001's finding, and locking a too-short
    period would be counterproductive. Google's ``_Required`` bucket ships
    locked at 400 days and will not fire here. Locking is irreversible, which
    is exactly why an auditor values it — say so before applying the fix.
    """

    id = "REG-002"
    title = "Log bucket retention policy is not locked"
    description = (
        "This Cloud Logging bucket retains logs for 180+ days but its retention "
        "policy is not locked, so a principal with logging.admin can shorten "
        "the period (including retroactively, after an incident). Locking the "
        "bucket makes the configured retention immutable and turns it into "
        "defensible audit evidence. Note: locking is irreversible."
    )
    severity = Severity.MEDIUM
    category = Category.OPERATIONS
    service = "Compliance"
    service_category = ServiceCategory.COMPLIANCE
    required_apis: ClassVar[list[str]] = ["logging.googleapis.com"]
    gcloud_command = "gcloud logging buckets list --location=global --project={project_id} --format=json"
    fix_command_template = (
        "gcloud logging buckets update {bucket_id} --location={location} "
        "--locked --project={project_id}"
    )
    references: ClassVar[list[str]] = [
        "https://cloud.google.com/logging/docs/buckets#lock-bucket",
        CERT_IN_DIRECTIONS_URL,
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {CERT_IN: ["VI"], ISO_27001: ["A.5.33"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for bucket in await _list_log_buckets(project_id, gcloud_runner):
            if not _is_active(bucket):
                continue
            days = bucket.get("retentionDays", 30)
            if not isinstance(days, (int, float)) or days < CERT_IN_RETENTION_DAYS:
                continue  # short retention is REG-001's finding; don't double-report
            if bucket.get("locked", False):
                continue
            bucket_id = _bucket_id(bucket)
            location = _bucket_location(bucket)
            findings.append(CheckResult(
                check_id=self.id, title=self.title, description=self.description,
                severity=self.severity, category=self.category, service=self.service,
                resource_name=bucket.get("name", f"projects/{project_id}/buckets/{bucket_id}"),
                project_id=project_id,
                resource_link=self.console_link("logging", project_id),
                current_state=f"retentionDays={int(days)} but locked=false — retention can be shortened later",
                recommended_state="Lock the retention policy once the period is final (irreversible)",
                fix_command=self.build_fix_command(
                    bucket_id=bucket_id, location=location, project_id=project_id,
                ),
                references=self.references,
                metadata={"retention_days": days, "location": location},
            ))
        return findings


class LogBucketOutsideIndia(BaseCheck):
    """REG-003: _Default/_Required log bucket stored outside Indian regions.

    Worded as a data-residency *observation*, not a violation: ``global`` and
    multi-region storage are legitimate for many organisations, and CERT-In's
    "within Indian jurisdiction" wording plus DPDP Section 16 leave the
    residency determination to the organisation. Only the built-in
    ``_Default``/``_Required`` buckets are assessed — they are where audit
    logs land by default. Buckets in asia-south1, asia-south2 or ``global``
    do not fire.
    """

    id = "REG-003"
    title = "Built-in log bucket is stored in a region outside India"
    description = (
        "The project's _Default or _Required log bucket is homed in a specific "
        "region outside India (not asia-south1/asia-south2 and not the default "
        "'global'). For a CERT-In/DPDP engagement this is a data-residency "
        "observation to review with counsel: CERT-In Direction VI expects logs "
        "maintained within Indian jurisdiction, and DPDP Section 16 governs "
        "cross-border transfer of personal data that may appear in logs. This "
        "is a configuration observation, not a determination of non-compliance "
        "— regionalising logs may be intentional and permissible."
    )
    severity = Severity.MEDIUM
    category = Category.OPERATIONS
    service = "Compliance"
    service_category = ServiceCategory.COMPLIANCE
    required_apis: ClassVar[list[str]] = ["logging.googleapis.com"]
    gcloud_command = "gcloud logging buckets list --project={project_id} --format=json"
    # Bucket locations are immutable; remediation is routing to a new
    # India-region bucket, not updating the existing one.
    fix_command_template = (
        "gcloud logging buckets create {bucket_id}-in --location=asia-south1 "
        f"--retention-days={CERT_IN_RETENTION_DAYS} --project={{project_id}}"
    )
    references: ClassVar[list[str]] = [
        "https://cloud.google.com/logging/docs/regionalized-logs",
        CERT_IN_DIRECTIONS_URL,
        DPDP_ACT_URL,
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {CERT_IN: ["VI"], DPDP: ["16"]}

    BUILTIN_BUCKETS = ("_Default", "_Required")

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for bucket in await _list_log_buckets(project_id, gcloud_runner):
            bucket_id = _bucket_id(bucket)
            if bucket_id not in self.BUILTIN_BUCKETS:
                continue
            location = _bucket_location(bucket)
            if not location or location == "global" or location in INDIA_REGIONS:
                continue
            findings.append(CheckResult(
                check_id=self.id, title=self.title, description=self.description,
                severity=self.severity, category=self.category, service=self.service,
                resource_name=bucket.get("name", f"projects/{project_id}/buckets/{bucket_id}"),
                project_id=project_id,
                resource_link=self.console_link("logging", project_id),
                current_state=(
                    f"{bucket_id} bucket is homed in '{location}' — outside the Indian "
                    "regions (asia-south1, asia-south2); review against your "
                    "data-residency policy"
                ),
                recommended_state=(
                    "If Indian residency is required for these logs, route them to a "
                    "log bucket in asia-south1/asia-south2; otherwise document the "
                    "residency decision for the audit"
                ),
                fix_command=self.build_fix_command(bucket_id=bucket_id, project_id=project_id),
                references=self.references,
                metadata={"location": location, "bucket": bucket_id},
            ))
        return findings


def _normalise_location(location: str) -> str:
    """Collapse a zone ('us-central1-a') to its region ('us-central1')."""
    loc = location.strip().lower()
    if _ZONE_RE.fullmatch(loc):
        return loc.rsplit("-", 1)[0]
    return loc


class ResourcesOutsideApprovedRegions(BaseCheck):
    """REG-004: Resources located outside the approved data-residency regions.

    INERT UNTIL CONFIGURED: when ``settings.data_residency_allowed_regions``
    (env var ``DR_DATA_RESIDENCY_ALLOWED_REGIONS``) is empty — the default —
    this check returns no findings and makes no API calls. A residency check
    that fired on every non-India resource out of the box would bury a
    non-Indian customer in noise; the operator must opt in by declaring their
    approved regions (for an Indian DPDP engagement, asia-south1/asia-south2).

    Zones are normalised to their region before comparison. Resources whose
    location is ``global`` (or blank) are not flagged — global services have
    no single homing to assess. Multi-region locations ('us', 'asia', 'eu',
    'nam4', …) ARE flagged unless listed in the allow-list, since a
    multi-region spans jurisdictions. Findings are aggregated per offending
    region to keep the report readable. Worded as an observation for
    residency review, not a violation.
    """

    id = "REG-004"
    title = "Resources located outside the approved data-residency regions"
    description = (
        "Cloud Asset Inventory reports resources homed in locations that are "
        "not in the organisation's configured data-residency allow-list. For a "
        "DPDP engagement (Section 16, cross-border transfer) each such location "
        "should be reviewed: either the resource does not process personal "
        "data, the location is permissible, or the resource should be moved. "
        "This is a location inventory, not a legal determination."
    )
    severity = Severity.MEDIUM
    category = Category.OPERATIONS
    service = "Compliance"
    service_category = ServiceCategory.COMPLIANCE
    required_apis: ClassVar[list[str]] = ["cloudasset.googleapis.com"]
    gcloud_command = "gcloud asset search-all-resources --scope=projects/{project_id} --format=json"
    references: ClassVar[list[str]] = [
        "https://cloud.google.com/asset-inventory/docs/searching-resources",
        "https://cloud.google.com/architecture/framework/security/data-residency-sovereignty",
        DPDP_ACT_URL,
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {DPDP: ["16"], ISO_27001: ["A.5.23"]}

    # How many example resource names to embed per offending region.
    MAX_EXAMPLES = 5
    MAX_METADATA_RESOURCES = 50

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        allowed = {r.strip().lower() for r in settings.data_residency_allowed_regions if r.strip()}
        if not allowed:
            # Inert by design — see class docstring.
            return []

        try:
            assets = await gcloud_runner.run(
                f"gcloud asset search-all-resources --scope=projects/{project_id} --format=json"
            )
        except Exception as e:
            logger.debug("REG-004: %s", e)
            return []
        if not isinstance(assets, list):
            return []

        by_region: dict[str, list[dict]] = {}
        for asset in assets:
            if not isinstance(asset, dict):
                continue
            location = str(asset.get("location", "")).strip().lower()
            if not location or location == "global":
                continue
            region = _normalise_location(location)
            if location in allowed or region in allowed:
                continue
            by_region.setdefault(region, []).append(asset)

        findings: list[CheckResult] = []
        for region in sorted(by_region):
            offenders = by_region[region]
            names = [a.get("name", "") for a in offenders]
            examples = ", ".join(n.rsplit("/", 1)[-1] or n for n in names[:self.MAX_EXAMPLES])
            more = f" (+{len(names) - self.MAX_EXAMPLES} more)" if len(names) > self.MAX_EXAMPLES else ""
            findings.append(CheckResult(
                check_id=self.id, title=self.title, description=self.description,
                severity=self.severity, category=self.category, service=self.service,
                resource_name=f"projects/{project_id}/locations/{region}",
                project_id=project_id,
                current_state=(
                    f"{len(offenders)} resource(s) in '{region}', which is outside the "
                    f"approved regions ({', '.join(sorted(allowed))}): {examples}{more}"
                ),
                recommended_state=(
                    "Review each resource against the data-residency policy; migrate, "
                    "exempt, or document it for the audit"
                ),
                fix_command="", references=self.references,
                metadata={
                    "region": region,
                    "resource_count": len(offenders),
                    "resources": names[:self.MAX_METADATA_RESOURCES],
                    "allowed_regions": sorted(allowed),
                },
            ))
        return findings


class AssetInventoryDisabled(BaseCheck):
    """REG-005: Cloud Asset Inventory API is not enabled on the project.

    Deliberately has NO ``required_apis`` gate on cloudasset.googleapis.com —
    the disabled API is the very condition being detected; gating on it would
    make the check skip itself into uselessness. Complements POST-003 (asset
    feeds), which only runs once the API is on: when CAI is off, POST-003
    skips and this check fires; when CAI is on, this check stays quiet.
    """

    id = "REG-005"
    title = "Cloud Asset Inventory is not enabled — no authoritative asset inventory"
    description = (
        "cloudasset.googleapis.com is not enabled on this project, so there is "
        "no authoritative, queryable inventory of the estate. An asset "
        "inventory report is a standing deliverable of a security audit and "
        "the foundation for data-residency and drift review; without CAI it "
        "has to be assembled by hand, per service."
    )
    severity = Severity.MEDIUM
    category = Category.OPERATIONS
    service = "Compliance"
    service_category = ServiceCategory.COMPLIANCE
    # Intentionally NOT ["cloudasset.googleapis.com"] — see class docstring.
    required_apis: ClassVar[list[str]] = ["serviceusage.googleapis.com"]
    gcloud_command = "gcloud services list --project={project_id} --format=json --filter=name:cloudasset.googleapis.com"
    fix_command_template = "gcloud services enable cloudasset.googleapis.com --project={project_id}"
    references: ClassVar[list[str]] = [
        "https://cloud.google.com/asset-inventory/docs/overview",
        "https://cloud.google.com/asset-inventory/docs/quickstart",
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {ISO_27001: ["A.5.9"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            services = await gcloud_runner.run(
                f"gcloud services list --project={project_id} --format=json "
                "--filter=name:cloudasset.googleapis.com"
            )
        except Exception as e:
            logger.debug("REG-005: %s", e)
            return findings
        if not isinstance(services, list):
            return findings  # can't verify either way — don't assert absence
        if len(services) == 0:
            findings.append(CheckResult(
                check_id=self.id, title=self.title, description=self.description,
                severity=self.severity, category=self.category, service=self.service,
                resource_name=f"projects/{project_id}/services/cloudasset.googleapis.com",
                project_id=project_id,
                current_state="Cloud Asset Inventory API (cloudasset.googleapis.com) is not enabled",
                recommended_state="Enable Cloud Asset Inventory to get an authoritative estate inventory",
                fix_command=self.build_fix_command(project_id=project_id),
                references=self.references,
            ))
        return findings


class NoSecurityEssentialContact(BaseCheck):
    """REG-007: No SECURITY Essential Contact registered on the project.

    Honesty note for the report: this verifies only that a security contact
    is *registered* in GCP Essential Contacts — the mailbox Google (and your
    own tooling) can notify about security events. It does not, and cannot,
    verify that a CERT-In point of contact has been communicated to CERT-In,
    that a DPDP grievance/contact publication exists, or that an
    incident-response process operates behind the address. Those remain
    process evidence for the auditor.

    REG-006 (audit logging for all services) was considered for this module
    and skipped — IAM-013 already covers it; see the module docstring.
    """

    id = "REG-007"
    title = "No security/incident Essential Contact registered"
    description = (
        "The project has no Essential Contact subscribed to the SECURITY "
        "notification category (or ALL). Without one, Google's security "
        "notifications go to project owners by default and there is no "
        "registered point of contact to anchor the CERT-In designated "
        "point-of-contact direction or the DPDP Section 8(8) contact-publication "
        "obligation. Registering a contact is necessary supporting evidence, "
        "not sufficient proof of an incident-response capability."
    )
    severity = Severity.MEDIUM
    category = Category.OPERATIONS
    service = "Compliance"
    service_category = ServiceCategory.COMPLIANCE
    required_apis: ClassVar[list[str]] = ["essentialcontacts.googleapis.com"]
    gcloud_command = "gcloud alpha essential-contacts list --project={project_id} --format=json"
    fix_command_template = (
        "gcloud essential-contacts create --email=SECURITY_TEAM_EMAIL "
        "--notification-categories=SECURITY --project={project_id}"
    )
    references: ClassVar[list[str]] = [
        "https://cloud.google.com/resource-manager/docs/managing-notification-contacts",
        CERT_IN_DIRECTIONS_URL,
        DPDP_ACT_URL,
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {CERT_IN: ["III"], DPDP: ["8(8)"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            contacts = await gcloud_runner.run(
                f"gcloud alpha essential-contacts list --project={project_id} --format=json"
            )
        except Exception as e:
            logger.debug("REG-007: %s", e)
            return findings
        if not isinstance(contacts, list):
            return findings  # can't verify — don't assert absence
        for contact in contacts:
            if not isinstance(contact, dict):
                continue
            categories = contact.get("notificationCategorySubscriptions", [])
            if not isinstance(categories, list):
                continue
            if "SECURITY" in categories or "ALL" in categories:
                return []  # a security contact is registered
        findings.append(CheckResult(
            check_id=self.id, title=self.title, description=self.description,
            severity=self.severity, category=self.category, service=self.service,
            resource_name=f"projects/{project_id}", project_id=project_id,
            current_state=(
                f"{len(contacts)} Essential Contact(s) registered; none subscribed to "
                "the SECURITY (or ALL) notification category"
            ),
            recommended_state=(
                "Register a monitored security mailbox as an Essential Contact with "
                "the SECURITY category, and keep it aligned with the point of contact "
                "designated to CERT-In"
            ),
            fix_command=self.build_fix_command(project_id=project_id),
            references=self.references,
        ))
        return findings
