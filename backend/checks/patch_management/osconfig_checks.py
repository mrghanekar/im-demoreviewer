"""Patch management checks built on VM Manager (OS Config).

Checks: PATCH-001, PATCH-002, PATCH-003, PATCH-004, PATCH-006

PATCH-005 (deprecated/EOL guest OS image) is intentionally NOT implemented:
GCE-011 (GCEDeprecatedImages in backend/checks/gce/instance_checks.py) already
flags instances whose boot image is DEPRECATED/OBSOLETE/DELETED using the image
deprecation metadata Google publishes, which covers the same EOL families
(debian-9, ubuntu-1604-lts, centos-7, windows-2012, ...) authoritatively.
Duplicating it here with a static family list would double-report every
affected VM.
"""

import logging
from typing import Any, ClassVar

from backend.checks.base import BaseCheck
from backend.core.compliance import CIS_GCP_V3, ISO_27001
from backend.core.models import Category, CheckResult, ServiceCategory, Severity

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared module-level helpers (same pattern as security/org_policies.py).
# Every gcloud invocation here goes through the runner's command cache, so the
# checks in this module share one `instances list`, one `project-info
# describe` and one `patch-deployments list` subprocess per project.
# ---------------------------------------------------------------------------


async def _instances(project_id: str, gcloud_runner: Any) -> list[dict]:
    """All compute instances in the project (cached across checks)."""
    try:
        instances = await gcloud_runner.run(
            f"gcloud compute instances list --project={project_id} --format=json"
        )
    except Exception as e:
        logger.debug("patch_management: could not list instances for %s: %s", project_id, e)
        return []
    if not isinstance(instances, list):
        return []
    return [i for i in instances if isinstance(i, dict)]


async def _running_instances(project_id: str, gcloud_runner: Any) -> list[dict]:
    return [
        i for i in await _instances(project_id, gcloud_runner)
        if i.get("status") == "RUNNING"
    ]


def _zone_of(instance: dict) -> str:
    return str(instance.get("zone", "")).split("/")[-1]


def _metadata_value(metadata: Any, key: str) -> str | None:
    """Value of a metadata key, or None when the key is absent."""
    if not isinstance(metadata, dict):
        return None
    items = metadata.get("items", [])
    if not isinstance(items, list):
        return None
    for item in items:
        if isinstance(item, dict) and item.get("key") == key:
            return str(item.get("value", ""))
    return None


def _is_true(value: str | None) -> bool:
    return isinstance(value, str) and value.strip().lower() == "true"


async def _project_osconfig_metadata(project_id: str, gcloud_runner: Any) -> str | None:
    """Project-level `enable-osconfig` metadata value, or None when unset."""
    try:
        project_meta = await gcloud_runner.run(
            f"gcloud compute project-info describe --project={project_id} --format=json"
        )
    except Exception as e:
        logger.debug("patch_management: could not read project metadata for %s: %s", project_id, e)
        return None
    if not isinstance(project_meta, dict):
        return None
    return _metadata_value(project_meta.get("commonInstanceMetadata", {}), "enable-osconfig")


async def _patch_deployments(project_id: str, gcloud_runner: Any) -> list[dict] | None:
    """Patch deployments in the project.

    Returns None when the listing could not be performed (permission error,
    unexpected payload), so callers can distinguish "confirmed empty" from
    "unknown" and avoid false findings.
    """
    try:
        deployments = await gcloud_runner.run(
            f"gcloud compute os-config patch-deployments list "
            f"--project={project_id} --format=json"
        )
    except Exception as e:
        logger.debug("patch_management: could not list patch deployments for %s: %s", project_id, e)
        return None
    if not isinstance(deployments, list):
        return None
    return [d for d in deployments if isinstance(d, dict)]


async def _vulnerability_reports(
    project_id: str, gcloud_runner: Any, zones: list[str]
) -> list[dict]:
    """Vulnerability reports fanned out across the zones actually in use.

    The os-config listing surfaces are per-zone and reject `--location=-`
    (same trap the recommender checks in billing_checks.py fell into), so the
    fan-out enumerates only the zones that contain instances instead of every
    GCP zone.
    """
    reports: list[dict] = []
    for zone in zones:
        try:
            zone_reports = await gcloud_runner.run(
                f"gcloud compute os-config vulnerability-reports list "
                f"--project={project_id} --location={zone} --format=json"
            )
        except Exception as e:
            logger.debug("patch_management: no vulnerability reports in %s/%s: %s", project_id, zone, e)
            continue
        if isinstance(zone_reports, list):
            reports.extend(r for r in zone_reports if isinstance(r, dict))
    return reports


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


class OSConfigAPINotEnabled(BaseCheck):
    """PATCH-001: VM Manager (OS Config) API disabled on a project running VMs."""

    id = "PATCH-001"
    title = "VM Manager (OS Config API) not enabled on project with running VMs"
    description = (
        "Without the OS Config API there is no OS inventory, no vulnerability "
        "reporting and no automated patching for any VM in the project — zero "
        "patch visibility."
    )
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Patch Management"
    service_category = ServiceCategory.PATCH_MANAGEMENT
    gcloud_command = "gcloud services list --enabled --project={project_id} --format=json"
    fix_command_template = "gcloud services enable osconfig.googleapis.com --project={project_id}"
    references: ClassVar[list[str]] = [
        "https://cloud.google.com/compute/docs/vm-manager",
        "https://cloud.google.com/compute/docs/manage-os",
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {ISO_27001: ["A.8.8"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            services = await gcloud_runner.run(
                f"gcloud services list --enabled --project={project_id} --format=json"
            )
            if not isinstance(services, list):
                return []

            enabled: set[str] = set()
            for s in services:
                if not isinstance(s, dict):
                    continue
                config = s.get("config", {})
                if isinstance(config, dict) and config.get("name"):
                    enabled.add(str(config["name"]))
                if s.get("name"):
                    enabled.add(str(s["name"]).rsplit("/", 1)[-1])

            if "osconfig.googleapis.com" in enabled:
                return []

            running = await _running_instances(project_id, gcloud_runner)
            if not running:
                # No workloads to patch; not a finding.
                return []

            findings.append(CheckResult(
                check_id=self.id, title=self.title, description=self.description,
                severity=self.severity, category=self.category, service=self.service,
                resource_name=f"projects/{project_id}", project_id=project_id,
                current_state=(
                    f"osconfig.googleapis.com is disabled while {len(running)} "
                    f"VM(s) are running — no patch visibility"
                ),
                recommended_state="Enable the OS Config API and roll out VM Manager",
                fix_command=self.build_fix_command(project_id=project_id),
                references=self.references,
            ))
        except Exception as e:
            logger.error("PATCH-001 failed: %s", e)
        return findings


class VMOSConfigAgentNotEnabled(BaseCheck):
    """PATCH-002: VM not covered by `enable-osconfig=TRUE` metadata."""

    id = "PATCH-002"
    title = "VM does not have the OS Config agent enabled"
    description = (
        "VMs without enable-osconfig=TRUE (instance metadata or project-wide "
        "metadata) are invisible to VM Manager: no OS inventory, no "
        "vulnerability reports, no patch jobs."
    )
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "Patch Management"
    service_category = ServiceCategory.PATCH_MANAGEMENT
    gcloud_command = "gcloud compute instances list --project={project_id} --format=json"
    fix_command_template = (
        "gcloud compute instances add-metadata {name} --metadata=enable-osconfig=TRUE "
        "--zone={zone} --project={project_id}"
    )
    references: ClassVar[list[str]] = [
        "https://cloud.google.com/compute/docs/manage-os",
        "https://cloud.google.com/compute/docs/vm-manager",
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {ISO_27001: ["A.8.8", "A.8.9"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            # Project-level `enable-osconfig=TRUE` covers every VM that does not
            # explicitly override it, so it must be resolved first — flagging
            # per-VM only would false-positive on correctly configured fleets.
            project_enabled = _is_true(
                await _project_osconfig_metadata(project_id, gcloud_runner)
            )

            for instance in await _running_instances(project_id, gcloud_runner):
                name = instance.get("name", "")
                zone = _zone_of(instance)
                instance_value = _metadata_value(instance.get("metadata", {}), "enable-osconfig")
                # Instance metadata overrides project metadata; absence falls back.
                enabled = _is_true(instance_value) if instance_value is not None else project_enabled
                if enabled:
                    continue
                if instance_value is None:
                    current = "enable-osconfig not set at instance or project level"
                else:
                    current = f"enable-osconfig={instance_value} on instance metadata"
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"instances/{name}", project_id=project_id,
                    resource_link=self.console_link("gce_instance", project_id, name=name, zone=zone),
                    current_state=current,
                    recommended_state=(
                        "Set enable-osconfig=TRUE (project-wide metadata covers the whole fleet)"
                    ),
                    fix_command=self.build_fix_command(name=name, zone=zone, project_id=project_id),
                    references=self.references,
                ))
        except Exception as e:
            logger.error("PATCH-002 failed: %s", e)
        return findings


class NoPatchDeploymentSchedule(BaseCheck):
    """PATCH-003: project has VMs but no OS Config patch deployment at all."""

    id = "PATCH-003"
    title = "No patch deployment schedule configured"
    description = (
        "Without a patch deployment, OS patching relies on someone remembering "
        "to run it by hand — unpatched windows grow until a human intervenes."
    )
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Patch Management"
    service_category = ServiceCategory.PATCH_MANAGEMENT
    gcloud_command = "gcloud compute os-config patch-deployments list --project={project_id} --format=json"
    fix_command_template = (
        "gcloud compute os-config patch-deployments create weekly-patch "
        "--file=patch-deployment.json --project={project_id}"
    )
    references: ClassVar[list[str]] = [
        "https://cloud.google.com/compute/docs/os-patch-management",
        "https://cloud.google.com/compute/docs/os-patch-management/create-patch-job",
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {ISO_27001: ["A.8.8", "A.8.32"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            deployments = await _patch_deployments(project_id, gcloud_runner)
            if deployments is None or deployments:
                # Unknown (couldn't list) or at least one deployment exists.
                return []

            running = await _running_instances(project_id, gcloud_runner)
            if not running:
                return []

            findings.append(CheckResult(
                check_id=self.id, title=self.title, description=self.description,
                severity=self.severity, category=self.category, service=self.service,
                resource_name=f"projects/{project_id}", project_id=project_id,
                current_state=(
                    f"0 patch deployments configured for {len(running)} running VM(s)"
                ),
                recommended_state="Create a recurring OS Config patch deployment",
                fix_command=self.build_fix_command(project_id=project_id),
                references=self.references,
            ))
        except Exception as e:
            logger.error("PATCH-003 failed: %s", e)
        return findings


class VMMissingOSPatches(BaseCheck):
    """PATCH-004: VM Manager vulnerability report shows unpatched HIGH/CRITICAL CVEs."""

    id = "PATCH-004"
    title = "VM has unpatched HIGH/CRITICAL OS vulnerabilities"
    description = (
        "VM Manager's vulnerability report lists CVEs affecting installed OS "
        "packages for which fixes are available but not applied."
    )
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Patch Management"
    service_category = ServiceCategory.PATCH_MANAGEMENT
    gcloud_command = (
        "gcloud compute os-config vulnerability-reports list "
        "--project={project_id} --location={zone} --format=json"
    )
    fix_command_template = (
        "gcloud compute os-config patch-jobs execute "
        "--instance-filter-names=zones/{zone}/instances/{name} --project={project_id}"
    )
    references: ClassVar[list[str]] = [
        "https://cloud.google.com/compute/docs/os-patch-management",
        "https://cloud.google.com/compute/docs/vm-manager",
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {ISO_27001: ["A.8.8", "A.8.7"], CIS_GCP_V3: ["4.12"]}

    # Cap on CVE IDs quoted in the finding text; totals are always stated.
    MAX_LISTED_CVES = 5

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await _instances(project_id, gcloud_runner)
            if not instances:
                return []
            zones = sorted({_zone_of(i) for i in instances if _zone_of(i)})
            # The report name references the numeric instance ID (the API
            # serialises it as a string in instances list output).
            by_id = {str(i.get("id", "")): i for i in instances if i.get("id")}

            for report in await _vulnerability_reports(project_id, gcloud_runner, zones):
                name_parts = str(report.get("name", "")).split("/")
                instance_ref = ""
                report_zone = ""
                if "instances" in name_parts:
                    idx = name_parts.index("instances")
                    if idx + 1 < len(name_parts):
                        instance_ref = name_parts[idx + 1]
                if "locations" in name_parts:
                    idx = name_parts.index("locations")
                    if idx + 1 < len(name_parts):
                        report_zone = name_parts[idx + 1]

                instance = by_id.get(instance_ref)
                display_name = instance.get("name", instance_ref) if instance else instance_ref
                zone = _zone_of(instance) if instance else report_zone

                critical_cves: list[str] = []
                high_cves: list[str] = []
                vulnerabilities = report.get("vulnerabilities", [])
                if not isinstance(vulnerabilities, list):
                    continue
                for vuln in vulnerabilities:
                    if not isinstance(vuln, dict):
                        continue
                    details = vuln.get("details", {})
                    if not isinstance(details, dict):
                        continue
                    cve_severity = str(details.get("severity", "")).upper()
                    cve = str(details.get("cve", "") or "unidentified CVE")
                    if cve_severity == "CRITICAL":
                        critical_cves.append(cve)
                    elif cve_severity == "HIGH":
                        high_cves.append(cve)

                total = len(critical_cves) + len(high_cves)
                if total == 0:
                    continue

                all_cves = critical_cves + high_cves  # CRITICAL first
                listed = all_cves[:self.MAX_LISTED_CVES]
                cve_text = ", ".join(listed)
                if total > len(listed):
                    cve_text += f" and {total - len(listed)} more"

                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=Severity.CRITICAL if critical_cves else Severity.HIGH,
                    category=self.category, service=self.service,
                    resource_name=f"instances/{display_name}", project_id=project_id,
                    resource_link=(
                        self.console_link("gce_instance", project_id, name=display_name, zone=zone)
                        if instance else ""
                    ),
                    current_state=(
                        f"{total} unpatched CVE(s) ({len(critical_cves)} CRITICAL, "
                        f"{len(high_cves)} HIGH): {cve_text}"
                    ),
                    recommended_state="Run a patch job and schedule recurring patch deployments",
                    fix_command=self.build_fix_command(
                        name=display_name, zone=zone, project_id=project_id
                    ),
                    references=self.references,
                    metadata={
                        "cve_total": total,
                        "critical_cves": critical_cves,
                        "high_cves": high_cves,
                    },
                ))
        except Exception as e:
            logger.error("PATCH-004 failed: %s", e)
        return findings


class PatchDeploymentNotRecurring(BaseCheck):
    """PATCH-006: patch deployment exists but only ever ran once."""

    id = "PATCH-006"
    title = "Patch deployment has no recurring schedule"
    description = (
        "A one-time patch deployment patched the fleet once; without a "
        "recurring schedule new vulnerabilities accumulate unpatched."
    )
    severity = Severity.LOW
    category = Category.OPERATIONS
    service = "Patch Management"
    service_category = ServiceCategory.PATCH_MANAGEMENT
    gcloud_command = "gcloud compute os-config patch-deployments list --project={project_id} --format=json"
    fix_command_template = (
        "gcloud compute os-config patch-deployments update {name} "
        "--file=patch-deployment.json --project={project_id}"
    )
    references: ClassVar[list[str]] = [
        "https://cloud.google.com/compute/docs/os-patch-management/schedule-patch-jobs",
        "https://cloud.google.com/compute/docs/os-patch-management",
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {ISO_27001: ["A.8.8", "A.8.32"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            deployments = await _patch_deployments(project_id, gcloud_runner)
            for deployment in deployments or []:
                if deployment.get("recurringSchedule") or not deployment.get("oneTimeSchedule"):
                    continue
                name = str(deployment.get("name", "")).split("/")[-1]
                execute_time = deployment.get("oneTimeSchedule", {}).get("executeTime", "unknown")
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"patchDeployments/{name}", project_id=project_id,
                    current_state=f"One-time schedule only (executed {execute_time})",
                    recommended_state="Configure a recurring schedule (e.g. weekly)",
                    fix_command=self.build_fix_command(name=name, project_id=project_id),
                    references=self.references,
                ))
        except Exception as e:
            logger.error("PATCH-006 failed: %s", e)
        return findings


import sys as _sys

from backend.checks._module_helpers import apply_required_apis_by_id as _apply

_apply(_sys.modules[__name__], {
    # PATCH-001 detects that osconfig.googleapis.com is disabled, so it must
    # NOT require it (it would skip itself into uselessness). It only needs
    # serviceusage to read the enabled-services list and compute to see VMs.
    "PATCH-001": ["serviceusage.googleapis.com", "compute.googleapis.com"],
    # The remaining checks are meaningless while OS Config is off — PATCH-001
    # is the single finding for that state, so these skip instead of cascading.
    "PATCH-002": ["compute.googleapis.com", "osconfig.googleapis.com"],
    "PATCH-003": ["compute.googleapis.com", "osconfig.googleapis.com"],
    "PATCH-004": ["compute.googleapis.com", "osconfig.googleapis.com"],
    "PATCH-006": ["osconfig.googleapis.com"],
})
