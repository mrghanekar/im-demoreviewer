"""Tests for the PATCH-* (VM Manager / OS Config) checks.

Fixtures use the JSON shapes gcloud actually emits — instance `id` is an
int64 serialised as a *string*, zones are full URLs, service entries carry
both a resource `name` and a `config.name` — because idealised fixtures are
how silent check bugs survive in this codebase.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from backend.checks.patch_management.osconfig_checks import (
    NoPatchDeploymentSchedule,
    OSConfigAPINotEnabled,
    PatchDeploymentNotRecurring,
    VMMissingOSPatches,
    VMOSConfigAgentNotEnabled,
)
from backend.core.compliance import FRAMEWORKS
from backend.core.models import Severity

PROJECT = "test-project"

ZONE_URL = "https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-a"


def _vm(name="vm-1", *, metadata_items=None, status="RUNNING",
        instance_id="4567890123456789", zone_url=ZONE_URL):
    """An instance as `gcloud compute instances list --format=json` emits it."""
    return {
        "id": instance_id,  # int64 arrives as a string
        "name": name,
        "status": status,
        "zone": zone_url,
        "metadata": {"items": metadata_items} if metadata_items is not None else {},
        "disks": [{"boot": True, "source": f"https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-a/disks/{name}"}],
    }


def _service(api_name):
    """One entry from `gcloud services list --enabled --format=json`."""
    return {
        "config": {"name": api_name, "title": api_name},
        "name": f"projects/123456789/services/{api_name}",
        "parent": "projects/123456789",
        "state": "ENABLED",
    }


def _project_info(metadata_items=None):
    """`gcloud compute project-info describe --format=json` output."""
    info = {"name": PROJECT, "commonInstanceMetadata": {"kind": "compute#metadata"}}
    if metadata_items is not None:
        info["commonInstanceMetadata"]["items"] = metadata_items
    return info


def _vuln_report(instance_id="456", zone="us-central1-a", vulnerabilities=None):
    """Vulnerability report as the os-config surface returns it."""
    return {
        "name": f"projects/123/locations/{zone}/instances/{instance_id}/vulnerabilityReport",
        "vulnerabilities": vulnerabilities if vulnerabilities is not None else [],
        "updateTime": "2026-08-18T02:11:00.000Z",
    }


def _vuln(cve="CVE-2024-1234", severity="HIGH", score=8.1):
    return {
        "details": {
            "cve": cve,
            "severity": severity,
            "cvssV3": {"baseScore": score},
        },
        "installedInventoryItemIds": ["openssl-3.0.2-0ubuntu1.10"],
        "updateTime": "2026-08-18T02:11:00.000Z",
    }


RECURRING_DEPLOYMENT = {
    "name": f"projects/{PROJECT}/patchDeployments/weekly-patching",
    "instanceFilter": {"all": True},
    "recurringSchedule": {
        "timeZone": {"id": "UTC"},
        "timeOfDay": {"hours": 3},
        "frequency": "WEEKLY",
        "weekly": {"dayOfWeek": "SUNDAY"},
        "nextExecuteTime": "2026-08-23T03:00:00Z",
    },
    "createTime": "2026-01-05T10:00:00.000Z",
}

ONE_TIME_DEPLOYMENT = {
    "name": f"projects/{PROJECT}/patchDeployments/emergency-openssl",
    "instanceFilter": {"all": True},
    "oneTimeSchedule": {"executeTime": "2026-07-01T03:00:00Z"},
    "createTime": "2026-06-30T22:00:00.000Z",
}


@pytest.fixture
def runner():
    r = MagicMock()
    r.run = AsyncMock(return_value=[])
    return r


def _dispatch_runner(runner, responses):
    """Route runner.run by command substring; first match wins."""
    calls: list[str] = []

    async def fake_run(command, **kwargs):
        calls.append(command)
        for fragment, value in responses.items():
            if fragment in command:
                return value(command) if callable(value) else value
        return []

    runner.run = AsyncMock(side_effect=fake_run)
    return calls


# ---------------------------------------------------------------------------
# PATCH-001 — OS Config API not enabled
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestOSConfigAPINotEnabled:
    async def test_disabled_api_with_running_vms_is_flagged(self, runner):
        _dispatch_runner(runner, {
            "services list --enabled": [_service("compute.googleapis.com")],
            "instances list": [_vm()],
        })
        findings = await OSConfigAPINotEnabled().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "osconfig.googleapis.com" in findings[0].fix_command

    async def test_enabled_api_passes(self, runner):
        _dispatch_runner(runner, {
            "services list --enabled": [
                _service("compute.googleapis.com"),
                _service("osconfig.googleapis.com"),
            ],
            "instances list": [_vm()],
        })
        assert await OSConfigAPINotEnabled().execute(PROJECT, runner) == []

    async def test_no_vms_means_nothing_to_patch(self, runner):
        _dispatch_runner(runner, {
            "services list --enabled": [_service("compute.googleapis.com")],
            "instances list": [],
        })
        assert await OSConfigAPINotEnabled().execute(PROJECT, runner) == []

    async def test_only_terminated_vms_pass(self, runner):
        _dispatch_runner(runner, {
            "services list --enabled": [_service("compute.googleapis.com")],
            "instances list": [_vm(status="TERMINATED")],
        })
        assert await OSConfigAPINotEnabled().execute(PROJECT, runner) == []

    async def test_malformed_services_response_is_survivable(self, runner):
        runner.run = AsyncMock(return_value={"error": {"code": 403}})
        assert await OSConfigAPINotEnabled().execute(PROJECT, runner) == []


def test_patch_001_must_not_require_osconfig_api():
    """PATCH-001 detects that osconfig is off; requiring it would self-skip."""
    assert "osconfig.googleapis.com" not in OSConfigAPINotEnabled.required_apis


# ---------------------------------------------------------------------------
# PATCH-002 — per-VM OS Config agent metadata
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestVMOSConfigAgentNotEnabled:
    async def test_vm_without_metadata_is_flagged(self, runner):
        _dispatch_runner(runner, {
            "project-info describe": _project_info(),
            "instances list": [_vm(metadata_items=[])],
        })
        findings = await VMOSConfigAgentNotEnabled().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].resource_name == "instances/vm-1"
        assert "enable-osconfig=TRUE" in findings[0].fix_command

    async def test_instance_level_true_passes(self, runner):
        # Exact instance shape from the OS Config docs.
        instance = {
            "name": "vm-1",
            "status": "RUNNING",
            "zone": "https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-a",
            "metadata": {"items": [{"key": "enable-osconfig", "value": "TRUE"}]},
            "disks": [{"boot": True}],
        }
        _dispatch_runner(runner, {
            "project-info describe": _project_info(),
            "instances list": [instance],
        })
        assert await VMOSConfigAgentNotEnabled().execute(PROJECT, runner) == []

    async def test_project_level_true_suppresses_all_vms(self, runner):
        """Regression: project-wide enable-osconfig=TRUE covers a whole fleet
        of VMs that do not set the key themselves — a per-VM-only check would
        false-positive on every one of them."""
        _dispatch_runner(runner, {
            "project-info describe": {
                "commonInstanceMetadata": {
                    "items": [{"key": "enable-osconfig", "value": "TRUE"}]
                }
            },
            "instances list": [
                _vm("vm-1", metadata_items=[]),
                _vm("vm-2", metadata_items=[{"key": "foo", "value": "bar"}]),
                _vm("vm-3"),  # no metadata block at all
            ],
        })
        assert await VMOSConfigAgentNotEnabled().execute(PROJECT, runner) == []

    async def test_instance_false_overrides_project_true(self, runner):
        _dispatch_runner(runner, {
            "project-info describe": _project_info(
                [{"key": "enable-osconfig", "value": "TRUE"}]
            ),
            "instances list": [
                _vm("vm-optout", metadata_items=[{"key": "enable-osconfig", "value": "FALSE"}]),
            ],
        })
        findings = await VMOSConfigAgentNotEnabled().execute(PROJECT, runner)
        assert len(findings) == 1
        assert "FALSE" in findings[0].current_state

    async def test_stopped_vms_are_not_flagged(self, runner):
        _dispatch_runner(runner, {
            "project-info describe": _project_info(),
            "instances list": [_vm(status="TERMINATED")],
        })
        assert await VMOSConfigAgentNotEnabled().execute(PROJECT, runner) == []

    async def test_malformed_project_info_still_checks_instances(self, runner):
        _dispatch_runner(runner, {
            "project-info describe": [],  # unexpected shape
            "instances list": [_vm(metadata_items=[])],
        })
        findings = await VMOSConfigAgentNotEnabled().execute(PROJECT, runner)
        assert len(findings) == 1

    async def test_empty_project_passes(self, runner):
        _dispatch_runner(runner, {
            "project-info describe": _project_info(),
            "instances list": [],
        })
        assert await VMOSConfigAgentNotEnabled().execute(PROJECT, runner) == []


# ---------------------------------------------------------------------------
# PATCH-003 — no patch deployment configured
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestNoPatchDeploymentSchedule:
    async def test_no_deployments_with_vms_is_flagged(self, runner):
        _dispatch_runner(runner, {
            "patch-deployments list": [],
            "instances list": [_vm()],
        })
        findings = await NoPatchDeploymentSchedule().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    async def test_existing_deployment_passes(self, runner):
        _dispatch_runner(runner, {
            "patch-deployments list": [RECURRING_DEPLOYMENT],
            "instances list": [_vm()],
        })
        assert await NoPatchDeploymentSchedule().execute(PROJECT, runner) == []

    async def test_no_vms_passes(self, runner):
        _dispatch_runner(runner, {
            "patch-deployments list": [],
            "instances list": [],
        })
        assert await NoPatchDeploymentSchedule().execute(PROJECT, runner) == []

    async def test_listing_failure_produces_no_false_finding(self, runner):
        runner.run = AsyncMock(side_effect=RuntimeError("PERMISSION_DENIED"))
        assert await NoPatchDeploymentSchedule().execute(PROJECT, runner) == []

    async def test_malformed_response_produces_no_false_finding(self, runner):
        _dispatch_runner(runner, {
            "patch-deployments list": {"error": "boom"},
            "instances list": [_vm()],
        })
        assert await NoPatchDeploymentSchedule().execute(PROJECT, runner) == []


# ---------------------------------------------------------------------------
# PATCH-004 — unpatched HIGH/CRITICAL CVEs
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestVMMissingOSPatches:
    async def test_high_cve_is_flagged_with_instance_name(self, runner):
        calls = _dispatch_runner(runner, {
            "vulnerability-reports list": [
                _vuln_report(instance_id="456", vulnerabilities=[_vuln()]),
            ],
            "instances list": [_vm("vm-1", instance_id="456")],
        })
        findings = await VMMissingOSPatches().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].resource_name == "instances/vm-1"
        assert "CVE-2024-1234" in findings[0].current_state
        assert not any("--location=-" in c for c in calls), "wildcard location is invalid"

    async def test_critical_cve_escalates_severity(self, runner):
        _dispatch_runner(runner, {
            "vulnerability-reports list": [
                _vuln_report(instance_id="456", vulnerabilities=[
                    _vuln("CVE-2024-0001", "CRITICAL", 9.8),
                    _vuln("CVE-2024-0002", "HIGH", 8.1),
                ]),
            ],
            "instances list": [_vm(instance_id="456")],
        })
        findings = await VMMissingOSPatches().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    async def test_cve_list_is_capped_but_total_is_stated(self, runner):
        cves = [f"CVE-2024-{n:04d}" for n in range(1, 8)]  # 7 CVEs
        _dispatch_runner(runner, {
            "vulnerability-reports list": [
                _vuln_report(instance_id="456",
                             vulnerabilities=[_vuln(c, "HIGH") for c in cves]),
            ],
            "instances list": [_vm(instance_id="456")],
        })
        findings = await VMMissingOSPatches().execute(PROJECT, runner)
        assert len(findings) == 1
        state = findings[0].current_state
        listed = [c for c in cves if c in state]
        assert len(listed) == 5, "should list at most 5 CVE IDs"
        assert "7 unpatched CVE(s)" in state
        assert "and 2 more" in state
        assert findings[0].metadata["cve_total"] == 7

    async def test_only_low_medium_cves_pass(self, runner):
        _dispatch_runner(runner, {
            "vulnerability-reports list": [
                _vuln_report(instance_id="456", vulnerabilities=[
                    _vuln("CVE-2024-9999", "MEDIUM", 5.0),
                    _vuln("CVE-2024-9998", "LOW", 2.1),
                ]),
            ],
            "instances list": [_vm(instance_id="456")],
        })
        assert await VMMissingOSPatches().execute(PROJECT, runner) == []

    async def test_one_listing_call_per_distinct_zone_in_use(self, runner):
        calls = _dispatch_runner(runner, {
            "vulnerability-reports list": [],
            "instances list": [
                _vm("vm-a", zone_url=".../zones/asia-south1-a"),
                _vm("vm-b", zone_url=".../zones/asia-south1-a"),
                _vm("vm-c", zone_url=".../zones/us-central1-b"),
            ],
        })
        await VMMissingOSPatches().execute(PROJECT, runner)
        report_calls = [c for c in calls if "vulnerability-reports list" in c]
        assert len(report_calls) == 2
        assert any("--location=asia-south1-a" in c for c in report_calls)
        assert any("--location=us-central1-b" in c for c in report_calls)

    async def test_no_instances_makes_no_osconfig_calls(self, runner):
        calls = _dispatch_runner(runner, {"instances list": []})
        assert await VMMissingOSPatches().execute(PROJECT, runner) == []
        assert not any("vulnerability-reports" in c for c in calls)

    async def test_malformed_report_entries_are_survivable(self, runner):
        _dispatch_runner(runner, {
            "vulnerability-reports list": [
                {"name": "no-vulnerabilities-key"},
                {"name": "projects/123/locations/us-central1-a/instances/456/vulnerabilityReport",
                 "vulnerabilities": "not-a-list"},
                {"vulnerabilities": [{"details": None}, "garbage", {}]},
            ],
            "instances list": [_vm(instance_id="456")],
        })
        assert await VMMissingOSPatches().execute(PROJECT, runner) == []

    async def test_zone_listing_failure_skips_zone(self, runner):
        async def fake_run(command, **kwargs):
            if "instances list" in command:
                return [_vm(instance_id="456")]
            raise RuntimeError("PERMISSION_DENIED")

        runner.run = AsyncMock(side_effect=fake_run)
        assert await VMMissingOSPatches().execute(PROJECT, runner) == []


# ---------------------------------------------------------------------------
# PATCH-006 — deployment without recurring schedule
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestPatchDeploymentNotRecurring:
    async def test_one_time_only_deployment_is_flagged(self, runner):
        runner.run.return_value = [ONE_TIME_DEPLOYMENT]
        findings = await PatchDeploymentNotRecurring().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
        assert findings[0].resource_name == "patchDeployments/emergency-openssl"

    async def test_recurring_deployment_passes(self, runner):
        runner.run.return_value = [RECURRING_DEPLOYMENT]
        assert await PatchDeploymentNotRecurring().execute(PROJECT, runner) == []

    async def test_mixed_deployments_flag_only_the_one_time_one(self, runner):
        runner.run.return_value = [RECURRING_DEPLOYMENT, ONE_TIME_DEPLOYMENT]
        findings = await PatchDeploymentNotRecurring().execute(PROJECT, runner)
        assert len(findings) == 1
        assert "emergency-openssl" in findings[0].resource_name

    async def test_empty_and_malformed_responses_pass(self, runner):
        runner.run.return_value = []
        assert await PatchDeploymentNotRecurring().execute(PROJECT, runner) == []
        runner.run.return_value = {"error": "boom"}
        assert await PatchDeploymentNotRecurring().execute(PROJECT, runner) == []

    async def test_listing_failure_is_survivable(self, runner):
        runner.run = AsyncMock(side_effect=RuntimeError("PERMISSION_DENIED"))
        assert await PatchDeploymentNotRecurring().execute(PROJECT, runner) == []


# ---------------------------------------------------------------------------
# Catalog hygiene
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    OSConfigAPINotEnabled,
    VMOSConfigAgentNotEnabled,
    NoPatchDeploymentSchedule,
    VMMissingOSPatches,
    PatchDeploymentNotRecurring,
]


@pytest.mark.parametrize("check_cls", ALL_CHECKS)
def test_catalog_metadata(check_cls):
    check = check_cls()
    assert check.id.startswith("PATCH-")
    assert check.service_category.value == "patch_management"
    assert check.description and check.gcloud_command and check.references
    assert all(url.startswith("https://cloud.google.com/") for url in check.references)
    assert check.compliance_refs, f"{check.id} has no compliance refs"
    for framework in check.compliance_refs:
        assert framework in FRAMEWORKS, f"unknown framework key {framework}"


@pytest.mark.parametrize("check_cls", ALL_CHECKS)
def test_required_apis_are_set(check_cls):
    assert check_cls.required_apis, f"{check_cls.id} must declare required_apis"
