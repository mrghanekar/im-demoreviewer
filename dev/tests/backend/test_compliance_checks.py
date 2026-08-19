"""Tests for the REG-* regulatory checks (CERT-In / DPDP / asset inventory).

Fixtures use the shapes gcloud actually emits for `logging buckets list`,
`asset search-all-resources`, `services list` and `essential-contacts list`.
The boundary cases matter more than the happy path here: REG-001 must NOT
fire at exactly 180 days, and REG-004 must be completely inert until the
operator configures an allowed-regions list.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from backend.checks.compliance.regulatory_checks import (
    AssetInventoryDisabled,
    LogBucketOutsideIndia,
    LogRetentionBelowCertIn,
    LogRetentionNotLocked,
    NoSecurityEssentialContact,
    ResourcesOutsideApprovedRegions,
)
from backend.config import settings
from backend.core.compliance import CONTROL_TITLES, FRAMEWORKS

PROJECT = "test-project"


@pytest.fixture
def runner():
    r = MagicMock()
    r.run = AsyncMock(return_value=[])
    return r


def _bucket(
    name="projects/p/locations/global/buckets/_Default",
    days=30,
    locked=False,
    state="ACTIVE",
):
    """A log bucket as `gcloud logging buckets list --format=json` emits it."""
    return {
        "name": name,
        "retentionDays": days,
        "lifecycleState": state,
        "createTime": "2025-01-01T00:00:00Z",
        "locked": locked,
    }


def _asset(name, asset_type, location):
    """An entry as `gcloud asset search-all-resources --format=json` emits it."""
    return {
        "name": name,
        "assetType": asset_type,
        "location": location,
        "project": "projects/123",
    }


# ---------------------------------------------------------------------------
# REG-001 — retention below the CERT-In 180-day direction
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestREG001RetentionBelow180:
    async def test_default_30_day_bucket_is_flagged(self, runner):
        runner.run.return_value = [_bucket(days=30)]
        findings = await LogRetentionBelowCertIn().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "REG-001"
        assert findings[0].severity == "high"
        # The citation is the deliverable.
        assert "180" in findings[0].current_state
        assert "CERT-In Direction No. 20(3)/2022-CERT-In" in findings[0].current_state

    async def test_exactly_180_days_does_not_fire(self, runner):
        runner.run.return_value = [_bucket(days=180)]
        assert await LogRetentionBelowCertIn().execute(PROJECT, runner) == []

    async def test_179_days_fires(self, runner):
        runner.run.return_value = [_bucket(days=179)]
        assert len(await LogRetentionBelowCertIn().execute(PROJECT, runner)) == 1

    async def test_400_day_bucket_passes(self, runner):
        runner.run.return_value = [
            _bucket(name="projects/p/locations/global/buckets/_Required", days=400, locked=True)
        ]
        assert await LogRetentionBelowCertIn().execute(PROJECT, runner) == []

    async def test_delete_requested_bucket_is_ignored(self, runner):
        runner.run.return_value = [_bucket(days=30, state="DELETE_REQUESTED")]
        assert await LogRetentionBelowCertIn().execute(PROJECT, runner) == []

    async def test_fix_command_targets_the_bucket_and_location(self, runner):
        runner.run.return_value = [
            _bucket(name="projects/p/locations/asia-south1/buckets/audit", days=90)
        ]
        findings = await LogRetentionBelowCertIn().execute(PROJECT, runner)
        assert "audit" in findings[0].fix_command
        assert "--location=asia-south1" in findings[0].fix_command
        assert "--retention-days=180" in findings[0].fix_command

    async def test_empty_list_and_malformed_responses(self, runner):
        runner.run.return_value = []
        assert await LogRetentionBelowCertIn().execute(PROJECT, runner) == []
        runner.run.return_value = {"error": "unexpected"}
        assert await LogRetentionBelowCertIn().execute(PROJECT, runner) == []
        runner.run.return_value = ["not-a-dict", None]
        assert await LogRetentionBelowCertIn().execute(PROJECT, runner) == []

    async def test_runner_error_is_survivable(self, runner):
        runner.run = AsyncMock(side_effect=RuntimeError("PERMISSION_DENIED"))
        assert await LogRetentionBelowCertIn().execute(PROJECT, runner) == []

    async def test_falls_back_to_global_location_listing(self, runner):
        """If the all-locations call fails, --location=global is tried."""
        calls = []

        async def fake_run(command, **kwargs):
            calls.append(command)
            if "--location=global" in command:
                return [_bucket(days=30)]
            raise RuntimeError("INVALID_ARGUMENT")

        runner.run = AsyncMock(side_effect=fake_run)
        findings = await LogRetentionBelowCertIn().execute(PROJECT, runner)
        assert len(findings) == 1
        assert not any("--location=-" in c for c in calls)


# ---------------------------------------------------------------------------
# REG-002 — retention meets 180 days but is not locked
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestREG002RetentionNotLocked:
    async def test_compliant_retention_unlocked_is_flagged(self, runner):
        runner.run.return_value = [_bucket(days=365, locked=False)]
        findings = await LogRetentionNotLocked().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "REG-002"

    async def test_exactly_180_days_unlocked_is_flagged(self, runner):
        runner.run.return_value = [_bucket(days=180, locked=False)]
        assert len(await LogRetentionNotLocked().execute(PROJECT, runner)) == 1

    async def test_locked_bucket_passes(self, runner):
        runner.run.return_value = [_bucket(days=365, locked=True)]
        assert await LogRetentionNotLocked().execute(PROJECT, runner) == []

    async def test_short_retention_bucket_is_reg001_territory(self, runner):
        """A 30-day unlocked bucket is REG-001's finding — no double-report."""
        runner.run.return_value = [_bucket(days=30, locked=False)]
        assert await LogRetentionNotLocked().execute(PROJECT, runner) == []

    async def test_malformed_response_is_survivable(self, runner):
        runner.run.return_value = {"unexpected": True}
        assert await LogRetentionNotLocked().execute(PROJECT, runner) == []


# ---------------------------------------------------------------------------
# REG-003 — built-in log bucket homed outside India
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestREG003LogBucketResidency:
    async def test_default_bucket_in_us_region_is_flagged(self, runner):
        runner.run.return_value = [
            _bucket(name="projects/p/locations/us-central1/buckets/_Default", days=180)
        ]
        findings = await LogBucketOutsideIndia().execute(PROJECT, runner)
        assert len(findings) == 1
        assert "us-central1" in findings[0].current_state
        # Observation, not a legal conclusion.
        assert "review" in findings[0].current_state.lower()

    async def test_required_bucket_in_europe_is_flagged(self, runner):
        runner.run.return_value = [
            _bucket(name="projects/p/locations/europe-west1/buckets/_Required", days=400, locked=True)
        ]
        assert len(await LogBucketOutsideIndia().execute(PROJECT, runner)) == 1

    @pytest.mark.parametrize("location", ["global", "asia-south1", "asia-south2"])
    async def test_acceptable_locations_pass(self, runner, location):
        runner.run.return_value = [
            _bucket(name=f"projects/p/locations/{location}/buckets/_Default", days=180)
        ]
        assert await LogBucketOutsideIndia().execute(PROJECT, runner) == []

    async def test_custom_bucket_outside_india_is_not_assessed(self, runner):
        runner.run.return_value = [
            _bucket(name="projects/p/locations/us-central1/buckets/app-logs", days=180)
        ]
        assert await LogBucketOutsideIndia().execute(PROJECT, runner) == []

    async def test_empty_and_malformed_responses(self, runner):
        runner.run.return_value = []
        assert await LogBucketOutsideIndia().execute(PROJECT, runner) == []
        runner.run.return_value = None
        assert await LogBucketOutsideIndia().execute(PROJECT, runner) == []


# ---------------------------------------------------------------------------
# REG-004 — resources outside the approved data-residency regions
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestREG004DataResidency:
    async def test_inert_when_allowed_regions_not_configured(self, runner, monkeypatch):
        """Empty allow-list (the shipped default) => no findings, no API calls."""
        monkeypatch.setattr(settings, "data_residency_allowed_regions", [])
        runner.run.return_value = [
            _asset(
                "//compute.googleapis.com/projects/p/zones/us-central1-a/instances/vm-1",
                "compute.googleapis.com/Instance",
                "us-central1",
            )
        ]
        assert await ResourcesOutsideApprovedRegions().execute(PROJECT, runner) == []
        runner.run.assert_not_awaited()

    async def test_fires_when_configured_and_resource_is_outside(self, runner, monkeypatch):
        monkeypatch.setattr(
            settings, "data_residency_allowed_regions", ["asia-south1", "asia-south2"]
        )
        runner.run.return_value = [
            _asset(
                "//compute.googleapis.com/projects/p/zones/us-central1-a/instances/vm-1",
                "compute.googleapis.com/Instance",
                "us-central1",
            )
        ]
        findings = await ResourcesOutsideApprovedRegions().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "REG-004"
        assert "us-central1" in findings[0].current_state
        assert "vm-1" in findings[0].current_state

    async def test_resources_in_allowed_regions_pass(self, runner, monkeypatch):
        monkeypatch.setattr(
            settings, "data_residency_allowed_regions", ["asia-south1", "asia-south2"]
        )
        runner.run.return_value = [
            _asset(
                "//sqladmin.googleapis.com/projects/p/instances/db-1",
                "sqladmin.googleapis.com/Instance",
                "asia-south1",
            ),
            # Zone form normalises to its region before comparison.
            _asset(
                "//compute.googleapis.com/projects/p/zones/asia-south2-a/instances/vm-2",
                "compute.googleapis.com/Instance",
                "asia-south2-a",
            ),
            # Global resources have no single homing to assess.
            _asset(
                "//cloudresourcemanager.googleapis.com/projects/p",
                "cloudresourcemanager.googleapis.com/Project",
                "global",
            ),
        ]
        assert await ResourcesOutsideApprovedRegions().execute(PROJECT, runner) == []

    async def test_offenders_are_grouped_per_region(self, runner, monkeypatch):
        monkeypatch.setattr(settings, "data_residency_allowed_regions", ["asia-south1"])
        runner.run.return_value = [
            _asset(
                "//compute.googleapis.com/projects/p/zones/us-central1-a/instances/vm-1",
                "compute.googleapis.com/Instance",
                "us-central1",
            ),
            _asset(
                "//compute.googleapis.com/projects/p/zones/us-central1-b/instances/vm-2",
                "compute.googleapis.com/Instance",
                "us-central1-b",
            ),
        ]
        findings = await ResourcesOutsideApprovedRegions().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].metadata["resource_count"] == 2

    async def test_malformed_response_is_survivable(self, runner, monkeypatch):
        monkeypatch.setattr(settings, "data_residency_allowed_regions", ["asia-south1"])
        runner.run.return_value = {"error": "unexpected"}
        assert await ResourcesOutsideApprovedRegions().execute(PROJECT, runner) == []
        runner.run.return_value = ["not-a-dict"]
        assert await ResourcesOutsideApprovedRegions().execute(PROJECT, runner) == []

    async def test_runner_error_is_survivable(self, runner, monkeypatch):
        monkeypatch.setattr(settings, "data_residency_allowed_regions", ["asia-south1"])
        runner.run = AsyncMock(side_effect=RuntimeError("PERMISSION_DENIED"))
        assert await ResourcesOutsideApprovedRegions().execute(PROJECT, runner) == []


# ---------------------------------------------------------------------------
# REG-005 — Cloud Asset Inventory not enabled
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestREG005AssetInventoryDisabled:
    async def test_fires_when_api_not_enabled(self, runner):
        runner.run.return_value = []  # filter matched no enabled service
        findings = await AssetInventoryDisabled().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "REG-005"
        assert "cloudasset.googleapis.com" in findings[0].fix_command

    async def test_quiet_when_api_enabled(self, runner):
        runner.run.return_value = [{
            "config": {"name": "cloudasset.googleapis.com"},
            "name": "projects/123/services/cloudasset.googleapis.com",
            "state": "ENABLED",
        }]
        assert await AssetInventoryDisabled().execute(PROJECT, runner) == []

    async def test_does_not_gate_itself_on_the_api_it_detects(self):
        """required_apis with cloudasset would make the check skip itself."""
        assert "cloudasset.googleapis.com" not in AssetInventoryDisabled.required_apis

    async def test_malformed_response_does_not_assert_absence(self, runner):
        runner.run.return_value = {"unexpected": True}
        assert await AssetInventoryDisabled().execute(PROJECT, runner) == []

    async def test_runner_error_is_survivable(self, runner):
        runner.run = AsyncMock(side_effect=RuntimeError("PERMISSION_DENIED"))
        assert await AssetInventoryDisabled().execute(PROJECT, runner) == []


# ---------------------------------------------------------------------------
# REG-007 — no SECURITY Essential Contact registered
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestREG007SecurityContact:
    @staticmethod
    def _contact(categories, email="ops@example.in"):
        """A contact as `gcloud alpha essential-contacts list --format=json` emits it."""
        return {
            "name": "projects/p/contacts/12345",
            "email": email,
            "notificationCategorySubscriptions": categories,
            "languageTag": "en-US",
            "validationState": "VALID",
        }

    async def test_no_contacts_at_all_is_flagged(self, runner):
        runner.run.return_value = []
        findings = await NoSecurityEssentialContact().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "REG-007"

    async def test_contacts_without_security_category_are_flagged(self, runner):
        runner.run.return_value = [self._contact(["TECHNICAL", "BILLING"])]
        findings = await NoSecurityEssentialContact().execute(PROJECT, runner)
        assert len(findings) == 1
        assert "SECURITY" in findings[0].current_state

    @pytest.mark.parametrize("categories", [["SECURITY"], ["ALL"], ["TECHNICAL", "SECURITY"]])
    async def test_security_contact_passes(self, runner, categories):
        runner.run.return_value = [self._contact(categories)]
        assert await NoSecurityEssentialContact().execute(PROJECT, runner) == []

    async def test_malformed_response_does_not_assert_absence(self, runner):
        runner.run.return_value = {"unexpected": True}
        assert await NoSecurityEssentialContact().execute(PROJECT, runner) == []

    async def test_runner_error_is_survivable(self, runner):
        runner.run = AsyncMock(side_effect=RuntimeError("PERMISSION_DENIED"))
        assert await NoSecurityEssentialContact().execute(PROJECT, runner) == []


# ---------------------------------------------------------------------------
# Metadata hygiene — refs resolve, commands are shell-feature-free
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    LogRetentionBelowCertIn,
    LogRetentionNotLocked,
    LogBucketOutsideIndia,
    ResourcesOutsideApprovedRegions,
    AssetInventoryDisabled,
    NoSecurityEssentialContact,
]


class TestComplianceMetadata:
    @pytest.mark.parametrize("check_cls", ALL_CHECKS)
    def test_compliance_refs_use_known_frameworks_and_controls(self, check_cls):
        assert check_cls.compliance_refs, f"{check_cls.id} has no compliance_refs"
        for framework, control_ids in check_cls.compliance_refs.items():
            assert framework in FRAMEWORKS
            for control_id in control_ids:
                assert control_id in CONTROL_TITLES.get(framework, {}), (
                    f"{check_cls.id}: {framework} control {control_id} has no title"
                )

    @pytest.mark.parametrize("check_cls", ALL_CHECKS)
    def test_gcloud_commands_have_no_shell_features(self, check_cls):
        """The runner shlex-splits and execs — pipes/substitution would break."""
        for cmd in (check_cls.gcloud_command, check_cls.fix_command_template):
            for feature in ("|", "&&", "$(", "`", ";"):
                assert feature not in cmd, f"{check_cls.id}: shell feature {feature!r} in {cmd!r}"
        assert "--location=-" not in check_cls.gcloud_command

    @pytest.mark.parametrize("check_cls", ALL_CHECKS)
    def test_class_attributes_are_set(self, check_cls):
        assert check_cls.id.startswith("REG-")
        assert check_cls.title and check_cls.description and check_cls.references
        assert check_cls.service_category == "compliance"
