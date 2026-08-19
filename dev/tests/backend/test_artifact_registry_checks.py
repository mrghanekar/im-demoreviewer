"""Tests for the Artifact Registry checks (AR-001 .. AR-006).

Fixtures mirror what gcloud actually emits: repository ``name`` is a full
resource path, ``kmsKeyName`` is present-but-empty, and vulnerability counts
can arrive as strings (the API JSON-encodes int64 as strings elsewhere, and
idealised int fixtures have hidden bugs in this repo before).
"""

from typing import ClassVar
from unittest.mock import AsyncMock, MagicMock

import pytest

from backend.checks.artifact_registry.registry_checks import (
    ImagesWithCriticalVulnerabilities,
    LegacyContainerRegistryInUse,
    RepositoryNoCleanupPolicy,
    RepositoryNoCMEK,
    RepositoryPublicAccess,
    VulnerabilityScanningDisabled,
    _repo_location_and_id,
)
from backend.core.models import Severity

PROJECT = "test-project"


@pytest.fixture
def runner():
    r = MagicMock()
    r.run = AsyncMock(return_value=[])
    return r


def _repo(
    name="projects/p/locations/us-central1/repositories/my-repo",
    fmt="DOCKER",
    mode="STANDARD_REPOSITORY",
    kms="",
    **extra,
):
    """A repository as `gcloud artifacts repositories list --format=json` emits it."""
    repo = {
        "name": name,
        "format": fmt,
        "mode": mode,
        "createTime": "2025-11-02T10:15:22.123456Z",
        "updateTime": "2026-01-15T08:00:01.000000Z",
        "kmsKeyName": kms,
        "cleanupPolicyDryRun": False,
    }
    repo.update(extra)
    return repo


def _routed_runner(routes):
    """Runner whose run() picks the first route whose substring matches."""
    async def fake_run(command, **kwargs):
        for substring, result in routes:
            if substring in command:
                return result
        return []

    r = MagicMock()
    r.run = AsyncMock(side_effect=fake_run)
    return r


class TestRepoNameParsing:
    def test_full_resource_path(self):
        loc, repo_id = _repo_location_and_id(_repo())
        assert (loc, repo_id) == ("us-central1", "my-repo")

    @pytest.mark.parametrize(
        "name",
        ["my-repo", "projects/p/locations/us-central1", "", "a/b/c/d/e"],
    )
    def test_short_or_malformed_name_does_not_raise(self, name):
        assert _repo_location_and_id({"name": name}) == ("", "")

    def test_missing_name_key(self):
        assert _repo_location_and_id({}) == ("", "")


@pytest.mark.asyncio
class TestPublicAccessAR001:
    @pytest.mark.parametrize("member", ["allUsers", "allAuthenticatedUsers"])
    async def test_public_member_flagged(self, member):
        runner = _routed_runner([
            ("repositories list", [_repo()]),
            ("get-iam-policy", {
                "bindings": [{
                    "role": "roles/artifactregistry.reader",
                    "members": [member],
                }],
                "etag": "BwYqXo0Y2ZI=",
                "version": 1,
            }),
        ])
        findings = await RepositoryPublicAccess().execute(PROJECT, runner)
        assert len(findings) == 1
        assert member in findings[0].current_state
        assert findings[0].severity == Severity.CRITICAL
        assert "my-repo" in findings[0].fix_command
        assert "--location=us-central1" in findings[0].fix_command
        # The IAM lookup must be built from the parsed resource path
        iam_calls = [
            c.args[0] for c in runner.run.call_args_list if "get-iam-policy" in c.args[0]
        ]
        assert iam_calls == [
            (
                "gcloud artifacts repositories get-iam-policy my-repo "
                "--location=us-central1 --project=test-project --format=json"
            )
        ]

    async def test_private_policy_passes(self):
        runner = _routed_runner([
            ("repositories list", [_repo()]),
            ("get-iam-policy", {
                "bindings": [{
                    "role": "roles/artifactregistry.reader",
                    "members": ["serviceAccount:ci@test-project.iam.gserviceaccount.com"],
                }],
            }),
        ])
        assert await RepositoryPublicAccess().execute(PROJECT, runner) == []

    async def test_malformed_short_name_skipped_without_raising(self):
        """A repo whose name isn't a full resource path must not crash AR-001."""
        runner = _routed_runner([
            ("repositories list", [{"name": "my-repo", "format": "DOCKER"}]),
            ("get-iam-policy", {"bindings": [{"role": "r", "members": ["allUsers"]}]}),
        ])
        assert await RepositoryPublicAccess().execute(PROJECT, runner) == []
        # No IAM call is attempted for an unparseable name
        assert not any(
            "get-iam-policy" in c.args[0] for c in runner.run.call_args_list
        )

    async def test_non_dict_policy_ignored(self):
        runner = _routed_runner([
            ("repositories list", [_repo()]),
            ("get-iam-policy", "ERROR: not json"),
        ])
        assert await RepositoryPublicAccess().execute(PROJECT, runner) == []

    async def test_list_failure_returns_empty(self, runner):
        runner.run = AsyncMock(side_effect=RuntimeError("PERMISSION_DENIED"))
        assert await RepositoryPublicAccess().execute(PROJECT, runner) == []

    async def test_no_repos(self, runner):
        assert await RepositoryPublicAccess().execute(PROJECT, runner) == []


@pytest.mark.asyncio
class TestScanningDisabledAR002:
    ENABLED_NO_SCANNING: ClassVar[list[dict]] = [
        {
            "config": {"name": "artifactregistry.googleapis.com"},
            "name": "projects/123456789/services/artifactregistry.googleapis.com",
            "state": "ENABLED",
        },
    ]
    ENABLED_WITH_SCANNING: ClassVar[list[dict]] = ENABLED_NO_SCANNING + [
        {
            "config": {"name": "containerscanning.googleapis.com"},
            "name": "projects/123456789/services/containerscanning.googleapis.com",
            "state": "ENABLED",
        },
    ]

    async def test_docker_repos_without_scanning_api_flagged(self):
        runner = _routed_runner([
            ("repositories list", [_repo()]),
            ("services list", self.ENABLED_NO_SCANNING),
        ])
        findings = await VulnerabilityScanningDisabled().execute(PROJECT, runner)
        assert len(findings) == 1
        assert "containerscanning.googleapis.com" in findings[0].fix_command

    async def test_scanning_api_enabled_passes(self):
        runner = _routed_runner([
            ("repositories list", [_repo()]),
            ("services list", self.ENABLED_WITH_SCANNING),
        ])
        assert await VulnerabilityScanningDisabled().execute(PROJECT, runner) == []

    async def test_scanning_api_matched_by_resource_path_only(self):
        """Some gcloud versions omit config; the projects/N/services path counts."""
        runner = _routed_runner([
            ("repositories list", [_repo()]),
            ("services list", [
                {"name": "projects/123456789/services/containerscanning.googleapis.com"},
            ]),
        ])
        assert await VulnerabilityScanningDisabled().execute(PROJECT, runner) == []

    async def test_no_docker_repos_means_no_finding(self):
        runner = _routed_runner([
            ("repositories list", [_repo(
                name="projects/p/locations/us-central1/repositories/py-repo",
                fmt="PYTHON",
            )]),
            ("services list", self.ENABLED_NO_SCANNING),
        ])
        assert await VulnerabilityScanningDisabled().execute(PROJECT, runner) == []

    async def test_malformed_services_response(self):
        runner = _routed_runner([
            ("repositories list", [_repo()]),
            ("services list", {"error": "unexpected"}),
        ])
        assert await VulnerabilityScanningDisabled().execute(PROJECT, runner) == []


@pytest.mark.asyncio
class TestNoCMEKAR003:
    async def test_empty_kms_key_flagged(self, runner):
        runner.run.return_value = [_repo(kms="")]
        findings = await RepositoryNoCMEK().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
        assert "--repository-format=docker" in findings[0].fix_command

    async def test_cmek_repo_passes(self, runner):
        runner.run.return_value = [_repo(
            kms="projects/p/locations/us-central1/keyRings/kr/cryptoKeys/k1",
        )]
        assert await RepositoryNoCMEK().execute(PROJECT, runner) == []

    async def test_empty_and_malformed_responses(self, runner):
        runner.run.return_value = []
        assert await RepositoryNoCMEK().execute(PROJECT, runner) == []
        runner.run.return_value = "not-a-list"
        assert await RepositoryNoCMEK().execute(PROJECT, runner) == []
        runner.run.return_value = ["not-a-dict", 42]
        assert await RepositoryNoCMEK().execute(PROJECT, runner) == []


@pytest.mark.asyncio
class TestNoCleanupPolicyAR004:
    async def test_docker_repo_without_policies_flagged(self, runner):
        runner.run.return_value = [_repo()]
        findings = await RepositoryNoCleanupPolicy().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].category == "cost"
        assert "set-cleanup-policies" in findings[0].fix_command

    async def test_repo_with_policies_passes(self, runner):
        runner.run.return_value = [_repo(cleanupPolicies={
            "delete-old": {
                "id": "delete-old",
                "action": "DELETE",
                "condition": {"olderThan": "2592000s", "tagState": "UNTAGGED"},
            },
        })]
        assert await RepositoryNoCleanupPolicy().execute(PROJECT, runner) == []

    async def test_remote_repository_not_flagged(self, runner):
        runner.run.return_value = [_repo(mode="REMOTE_REPOSITORY")]
        assert await RepositoryNoCleanupPolicy().execute(PROJECT, runner) == []

    async def test_inapplicable_format_not_flagged(self, runner):
        runner.run.return_value = [_repo(fmt="KFP")]
        assert await RepositoryNoCleanupPolicy().execute(PROJECT, runner) == []

    async def test_dry_run_flag_alone_is_not_a_policy(self, runner):
        """cleanupPolicyDryRun says nothing about whether policies exist."""
        runner.run.return_value = [_repo(cleanupPolicyDryRun=True)]
        assert len(await RepositoryNoCleanupPolicy().execute(PROJECT, runner)) == 1


@pytest.mark.asyncio
class TestVulnerableImagesAR005:
    @staticmethod
    def _image(critical=0, high=0, as_strings=False):
        counts = {
            "CRITICAL": str(critical) if as_strings else critical,
            "HIGH": str(high) if as_strings else high,
            "MEDIUM": 12,
            "LOW": 30,
        }
        return {
            "package": "us-central1-docker.pkg.dev/test-project/my-repo/api",
            "version": "sha256:deadbeef",
            "tags": ["latest"],
            "createTime": "2026-01-01T00:00:00Z",
            "updateTime": "2026-01-02T00:00:00Z",
            "vulnerability_counts": counts,
        }

    async def test_critical_vulns_flagged_as_critical(self):
        runner = _routed_runner([
            ("repositories list", [_repo()]),
            ("docker images list", [self._image(critical=2, high=5)]),
        ])
        findings = await ImagesWithCriticalVulnerabilities().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "2 CRITICAL" in findings[0].current_state
        assert "5 HIGH" in findings[0].current_state

    async def test_high_only_flagged_as_high_with_string_counts(self):
        """The API can emit counts as strings; they must still be summed."""
        runner = _routed_runner([
            ("repositories list", [_repo()]),
            ("docker images list", [self._image(critical=0, high=3, as_strings=True)]),
        ])
        findings = await ImagesWithCriticalVulnerabilities().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    async def test_clean_images_pass(self):
        runner = _routed_runner([
            ("repositories list", [_repo()]),
            ("docker images list", [
                self._image(critical=0, high=0),
                {"package": "no-scan-data", "version": "sha256:abc"},
            ]),
        ])
        assert await ImagesWithCriticalVulnerabilities().execute(PROJECT, runner) == []

    async def test_non_docker_repos_not_inspected(self):
        runner = _routed_runner([
            ("repositories list", [_repo(
                name="projects/p/locations/us-central1/repositories/py-repo",
                fmt="PYTHON",
            )]),
            ("docker images list", [self._image(critical=9)]),
        ])
        assert await ImagesWithCriticalVulnerabilities().execute(PROJECT, runner) == []
        assert not any(
            "docker images list" in c.args[0] for c in runner.run.call_args_list
        )

    async def test_more_than_ten_repos_caps_inspection_and_says_so(self):
        repos = [
            _repo(name=f"projects/p/locations/us-central1/repositories/repo-{i:02d}")
            for i in range(12)
        ]
        runner = _routed_runner([
            ("repositories list", repos),
            ("docker images list", [self._image(critical=1)]),
        ])
        findings = await ImagesWithCriticalVulnerabilities().execute(PROJECT, runner)
        image_calls = [
            c.args[0] for c in runner.run.call_args_list
            if "docker images list" in c.args[0]
        ]
        assert len(image_calls) == 10, "must inspect at most 10 repositories"
        assert len(findings) == 10
        assert "first 10 of 12" in findings[0].current_state

    async def test_malformed_images_response(self):
        runner = _routed_runner([
            ("repositories list", [_repo()]),
            ("docker images list", {"error": "boom"}),
        ])
        assert await ImagesWithCriticalVulnerabilities().execute(PROJECT, runner) == []

    async def test_images_call_failure_is_survivable(self):
        async def fake_run(command, **kwargs):
            if "repositories list" in command:
                return [_repo()]
            raise RuntimeError("DEADLINE_EXCEEDED")

        runner = MagicMock()
        runner.run = AsyncMock(side_effect=fake_run)
        assert await ImagesWithCriticalVulnerabilities().execute(PROJECT, runner) == []


@pytest.mark.asyncio
class TestLegacyGCRAR006:
    async def test_gcr_images_flagged(self, runner):
        runner.run.return_value = [
            {"name": "gcr.io/test-project/api-server"},
            {"name": "gcr.io/test-project/worker"},
        ]
        findings = await LegacyContainerRegistryInUse().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "gcr.io/test-project/api-server" in findings[0].current_state

    async def test_no_gcr_images_passes(self, runner):
        runner.run.return_value = []
        assert await LegacyContainerRegistryInUse().execute(PROJECT, runner) == []

    async def test_malformed_response(self, runner):
        runner.run.return_value = {"error": "unexpected"}
        assert await LegacyContainerRegistryInUse().execute(PROJECT, runner) == []

    async def test_list_failure_returns_empty(self, runner):
        runner.run = AsyncMock(side_effect=RuntimeError("PERMISSION_DENIED"))
        assert await LegacyContainerRegistryInUse().execute(PROJECT, runner) == []


class TestModuleMetadata:
    ALL_CHECKS = (
        RepositoryPublicAccess,
        VulnerabilityScanningDisabled,
        RepositoryNoCMEK,
        RepositoryNoCleanupPolicy,
        ImagesWithCriticalVulnerabilities,
        LegacyContainerRegistryInUse,
    )

    def test_required_apis(self):
        for check in self.ALL_CHECKS:
            if check.id == "AR-006":
                assert check.required_apis == ["containerregistry.googleapis.com"]
            else:
                assert check.required_apis == ["artifactregistry.googleapis.com"], check.id

    def test_compliance_refs_use_known_framework_keys(self):
        from backend.core.compliance import FRAMEWORKS

        for check in self.ALL_CHECKS:
            assert check.compliance_refs, f"{check.id} has no compliance_refs"
            for framework in check.compliance_refs:
                assert framework in FRAMEWORKS, f"{check.id}: unknown {framework}"

    def test_ids_and_service_category(self):
        from backend.core.models import ServiceCategory

        ids = [c.id for c in self.ALL_CHECKS]
        assert ids == ["AR-001", "AR-002", "AR-003", "AR-004", "AR-005", "AR-006"]
        for check in self.ALL_CHECKS:
            assert check.service_category == ServiceCategory.ARTIFACT_REGISTRY
