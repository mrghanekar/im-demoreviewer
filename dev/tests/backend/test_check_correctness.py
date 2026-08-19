"""Regression tests for checks that reported a clean result on real-world data.

Every case here was a *silent* wrong answer: the check ran, raised no error, and
told the operator the environment was fine. Fixtures use the shapes gcloud
actually emits (int64 as strings, `logConfig` present but disabled, port
ranges), because idealised fixtures are how these survived in the first place.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from backend.checks._identity import is_google_managed_agent
from backend.checks.billing.billing_checks import IdleVMs, OldSnapshots
from backend.checks.networking.network_checks import (
    FlowLogsDisabled,
    OpenFirewallRDP,
    OpenFirewallSSH,
    OverlyPermissiveFirewall,
    port_list_covers,
    port_list_is_unrestricted,
)
from backend.checks.security.org_policies import (
    KMSKeyDestructionProtection,
    KMSRotationPeriodLong,
)

PROJECT = "test-project"


@pytest.fixture
def runner():
    r = MagicMock()
    r.run = AsyncMock(return_value=[])
    return r


def _fw_rule(ports, proto="tcp", name="allow-all"):
    """A firewall rule as `gcloud compute firewall-rules list --format=json` emits it."""
    return {
        "name": name,
        "direction": "INGRESS",
        "disabled": False,
        "sourceRanges": ["0.0.0.0/0"],
        "allowed": [{"IPProtocol": proto, "ports": ports}],
    }


class TestPortListParsing:
    @pytest.mark.parametrize(
        "ports,target,expected",
        [
            (["22"], 22, True),
            (["22"], 3389, False),
            (["20-1000"], 22, True),
            (["20-1000"], 3389, False),
            (["1-65535"], 22, True),
            (["1-65535"], 3389, True),
            (["3380-3390"], 3389, True),
            ([], 22, True),  # gcloud omits `ports` when the rule allows all
            (["80", "443", "3000-3300"], 3389, False),
            (["80", "443", "3000-4000"], 3389, True),
            # "22" is a substring of "2200" and of "1-6553**5**" — the old
            # `"22" in ports` test matched neither correctly.
            (["2200"], 22, False),
        ],
    )
    def test_port_list_covers(self, ports, target, expected):
        assert port_list_covers(ports, target) is expected

    @pytest.mark.parametrize(
        "ports,expected",
        [
            ([], True),
            (["1-65535"], True),
            (["0-65535"], True),
            (["20-1000"], False),
            (["22"], False),
            (["80", "1-65535"], True),
        ],
    )
    def test_port_list_is_unrestricted(self, ports, expected):
        assert port_list_is_unrestricted(ports) is expected


@pytest.mark.asyncio
class TestFirewallRangesAreCaught:
    """A rule opening tcp:1-65535 to the world evaded NET-001/002/003."""

    @pytest.mark.parametrize("ports", [["22"], ["20-1000"], ["1-65535"], []])
    async def test_ssh_exposure_flagged(self, runner, ports):
        runner.run.return_value = [_fw_rule(ports)]
        findings = await OpenFirewallSSH().execute(PROJECT, runner)
        assert len(findings) == 1, f"NET-001 missed ports={ports}"

    @pytest.mark.parametrize("ports", [["3389"], ["3000-4000"], ["1-65535"], []])
    async def test_rdp_exposure_flagged(self, runner, ports):
        runner.run.return_value = [_fw_rule(ports)]
        findings = await OpenFirewallRDP().execute(PROJECT, runner)
        assert len(findings) == 1, f"NET-002 missed ports={ports}"

    @pytest.mark.parametrize(
        "ports,proto",
        [
            (["1-65535"], "tcp"),
            (["1-65535"], "udp"),
            ([], "all"),
            ([], "tcp"),
        ],
    )
    async def test_wide_open_rule_flagged(self, runner, ports, proto):
        runner.run.return_value = [_fw_rule(ports, proto=proto)]
        findings = await OverlyPermissiveFirewall().execute(PROJECT, runner)
        assert len(findings) == 1, f"NET-003 missed {proto}:{ports}"

    async def test_udp_all_ports_is_flagged(self, runner):
        """UDP-all from the internet was never reachable by the old condition."""
        runner.run.return_value = [_fw_rule(["1-65535"], proto="udp")]
        assert await OverlyPermissiveFirewall().execute(PROJECT, runner)

    async def test_narrow_rule_still_passes(self, runner):
        runner.run.return_value = [_fw_rule(["443"], name="allow-https")]
        assert await OpenFirewallSSH().execute(PROJECT, runner) == []
        assert await OpenFirewallRDP().execute(PROJECT, runner) == []
        assert await OverlyPermissiveFirewall().execute(PROJECT, runner) == []

    async def test_disabled_and_egress_rules_ignored(self, runner):
        disabled = _fw_rule(["1-65535"])
        disabled["disabled"] = True
        egress = _fw_rule(["1-65535"], name="egress")
        egress["direction"] = "EGRESS"
        runner.run.return_value = [disabled, egress]
        assert await OpenFirewallSSH().execute(PROJECT, runner) == []


@pytest.mark.asyncio
class TestFlowLogsDisabledSubnet:
    async def test_logconfig_present_but_disabled_is_flagged(self, runner):
        """`{"enable": false}` is a truthy dict — the old check called it compliant."""
        runner.run.return_value = [{
            "name": "subnet-a",
            "region": "https://.../regions/asia-south1",
            "logConfig": {"enable": False, "aggregationInterval": "INTERVAL_5_SEC"},
        }]
        findings = await FlowLogsDisabled().execute(PROJECT, runner)
        assert len(findings) == 1

    async def test_logconfig_enabled_passes(self, runner):
        runner.run.return_value = [{
            "name": "subnet-a",
            "region": "https://.../regions/asia-south1",
            "logConfig": {"enable": True, "flowSampling": 0.5},
        }]
        assert await FlowLogsDisabled().execute(PROJECT, runner) == []

    async def test_legacy_enable_flow_logs_field_passes(self, runner):
        runner.run.return_value = [
            {"name": "subnet-a", "region": "r/asia-south1", "enableFlowLogs": True}
        ]
        assert await FlowLogsDisabled().execute(PROJECT, runner) == []

    async def test_no_logconfig_at_all_is_flagged(self, runner):
        runner.run.return_value = [{"name": "subnet-a", "region": "r/asia-south1"}]
        assert len(await FlowLogsDisabled().execute(PROJECT, runner)) == 1


@pytest.mark.asyncio
class TestOldSnapshotSizeParsing:
    async def test_string_storage_bytes_does_not_abort_the_check(self, runner):
        """Compute JSON-encodes int64 as a string; dividing it raised TypeError."""
        runner.run.return_value = [{
            "name": "snap-old",
            "creationTimestamp": "2020-01-01T00:00:00.000-08:00",
            "storageBytes": "10737418240",
        }]
        findings = await OldSnapshots().execute(PROJECT, runner)
        assert len(findings) == 1
        assert "10.0 GB" in findings[0].current_state

    async def test_missing_storage_bytes_still_reports_the_snapshot(self, runner):
        runner.run.return_value = [
            {"name": "snap-old", "creationTimestamp": "2020-01-01T00:00:00.000-08:00"}
        ]
        findings = await OldSnapshots().execute(PROJECT, runner)
        assert len(findings) == 1
        assert "0.0 GB" in findings[0].current_state

    async def test_recent_snapshot_ignored(self, runner):
        from datetime import datetime, timezone

        runner.run.return_value = [{
            "name": "snap-new",
            "creationTimestamp": datetime.now(timezone.utc).isoformat(),
            "storageBytes": "1024",
        }]
        assert await OldSnapshots().execute(PROJECT, runner) == []


@pytest.mark.asyncio
class TestRecommenderLocationFanout:
    """`--location=-` is rejected by the recommender API, so BIL-006/007 never fired."""

    async def test_zones_are_enumerated_instead_of_wildcard(self, runner):
        calls = []

        async def fake_run(command, **kwargs):
            calls.append(command)
            if "instances list" in command:
                return "asia-south1-a\nasia-south1-a\nus-central1-b\n"
            if "recommender recommendations list" in command:
                return [{
                    "name": "rec-1",
                    "description": "This VM has been idle for 14 days",
                    "content": {
                        "operationGroups": [{
                            "operations": [{
                                "resource": "//compute.googleapis.com/projects/p/zones/z/instances/vm-idle"
                            }]
                        }]
                    },
                }]
            return []

        runner.run = AsyncMock(side_effect=fake_run)
        findings = await IdleVMs().execute(PROJECT, runner)

        assert not any("--location=-" in c for c in calls), "wildcard location is invalid"
        rec_calls = [c for c in calls if "recommendations list" in c]
        assert len(rec_calls) == 2, "one call per distinct zone in use"
        assert any("--location=asia-south1-a" in c for c in rec_calls)
        assert any("--location=us-central1-b" in c for c in rec_calls)
        assert len(findings) == 2

    async def test_project_with_no_instances_makes_no_recommender_calls(self, runner):
        async def fake_run(command, **kwargs):
            return "" if "instances list" in command else []

        runner.run = AsyncMock(side_effect=fake_run)
        assert await IdleVMs().execute(PROJECT, runner) == []


@pytest.mark.asyncio
class TestKMSLocationEnumeration:
    """`gcloud kms keyrings list --location=-` errors out; SEC-011/012 were inert."""

    @staticmethod
    def _runner_with_one_key(key):
        async def fake_run(command, **kwargs):
            if "kms locations list" in command:
                return [{"locationId": "asia-south1"}, {"locationId": "global"}]
            if "kms keyrings list" in command:
                if "--location=asia-south1" in command:
                    return [{
                        "name": "projects/p/locations/asia-south1/keyRings/ring-a"
                    }]
                return []
            if "kms keys list" in command:
                return [key]
            return []

        r = MagicMock()
        r.run = AsyncMock(side_effect=fake_run)
        return r

    async def test_destruction_protection_finds_keys(self):
        runner = self._runner_with_one_key({
            "name": "projects/p/locations/asia-south1/keyRings/ring-a/cryptoKeys/k1",
            "purpose": "ENCRYPT_DECRYPT",
            "destroyScheduledDuration": "86400s",
        })
        findings = await KMSKeyDestructionProtection().execute(PROJECT, runner)
        assert len(findings) == 1
        assert not any(
            "--location=-" in c.args[0] for c in runner.run.call_args_list
        )

    async def test_rotation_period_finds_keys(self):
        runner = self._runner_with_one_key({
            "name": "projects/p/locations/asia-south1/keyRings/ring-a/cryptoKeys/k1",
            "purpose": "ENCRYPT_DECRYPT",
            "rotationPeriod": "63072000s",  # 2 years
        })
        findings = await KMSRotationPeriodLong().execute(PROJECT, runner)
        assert len(findings) == 1

    async def test_compliant_key_passes(self):
        runner = self._runner_with_one_key({
            "name": "projects/p/locations/asia-south1/keyRings/ring-a/cryptoKeys/k1",
            "purpose": "ENCRYPT_DECRYPT",
            "rotationPeriod": "7776000s",  # 90 days
            "destroyScheduledDuration": "2592000s",
        })
        assert await KMSRotationPeriodLong().execute(PROJECT, runner) == []
        assert await KMSKeyDestructionProtection().execute(PROJECT, runner) == []

    async def test_locations_call_failure_is_survivable(self, runner):
        runner.run = AsyncMock(side_effect=RuntimeError("PERMISSION_DENIED"))
        assert await KMSRotationPeriodLong().execute(PROJECT, runner) == []


class TestGoogleManagedAgentClassification:
    @pytest.mark.parametrize(
        "member",
        [
            "serviceAccount:service-123456789@gcp-sa-pubsub.iam.gserviceaccount.com",
            "serviceAccount:123456789@cloudservices.gserviceaccount.com",
            "serviceAccount:service-123456789@compute-system.iam.gserviceaccount.com",
            "serviceAccount:service-123456789@container-engine-robot.iam.gserviceaccount.com",
            "service-123456789@serverless-robot-prod.iam.gserviceaccount.com",
        ],
    )
    def test_google_agents_are_skipped(self, member):
        assert is_google_managed_agent(member) is True

    @pytest.mark.parametrize(
        "member",
        [
            # The bug: a substring match on "service-" swallowed these.
            "serviceAccount:payment-service-prod@acme.iam.gserviceaccount.com",
            "serviceAccount:service-account-admin@acme.iam.gserviceaccount.com",
            "serviceAccount:my-service-01@acme.iam.gserviceaccount.com",
            # Default SAs are customer-controlled and stay in scope.
            "serviceAccount:123456789-compute@developer.gserviceaccount.com",
            "serviceAccount:acme@appspot.gserviceaccount.com",
            "user:alice@example.com",
            "group:admins@example.com",
            "allUsers",
        ],
    )
    def test_customer_principals_stay_in_scope(self, member):
        assert is_google_managed_agent(member) is False


@pytest.mark.asyncio
class TestPrimitiveRolesSkipLogic:
    async def test_user_sa_named_like_an_agent_is_still_flagged(self, runner):
        from backend.checks.iam.role_bindings import PrimitiveRolesInUse

        runner.run.return_value = {
            "bindings": [{
                "role": "roles/owner",
                "members": [
                    "serviceAccount:payment-service-prod@acme.iam.gserviceaccount.com",
                    "serviceAccount:service-123456789@gcp-sa-pubsub.iam.gserviceaccount.com",
                ],
            }]
        }
        findings = await PrimitiveRolesInUse().execute(PROJECT, runner)
        assert len(findings) == 1
        assert "payment-service-prod" in findings[0].resource_name
