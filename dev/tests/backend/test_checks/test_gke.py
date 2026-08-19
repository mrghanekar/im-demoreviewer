"""Tests for GKE check modules (backend/checks/gke/).

Covers all 23 GKE checks (GKE-001 through GKE-023) split across
cluster_checks.py (cluster-level attributes) and node_checks.py
(node-pool and additional cluster-level attributes).

Fixture JSON shapes mirror `gcloud container clusters list --format=json`
output field-for-field (booleans stay real JSON booleans, version strings
stay strings, etc.) since that's exactly what every check here parses.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from backend.checks.gke.cluster_checks import (
    GKEAutopilotRecommendation,
    GKEAutoRepair,
    GKEAutoUpgrade,
    GKEBackupNotEnabled,
    GKEBinaryAuthorization,
    GKEClusterLogging,
    GKEDeprecatedKubernetesVersion,
    GKEIntraNodeVisibility,
    GKELegacyAuth,
    GKENetworkPolicy,
    GKEPrivateCluster,
    GKEShieldedNodes,
    GKEWorkloadIdentity,
)
from backend.checks.gke.node_checks import (
    GKEClusterMonitoring,
    GKECosNodeImage,
    GKEDatabaseEncryption,
    GKEMaintenanceWindow,
    GKEMasterAuthorizedNetworks,
    GKENodeAutoScaling,
    GKEPodSecurityPolicy,
    GKEReleasChannel,
    GKEVerticalPodAutoscaler,
    GKEVPCNative,
)
from backend.core.models import Severity

PROJECT = "test-project"


@pytest.fixture
def runner():
    r = MagicMock()
    r.run = AsyncMock(return_value=[])
    return r


# ---------------------------------------------------------------------------
# cluster_checks.py
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestGKELegacyAuth:

    async def test_flags_legacy_abac_enabled(self, runner):
        runner.run.return_value = [{
            "name": "cluster-1",
            "zone": "us-central1-a",
            "legacyAbac": {"enabled": True},
        }]
        check = GKELegacyAuth()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "GKE-001"
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].resource_name == "clusters/cluster-1"
        runner.run.assert_called_once_with(
            f"gcloud container clusters list --project={PROJECT} --format=json"
        )

    async def test_passes_when_legacy_abac_disabled(self, runner):
        runner.run.return_value = [{
            "name": "cluster-2",
            "zone": "us-central1-a",
            "legacyAbac": {"enabled": False},
        }]
        check = GKELegacyAuth()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0

    async def test_handles_non_list_response(self, runner):
        # Defensive branch: gcloud returned an error dict instead of a list.
        runner.run.return_value = {"error": "PERMISSION_DENIED"}
        check = GKELegacyAuth()
        findings = await check.execute(PROJECT, runner)
        assert findings == []


@pytest.mark.asyncio
class TestGKENetworkPolicy:

    async def test_flags_network_policy_disabled(self, runner):
        runner.run.return_value = [{
            "name": "cluster-1",
            "zone": "us-central1-a",
            "networkPolicy": {"enabled": False},
        }]
        check = GKENetworkPolicy()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "GKE-002"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].resource_name == "clusters/cluster-1"

    async def test_flags_when_network_policy_key_missing(self, runner):
        runner.run.return_value = [{"name": "cluster-2", "zone": "us-central1-a"}]
        check = GKENetworkPolicy()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1

    async def test_passes_network_policy_enabled(self, runner):
        runner.run.return_value = [{
            "name": "cluster-3",
            "zone": "us-central1-a",
            "networkPolicy": {"enabled": True, "provider": "CALICO"},
        }]
        check = GKENetworkPolicy()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


@pytest.mark.asyncio
class TestGKEWorkloadIdentity:

    async def test_flags_workload_identity_not_configured(self, runner):
        runner.run.return_value = [{"name": "cluster-1", "zone": "us-central1-a"}]
        check = GKEWorkloadIdentity()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "GKE-003"
        assert findings[0].resource_name == "clusters/cluster-1"

    async def test_passes_workload_identity_configured(self, runner):
        runner.run.return_value = [{
            "name": "cluster-2",
            "zone": "us-central1-a",
            "workloadIdentityConfig": {"workloadPool": f"{PROJECT}.svc.id.goog"},
        }]
        check = GKEWorkloadIdentity()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


@pytest.mark.asyncio
class TestGKEShieldedNodes:

    async def test_flags_shielded_nodes_disabled(self, runner):
        runner.run.return_value = [{
            "name": "cluster-1",
            "zone": "us-central1-a",
            "shieldedNodes": {"enabled": False},
        }]
        check = GKEShieldedNodes()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "GKE-004"
        assert findings[0].severity == Severity.MEDIUM

    async def test_passes_shielded_nodes_enabled(self, runner):
        runner.run.return_value = [{
            "name": "cluster-2",
            "zone": "us-central1-a",
            "shieldedNodes": {"enabled": True},
        }]
        check = GKEShieldedNodes()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


@pytest.mark.asyncio
class TestGKEPrivateCluster:

    async def test_flags_public_cluster(self, runner):
        runner.run.return_value = [{
            "name": "cluster-1",
            "zone": "us-central1-a",
            "privateClusterConfig": {"enablePrivateNodes": False},
        }]
        check = GKEPrivateCluster()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "GKE-005"
        assert findings[0].severity == Severity.HIGH

    async def test_flags_when_private_cluster_config_missing(self, runner):
        runner.run.return_value = [{"name": "cluster-2", "zone": "us-central1-a"}]
        check = GKEPrivateCluster()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1

    async def test_passes_private_cluster(self, runner):
        runner.run.return_value = [{
            "name": "cluster-3",
            "zone": "us-central1-a",
            "privateClusterConfig": {
                "enablePrivateNodes": True,
                "enablePrivateEndpoint": False,
                "masterIpv4CidrBlock": "172.16.0.0/28",
            },
        }]
        check = GKEPrivateCluster()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


@pytest.mark.asyncio
class TestGKEAutoUpgrade:

    async def test_flags_node_pool_without_auto_upgrade(self, runner):
        runner.run.return_value = [{
            "name": "cluster-1",
            "zone": "us-central1-a",
            "nodePools": [
                {"name": "default-pool", "management": {"autoUpgrade": False, "autoRepair": True}},
            ],
        }]
        check = GKEAutoUpgrade()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "GKE-006"
        assert findings[0].resource_name == "clusters/cluster-1/nodePools/default-pool"

    async def test_passes_all_node_pools_auto_upgrade(self, runner):
        runner.run.return_value = [{
            "name": "cluster-2",
            "zone": "us-central1-a",
            "nodePools": [
                {"name": "default-pool", "management": {"autoUpgrade": True, "autoRepair": True}},
            ],
        }]
        check = GKEAutoUpgrade()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0

    async def test_flags_one_of_multiple_node_pools(self, runner):
        runner.run.return_value = [{
            "name": "cluster-3",
            "zone": "us-central1-a",
            "nodePools": [
                {"name": "pool-a", "management": {"autoUpgrade": True}},
                {"name": "pool-b", "management": {"autoUpgrade": False}},
            ],
        }]
        check = GKEAutoUpgrade()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].resource_name == "clusters/cluster-3/nodePools/pool-b"


@pytest.mark.asyncio
class TestGKEAutoRepair:

    async def test_flags_node_pool_without_auto_repair(self, runner):
        runner.run.return_value = [{
            "name": "cluster-1",
            "zone": "us-central1-a",
            "nodePools": [
                {"name": "default-pool", "management": {"autoUpgrade": True, "autoRepair": False}},
            ],
        }]
        check = GKEAutoRepair()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "GKE-007"
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].resource_name == "clusters/cluster-1/nodePools/default-pool"

    async def test_passes_node_pool_with_auto_repair(self, runner):
        runner.run.return_value = [{
            "name": "cluster-2",
            "zone": "us-central1-a",
            "nodePools": [
                {"name": "default-pool", "management": {"autoUpgrade": True, "autoRepair": True}},
            ],
        }]
        check = GKEAutoRepair()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


@pytest.mark.asyncio
class TestGKEBinaryAuthorization:

    async def test_flags_binary_authorization_disabled(self, runner):
        runner.run.return_value = [{
            "name": "cluster-1",
            "zone": "us-central1-a",
            "binaryAuthorization": {"enabled": False},
        }]
        check = GKEBinaryAuthorization()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "GKE-008"

    async def test_passes_binary_authorization_enabled(self, runner):
        runner.run.return_value = [{
            "name": "cluster-2",
            "zone": "us-central1-a",
            "binaryAuthorization": {"enabled": True, "evaluationMode": "PROJECT_SINGLETON_POLICY_ENFORCE"},
        }]
        check = GKEBinaryAuthorization()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


@pytest.mark.asyncio
class TestGKEIntraNodeVisibility:

    async def test_flags_intra_node_visibility_disabled(self, runner):
        runner.run.return_value = [{
            "name": "cluster-1",
            "zone": "us-central1-a",
            "networkConfig": {"enableIntraNodeVisibility": False},
        }]
        check = GKEIntraNodeVisibility()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "GKE-009"
        assert findings[0].severity == Severity.LOW

    async def test_passes_intra_node_visibility_enabled(self, runner):
        runner.run.return_value = [{
            "name": "cluster-2",
            "zone": "us-central1-a",
            "networkConfig": {"enableIntraNodeVisibility": True},
        }]
        check = GKEIntraNodeVisibility()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


@pytest.mark.asyncio
class TestGKEClusterLogging:

    async def test_flags_logging_none(self, runner):
        runner.run.return_value = [{
            "name": "cluster-1",
            "zone": "us-central1-a",
            "loggingService": "none",
        }]
        check = GKEClusterLogging()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "GKE-010"
        assert "none" in findings[0].current_state

    async def test_flags_logging_service_missing(self, runner):
        runner.run.return_value = [{"name": "cluster-2", "zone": "us-central1-a"}]
        check = GKEClusterLogging()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1

    async def test_passes_logging_enabled(self, runner):
        runner.run.return_value = [{
            "name": "cluster-3",
            "zone": "us-central1-a",
            "loggingService": "logging.googleapis.com/kubernetes",
        }]
        check = GKEClusterLogging()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


@pytest.mark.asyncio
class TestGKEDeprecatedKubernetesVersion:

    async def test_flags_deprecated_minor_version(self, runner):
        # currentMasterVersion is a version string, e.g. "1.27.3-gke.100"
        runner.run.return_value = [{
            "name": "cluster-1",
            "currentMasterVersion": "1.27.3-gke.100",
        }]
        check = GKEDeprecatedKubernetesVersion()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "GKE-021"
        assert findings[0].severity == Severity.HIGH
        assert "1.27" in findings[0].current_state

    async def test_passes_supported_minor_version(self, runner):
        runner.run.return_value = [{
            "name": "cluster-2",
            "currentMasterVersion": "1.30.1-gke.50",
        }]
        check = GKEDeprecatedKubernetesVersion()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0

    async def test_passes_when_version_missing(self, runner):
        # No currentMasterVersion -> minor becomes "" which is not in the
        # deprecated set, so this must not be flagged.
        runner.run.return_value = [{"name": "cluster-3"}]
        check = GKEDeprecatedKubernetesVersion()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


@pytest.mark.asyncio
class TestGKEBackupNotEnabled:

    async def test_flags_backup_addon_disabled(self, runner):
        runner.run.return_value = [{
            "name": "cluster-1",
            "addonsConfig": {"gkeBackupAgentConfig": {"enabled": False}},
        }]
        check = GKEBackupNotEnabled()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "GKE-022"
        assert findings[0].severity == Severity.MEDIUM

    async def test_flags_when_addons_config_missing(self, runner):
        runner.run.return_value = [{"name": "cluster-2"}]
        check = GKEBackupNotEnabled()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1

    async def test_passes_backup_addon_enabled(self, runner):
        runner.run.return_value = [{
            "name": "cluster-3",
            "addonsConfig": {"gkeBackupAgentConfig": {"enabled": True}},
        }]
        check = GKEBackupNotEnabled()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


@pytest.mark.asyncio
class TestGKEAutopilotRecommendation:

    async def test_flags_standard_cluster(self, runner):
        runner.run.return_value = [{
            "name": "cluster-1",
            "autopilot": {"enabled": False},
        }]
        check = GKEAutopilotRecommendation()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "GKE-023"
        assert findings[0].severity == Severity.INFO

    async def test_passes_autopilot_cluster(self, runner):
        runner.run.return_value = [{
            "name": "cluster-2",
            "autopilot": {"enabled": True},
        }]
        check = GKEAutopilotRecommendation()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# node_checks.py
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestGKEClusterMonitoring:

    async def test_flags_monitoring_none(self, runner):
        runner.run.return_value = [{
            "name": "cluster-1",
            "zone": "us-central1-a",
            "monitoringService": "none",
        }]
        check = GKEClusterMonitoring()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "GKE-011"
        assert findings[0].severity == Severity.HIGH

    async def test_passes_monitoring_enabled(self, runner):
        runner.run.return_value = [{
            "name": "cluster-2",
            "zone": "us-central1-a",
            "monitoringService": "monitoring.googleapis.com/kubernetes",
        }]
        check = GKEClusterMonitoring()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


@pytest.mark.asyncio
class TestGKENodeAutoScaling:

    async def test_flags_autoscaling_disabled(self, runner):
        runner.run.return_value = [{
            "name": "cluster-1",
            "zone": "us-central1-a",
            "nodePools": [
                {"name": "pool-1", "autoscaling": {"enabled": False}},
            ],
        }]
        check = GKENodeAutoScaling()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "GKE-012"
        assert findings[0].resource_name == "clusters/cluster-1/nodePools/pool-1"

    async def test_flags_when_autoscaling_key_missing(self, runner):
        runner.run.return_value = [{
            "name": "cluster-2",
            "zone": "us-central1-a",
            "nodePools": [{"name": "pool-2"}],
        }]
        check = GKENodeAutoScaling()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1

    async def test_passes_autoscaling_enabled(self, runner):
        # minNodeCount / maxNodeCount come through as real ints from the API.
        runner.run.return_value = [{
            "name": "cluster-3",
            "zone": "us-central1-a",
            "nodePools": [
                {"name": "pool-3", "autoscaling": {"enabled": True, "minNodeCount": 1, "maxNodeCount": 5}},
            ],
        }]
        check = GKENodeAutoScaling()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


@pytest.mark.asyncio
class TestGKECosNodeImage:

    async def test_flags_non_cos_image(self, runner):
        runner.run.return_value = [{
            "name": "cluster-1",
            "zone": "us-central1-a",
            "nodePools": [
                {"name": "pool-1", "config": {"imageType": "UBUNTU_CONTAINERD"}},
            ],
        }]
        check = GKECosNodeImage()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "GKE-013"
        assert "UBUNTU_CONTAINERD" in findings[0].current_state

    async def test_passes_cos_containerd_image(self, runner):
        runner.run.return_value = [{
            "name": "cluster-2",
            "zone": "us-central1-a",
            "nodePools": [
                {"name": "pool-2", "config": {"imageType": "COS_CONTAINERD"}},
            ],
        }]
        check = GKECosNodeImage()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0

    async def test_passes_when_image_type_missing(self, runner):
        # img="" is falsy, so the check's `if img and ...` short-circuits and
        # this node pool is silently skipped rather than flagged. Documenting
        # current (arguably lenient) behaviour, not asserting it's correct.
        runner.run.return_value = [{
            "name": "cluster-3",
            "zone": "us-central1-a",
            "nodePools": [{"name": "pool-3", "config": {}}],
        }]
        check = GKECosNodeImage()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


@pytest.mark.asyncio
class TestGKEMasterAuthorizedNetworks:

    async def test_flags_authorized_networks_disabled(self, runner):
        runner.run.return_value = [{
            "name": "cluster-1",
            "zone": "us-central1-a",
            "masterAuthorizedNetworksConfig": {"enabled": False},
        }]
        check = GKEMasterAuthorizedNetworks()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "GKE-014"
        assert findings[0].severity == Severity.HIGH

    async def test_passes_authorized_networks_configured(self, runner):
        runner.run.return_value = [{
            "name": "cluster-2",
            "zone": "us-central1-a",
            "masterAuthorizedNetworksConfig": {
                "enabled": True,
                "cidrBlocks": [{"cidrBlock": "203.0.113.0/24", "displayName": "office"}],
            },
        }]
        check = GKEMasterAuthorizedNetworks()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


@pytest.mark.asyncio
class TestGKEPodSecurityPolicy:
    """GKE-015 is intentionally informational: every cluster is flagged
    unconditionally so an operator manually verifies PSS at the namespace
    level. There is no "pass" fixture because the check has no negative
    branch by design.
    """

    async def test_flags_every_cluster_informationally(self, runner):
        runner.run.return_value = [{"name": "cluster-1", "zone": "us-central1-a"}]
        check = GKEPodSecurityPolicy()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "GKE-015"
        assert findings[0].severity == Severity.INFO

    async def test_no_clusters_no_findings(self, runner):
        runner.run.return_value = []
        check = GKEPodSecurityPolicy()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


@pytest.mark.asyncio
class TestGKEVPCNative:

    async def test_flags_routes_based_networking(self, runner):
        runner.run.return_value = [{
            "name": "cluster-1",
            "zone": "us-central1-a",
            "ipAllocationPolicy": {"useIpAliases": False},
        }]
        check = GKEVPCNative()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "GKE-016"
        assert findings[0].severity == Severity.MEDIUM

    async def test_passes_vpc_native_cluster(self, runner):
        runner.run.return_value = [{
            "name": "cluster-2",
            "zone": "us-central1-a",
            "ipAllocationPolicy": {
                "useIpAliases": True,
                "clusterIpv4CidrBlock": "10.4.0.0/14",
                "servicesIpv4CidrBlock": "10.8.0.0/20",
            },
        }]
        check = GKEVPCNative()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


@pytest.mark.asyncio
class TestGKEDatabaseEncryption:

    async def test_flags_secrets_encryption_decrypted(self, runner):
        runner.run.return_value = [{
            "name": "cluster-1",
            "zone": "us-central1-a",
            "databaseEncryption": {"state": "DECRYPTED"},
        }]
        check = GKEDatabaseEncryption()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "GKE-017"

    async def test_flags_when_database_encryption_missing(self, runner):
        runner.run.return_value = [{"name": "cluster-2", "zone": "us-central1-a"}]
        check = GKEDatabaseEncryption()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1

    async def test_passes_secrets_encrypted(self, runner):
        runner.run.return_value = [{
            "name": "cluster-3",
            "zone": "us-central1-a",
            "databaseEncryption": {
                "state": "ENCRYPTED",
                "keyName": "projects/p/locations/global/keyRings/r/cryptoKeys/k",
            },
        }]
        check = GKEDatabaseEncryption()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


@pytest.mark.asyncio
class TestGKEReleasChannel:

    async def test_flags_unspecified_channel(self, runner):
        runner.run.return_value = [{
            "name": "cluster-1",
            "zone": "us-central1-a",
            "releaseChannel": {"channel": "UNSPECIFIED"},
        }]
        check = GKEReleasChannel()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "GKE-018"

    async def test_flags_when_release_channel_missing(self, runner):
        runner.run.return_value = [{"name": "cluster-2", "zone": "us-central1-a"}]
        check = GKEReleasChannel()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1

    async def test_passes_regular_channel(self, runner):
        runner.run.return_value = [{
            "name": "cluster-3",
            "zone": "us-central1-a",
            "releaseChannel": {"channel": "REGULAR"},
        }]
        check = GKEReleasChannel()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


@pytest.mark.asyncio
class TestGKEMaintenanceWindow:

    async def test_flags_no_maintenance_window(self, runner):
        runner.run.return_value = [{"name": "cluster-1", "zone": "us-central1-a"}]
        check = GKEMaintenanceWindow()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "GKE-019"
        assert findings[0].severity == Severity.LOW

    async def test_passes_maintenance_window_configured(self, runner):
        runner.run.return_value = [{
            "name": "cluster-2",
            "zone": "us-central1-a",
            "maintenancePolicy": {
                "window": {"dailyMaintenanceWindow": {"startTime": "03:00"}},
            },
        }]
        check = GKEMaintenanceWindow()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


@pytest.mark.asyncio
class TestGKEVerticalPodAutoscaler:

    async def test_flags_vpa_disabled(self, runner):
        runner.run.return_value = [{
            "name": "cluster-1",
            "zone": "us-central1-a",
            "verticalPodAutoscaling": {"enabled": False},
        }]
        check = GKEVerticalPodAutoscaler()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "GKE-020"
        assert findings[0].severity == Severity.LOW

    async def test_passes_vpa_enabled(self, runner):
        runner.run.return_value = [{
            "name": "cluster-2",
            "zone": "us-central1-a",
            "verticalPodAutoscaling": {"enabled": True},
        }]
        check = GKEVerticalPodAutoscaler()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0
