"""Tests for Cloud Run service checks (CR-001..CR-008) and Cloud Run Jobs
checks (CRJ-001..CRJ-003).

Conventions follow test_networking.py / test_gce.py: a MagicMock runner with
``run``/``list`` patched to AsyncMock, one class per check, one fixture that
must produce a finding and one that must not.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from backend.checks.cloudrun.cloudrun_checks import (
    CloudRunDefaultServiceAccount,
    CloudRunIngressAllAllowed,
    CloudRunNoCMEK,
    CloudRunNoMinInstances,
    CloudRunNoVPCConnector,
    CloudRunPlaintextSecrets,
    CloudRunPublicAccess,
    CloudRunUnboundedMaxInstances,
)
from backend.checks.cloudrun_jobs.cloudrun_jobs_checks import (
    CloudRunJobDefaultServiceAccount,
    CloudRunJobNoRetryPolicy,
    CloudRunJobPlaintextSecrets,
)

PROJECT = "test-project"


@pytest.fixture
def runner():
    r = MagicMock()
    r.run = AsyncMock(return_value=[])
    r.list = AsyncMock(return_value=[])
    return r


def _service(name="svc-1", region="us-central1", annotations=None,
             template_annotations=None, containers=None, service_account="",
             ingress=None):
    """Build a Knative-style `gcloud run services list --format=json` entry."""
    meta_annotations = {}
    if ingress is not None:
        meta_annotations["run.googleapis.com/ingress"] = ingress
    return {
        "metadata": {
            "name": name,
            "labels": {"cloud.googleapis.com/location": region},
            "annotations": meta_annotations,
        },
        "spec": {
            "template": {
                "metadata": {
                    "annotations": template_annotations or {},
                },
                "spec": {
                    "serviceAccountName": service_account,
                    "containers": containers or [{"env": []}],
                },
            },
        },
    }


# ---------------------------------------------------------------------------
# CR-001 CloudRunPublicAccess
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCloudRunPublicAccess:

    async def test_flags_allusers_invoker(self, runner):
        svc = _service(name="public-svc")
        policy = {
            "bindings": [
                {"role": "roles/run.invoker", "members": ["allUsers"]},
            ],
            "etag": "BwYqwXTui/8=",
        }
        runner.run.side_effect = [[svc], policy]

        check = CloudRunPublicAccess()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 1
        assert findings[0].check_id == "CR-001"
        assert findings[0].severity == "high"
        assert findings[0].resource_name == "services/public-svc"

    async def test_passes_restricted_invoker(self, runner):
        svc = _service(name="private-svc")
        policy = {
            "bindings": [
                {
                    "role": "roles/run.invoker",
                    "members": ["serviceAccount:caller@test-project.iam.gserviceaccount.com"],
                },
            ],
            "etag": "BwYqwXTui/8=",
        }
        runner.run.side_effect = [[svc], policy]

        check = CloudRunPublicAccess()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CR-002 CloudRunPlaintextSecrets
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCloudRunPlaintextSecrets:

    async def test_flags_plaintext_secret_env(self, runner):
        svc = _service(
            name="secret-svc",
            containers=[{"env": [{"name": "DB_PASSWORD", "value": "hunter2"}]}],
        )
        runner.run.return_value = [svc]

        check = CloudRunPlaintextSecrets()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 1
        assert findings[0].check_id == "CR-002"
        assert findings[0].severity == "high"
        assert findings[0].resource_name == "services/secret-svc"
        assert "DB_PASSWORD" in findings[0].current_state

    async def test_passes_secret_manager_ref(self, runner):
        svc = _service(
            name="safe-svc",
            containers=[{
                "env": [{
                    "name": "DB_PASSWORD",
                    "valueFrom": {"secretKeyRef": {"name": "db-password", "key": "latest"}},
                }],
            }],
        )
        runner.run.return_value = [svc]

        check = CloudRunPlaintextSecrets()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CR-003 CloudRunNoVPCConnector
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCloudRunNoVPCConnector:

    async def test_flags_missing_connector(self, runner):
        svc = _service(name="no-vpc-svc", template_annotations={})
        runner.run.return_value = [svc]

        check = CloudRunNoVPCConnector()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 1
        assert findings[0].check_id == "CR-003"
        assert findings[0].resource_name == "services/no-vpc-svc"

    async def test_passes_with_connector(self, runner):
        svc = _service(
            name="vpc-svc",
            template_annotations={
                "run.googleapis.com/vpc-access-connector": "projects/test-project/locations/us-central1/connectors/my-conn",
            },
        )
        runner.run.return_value = [svc]

        check = CloudRunNoVPCConnector()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CR-004 CloudRunUnboundedMaxInstances
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCloudRunUnboundedMaxInstances:

    async def test_flags_missing_max_scale(self, runner):
        svc = _service(name="unbounded-svc", template_annotations={})
        runner.run.return_value = [svc]

        check = CloudRunUnboundedMaxInstances()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 1
        assert findings[0].check_id == "CR-004"
        assert findings[0].resource_name == "services/unbounded-svc"

    async def test_flags_max_scale_at_default_cap(self, runner):
        # Knative annotations are always strings, even for numeric values —
        # use "1000" (str), not 1000 (int), to match the real gcloud shape.
        svc = _service(
            name="cap-svc",
            template_annotations={"autoscaling.knative.dev/maxScale": "1000"},
        )
        runner.run.return_value = [svc]

        check = CloudRunUnboundedMaxInstances()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 1

    async def test_passes_bounded_max_scale(self, runner):
        svc = _service(
            name="bounded-svc",
            template_annotations={"autoscaling.knative.dev/maxScale": "20"},
        )
        runner.run.return_value = [svc]

        check = CloudRunUnboundedMaxInstances()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CR-005 CloudRunNoMinInstances
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCloudRunNoMinInstances:

    async def test_flags_zero_min_scale(self, runner):
        svc = _service(
            name="cold-svc",
            template_annotations={"autoscaling.knative.dev/minScale": "0"},
        )
        runner.run.return_value = [svc]

        check = CloudRunNoMinInstances()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 1
        assert findings[0].check_id == "CR-005"
        assert findings[0].resource_name == "services/cold-svc"

    async def test_flags_missing_min_scale_defaults_to_zero(self, runner):
        svc = _service(name="cold-svc-2", template_annotations={})
        runner.run.return_value = [svc]

        check = CloudRunNoMinInstances()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 1

    async def test_passes_warm_min_scale(self, runner):
        svc = _service(
            name="warm-svc",
            template_annotations={"autoscaling.knative.dev/minScale": "1"},
        )
        runner.run.return_value = [svc]

        check = CloudRunNoMinInstances()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CR-006 CloudRunDefaultServiceAccount
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCloudRunDefaultServiceAccount:

    async def test_flags_missing_service_account(self, runner):
        svc = _service(name="no-sa-svc", service_account="")
        runner.run.return_value = [svc]

        check = CloudRunDefaultServiceAccount()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 1
        assert findings[0].check_id == "CR-006"
        assert findings[0].resource_name == "services/no-sa-svc"

    async def test_flags_default_compute_service_account(self, runner):
        svc = _service(
            name="default-sa-svc",
            service_account="123456789012-compute@developer.gserviceaccount.com",
        )
        runner.run.return_value = [svc]

        check = CloudRunDefaultServiceAccount()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 1

    async def test_passes_dedicated_service_account(self, runner):
        svc = _service(
            name="dedicated-sa-svc",
            service_account="run-sa@test-project.iam.gserviceaccount.com",
        )
        runner.run.return_value = [svc]

        check = CloudRunDefaultServiceAccount()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CR-007 CloudRunNoCMEK
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCloudRunNoCMEK:

    async def test_flags_google_managed_encryption(self, runner):
        svc = _service(name="gmek-svc", template_annotations={})
        runner.run.return_value = [svc]

        check = CloudRunNoCMEK()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 1
        assert findings[0].check_id == "CR-007"
        assert findings[0].resource_name == "services/gmek-svc"

    async def test_passes_cmek_configured(self, runner):
        svc = _service(
            name="cmek-svc",
            template_annotations={
                "run.googleapis.com/encryption-key": "projects/test-project/locations/us-central1/keyRings/kr/cryptoKeys/k1",
            },
        )
        runner.run.return_value = [svc]

        check = CloudRunNoCMEK()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CR-008 CloudRunIngressAllAllowed
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCloudRunIngressAllAllowed:

    async def test_flags_default_ingress_all(self, runner):
        # No ingress annotation at all — code defaults the .get() to "all".
        svc = _service(name="open-svc")
        runner.run.return_value = [svc]

        check = CloudRunIngressAllAllowed()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 1
        assert findings[0].check_id == "CR-008"
        assert findings[0].severity == "medium"
        assert findings[0].resource_name == "services/open-svc"

    async def test_flags_explicit_ingress_all(self, runner):
        svc = _service(name="open-svc-2", ingress="all")
        runner.run.return_value = [svc]

        check = CloudRunIngressAllAllowed()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 1

    async def test_passes_internal_ingress(self, runner):
        svc = _service(name="internal-svc", ingress="internal")
        runner.run.return_value = [svc]

        check = CloudRunIngressAllAllowed()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 0


# ===========================================================================
# Cloud Run Jobs (CRJ-001..CRJ-003)
# ===========================================================================
#
# `gcloud run jobs list --format=json` returns Knative-style Job resources.
# Real-world confirmed field is `metadata.name` (short job id) for the object
# itself; the top-level `name` field carrying the full
# `projects/.../locations/.../jobs/...` path used for region extraction in
# `_job_region()` is an assumption implied by the check's own parsing code
# (see cloudrun_jobs_checks.py:_job_region) rather than a verified sample —
# flagged here for visibility.

def _job(name="job-1", region="us-central1", service_account="",
         max_retries=3, containers=None):
    return {
        "metadata": {"name": name},
        "name": f"projects/test-project/locations/{region}/jobs/{name}",
        "spec": {
            "template": {  # ExecutionTemplateSpec
                "spec": {  # ExecutionSpec
                    "template": {  # TaskTemplateSpec
                        "spec": {  # TaskSpec
                            "serviceAccountName": service_account,
                            "maxRetries": max_retries,
                            "containers": containers or [{"env": []}],
                        },
                    },
                },
            },
        },
    }


# ---------------------------------------------------------------------------
# CRJ-001 CloudRunJobDefaultServiceAccount
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCloudRunJobDefaultServiceAccount:

    async def test_flags_missing_service_account(self, runner):
        runner.list.return_value = [_job(name="nightly-etl", service_account="")]

        check = CloudRunJobDefaultServiceAccount()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 1
        assert findings[0].check_id == "CRJ-001"
        assert findings[0].severity == "high"
        assert findings[0].resource_name == "jobs/nightly-etl"

    async def test_flags_default_compute_service_account(self, runner):
        runner.list.return_value = [_job(
            name="nightly-etl-2",
            service_account="123456789012-compute@developer.gserviceaccount.com",
        )]

        check = CloudRunJobDefaultServiceAccount()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 1

    async def test_passes_dedicated_service_account(self, runner):
        runner.list.return_value = [_job(
            name="nightly-etl-3",
            service_account="job-runner@test-project.iam.gserviceaccount.com",
        )]

        check = CloudRunJobDefaultServiceAccount()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CRJ-002 CloudRunJobNoRetryPolicy
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCloudRunJobNoRetryPolicy:

    async def test_flags_zero_max_retries(self, runner):
        runner.list.return_value = [_job(name="flaky-job", max_retries=0)]

        check = CloudRunJobNoRetryPolicy()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 1
        assert findings[0].check_id == "CRJ-002"
        assert findings[0].severity == "low"
        assert findings[0].resource_name == "jobs/flaky-job"
        assert "maxRetries=0" in findings[0].current_state

    async def test_passes_nonzero_max_retries(self, runner):
        runner.list.return_value = [_job(name="resilient-job", max_retries=3)]

        check = CloudRunJobNoRetryPolicy()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 0


# ---------------------------------------------------------------------------
# CRJ-003 CloudRunJobPlaintextSecrets
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCloudRunJobPlaintextSecrets:

    async def test_flags_plaintext_secret_env(self, runner):
        job = _job(
            name="secret-job",
            containers=[{"env": [{"name": "API_TOKEN", "value": "abc123"}]}],
        )
        runner.list.return_value = [job]

        check = CloudRunJobPlaintextSecrets()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 1
        assert findings[0].check_id == "CRJ-003"
        assert findings[0].severity == "high"
        assert findings[0].resource_name == "jobs/secret-job"
        assert "API_TOKEN" in findings[0].current_state

    async def test_passes_secret_manager_ref(self, runner):
        job = _job(
            name="safe-job",
            containers=[{
                "env": [{
                    "name": "API_TOKEN",
                    "valueFrom": {"secretKeyRef": {"name": "api-token", "key": "latest"}},
                }],
            }],
        )
        runner.list.return_value = [job]

        check = CloudRunJobPlaintextSecrets()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 0

    async def test_passes_no_secret_looking_env(self, runner):
        job = _job(
            name="benign-job",
            containers=[{"env": [{"name": "LOG_LEVEL", "value": "info"}]}],
        )
        runner.list.return_value = [job]

        check = CloudRunJobPlaintextSecrets()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 0
