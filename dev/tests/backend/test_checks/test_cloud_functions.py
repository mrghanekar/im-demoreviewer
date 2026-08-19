"""Tests for Cloud Functions (Gen2) checks (FN-001..FN-006)."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from backend.checks.functions.functions_checks import (
    FunctionsDefaultServiceAccount,
    FunctionsDeprecatedRuntime,
    FunctionsNoVPCConnector,
    FunctionsPlaintextSecrets,
    FunctionsPublicAccess,
    FunctionsUnboundedMaxInstances,
)

PROJECT = "test-project"


@pytest.fixture
def runner():
    r = MagicMock()
    r.run = AsyncMock(return_value=[])
    r.list = AsyncMock(return_value=[])
    return r


def _function(name="my-func", region="us-central1", build_config=None,
              service_config=None, runtime_top_level=None):
    """Build a `gcloud functions list --format=json` (Gen2) style entry.

    The real resource name is the full path
    projects/{p}/locations/{r}/functions/{name}; `_fn_name`/`_fn_region`
    both split on that.
    """
    fn = {
        "name": f"projects/{PROJECT}/locations/{region}/functions/{name}",
        "buildConfig": build_config or {},
        "serviceConfig": service_config or {},
    }
    if runtime_top_level is not None:
        fn["runtime"] = runtime_top_level
    return fn


# ---------------------------------------------------------------------------
# FN-001 FunctionsPublicAccess
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestFunctionsPublicAccess:

    async def test_flags_allusers_run_invoker(self, runner):
        # Gen2 functions are backed by Cloud Run, so the invoker role is
        # roles/run.invoker (not roles/cloudfunctions.invoker).
        fn = _function(name="public-func")
        policy = {
            "bindings": [
                {"role": "roles/run.invoker", "members": ["allUsers"]},
            ],
        }
        runner.run.side_effect = [[fn], policy]

        check = FunctionsPublicAccess()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 1
        assert findings[0].check_id == "FN-001"
        assert findings[0].severity == "high"
        assert findings[0].resource_name == "functions/public-func"

    async def test_flags_allusers_gen1_cloudfunctions_invoker(self, runner):
        # Gen1-style role name should also match via the "invoker" substring check.
        fn = _function(name="public-func-gen1")
        policy = {
            "bindings": [
                {"role": "roles/cloudfunctions.invoker", "members": ["allUsers"]},
            ],
        }
        runner.run.side_effect = [[fn], policy]

        check = FunctionsPublicAccess()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 1

    async def test_passes_restricted_invoker(self, runner):
        fn = _function(name="private-func")
        policy = {
            "bindings": [
                {
                    "role": "roles/run.invoker",
                    "members": ["serviceAccount:caller@test-project.iam.gserviceaccount.com"],
                },
            ],
        }
        runner.run.side_effect = [[fn], policy]

        check = FunctionsPublicAccess()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 0


# ---------------------------------------------------------------------------
# FN-002 FunctionsPlaintextSecrets
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestFunctionsPlaintextSecrets:

    async def test_flags_plaintext_secret_in_service_config(self, runner):
        fn = _function(
            name="secret-func",
            service_config={"environmentVariables": {"API_KEY": "abcd1234"}},
        )
        runner.run.return_value = [fn]

        check = FunctionsPlaintextSecrets()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 1
        assert findings[0].check_id == "FN-002"
        assert findings[0].severity == "high"
        assert findings[0].resource_name == "functions/secret-func"
        assert "API_KEY" in findings[0].current_state

    async def test_passes_no_secret_looking_env(self, runner):
        fn = _function(
            name="benign-func",
            service_config={"environmentVariables": {"LOG_LEVEL": "debug"}},
        )
        runner.run.return_value = [fn]

        check = FunctionsPlaintextSecrets()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 0

    async def test_inspects_runtime_vars_even_when_build_vars_exist(self, runner):
        """Build-time vars must not mask the runtime ones.

        Buildpacks set GOOGLE_FUNCTION_TARGET on almost every function, so
        selecting one map over the other meant runtime secrets — the common
        case — were never looked at.
        """
        fn = _function(
            name="masked-secret-func",
            build_config={"environmentVariables": {"GOOGLE_FUNCTION_TARGET": "handler"}},
            service_config={"environmentVariables": {"DB_PASSWORD": "hunter2"}},
        )
        runner.run.return_value = [fn]

        check = FunctionsPlaintextSecrets()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 1
        assert "DB_PASSWORD" in findings[0].current_state


# ---------------------------------------------------------------------------
# FN-003 FunctionsDeprecatedRuntime
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestFunctionsDeprecatedRuntime:

    async def test_flags_deprecated_runtime(self, runner):
        fn = _function(name="old-func", build_config={"runtime": "python38"})
        runner.run.return_value = [fn]

        check = FunctionsDeprecatedRuntime()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 1
        assert findings[0].check_id == "FN-003"
        assert findings[0].severity == "high"
        assert findings[0].resource_name == "functions/old-func"
        assert "python38" in findings[0].current_state

    async def test_flags_deprecated_runtime_top_level_fallback(self, runner):
        # Gen1-style functions may carry `runtime` at the top level rather
        # than nested under buildConfig.
        fn = _function(name="old-gen1-func", runtime_top_level="nodejs10")
        runner.run.return_value = [fn]

        check = FunctionsDeprecatedRuntime()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 1

    async def test_passes_supported_runtime(self, runner):
        fn = _function(name="current-func", build_config={"runtime": "python312"})
        runner.run.return_value = [fn]

        check = FunctionsDeprecatedRuntime()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 0


# ---------------------------------------------------------------------------
# FN-004 FunctionsDefaultServiceAccount
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestFunctionsDefaultServiceAccount:

    async def test_flags_missing_service_account(self, runner):
        fn = _function(name="no-sa-func", service_config={})
        runner.run.return_value = [fn]

        check = FunctionsDefaultServiceAccount()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 1
        assert findings[0].check_id == "FN-004"
        assert findings[0].resource_name == "functions/no-sa-func"

    async def test_flags_default_compute_service_account(self, runner):
        fn = _function(
            name="default-sa-func",
            service_config={"serviceAccountEmail": "123456789012-compute@developer.gserviceaccount.com"},
        )
        runner.run.return_value = [fn]

        check = FunctionsDefaultServiceAccount()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 1

    async def test_passes_dedicated_service_account(self, runner):
        fn = _function(
            name="dedicated-sa-func",
            service_config={"serviceAccountEmail": "func-sa@test-project.iam.gserviceaccount.com"},
        )
        runner.run.return_value = [fn]

        check = FunctionsDefaultServiceAccount()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 0


# ---------------------------------------------------------------------------
# FN-005 FunctionsNoVPCConnector
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestFunctionsNoVPCConnector:

    async def test_flags_missing_vpc_connector(self, runner):
        fn = _function(name="no-vpc-func", service_config={})
        runner.run.return_value = [fn]

        check = FunctionsNoVPCConnector()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 1
        assert findings[0].check_id == "FN-005"
        assert findings[0].resource_name == "functions/no-vpc-func"

    async def test_passes_with_vpc_connector(self, runner):
        fn = _function(
            name="vpc-func",
            service_config={"vpcConnector": "projects/test-project/locations/us-central1/connectors/my-conn"},
        )
        runner.run.return_value = [fn]

        check = FunctionsNoVPCConnector()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 0


# ---------------------------------------------------------------------------
# FN-006 FunctionsUnboundedMaxInstances
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestFunctionsUnboundedMaxInstances:

    async def test_flags_missing_max_instance_count(self, runner):
        fn = _function(name="unbounded-func", service_config={})
        runner.run.return_value = [fn]

        check = FunctionsUnboundedMaxInstances()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 1
        assert findings[0].check_id == "FN-006"
        assert findings[0].severity == "medium"
        assert findings[0].resource_name == "functions/unbounded-func"

    async def test_flags_zero_max_instance_count(self, runner):
        fn = _function(name="zero-func", service_config={"maxInstanceCount": 0})
        runner.run.return_value = [fn]

        check = FunctionsUnboundedMaxInstances()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 1

    async def test_flags_max_instance_count_at_ceiling(self, runner):
        # maxInstanceCount is int32 in the Cloud Functions v2 API and is
        # rendered as a JSON number (not a string) by gcloud — use a real int.
        fn = _function(name="ceiling-func", service_config={"maxInstanceCount": 3000})
        runner.run.return_value = [fn]

        check = FunctionsUnboundedMaxInstances()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 1

    async def test_passes_bounded_max_instance_count(self, runner):
        fn = _function(name="bounded-func", service_config={"maxInstanceCount": 50})
        runner.run.return_value = [fn]

        check = FunctionsUnboundedMaxInstances()
        findings = await check.execute(PROJECT, runner)

        assert len(findings) == 0
