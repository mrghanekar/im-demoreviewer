"""Tests for the API & API-key security checks (API-001 .. API-006).

Fixtures mirror the JSON shapes gcloud actually emits (full resource names,
string timestamps, knative envelopes for Cloud Run) — idealised fixtures are
how real-world parsing bugs survive.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from backend.checks.api_security.api_checks import (
    APIGatewayUnauthenticatedConfig,
    APIKeyNoAPITargets,
    APIKeyNotRotated,
    APIKeyWildcardReferrer,
    NoAPIGatewayInFrontOfPublicServices,
    UnrestrictedAPIKey,
)

PROJECT = "test-project"


@pytest.fixture
def runner():
    r = MagicMock()
    r.run = AsyncMock(return_value=[])
    return r


def _key(name="abc", display="Browser key", restrictions=None, create_time="2026-05-01T10:20:30.123456Z"):
    """An API key as `gcloud services api-keys list --format=json` emits it."""
    key = {
        "name": f"projects/123/locations/global/keys/{name}",
        "displayName": display,
        "uid": name,
        "createTime": create_time,
    }
    if restrictions is not None:
        key["restrictions"] = restrictions
    return key


# The shape from the task description, verbatim (restricted browser key).
FULLY_RESTRICTED_KEY = {
    "name": "projects/123/locations/global/keys/abc",
    "displayName": "Browser key",
    "uid": "abc",
    "restrictions": {
        "browserKeyRestrictions": {"allowedReferrers": ["https://app.example.com/*"]},
        "apiTargets": [{"service": "maps.googleapis.com"}],
    },
    "createTime": "2026-05-01T10:20:30.123456Z",
}


# ---------------------------------------------------------------------------
# API-001 — unrestricted key
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestUnrestrictedAPIKey:
    async def test_key_without_restrictions_field_is_flagged(self, runner):
        runner.run.return_value = [_key(name="loose")]
        findings = await UnrestrictedAPIKey().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "API-001"
        assert "apikeys/loose" == findings[0].resource_name
        assert "loose" in findings[0].fix_command

    async def test_key_with_empty_restrictions_is_flagged(self, runner):
        runner.run.return_value = [_key(name="empty", restrictions={})]
        assert len(await UnrestrictedAPIKey().execute(PROJECT, runner)) == 1

    async def test_restricted_key_passes(self, runner):
        runner.run.return_value = [FULLY_RESTRICTED_KEY]
        assert await UnrestrictedAPIKey().execute(PROJECT, runner) == []

    async def test_client_restriction_alone_is_not_api_001(self, runner):
        runner.run.return_value = [_key(
            restrictions={"androidKeyRestrictions": {"allowedApplications": [
                {"sha1Fingerprint": "DA:39:A3:EE", "packageName": "com.example.app"}
            ]}}
        )]
        assert await UnrestrictedAPIKey().execute(PROJECT, runner) == []

    async def test_api_targets_alone_pass(self, runner):
        runner.run.return_value = [_key(
            restrictions={"apiTargets": [{"service": "maps.googleapis.com"}]}
        )]
        assert await UnrestrictedAPIKey().execute(PROJECT, runner) == []

    async def test_empty_and_malformed_responses(self, runner):
        runner.run.return_value = []
        assert await UnrestrictedAPIKey().execute(PROJECT, runner) == []
        runner.run.return_value = {"error": "nope"}  # dict instead of list
        assert await UnrestrictedAPIKey().execute(PROJECT, runner) == []
        runner.run.return_value = ["not-a-dict", 42, None]
        assert await UnrestrictedAPIKey().execute(PROJECT, runner) == []

    async def test_runner_error_returns_empty(self, runner):
        runner.run = AsyncMock(side_effect=RuntimeError("PERMISSION_DENIED"))
        assert await UnrestrictedAPIKey().execute(PROJECT, runner) == []


# ---------------------------------------------------------------------------
# API-002 — no API target restrictions
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestAPIKeyNoAPITargets:
    async def test_client_restriction_without_api_targets_is_flagged(self, runner):
        runner.run.return_value = [_key(
            name="webkey",
            restrictions={"browserKeyRestrictions": {"allowedReferrers": ["https://app.example.com/*"]}},
        )]
        findings = await APIKeyNoAPITargets().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "API-002"

    async def test_empty_api_targets_list_is_flagged(self, runner):
        runner.run.return_value = [_key(
            restrictions={
                "serverKeyRestrictions": {"allowedIps": ["203.0.113.4"]},
                "apiTargets": [],
            },
        )]
        assert len(await APIKeyNoAPITargets().execute(PROJECT, runner)) == 1

    async def test_key_with_api_targets_passes(self, runner):
        runner.run.return_value = [FULLY_RESTRICTED_KEY]
        assert await APIKeyNoAPITargets().execute(PROJECT, runner) == []

    async def test_fully_unrestricted_key_is_left_to_api_001(self, runner):
        runner.run.return_value = [_key(name="loose")]
        assert await APIKeyNoAPITargets().execute(PROJECT, runner) == []

    async def test_malformed_response(self, runner):
        runner.run.return_value = "unexpected string"
        assert await APIKeyNoAPITargets().execute(PROJECT, runner) == []


# ---------------------------------------------------------------------------
# API-003 — wildcard referrer
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestAPIKeyWildcardReferrer:
    async def test_star_referrer_is_flagged(self, runner):
        # Shape from the task description, verbatim.
        runner.run.return_value = [{
            "name": "projects/123/locations/global/keys/abc",
            "displayName": "Browser key",
            "uid": "abc",
            "restrictions": {
                "browserKeyRestrictions": {"allowedReferrers": ["*"]},
                "apiTargets": [{"service": "maps.googleapis.com"}],
            },
            "createTime": "2026-05-01T10:20:30.123456Z",
        }]
        findings = await APIKeyWildcardReferrer().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "API-003"
        assert "*" in findings[0].current_state

    async def test_star_dot_star_referrer_is_flagged(self, runner):
        runner.run.return_value = [_key(
            restrictions={"browserKeyRestrictions": {"allowedReferrers": ["*.*"]}},
        )]
        assert len(await APIKeyWildcardReferrer().execute(PROJECT, runner)) == 1

    async def test_real_referrer_passes(self, runner):
        runner.run.return_value = [FULLY_RESTRICTED_KEY]
        assert await APIKeyWildcardReferrer().execute(PROJECT, runner) == []

    async def test_subdomain_wildcard_is_not_flagged(self, runner):
        # "*.example.com/*" is a legitimate scoped pattern, not allow-anything.
        runner.run.return_value = [_key(
            restrictions={"browserKeyRestrictions": {"allowedReferrers": ["*.example.com/*"]}},
        )]
        assert await APIKeyWildcardReferrer().execute(PROJECT, runner) == []

    async def test_key_without_browser_restriction_passes(self, runner):
        runner.run.return_value = [_key(name="loose"), _key(restrictions={})]
        assert await APIKeyWildcardReferrer().execute(PROJECT, runner) == []


# ---------------------------------------------------------------------------
# API-004 — never rotated
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestAPIKeyNotRotated:
    async def test_old_key_is_flagged(self, runner):
        runner.run.return_value = [_key(name="ancient", create_time="2020-01-15T08:00:00.000000Z")]
        findings = await APIKeyNotRotated().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "API-004"
        assert "days old" in findings[0].current_state

    async def test_recent_key_passes(self, runner):
        from datetime import datetime, timezone

        runner.run.return_value = [_key(
            create_time=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        )]
        assert await APIKeyNotRotated().execute(PROJECT, runner) == []

    async def test_unparseable_create_time_is_skipped_not_raised(self, runner):
        runner.run.return_value = [
            _key(name="bad-ts", create_time="not-a-timestamp"),
            _key(name="int-ts", create_time=1577836800),  # int where API gives string
            _key(name="old", create_time="2019-06-01T00:00:00Z"),
        ]
        findings = await APIKeyNotRotated().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].resource_name == "apikeys/old"

    async def test_missing_create_time_is_skipped(self, runner):
        key = _key(name="no-ts")
        del key["createTime"]
        runner.run.return_value = [key]
        assert await APIKeyNotRotated().execute(PROJECT, runner) == []

    async def test_offset_timestamp_is_parsed(self, runner):
        runner.run.return_value = [_key(create_time="2020-01-01T00:00:00.000+05:30")]
        assert len(await APIKeyNotRotated().execute(PROJECT, runner)) == 1


# ---------------------------------------------------------------------------
# API-005 — gateway without api config
# ---------------------------------------------------------------------------

def _gateway(name="gw-1", state="ACTIVE", api_config="projects/123/locations/global/apis/my-api/configs/cfg-1"):
    """A gateway as `gcloud api-gateway gateways list --format=json` emits it."""
    gw = {
        "name": f"projects/{PROJECT}/locations/us-central1/gateways/{name}",
        "state": state,
        "defaultHostname": f"{name}-abc123.uc.gateway.dev",
        "createTime": "2025-11-02T12:00:00.000000Z",
        "updateTime": "2025-11-02T12:05:00.000000Z",
    }
    if api_config:
        gw["apiConfig"] = api_config
    return gw


@pytest.mark.asyncio
class TestAPIGatewayUnauthenticatedConfig:
    async def test_active_gateway_without_config_is_flagged(self, runner):
        runner.run.return_value = [_gateway(api_config=None)]
        findings = await APIGatewayUnauthenticatedConfig().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "API-005"
        assert findings[0].resource_name == "gateways/gw-1"
        assert "--location=us-central1" in findings[0].fix_command

    async def test_active_gateway_with_config_passes(self, runner):
        runner.run.return_value = [_gateway()]
        assert await APIGatewayUnauthenticatedConfig().execute(PROJECT, runner) == []

    async def test_non_active_gateway_is_ignored(self, runner):
        runner.run.return_value = [
            _gateway(name="gw-new", state="CREATING", api_config=None),
            _gateway(name="gw-dead", state="FAILED", api_config=None),
        ]
        assert await APIGatewayUnauthenticatedConfig().execute(PROJECT, runner) == []

    async def test_empty_and_malformed_responses(self, runner):
        runner.run.return_value = []
        assert await APIGatewayUnauthenticatedConfig().execute(PROJECT, runner) == []
        runner.run.return_value = {"unexpected": True}
        assert await APIGatewayUnauthenticatedConfig().execute(PROJECT, runner) == []
        runner.run.return_value = [None, "junk"]
        assert await APIGatewayUnauthenticatedConfig().execute(PROJECT, runner) == []

    async def test_runner_error_returns_empty(self, runner):
        runner.run = AsyncMock(side_effect=RuntimeError("403"))
        assert await APIGatewayUnauthenticatedConfig().execute(PROJECT, runner) == []


# ---------------------------------------------------------------------------
# API-006 — no API management in front of public services
# ---------------------------------------------------------------------------

def _enabled_service(name):
    """An entry as `gcloud services list --enabled --format=json` emits it."""
    return {
        "config": {"name": name, "title": name},
        "name": f"projects/123456789/services/{name}",
        "parent": "projects/123456789",
        "state": "ENABLED",
    }


def _run_service(name="my-api", ingress="all"):
    """A Cloud Run service in the knative envelope `gcloud run services list` emits."""
    annotations = {"serving.knative.dev/creator": "dev@example.com"}
    if ingress is not None:
        annotations["run.googleapis.com/ingress"] = ingress
        annotations["run.googleapis.com/ingress-status"] = ingress
    return {
        "apiVersion": "serving.knative.dev/v1",
        "kind": "Service",
        "metadata": {"name": name, "namespace": "123456789", "annotations": annotations},
        "status": {"url": f"https://{name}-xyz-uc.a.run.app"},
    }


def _api006_runner(enabled, run_services=None, app=None):
    async def fake_run(command, **kwargs):
        if "services list --enabled" in command:
            return [_enabled_service(s) for s in enabled]
        if "run services list" in command:
            return run_services if run_services is not None else []
        if "app describe" in command:
            if app is None:
                raise RuntimeError("does not contain an App Engine application")
            return app
        return []

    r = MagicMock()
    r.run = AsyncMock(side_effect=fake_run)
    return r


@pytest.mark.asyncio
class TestNoAPIGatewayInFrontOfPublicServices:
    async def test_public_run_service_without_gateway_is_flagged(self):
        runner = _api006_runner(
            enabled=["run.googleapis.com", "compute.googleapis.com"],
            run_services=[_run_service()],
        )
        findings = await NoAPIGatewayInFrontOfPublicServices().execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].check_id == "API-006"
        assert findings[0].severity == "low"
        assert "my-api" in findings[0].current_state

    async def test_missing_ingress_annotation_defaults_to_public(self):
        runner = _api006_runner(
            enabled=["run.googleapis.com"],
            run_services=[_run_service(ingress=None)],
        )
        assert len(await NoAPIGatewayInFrontOfPublicServices().execute(PROJECT, runner)) == 1

    async def test_quiet_when_api_gateway_enabled(self):
        runner = _api006_runner(
            enabled=["run.googleapis.com", "apigateway.googleapis.com"],
            run_services=[_run_service()],
        )
        assert await NoAPIGatewayInFrontOfPublicServices().execute(PROJECT, runner) == []

    async def test_quiet_when_apigee_enabled(self):
        runner = _api006_runner(
            enabled=["run.googleapis.com", "apigee.googleapis.com"],
            run_services=[_run_service()],
        )
        assert await NoAPIGatewayInFrontOfPublicServices().execute(PROJECT, runner) == []

    async def test_internal_ingress_services_do_not_fire(self):
        runner = _api006_runner(
            enabled=["run.googleapis.com"],
            run_services=[
                _run_service(name="internal-svc", ingress="internal"),
                _run_service(name="lb-svc", ingress="internal-and-cloud-load-balancing"),
            ],
        )
        assert await NoAPIGatewayInFrontOfPublicServices().execute(PROJECT, runner) == []

    async def test_serving_app_engine_without_iap_fires(self):
        runner = _api006_runner(
            enabled=["appengine.googleapis.com"],
            app={"id": PROJECT, "servingStatus": "SERVING", "locationId": "asia-south1"},
        )
        findings = await NoAPIGatewayInFrontOfPublicServices().execute(PROJECT, runner)
        assert len(findings) == 1
        assert f"appengine/{PROJECT}" in findings[0].current_state

    async def test_iap_protected_app_engine_does_not_fire(self):
        runner = _api006_runner(
            enabled=["appengine.googleapis.com"],
            app={
                "id": PROJECT,
                "servingStatus": "SERVING",
                "iap": {"enabled": True, "oauth2ClientId": "x"},
            },
        )
        assert await NoAPIGatewayInFrontOfPublicServices().execute(PROJECT, runner) == []

    async def test_no_public_services_no_finding(self):
        runner = _api006_runner(enabled=["compute.googleapis.com"])
        assert await NoAPIGatewayInFrontOfPublicServices().execute(PROJECT, runner) == []

    async def test_empty_enabled_services_response_is_quiet(self):
        runner = _api006_runner(enabled=[])
        assert await NoAPIGatewayInFrontOfPublicServices().execute(PROJECT, runner) == []

    async def test_malformed_responses_are_survivable(self):
        async def fake_run(command, **kwargs):
            if "services list --enabled" in command:
                return [{"config": {"name": "run.googleapis.com"}}, "junk", None]
            if "run services list" in command:
                return {"not": "a list"}
            return []

        runner = MagicMock()
        runner.run = AsyncMock(side_effect=fake_run)
        assert await NoAPIGatewayInFrontOfPublicServices().execute(PROJECT, runner) == []

    async def test_runner_error_returns_empty(self):
        runner = MagicMock()
        runner.run = AsyncMock(side_effect=RuntimeError("PERMISSION_DENIED"))
        assert await NoAPIGatewayInFrontOfPublicServices().execute(PROJECT, runner) == []


# ---------------------------------------------------------------------------
# Catalog / metadata sanity
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    UnrestrictedAPIKey,
    APIKeyNoAPITargets,
    APIKeyWildcardReferrer,
    APIKeyNotRotated,
    APIGatewayUnauthenticatedConfig,
    NoAPIGatewayInFrontOfPublicServices,
]


class TestCatalogMetadata:
    def test_ids_and_service_category(self):
        from backend.core.models import ServiceCategory

        ids = [c.id for c in ALL_CHECKS]
        assert ids == ["API-001", "API-002", "API-003", "API-004", "API-005", "API-006"]
        for c in ALL_CHECKS:
            assert c.service_category == ServiceCategory.API_SECURITY

    def test_compliance_refs_use_known_frameworks(self):
        from backend.core.compliance import FRAMEWORKS

        for c in ALL_CHECKS:
            assert c.compliance_refs, f"{c.id} has no compliance_refs"
            for framework in c.compliance_refs:
                assert framework in FRAMEWORKS, f"{c.id} references unknown framework {framework}"

    def test_required_apis(self):
        for c in ALL_CHECKS[:4]:
            assert c.required_apis == ["apikeys.googleapis.com"], c.id
        assert APIGatewayUnauthenticatedConfig.required_apis == ["apigateway.googleapis.com"]
        # API-006 must run precisely when the gateway APIs are disabled.
        assert NoAPIGatewayInFrontOfPublicServices.required_apis == []

    def test_commands_are_shlex_safe(self):
        """The runner exec's after shlex.split — no shell metacharacters allowed."""
        import shlex

        for c in ALL_CHECKS:
            cmd = c.gcloud_command.format(project_id=PROJECT)
            parts = shlex.split(cmd)
            assert parts[0] == "gcloud"
            assert "--format=json" in parts
            for token in parts:
                for banned in ("|", "&&", ";", "$("):
                    assert banned not in token, f"{c.id} command contains {banned!r}"
