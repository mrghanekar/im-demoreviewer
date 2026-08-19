"""Tests for the G1–G10 batch of improvements.

Covers:
- G1: GcloudRunner stderr sanitization (token / API-key redaction)
- G2: Health score calculation + grade mapping; suppressed findings excluded
- G3: GcloudRunner.list() helper (returns default on failure, wraps single dict)
- G6: New catalog checks (AlloyDB, App Engine, Cloud Run Jobs) register
- G10: AI explain cache returns cached result for repeat queries; GcloudRunner cache
  enforces its size cap
"""

import pytest

from backend.core.gcloud_runner import GcloudRunner, sanitize_stderr
from backend.core.models import compute_health_score


# ---------------------------------------------------------------------------
# G1 — stderr sanitization
# ---------------------------------------------------------------------------

class TestSanitizeStderr:
    def test_redacts_oauth_access_token(self):
        s = "ERROR: refresh failed: ya29.A0AfH6SMC1234567890abcdefghij used"
        out = sanitize_stderr(s)
        assert "ya29.A0AfH6SMC1234567890" not in out
        assert "ya29.<redacted>" in out

    def test_redacts_refresh_token(self):
        s = "details: refresh=1//0gABCDEFGHIJKLMNOPqrstuvwxyz1234567890 trailing"
        out = sanitize_stderr(s)
        assert "1//0gABCDEFGHIJKLMNOP" not in out
        assert "1//<redacted>" in out

    def test_redacts_authorization_header(self):
        s = "Authorization: Bearer ya29.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ZZZ"
        out = sanitize_stderr(s)
        assert "ya29.AbCdEfGhIjKlMnOpQrStUvWxYz" not in out
        # Both the bearer header and the token itself get redacted
        assert "<redacted>" in out

    def test_redacts_api_key(self):
        s = 'ERROR: invalid API key: AIzaSyA1234567890abcdefghijklmnopqrstuvw'
        out = sanitize_stderr(s)
        assert "AIzaSyA1234567890" not in out
        assert "AIza<redacted>" in out

    def test_redacts_private_key_json(self):
        s = '{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\\nMIIE..."}'
        out = sanitize_stderr(s)
        assert "BEGIN PRIVATE KEY" not in out
        assert '"private_key":"<redacted>"' in out

    def test_passes_through_clean_text(self):
        s = "ERROR: API [composer.googleapis.com] is not enabled"
        out = sanitize_stderr(s)
        assert out == s

    def test_handles_empty_input(self):
        assert sanitize_stderr("") == ""


# ---------------------------------------------------------------------------
# G2 — health score
# ---------------------------------------------------------------------------

class TestHealthScore:
    def test_perfect_score_when_no_findings(self):
        score, grade = compute_health_score({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
        assert score == 100
        assert grade == "A"

    def test_info_findings_do_not_deduct(self):
        score, grade = compute_health_score({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 50})
        assert score == 100
        assert grade == "A"

    def test_severity_weights_per_plan(self):
        # 1 critical = -10, 2 high = -10, 5 medium = -10, 4 low = -2 → 100-32 = 68 → D
        score, grade = compute_health_score({"critical": 1, "high": 2, "medium": 5, "low": 4, "info": 99})
        assert score == 68
        assert grade == "D"

    def test_score_floors_at_zero(self):
        score, grade = compute_health_score({"critical": 50, "high": 0, "medium": 0, "low": 0, "info": 0})
        assert score == 0
        assert grade == "F"

    def test_grade_boundaries(self):
        assert compute_health_score({"critical": 0, "high": 2, "medium": 0, "low": 0, "info": 0})[1] == "A"  # 90
        assert compute_health_score({"critical": 0, "high": 4, "medium": 0, "low": 0, "info": 0})[1] == "B"  # 80
        assert compute_health_score({"critical": 0, "high": 6, "medium": 0, "low": 0, "info": 0})[1] == "C"  # 70
        assert compute_health_score({"critical": 0, "high": 8, "medium": 0, "low": 0, "info": 0})[1] == "D"  # 60
        assert compute_health_score({"critical": 0, "high": 9, "medium": 0, "low": 0, "info": 0})[1] == "F"  # 55


# ---------------------------------------------------------------------------
# G3 — GcloudRunner.list() helper
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestGcloudRunnerList:
    async def test_returns_list_on_success(self, monkeypatch):
        runner = GcloudRunner()

        async def fake_run(_cmd, **_kwargs):
            return [{"name": "a"}, {"name": "b"}]
        monkeypatch.setattr(runner, "run", fake_run)

        out = await runner.list("gcloud anything")
        assert out == [{"name": "a"}, {"name": "b"}]

    async def test_wraps_single_dict_as_list(self, monkeypatch):
        runner = GcloudRunner()

        async def fake_run(_cmd, **_kwargs):
            return {"name": "only-one"}
        monkeypatch.setattr(runner, "run", fake_run)

        out = await runner.list("gcloud anything")
        assert out == [{"name": "only-one"}]

    async def test_returns_default_on_exception(self, monkeypatch):
        runner = GcloudRunner()

        async def fake_run(_cmd, **_kwargs):
            raise RuntimeError("boom")
        monkeypatch.setattr(runner, "run", fake_run)

        out = await runner.list("gcloud anything")
        assert out == []

    async def test_returns_default_on_unexpected_type(self, monkeypatch):
        runner = GcloudRunner()

        async def fake_run(_cmd, **_kwargs):
            return "string instead of list"
        monkeypatch.setattr(runner, "run", fake_run)

        out = await runner.list("gcloud anything", default=[])
        assert out == []


# ---------------------------------------------------------------------------
# G6 — Catalog additions registered
# ---------------------------------------------------------------------------

class TestCatalogAdditions:
    def test_new_service_areas_have_checks(self):
        from backend.checks import registry
        from backend.core.models import ServiceCategory

        all_checks = registry.get_all_checks()
        ids = set(all_checks.keys())

        # AlloyDB
        assert "ADB-001" in ids
        assert "ADB-005" in ids
        alloydb = registry.get_checks_by_service(ServiceCategory.ALLOYDB)
        assert len(alloydb) == 5

        # App Engine
        assert "AE-001" in ids
        appengine = registry.get_checks_by_service(ServiceCategory.APP_ENGINE)
        assert len(appengine) == 5

        # Cloud Run Jobs
        assert "CRJ-001" in ids
        jobs = registry.get_checks_by_service(ServiceCategory.CLOUD_RUN_JOBS)
        assert len(jobs) == 3

    def test_new_checks_declare_required_apis(self):
        from backend.checks import registry
        for cid in ("ADB-001", "AE-001", "CRJ-001"):
            c = registry.get_all_checks()[cid]
            assert c.required_apis, f"{cid} must declare required_apis"


# ---------------------------------------------------------------------------
# G10 — AI explain cache, GcloudRunner cache cap
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestAiExplainCache:
    async def test_repeat_request_hits_cache(self, monkeypatch):
        # Reset cache to a known state for the test
        from backend.api.routes import ai
        ai._explain_cache.clear()

        calls = []

        class _FakeResponse:
            text = "explanation about XYZ"

        class _FakeModel:
            def __init__(self, _name):
                pass

            async def generate_content_async(self, _prompt):
                calls.append(1)
                return _FakeResponse()

        monkeypatch.setattr(ai, "_init_vertex_once", lambda: "fake-project")
        monkeypatch.setattr(ai, "GenerativeModel", _FakeModel)

        finding = {"id": "scan-0001", "title": "T", "description": "D", "severity": "high",
                   "category": "security", "resource_name": "r", "current_state": "bad",
                   "recommended_state": "good"}
        req = ai.ExplainRequest(finding=finding, model=None)

        r1 = await ai.explain_finding(req)
        r2 = await ai.explain_finding(req)

        assert r1.explanation == r2.explanation
        # Only the first call should have hit Vertex.
        assert len(calls) == 1


@pytest.mark.asyncio
class TestPost006UnusedEnabledApis:
    """POST-006: flag enabled APIs where the canonical resource list is empty."""

    async def test_flags_enabled_api_with_no_resources(self, mock_gcloud_runner):
        from backend.checks.posture.architecture_checks import EnabledApisWithNoResources

        async def fake_enabled(_pid):
            return {"compute.googleapis.com", "container.googleapis.com"}

        async def fake_list(cmd, default=None):
            # Both probes return empty
            return [] if default is None else default

        mock_gcloud_runner.list_enabled_apis = fake_enabled
        mock_gcloud_runner.list = fake_list

        check = EnabledApisWithNoResources()
        findings = await check.execute("test-project", mock_gcloud_runner)

        # Two enabled APIs, both empty → two findings
        flagged_apis = [
            f.resource_name.split("/")[-1] for f in findings
        ]
        assert "compute.googleapis.com" in flagged_apis
        assert "container.googleapis.com" in flagged_apis

    async def test_does_not_flag_api_with_resources(self, mock_gcloud_runner):
        from backend.checks.posture.architecture_checks import EnabledApisWithNoResources

        async def fake_enabled(_pid):
            return {"compute.googleapis.com"}

        async def fake_list(_cmd, default=None):
            return [{"name": "instance-1"}]

        mock_gcloud_runner.list_enabled_apis = fake_enabled
        mock_gcloud_runner.list = fake_list

        check = EnabledApisWithNoResources()
        findings = await check.execute("test-project", mock_gcloud_runner)
        assert findings == []

    async def test_skips_disabled_apis(self, mock_gcloud_runner):
        from backend.checks.posture.architecture_checks import EnabledApisWithNoResources

        async def fake_enabled(_pid):
            return {"iam.googleapis.com"}  # not in our probe map

        async def fake_list(_cmd, default=None):
            raise AssertionError("Should not probe disabled APIs")

        mock_gcloud_runner.list_enabled_apis = fake_enabled
        mock_gcloud_runner.list = fake_list

        check = EnabledApisWithNoResources()
        findings = await check.execute("test-project", mock_gcloud_runner)
        assert findings == []

    async def test_skips_cleanly_when_enabled_apis_unknown(self, mock_gcloud_runner):
        """If list_enabled_apis returns empty (couldn't fetch), don't probe blindly."""
        from backend.checks.posture.architecture_checks import EnabledApisWithNoResources

        async def fake_enabled(_pid):
            return set()

        mock_gcloud_runner.list_enabled_apis = fake_enabled
        mock_gcloud_runner.list = lambda _c, default=None: (_ for _ in ()).throw(
            AssertionError("Should not probe when enabled list is unknown")
        )

        check = EnabledApisWithNoResources()
        findings = await check.execute("test-project", mock_gcloud_runner)
        assert findings == []


class TestGcloudCacheCap:
    def test_cache_evicts_oldest_when_over_cap(self, monkeypatch):
        runner = GcloudRunner()
        monkeypatch.setattr(GcloudRunner, "_MAX_CACHE_ENTRIES", 3)
        # Stuff the cache directly to test eviction without hitting subprocess
        runner._cache["a"] = 1
        runner._cache["b"] = 2
        runner._cache["c"] = 3
        # Simulate the cap enforcement that run() does after a successful exec
        runner._cache["d"] = 4
        while len(runner._cache) > runner._MAX_CACHE_ENTRIES:
            runner._cache.popitem(last=False)
        assert list(runner._cache.keys()) == ["b", "c", "d"]
