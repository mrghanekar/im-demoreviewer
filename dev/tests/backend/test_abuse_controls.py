"""Regression tests for exfiltration and resource-abuse controls.

- The GCS export endpoint accepted any syntactically valid bucket name, so a
  caller could have the server's service account push a full estate inventory
  into a bucket they controlled.
- The rate limiter trusted the leftmost X-Forwarded-For entry, which is
  client-supplied; rotating it bypassed both buckets.
- Billed Vertex endpoints (/ai/*, /cost/.../cost-analysis) sat in the loose
  general bucket rather than the tight one.
"""

import pytest
from fastapi import HTTPException

from backend.api.middleware.security import RateLimitMiddleware
from backend.api.routes.export import _require_allowed_bucket
from backend.config import settings


class TestExportBucketAllowlist:
    def test_configured_export_bucket_is_allowed(self, monkeypatch):
        monkeypatch.setattr(settings, "gcs_export_bucket", "my-reports")
        monkeypatch.setattr(settings, "gcs_export_bucket_allowlist", [])
        assert _require_allowed_bucket("my-reports") == "my-reports"

    def test_allowlisted_bucket_is_allowed(self, monkeypatch):
        monkeypatch.setattr(settings, "gcs_export_bucket", "")
        monkeypatch.setattr(
            settings, "gcs_export_bucket_allowlist", ["team-a", "team-b"]
        )
        assert _require_allowed_bucket("team-b") == "team-b"

    def test_attacker_bucket_is_rejected(self, monkeypatch):
        monkeypatch.setattr(settings, "gcs_export_bucket", "my-reports")
        monkeypatch.setattr(settings, "gcs_export_bucket_allowlist", [])
        with pytest.raises(HTTPException) as exc:
            _require_allowed_bucket("evil-corp-dump")
        assert exc.value.status_code == 403

    def test_export_blocked_when_nothing_configured(self, monkeypatch):
        monkeypatch.setattr(settings, "gcs_export_bucket", "")
        monkeypatch.setattr(settings, "gcs_export_bucket_allowlist", [])
        with pytest.raises(HTTPException) as exc:
            _require_allowed_bucket("any-bucket")
        assert exc.value.status_code == 409


class _Req:
    """Minimal stand-in for a Starlette Request."""

    def __init__(self, xff=None, peer="10.0.0.1"):
        self.headers = {"x-forwarded-for": xff} if xff else {}
        self.client = type("C", (), {"host": peer})()


class TestClientIpResolution:
    @pytest.fixture
    def mw(self):
        return RateLimitMiddleware(app=None, trusted_proxy_hops=1)

    def test_spoofed_leftmost_entry_is_ignored(self, mw):
        # The proxy appends the address it saw, so the real client is last.
        assert mw._get_client_ip(_Req(xff="1.2.3.4, 203.0.113.9")) == "203.0.113.9"

    def test_rotating_the_spoofed_prefix_does_not_change_the_key(self, mw):
        """This is the bypass: a fresh fake IP per request reset the counter."""
        keys = {
            mw._get_client_ip(_Req(xff=f"1.2.3.{n}, 203.0.113.9"))
            for n in range(50)
        }
        assert keys == {"203.0.113.9"}, (
            "rotating the client-controlled XFF prefix still changes the "
            "rate-limit key — the limiter is bypassable"
        )

    def test_falls_back_to_peer_address(self, mw):
        assert mw._get_client_ip(_Req(peer="192.0.2.7")) == "192.0.2.7"

    def test_single_entry_is_used(self, mw):
        assert mw._get_client_ip(_Req(xff="203.0.113.9")) == "203.0.113.9"

    def test_two_trusted_hops_skips_both(self):
        mw = RateLimitMiddleware(app=None, trusted_proxy_hops=2)
        ip = mw._get_client_ip(_Req(xff="1.2.3.4, 203.0.113.9, 10.0.0.5"))
        assert ip == "203.0.113.9"

    def test_zero_hops_ignores_the_header_entirely(self):
        """With no proxy in front, XFF is entirely attacker-controlled."""
        mw = RateLimitMiddleware(app=None, trusted_proxy_hops=0)
        ip = mw._get_client_ip(_Req(xff="1.2.3.4, 203.0.113.9", peer="192.0.2.7"))
        assert ip == "192.0.2.7"


class TestExpensiveEndpointClassification:
    @pytest.mark.parametrize(
        "path",
        [
            "/api/v1/scans",
            "/api/v1/cost/scans/abc/cost-analysis",
            "/api/v1/ai/explain",
        ],
    )
    def test_billed_and_fanout_paths_use_the_tight_bucket(self, path):
        assert RateLimitMiddleware._is_expensive(path) is True

    @pytest.mark.parametrize(
        "path", ["/api/v1/scans/abc/findings", "/api/v1/setup/projects"]
    )
    def test_cheap_paths_use_the_general_bucket(self, path):
        assert RateLimitMiddleware._is_expensive(path) is False
