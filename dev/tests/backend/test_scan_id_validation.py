"""Every route taking a scan_id must validate it before using it.

The scan_id is not only a dictionary key. It is interpolated into a GCS
object prefix (``export_to_gcs``) and into a ``Content-Disposition``
filename (the file exports), so a scan_id containing a slash, a quote or a
newline is a path-traversal / header-injection primitive. These tests pin
the 422 so a future route added without ``Depends(require_scan_id)`` fails
here rather than in production.
"""

import pytest
from fastapi.testclient import TestClient

from backend.main import app

# Path segments that must never reach a handler. Kept literal rather than
# URL-encoded so the request travels the same way an attacker would send it.
BAD_IDS = [
    "abc;whoami",
    "abc$(id)",
    "abc`id`",
    "abc|id",
    "scan id",
    "scan'id",
    'scan"id',
    "scan..id",
    "s" * 37,  # exceeds the 36-char ceiling
    "scan%0d%0aX-Injected:%20yes",
]

# Every route below is reachable with a well-formed but nonexistent ID; each
# should then 404 rather than 422, which is what proves the ID got through.
GET_ROUTES = [
    "/api/v1/scans/{sid}",
    "/api/v1/scans/{sid}/findings",
    "/api/v1/scans/{sid}/findings/finding-1",
    "/api/v1/scans/{sid}/summary",
    "/api/v1/scans/{sid}/compliance",
    "/api/v1/scans/{sid}/export/json",
    "/api/v1/scans/{sid}/export/html",
    "/api/v1/scans/{sid}/export/csv",
]


@pytest.fixture(autouse=True)
def _fresh_rate_limiter():
    """Drop the limiter's windows between cases.

    This module fires a few hundred requests from one client IP, which the
    60-rpm general bucket would otherwise start answering with 429 — masking
    whatever the route actually does.
    """
    from backend.api.middleware.security import RateLimitMiddleware

    if app.middleware_stack is None:
        app.middleware_stack = app.build_middleware_stack()
    node = app.middleware_stack
    while node is not None:
        if isinstance(node, RateLimitMiddleware):
            node._general_counts.clear()
            node._scan_counts.clear()
        node = getattr(node, "app", None)


@pytest.fixture
def client():
    return TestClient(app)


class TestMalformedScanIdRejected:
    @pytest.mark.parametrize("route", GET_ROUTES)
    @pytest.mark.parametrize("bad", BAD_IDS)
    def test_get_routes_reject(self, client, route, bad):
        response = client.get(route.format(sid=bad))
        assert response.status_code == 422, (
            f"{route} accepted scan_id {bad!r} (got {response.status_code})"
        )

    @pytest.mark.parametrize("bad", BAD_IDS)
    def test_delete_scan_rejects(self, client, bad):
        assert client.delete(f"/api/v1/scans/{bad}").status_code == 422

    @pytest.mark.parametrize("bad", BAD_IDS)
    def test_suppress_routes_reject(self, client, bad):
        assert client.post(
            f"/api/v1/scans/{bad}/findings/f-1/suppress", json={"reason": "x"}
        ).status_code == 422
        assert client.delete(
            f"/api/v1/scans/{bad}/findings/f-1/suppress"
        ).status_code == 422

    @pytest.mark.parametrize("bad", BAD_IDS)
    def test_gcs_export_rejects(self, client, bad):
        # The GCS object prefix is democratized-reviewer/scans/{scan_id}.
        response = client.post(
            f"/api/v1/scans/{bad}/export", params={"bucket": "some-bucket"}
        )
        assert response.status_code == 422

    def test_gcs_export_accepts_a_valid_id(self, client):
        response = client.post(
            "/api/v1/scans/a0b1c2d3-0000-4000-8000-abcdef012345/export",
            params={"bucket": "some-bucket"},
        )
        # 409 — the bucket allowlist rejects it first, which still proves the
        # scan_id itself got past validation.
        assert response.status_code == 409


class TestWellFormedScanIdStillWorks:
    """The validator must not reject legitimate IDs."""

    @pytest.mark.parametrize("route", GET_ROUTES)
    def test_unknown_but_valid_id_is_404_not_422(self, client, route):
        response = client.get(route.format(sid="a0b1c2d3-0000-4000-8000-abcdef012345"))
        assert response.status_code == 404, (
            f"{route} rejected a well-formed scan_id (got {response.status_code})"
        )

    def test_real_scan_is_served(self, client):
        from backend.api.routes.scan import get_store
        from backend.core.models import Scan, ScanSummary

        scan = Scan(
            id="a0b1c2d3-0000-4000-8000-abcdef012345",
            scope="project",
            target_id="test-project",
            status="completed",
            categories=["security"],
            summary=ScanSummary(),
            findings=[],
            projects_scanned=["test-project"],
        )
        store = get_store()
        store._scans[scan.id] = scan
        try:
            response = client.get(f"/api/v1/scans/{scan.id}")
            assert response.status_code == 200
            assert response.json()["id"] == scan.id
        finally:
            store._scans.pop(scan.id, None)
