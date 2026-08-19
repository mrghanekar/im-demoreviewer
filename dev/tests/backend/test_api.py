"""Tests for the FastAPI API endpoints."""

import pytest
from fastapi.testclient import TestClient

from backend.main import app


@pytest.fixture
def client():
    """FastAPI test client."""
    return TestClient(app)


class TestHealthEndpoint:
    """Tests for the health check endpoint."""

    def test_health_returns_ok(self, client):
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data
        assert "app_name" in data

    def test_health_returns_correct_app_name(self, client):
        response = client.get("/api/v1/health")
        data = response.json()
        assert data["app_name"] == "Democratized Reviewer"

    def test_health_reports_the_deployed_region(self, client, monkeypatch):
        """The UI builds its `gcloud run services logs read` hint from these.

        Cloud Run injects K_SERVICE but not the region, so setup.sh passes
        DR_REGION. Before this, the hint hardcoded asia-south1 and was simply
        wrong for anyone who deployed elsewhere.
        """
        monkeypatch.setenv("K_SERVICE", "democratized-reviewer")
        monkeypatch.setenv("DR_REGION", "europe-west1")
        data = client.get("/api/v1/health").json()
        assert data["environment"] == "cloud_run"
        assert data["service_name"] == "democratized-reviewer"
        assert data["region"] == "europe-west1"

    def test_health_leaves_region_empty_when_unknown(self, client, monkeypatch):
        """Absent DR_REGION the UI must omit --region, not guess one."""
        monkeypatch.delenv("DR_REGION", raising=False)
        monkeypatch.delenv("K_SERVICE", raising=False)
        data = client.get("/api/v1/health").json()
        assert data["region"] == ""
        assert data["service_name"] == ""


class TestScanEndpoints:
    """Tests for scan management endpoints."""

    def test_list_scans_empty(self, client):
        response = client.get("/api/v1/scans")
        assert response.status_code == 200
        assert response.json() == []

    def test_create_scan(self, client):
        response = client.post("/api/v1/scans", json={
            "scope": "project",
            "target_id": "test-project",
            "categories": ["iam", "gcs"],
        })
        assert response.status_code == 200
        data = response.json()
        assert data["scope"] == "project"
        assert data["target_id"] == "test-project"
        assert data["status"] == "pending"
        assert "id" in data

    def test_create_scan_invalid_scope(self, client):
        response = client.post("/api/v1/scans", json={
            "scope": "invalid",
            "target_id": "test-project",
        })
        assert response.status_code == 422

    def test_get_scan_not_found(self, client):
        response = client.get("/api/v1/scans/nonexistent")
        assert response.status_code == 404

