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

