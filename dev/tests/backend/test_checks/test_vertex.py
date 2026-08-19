"""Tests for Vertex AI check modules."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from backend.checks.vertex.notebooks import NotebookPublicIP, NotebookDefaultSA
from backend.checks.vertex.endpoints import ModelEndpointPublic, VectorSearchPublic

PROJECT = "test-project"

@pytest.fixture
def runner():
    r = MagicMock()
    r.run = AsyncMock(return_value=[])
    return r

@pytest.mark.asyncio
class TestVertexChecks:

    async def test_notebook_public_ip(self, runner):
        runner.run.return_value = [
            {"name": "projects/p/locations/l/instances/nb-1", "noPublicIp": False},
            {"name": "projects/p/locations/l/instances/nb-2", "noPublicIp": True}
        ]
        check = NotebookPublicIP()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].resource_name == "notebooks/nb-1"

    async def test_notebook_default_sa(self, runner):
        runner.run.return_value = [
            {"name": "nb-1", "serviceAccount": "123-compute@developer.gserviceaccount.com"},
            {"name": "nb-2", "serviceAccount": "custom-sa@p.iam.gserviceaccount.com"}
        ]
        check = NotebookDefaultSA()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].resource_name == "notebooks/nb-1"

    async def test_endpoint_public(self, runner):
        runner.run.return_value = [
            {"displayName": "ep-1"}, # No network = public
            {"displayName": "ep-2", "network": "projects/p/global/networks/vpc"}
        ]
        check = ModelEndpointPublic()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].resource_name == "endpoints/ep-1"

    async def test_vector_search_public(self, runner):
        runner.run.return_value = [
            {"displayName": "idx-1", "publicEndpointEnabled": True},
            {"displayName": "idx-2", "publicEndpointEnabled": False}
        ]
        check = VectorSearchPublic()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].resource_name == "index-endpoints/idx-1"
