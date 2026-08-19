"""Tests for Networking check modules."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from backend.checks.networking.network_checks import IdleLoadBalancer

PROJECT = "test-project"

@pytest.fixture
def runner():
    r = MagicMock()
    r.run = AsyncMock(return_value=[])
    return r

@pytest.mark.asyncio
class TestIdleLoadBalancer:

    async def test_flags_backend_service_no_backends(self, runner):
        runner.run.return_value = [{
            "name": "bs-idle",
            "backends": []
        }]
        check = IdleLoadBalancer()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].resource_name == "backend-services/bs-idle"

    async def test_passes_backend_service_with_backends(self, runner):
        runner.run.return_value = [{
            "name": "bs-active",
            "backends": [{"group": "instance-group-1"}]
        }]
        check = IdleLoadBalancer()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0

    async def test_handles_no_backends_field(self, runner):
        runner.run.return_value = [{
            "name": "bs-weird"
            # "backends" key missing
        }]
        check = IdleLoadBalancer()
        findings = await check.execute(PROJECT, runner)
        # Should flag it as it has no backends (empty list default)
        assert len(findings) == 1
