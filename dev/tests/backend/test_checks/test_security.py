"""Tests for Security check modules."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from backend.checks.security.org_policies import (
    OrgPolicyDomainRestriction,
    SCCNotEnabled,
    AccessTransparencyNotEnabled,
)

PROJECT = "test-project"


@pytest.fixture
def runner():
    r = MagicMock()
    r.run = AsyncMock(return_value=[])
    return r


# ---- SEC-001: Domain Restriction ----

@pytest.mark.asyncio
class TestOrgPolicyDomainRestriction:

    async def test_flags_missing_policy(self, runner):
        runner.run = AsyncMock(return_value={})
        check = OrgPolicyDomainRestriction()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].severity == "high"

    async def test_passes_when_policy_set(self, runner):
        runner.run = AsyncMock(return_value={
            "spec": {"rules": [{"values": {"allowedValues": ["C0xxxxxxx"]}}]}
        })
        check = OrgPolicyDomainRestriction()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


# ---- SEC-003: SCC ----

@pytest.mark.asyncio
class TestSCCNotEnabled:

    async def test_flags_scc_disabled(self, runner):
        runner.run = AsyncMock(return_value=[])
        check = SCCNotEnabled()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].fix_command != ""

    async def test_passes_scc_enabled(self, runner):
        runner.run = AsyncMock(return_value=[{"name": "securitycenter.googleapis.com"}])
        check = SCCNotEnabled()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


# ---- SEC-010: Access Transparency ----

@pytest.mark.asyncio
class TestAccessTransparencyNotEnabled:

    async def test_flags_when_disabled(self, runner):
        runner.run = AsyncMock(return_value=[])
        check = AccessTransparencyNotEnabled()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1

    async def test_passes_when_enabled(self, runner):
        runner.run = AsyncMock(return_value=[{"name": "accessapproval.googleapis.com"}])
        check = AccessTransparencyNotEnabled()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0
