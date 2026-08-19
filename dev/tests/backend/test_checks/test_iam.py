"""Tests for IAM check modules."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from backend.checks.iam.role_bindings import (
    PrimitiveRolesInUse,
    AllUsersInBindings,
    OverPermissionedServiceAccounts,
    NoCustomRoles,
    NoOrgLevelIAMAudit,
)
from backend.checks.iam.service_accounts import (
    UserManagedSAKeys,
)
# IAM-005 (SAImpersonationNotUsed) was removed as a duplicate of IAM-003.

PROJECT = "test-project"


@pytest.fixture
def runner():
    r = MagicMock()
    r.run = AsyncMock(return_value=[])
    return r


# ---- IAM-001: Primitive Roles ----

@pytest.mark.asyncio
class TestPrimitiveRolesInUse:

    async def test_finds_owner_role(self, runner):
        runner.run = AsyncMock(return_value={
            "bindings": [
                {"role": "roles/owner", "members": ["user:admin@example.com"]},
            ]
        })
        check = PrimitiveRolesInUse()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert "admin@example.com" in findings[0].resource_name

    async def test_skips_google_service_agents(self, runner):
        runner.run = AsyncMock(return_value={
            "bindings": [
                {"role": "roles/editor", "members": [
                    "serviceAccount:service-123@cloudservices.gserviceaccount.com",
                ]},
            ]
        })
        check = PrimitiveRolesInUse()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0

    async def test_passes_with_predefined_roles(self, runner):
        runner.run = AsyncMock(return_value={
            "bindings": [
                {"role": "roles/viewer", "members": ["user:reader@example.com"]},
            ]
        })
        check = PrimitiveRolesInUse()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


# ---- IAM-009: Public Access ----

@pytest.mark.asyncio
class TestAllUsersInBindings:

    async def test_finds_allUsers(self, runner):
        runner.run = AsyncMock(return_value={
            "bindings": [
                {"role": "roles/storage.objectViewer", "members": ["allUsers"]},
            ]
        })
        check = AllUsersInBindings()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    async def test_finds_allAuthenticatedUsers(self, runner):
        runner.run = AsyncMock(return_value={
            "bindings": [
                {"role": "roles/viewer", "members": ["allAuthenticatedUsers"]},
            ]
        })
        check = AllUsersInBindings()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1

    async def test_passes_no_public_members(self, runner):
        runner.run = AsyncMock(return_value={
            "bindings": [
                {"role": "roles/viewer", "members": ["user:a@corp.com"]},
            ]
        })
        check = AllUsersInBindings()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


# ---- IAM-003: User-managed SA Keys ----

@pytest.mark.asyncio
class TestUserManagedSAKeys:

    async def test_finds_user_managed_keys(self, runner):
        async def mock_run(cmd, **kwargs):
            if "service-accounts list" in cmd:
                return [{"email": "my-sa@test-project.iam.gserviceaccount.com"}]
            if "keys list" in cmd:
                return [{"keyType": "USER_MANAGED", "name": "projects/test/serviceAccounts/my-sa/keys/abc123"}]
            return []
        runner.run = AsyncMock(side_effect=mock_run)

        check = UserManagedSAKeys()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].severity == "high"

    async def test_passes_no_user_keys(self, runner):
        async def mock_run(cmd, **kwargs):
            if "service-accounts list" in cmd:
                return [{"email": "my-sa@test-project.iam.gserviceaccount.com"}]
            if "keys list" in cmd:
                return []
            return []
        runner.run = AsyncMock(side_effect=mock_run)

        check = UserManagedSAKeys()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


# ---- IAM-004: Over-permissioned SAs ----

@pytest.mark.asyncio
class TestOverPermissionedSA:

    async def test_flags_sa_with_editor(self, runner):
        runner.run = AsyncMock(return_value={
            "bindings": [
                {"role": "roles/editor", "members": ["serviceAccount:deploy@test-project.iam.gserviceaccount.com"]},
            ]
        })
        check = OverPermissionedServiceAccounts()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1


# ---- IAM-010: No Custom Roles ----

@pytest.mark.asyncio
class TestNoCustomRoles:

    async def test_flags_when_no_custom_roles(self, runner):
        runner.run = AsyncMock(return_value=[])
        check = NoCustomRoles()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].severity == "low"

    async def test_passes_when_custom_roles_exist(self, runner):
        runner.run = AsyncMock(return_value=[{"name": "projects/test/roles/customViewer"}])
        check = NoCustomRoles()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 0


# ---- IAM-006: Org-level audit (informational) ----

@pytest.mark.asyncio
class TestNoOrgLevelIAMAudit:

    async def test_always_returns_info(self, runner):
        check = NoOrgLevelIAMAudit()
        findings = await check.execute(PROJECT, runner)
        assert len(findings) == 1
        assert findings[0].severity == "info"
