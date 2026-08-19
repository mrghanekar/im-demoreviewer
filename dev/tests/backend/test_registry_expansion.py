"""Sanity tests for the 2026-05 catalog expansion.

Ensures the new check modules import and register correctly, IDs are unique,
and every new ServiceCategory has at least one check.
"""

import pytest

from backend.checks.base import BaseCheck
from backend.checks.registry import (
    DuplicateCheckIdError,
    _register_check_class,
    discover_checks,
    reset_registry,
)
from backend.core.models import ServiceCategory


def setup_module(_mod):
    # Force a fresh discovery so prior tests don't poison the registry
    reset_registry()


def test_registry_discovers_new_categories():
    checks = discover_checks()
    seen = {c.service_category for c in checks.values()}

    for cat in (
        ServiceCategory.CLOUD_RUN,
        ServiceCategory.CLOUD_FUNCTIONS,
        ServiceCategory.SECRET_MANAGER,
        ServiceCategory.CLOUD_BUILD,
        ServiceCategory.MEMORYSTORE,
        ServiceCategory.FIRESTORE,
        ServiceCategory.SPANNER,
        ServiceCategory.IAP,
        ServiceCategory.COMPOSER,
        ServiceCategory.POSTURE,
    ):
        assert cat in seen, f"No checks registered for {cat}"


def test_duplicate_check_id_raises():
    """Two different classes claiming one ID must abort discovery, not
    silently shadow each other."""

    class FirstDummy(BaseCheck):
        id = "TEST-DUP-001"
        title = "first"
        service = "Test"

        async def execute(self, project_id, gcloud_runner):
            return []

    class SecondDummy(BaseCheck):
        id = "TEST-DUP-001"
        title = "second"
        service = "Test"

        async def execute(self, project_id, gcloud_runner):
            return []

    try:
        _register_check_class(FirstDummy)
        # Same class again is fine (modules re-export check classes).
        _register_check_class(FirstDummy)
        with pytest.raises(DuplicateCheckIdError) as exc_info:
            _register_check_class(SecondDummy)
        message = str(exc_info.value)
        assert "TEST-DUP-001" in message
        assert "FirstDummy" in message
        assert "SecondDummy" in message
    finally:
        reset_registry()


def test_total_check_count_increased():
    """Sanity floor: original catalog was ~130; with additions we expect >= 175."""
    checks = discover_checks()
    assert len(checks) >= 175, f"Expected >=175 checks after expansion, got {len(checks)}"


def test_every_check_has_required_attrs():
    """Every BaseCheck instance must have non-empty id/title/severity/category/service."""
    checks = discover_checks()
    bad: list[str] = []
    for cid, c in checks.items():
        if not c.id or not c.title or not c.service:
            bad.append(cid)
        if not c.severity or not c.category:
            bad.append(cid)
    assert not bad, f"Checks with missing required attributes: {bad}"
