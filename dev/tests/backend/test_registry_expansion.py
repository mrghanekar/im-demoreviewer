"""Sanity tests for the 2026-05 catalog expansion.

Ensures the new check modules import and register correctly, IDs are unique,
and every new ServiceCategory has at least one check.
"""

from backend.checks.registry import discover_checks, reset_registry
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


def test_check_ids_are_unique():
    checks = discover_checks()
    ids = [c.id for c in checks.values()]
    assert len(ids) == len(set(ids)), f"Duplicate check IDs: {sorted([x for x in ids if ids.count(x) > 1])}"


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
