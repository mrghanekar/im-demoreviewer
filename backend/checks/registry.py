"""Auto-discovery registry for GCP checks.

Scans the checks/ directory for all BaseCheck subclasses and registers
them for use by the check engine. No manual registration needed —
just create a class inheriting from BaseCheck in any file under checks/.
"""

import importlib
import inspect
import logging
import pkgutil
from pathlib import Path

from backend.checks.base import BaseCheck
from backend.core.models import ServiceCategory

logger = logging.getLogger(__name__)

# Global registry of discovered checks
_registry: dict[str, BaseCheck] = {}
_discovered: bool = False


def discover_checks() -> dict[str, BaseCheck]:
    """Discover and instantiate all BaseCheck subclasses in the checks package.
    
    Scans all Python modules under backend/checks/ recursively, finds
    classes that inherit from BaseCheck, and instantiates them.
    
    Returns:
        Dictionary mapping check ID to check instance.
    """
    global _registry, _discovered

    if _discovered:
        return _registry

    checks_dir = Path(__file__).parent
    package_name = "backend.checks"

    logger.info("Discovering checks in %s", checks_dir)

    for module_info in pkgutil.walk_packages(
        path=[str(checks_dir)],
        prefix=f"{package_name}.",
    ):
        # Skip __init__ and utility modules
        if module_info.name.endswith((".base", ".registry")):
            continue

        try:
            module = importlib.import_module(module_info.name)
        except Exception as e:
            logger.warning("Failed to import check module %s: %s", module_info.name, e)
            continue

        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, BaseCheck)
                and obj is not BaseCheck
                and getattr(obj, "id", "")  # Must have a check ID
            ):
                check_instance = obj()
                check_id = check_instance.id

                if check_id in _registry:
                    logger.warning(
                        "Duplicate check ID '%s' — %s overwrites %s",
                        check_id, obj.__name__, type(_registry[check_id]).__name__,
                    )

                _registry[check_id] = check_instance
                logger.debug("Registered check: %s (%s)", check_id, obj.__name__)

    _discovered = True
    logger.info("Discovered %d checks", len(_registry))
    return _registry


def get_all_checks() -> dict[str, BaseCheck]:
    """Get all registered checks.
    
    Returns:
        Dictionary mapping check ID to check instance.
    """
    return discover_checks()


def get_checks_by_service(service_category: ServiceCategory) -> list[BaseCheck]:
    """Get all checks for a specific service category.
    
    Args:
        service_category: The service category to filter by.
        
    Returns:
        List of check instances for the given service.
    """
    checks = discover_checks()
    return [
        check for check in checks.values()
        if check.service_category == service_category
    ]


def get_check_by_id(check_id: str) -> BaseCheck | None:
    """Get a specific check by its ID.
    
    Args:
        check_id: Check identifier (e.g., "GKE-001").
        
    Returns:
        Check instance, or None if not found.
    """
    checks = discover_checks()
    return checks.get(check_id)


def get_check_catalog() -> list[dict[str, str]]:
    """Get the full check catalog for the API listing.
    
    Returns:
        List of catalog entries (dicts) for all registered checks.
    """
    checks = discover_checks()
    return [check.to_catalog_entry() for check in sorted(checks.values(), key=lambda c: c.id)]


def reset_registry() -> None:
    """Reset the registry. Used in testing."""
    global _registry, _discovered
    _registry = {}
    _discovered = False
