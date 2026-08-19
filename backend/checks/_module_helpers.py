"""Helpers used by check modules to attach metadata to every check class
defined in the module without repeating it on each class.
"""

from types import ModuleType
from typing import Iterable, Mapping

from backend.checks.base import BaseCheck


def apply_required_apis(module: ModuleType, apis: Iterable[str]) -> None:
    """Set ``required_apis`` on every BaseCheck subclass declared in ``module``.

    Subclasses that already declare their own ``required_apis`` are left
    untouched. This lets a module set a default and individual classes override.
    """
    api_list = list(apis)
    for name in dir(module):
        obj = getattr(module, name)
        if (
            isinstance(obj, type)
            and issubclass(obj, BaseCheck)
            and obj is not BaseCheck
            and getattr(obj, "id", "")
            and not obj.__dict__.get("required_apis")
        ):
            obj.required_apis = list(api_list)


def apply_required_apis_by_id(
    module: ModuleType,
    mapping: Mapping[str, Iterable[str]],
) -> None:
    """Set ``required_apis`` per check ID.

    For modules that bundle classes hitting several services, ``mapping`` keys
    are check IDs and values are the APIs each check needs. Classes whose ID is
    absent from the mapping are left with the BaseCheck default (empty list →
    never pre-skipped).
    """
    for name in dir(module):
        obj = getattr(module, name)
        if not (
            isinstance(obj, type)
            and issubclass(obj, BaseCheck)
            and obj is not BaseCheck
        ):
            continue
        check_id = getattr(obj, "id", "")
        if not check_id:
            continue
        apis = mapping.get(check_id)
        if apis is None or obj.__dict__.get("required_apis"):
            continue
        obj.required_apis = list(apis)
