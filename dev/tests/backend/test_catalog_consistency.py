"""Meta-tests that keep the catalog, the enum, and the UI from drifting apart.

This repo has drifted before: the docs claimed 199 checks while the registry
discovered 213, and a new ServiceCategory can be added on the backend without
the scan form ever offering it. Both are silent — the tool simply never runs
those checks and nobody notices. These tests make the drift loud.
"""

import re
from pathlib import Path

import pytest

from backend.checks.registry import discover_checks, get_all_checks
from backend.core.models import ServiceCategory

REPO_ROOT = Path(__file__).resolve().parents[3]
FRONTEND_TYPES = REPO_ROOT / "frontend" / "src" / "lib" / "types.ts"


@pytest.fixture(scope="module", autouse=True)
def _catalog():
    discover_checks()


# ---------------------------------------------------------------------------
# Catalog integrity
# ---------------------------------------------------------------------------

def test_no_duplicate_check_ids_in_source():
    """The registry is keyed by ID, so a collision there is invisible.

    ``get_all_checks()`` returns a dict — a second class claiming an existing
    ID silently replaces the first and its checks never run. Reading the IDs
    back out of that dict can never catch it, so read the source instead.
    """
    ids: dict[str, list[str]] = {}
    pattern = re.compile(r'^\s+id = "([A-Z]+-\d+)"', re.MULTILINE)
    for path in (REPO_ROOT / "backend" / "checks").rglob("*.py"):
        if path.name == "base.py":
            continue  # its docstring carries an illustrative `id = "GCS-001"`
        for check_id in pattern.findall(path.read_text()):
            ids.setdefault(check_id, []).append(str(path.relative_to(REPO_ROOT)))

    duplicates = {k: v for k, v in ids.items() if len(v) > 1}
    assert not duplicates, f"duplicate check IDs: {duplicates}"


def test_every_service_category_has_at_least_one_check():
    """An empty category is a checkbox in the UI that scans nothing."""
    used = {check.service_category for check in get_all_checks().values()}
    unused = sorted(c.value for c in ServiceCategory if c not in used)
    assert not unused, f"ServiceCategory members with no checks: {unused}"


def test_every_check_declares_a_known_category():
    for check_id, check in get_all_checks().items():
        assert isinstance(check.service_category, ServiceCategory), (
            f"{check_id} has a non-enum service_category"
        )


# ---------------------------------------------------------------------------
# Backend <-> frontend parity
# ---------------------------------------------------------------------------

def _frontend_source() -> str:
    if not FRONTEND_TYPES.exists():
        pytest.skip("frontend sources not present in this checkout")
    return FRONTEND_TYPES.read_text()


def _frontend_union() -> set[str]:
    src = _frontend_source()
    match = re.search(
        r"export type ServiceCategory\s*=\s*(.*?);", src, re.DOTALL
    )
    assert match, "could not locate the ServiceCategory union in types.ts"
    return set(re.findall(r"'([a-z_]+)'", match.group(1)))


def _frontend_list(name: str) -> set[str]:
    src = _frontend_source()
    match = re.search(rf"export const {name}[^=]*=\s*\[(.*?)\];", src, re.DOTALL)
    assert match, f"could not locate {name} in types.ts"
    return set(re.findall(r"'([a-z_]+)'", match.group(1)))


def _frontend_labels() -> set[str]:
    src = _frontend_source()
    match = re.search(
        r"export const SERVICE_LABELS: Record<ServiceCategory, string> = \{(.*?)\};",
        src,
        re.DOTALL,
    )
    assert match, "could not locate SERVICE_LABELS in types.ts"
    return set(re.findall(r"^\s*([a-z_]+):", match.group(1), re.MULTILINE))


@pytest.mark.parametrize(
    ("what", "reader"),
    [
        ("ServiceCategory union", _frontend_union),
        ("SERVICE_LABELS", _frontend_labels),
        ("ALL_SERVICE_CATEGORIES", lambda: _frontend_list("ALL_SERVICE_CATEGORIES")),
    ],
)
def test_frontend_mirrors_the_service_category_enum(what, reader):
    backend = {c.value for c in ServiceCategory}
    frontend = reader()
    assert frontend == backend, (
        f"{what} is out of sync with ServiceCategory — "
        f"missing in frontend: {sorted(backend - frontend)}, "
        f"unknown to backend: {sorted(frontend - backend)}"
    )


def test_default_scan_selection_covers_every_category():
    """A category left out of the default selection is coverage nobody opts into."""
    store = REPO_ROOT / "frontend" / "src" / "stores" / "scanStore.ts"
    if not store.exists():
        pytest.skip("frontend sources not present in this checkout")

    match = re.search(r"selectedCategories:\s*\[(.*?)\]", store.read_text(), re.DOTALL)
    assert match, "could not locate the default selectedCategories in scanStore.ts"
    selected = set(re.findall(r"'([a-z_]+)'", match.group(1)))

    missing = sorted({c.value for c in ServiceCategory} - selected)
    assert not missing, f"categories missing from the default scan selection: {missing}"


# ---------------------------------------------------------------------------
# Documented counts
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("relpath", "pattern"),
    [
        ("README.md", r"against (\d+) best-practice checks across (\d+) service areas"),
        ("setup.sh", r"(\d+) checks · (\d+) service areas"),
    ],
)
def test_documented_counts_match_the_registry(relpath, pattern):
    """The README claimed 199 checks while the registry discovered 213.

    A wrong number in the pitch is how a customer discovers the tool's scope
    is not what they were sold. Fail the build instead.
    """
    path = REPO_ROOT / relpath
    if not path.exists():
        pytest.skip(f"{relpath} not present in this checkout")

    match = re.search(pattern, path.read_text())
    assert match, f"could not find the check-count claim in {relpath}"
    checks, categories = int(match.group(1)), int(match.group(2))

    assert checks == len(get_all_checks()), (
        f"{relpath} claims {checks} checks; the registry has {len(get_all_checks())}"
    )
    assert categories == len(ServiceCategory), (
        f"{relpath} claims {categories} service areas; the enum has {len(ServiceCategory)}"
    )


def test_home_page_check_count_matches_the_registry():
    home = REPO_ROOT / "frontend" / "src" / "pages" / "Home.tsx"
    if not home.exists():
        pytest.skip("frontend sources not present in this checkout")

    claimed = set(re.findall(r"(\d+)[ -]best-practice checks|the (\d+)-check catalog", home.read_text()))
    numbers = {int(n) for pair in claimed for n in pair if n}
    assert numbers, "could not find a check-count claim on the home page"
    assert numbers == {len(get_all_checks())}, (
        f"Home.tsx claims {sorted(numbers)} checks; the registry has {len(get_all_checks())}"
    )
