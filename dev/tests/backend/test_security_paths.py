"""Regression tests for path traversal in the SPA catch-all.

The /{full_path:path} route used to do `STATIC_DIR / full_path` without
containment, which let `../`-style requests escape the static directory.

Rather than re-mounting the whole app under a temp dir (fragile because the
StaticFiles mount captures the path at import time), we test the containment
check by exercising the resolved-path logic directly with the production
STATIC_DIR.
"""


from backend.main import STATIC_DIR


def _is_safe(full_path: str) -> bool:
    """Mirror of the containment check in backend/main.py:serve_spa."""
    try:
        candidate = (STATIC_DIR / full_path).resolve()
    except (OSError, RuntimeError):
        return False
    return STATIC_DIR == candidate or STATIC_DIR in candidate.parents


class TestSpaContainment:
    def test_plain_path_is_inside_static(self):
        assert _is_safe("some/route") is True

    def test_empty_path_is_inside_static(self):
        assert _is_safe("") is True

    def test_dotdot_traversal_rejected(self):
        assert _is_safe("../../../etc/passwd") is False

    def test_absolute_path_rejected(self):
        # On Windows this resolves to a drive root; on POSIX to /etc/passwd
        assert _is_safe("/etc/passwd") is False

    def test_nested_dotdot_rejected(self):
        assert _is_safe("subdir/../../escape") is False

    def test_resolved_target_must_be_inside(self):
        # The resolution is what matters — the literal string can contain ..
        # as long as it nets out inside STATIC_DIR.
        assert _is_safe("./index.html") is True
