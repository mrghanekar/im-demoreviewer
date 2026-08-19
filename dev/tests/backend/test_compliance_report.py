"""Tests for the compliance regrouping of a scan.

The property that matters most here is the conservative status derivation: a
control whose checks could not be evaluated must never render as passing. An
auditor reading "PASS" against ISO A.8.20 when the scanner got a 403 is worse
than no report at all.
"""

import pytest

from backend.core.compliance import CONTROL_TITLES, FRAMEWORKS
from backend.core.models import (
    Category,
    CheckExecution,
    CheckStatus,
    Finding,
    Scan,
    ServiceCategory,
    Severity,
)
from backend.utils.compliance_report import (
    _control_sort_key,
    build_compliance_summary,
    render_compliance_html,
)


def _escape(value: str) -> str:
    """Stand-in for the report generator's escaper."""
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _execution(check_id: str, status: CheckStatus, **kwargs) -> CheckExecution:
    return CheckExecution(
        check_id=check_id,
        check_title=kwargs.pop("title", f"{check_id} title"),
        service_category=ServiceCategory.NETWORKING,
        status=status,
        **kwargs,
    )


def _finding(check_id: str, suppressed: bool = False) -> Finding:
    return Finding(
        id=f"f-{check_id}-{suppressed}",
        scan_id="scan-1",
        check_id=check_id,
        title=f"{check_id} finding",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        service="Networking",
        resource_name="projects/p/foo",
        suppressed=suppressed,
    )


def _scan(executions, findings=()) -> Scan:
    return Scan(
        id="scan-1",
        scope="project",
        target_id="my-project",
        check_executions=list(executions),
        findings=list(findings),
    )


@pytest.fixture
def mapped(monkeypatch):
    """Pin the check -> control mapping so tests don't ride on the live catalog."""

    def _apply(mapping):
        monkeypatch.setattr(
            "backend.utils.compliance_report._check_compliance_map",
            lambda: mapping,
        )

    return _apply


# ---------------------------------------------------------------------------
# Status derivation matrix
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("statuses", "finding_check", "expected"),
    [
        # Any finding wins, whatever else happened.
        ([CheckStatus.FAILED, CheckStatus.PASSED], "C-1", "failed"),
        ([CheckStatus.ERRORED, CheckStatus.PASSED], "C-1", "failed"),
        # No findings, everything ran: clean.
        ([CheckStatus.PASSED, CheckStatus.PASSED], None, "passed"),
        # Some evidence missing.
        ([CheckStatus.PASSED, CheckStatus.ERRORED], None, "partial"),
        ([CheckStatus.PASSED, CheckStatus.SKIPPED], None, "partial"),
        # No evidence at all — must not read as a pass.
        ([CheckStatus.ERRORED, CheckStatus.SKIPPED], None, "not_assessed"),
        ([CheckStatus.PENDING], None, "not_assessed"),
        ([CheckStatus.RUNNING], None, "not_assessed"),
    ],
)
def test_control_status_derivation(mapped, statuses, finding_check, expected):
    check_ids = [f"C-{i + 1}" for i in range(len(statuses))]
    mapped({cid: {"ISO_27001": ["A.8.20"]} for cid in check_ids})

    executions = [_execution(cid, st) for cid, st in zip(check_ids, statuses)]
    findings = [_finding(finding_check)] if finding_check else []

    data = build_compliance_summary(_scan(executions, findings))
    control = data["frameworks"][0]["controls"][0]
    assert control["status"] == expected


def test_suppressed_findings_do_not_fail_a_control(mapped):
    """Suppression is an accepted risk, not an open finding."""
    mapped({"C-1": {"ISO_27001": ["A.8.20"]}})
    scan = _scan(
        [_execution("C-1", CheckStatus.FAILED)],
        [_finding("C-1", suppressed=True)],
    )

    control = build_compliance_summary(scan)["frameworks"][0]["controls"][0]
    assert control["status"] == "passed"
    assert control["findings_count"] == 0


def test_unsuppressed_finding_still_counts(mapped):
    mapped({"C-1": {"ISO_27001": ["A.8.20"]}})
    scan = _scan(
        [_execution("C-1", CheckStatus.FAILED)],
        [_finding("C-1", suppressed=True), _finding("C-1")],
    )

    control = build_compliance_summary(scan)["frameworks"][0]["controls"][0]
    assert control["status"] == "failed"
    assert control["findings_count"] == 1


def test_checks_not_in_this_scan_are_ignored(mapped):
    """A control is only reported when at least one of its checks actually ran."""
    mapped({
        "C-1": {"ISO_27001": ["A.8.20"]},
        "C-2": {"ISO_27001": ["A.8.24"]},
    })
    scan = _scan([_execution("C-1", CheckStatus.PASSED)])

    controls = build_compliance_summary(scan)["frameworks"][0]["controls"]
    assert [c["id"] for c in controls] == ["A.8.20"]


# ---------------------------------------------------------------------------
# Shape and ordering
# ---------------------------------------------------------------------------

def test_one_check_feeds_several_frameworks_and_controls(mapped):
    mapped({"C-1": {"ISO_27001": ["A.8.20", "A.8.22"], "CIS_GCP_V3": ["3.6"]}})
    scan = _scan([_execution("C-1", CheckStatus.FAILED)], [_finding("C-1")])

    data = build_compliance_summary(scan)
    by_key = {f["key"]: f for f in data["frameworks"]}
    assert set(by_key) == {"ISO_27001", "CIS_GCP_V3"}
    assert {c["id"] for c in by_key["ISO_27001"]["controls"]} == {"A.8.20", "A.8.22"}
    assert by_key["CIS_GCP_V3"]["controls"][0]["findings_count"] == 1


def test_failing_controls_are_listed_first(mapped):
    mapped({
        "C-1": {"ISO_27001": ["A.8.24"]},   # passes
        "C-2": {"ISO_27001": ["A.8.20"]},   # fails
        "C-3": {"ISO_27001": ["A.8.22"]},   # not assessed
    })
    scan = _scan(
        [
            _execution("C-1", CheckStatus.PASSED),
            _execution("C-2", CheckStatus.FAILED),
            _execution("C-3", CheckStatus.ERRORED),
        ],
        [_finding("C-2")],
    )

    controls = build_compliance_summary(scan)["frameworks"][0]["controls"]
    assert [c["status"] for c in controls] == ["failed", "not_assessed", "passed"]


def test_totals_match_control_statuses(mapped):
    mapped({
        "C-1": {"ISO_27001": ["A.8.24"]},
        "C-2": {"ISO_27001": ["A.8.20"]},
    })
    scan = _scan(
        [_execution("C-1", CheckStatus.PASSED), _execution("C-2", CheckStatus.FAILED)],
        [_finding("C-2"), _finding("C-2")],
    )

    framework = build_compliance_summary(scan)["frameworks"][0]
    assert framework["totals"] == {
        "failed": 1, "partial": 0, "passed": 1, "not_assessed": 0,
    }


def test_control_titles_are_resolved(mapped):
    mapped({"C-1": {"ISO_27001": ["A.8.20"], "CIS_GCP_V3": ["9.9.9"]}})
    scan = _scan([_execution("C-1", CheckStatus.PASSED)])

    data = build_compliance_summary(scan)
    by_key = {f["key"]: f for f in data["frameworks"]}
    assert by_key["ISO_27001"]["controls"][0]["title"] == "Networks security"
    # Unknown IDs fall back to the bare ID rather than blowing up.
    assert by_key["CIS_GCP_V3"]["controls"][0]["title"] == "9.9.9"


def test_unmapped_checks_are_reported(mapped):
    mapped({"C-1": {"ISO_27001": ["A.8.20"]}})
    scan = _scan(
        [_execution("C-1", CheckStatus.PASSED), _execution("BIL-999", CheckStatus.PASSED)]
    )

    assert build_compliance_summary(scan)["unmapped_checks"] == ["BIL-999"]


def test_no_mappings_yields_no_frameworks(mapped):
    mapped({})
    scan = _scan([_execution("C-1", CheckStatus.PASSED)])

    data = build_compliance_summary(scan)
    assert data["frameworks"] == []
    assert data["unmapped_checks"] == ["C-1"]


# ---------------------------------------------------------------------------
# Sorting
# ---------------------------------------------------------------------------

def test_dotted_numeric_ids_sort_numerically():
    ids = ["1.10", "1.9", "1.1", "2.1"]
    assert sorted(ids, key=_control_sort_key) == ["1.1", "1.9", "1.10", "2.1"]


def test_iso_ids_sort_numerically_within_a_clause():
    ids = ["A.8.20", "A.8.3", "A.8.10", "A.5.15"]
    assert sorted(ids, key=_control_sort_key) == [
        "A.5.15", "A.8.3", "A.8.10", "A.8.20",
    ]


def test_mixed_id_shapes_do_not_raise():
    """CERT-In roman numerals and DPDP section refs share the sort with the rest."""
    ids = ["VI", "8(5)", "16", "III"]
    assert sorted(ids, key=_control_sort_key) == ["8(5)", "16", "III", "VI"]


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

def test_html_is_empty_when_nothing_is_mapped(mapped):
    mapped({})
    assert render_compliance_html(_scan([_execution("C-1", CheckStatus.PASSED)]), _escape) == ""


def test_html_contains_control_status_and_evidence(mapped):
    mapped({"C-1": {"ISO_27001": ["A.8.20"]}})
    scan = _scan([_execution("C-1", CheckStatus.FAILED)], [_finding("C-1")])

    html = render_compliance_html(scan, _escape)
    assert "Compliance Mapping" in html
    assert "A.8.20" in html
    assert "Networks security" in html
    assert "FAIL" in html
    assert "C-1 (1)" in html  # evidence column: check ID with its finding count
    # The caveat must travel with the table, not just live in the module.
    assert "Clauses 4-10" in html


def test_html_marks_unevaluated_controls_as_not_assessed(mapped):
    mapped({"C-1": {"ISO_27001": ["A.8.20"]}})
    scan = _scan([_execution("C-1", CheckStatus.ERRORED, error_message="403")])

    html = render_compliance_html(scan, _escape)
    assert "NOT ASSESSED" in html
    assert "PASS</strong>" not in html


def test_html_escapes_control_titles(mapped):
    """Titles are curated, but the escaper must actually be applied to them."""
    mapped({"C-1": {"ISO_27001": ["<script>"]}})
    scan = _scan([_execution("C-1", CheckStatus.PASSED)])

    html = render_compliance_html(scan, _escape)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_html_notes_unmapped_checks(mapped):
    mapped({"C-1": {"ISO_27001": ["A.8.20"]}})
    scan = _scan(
        [_execution("C-1", CheckStatus.PASSED), _execution("BIL-999", CheckStatus.PASSED)]
    )

    assert "1 check(s) in this scan are not mapped" in render_compliance_html(scan, _escape)


# ---------------------------------------------------------------------------
# Against the live catalog
# ---------------------------------------------------------------------------

def test_live_catalog_produces_a_report():
    """End-to-end against the real registry, not a stubbed mapping."""
    from backend.checks.registry import get_all_checks

    tagged = [c for c in get_all_checks().values() if c.compliance_refs]
    assert tagged, "no check in the catalog carries compliance_refs"

    executions = [
        _execution(check.id, CheckStatus.PASSED, title=check.title)
        for check in tagged[:40]
    ]
    data = build_compliance_summary(_scan(executions))

    assert data["frameworks"]
    for framework in data["frameworks"]:
        assert framework["key"] in FRAMEWORKS
        assert framework["controls"]
        assert all(c["status"] == "passed" for c in framework["controls"])


def test_every_catalog_mapping_is_well_formed():
    """A typo'd framework key would silently drop checks out of the report."""
    from backend.checks.registry import get_all_checks

    for check_id, check in get_all_checks().items():
        for framework, controls in check.compliance_refs.items():
            assert framework in FRAMEWORKS, (
                f"{check_id} references unknown framework {framework!r}"
            )
            assert isinstance(controls, list) and controls, (
                f"{check_id} has an empty control list for {framework}"
            )
            for control_id in controls:
                assert isinstance(control_id, str) and control_id.strip(), (
                    f"{check_id} has a blank control ID under {framework}"
                )


def test_iso_and_certin_control_ids_have_titles():
    """An untitled control renders as a bare ID, which reads as a gap to an auditor."""
    from backend.checks.registry import get_all_checks

    missing = set()
    for check in get_all_checks().values():
        for framework, controls in check.compliance_refs.items():
            # CIS recommendation numbers are self-describing and deliberately
            # untitled; the named-control frameworks are not.
            if framework == "CIS_GCP_V3":
                continue
            titles = CONTROL_TITLES.get(framework, {})
            missing.update(
                f"{framework}:{c}" for c in controls if c not in titles
            )

    assert not missing, f"control IDs used without a title: {sorted(missing)}"


# ---------------------------------------------------------------------------
# API surface
# ---------------------------------------------------------------------------

class TestComplianceEndpoint:
    """GET /api/v1/scans/{id}/compliance."""

    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient

        from backend.main import app

        return TestClient(app)

    @pytest.fixture
    def stored_scan(self):
        """Put a scan carrying a real, tagged check into the shared store."""
        from backend.api.routes.scan import get_store
        from backend.checks.registry import get_all_checks

        check = next(c for c in get_all_checks().values() if c.compliance_refs)
        scan = _scan([
            _execution(check.id, CheckStatus.FAILED, title=check.title)
        ], [_finding(check.id)])
        scan.id = "compliance-endpoint-scan"

        store = get_store()
        store._scans[scan.id] = scan
        yield scan, check
        store._scans.pop(scan.id, None)

    def test_returns_frameworks_for_a_stored_scan(self, client, stored_scan):
        scan, check = stored_scan
        response = client.get(f"/api/v1/scans/{scan.id}/compliance")

        assert response.status_code == 200
        data = response.json()
        assert data["frameworks"], "a tagged check must produce at least one framework"
        framework = next(
            f for f in data["frameworks"] if f["key"] in check.compliance_refs
        )
        assert framework["totals"]["failed"] >= 1
        assert framework["caveat"]

    def test_unknown_scan_is_404(self, client):
        assert client.get("/api/v1/scans/scan-does-not-exist/compliance").status_code == 404

    def test_malformed_scan_id_is_rejected(self, client):
        """scan_id reaches nothing dangerous here, but the guard must still hold."""
        response = client.get("/api/v1/scans/abc;whoami/compliance")
        assert response.status_code in (404, 422)
        assert response.status_code != 200
