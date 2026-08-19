"""Unit tests for the export system: JSON, HTML generation."""

import pytest
from datetime import datetime, timezone

from backend.core.models import (
    Scan,
    ScanSummary,
    Finding,
)
from backend.utils.report_generator import generate_html_report, _escape


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_scan(findings_count: int = 3) -> Scan:
    """Create a fake scan for testing."""
    scan_id = "scan-test-001"
    findings = []
    for i in range(findings_count):
        sev = ["critical", "high", "medium"][i % 3]
        findings.append(Finding(
            id=f"f-{i+1}",
            scan_id=scan_id,
            check_id=f"TEST-{i+1:03d}",
            title=f"Test finding {i+1}",
            description=f"Description for finding {i+1}",
            severity=sev,
            category="security" if i % 2 == 0 else "cost",
            service="TestService",
            resource_name=f"resource-{i+1}",
            project_id="test-project",
            current_state=f"Bad state {i+1}",
            recommended_state=f"Good state {i+1}",
            fix_command=f"gcloud fix --resource={i+1}" if i % 2 == 0 else "",
            references=[f"https://example.com/ref-{i+1}"],
        ))

    summary = ScanSummary(
        total_findings=findings_count,
        by_severity={"critical": 1, "high": 1, "medium": 1, "low": 0, "info": 0},
        by_category={"security": 2, "cost": 1, "reliability": 0, "performance": 0, "operations": 0},
        by_service={"TestService": findings_count},
        checks_passed=7,
        checks_failed=3,
        checks_errored=0,
        checks_skipped=0,
        scan_duration_seconds=12,
    )

    return Scan(
        id=scan_id,
        scope="project",
        target_id="test-project",
        status="completed",
        categories=["security"],
        started_at=datetime(2026, 2, 7, 10, 0, 0, tzinfo=timezone.utc),
        completed_at=datetime(2026, 2, 7, 10, 0, 12, tzinfo=timezone.utc),
        summary=summary,
        findings=findings,
        projects_scanned=["test-project"],
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestHtmlReport:
    def test_report_contains_title(self):
        scan = _make_scan()
        html = generate_html_report(scan)
        assert "DEMOCRATIZED REVIEWER" in html

    def test_report_contains_findings(self):
        scan = _make_scan()
        html = generate_html_report(scan)
        assert "Test finding 1" in html
        assert "Test finding 2" in html
        assert "Test finding 3" in html

    def test_report_contains_fix_commands(self):
        scan = _make_scan()
        html = generate_html_report(scan)
        assert "gcloud fix --resource=1" in html

    def test_report_contains_severity_badges(self):
        scan = _make_scan()
        html = generate_html_report(scan)
        assert "CRITICAL" in html
        assert "HIGH" in html
        assert "MEDIUM" in html

    def test_report_contains_interactive_js(self):
        # The current report ships toggle + copy. Filter-bar JS is not yet implemented.
        scan = _make_scan()
        html = generate_html_report(scan)
        assert "toggleDetail" in html
        assert "copyFix" in html

    @pytest.mark.xfail(reason="Filter bar in HTML report not yet implemented", strict=False)
    def test_report_has_filter_bar(self):
        scan = _make_scan()
        html = generate_html_report(scan)
        assert "search-input" in html
        assert "severity-filter" in html
        assert "category-filter" in html

    def test_report_no_findings(self):
        scan = _make_scan(findings_count=0)
        scan.summary.total_findings = 0
        scan.summary.by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        html = generate_html_report(scan)
        assert "looks clean" in html

    def test_report_contains_svg_chart(self):
        scan = _make_scan()
        html = generate_html_report(scan)
        assert "<svg" in html
        assert "<rect" in html

    def test_report_contains_category_section(self):
        scan = _make_scan()
        html = generate_html_report(scan)
        assert "By Category" in html
        assert "By Service" in html

    def test_report_references(self):
        scan = _make_scan()
        html = generate_html_report(scan)
        assert "example.com/ref-1" in html


class TestEscape:
    def test_escape_html(self):
        assert _escape("<script>alert('xss')</script>") == "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"

    def test_escape_empty(self):
        assert _escape("") == ""

    def test_escape_none(self):
        assert _escape(None) == ""

    def test_escape_ampersand(self):
        assert _escape("a & b") == "a &amp; b"



class TestHtmlReportComplianceSection:
    """The compliance regrouping as it reaches an actual exported report."""

    def _scan_with_a_tagged_check(self) -> Scan:
        from backend.checks.registry import get_all_checks
        from backend.core.models import CheckExecution, CheckStatus

        check = next(c for c in get_all_checks().values() if c.compliance_refs)
        scan = _make_scan(findings_count=0)
        scan.check_executions = [CheckExecution(
            check_id=check.id,
            check_title=check.title,
            service_category=check.service_category,
            status=CheckStatus.PASSED,
        )]
        return scan

    def test_section_is_rendered_for_a_tagged_scan(self):
        html = generate_html_report(self._scan_with_a_tagged_check())
        assert "Compliance Mapping" in html

    def test_section_is_absent_when_nothing_is_tagged(self):
        """An empty compliance table would read as "no controls apply", which is a lie."""
        html = generate_html_report(_make_scan())  # no check_executions at all
        assert "Compliance Mapping" not in html

    def test_report_survives_a_broken_compliance_section(self, monkeypatch):
        """A bug in the compliance renderer must not cost the customer their report."""
        def boom(*_args, **_kwargs):
            raise RuntimeError("compliance renderer exploded")

        monkeypatch.setattr("backend.utils.report_generator.render_compliance_html", boom)
        html = generate_html_report(self._scan_with_a_tagged_check())
        assert "DEMOCRATIZED REVIEWER" in html
        assert "Compliance Mapping" not in html
