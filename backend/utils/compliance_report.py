"""Regroup a scan by compliance control instead of by service.

A scan answers "what is wrong with my Cloud Storage?". An audit asks the
transpose: "what is your evidence for ISO 27001 A.8.20, and is any of it
failing?". Same findings, different index.

The status of a control is derived from the checks mapped to it, and the
derivation is deliberately conservative:

* ``failed``  — at least one mapped check produced findings. Something under
  this control is demonstrably misconfigured.
* ``partial`` — no mapped check failed, but at least one could not be
  evaluated (denied, errored) while at least one passed. Some evidence, not
  all of it.
* ``not_assessed`` — nothing under this control could be evaluated. Reporting
  this as a pass is the failure mode this whole module exists to avoid.
* ``passed``  — every mapped check ran and produced no findings.

A ``passed`` control means the technical configuration this tool can observe
is correct. It is not a statement that the organisation satisfies the control,
which for most frameworks also requires documented process the scanner cannot
see. :data:`backend.core.compliance.FRAMEWORK_CAVEATS` carries that disclaimer
into the rendered report.
"""

from typing import TYPE_CHECKING, Any

from backend.core.compliance import (
    FRAMEWORK_CAVEATS,
    FRAMEWORKS,
    control_title,
    framework_title,
)

if TYPE_CHECKING:
    from backend.core.models import Scan

# CheckStatus values that mean "we did not get an answer".
_INCONCLUSIVE = frozenset({"errored", "skipped", "pending", "running"})

CONTROL_STATUS_ORDER = ["failed", "partial", "not_assessed", "passed"]


def _check_compliance_map() -> dict[str, dict[str, list[str]]]:
    """check_id -> compliance_refs, from the live registry."""
    from backend.checks.registry import get_all_checks

    return {
        check_id: dict(check.compliance_refs)
        for check_id, check in get_all_checks().items()
        if check.compliance_refs
    }


def _derive_status(statuses: list[str], finding_count: int) -> str:
    if finding_count:
        return "failed"
    inconclusive = [s for s in statuses if s in _INCONCLUSIVE]
    if not statuses:
        return "not_assessed"
    if len(inconclusive) == len(statuses):
        return "not_assessed"
    if inconclusive:
        return "partial"
    return "passed"


def build_compliance_summary(scan: "Scan") -> dict[str, Any]:
    """Index a scan's results by framework and control.

    Only checks that actually ran in this scan are counted. A control whose
    checks were all outside the scan's selected categories is reported as
    ``not_assessed`` rather than silently omitted — an auditor needs to see the
    gap in coverage, not a report that quietly skips it.

    Returns a dict shaped for both the JSON API and the HTML renderer::

        {
          "frameworks": [
            {"key": "ISO_27001", "title": "...", "caveat": "...",
             "totals": {"failed": 2, "partial": 0, "passed": 9, "not_assessed": 1},
             "controls": [
               {"id": "A.8.20", "title": "Networks security",
                "status": "failed", "findings_count": 3,
                "checks": [{"id": "NET-001", "status": "failed", "findings": 3}, ...]},
               ...
             ]},
            ...
          ],
          "unmapped_checks": ["BIL-006", ...],
        }
    """
    refs_by_check = _check_compliance_map()

    executions = {e.check_id: e for e in scan.check_executions}
    findings_by_check: dict[str, int] = {}
    for f in scan.findings:
        if getattr(f, "suppressed", False):
            continue
        findings_by_check[f.check_id] = findings_by_check.get(f.check_id, 0) + 1

    # framework -> control -> list of per-check records
    index: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for check_id, refs in refs_by_check.items():
        execution = executions.get(check_id)
        if execution is None:
            # The check exists in the catalog but wasn't part of this scan.
            continue
        record = {
            "id": check_id,
            "title": execution.check_title,
            "status": str(execution.status),
            "findings": findings_by_check.get(check_id, 0),
            "error": execution.error_message,
        }
        for framework, control_ids in refs.items():
            per_control = index.setdefault(framework, {})
            for control_id in control_ids:
                per_control.setdefault(control_id, []).append(record)

    frameworks: list[dict[str, Any]] = []
    for framework in FRAMEWORKS:
        controls_raw = index.get(framework)
        if not controls_raw:
            continue

        controls: list[dict[str, Any]] = []
        totals = {"failed": 0, "partial": 0, "passed": 0, "not_assessed": 0}
        for control_id in sorted(controls_raw, key=_control_sort_key):
            records = controls_raw[control_id]
            finding_count = sum(r["findings"] for r in records)
            status = _derive_status([r["status"] for r in records], finding_count)
            totals[status] += 1
            controls.append({
                "id": control_id,
                "title": control_title(framework, control_id),
                "status": status,
                "findings_count": finding_count,
                "checks": sorted(records, key=lambda r: r["id"]),
            })

        # Failing controls first: that is the order an auditor reads in.
        controls.sort(key=lambda c: (CONTROL_STATUS_ORDER.index(c["status"]),
                                     _control_sort_key(c["id"])))
        frameworks.append({
            "key": framework,
            "title": framework_title(framework),
            "caveat": FRAMEWORK_CAVEATS.get(framework, ""),
            "totals": totals,
            "controls": controls,
        })

    unmapped = sorted(
        e.check_id for e in scan.check_executions if e.check_id not in refs_by_check
    )
    return {"frameworks": frameworks, "unmapped_checks": unmapped}


_STATUS_LABELS = {
    "failed": ("FAIL", "#f85149"),
    "partial": ("PARTIAL", "#d29922"),
    "not_assessed": ("NOT ASSESSED", "#8b949e"),
    "passed": ("PASS", "#00ff41"),
}


def render_compliance_html(scan: "Scan", escape) -> str:
    """Render the compliance section as an HTML fragment.

    ``escape`` is passed in rather than imported so this module stays free of
    a circular dependency on the report generator.

    Returns an empty string when no check in the scan carries a mapping, so a
    scan of an untagged category doesn't produce an empty, misleading section.
    """
    data = build_compliance_summary(scan)
    if not data["frameworks"]:
        return ""

    blocks = []
    for framework in data["frameworks"]:
        totals = framework["totals"]
        rows = []
        for control in framework["controls"]:
            label, colour = _STATUS_LABELS[control["status"]]
            evidence = ", ".join(
                f'{escape(c["id"])}'
                + (f' ({c["findings"]})' if c["findings"] else "")
                for c in control["checks"]
            )
            rows.append(
                "<tr>"
                f'<td style="white-space:nowrap"><strong>{escape(control["id"])}</strong></td>'
                f'<td>{escape(control["title"])}</td>'
                f'<td style="color:{colour}; white-space:nowrap"><strong>{label}</strong></td>'
                f'<td style="text-align:right">{control["findings_count"]}</td>'
                f'<td style="font-size:0.8rem; color:#8b949e">{evidence}</td>'
                "</tr>"
            )

        blocks.append(f"""
        <div class="project-section">
            <div style="padding:0.75rem 1rem; background:#161b22; border-bottom:1px solid #30363d;">
                <strong>{escape(framework["title"])}</strong>
                <span style="float:right; font-size:0.85rem;">
                    <span style="color:#f85149">{totals["failed"]} failing</span> &bull;
                    <span style="color:#d29922">{totals["partial"]} partial</span> &bull;
                    <span style="color:#00ff41">{totals["passed"]} passing</span> &bull;
                    <span style="color:#8b949e">{totals["not_assessed"]} not assessed</span>
                </span>
            </div>
            <p style="margin:0; padding:0.5rem 1rem; font-size:0.78rem; color:#8b949e; border-bottom:1px solid #30363d;">
                {escape(framework["caveat"])}
            </p>
            <table style="width:100%; border-collapse:collapse;">
                <thead><tr style="text-align:left; font-size:0.78rem; color:#8b949e;">
                    <th style="padding:0.4rem 1rem;">Control</th><th>Title</th>
                    <th>Status</th><th style="text-align:right">Findings</th><th>Evidence (check IDs)</th>
                </tr></thead>
                <tbody>{"".join(rows)}</tbody>
            </table>
        </div>""")

    unmapped_note = ""
    if data["unmapped_checks"]:
        unmapped_note = (
            '<p style="font-size:0.78rem; color:#8b949e; margin-top:0.5rem;">'
            f'{len(data["unmapped_checks"])} check(s) in this scan are not mapped to '
            "any framework control and are reported only in the findings section "
            "above.</p>"
        )

    return f"""
    <h2>Compliance Mapping</h2>
    <p style="font-size:0.82rem; color:#8b949e; margin-top:-0.5rem;">
        Findings regrouped by control. A passing control means the technical
        configuration observable from the GCP APIs is correct; it is not an
        assertion that the organisation satisfies the control, which for every
        framework here also requires process evidence a configuration scan
        cannot see.
    </p>
    <div class="project-list">{"".join(blocks)}</div>
    {unmapped_note}
"""


def _control_sort_key(control_id: str) -> tuple:
    """Sort control IDs so 1.10 comes after 1.9, not after 1.1.

    Falls back to plain string ordering for IDs that aren't dotted numbers
    (``A.8.20``, ``8(5)``, ``VI``).
    """
    parts = control_id.replace("(", ".").replace(")", "").split(".")
    key: list[Any] = []
    for part in parts:
        key.append((0, int(part), "") if part.isdigit() else (1, 0, part))
    return tuple(key)
