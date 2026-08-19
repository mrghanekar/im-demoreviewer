"""HTML report generator for scan results.

Produces a self-contained HTML report with embedded CSS and JS
suitable for viewing in a browser, emailing, or printing.
"""

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from backend.utils.compliance_report import render_compliance_html

if TYPE_CHECKING:
    from backend.core.models import Scan

logger = logging.getLogger(__name__)


SEVERITY_COLORS = {
    "critical": "#f85149",
    "high": "#d29922",
    "medium": "#58a6ff",
    "low": "#8b949e",
    "info": "#6e7681",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

CATEGORY_COLORS = {
    "security": "#f85149",
    "reliability": "#d29922",
    "performance": "#58a6ff",
    "cost": "#00ff41",
    "operations": "#bc8cff",
}


def generate_html_report(scan: "Scan") -> str:
    """Generate a self-contained HTML report from scan results.

    Args:
        scan: Completed scan with findings and summary.

    Returns:
        HTML string for the full report.
    """
    summary = scan.summary
    findings = scan.findings

    # Sort findings by severity
    severity_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    sorted_findings = sorted(findings, key=lambda f: severity_rank.get(f.severity, 99))

    # Collect unique projects for dropdown
    project_ids = sorted(list({f.project_id for f in findings if f.project_id}))
    project_options = '<option value="">Entire Org / All Projects</option>'
    for pid in project_ids:
        project_options += f'<option value="{_escape_attr(pid)}">{_escape(pid)}</option>'

    # Build findings rows grouped by project
    findings_by_project = {}
    for f in sorted_findings:
        pid = f.project_id or "Unknown Project"
        if pid not in findings_by_project:
            findings_by_project[pid] = []
        findings_by_project[pid].append(f)

    project_sections = ""
    for pid, p_findings in sorted(findings_by_project.items()):
        p_rows = ""
        for idx, f in enumerate(p_findings):
            unique_id = f"{_escape_attr(pid)}-{idx}"
            color = SEVERITY_COLORS.get(f.severity, "#8b949e")
            fix_html = (
                f'<div class="fix-cmd"><span class="fix-label">Fix Command:</span>'
                f'<pre><code>{_escape(f.fix_command)}</code></pre>'
                f'<button class="copy-btn" onclick="copyFix(this)" data-cmd="{_escape_attr(f.fix_command)}">Copy</button></div>'
                if f.fix_command
                else ""
            )
            refs_html = ""
            if f.references:
                ref_links = "".join(
                    f'<a href="{_escape_attr(r)}" target="_blank" rel="noopener">{_escape(r)}</a><br>'
                    for r in f.references
                )
                refs_html = f'<div class="refs"><span class="fix-label">References:</span>{ref_links}</div>'

            cost_cell = (
                f'<span class="cost-badge">${f.estimated_monthly_cost_usd:,.0f}/mo</span>'
                if f.estimated_monthly_cost_usd
                else ""
            )
            cost_hint_html = (
                f'<div class="cost-hint"><span class="fix-label">Cost Hint:</span> '
                f'<strong>${f.estimated_monthly_cost_usd:,.2f}/mo</strong> &mdash; '
                f'{_escape(f.cost_basis)}</div>'
                if f.estimated_monthly_cost_usd
                else ""
            )

            p_rows += f"""
            <tr class="finding-row" onclick="toggleDetail('detail-{unique_id}')">
                <td><span class="badge" style="background-color: {color}">{f.severity.upper()}</span></td>
                <td class="mono">{_escape(f.check_id)}</td>
                <td>{_escape(f.title)}</td>
                <td class="resource-cell"><code>{_escape(f.resource_name)}</code></td>
                <td><span class="cat-badge" style="color: {CATEGORY_COLORS.get(f.category, '#8b949e')}">{_escape(f.category)}</span></td>
                <td>{cost_cell}</td>
            </tr>
            <tr class="detail-row" id="detail-{unique_id}">
                <td colspan="6">
                    <div class="finding-detail">
                        {f'<p class="desc">{_escape(f.description)}</p>' if f.description else ''}
                        <div class="detail-grid">
                            <div class="detail-box bad">
                                <span class="detail-label">Current State</span>
                                <span>{_escape(f.current_state)}</span>
                            </div>
                            <div class="detail-box good">
                                <span class="detail-label">Recommended</span>
                                <span>{_escape(f.recommended_state)}</span>
                            </div>
                        </div>
                        {cost_hint_html}
                        {fix_html}
                        {refs_html}
                        {f'<a class="console-link" href="{_escape_attr(f.resource_link)}" target="_blank" rel="noopener">Open in Cloud Console &rarr;</a>' if f.resource_link else ''}
                    </div>
                </td>
            </tr>
            """
        
        project_sections += f"""
        <div class="project-section">
            <button class="project-header" onclick="toggleProject('{_escape_attr(pid)}')">
                <span class="project-title">Project: {_escape(pid)}</span>
                <span class="count-badge">{len(p_findings)} findings</span>
                <span class="chevron" id="chev-{_escape_attr(pid)}">&#9660;</span>
            </button>
            <div class="project-content" id="proj-{_escape_attr(pid)}">
                <table>
                    <thead>
                        <tr>
                            <th style="width:90px">Severity</th>
                            <th style="width:80px">Check</th>
                            <th>Title</th>
                            <th>Resource</th>
                            <th style="width:100px">Category</th>
                            <th style="width:90px">Cost / mo</th>
                        </tr>
                    </thead>
                    <tbody>
                        {p_rows}
                    </tbody>
                </table>
            </div>
        </div>
        """

    # Build summary items
    severity_items = ""
    for s in SEVERITY_ORDER:
        count = summary.by_severity.get(s, 0)
        color = SEVERITY_COLORS.get(s, "#8b949e")
        severity_items += f'<div class="stat-card" style="border-top: 3px solid {color}"><span class="stat-value" style="color:{color}">{count}</span><span class="stat-label">{s}</span></div>'

    category_items = ""
    for c, count in sorted(summary.by_category.items(), key=lambda x: x[1], reverse=True):
        if count > 0:
            color = CATEGORY_COLORS.get(c, "#8b949e")
            category_items += f'<div class="stat-card"><span class="stat-value" style="color:{color}">{count}</span><span class="stat-label">{c}</span></div>'

    service_items = ""
    for s, count in sorted(summary.by_service.items(), key=lambda x: x[1], reverse=True):
        if count > 0:
            service_items += f'<div class="stat-card"><span class="stat-value">{count}</span><span class="stat-label">{s}</span></div>'

    # SVG severity bar chart
    svg_bars = _build_severity_svg(summary)

    # Findings regrouped by audit control. Empty string when nothing in this
    # scan carries a framework mapping, so an untagged scan doesn't render a
    # hollow "Compliance" heading that implies coverage it doesn't have.
    try:
        compliance_section = render_compliance_html(scan, _escape)
    # A report must still render even if the compliance regrouping cannot.
    except Exception:
        logger.exception("Compliance section failed to render for scan %s", scan.id)
        compliance_section = ""

    # Notice line shown above the Summary block when the user has run the
    # Gemini-powered Cost Saving analysis. Quietly omitted otherwise.
    cost_notice = ""
    if (
        getattr(scan, "cost_analysis", None)
        and scan.cost_analysis is not None
        and scan.cost_analysis.status == "completed"
    ):
        ca = scan.cost_analysis
        when = ca.completed_at.strftime("%Y-%m-%d %H:%M UTC") if ca.completed_at else "—"
        cost_notice = (
            f'<p style="margin: 1rem 0 0; color: #00ff41; font-size: 0.85rem;">'
            f'Cost figures below were generated by '
            f'<strong>{_escape(ca.model)}</strong> with Google Search grounding on {when}. '
            f'{ca.costed_count} of {ca.findings_count} resources had a measurable monthly cost.'
            f'</p>'
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Democratized Reviewer Report - {_escape(scan.target_id)}</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0d1117; color: #e6edf3; line-height: 1.6; padding: 2rem; }}
    .container {{ max-width: 1300px; margin: 0 auto; }}
    h1 {{ color: #00ff41; font-family: 'Courier New', monospace; margin-bottom: 0.25rem; font-size: 1.5rem; }}
    h2 {{ color: #58a6ff; margin: 2rem 0 1rem; border-bottom: 1px solid #30363d; padding-bottom: 0.5rem; font-size: 1.1rem; }}
    .meta {{ color: #8b949e; margin-bottom: 1.5rem; font-size: 0.85rem; }}
    .mono {{ font-family: 'Courier New', monospace; font-size: 0.85rem; }}

    /* Stats Grid */
    .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(100px, 1fr)); gap: 0.75rem; margin: 0.75rem 0; }}
    .stat-card {{ text-align: center; padding: 0.75rem; background: #161b22; border-radius: 8px; border: 1px solid #30363d; }}
    .stat-value {{ display: block; font-size: 1.5rem; font-weight: bold; font-family: 'Courier New', monospace; }}
    .stat-label {{ display: block; color: #8b949e; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; }}

    /* Chart */
    .chart-row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin: 1rem 0; }}

    /* Project Sections */
    .project-section {{ margin-bottom: 1rem; border: 1px solid #30363d; border-radius: 8px; overflow: hidden; }}
    .project-header {{ width: 100%; display: flex; align-items: center; justify-content: space-between; padding: 1rem; background: #161b22; border: none; color: #e6edf3; cursor: pointer; text-align: left; transition: background 0.15s; }}
    .project-header:hover {{ background: #21262d; }}
    .project-title {{ font-weight: bold; font-family: 'Courier New', monospace; }}
    .chevron {{ transition: transform 0.2s; }}
    .chevron.rotate {{ transform: rotate(180deg); }}
    .project-content {{ display: none; background: #0d1117; border-top: 1px solid #30363d; }}
    .project-content.open {{ display: block; }}

    /* Table */
    table {{ width: 100%; border-collapse: collapse; margin: 0; font-size: 0.85rem; }}
    th {{ background: #161b22; color: #8b949e; text-align: left; padding: 0.6rem 0.75rem; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 2px solid #30363d; }}
    td {{ padding: 0.6rem 0.75rem; border-bottom: 1px solid #21262d; }}
    .finding-row {{ cursor: pointer; transition: background 0.15s; }}
    .finding-row:hover {{ background: #161b22; }}
    .detail-row {{ display: none; }}
    .detail-row.open {{ display: table-row; }}
    .detail-row td {{ padding: 1rem 1.5rem; background: #0d1117; border-bottom: 2px solid #30363d; }}
    .resource-cell {{ max-width: 220px; }}
    .resource-cell code {{ word-break: break-all; }}

    /* Finding Detail */
    .finding-detail {{ max-width: 900px; }}
    .desc {{ color: #8b949e; margin-bottom: 0.75rem; font-size: 0.85rem; }}
    .detail-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 0.75rem; }}
    .detail-box {{ padding: 0.75rem; border-radius: 6px; font-size: 0.85rem; }}
    .detail-box.bad {{ background: rgba(248,81,73,0.08); border: 1px solid rgba(248,81,73,0.2); }}
    .detail-box.good {{ background: rgba(0,255,65,0.05); border: 1px solid rgba(0,255,65,0.15); }}
    .detail-label {{ display: block; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; color: #8b949e; margin-bottom: 0.25rem; }}
    .fix-cmd {{ margin: 0.75rem 0; }}
    .fix-cmd pre {{ background: #161b22; padding: 0.75rem; border-radius: 6px; overflow-x: auto; border: 1px solid #30363d; margin: 0.25rem 0; }}
    .fix-cmd code {{ color: #00ff41; font-family: 'Courier New', monospace; font-size: 0.8rem; }}
    .fix-label {{ font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; color: #8b949e; }}
    .copy-btn {{ background: #21262d; border: 1px solid #30363d; color: #8b949e; padding: 0.25rem 0.5rem; border-radius: 4px; cursor: pointer; font-size: 0.7rem; margin-left: 0.5rem; }}
    .copy-btn:hover {{ color: #e6edf3; border-color: #58a6ff; }}
    .refs {{ margin-top: 0.5rem; }}
    .refs a {{ color: #58a6ff; font-size: 0.8rem; text-decoration: none; }}
    .refs a:hover {{ text-decoration: underline; }}
    .console-link {{ display: inline-block; margin-top: 0.5rem; color: #58a6ff; font-size: 0.8rem; text-decoration: none; }}
    .console-link:hover {{ text-decoration: underline; }}

    .badge {{ padding: 0.2rem 0.6rem; border-radius: 12px; color: white; font-size: 0.65rem; font-weight: bold; text-transform: uppercase; white-space: nowrap; }}
    .cat-badge {{ font-size: 0.75rem; text-transform: capitalize; font-weight: 600; }}
    .cost-badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 10px; background: rgba(0,255,65,0.1); color: #00ff41; font-family: 'Courier New', monospace; font-size: 0.75rem; font-weight: bold; white-space: nowrap; }}
    .cost-hint {{ margin: 0.5rem 0; padding: 0.6rem 0.75rem; background: rgba(0,255,65,0.05); border: 1px solid rgba(0,255,65,0.2); border-radius: 6px; color: #00ff41; font-size: 0.8rem; }}
    .cost-hint strong {{ color: #00ff41; font-family: 'Courier New', monospace; }}
    code {{ background: #161b22; padding: 0.1rem 0.3rem; border-radius: 4px; font-size: 0.8rem; color: #e6edf3; }}
    .count-badge {{ background: #21262d; padding: 0.15rem 0.5rem; border-radius: 10px; font-size: 0.75rem; color: #8b949e; margin-left: 0.5rem; }}

    .footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #30363d; color: #8b949e; text-align: center; font-size: 0.8rem; }}
    
    @media print {{
        @page {{ margin: 1cm; size: A4; }}
        body {{ background: white !important; color: #1a1a1a !important; padding: 0 !important; font-size: 9pt !important; -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }}
        .container {{ max-width: none !important; width: 100% !important; margin: 0 !important; }}
        
        /* Elements to hide */
        .copy-btn, .console-link, button {{ display: none !important; }}
        
        /* Typography */
        h1 {{ color: #2ea043 !important; font-size: 18pt !important; margin-bottom: 0.5cm !important; }}
        h2 {{ color: #0969da !important; font-size: 14pt !important; border-bottom: 2px solid #d0d7de !important; margin-top: 1cm !important; page-break-after: avoid; }}
        .meta {{ color: #57606a !important; font-size: 8pt !important; margin-bottom: 1cm !important; }}
        
        /* Stats Cards */
        .stats-grid {{ gap: 0.5cm !important; display: flex !important; flex-wrap: wrap !important; justify-content: flex-start !important; }}
        .stat-card {{ 
            background: #f6f8fa !important; 
            border: 1px solid #d0d7de !important; 
            padding: 0.5cm !important; 
            min-width: 120px !important;
            box-shadow: none !important;
            break-inside: avoid !important;
        }}
        .stat-value {{ color: #1f2328 !important; font-size: 16pt !important; }}
        
        /* Project Sections - Force open for print */
        .project-section {{ border: none !important; margin-bottom: 2cm !important; break-inside: avoid; }}
        .project-header {{ background: #f6f8fa !important; color: #24292f !important; border-bottom: 2px solid #d0d7de !important; }}
        .project-content {{ display: block !important; border: none !important; }}
        .chevron {{ display: none !important; }}
        
        /* Tables */
        table {{ width: 100% !important; font-size: 8pt !important; table-layout: fixed !important; }}
        th {{ background: #f6f8fa !important; color: #24292f !important; border-bottom: 2px solid #d0d7de !important; font-weight: bold !important; }}
        td {{ border-bottom: 1px solid #d0d7de !important; padding: 0.3cm !important; }}
        
        /* Finding Rows */
        .finding-row {{ page-break-inside: avoid !important; break-inside: avoid !important; }}
        .detail-row {{ display: table-row !important; page-break-inside: avoid !important; break-inside: avoid !important; }}
        .detail-row td {{ background: #ffffff !important; border-bottom: 2px solid #d0d7de !important; }}
        
        /* Details */
        .detail-grid {{ display: block !important; }}
        .detail-box {{ margin-bottom: 0.2cm !important; border: 1px solid #d0d7de !important; page-break-inside: avoid; }}
        .detail-box.bad {{ background: #ffebe9 !important; border-color: #ff8182 !important; }}
        .detail-box.good {{ background: #dafbe1 !important; border-color: #4ac26b !important; }}
        
        /* Code blocks */
        code, pre {{ 
            background: #f6f8fa !important; 
            color: #24292f !important; 
            border: 1px solid #d0d7de !important; 
            white-space: pre-wrap !important; 
            word-break: break-all !important; 
            font-family: 'Courier New', monospace !important;
        }}
        .fix-cmd pre {{ padding: 0.3cm !important; }}
        
        /* Badges */
        .badge {{ 
            border: 1px solid #d0d7de !important; 
            color: #000 !important; 
            background: #fff !important; 
            font-weight: bold !important;
        }}
        
        /* Chart row */
        .chart-row {{ display: block !important; page-break-inside: avoid; }}
    }}
</style>
</head>
<body>
<div class="container">
    <h1>// DEMOCRATIZED REVIEWER</h1>
    <p class="meta">
        Scan <strong>{_escape(scan.id)}</strong> &bull;
        {_escape(scan.scope).upper()}: <strong>{_escape(scan.target_id)}</strong> &bull;
        {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} &bull;
        {len(scan.projects_scanned)} project(s) scanned
    </p>

    <div style="margin: 2rem 0;">
        <h2 style="margin-top:0; border: none;">Severity Breakdown</h2>
        <div class="stats-grid">{severity_items}</div>
        {svg_bars}
    </div>

    {cost_notice}
    <h2>Summary</h2>
    <div class="stats-grid">
        <div class="stat-card"><span class="stat-value">{summary.total_findings}</span><span class="stat-label">Total Findings</span></div>
        <div class="stat-card"><span class="stat-value" style="color: #00ff41">{summary.checks_passed}</span><span class="stat-label">Passed</span></div>
        <div class="stat-card"><span class="stat-value" style="color: #f85149">{summary.checks_failed}</span><span class="stat-label">Failed</span></div>
        <div class="stat-card"><span class="stat-value" style="color: #d29922">{summary.checks_errored}</span><span class="stat-label">Errored</span></div>
        <div class="stat-card"><span class="stat-value">{summary.checks_skipped}</span><span class="stat-label">Skipped</span></div>
        <div class="stat-card"><span class="stat-value">{summary.scan_duration_seconds}s</span><span class="stat-label">Duration</span></div>
        {f'<div class="stat-card"><span class="stat-value" style="color: #00ff41">${summary.estimated_monthly_waste_usd:,.0f}</span><span class="stat-label">Est. Waste / mo</span></div>' if summary.estimated_monthly_waste_usd > 0 else ''}
    </div>

    <div class="chart-row">
        <div>
            <h2>By Category</h2>
            <div class="stats-grid">{category_items}</div>
        </div>
        <div>
            <h2>By Service</h2>
            <div class="stats-grid">{service_items if service_items else '<div class="stat-card"><span class="stat-value">0</span><span class="stat-label">No findings</span></div>'}</div>
        </div>
    </div>

    <h2>Project Findings <span class="count-badge">{len(sorted_findings)}</span></h2>

    <div class="project-list">
        {project_sections if project_sections else '<div style="text-align:center; color: #00ff41; padding: 2rem; font-family: monospace;">&#10003; No findings &mdash; your cloud environment looks clean!</div>'}
    </div>

    {compliance_section}

    <div class="footer">
        <p>Generated by <strong>Democratized Reviewer v0.1.0</strong> &bull; {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>
        <p style="margin-top:0.25rem; font-size:0.75rem;">All checks use viewer-only IAM roles. No infrastructure was modified.</p>
    </div>
</div>

<script>
function toggleDetail(id) {{
    var el = document.getElementById(id);
    if (el) el.classList.toggle('open');
}}

function toggleProject(id) {{
    var content = document.getElementById('proj-' + id);
    var chev = document.getElementById('chev-' + id);
    if (content) content.classList.toggle('open');
    if (chev) chev.classList.toggle('rotate');
}}

function copyFix(btn) {{
    var cmd = btn.getAttribute('data-cmd');
    if (navigator.clipboard) {{
        navigator.clipboard.writeText(cmd).then(function() {{
            btn.textContent = 'Copied!';
            setTimeout(function() {{ btn.textContent = 'Copy'; }}, 2000);
        }});
    }}
}}
</script>
</body>
</html>"""


def generate_pdf_report(scan: "Scan") -> bytes:
    """Generate a PDF report from scan results using WeasyPrint.

    Args:
        scan: Completed scan object.

    Returns:
        Bytes of the PDF file.
    """
    from weasyprint import HTML

    summary = scan.summary
    findings = scan.findings

    # Group findings by project
    findings_by_project = {}
    for f in findings:
        pid = f.project_id or "Unknown Project"
        if pid not in findings_by_project:
            findings_by_project[pid] = []
        findings_by_project[pid].append(f)

    # Org Summary Section
    org_summary_html = f"""
    <div class="header">
        <h1>// DEMOCRATIZED REVIEWER</h1>
        <p><strong>Scan Report:</strong> {_escape(scan.id)} &bull; {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>
        <p><strong>Target:</strong> {_escape(scan.target_id)} ({_escape(scan.scope)})</p>
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <div class="stats-grid">
            <div class="stat-box">
                <span class="stat-val">{summary.total_findings}</span>
                <span class="stat-lbl">Total Findings</span>
            </div>
            <div class="stat-box">
                <span class="stat-val" style="color:#d73a49">{summary.by_severity.get('critical', 0)}</span>
                <span class="stat-lbl">Critical</span>
            </div>
            <div class="stat-box">
                <span class="stat-val" style="color:#b08800">{summary.by_severity.get('high', 0)}</span>
                <span class="stat-lbl">High</span>
            </div>
            <div class="stat-box">
                <span class="stat-val" style="color:#0366d6">{summary.by_severity.get('medium', 0)}</span>
                <span class="stat-lbl">Medium</span>
            </div>
            <div class="stat-box">
                <span class="stat-val" style="color:#6a737d">{summary.by_severity.get('low', 0)}</span>
                <span class="stat-lbl">Low</span>
            </div>
        </div>
        
        <h3>Category Breakdown</h3>
        <table class="summary-table">
            <tr><th>Category</th><th>Count</th></tr>
            {''.join(f'<tr><td>{k.capitalize()}</td><td>{v}</td></tr>' for k, v in summary.by_category.items() if v > 0)}
        </table>
    </div>
    """

    # Project Sections
    project_pages = ""
    for pid, p_findings in sorted(findings_by_project.items()):
        # Sort findings by severity
        severity_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        p_findings.sort(key=lambda f: severity_rank.get(f.severity, 99))

        p_rows = ""
        for f in p_findings:
            color = SEVERITY_COLORS.get(f.severity, "#000")
            p_rows += f"""
            <div class="finding-block">
                <div class="finding-header" style="border-left: 4px solid {color}">
                    <span class="badge" style="background:{color}">{f.severity.upper()}</span>
                    <span class="finding-title">{_escape(f.title)}</span>
                    <span class="check-id">{_escape(f.check_id)}</span>
                </div>
                <div class="finding-body">
                    <p><strong>Resource:</strong> <code style="background:#f6f8fa;padding:2px 4px;">{_escape(f.resource_name)}</code></p>
                    <p>{_escape(f.description)}</p>
                    <div class="detail-grid">
                        <div>
                            <span class="lbl">Current State:</span>
                            <div class="val text-red">{_escape(f.current_state)}</div>
                        </div>
                        <div>
                            <span class="lbl">Recommended:</span>
                            <div class="val text-green">{_escape(f.recommended_state)}</div>
                        </div>
                    </div>
                    {f'<div class="fix-block"><span class="lbl">Fix:</span><pre>{_escape(f.fix_command)}</pre></div>' if f.fix_command else ''}
                </div>
            </div>
            """

        project_pages += f"""
        <div class="page-break"></div>
        <div class="project-header">
            <h2>Project: {_escape(pid)}</h2>
            <p>{len(p_findings)} findings identified</p>
        </div>
        {p_rows}
        """

    full_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
    <style>
        @page {{ size: A4; margin: 2cm; }}
        body {{ font-family: sans-serif; font-size: 10pt; color: #24292e; line-height: 1.4; }}
        h1 {{ color: #24292e; border-bottom: 2px solid #eaecef; padding-bottom: 10px; }}
        h2 {{ color: #0366d6; margin-top: 20px; }}
        .header {{ margin-bottom: 30px; }}
        .stats-grid {{ display: flex; gap: 10px; margin-bottom: 20px; }}
        .stat-box {{ border: 1px solid #e1e4e8; padding: 10px; border-radius: 6px; text-align: center; flex: 1; }}
        .stat-val {{ display: block; font-size: 18pt; font-weight: bold; }}
        .stat-lbl {{ display: block; font-size: 8pt; color: #586069; text-transform: uppercase; }}
        .summary-table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        .summary-table th {{ text-align: left; background: #f6f8fa; padding: 5px; }}
        .summary-table td {{ padding: 5px; border-bottom: 1px solid #eaecef; }}
        
        .page-break {{ page-break-before: always; }}
        .project-header {{ margin-bottom: 20px; border-bottom: 2px solid #0366d6; padding-bottom: 10px; }}
        
        .finding-block {{ margin-bottom: 20px; border: 1px solid #e1e4e8; border-radius: 6px; page-break-inside: avoid; }}
        .finding-header {{ padding: 10px; background: #f6f8fa; border-bottom: 1px solid #e1e4e8; display: flex; align-items: center; gap: 10px; }}
        .finding-body {{ padding: 15px; }}
        .badge {{ color: white; padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 8pt; }}
        .finding-title {{ font-weight: bold; flex: 1; }}
        .check-id {{ font-family: monospace; color: #586069; }}
        
        .detail-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin: 10px 0; }}
        .lbl {{ font-size: 8pt; font-weight: bold; color: #586069; text-transform: uppercase; }}
        .text-red {{ color: #d73a49; }}
        .text-green {{ color: #28a745; }}
        .fix-block pre {{ background: #f6f8fa; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 8pt; margin-top: 5px; border: 1px solid #e1e4e8; white-space: pre-wrap; }}
    </style>
    </head>
    <body>
        {org_summary_html}
        {project_pages}
        <div style="margin-top: 50px; text-align: center; color: #586069; font-size: 8pt;">
            Generated by Democratized Reviewer &bull; All checks performed with viewer-only permissions.
        </div>
    </body>
    </html>
    """
    
    return HTML(string=full_html).write_pdf()


def _build_severity_svg(summary) -> str:
    """Build an inline SVG horizontal bar chart for severity distribution."""
    total = sum(summary.by_severity.get(s, 0) for s in SEVERITY_ORDER)
    if total == 0:
        return ""

    bars = ""
    x = 0
    width = 400
    height = 24
    for sev in SEVERITY_ORDER:
        count = summary.by_severity.get(sev, 0)
        if count == 0:
            continue
        bar_width = max(2, (count / total) * width)
        color = SEVERITY_COLORS.get(sev, "#8b949e")
        bars += f'<rect x="{x}" y="0" width="{bar_width}" height="{height}" fill="{color}" rx="3"/>'
        if bar_width > 30:
            bars += f'<text x="{x + bar_width / 2}" y="{height / 2 + 1}" text-anchor="middle" dominant-baseline="middle" fill="white" font-size="10" font-weight="bold" font-family="monospace">{count}</text>'
        x += bar_width

    return f'<svg viewBox="0 0 {width} {height}" style="width:100%;max-width:{width}px;height:{height}px;margin-top:0.5rem;border-radius:4px;overflow:hidden">{bars}</svg>'


def _escape(text: str) -> str:
    """HTML-escape a string."""
    if not text:
        return ""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def _escape_attr(text: str) -> str:
    """Escape for use in HTML attributes."""
    if not text:
        return ""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )
