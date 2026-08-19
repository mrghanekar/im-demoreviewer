"""Scan management API routes.

Handles creating, running, listing, and cancelling scans.
"""

import asyncio
import logging

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field

from backend.core.models import (
    Finding,
    Scan,
    ScanRequest,
    ScanSummary,
)
from backend.core.scanner import Scanner, ScanStore
from backend.api.routes.websocket import get_event_callback, generate_scan_token
from backend.api.middleware.validation import validate_scan_id, validate_target_id


async def _background_save(store: ScanStore, scan: Scan) -> None:
    """Push a save off the request path.

    Suppress toggles re-upload the entire scan JSON to GCS. For a scan with
    thousands of findings that's megabytes — synchronously blocking the
    endpoint makes the UI feel laggy. asyncio.to_thread avoids blocking the
    event loop on the sync GCS client. Last-writer-wins on bursts; that's
    acceptable because the in-memory state (returned synchronously to the
    caller) is the source of truth.
    """
    try:
        await asyncio.to_thread(store.save, scan)
    except Exception as e:
        logger.error("Background save for scan %s failed: %s", scan.id, e)


class SuppressionRequest(BaseModel):
    """Optional payload for the suppress endpoint."""
    reason: str = Field(default="", max_length=500)


def _require_scan_id(scan_id: str) -> str:
    cleaned = validate_scan_id(scan_id)
    if not cleaned:
        raise HTTPException(status_code=422, detail="Invalid scan ID")
    return cleaned

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])

# Lazy module-level singletons. Constructing at import time was loading env
# vars before tests could monkeypatch them and re-creating the store across
# uvicorn worker reloads. Build on first access instead.
_scan_store: ScanStore | None = None
_scanner: Scanner | None = None


def get_store() -> ScanStore:
    """Dependency injection for the ScanStore (lazy)."""
    global _scan_store
    if _scan_store is None:
        _scan_store = ScanStore()
    return _scan_store


def get_scanner() -> Scanner:
    """Dependency injection for the Scanner (lazy)."""
    global _scanner
    if _scanner is None:
        _scanner = Scanner(store=get_store())
    return _scanner


def reset_state_for_tests() -> None:
    """Drop the cached store + scanner. Tests call this between cases that
    rely on different env vars or a clean store. NOT for production use."""
    global _scan_store, _scanner
    _scan_store = None
    _scanner = None


@router.post("", response_model=Scan)
async def create_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    scanner: Scanner = Depends(get_scanner),
) -> Scan:
    """Start a new scan.

    Creates a scan record and kicks off execution in the background.
    Returns immediately with the scan ID, scan_token (for WebSocket), and PENDING status.
    """
    cleaned = validate_target_id(request.target_id, request.scope)
    if not cleaned:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid target ID '{request.target_id}' for scope '{request.scope}'. "
                   f"{'Org IDs must be numeric.' if request.scope == 'org' else 'Project IDs must be 6-30 lowercase alphanumeric/hyphen chars.'}",
        )
    request.target_id = cleaned

    scan = await scanner.create_scan(request)

    scan_token = generate_scan_token(scan.id)

    # Pass the per-scan WebSocket callback via run_scan so concurrent scans
    # don't trample each other's event channel.
    on_event = get_event_callback(scan.id)
    background_tasks.add_task(scanner.run_scan, scan.id, on_event)

    logger.info("Scan %s queued (scope=%s, target=%s)", scan.id, request.scope, request.target_id)

    scan.scan_token = scan_token
    return scan


@router.get("", response_model=list[Scan])
async def list_scans(
    store: ScanStore = Depends(get_store),
) -> list[Scan]:
    """List all scans in the current session (newest first).

    Strips ``findings`` and ``check_executions`` to keep the payload small;
    use the dedicated endpoints to fetch them per scan.
    """
    scans = store.get_all()
    return [
        scan.model_copy(update={"findings": [], "check_executions": [], "scan_token": ""})
        for scan in scans
    ]


@router.get("/{scan_id}", response_model=Scan)
async def get_scan(
    scan_id: str,
    store: ScanStore = Depends(get_store),
) -> Scan:
    """Get a scan by ID, including status and a live-recomputed summary.

    The persisted summary on the scan is only finalised after the engine
    finishes (`_compute_aggregate_summary` runs once at end of run_scan).
    During a running scan the persisted summary is empty, so the dashboard's
    stat cards would stay at 0 even as findings stream in. Recompute the
    summary from `scan.findings` on every read so the polling path shows
    accurate counts mid-scan.
    """
    scan = store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    from backend.core.models import Category, CheckStatus, Severity, compute_health_score

    visible = [f for f in scan.findings if not getattr(f, "suppressed", False)]
    by_sev: dict[str, int] = {s.value: 0 for s in Severity}
    by_cat: dict[str, int] = {c.value: 0 for c in Category}
    by_svc: dict[str, int] = {}
    for f in visible:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
        by_svc[f.service] = by_svc.get(f.service, 0) + 1
    score, grade = compute_health_score(by_sev)

    # check_executions might be empty mid-scan (engine collects them at the
    # end), so the check counters only become accurate after completion.
    # That's acceptable — the severity / total-findings counters are the
    # ones users actually watch tick up during a run.
    passed = sum(1 for e in scan.check_executions if e.status == CheckStatus.PASSED)
    failed = sum(1 for e in scan.check_executions if e.status == CheckStatus.FAILED)
    errored = sum(1 for e in scan.check_executions if e.status == CheckStatus.ERRORED)
    skipped = sum(1 for e in scan.check_executions if e.status == CheckStatus.SKIPPED)

    live_summary = scan.summary.model_copy(update={
        "total_findings": len(visible),
        "by_severity": by_sev,
        "by_category": by_cat,
        "by_service": by_svc,
        "checks_passed": max(passed, scan.summary.checks_passed),
        "checks_failed": max(failed, scan.summary.checks_failed),
        "checks_errored": max(errored, scan.summary.checks_errored),
        "checks_skipped": max(skipped, scan.summary.checks_skipped),
        "health_score": score,
        "health_grade": grade,
    })
    return scan.model_copy(update={"findings": [], "scan_token": "", "summary": live_summary})


@router.delete("/{scan_id}", response_model=Scan)
async def cancel_scan(
    scan_id: str,
    scanner: Scanner = Depends(get_scanner),
) -> Scan:
    """Cancel a running scan."""
    scan = await scanner.cancel_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return scan


@router.get("/{scan_id}/findings", response_model=list[Finding])
async def get_findings(
    scan_id: str,
    severity: str | None = None,
    category: str | None = None,
    service: str | None = None,
    id_prefix: str | None = None,
    include_suppressed: bool = False,
    store: ScanStore = Depends(get_store),
) -> list[Finding]:
    """Get findings for a scan with optional filters.

    Query Parameters:
        severity: Filter by severity (critical, high, medium, low, info)
        category: Filter by category (security, reliability, performance, cost, operations)
        service: Filter by service (gke, gce, gcs, etc.)
        id_prefix: Filter by check-ID prefix (e.g. "IAM-", "GKE", "BIL-001").
            Matches case-insensitively against the start of each finding's check_id.
        include_suppressed: Include suppressed findings in the result (default false).
    """
    scan = store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    findings = scan.findings

    if not include_suppressed:
        findings = [f for f in findings if not f.suppressed]
    if severity:
        findings = [f for f in findings if f.severity == severity]
    if category:
        findings = [f for f in findings if f.category == category]
    if service:
        findings = [f for f in findings if f.service.lower() == service.lower()]
    if id_prefix:
        prefix_norm = id_prefix.lower()
        findings = [f for f in findings if f.check_id.lower().startswith(prefix_norm)]

    logger.info(
        "Returning %d findings for scan %s (filters: severity=%s, category=%s, service=%s, id_prefix=%s, include_suppressed=%s)",
        len(findings), scan_id, severity, category, service, id_prefix, include_suppressed,
    )
    return findings


@router.post("/{scan_id}/findings/{finding_id}/suppress", response_model=Finding)
async def suppress_finding(
    scan_id: str,
    finding_id: str,
    payload: SuppressionRequest | None = None,
    store: ScanStore = Depends(get_store),
) -> Finding:
    """Mark a finding as suppressed (hidden from default views and counts)."""
    scan = store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    for f in scan.findings:
        if f.id == finding_id:
            f.suppressed = True
            f.suppression_reason = (payload.reason if payload else "") or ""
            # In-memory mutation is what readers see immediately; GCS persistence
            # is fire-and-forget so the user doesn't wait on a multi-MB upload.
            asyncio.create_task(_background_save(store, scan))
            logger.info("Suppressed finding %s in scan %s", finding_id, scan_id)
            return f

    raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")


@router.delete("/{scan_id}/findings/{finding_id}/suppress", response_model=Finding)
async def unsuppress_finding(
    scan_id: str,
    finding_id: str,
    store: ScanStore = Depends(get_store),
) -> Finding:
    """Unsuppress a finding so it appears in default views and counts again."""
    scan = store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    for f in scan.findings:
        if f.id == finding_id:
            f.suppressed = False
            f.suppression_reason = ""
            asyncio.create_task(_background_save(store, scan))
            logger.info("Unsuppressed finding %s in scan %s", finding_id, scan_id)
            return f

    raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")


@router.get("/{scan_id}/findings/{finding_id}", response_model=Finding)
async def get_finding(
    scan_id: str,
    finding_id: str,
    store: ScanStore = Depends(get_store),
) -> Finding:
    """Get a single finding by ID."""
    scan = store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    for f in scan.findings:
        if f.id == finding_id:
            return f

    raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")


@router.get("/{scan_id}/summary", response_model=ScanSummary)
async def get_summary(
    scan_id: str,
    store: ScanStore = Depends(get_store),
) -> ScanSummary:
    """Get scan summary statistics."""
    scan = store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    return scan.summary
