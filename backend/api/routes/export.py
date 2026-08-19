"""Export API routes.

Handles exporting scan results to JSON / CSV / HTML / PDF, and GCS upload.
"""

import asyncio
import csv
import io
import json
import logging
import sys
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import HTMLResponse

from backend.core.scanner import ScanStore
from backend.api.routes.scan import get_store
from backend.utils.report_generator import generate_html_report, generate_pdf_report
from backend.api.middleware.validation import validate_bucket_name
from backend.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["export"])

# Maximum export size: 5 GB
MAX_EXPORT_SIZE_BYTES = 5 * 1024 * 1024 * 1024  # 5 GB


def _estimate_scan_size(scan) -> int:
    """Estimate the serialized size of a scan in bytes."""
    return sys.getsizeof(scan.model_dump_json())


def _allowed_export_buckets() -> set[str]:
    """Buckets the export endpoint is permitted to write to."""
    allowed = {b.strip().lower() for b in settings.gcs_export_bucket_allowlist if b.strip()}
    if settings.gcs_export_bucket:
        allowed.add(settings.gcs_export_bucket.strip().lower())
    return allowed


def _require_allowed_bucket(bucket: str) -> str:
    """Reject export targets outside the configured allowlist.

    An export is a full inventory of the estate — resource names, project IDs,
    misconfigurations. Without this an attacker could name their own bucket and
    have the server's service account push the whole report out of the org.
    """
    allowed = _allowed_export_buckets()
    if not allowed:
        raise HTTPException(
            status_code=409,
            detail=(
                "No export bucket is configured. Set DR_GCS_EXPORT_BUCKET (or "
                "DR_GCS_EXPORT_BUCKET_ALLOWLIST) before exporting to GCS."
            ),
        )
    if bucket not in allowed:
        logger.warning("Rejected export to non-allowlisted bucket: %s", bucket)
        raise HTTPException(
            status_code=403,
            detail=f"Bucket '{bucket}' is not an allowed export destination.",
        )
    return bucket


@router.get("/{scan_id}/export/json")
async def export_json(
    scan_id: str,
    store: ScanStore = Depends(get_store),
) -> Response:
    """Download the full scan record as JSON."""
    scan = store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    body = scan.model_copy(update={"scan_token": ""}).model_dump_json(indent=2)

    if len(body.encode("utf-8")) > MAX_EXPORT_SIZE_BYTES:
        raise HTTPException(status_code=413, detail="Export exceeds 5 GB size limit")

    filename = f"democratized-reviewer-{scan_id}-{datetime.now(timezone.utc).strftime('%Y%m%d')}.json"
    return Response(
        content=body,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{scan_id}/export/html")
async def export_html(
    scan_id: str,
    store: ScanStore = Depends(get_store),
) -> HTMLResponse:
    """Download scan results as a styled HTML report."""
    scan = store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    html = await asyncio.to_thread(generate_html_report, scan)

    # Check export size limit
    if len(html.encode("utf-8")) > MAX_EXPORT_SIZE_BYTES:
        raise HTTPException(status_code=413, detail="Export exceeds 5 GB size limit")

    filename = f"democratized-reviewer-{scan_id}-{datetime.now(timezone.utc).strftime('%Y%m%d')}.html"

    return HTMLResponse(
        content=html,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@router.get("/{scan_id}/export/csv")
async def export_csv(
    scan_id: str,
    include_suppressed: bool = False,
    store: ScanStore = Depends(get_store),
) -> Response:
    """Download findings as CSV. One row per finding.

    Suppressed findings are excluded by default (matches the default findings
    view); pass ``include_suppressed=true`` to include them with a ``suppressed``
    column populated.
    """
    scan = store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    findings = scan.findings
    if not include_suppressed:
        findings = [f for f in findings if not f.suppressed]

    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\n")
    writer.writerow([
        "check_id", "title", "severity", "category", "service",
        "project_id", "resource_name", "resource_link",
        "current_state", "recommended_state", "fix_command",
        "estimated_monthly_cost_usd", "cost_basis",
        "suppressed", "suppression_reason", "discovered_at",
    ])
    for f in findings:
        writer.writerow([
            f.check_id, f.title, f.severity, f.category, f.service,
            f.project_id, f.resource_name, f.resource_link,
            f.current_state, f.recommended_state, f.fix_command,
            f"{f.estimated_monthly_cost_usd:.2f}" if f.estimated_monthly_cost_usd else "",
            f.cost_basis,
            "true" if f.suppressed else "false",
            f.suppression_reason,
            f.discovered_at.isoformat() if f.discovered_at else "",
        ])

    body = buf.getvalue()
    if len(body.encode("utf-8")) > MAX_EXPORT_SIZE_BYTES:
        raise HTTPException(status_code=413, detail="Export exceeds 5 GB size limit")

    filename = f"democratized-reviewer-{scan_id}-{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv"
    return Response(
        content=body,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{scan_id}/export/pdf")
async def export_pdf(
    scan_id: str,
    store: ScanStore = Depends(get_store),
) -> Response:
    """Download scan results as a PDF report."""
    scan = store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    try:
        # WeasyPrint renders synchronously and can take seconds on a large
        # scan. Inline on the event loop it stalls every heartbeat, WebSocket
        # frame and in-flight scan in the process.
        pdf_bytes = await asyncio.to_thread(generate_pdf_report, scan)
    except (ImportError, OSError) as e:
        logger.error("PDF generation failed: %s", e)
        raise HTTPException(
            status_code=501,
            detail="PDF generation failed. Ensure 'weasyprint' and system dependencies are installed."
        )
    except Exception as e:
        logger.error("PDF generation unexpected error: %s", e)
        raise HTTPException(status_code=500, detail="PDF generation failed")

    # Check export size limit
    if len(pdf_bytes) > MAX_EXPORT_SIZE_BYTES:
        raise HTTPException(status_code=413, detail="Export exceeds 5 GB size limit")

    filename = f"democratized-reviewer-{scan_id}-{datetime.now(timezone.utc).strftime('%Y%m%d')}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


def _perform_gcs_export(bucket: str, scan_id: str, scan) -> dict:
    """Render the reports and upload them. Blocking — run in a thread."""
    from google.cloud import storage

    client = storage.Client()
    try:
        gcs_bucket = client.bucket(bucket)
        prefix = f"democratized-reviewer/scans/{scan_id}"
        total_uploaded = 0

        # Upload HTML report
        html_report = generate_html_report(scan)
        total_uploaded += len(html_report.encode("utf-8"))
        if total_uploaded > MAX_EXPORT_SIZE_BYTES:
            raise HTTPException(status_code=413, detail="Export exceeds 5 GB size limit")
        report_blob = gcs_bucket.blob(f"{prefix}/report.html")
        report_blob.upload_from_string(html_report, content_type="text/html")

        # Upload PDF report
        try:
            pdf_bytes = generate_pdf_report(scan)
            total_uploaded += len(pdf_bytes)
            if total_uploaded > MAX_EXPORT_SIZE_BYTES:
                raise HTTPException(status_code=413, detail="Export exceeds 5 GB size limit")
            pdf_blob = gcs_bucket.blob(f"{prefix}/report.pdf")
            pdf_blob.upload_from_string(pdf_bytes, content_type="application/pdf")
        except HTTPException:
            raise
        except Exception as e:
            logger.warning("Failed to generate PDF for GCS export: %s", e)

        # Upload metadata
        metadata = {
            "scan_id": scan.id,
            "scope": scan.scope,
            "target_id": scan.target_id,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "findings_count": scan.summary.total_findings,
        }
        meta_json = json.dumps(metadata, indent=2)
        meta_blob = gcs_bucket.blob(f"{prefix}/metadata.json")
        meta_blob.upload_from_string(meta_json, content_type="application/json")

        gcs_uri = f"gs://{bucket}/{prefix}/"
        logger.info("Exported scan %s to %s", scan_id, gcs_uri)

        return {
            "status": "exported",
            "gcs_uri": gcs_uri,
            "files": [
                f"{gcs_uri}report.html",
                f"{gcs_uri}report.pdf",
                f"{gcs_uri}metadata.json",
            ],
        }
    finally:
        client.close()


@router.post("/{scan_id}/export")
async def export_to_gcs(
    scan_id: str,
    bucket: str = Query(..., description="GCS bucket name for export"),
    store: ScanStore = Depends(get_store),
) -> dict:
    """Export scan results to a GCS bucket.

    Uploads findings.json (internal use), report.html, and report.pdf to:
    gs://<bucket>/democratized-reviewer/scans/<scan-id>/

    Maximum export size: 5 GB.
    """
    # Validate bucket name
    cleaned_bucket = validate_bucket_name(bucket)
    if not cleaned_bucket:
        raise HTTPException(status_code=422, detail=f"Invalid GCS bucket name: '{bucket}'")
    bucket = _require_allowed_bucket(cleaned_bucket)

    scan = store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    # Estimate total export size
    estimated_size = _estimate_scan_size(scan)
    if estimated_size > MAX_EXPORT_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Export data exceeds 5 GB size limit (estimated: {estimated_size / (1024**3):.1f} GB)",
        )

    try:
        # Rendering and three synchronous GCS uploads; off-loop or every other
        # request in the process waits on it. Snapshot first — a scan that is
        # still running keeps appending findings, and serialising a mutating
        # model from a worker thread is a data race.
        return await asyncio.to_thread(
            _perform_gcs_export, bucket, scan_id, scan.model_copy(deep=True)
        )

    except HTTPException:
        raise
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="google-cloud-storage not installed. Install with: pip install google-cloud-storage",
        )
    except Exception as e:
        logger.error("GCS export failed: %s", e)
        raise HTTPException(status_code=500, detail="Export failed")
