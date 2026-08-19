"""On-demand cost analysis powered by Gemini + Google Search grounding.

The customer's scan turns up resources but no $/month figure for any of
them (hardcoded list prices were removed in commit d7f74778 because
they drift). This route fills that gap on demand:

  1. User clicks "Compute Costs" on the new Results "Cost Saving" tab.
  2. We send every finding-with-a-resource to Gemini 3 in batches of 30,
     with the google_search tool enabled so the model grounds each
     answer against current cloud.google.com pricing pages.
  3. Per-finding $/month + basis come back as JSON; we patch them onto
     each Finding, sum into ScanSummary.estimated_monthly_waste_usd,
     and persist via store.save (GCS-backed) so the result survives a
     restart.

Cost is billed to the customer's project — same auth posture as the
existing /ai/explain endpoint. Frontend warns the user before kicking
off.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from vertexai.generative_models import GenerativeModel, GenerationConfig, Tool, grounding

from backend.api.routes._ai_common import (
    get_model_name,
    init_vertex_once,
    truncate,
)
from backend.api.routes.health import gemini_enabled
from backend.api.routes.scan import _background_save, get_store
from backend.core.models import CostAnalysis, CostAnalysisStatus, Scan
from backend.core.scanner import ScanStore

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/cost", tags=["cost"])

# Batch + concurrency caps — kept small to bound Gemini token spend per
# scan and respect Vertex per-project QPS. Each batch is one Gemini call.
_BATCH_SIZE = 30
_MAX_CONCURRENT_BATCHES = 4

# Rough token-cost estimates (USD per million tokens) for the warning banner.
# These intentionally lag actual Vertex billing so the user is told the
# upper bound; real bill is usually lower. Source: cloud.google.com/vertex-ai/pricing.
_MODEL_PRICING_USD_PER_M_TOKENS = {
    "gemini-3-flash":  {"in": 0.30, "out": 1.20},
    "gemini-3.1-pro":  {"in": 2.50, "out": 10.0},
}
# Default if model not in table.
_FALLBACK_PRICING = {"in": 1.0, "out": 4.0}


# ---------------------------------------------------------------------------
# Response shapes
# ---------------------------------------------------------------------------


class CostEstimate(BaseModel):
    findings_to_analyze: int
    estimated_tokens_in: int
    estimated_tokens_out: int
    estimated_usd: float
    model: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


def _require_gemini() -> None:
    """Reject the request when the operator opted out of Vertex AI at install time."""
    if not gemini_enabled():
        raise HTTPException(
            status_code=503,
            detail="Gemini features are disabled for this deployment. Re-run setup.sh to enable Vertex AI.",
        )


@router.get("/scans/{scan_id}/cost-analysis/estimate", response_model=CostEstimate)
async def get_cost_estimate(
    scan_id: str,
    store: ScanStore = Depends(get_store),
) -> CostEstimate:
    """Project token spend and $ cost so the UI can show a real number in the warning."""
    _require_gemini()
    scan = store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    targets = _resource_findings(scan)
    model = get_model_name()
    # Rough heuristic: 220 input tokens / finding (prompt + truncated fields)
    # and 60 output tokens / finding (structured JSON answer). System prompt
    # and grounding-tool overhead amortise across the batch.
    tokens_in = len(targets) * 220 + 1500
    tokens_out = len(targets) * 60
    pricing = _MODEL_PRICING_USD_PER_M_TOKENS.get(model, _FALLBACK_PRICING)
    usd = (tokens_in * pricing["in"] + tokens_out * pricing["out"]) / 1_000_000
    return CostEstimate(
        findings_to_analyze=len(targets),
        estimated_tokens_in=tokens_in,
        estimated_tokens_out=tokens_out,
        estimated_usd=round(usd, 4),
        model=model,
    )


@router.get("/scans/{scan_id}/cost-analysis", response_model=CostAnalysis)
async def get_cost_analysis(
    scan_id: str,
    store: ScanStore = Depends(get_store),
) -> CostAnalysis:
    """Return the current cost analysis state (or 404 if never started)."""
    scan = store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    if scan.cost_analysis is None:
        raise HTTPException(status_code=404, detail="Cost analysis has not been started for this scan")
    return scan.cost_analysis


@router.post("/scans/{scan_id}/cost-analysis", response_model=CostAnalysis, status_code=202)
async def start_cost_analysis(
    scan_id: str,
    background_tasks: BackgroundTasks,
    force: bool = False,
    store: ScanStore = Depends(get_store),
) -> CostAnalysis:
    """Kick off Gemini cost analysis. Returns immediately; poll GET for status."""
    _require_gemini()
    scan = store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    existing = scan.cost_analysis
    if existing and not force:
        if existing.status == CostAnalysisStatus.RUNNING:
            return existing  # idempotent — caller can poll
        if existing.status == CostAnalysisStatus.COMPLETED:
            return existing  # already done; pass force=true to re-run

    model = get_model_name()
    targets = _resource_findings(scan)
    analysis = CostAnalysis(
        status=CostAnalysisStatus.RUNNING,
        model=model,
        started_at=datetime.now(timezone.utc),
        findings_count=len(targets),
    )
    scan.cost_analysis = analysis
    store.save(scan)

    background_tasks.add_task(_run_analysis_in_background, scan_id, store)
    return analysis


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _resource_findings(scan: Scan) -> list[Any]:
    """Findings the cost analyzer should consider: visible + has a resource_name."""
    return [
        f for f in scan.findings
        if not f.suppressed and (f.resource_name or "").strip()
    ]


async def _run_analysis_in_background(scan_id: str, store: ScanStore) -> None:
    """Run the analysis end-to-end. Updates scan.cost_analysis as it goes."""
    scan = store.get(scan_id)
    if not scan or scan.cost_analysis is None:
        logger.error("cost analysis: scan %s vanished mid-run", scan_id)
        return
    analysis = scan.cost_analysis
    targets = _resource_findings(scan)

    try:
        init_vertex_once()
        results, sources, notes = await _ask_gemini_for_costs(analysis.model, targets)

        # Patch the cost back onto each Finding (and zero out any others
        # so a re-run with `force=true` doesn't leave stale numbers).
        finding_by_id = {f.id: f for f in scan.findings}
        for f in scan.findings:
            f.estimated_monthly_cost_usd = None
            f.cost_basis = ""
        total = 0.0
        costed = 0
        for r in results:
            f = finding_by_id.get(r["finding_id"])
            if not f:
                continue
            amount = float(r.get("monthly_usd") or 0)
            if amount > 0:
                f.estimated_monthly_cost_usd = round(amount, 2)
                f.cost_basis = str(r.get("basis", ""))[:500]
                total += amount
                costed += 1

        scan.summary.estimated_monthly_waste_usd = round(total, 2)
        analysis.total_monthly_usd = round(total, 2)
        analysis.costed_count = costed
        analysis.grounding_sources = sources
        analysis.notes = notes
        analysis.status = CostAnalysisStatus.COMPLETED
        analysis.completed_at = datetime.now(timezone.utc)
    except Exception as e:
        logger.error("cost analysis failed for scan %s: %s", scan_id, e, exc_info=True)
        analysis.status = CostAnalysisStatus.FAILED
        analysis.error_message = str(e)[:500] or e.__class__.__name__
        analysis.completed_at = datetime.now(timezone.utc)
    finally:
        # Hand to the same background-save helper scan.py uses so we don't
        # block on GCS in the background task itself.
        await _background_save(store, scan)


async def _ask_gemini_for_costs(
    model_name: str, targets: list[Any]
) -> tuple[list[dict[str, Any]], list[str], str]:
    """Send findings to Gemini in batches, return merged results.

    Returns ``(per_finding_results, grounding_source_urls, summary_notes)``.
    """
    if not targets:
        return [], [], "No findings with resources to price."

    grounding_tool = Tool.from_google_search_retrieval(grounding.GoogleSearchRetrieval())
    model = GenerativeModel(model_name, tools=[grounding_tool])
    gen_config = GenerationConfig(temperature=0.1)
    sem = asyncio.Semaphore(_MAX_CONCURRENT_BATCHES)

    batches = [targets[i : i + _BATCH_SIZE] for i in range(0, len(targets), _BATCH_SIZE)]

    async def run_batch(batch: list[Any]) -> tuple[list[dict[str, Any]], list[str]]:
        async with sem:
            return await _price_one_batch(model, gen_config, batch)

    batch_results = await asyncio.gather(*(run_batch(b) for b in batches), return_exceptions=True)

    all_costs: list[dict[str, Any]] = []
    all_sources: set[str] = set()
    failures = 0
    for r in batch_results:
        if isinstance(r, Exception):
            logger.warning("cost-analysis batch failed: %s", r)
            failures += 1
            continue
        costs, sources = r
        all_costs.extend(costs)
        all_sources.update(sources)

    costed = sum(1 for c in all_costs if (c.get("monthly_usd") or 0) > 0)
    notes_parts = [
        f"Analyzed {len(targets)} resources across {len(batches)} batch(es); "
        f"{costed} had a measurable monthly cost.",
    ]
    if failures:
        notes_parts.append(f"{failures} batch(es) failed and were skipped.")
    notes = " ".join(notes_parts)
    return all_costs, sorted(all_sources), notes


async def _price_one_batch(
    model: GenerativeModel,
    gen_config: GenerationConfig,
    batch: list[Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Price one batch of findings via a single grounded Gemini call."""
    items = "\n".join(
        json.dumps({
            "finding_id": f.id,
            "service": truncate(f.service, 50),
            "check_id": truncate(f.check_id, 32),
            "title": truncate(f.title, 200),
            "resource_name": truncate(f.resource_name, 200),
            "project_id": truncate(f.project_id, 80),
            "current_state": truncate(f.current_state, 300),
        })
        for f in batch
    )

    prompt = f"""You are a Google Cloud cost analyst. For each resource in
the JSON list below, estimate its **current monthly waste in USD** if the
finding's recommended remediation (e.g. delete the unused resource, right-size
the over-provisioned instance) is applied.

REQUIREMENTS:
- Use the google_search tool to ground every non-zero figure against the
  current cloud.google.com pricing page for that service.
- Assume US multi-region pricing unless the resource name suggests another
  region.
- Return 0 when the resource has no recurring cost (e.g. an IAM policy
  finding), when pricing cannot be located, or when the finding doesn't
  represent direct waste (e.g. "no budget alerts configured").
- Never fabricate numbers. When uncertain, return 0 with confidence="low".

Respond with a single JSON object (no markdown fences, no commentary)
shaped exactly:

{{
  "results": [
    {{"finding_id": "...", "monthly_usd": 0.0, "basis": "one-line math/source", "confidence": "high|medium|low"}}
  ]
}}

Findings (one per line, JSON):
{items}
"""

    response = await model.generate_content_async(prompt, generation_config=gen_config)

    # Parse the JSON body — model may or may not wrap in ```json fences.
    text = (response.text or "").strip()
    parsed = _extract_json_object(text)
    results_raw = parsed.get("results", []) if isinstance(parsed, dict) else []

    cleaned: list[dict[str, Any]] = []
    for r in results_raw:
        if not isinstance(r, dict):
            continue
        confidence = str(r.get("confidence", "")).lower()
        amount = float(r.get("monthly_usd") or 0)
        if confidence == "low" and amount > 0:
            # Low-confidence figures are treated as 0 so the UI doesn't
            # mislead the user. Keep the basis so the user sees the reasoning.
            amount = 0.0
        cleaned.append({
            "finding_id": str(r.get("finding_id", "")),
            "monthly_usd": amount,
            "basis": str(r.get("basis", "")),
            "confidence": confidence,
        })

    sources = _extract_grounding_sources(response)
    return cleaned, sources


_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def _extract_json_object(text: str) -> dict[str, Any]:
    """Pull the first JSON object out of a Gemini response.

    Handles ```json … ``` fences, leading/trailing prose, and partial
    failures. Returns {} on parse failure (caller treats as no costs found).
    """
    if not text:
        return {}
    m = _JSON_FENCE_RE.search(text)
    blob = m.group(1) if m else text
    # Trim to first { and last } if there's prose around it.
    first = blob.find("{")
    last = blob.rfind("}")
    if first >= 0 and last > first:
        blob = blob[first : last + 1]
    try:
        parsed = json.loads(blob)
        return parsed if isinstance(parsed, dict) else {}
    except (json.JSONDecodeError, ValueError):
        return {}


def _extract_grounding_sources(response: Any) -> list[str]:
    """Pull cloud.google.com URLs out of Vertex's grounding metadata.

    The Vertex SDK exposes citations as ``candidate.grounding_metadata`` —
    its exact shape has changed across SDK minor versions, so we walk
    defensively and accept either ``grounding_chunks`` or
    ``grounding_attributions`` field names.
    """
    urls: set[str] = set()
    try:
        for cand in getattr(response, "candidates", []) or []:
            meta = getattr(cand, "grounding_metadata", None)
            if not meta:
                continue
            for chunk in getattr(meta, "grounding_chunks", []) or []:
                web = getattr(chunk, "web", None)
                if web and getattr(web, "uri", ""):
                    urls.add(web.uri)
            for attr in getattr(meta, "grounding_attributions", []) or []:
                web = getattr(attr, "web", None)
                if web and getattr(web, "uri", ""):
                    urls.add(web.uri)
    except Exception as e:
        logger.debug("could not extract grounding sources: %s", e)
    return sorted(urls)
