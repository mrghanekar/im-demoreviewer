"""Health check endpoint."""

import os

from fastapi import APIRouter

from backend.config import settings
from backend.core.models import HealthResponse
from backend.checks.registry import discover_checks

router = APIRouter(tags=["health"])


def gemini_enabled() -> bool:
    """Whether the deploy opted in to Vertex AI / Gemini features.

    Set by setup.sh via the DR_GEMINI_ENABLED env var (string "true" / "false").
    Defaults to True so older deployments that predate this flag keep working.
    """
    return os.environ.get("DR_GEMINI_ENABLED", "true").strip().lower() == "true"


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Health check endpoint for Cloud Run and monitoring.

    Returns basic app info plus check count for diagnostics.
    The response is kept minimal for fast health-check probes.
    """
    checks = discover_checks()
    return HealthResponse(
        status="ok",
        version=settings.app_version,
        app_name=settings.app_name,
        checks_loaded=len(checks),
        environment="cloud_run" if os.environ.get("K_SERVICE") else "local",
        gemini_enabled=gemini_enabled(),
    )
