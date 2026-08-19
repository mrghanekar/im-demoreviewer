"""Democratized Reviewer — FastAPI Application.

Main entry point for the backend. Serves:
- REST API under /api/v1/
- React SPA from /static/ (in production)
- Health check at /api/v1/health
"""

import logging
import os
import signal
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.config import settings
from backend.api.middleware.error_handler import ErrorHandlerMiddleware
from backend.api.middleware.security import (
    SecurityHeadersMiddleware,
    RateLimitMiddleware,
    RequestIdMiddleware,
    BodySizeLimitMiddleware,
)
from backend.api.middleware.logging_config import setup_logging
from backend.api.routes import health, scan, setup, export, websocket, ai, cost
from backend.checks.registry import discover_checks


# ---------------------------------------------------------------------------
# Logging (structured JSON on Cloud Run, console for local dev)
# ---------------------------------------------------------------------------

_is_cloud_run = bool(os.environ.get("K_SERVICE"))
setup_logging(
    log_level=settings.log_level.upper(),
    json_logs=_is_cloud_run,
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Graceful Shutdown
# ---------------------------------------------------------------------------

_shutting_down = False


def _handle_shutdown(signum, frame):
    """Set shutdown flag on SIGTERM (sent by Cloud Run during scale-down)."""
    global _shutting_down
    _shutting_down = True
    logger.info("Received signal %s — initiating graceful shutdown", signum)


# Register signal handlers (SIGTERM for Cloud Run, SIGINT for local dev)
signal.signal(signal.SIGTERM, _handle_shutdown)
signal.signal(signal.SIGINT, _handle_shutdown)


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    logger.info("Starting %s v%s", settings.app_name, settings.app_version)

    if _is_cloud_run:
        logger.info("Running on Cloud Run (K_SERVICE=%s)", os.environ.get("K_SERVICE"))

    # Discover checks on startup
    checks = discover_checks()
    logger.info("Loaded %d checks across %d categories", len(checks), len({
        c.service_category for c in checks.values()
    }))

    yield

    logger.info("Shutting down %s", settings.app_name)


# ---------------------------------------------------------------------------
# App Factory
# ---------------------------------------------------------------------------

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="GCP audit and best-practices review tool",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Middleware (applied in reverse order — last added runs first)
# ---------------------------------------------------------------------------

# Error handler — outermost (catches all unhandled exceptions)
app.add_middleware(ErrorHandlerMiddleware)

# Security headers
app.add_middleware(SecurityHeadersMiddleware)

# Rate limiting
app.add_middleware(RateLimitMiddleware, general_rpm=settings.rate_limit_general_rpm, scan_rpm=settings.rate_limit_scan_rpm)

# Reject oversized bodies before they're buffered
app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_body_bytes)

# Request ID tracking
app.add_middleware(RequestIdMiddleware)

# CORS — same-origin in production (Cloud Run); explicit dev origins locally.
# allow_credentials=True is incompatible with allow_origins=["*"], so we never widen origins here.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-Id"],
)


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------

API_PREFIX = "/api/v1"

app.include_router(health.router, prefix=API_PREFIX)
app.include_router(scan.router, prefix=API_PREFIX)
app.include_router(setup.router, prefix=API_PREFIX)
app.include_router(export.router, prefix=API_PREFIX)
app.include_router(websocket.router, prefix=API_PREFIX)
app.include_router(ai.router, prefix=API_PREFIX)
app.include_router(cost.router, prefix=API_PREFIX)


# ---------------------------------------------------------------------------
# Static Files (React SPA in production)
# ---------------------------------------------------------------------------

STATIC_DIR = (Path(__file__).parent.parent / "static").resolve()

if STATIC_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(STATIC_DIR / "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        """Serve the React SPA for all non-API routes.

        Resolves the requested path and verifies it lives inside STATIC_DIR
        before serving, to block traversal attempts like `..%2f..%2fetc/passwd`.
        """
        index = STATIC_DIR / "index.html"
        if not full_path:
            return FileResponse(index)

        try:
            candidate = (STATIC_DIR / full_path).resolve()
        except (OSError, RuntimeError):
            return FileResponse(index)

        # Containment check — candidate must be inside STATIC_DIR
        if STATIC_DIR != candidate and STATIC_DIR not in candidate.parents:
            return FileResponse(index)

        if candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(index)
else:
    @app.get("/")
    async def root():
        """Root endpoint when no frontend is built."""
        return {
            "app": settings.app_name,
            "version": settings.app_version,
            "status": "running",
            "note": "Frontend not built. Run 'cd frontend && npm run build' to build the SPA.",
        }
