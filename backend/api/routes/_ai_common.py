"""Shared Vertex AI helpers used by /ai (explain) and /cost (cost analysis).

Both routes need the same Vertex init, model resolution, and field
truncation. Keeping the helpers here avoids duplication and ensures any
model-policy change (e.g. supported list) updates both at once.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import google.auth
import vertexai

logger = logging.getLogger(__name__)

# Supported Gemini models — configurable via DR_AI_MODEL env var.
# IDs from https://cloud.google.com/vertex-ai/generative-ai/docs/models
# Only Gemini 3-series models are supported; 2.x is deprecated for this project.
SUPPORTED_MODELS: dict[str, str] = {
    "gemini-3.1-pro": "gemini-3.1-pro",
    "gemini-3-flash": "gemini-3-flash",
}

DEFAULT_MODEL = "gemini-3-flash"

# Cached vertexai init state — vertexai.init() mutates global state, so we
# only call it once per process.
_vertex_initialized: tuple[str, str] | None = None


def get_model_name() -> str:
    """Return the configured AI model name, validated against SUPPORTED_MODELS."""
    configured = os.environ.get("DR_AI_MODEL", DEFAULT_MODEL).strip()
    if configured not in SUPPORTED_MODELS:
        logger.warning(
            "Configured model '%s' not in supported list %s. Falling back to '%s'.",
            configured, list(SUPPORTED_MODELS.keys()), DEFAULT_MODEL,
        )
        return DEFAULT_MODEL
    return configured


def init_vertex_once() -> str:
    """Initialize vertexai once per process. Returns the project ID."""
    global _vertex_initialized
    if _vertex_initialized is not None:
        return _vertex_initialized[0]
    _credentials, project = google.auth.default()
    location = "global"
    logger.info("Initializing Vertex AI: project=%s, location=%s", project, location)
    vertexai.init(project=project, location=location)
    _vertex_initialized = (project, location)
    return project


def truncate(value: Any, limit: int = 800) -> str:
    """Cap each finding field so adversarial resource names can't blow up the prompt."""
    s = str(value) if value is not None else ""
    if len(s) > limit:
        s = s[:limit] + "…"
    return s
