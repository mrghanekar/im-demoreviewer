# =============================================================================
# Democratized Reviewer - Multi-stage Docker Build
# Stage 1: Build React frontend
# Stage 2: Python runtime with FastAPI + gcloud CLI + built frontend
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Build frontend
# ---------------------------------------------------------------------------
FROM node:22-slim AS frontend-builder

WORKDIR /app/frontend

# Install dependencies first (better caching)
COPY frontend/package.json frontend/package-lock.json ./
# Update npm to latest to match dev environment and avoid legacy warnings
RUN npm install -g npm@latest
RUN npm ci --no-audit --no-fund

# Copy source and build
COPY frontend/ ./
RUN npm run build

# ---------------------------------------------------------------------------
# Stage 2: Python runtime
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

# Prevent interactive prompts during build
ARG DEBIAN_FRONTEND=noninteractive

# Metadata
LABEL maintainer="aghanekar"
LABEL description="Democratized Reviewer - GCP Audit & Best-Practices Review Tool"
LABEL version="0.1.0"

# Install system dependencies + gcloud CLI
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gnupg \
    apt-transport-https \
    ca-certificates \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz-subset0 \
    libharfbuzz0b \
    libgdk-pixbuf-2.0-0 \
    shared-mime-info \
    libjpeg-dev \
    libopenjp2-7-dev \
    libxcb1 \
    libffi-dev \
    fontconfig \
    && echo "deb [signed-by=/usr/share/keyrings/cloud.google.asc] https://packages.cloud.google.com/apt cloud-sdk main" \
       > /etc/apt/sources.list.d/google-cloud-sdk.list \
    && curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg \
       | tee /usr/share/keyrings/cloud.google.asc > /dev/null \
    && apt-get update \
    # Pin gcloud version so a silent backend upgrade doesn't change which
    # resource fields our checks look at. Bump this deliberately when adopting
    # new gcloud features; see backend/core/gcloud_runner.get_gcloud_version().
    && apt-get install -y --no-install-recommends "google-cloud-cli=507.0.0-0" \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Create non-root user
RUN groupadd -r reviewer && useradd -r -g reviewer -m reviewer

WORKDIR /app

# Silence two pip nags that show up red in Cloud Build logs and worry users:
#   1. "Running pip as the 'root' user can result in broken permissions..."
#      Standard pip warning when run as root. Docker builds always run as
#      root; pip's recommendation to use a venv is not applicable here.
#   2. "A new release of pip is available: X -> Y"
#      Self-update notice. We pin pip explicitly; auto-update would defeat
#      the purpose. Disable the check entirely.
ENV PIP_ROOT_USER_ACTION=ignore \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install Python dependencies (production only — no test/dev tools)
COPY backend/requirements-prod.txt ./requirements.txt
RUN pip install --no-cache-dir --upgrade 'pip>=24.3,<26'
RUN pip install --no-cache-dir --no-compile -r requirements.txt \
    && rm -rf /root/.cache

# Copy backend source
COPY backend/ ./backend/

# Copy built frontend from stage 1
COPY --from=frontend-builder /app/static ./static/

# Ensure correct permissions
RUN chown -R reviewer:reviewer /app

# Switch to non-root user
USER reviewer

# Environment defaults
ENV DR_PORT=8080 \
    DR_HOST=0.0.0.0 \
    DR_LOG_LEVEL=INFO \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8080/api/v1/health || exit 1

# Run with uvicorn
# Single worker: app keeps in-memory ScanStore / WebSocket queues / rate-limit state.
# Scale by Cloud Run instances (pinned to 1) rather than workers.
CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1", "--timeout-keep-alive", "75"]
