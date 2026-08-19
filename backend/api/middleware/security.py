"""Security middleware — rate limiting, CSP headers, body-size limit, request ID.

Authentication is handled by Cloud Run IAM (the service is deployed without
``--allow-unauthenticated`` by default). There is no application-layer auth.
"""

import logging
import time
import uuid
from collections import OrderedDict
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from backend.config import settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Body Size Limit Middleware
# ---------------------------------------------------------------------------

class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests whose declared Content-Length exceeds ``max_bytes``.

    Cheap pre-check based on the header (Cloud Run already caps at 32 MB,
    but we want a tighter app-level limit). For chunked bodies without a
    Content-Length, this is a no-op — Starlette/uvicorn will still error
    out on truly oversized payloads.
    """

    def __init__(self, app, max_bytes: int = 1_048_576):
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > self.max_bytes:
                    return Response(
                        content=f'{{"detail":"Request body exceeds {self.max_bytes} bytes"}}',
                        status_code=413,
                        media_type="application/json",
                    )
            except ValueError:
                pass
        return await call_next(request)


# ---------------------------------------------------------------------------
# Security Headers Middleware
# ---------------------------------------------------------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds Content-Security-Policy, HSTS, and other security headers."""

    CSP_POLICY = "; ".join([
        "default-src 'self'",
        # 'unsafe-inline' is required by the standalone HTML report which inlines
        # styles and a small chart script. The SPA itself doesn't rely on inline
        # script. TODO: extract report JS to /assets/report.js and drop unsafe-inline.
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: https:",
        "font-src 'self' https:",
        "connect-src 'self' ws: wss:",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
    ])

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
            "magnetometer=(), microphone=(), payment=(), usb=()"
        )

        content_type = response.headers.get("content-type", "")
        if "text/html" in content_type:
            response.headers["Content-Security-Policy"] = self.CSP_POLICY

        if not settings.debug:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        return response


# ---------------------------------------------------------------------------
# Rate Limiting Middleware
# ---------------------------------------------------------------------------

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window rate limiter, per client IP, with bounded memory.

    Limits requests per minute. Only applies to API endpoints. State is
    in-process (matches the single-instance Cloud Run deployment model).
    Cold IPs are evicted via LRU once we exceed ``max_clients``.
    """

    WINDOW_SECONDS = 60.0

    def __init__(self, app, general_rpm: int = 60, scan_rpm: int = 5, max_clients: int = 10_000):
        super().__init__(app)
        self.general_rpm = general_rpm
        self.scan_rpm = scan_rpm
        self.max_clients = max_clients
        self._general_counts: "OrderedDict[str, list[float]]" = OrderedDict()
        self._scan_counts: "OrderedDict[str, list[float]]" = OrderedDict()

    def _check_rate(self, bucket: "OrderedDict[str, list[float]]", key: str, limit: int) -> bool:
        now = time.monotonic()
        timestamps = bucket.get(key, [])
        timestamps = [t for t in timestamps if now - t < self.WINDOW_SECONDS]
        if len(timestamps) >= limit:
            bucket[key] = timestamps
            bucket.move_to_end(key)
            return False
        timestamps.append(now)
        bucket[key] = timestamps
        bucket.move_to_end(key)
        # Evict oldest clients when bucket overflows
        while len(bucket) > self.max_clients:
            bucket.popitem(last=False)
        return True

    def _get_client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path

        if not path.startswith("/api/"):
            return await call_next(request)

        if path.endswith("/health"):
            return await call_next(request)

        client_ip = self._get_client_ip(request)

        if path.endswith("/scans") and request.method == "POST":
            if not self._check_rate(self._scan_counts, client_ip, self.scan_rpm):
                logger.warning("Rate limit exceeded (scan) for %s", client_ip)
                return Response(
                    content=f'{{"detail":"Rate limit exceeded. Max {self.scan_rpm} scans per minute."}}',
                    status_code=429,
                    media_type="application/json",
                    headers={"Retry-After": "60"},
                )

        if not self._check_rate(self._general_counts, client_ip, self.general_rpm):
            logger.warning("Rate limit exceeded (general) for %s", client_ip)
            return Response(
                content='{"detail":"Rate limit exceeded. Try again in a minute."}',
                status_code=429,
                media_type="application/json",
                headers={"Retry-After": "60"},
            )

        return await call_next(request)


# ---------------------------------------------------------------------------
# Request ID Middleware
# ---------------------------------------------------------------------------

class RequestIdMiddleware(BaseHTTPMiddleware):
    """Assigns a unique request ID to each request for tracing."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = request.headers.get("x-request-id") or str(uuid.uuid4())[:12]
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers["X-Request-Id"] = request_id
        return response
