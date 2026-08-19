"""WebSocket endpoint for real-time scan progress streaming.

Clients connect to /api/v1/scans/{scan_id}/stream and receive
events as the scan progresses (check_started, check_completed,
finding_discovered, scan_completed, etc.).

Access control: Requires a valid scan_token query parameter that
is generated when the scan is created.
"""

import asyncio
import hashlib
import hmac
import logging
import secrets
from collections import OrderedDict
from datetime import datetime, timezone

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from fastapi.encoders import jsonable_encoder

from backend.api.middleware.validation import validate_scan_id

logger = logging.getLogger(__name__)

router = APIRouter(tags=["websocket"])

# Hard caps so the in-memory bus can't grow without bound across long-lived
# sessions where scanner never calls cleanup_scan_state (e.g. crashed scan).
_MAX_TOKENS = 1_000
_MAX_QUEUE_KEYS = 1_000

# In-memory event bus for scan events. OrderedDict so LRU eviction below kicks
# out the oldest scans first.
_event_queues: "OrderedDict[str, list[asyncio.Queue]]" = OrderedDict()

# Scan access tokens: scan_id -> token (set when scan is created)
_scan_tokens: "OrderedDict[str, str]" = OrderedDict()

# Module-level secret for HMAC-based token generation
_TOKEN_SECRET = secrets.token_bytes(32)


def generate_scan_token(scan_id: str) -> str:
    """Generate a deterministic access token for a scan."""
    token = hmac.new(_TOKEN_SECRET, scan_id.encode(), hashlib.sha256).hexdigest()[:32]
    _scan_tokens[scan_id] = token
    _scan_tokens.move_to_end(scan_id)
    while len(_scan_tokens) > _MAX_TOKENS:
        evicted_id, _ = _scan_tokens.popitem(last=False)
        logger.debug("Evicted oldest scan token (%s) — token cache full", evicted_id)
    return token


def verify_scan_token(scan_id: str, token: str) -> bool:
    """Verify that the provided token matches the scan's access token."""
    expected = _scan_tokens.get(scan_id)
    if not expected:
        return False
    return hmac.compare_digest(expected, token)


def cleanup_scan_state(scan_id: str) -> None:
    """Drop bus state for a completed/failed/cancelled scan.

    Called by the scanner after a terminal status so the token map and event
    queue dict don't grow for the life of the process. Safe to call multiple
    times; missing entries are silently ignored. If a WebSocket client is still
    subscribed we leave the queue list in place — the client will see the
    terminal event in its stream and unregister itself cleanly.
    """
    _scan_tokens.pop(scan_id, None)
    queues = _event_queues.get(scan_id)
    if queues is not None and not queues:
        _event_queues.pop(scan_id, None)


def get_event_callback(scan_id: str):
    """Create an event callback that broadcasts to all WebSocket clients for a scan."""
    def callback(event: dict):
        if scan_id in _event_queues:
            for queue in _event_queues[scan_id]:
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    pass  # Drop events if client is too slow
    return callback


def register_scan_events(scan_id: str) -> asyncio.Queue:
    """Register a new WebSocket client for scan events."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
    if scan_id not in _event_queues:
        _event_queues[scan_id] = []
    _event_queues[scan_id].append(queue)
    _event_queues.move_to_end(scan_id)
    while len(_event_queues) > _MAX_QUEUE_KEYS:
        evicted_id, _ = _event_queues.popitem(last=False)
        logger.debug("Evicted oldest event-queue slot (%s) — queue cache full", evicted_id)
    return queue


def unregister_scan_events(scan_id: str, queue: asyncio.Queue) -> None:
    """Unregister a WebSocket client."""
    if scan_id in _event_queues:
        _event_queues[scan_id] = [q for q in _event_queues[scan_id] if q is not queue]
        if not _event_queues[scan_id]:
            del _event_queues[scan_id]


@router.websocket("/scans/{scan_id}/stream")
async def scan_stream(websocket: WebSocket, scan_id: str, token: str = Query(default="")):
    """WebSocket endpoint for real-time scan progress.

    Requires a valid `token` query parameter for access control.
    """
    await websocket.accept()

    # Validate scan_id format before any dict lookups
    cleaned_id = validate_scan_id(scan_id)
    if not cleaned_id:
        await websocket.send_json({
            "event_type": "error",
            "data": {"message": "Invalid scan ID"},
        })
        await websocket.close(code=4002)
        return
    scan_id = cleaned_id

    # Verify access token (constant-time compare inside verify_scan_token)
    if not token or not verify_scan_token(scan_id, token):
        await websocket.send_json({
            "event_type": "error",
            "data": {"message": "Invalid or missing scan access token"},
        })
        await websocket.close(code=4003)
        return

    from backend.api.routes.scan import get_store
    store = get_store()
    scan = store.get(scan_id)
    if not scan:
        await websocket.send_json({"event_type": "error", "data": {"message": f"Scan {scan_id} not found"}})
        await websocket.close()
        return

    queue = register_scan_events(scan_id)

    try:
        # Send initial state
        await websocket.send_json({
            "event_type": "connected",
            "scan_id": scan_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {"status": scan.status, "message": "Connected to scan stream"},
        })

        # Stream events until scan completes or client disconnects
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30.0)
                await websocket.send_json(jsonable_encoder(event))

                # If scan completed/failed/cancelled, send final event and close
                if event.get("event_type") in ("scan_completed", "scan_failed", "scan_cancelled"):
                    break
            except asyncio.TimeoutError:
                # Send heartbeat to keep connection alive
                await websocket.send_json(jsonable_encoder({
                    "event_type": "heartbeat",
                    "scan_id": scan_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "data": {},
                }))
                # Check if scan is still running
                current_scan = store.get(scan_id)
                if current_scan and current_scan.status in ("completed", "failed", "cancelled"):
                    await websocket.send_json(jsonable_encoder({
                        "event_type": f"scan_{current_scan.status}",
                        "scan_id": scan_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "data": {"summary": current_scan.summary.model_dump() if current_scan.summary else {}},
                    }))
                    break

    except WebSocketDisconnect:
        logger.debug("WebSocket client disconnected for scan %s", scan_id)
    except Exception as e:
        logger.error("WebSocket error for scan %s: %s", scan_id, e)
    finally:
        unregister_scan_events(scan_id, queue)
