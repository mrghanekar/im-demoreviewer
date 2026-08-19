"""Scan orchestrator.

Manages the full lifecycle of a scan: creation, project enumeration
(for org-level scans), engine execution, result aggregation, and
storage. This is the top-level coordinator that the API routes call.
"""

import asyncio
import json
import logging
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from backend.config import settings
from backend.core.engine import CheckEngine
from backend.core.gcloud_runner import GcloudRunner
from backend.core.models import (
    Finding,
    Scan,
    ScanRequest,
    ScanStatus,
    ScanSummary,
    Severity,
)

logger = logging.getLogger(__name__)


class ScanStore:
    """Store for scan sessions with persistence support.
    
    Supports:
    1. In-memory storage (default)
    2. GCS persistence (if DR_GCS_EXPORT_BUCKET is set)
    3. Local file persistence (if DR_DATA_DIR is set)
    """

    # Sentinel used in _miss_cache to remember "we already looked, it's not there"
    # so repeated lookups for a non-existent scan don't hammer GCS.
    _MISS_TTL_SECONDS = 60.0

    def __init__(self) -> None:
        self._scans: dict[str, Scan] = {}
        self._miss_cache: dict[str, float] = {}
        self._gcs_bucket = os.environ.get("DR_GCS_EXPORT_BUCKET") or settings.gcs_export_bucket
        self._data_dir = os.environ.get("DR_DATA_DIR")

        # Initialize persistence — load eagerly so a freshly-rotated Cloud Run
        # instance can serve historical scans before the first user request hits
        # a lazy-load path.
        if self._data_dir:
            self._data_path = Path(self._data_dir)
            self._data_path.mkdir(parents=True, exist_ok=True)
            self._load_from_disk()
        elif self._gcs_bucket:
            try:
                self._sync_index_from_gcs()
            except Exception as e:
                logger.error("Eager GCS sync failed at startup: %s", e)

        # Any RUNNING/PENDING scan we loaded from persistence was orphaned by the
        # previous instance's death — there's no way it's actually still running.
        # Mark it FAILED so the dashboard shows accurate state.
        self._mark_orphaned_scans_failed()

    def _mark_orphaned_scans_failed(self) -> None:
        for scan in list(self._scans.values()):
            if scan.status in (ScanStatus.RUNNING, ScanStatus.PENDING):
                logger.warning(
                    "Marking orphaned scan %s (status=%s) as FAILED on startup",
                    scan.id, scan.status,
                )
                scan.status = ScanStatus.FAILED
                scan.error_message = scan.error_message or (
                    "Interrupted: scan was running when the server restarted; results may be partial."
                )
                if scan.started_at and not scan.completed_at:
                    scan.completed_at = datetime.now(timezone.utc)
                # Best-effort re-persist; don't fail startup if GCS is down.
                try:
                    if self._data_dir:
                        self._save_to_disk(scan)
                    if self._gcs_bucket:
                        self._save_to_gcs(scan)
                except Exception as e:
                    logger.error("Failed to re-persist orphaned scan %s: %s", scan.id, e)

    def _miss_cache_hit(self, scan_id: str) -> bool:
        ts = self._miss_cache.get(scan_id)
        if ts is None:
            return False
        if (datetime.now(timezone.utc).timestamp() - ts) > self._MISS_TTL_SECONDS:
            self._miss_cache.pop(scan_id, None)
            return False
        return True

    def get(self, scan_id: str) -> Scan | None:
        """Get a scan by ID."""
        if scan_id in self._scans:
            return self._scans[scan_id]

        # Recently-seen miss — don't pay the GCS round-trip again.
        if self._miss_cache_hit(scan_id):
            return None

        # Try to load from GCS if not in memory
        if self._gcs_bucket:
            scan = self._load_scan_from_gcs(scan_id)
            if scan:
                self._scans[scan.id] = scan
                return scan

        self._miss_cache[scan_id] = datetime.now(timezone.utc).timestamp()
        return None

    def get_all(self) -> list[Scan]:
        """Get all scans, newest first."""
        # Index is synced eagerly at startup; refresh on every list call would
        # be expensive. Callers that want fresh state should call get(scan_id)
        # directly, which will hit GCS if the scan isn't in memory.
        return sorted(
            self._scans.values(),
            key=lambda s: s.started_at or datetime.min,
            reverse=True,
        )

    def save(self, scan: Scan) -> None:
        """Save or update a scan."""
        self._scans[scan.id] = scan
        # A save invalidates any prior miss for this ID.
        self._miss_cache.pop(scan.id, None)

        if self._data_dir:
            self._save_to_disk(scan)

        if self._gcs_bucket:
            # We save to GCS in background/thread ideally, but here synchronous for safety
            self._save_to_gcs(scan)

    def delete(self, scan_id: str) -> bool:
        """Delete a scan by ID. Returns True if a scan was deleted from any tier."""
        in_memory = self._scans.pop(scan_id, None) is not None
        deleted_disk = False
        deleted_gcs = False

        if self._data_dir:
            try:
                file_path = self._data_path / f"{scan_id}.json"
                if file_path.exists():
                    file_path.unlink()
                    deleted_disk = True
            except Exception as e:
                logger.error("Failed to delete scan %s from disk: %s", scan_id, e)

        if self._gcs_bucket:
            try:
                client = self._get_gcs_client()
                bucket = client.bucket(self._gcs_bucket)
                blob = bucket.blob(f"scans/{scan_id}.json")
                if blob.exists():
                    blob.delete()
                    deleted_gcs = True
            except Exception as e:
                logger.error("Failed to delete scan %s from GCS: %s", scan_id, e)

        # Negative-cache the deletion so a follow-up get() doesn't re-fetch from GCS.
        self._miss_cache[scan_id] = datetime.now(timezone.utc).timestamp()
        return in_memory or deleted_disk or deleted_gcs

    def _save_to_disk(self, scan: Scan) -> None:
        try:
            file_path = self._data_path / f"{scan.id}.json"
            with open(file_path, "w") as f:
                f.write(scan.model_dump_json(indent=2))
        except Exception as e:
            logger.error(f"Failed to save scan {scan.id} to disk: {e}")

    def _load_from_disk(self) -> None:
        try:
            for file_path in self._data_path.glob("*.json"):
                try:
                    with open(file_path, "r") as f:
                        data = json.load(f)
                        scan = Scan(**data)
                        self._scans[scan.id] = scan
                except Exception as e:
                    logger.error(f"Failed to load scan from {file_path}: {e}")
            logger.info(f"Loaded {len(self._scans)} scans from disk")
        except Exception as e:
            logger.error(f"Failed to scan data directory: {e}")

    def _get_gcs_client(self):
        """Get or create a GCS client, reusing connections."""
        from google.cloud import storage
        if not hasattr(self, "_gcs_client") or self._gcs_client is None:
            self._gcs_client = storage.Client()
        return self._gcs_client

    def _save_to_gcs(self, scan: Scan) -> None:
        try:
            client = self._get_gcs_client()
            bucket = client.bucket(self._gcs_bucket)
            blob = bucket.blob(f"scans/{scan.id}.json")
            blob.upload_from_string(
                scan.model_dump_json(),
                content_type="application/json"
            )
        except Exception as e:
            logger.error("Failed to save scan %s to GCS: %s", scan.id, e)

    def _load_scan_from_gcs(self, scan_id: str) -> Scan | None:
        try:
            client = self._get_gcs_client()
            bucket = client.bucket(self._gcs_bucket)
            blob = bucket.blob(f"scans/{scan_id}.json")
            if blob.exists():
                data = json.loads(blob.download_as_string())
                scan = Scan(**data)
                return scan
        except Exception as e:
            logger.error("Failed to load scan %s from GCS: %s", scan_id, e)
        return None

    def _sync_index_from_gcs(self) -> None:
        try:
            client = self._get_gcs_client()
            bucket = client.bucket(self._gcs_bucket)
            blobs = bucket.list_blobs(prefix="scans/")
            for blob in blobs:
                if blob.name.endswith(".json"):
                    scan_id = blob.name.split("/")[-1].replace(".json", "")
                    if scan_id not in self._scans:
                        self._load_scan_from_gcs(scan_id)
        except Exception as e:
            logger.error("Failed to sync index from GCS: %s", e)


class Scanner:
    """Orchestrates scan execution across projects.
    
    For project-level scans: runs checks against a single project.
    For org-level scans: enumerates projects, then runs checks per project.
    """

    def __init__(
        self,
        store: ScanStore | None = None,
        gcloud_runner: GcloudRunner | None = None,
        on_event: Callable[[dict[str, Any]], None] | None = None,
    ):
        """Initialize the scanner.
        
        Args:
            store: ScanStore for persisting scan results.
            gcloud_runner: Shared GcloudRunner instance.
            on_event: Callback for real-time progress events.
        """
        self.store = store or ScanStore()
        self.gcloud_runner = gcloud_runner or GcloudRunner()
        self.on_event = on_event

    def _emit(
        self,
        event_type: str,
        scan_id: str,
        data: dict[str, Any] | None = None,
        on_event: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        """Emit a scan-level event via the supplied callback (or default)."""
        logger.info("Emitting event: %s for scan %s", event_type, scan_id)
        cb = on_event or self.on_event
        if cb:
            cb({
                "event_type": event_type,
                "scan_id": scan_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": data or {},
            })

    async def create_scan(self, request: ScanRequest) -> Scan:
        """Create a new scan from a request.

        Returns:
            Created Scan object (status=PENDING).
        """
        # Full UUID — 8-char prefixes collide once you've run a few hundred scans.
        scan_id = str(uuid.uuid4())
        scan = Scan(
            id=scan_id,
            scope=request.scope,
            target_id=request.target_id,
            categories=request.categories,
            specific_projects=request.specific_projects,
            status=ScanStatus.PENDING,
        )
        self.store.save(scan)
        logger.info("Created scan %s (scope=%s, target=%s)", scan_id, request.scope, request.target_id)
        return scan

    async def run_scan(
        self,
        scan_id: str,
        on_event: Callable[[dict[str, Any]], None] | None = None,
    ) -> Scan | None:
        """Execute a scan asynchronously.

        Args:
            scan_id: ID of a previously created scan.
            on_event: Optional per-scan event callback. Passing it here (instead
                of mutating ``self.on_event``) avoids a race when multiple scans
                run concurrently on the shared Scanner instance.

        Returns:
            Updated Scan object with results, or None if not found.
        """
        scan = self.store.get(scan_id)
        if not scan:
            logger.error("Scan %s not found in store", scan_id)
            return None

        # Per-call event callback; falls back to the Scanner's default
        scan_on_event = on_event or self.on_event

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        # Clear any existing findings/executions in case of retry
        scan.findings = []
        scan.check_executions = []
        scan.summary = ScanSummary()
        # Record the gcloud SDK version that's about to do the work. Surfaces
        # in the scan summary so users notice when CI auto-bumps gcloud and
        # checks behave differently (resource fields can be renamed).
        try:
            scan.gcloud_version = await self.gcloud_runner.get_gcloud_version()
        except Exception as e:
            logger.debug("Couldn't read gcloud version: %s", e)
        self.store.save(scan)

        self._emit("scan_started", scan_id, {
            "scope": scan.scope,
            "target_id": scan.target_id,
            "categories": [c.value for c in scan.categories],
        }, on_event=scan_on_event)

        try:
            # Enumerate projects to scan
            if scan.scope == "org":
                if scan.specific_projects:
                    projects = scan.specific_projects
                    logger.info("Using %d specific projects for org scan", len(projects))
                else:
                    projects = await self._enumerate_org_projects(scan.target_id)
            else:
                projects = [scan.target_id]

            scan.projects_scanned = projects
            self.store.save(scan)

            logger.info("Scanning %d project(s) for scan %s", len(projects), scan_id)

            _scan_lock = threading.Lock()

            def event_interceptor(event: dict[str, Any]) -> None:
                # Forward to the per-scan callback (WebSocket fan-out)
                if scan_on_event:
                    scan_on_event(event)

                event_type = event.get("event_type")
                if event_type == "finding_discovered":
                    try:
                        f = Finding(**event["data"])
                        with _scan_lock:
                            scan.findings.append(f)
                    except Exception as e:
                        logger.error("Failed to update scan findings from event: %s", e)

            all_findings: list[Finding] = []
            all_executions: list = []

            # Clear the gcloud cache ONCE at the start of the whole scan; per-engine
            # clear inside run_checks would wipe in-flight other-project work.
            self.gcloud_runner.clear_cache()

            project_concurrency = max(1, settings.max_concurrent_projects)
            project_sem = asyncio.Semaphore(project_concurrency)

            # Shared finding-ID sequence across all parallel engines so IDs are
            # globally unique within the scan (suppress endpoint relies on this).
            _id_counter = [0]
            _id_lock = threading.Lock()

            def _next_finding_id() -> int:
                with _id_lock:
                    _id_counter[0] += 1
                    return _id_counter[0]

            # Lock for intermediate saves so two completing projects don't write
            # GCS simultaneously and last-writer-wins lose findings.
            _save_lock = threading.Lock()

            async def _run_project(project_id: str) -> tuple[list[Finding], list[Any]]:
                async with project_sem:
                    self._emit(
                        "project_started", scan_id, {"project_id": project_id},
                        on_event=scan_on_event,
                    )
                    # One engine per project — _findings/_executions are instance
                    # state that must not be shared across concurrent run_checks().
                    # The finding-ID sequence IS shared so IDs stay unique.
                    engine = CheckEngine(
                        gcloud_runner=self.gcloud_runner,
                        max_concurrent=settings.max_concurrent_checks,
                        on_event=event_interceptor,
                        finding_id_seq=_next_finding_id,
                    )
                    findings, executions, _s = await engine.run_checks(
                        scan_id=scan_id,
                        project_id=project_id,
                        categories=scan.categories,
                    )
                    # Best-effort intermediate save so a Cloud Run instance
                    # rotation mid-org-scan doesn't lose completed projects.
                    # Serialized by _save_lock to avoid two writers racing on GCS.
                    try:
                        with _save_lock:
                            self.store.save(scan)
                    except Exception as e:
                        logger.warning(
                            "Intermediate save after project %s failed: %s",
                            project_id, e,
                        )
                    self._emit(
                        "project_completed", scan_id,
                        {"project_id": project_id, "findings_count": len(findings)},
                        on_event=scan_on_event,
                    )
                    logger.info(
                        "Project %s completed (%d findings)", project_id, len(findings),
                    )
                    return findings, executions

            # Run projects with bounded concurrency. Failures in one project shouldn't
            # take down the whole scan — gather with return_exceptions.
            project_results = await asyncio.gather(
                *(_run_project(p) for p in projects),
                return_exceptions=True,
            )

            for project_id, result in zip(projects, project_results):
                if isinstance(result, BaseException):
                    logger.error("Project %s failed: %s", project_id, result)
                    continue
                findings, executions = result
                all_findings.extend(findings)
                all_executions.extend(executions)

            # Finalize scan with authoritative data
            scan.findings = all_findings
            scan.check_executions = all_executions
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(timezone.utc)

            duration = (
                (scan.completed_at - scan.started_at).total_seconds()
                if scan.started_at else 0.0
            )

            # Rebuild summary from final findings; pass duration so it's not lost.
            scan.summary = self._compute_aggregate_summary(
                all_findings, all_executions, duration_seconds=duration
            )

            self.store.save(scan)

            self._emit("scan_completed", scan_id, scan.summary.model_dump(mode="json"), on_event=scan_on_event)

            logger.info(
                "Scan %s completed: %d findings in %d projects",
                scan_id,
                scan.summary.total_findings,
                len(projects)
            )

            self._cleanup_bus_state(scan_id)
            return scan

        except Exception as e:
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            scan.completed_at = datetime.now(timezone.utc)
            self.store.save(scan)

            self._emit("scan_failed", scan_id, {"error": str(e)}, on_event=scan_on_event)
            logger.error("Scan %s failed: %s", scan_id, e, exc_info=True)

            self._cleanup_bus_state(scan_id)
            return scan

    @staticmethod
    def _cleanup_bus_state(scan_id: str) -> None:
        """Release the websocket-bus token + queue dict slot for a terminal scan.

        Lives here (instead of being called directly) so the scanner module
        doesn't need a hard import of the websocket route module at top level
        (would create a circular import: routes/scan.py → scanner → websocket).
        """
        try:
            from backend.api.routes.websocket import cleanup_scan_state
            cleanup_scan_state(scan_id)
        except Exception as e:
            logger.debug("Bus cleanup for scan %s skipped: %s", scan_id, e)

    async def cancel_scan(self, scan_id: str) -> Scan | None:
        """Cancel a running scan.
        
        Args:
            scan_id: ID of the scan to cancel.
            
        Returns:
            Updated scan or None if not found.
        """
        scan = self.store.get(scan_id)
        if not scan:
            return None

        if scan.status == ScanStatus.RUNNING:
            scan.status = ScanStatus.CANCELLED
            scan.completed_at = datetime.now(timezone.utc)
            self.store.save(scan)
            self._emit("scan_cancelled", scan_id)
            logger.info("Scan %s cancelled", scan_id)
            self._cleanup_bus_state(scan_id)

        return scan

    async def _enumerate_org_projects(self, org_id: str) -> list[str]:
        """List all projects under an organization recursively.
        
        Uses Cloud Asset Inventory to find all projects, including those in folders.
        
        Args:
            org_id: GCP organization ID.
            
        Returns:
            List of project IDs.
        """
        # Validate strict numeric Org ID to prevent injection or misuse
        if not org_id.isdigit():
            logger.warning("Org ID '%s' is not numeric. Treating as single target ID.", org_id)
            return [org_id]

        try:
            # Use Asset Inventory for recursive search
            results = await self.gcloud_runner.run_long(
                f"gcloud asset search-all-resources --scope=organizations/{org_id} "
                "--asset-types=cloudresourcemanager.googleapis.com/Project "
                "--format='json(additionalAttributes.projectId)'"
            )
            
            project_ids = []
            if isinstance(results, list):
                for res in results:
                    if "additionalAttributes" in res and "projectId" in res["additionalAttributes"]:
                        project_ids.append(res["additionalAttributes"]["projectId"])
            
            project_ids = list(set(project_ids))
            
            if not project_ids:
                logger.warning("Cloud Asset Inventory returned 0 projects for Org %s. Checking permissions...", org_id)
            else:
                logger.info("Enumerated %d projects for org %s via Asset Inventory", len(project_ids), org_id)
                return project_ids
            
        except Exception as e:
            logger.warning("Asset Inventory enumeration failed (likely missing 'cloudasset.viewer' on Org). Error: %s", e)

        # Fallback: List projects where this SA has access and parent matches
        # Note: If SA only has Project Viewer on specific projects, this only returns those.
        try:
            logger.info("Attempting fallback project enumeration via Resource Manager API...")
            projects = await self.gcloud_runner.run(
                f"gcloud projects list --filter=parent.id={org_id} --format='value(projectId)'",
                parse_json=False
            )
            
            p_list = projects.strip().split() if projects else []
            p_list = list(set(p_list))
            
            if len(p_list) <= 1:
                logger.warning(
                    "Enumerated only %d project(s). For a full Organization scan, the Service Account "
                    "needs 'Browser' or 'Viewer' role granted at the Organization level.", 
                    len(p_list)
                )
            
            logger.info("Enumerated %d projects via fallback list", len(p_list))
            return p_list

        except Exception as e2:
            logger.error("Fallback enumeration failed: %s", e2)
            # If all else fails, return nothing (or could raise)
            raise

    def _compute_aggregate_summary(
        self,
        findings: list[Finding],
        executions: list,
        duration_seconds: float = 0.0,
    ) -> ScanSummary:
        """Compute summary across all projects in a scan."""
        from backend.core.models import Category, CheckStatus, compute_health_score

        by_severity: dict[str, int] = {s.value: 0 for s in Severity}
        by_category: dict[str, int] = {c.value: 0 for c in Category}
        by_service: dict[str, int] = {}

        for f in findings:
            # Suppressed findings don't count toward severity totals (or the
            # health score) — that's the point of suppression. They're still
            # in the findings list for the "show suppressed" toggle.
            if getattr(f, "suppressed", False):
                continue
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            by_category[f.category] = by_category.get(f.category, 0) + 1
            by_service[f.service] = by_service.get(f.service, 0) + 1

        checks_passed = sum(1 for e in executions if e.status == CheckStatus.PASSED)
        checks_failed = sum(1 for e in executions if e.status == CheckStatus.FAILED)
        checks_errored = sum(1 for e in executions if e.status == CheckStatus.ERRORED)
        checks_skipped = sum(1 for e in executions if e.status == CheckStatus.SKIPPED)

        health_score, health_grade = compute_health_score(by_severity)

        return ScanSummary(
            total_findings=sum(by_severity.values()),
            by_severity=by_severity,
            by_category=by_category,
            by_service=by_service,
            checks_passed=checks_passed,
            checks_failed=checks_failed,
            checks_errored=checks_errored,
            checks_skipped=checks_skipped,
            scan_duration_seconds=round(duration_seconds, 2),
            health_score=health_score,
            health_grade=health_grade,
        )
