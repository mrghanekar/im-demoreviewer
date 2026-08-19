"""Check execution engine.

Orchestrates the parallel execution of checks against GCP projects.
Handles concurrency limits, error isolation, progress tracking,
and result aggregation.
"""

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any, Callable

from backend.checks.base import BaseCheck
from backend.checks.registry import get_checks_by_service
from backend.config import settings
from backend.core.gcloud_runner import GcloudRunner
from backend.core.exceptions import ServiceNotEnabledError
from backend.core.models import (
    Category,
    CheckExecution,
    CheckResult,
    CheckStatus,
    Finding,
    ScanSummary,
    ServiceCategory,
    Severity,
)

logger = logging.getLogger(__name__)


class CheckEngine:
    """Executes checks against GCP projects with controlled concurrency.
    
    The engine:
    1. Gathers checks for the requested service categories
    2. Runs them in parallel (bounded by max_concurrent)
    3. Tracks execution status per check
    4. Collects findings and computes summary statistics
    5. Emits progress events for real-time UI updates
    """

    # Permission-storm short-circuit: if a scan's SA has no read perms on the
    # target project, every check's first gcloud call returns 403. Without
    # this guard, all 213 checks each waste up to `check_timeout_seconds`
    # before failing, and the scan can take an hour to "fail". When we see
    # >= PERMISSION_STORM_THRESHOLD perm-denied errors in the first
    # PERMISSION_STORM_WINDOW_SECONDS, mark the scan aborted; remaining
    # checks fast-path to SKIPPED.
    PERMISSION_STORM_THRESHOLD = 5
    PERMISSION_STORM_WINDOW_SECONDS = 30

    def __init__(
        self,
        gcloud_runner: GcloudRunner | None = None,
        max_concurrent: int = 10,
        on_event: Callable[[dict[str, Any]], None] | None = None,
        finding_id_seq: Callable[[], int] | None = None,
    ):
        """Initialize the check engine.

        Args:
            gcloud_runner: GcloudRunner instance (created if not provided).
            max_concurrent: Maximum number of checks running simultaneously.
            on_event: Callback for real-time progress events.
            finding_id_seq: Optional zero-arg callable returning the next integer
                to use as the finding's numeric suffix. When the scanner runs
                multiple engines in parallel (one per project), passing a shared
                sequence keeps finding IDs globally unique within a scan;
                otherwise each engine starts from 1 and IDs collide.
        """
        self.gcloud_runner = gcloud_runner or GcloudRunner()
        self.max_concurrent = max_concurrent
        self.on_event = on_event

        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._findings: list[Finding] = []
        self._executions: list[CheckExecution] = []
        self._finding_counter: int = 0
        self._finding_id_seq = finding_id_seq
        self._scan_id: str = ""
        # Permission-storm tracking — reset at the start of each run_checks().
        self._scan_start_time: float = 0.0
        self._permission_denied_count: int = 0
        self._scan_aborted: bool = False
        self._abort_reason: str = ""

    @staticmethod
    def _looks_like_permission_denied(err: BaseException) -> bool:
        """Heuristic for whether an exception came from a 403 on the target."""
        msg = (str(err) or "").lower()
        return (
            "permission_denied" in msg
            or "permission denied" in msg
            or "does not have permission" in msg
            or "forbidden" in msg
            or "403" in msg
        )

    def _maybe_trip_permission_storm(self) -> None:
        """Flip the abort flag when the permission-denied window is exceeded."""
        if self._scan_aborted:
            return
        elapsed = time.monotonic() - self._scan_start_time
        if (
            self._permission_denied_count >= self.PERMISSION_STORM_THRESHOLD
            and elapsed < self.PERMISSION_STORM_WINDOW_SECONDS
        ):
            self._scan_aborted = True
            self._abort_reason = (
                f"Aborted: the service account has no read permission on this project. "
                f"Saw {self._permission_denied_count} PERMISSION_DENIED responses in the first "
                f"{int(elapsed)}s. Grant the SA viewer roles "
                f"(see `./setup.sh --grant-on <PROJECT>`) and re-scan."
            )
            logger.warning(self._abort_reason)
            self._emit_event("debug", {"message": f"[ABORT] {self._abort_reason}"})

    def _emit_event(self, event_type: str, data: dict[str, Any] | None = None) -> None:
        """Emit a progress event if a callback is registered."""
        if self.on_event:
            self.on_event({
                "event_type": event_type,
                "scan_id": self._scan_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": data or {},
            })

    async def _run_single_check(
        self,
        check: BaseCheck,
        project_id: str,
        execution: CheckExecution,
    ) -> list[Finding]:
        """Run a single check with concurrency control and error isolation.
        
        Args:
            check: The check instance to execute.
            project_id: GCP project to check.
            execution: CheckExecution tracker for this check.
            
        Returns:
            List of findings from this check (may be empty).
        """
        # Fast-path SKIP if the engine has already tripped the 403-storm guard:
        # don't waste another subprocess on a project we know we can't read.
        if self._scan_aborted:
            execution.status = CheckStatus.SKIPPED
            execution.error_message = self._abort_reason
            execution.started_at = datetime.now(timezone.utc)
            execution.completed_at = execution.started_at
            execution.duration_ms = 0
            self._emit_event("check_completed", {
                "check_id": check.id,
                "status": "skipped",
                "error": execution.error_message,
                "duration_ms": 0,
            })
            return []

        async with self._semaphore:
            execution.status = CheckStatus.RUNNING
            execution.started_at = datetime.now(timezone.utc)

            self._emit_event("check_started", {
                "check_id": check.id,
                "check_title": check.title,
                "project_id": project_id,
            })

            start_time = time.monotonic()

            try:
                # Enforce a hard timeout per check to prevent stalls
                check_timeout = float(settings.check_timeout_seconds)
                results: list[CheckResult] = await asyncio.wait_for(
                    check.execute(
                        project_id=project_id,
                        gcloud_runner=self.gcloud_runner,
                    ),
                    timeout=check_timeout,
                )

                elapsed_ms = int((time.monotonic() - start_time) * 1000)
                execution.duration_ms = elapsed_ms
                execution.completed_at = datetime.now(timezone.utc)

                # Convert CheckResults to Findings. When a shared sequence is
                # injected (multi-project parallel scans), use it for global
                # uniqueness; otherwise fall back to a per-engine counter.
                findings: list[Finding] = []
                for result in results:
                    if self._finding_id_seq is not None:
                        idx = self._finding_id_seq()
                    else:
                        self._finding_counter += 1
                        idx = self._finding_counter
                    finding = Finding(
                        id=f"{self._scan_id}-{idx:04d}",
                        scan_id=self._scan_id,
                        **result.model_dump(),
                    )
                    findings.append(finding)

                    self._emit_event("finding_discovered", finding.model_dump(mode="json"))

                execution.findings_count = len(findings)
                execution.status = (
                    CheckStatus.FAILED if findings else CheckStatus.PASSED
                )

                logger.info(
                    "Check %s completed in %dms — %d finding(s)",
                    check.id, elapsed_ms, len(findings),
                )

                self._emit_event("check_completed", {
                    "check_id": check.id,
                    "status": execution.status,
                    "findings_count": len(findings),
                    "duration_ms": elapsed_ms,
                })

                return findings

            except ServiceNotEnabledError as e:
                # Reactive skip — the pre-skip path missed this one either because
                # the check didn't declare the required API or the enabled-API
                # list couldn't be fetched. Match the pre-skip wording so the
                # UI shows one consistent reason regardless of code path.
                elapsed_ms = int((time.monotonic() - start_time) * 1000)
                execution.duration_ms = elapsed_ms
                execution.completed_at = datetime.now(timezone.utc)
                execution.status = CheckStatus.SKIPPED
                execution.error_message = (
                    f"Skipped: service not active in project (API disabled: {e})"
                )

                logger.info(
                    "Check %s skipped (API disabled) after %dms",
                    check.id, elapsed_ms,
                )

                self._emit_event("check_completed", {
                    "check_id": check.id,
                    "status": "skipped",
                    "error": execution.error_message,
                    "duration_ms": elapsed_ms,
                })

                return []

            except BaseException as e:
                elapsed_ms = int((time.monotonic() - start_time) * 1000)
                execution.duration_ms = elapsed_ms
                execution.completed_at = datetime.now(timezone.utc)
                execution.status = CheckStatus.ERRORED
                execution.error_message = str(e)

                logger.error(
                    "Check %s errored/crashed after %dms: %s",
                    check.id, elapsed_ms, e,
                    exc_info=True,
                )

                self._emit_event("check_completed", {
                    "check_id": check.id,
                    "status": "errored",
                    "error": str(e),
                    "duration_ms": elapsed_ms,
                })

                # Track permission-denied errors to detect a 403-storm early.
                # Don't count CancelledError or timeouts — only auth-shaped fails.
                if not isinstance(e, asyncio.CancelledError) and self._looks_like_permission_denied(e):
                    self._permission_denied_count += 1
                    self._maybe_trip_permission_storm()

                # Re-raise CancelledError to ensure proper task cancellation
                if isinstance(e, asyncio.CancelledError):
                    raise

                return []

    async def _skip_for_disabled_apis(
        self,
        check: BaseCheck,
        execution: CheckExecution,
        enabled_apis: set[str],
    ) -> bool:
        """Return True if the check was pre-skipped due to disabled APIs."""
        if not check.required_apis or not enabled_apis:
            return False
        missing = [api for api in check.required_apis if api not in enabled_apis]
        if not missing:
            return False
        execution.status = CheckStatus.SKIPPED
        execution.error_message = f"Skipped: service not active in project (API disabled: {', '.join(missing)})"
        execution.started_at = datetime.now(timezone.utc)
        execution.completed_at = execution.started_at
        execution.duration_ms = 0
        self._emit_event("check_completed", {
            "check_id": check.id,
            "status": "skipped",
            "error": execution.error_message,
            "duration_ms": 0,
        })
        return True

    async def run_checks(
        self,
        scan_id: str,
        project_id: str,
        categories: list[ServiceCategory],
    ) -> tuple[list[Finding], list[CheckExecution], ScanSummary]:
        """Run all checks for the given categories against a project.
        
        Args:
            scan_id: Unique scan identifier.
            project_id: GCP project to scan.
            categories: Service categories to include.
            
        Returns:
            Tuple of (findings, check_executions, summary).
        """
        self._scan_id = scan_id
        self._findings = []
        self._executions = []
        self._finding_counter = 0
        # Reset 403-storm tracking per run so a previous project's failures
        # don't carry over (each project gets its own engine instance under C5,
        # but this is also called directly in tests and single-project flows).
        self._scan_start_time = time.monotonic()
        self._permission_denied_count = 0
        self._scan_aborted = False
        self._abort_reason = ""

        # Validate project_id is not empty
        if not project_id or not project_id.strip():
            logger.error("Empty project_id passed to run_checks for scan %s", scan_id)
            return [], [], ScanSummary()

        # NOTE: gcloud cache is NOT cleared here. The scanner clears it once at
        # the start of a multi-project scan; clearing per-project would wipe
        # other-project work in flight when projects run concurrently.

        # Gather checks for requested categories
        all_checks: list[BaseCheck] = []
        for cat in categories:
            checks = get_checks_by_service(cat)
            all_checks.extend(checks)

        self._emit_event("debug", {
            "message": f"Discovered {len(all_checks)} checks for project {project_id} (categories: {len(categories)})"
        })

        logger.info(
            "Running %d checks across %d categories for project %s",
            len(all_checks), len(categories), project_id,
        )

        if not all_checks:
            logger.warning("No checks found for categories: %s", categories)
            return [], [], ScanSummary()

        # Create execution trackers
        executions: list[CheckExecution] = []
        for check in all_checks:
            executions.append(CheckExecution(
                check_id=check.id,
                check_title=check.title,
                service_category=check.service_category,
            ))
        self._executions = executions

        # Pre-fetch enabled APIs once so we can skip checks for services that
        # aren't active in this project (avoids hundreds of guaranteed-to-fail
        # subprocess calls). On error returns empty set → fall back to running
        # everything and relying on ServiceNotEnabledError reactive skipping.
        enabled_apis = await self.gcloud_runner.list_enabled_apis(project_id)
        if enabled_apis:
            self._emit_event("debug", {
                "message": f"{len(enabled_apis)} APIs enabled on {project_id}; will skip checks for disabled services",
            })

        # Run checks in parallel
        start_time = time.monotonic()

        self._emit_event("debug", {"message": f"Starting concurrent execution of {len(executions)} checks"})

        tasks = []
        for check, execution in zip(all_checks, executions):
            if await self._skip_for_disabled_apis(check, execution, enabled_apis):
                # Pre-skip: synthesize an empty-results coroutine so gather() shape is preserved
                async def _noop() -> list[Finding]:
                    return []
                tasks.append(_noop())
            else:
                tasks.append(self._run_single_check(check, project_id, execution))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Flatten findings
        findings: list[Finding] = []
        for result in results:
            if isinstance(result, list):
                findings.extend(result)
            elif isinstance(result, Exception):
                logger.error("Unexpected task exception: %s", result)

        elapsed = time.monotonic() - start_time

        # Compute summary
        summary = self._compute_summary(findings, executions, elapsed)

        logger.info(
            "Scan complete for project %s: %d checks (%d passed, %d failed, %d errored, %d skipped), %d findings, %.1fs",
            project_id,
            len(executions),
            summary.checks_passed,
            summary.checks_failed,
            summary.checks_errored,
            summary.checks_skipped,
            summary.total_findings,
            elapsed,
        )

        return findings, executions, summary

    def _compute_summary(
        self,
        findings: list[Finding],
        executions: list[CheckExecution],
        duration_seconds: float,
    ) -> ScanSummary:
        """Compute scan summary statistics.
        
        Args:
            findings: All findings from the scan.
            executions: All check execution records.
            duration_seconds: Total scan duration.
            
        Returns:
            Populated ScanSummary.
        """
        by_severity: dict[str, int] = {s.value: 0 for s in Severity}
        by_category: dict[str, int] = {c.value: 0 for c in Category}
        by_service: dict[str, int] = {}

        for f in findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            by_category[f.category] = by_category.get(f.category, 0) + 1
            by_service[f.service] = by_service.get(f.service, 0) + 1

        checks_passed = sum(1 for e in executions if e.status == CheckStatus.PASSED)
        checks_failed = sum(1 for e in executions if e.status == CheckStatus.FAILED)
        checks_errored = sum(1 for e in executions if e.status == CheckStatus.ERRORED)
        checks_skipped = sum(1 for e in executions if e.status == CheckStatus.SKIPPED)

        return ScanSummary(
            total_findings=len(findings),
            by_severity=by_severity,
            by_category=by_category,
            by_service=by_service,
            checks_passed=checks_passed,
            checks_failed=checks_failed,
            checks_errored=checks_errored,
            checks_skipped=checks_skipped,
            scan_duration_seconds=round(duration_seconds, 2),
        )
