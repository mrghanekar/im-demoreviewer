"""Async wrapper for executing gcloud CLI commands.

Provides a safe, structured way to run gcloud commands as subprocesses,
parse JSON output, and handle errors gracefully. This is the primary
mechanism for gathering GCP resource data.
"""

import asyncio
import json
import logging
import os
import re
import shlex
import shutil
from typing import Any

from backend.config import settings
from backend.core.exceptions import GcloudError, GcloudNotFoundError, ServiceNotEnabledError

logger = logging.getLogger(__name__)


# Patterns that might appear in gcloud stderr and leak credentials. Replace each
# match with a short redaction marker so we keep enough context for debugging
# without writing tokens to logs or HTTP responses.
_REDACTION_PATTERNS = (
    # OAuth 2 access tokens
    (re.compile(r"ya29\.[A-Za-z0-9_\-]{20,}"), "ya29.<redacted>"),
    # Refresh tokens
    (re.compile(r"1//0[A-Za-z0-9_\-]{20,}"), "1//<redacted>"),
    # Bearer headers gcloud sometimes echoes in --log-http output
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9_\-.]+"), r"\1<redacted>"),
    # API keys (AIza... is the standard format)
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "AIza<redacted>"),
    # GCP service-account private-key JSON snippets
    (re.compile(r'"private_key"\s*:\s*"[^"]+"'), '"private_key":"<redacted>"'),
)


def sanitize_stderr(text: str) -> str:
    """Strip credentials and tokens from gcloud stderr.

    Defense in depth: gcloud's own logs sometimes include access tokens when
    `--log-http` is set or when refresh fails. We forward stderr to logs and
    into GcloudError exception messages (which end up in the UI), so missing
    redaction here means token leakage in two places.
    """
    if not text:
        return text
    for pattern, replacement in _REDACTION_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


# Environment variables the gcloud CLI needs to locate credentials, config and
# a usable Python. Everything else in the parent environment is dropped so a
# subprocess can't inherit unrelated secrets.
_ENV_PASSTHROUGH = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "USER",
    "CLOUDSDK_CONFIG",
    "CLOUDSDK_PYTHON",
    "CLOUDSDK_CORE_PROJECT",
    "CLOUDSDK_CORE_ACCOUNT",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_CLOUD_PROJECT",
    "GCLOUD_PROJECT",
    "CLOUDSDK_PYTHON_SITEPACKAGES",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_FILE",
)


def _subprocess_env() -> dict[str, str]:
    """Build a minimal environment for gcloud subprocesses."""
    return {k: v for k, v in os.environ.items() if k in _ENV_PASSTHROUGH}


def _tokenize(command: str) -> list[str]:
    """Split a gcloud command string into an argv list.

    Commands are executed with create_subprocess_exec rather than through a
    shell, so shell metacharacters in an interpolated value become literal
    argv content instead of new commands. Input validation is still the first
    line of defence; this makes the whole injection class unreachable even if
    a future call site forgets to validate.
    """
    argv = shlex.split(command, posix=True)
    if not argv:
        raise ValueError("empty command")
    if argv[0] != "gcloud":
        raise ValueError(f"only gcloud commands may be executed, got {argv[0]!r}")
    return argv


class GcloudRunner:
    """Async runner for gcloud CLI commands.

    Usage:
        runner = GcloudRunner()
        instances = await runner.run("gcloud compute instances list --project=my-proj --format=json")
    """

    # Cap the per-runner cache so a long-lived single-instance Cloud Run doesn't
    # accumulate hundreds of MB of cached gcloud JSON across many scans.
    _MAX_CACHE_ENTRIES = 4_000

    # Patterns in gcloud stderr that suggest a transient backend problem worth
    # retrying once. Avoid retrying on auth or permission failures — those don't
    # recover and a retry just wastes time.
    _TRANSIENT_STDERR_PATTERNS = (
        "Internal error",
        "backend error",
        "deadline exceeded",
        "deadline was exceeded",
        "503",
        "Service Unavailable",
        "temporarily unavailable",
        "connection reset",
    )

    def __init__(
        self,
        timeout: int | None = None,
        long_timeout: int | None = None,
    ):
        self.timeout = timeout or settings.gcloud_timeout_seconds
        self.long_timeout = long_timeout or settings.gcloud_timeout_long_seconds
        self._gcloud_path: str | None = None
        # OrderedDict so we can LRU-evict at the cap.
        from collections import OrderedDict
        self._cache: "OrderedDict[str, Any]" = OrderedDict()
        self._pending: dict[str, asyncio.Future] = {}

    @property
    def gcloud_available(self) -> bool:
        """Check if gcloud CLI is available on the system."""
        return shutil.which("gcloud") is not None

    def clear_cache(self) -> None:
        """Clear the command result cache (called between scans)."""
        self._cache.clear()

    @staticmethod
    def _ensure_json_format(command: str) -> str:
        """Append --format=json iff no --format flag is present yet.

        Avoids double-format bugs when a caller already pinned a specific
        format like --format='value(name)'.
        """
        try:
            tokens = shlex.split(command, posix=True)
        except ValueError:
            # If shlex fails (unbalanced quotes), don't try to be clever
            return command if "--format" in command else f"{command} --format=json"

        for token in tokens:
            if token == "--format" or token.startswith("--format="):
                return command
        return f"{command} --format=json"

    async def run(
        self,
        command: str,
        timeout: int | None = None,
        use_cache: bool = True,
        parse_json: bool = True,
    ) -> Any:
        """Execute a gcloud command and return parsed output."""
        if not self.gcloud_available:
            raise GcloudNotFoundError()

        if parse_json:
            command = self._ensure_json_format(command)

        if use_cache and command in self._cache:
            logger.debug("Cache hit for: %s", command[:100])
            return self._cache[command]

        # Request coalescing: join existing execution if already in progress
        if command in self._pending:
            logger.debug("Joining pending execution for: %s", command[:100])
            return await self._pending[command]

        future = asyncio.get_running_loop().create_future()
        self._pending[command] = future

        logger.info("Executing: %s", command)
        effective_timeout = timeout or self.timeout

        process: asyncio.subprocess.Process | None = None
        try:
            try:
                argv = _tokenize(command)
            except ValueError as e:
                err = GcloudError(command, -1, f"Malformed command: {e}")
                if not future.done():
                    future.set_exception(err)
                raise err from e

            process = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=_subprocess_env(),
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(),
                    timeout=effective_timeout,
                )
            except asyncio.TimeoutError as e:
                logger.error("Command timed out: %s", command[:100])
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                # Reap the killed child so it doesn't linger as a zombie
                try:
                    await process.wait()
                except Exception:
                    pass
                err = GcloudError(command, -1, f"Command timed out after {effective_timeout}s")
                if not future.done():
                    future.set_exception(err)
                raise err from e

            stdout = stdout_bytes.decode("utf-8", errors="replace").strip()
            stderr = sanitize_stderr(stderr_bytes.decode("utf-8", errors="replace").strip())

            if process.returncode != 0:
                if "API" in stderr and ("not enabled" in stderr or "has not been used" in stderr):
                    service_name = "unknown-service"
                    if "API [" in stderr:
                        try:
                            service_name = stderr.split("API [")[1].split("]")[0]
                        except IndexError:
                            pass
                    logger.info("Service not enabled: %s", service_name)
                    err = ServiceNotEnabledError(service_name)
                    if not future.done():
                        future.set_exception(err)
                    raise err

                logger.error("Command failed (rc=%d): %s", process.returncode, command[:100])
                err = GcloudError(command, process.returncode or 1, stderr)
                if not future.done():
                    future.set_exception(err)
                raise err

            if stderr:
                logger.debug("gcloud stderr (non-fatal): %s", stderr[:300])

            if not stdout:
                result: Any = [] if parse_json else ""
            elif parse_json:
                try:
                    result = json.loads(stdout)
                except json.JSONDecodeError as e:
                    logger.warning("Failed to parse JSON: %s", e)
                    result = []
            else:
                result = stdout

            if use_cache:
                self._cache[command] = result
                self._cache.move_to_end(command)
                while len(self._cache) > self._MAX_CACHE_ENTRIES:
                    self._cache.popitem(last=False)

            if not future.done():
                future.set_result(result)

            return result

        except asyncio.CancelledError:
            # Propagate cancellation to any waiters, then clean up the child process
            if not future.done():
                future.cancel()
            if process is not None and process.returncode is None:
                try:
                    process.kill()
                    await process.wait()
                except (ProcessLookupError, Exception):
                    pass
            raise

        except Exception as e:
            if not future.done():
                future.set_exception(e)
            raise

        finally:
            self._pending.pop(command, None)

    async def run_long(self, command: str, **kwargs: Any) -> Any:
        """Execute a long-running gcloud command with extended timeout."""
        return await self.run(command, timeout=self.long_timeout, **kwargs)

    async def get_active_account(self) -> dict[str, str]:
        """Get the currently active gcloud account."""
        accounts = await self.run(
            "gcloud auth list --filter=status:ACTIVE --format=json",
            use_cache=False,
        )
        if accounts and isinstance(accounts, list):
            return {
                "account": accounts[0].get("account", ""),
                "status": accounts[0].get("status", ""),
            }
        return {"account": "", "status": ""}

    async def get_current_project(self) -> str:
        """Get the currently configured gcloud project ID."""
        result = await self.run(
            "gcloud config get-value project",
            parse_json=False,
            use_cache=False,
        )
        return result.strip() if isinstance(result, str) else ""

    async def get_gcloud_version(self) -> str:
        """Return the running gcloud SDK version string (e.g. '507.0.0').

        Surfaced in the scan summary so users can spot drift between the
        version pinned in the Dockerfile and the one their checks were
        originally authored against. Cached for the lifetime of the runner.
        """
        cache_key = "__gcloud_version__"
        if cache_key in self._cache:
            return self._cache[cache_key]
        try:
            payload = await self.run(
                "gcloud version --format=json",
                use_cache=False,
            )
            version = ""
            if isinstance(payload, dict):
                version = str(payload.get("Google Cloud SDK", "")).strip()
        except Exception as e:
            logger.debug("Could not read gcloud version: %s", e)
            version = ""
        self._cache[cache_key] = version
        return version

    async def list(self, command: str, default: Any = None) -> Any:
        """Run a list-style command and return ``default`` on any failure.

        Standard pattern used by ~150 check classes: wrap a gcloud_runner.run
        in try/except, check ``isinstance(x, list)``, return [] on anything
        unexpected. This helper consolidates that boilerplate so check classes
        can read more like the assertion they're actually making. Use ``default``
        if the caller expects a different empty shape (e.g. {}).
        """
        if default is None:
            default = []
        try:
            result = await self.run(command)
            if not isinstance(result, list):
                # gcloud occasionally returns a single dict for filters that match
                # one resource — treat that as a one-element list for ergonomics.
                if isinstance(result, dict):
                    return [result]
                return default
            return result
        except Exception as e:
            logger.debug("gcloud_runner.list silently swallowed: %s — %s", command[:80], e)
            return default

    async def list_enabled_apis(self, project_id: str) -> set[str]:
        """Return the set of API service names enabled on a project.

        Cached per-project for the lifetime of the runner (cleared between
        scans by ScanEngine via clear_cache). On error returns an empty set;
        callers should treat that as "unknown — don't proactively skip".
        """
        cache_key = f"__enabled_apis__::{project_id}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        try:
            services = await self.run(
                f"gcloud services list --project={project_id} --enabled --format=json",
                use_cache=False,
            )
        except Exception as e:
            logger.warning(
                "Could not list enabled APIs for %s (%s); API-based skipping disabled",
                project_id, e,
            )
            return set()
        if not isinstance(services, list):
            return set()
        # Each entry is {"config": {"name": "compute.googleapis.com"}, ...} or has top-level "name"
        names: set[str] = set()
        for s in services:
            cfg = s.get("config", {}) if isinstance(s, dict) else {}
            name = cfg.get("name") or s.get("name", "")
            if name:
                # serviceusage v1 returns "projects/123/services/compute.googleapis.com"
                names.add(name.split("/")[-1])
        self._cache[cache_key] = names
        return names
