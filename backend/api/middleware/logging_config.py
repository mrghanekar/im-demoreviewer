"""Structured JSON logging for Cloud Logging compatibility.

When running on Cloud Run, Google Cloud Logging automatically parses
JSON-structured log entries. This module provides a JSON formatter
that outputs logs in the expected format.

References:
    https://cloud.google.com/logging/docs/structured-logging
"""

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any


class CloudLoggingFormatter(logging.Formatter):
    """JSON log formatter compatible with Google Cloud Logging.

    Outputs each log entry as a single-line JSON object with fields:
    - severity: Cloud Logging severity level
    - message: Human-readable log message
    - timestamp: ISO 8601 timestamp
    - logger: Logger name (module path)
    - sourceLocation: File, line, function info

    Optional fields (if present in record):
    - httpRequest: For HTTP request context
    - labels: Custom labels for filtering
    """

    # Python logging levels -> Cloud Logging severity
    SEVERITY_MAP = {
        logging.DEBUG: "DEBUG",
        logging.INFO: "INFO",
        logging.WARNING: "WARNING",
        logging.ERROR: "ERROR",
        logging.CRITICAL: "CRITICAL",
    }

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "severity": self.SEVERITY_MAP.get(record.levelno, "DEFAULT"),
            "message": record.getMessage(),
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "logging.googleapis.com/sourceLocation": {
                "file": record.pathname,
                "line": record.lineno,
                "function": record.funcName,
            },
            "logger": record.name,
        }

        # Include exception info if present
        if record.exc_info and record.exc_info[1]:
            entry["exception"] = self.formatException(record.exc_info)

        # Include extra fields
        if hasattr(record, "request_id"):
            entry["logging.googleapis.com/labels"] = {
                "request_id": record.request_id,
            }

        if hasattr(record, "scan_id"):
            entry.setdefault("logging.googleapis.com/labels", {})["scan_id"] = record.scan_id

        return json.dumps(entry, default=str, ensure_ascii=False)


class ConsoleFormatter(logging.Formatter):
    """Human-readable colored formatter for local development."""

    COLORS = {
        logging.DEBUG: "\033[36m",      # Cyan
        logging.INFO: "\033[32m",       # Green
        logging.WARNING: "\033[33m",    # Yellow
        logging.ERROR: "\033[31m",      # Red
        logging.CRITICAL: "\033[1;31m", # Bold Red
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelno, "")
        timestamp = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        return (
            f"{timestamp} | {color}{record.levelname:<8}{self.RESET} | "
            f"{record.name} | {record.getMessage()}"
        )


def setup_logging(log_level: str = "INFO", json_logs: bool = False) -> None:
    """Configure application-wide logging.

    Args:
        log_level: Minimum log level (DEBUG, INFO, WARNING, ERROR).
        json_logs: Use JSON formatter (for Cloud Run) vs console (for dev).
    """
    root = logging.getLogger()
    root.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Clear any existing handlers
    root.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)

    if json_logs:
        handler.setFormatter(CloudLoggingFormatter())
    else:
        handler.setFormatter(ConsoleFormatter())

    root.addHandler(handler)

    # Reduce noise from third-party libs
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("google").setLevel(logging.WARNING)
