"""Application configuration via environment variables.

All configuration is loaded from environment variables with sensible defaults.
Use a .env file for local development.
"""

import logging
from enum import StrEnum
from typing import List

from pydantic import model_validator
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)


class ScanScope(StrEnum):
    """Scope level for scanning."""
    ORG = "org"
    PROJECT = "project"


class LogLevel(StrEnum):
    """Logging level."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class Settings(BaseSettings):
    """Application settings loaded from environment variables.

    All variables are prefixed with DR_ (Democratized Reviewer).
    """

    # Scan configuration
    scan_scope: ScanScope = ScanScope.PROJECT
    target_id: str = ""
    default_org_id: str = ""
    sa_email: str = ""

    # Server configuration
    port: int = 8080
    host: str = "0.0.0.0"
    log_level: LogLevel = LogLevel.INFO
    debug: bool = False
    cors_origins: List[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Security configuration
    rate_limit_general_rpm: int = 120
    rate_limit_scan_rpm: int = 10
    max_request_body_bytes: int = 1_048_576  # 1 MiB

    # Export configuration
    gcs_export_bucket: str = ""
    # Additional buckets the export endpoint may write to. The export payload is
    # a full inventory of the estate, so an unconstrained bucket parameter is an
    # exfiltration channel — callers may only target buckets named here or in
    # gcs_export_bucket.
    gcs_export_bucket_allowlist: List[str] = []

    # Engine configuration
    max_concurrent_checks: int = 10
    max_concurrent_projects: int = 4  # Org-scope: how many projects run in parallel
    gcloud_timeout_seconds: int = 30
    gcloud_timeout_long_seconds: int = 120
    check_timeout_seconds: int = 120

    # Compliance configuration
    # Region allow-list consulted by REG-004 (data-residency check in
    # backend/checks/compliance/). Empty (the default) leaves the check inert —
    # it reports nothing until an operator opts in. For an Indian DPDP/CERT-In
    # engagement set DR_DATA_RESIDENCY_ALLOWED_REGIONS='["asia-south1","asia-south2"]'.
    data_residency_allowed_regions: list[str] = []

    # AI configuration — only Gemini 3-series models are allowed.
    ai_model: str = "gemini-3-flash"
    ai_timeout_seconds: int = 120

    # App metadata
    app_name: str = "Democratized Reviewer"
    app_version: str = "0.1.0"

    @model_validator(mode="after")
    def validate_cross_field_dependencies(self):
        """Validate configuration dependencies between fields."""
        if self.scan_scope == ScanScope.ORG and not self.default_org_id:
            logger.warning(
                "DR_SCAN_SCOPE is 'org' but DR_DEFAULT_ORG_ID is not set. "
                "Org-level scans will require an org_id to be provided per request."
            )
        return self

    model_config = {
        "env_prefix": "DR_",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }


# Singleton instance
settings = Settings()
