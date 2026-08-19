"""Input validation utilities for API endpoints.

Provides reusable validators for GCP resource identifiers to prevent
injection attacks and ensure well-formed input.
"""

import re

# GCP Project ID: 6-30 chars, lowercase letters, digits, hyphens
# Must start with a letter and cannot end with a hyphen
PROJECT_ID_RE = re.compile(r"^[a-z][a-z0-9\-]{4,28}[a-z0-9]$")

# GCP Organization ID: numeric string, 1-25 digits
ORG_ID_RE = re.compile(r"^\d{1,25}$")

# GCS Bucket name: 3-63 chars, lowercase, digits, hyphens, dots
BUCKET_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$")

# Scan ID: alphanumeric with hyphens (UUID or UUID fragment)
SCAN_ID_RE = re.compile(r"^[a-z0-9\-]{1,36}$")


def validate_project_id(project_id: str) -> str | None:
    """Validate a GCP project ID.

    Returns:
        The cleaned project ID, or None if invalid.
    """
    cleaned = project_id.strip().lower()
    if PROJECT_ID_RE.match(cleaned):
        return cleaned
    return None


def validate_org_id(org_id: str) -> str | None:
    """Validate a GCP organization ID (numeric).

    Returns:
        The cleaned org ID, or None if invalid.
    """
    cleaned = org_id.strip()
    if ORG_ID_RE.match(cleaned):
        return cleaned
    return None


def validate_target_id(target_id: str, scope: str) -> str | None:
    """Validate a target ID based on scope.

    Args:
        target_id: Project ID or Org ID.
        scope: 'project' or 'org'.

    Returns:
        Cleaned target ID or None if invalid.
    """
    if scope == "org":
        return validate_org_id(target_id)
    return validate_project_id(target_id)


def validate_bucket_name(bucket: str) -> str | None:
    """Validate a GCS bucket name.

    Returns:
        The cleaned bucket name, or None if invalid.
    """
    cleaned = bucket.strip().lower()
    if BUCKET_NAME_RE.match(cleaned):
        return cleaned
    return None


def validate_scan_id(scan_id: str) -> str | None:
    """Validate a scan ID.

    Returns:
        The cleaned scan ID, or None if invalid.
    """
    cleaned = scan_id.strip().lower()
    if SCAN_ID_RE.match(cleaned):
        return cleaned
    return None


def sanitize_string(value: str, max_length: int = 500) -> str:
    """Basic string sanitization — strips control characters and limits length."""
    # Remove null bytes and control characters (except newline/tab)
    cleaned = "".join(
        c for c in value if c == "\n" or c == "\t" or (ord(c) >= 32 and ord(c) != 127)
    )
    return cleaned[:max_length]
