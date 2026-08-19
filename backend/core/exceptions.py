"""Custom exception classes for the application.

Centralizes all error types for consistent handling and reporting.
"""

class AppError(Exception):
    """Base class for all application exceptions."""
    pass


class GcloudError(AppError):
    """Raised when a gcloud command fails."""

    def __init__(self, command: str, return_code: int, stderr: str):
        self.command = command
        self.return_code = return_code
        self.stderr = stderr
        super().__init__(f"gcloud command failed (rc={return_code}): {stderr[:500]}")


class ServiceNotEnabledError(AppError):
    """Raised when a GCP service API is not enabled."""

    def __init__(self, service_name: str):
        self.service_name = service_name
        super().__init__(f"Service '{service_name}' is not enabled on the target project.")


class GcloudNotFoundError(AppError):
    """Raised when the gcloud CLI is not installed."""

    def __init__(self):
        super().__init__(
            "gcloud CLI not found. Please install the Google Cloud SDK: "
            "https://cloud.google.com/sdk/docs/install"
        )


class GCPClientError(AppError):
    """Raised when a Google Cloud SDK client fails to initialize."""

    def __init__(self, service: str, error: Exception):
        self.service = service
        self.original_error = error
        super().__init__(f"Failed to initialize GCP client for '{service}': {error}")


class ScanError(AppError):
    """Raised when a scan operation fails."""
    pass
