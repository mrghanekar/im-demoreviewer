"""Base check class for all GCP checks.

Every check in the system inherits from BaseCheck. This provides:
- Standardized interface (execute method)
- gcloud CLI execution helper
- GCP API client fallback
- Fix command templating
- Cloud Console link generation
"""

import abc
import logging
from typing import Any, ClassVar

from backend.core.models import (
    Category,
    CheckResult,
    Severity,
    ServiceCategory,
)

logger = logging.getLogger(__name__)


class BaseCheck(abc.ABC):
    """Abstract base class for all GCP checks.
    
    Subclasses must define class attributes and implement execute().
    The check engine discovers checks automatically by scanning for
    BaseCheck subclasses in the checks/ directory.
    
    Example:
        class PublicBucketCheck(BaseCheck):
            id = "GCS-001"
            title = "Bucket is publicly accessible"
            ...
            
            async def execute(self, project_id, gcloud_runner):
                ...
    """

    # --- Class attributes (must be set by subclasses) ---
    id: ClassVar[str] = ""
    title: ClassVar[str] = ""
    description: ClassVar[str] = ""
    severity: ClassVar[Severity] = Severity.MEDIUM
    category: ClassVar[Category] = Category.SECURITY
    service: ClassVar[str] = ""
    service_category: ClassVar[ServiceCategory] = ServiceCategory.SECURITY

    # gcloud command used by this check (for documentation/transparency)
    gcloud_command: ClassVar[str] = ""

    # Fix command template — use {placeholders} for resource-specific values
    fix_command_template: ClassVar[str] = ""

    # Documentation references
    references: ClassVar[list[str]] = []

    # Service APIs this check depends on. The engine fetches the project's enabled-API
    # list once per scan and skips this check (status=SKIPPED) if any required API is
    # disabled, without spending time on subprocess calls that would 403 anyway.
    # Example: ["run.googleapis.com"] for Cloud Run checks.
    required_apis: ClassVar[list[str]] = []

    @abc.abstractmethod
    async def execute(
        self,
        project_id: str,
        gcloud_runner: Any,
    ) -> list[CheckResult]:
        """Run this check against a GCP project.
        
        Args:
            project_id: The GCP project ID to scan.
            gcloud_runner: GcloudRunner instance for executing gcloud commands.
            
        Returns:
            List of CheckResult for each non-compliant resource found.
            Empty list means all resources pass this check.
            
        Raises:
            Should NOT raise exceptions. Catch errors internally and
            return empty list or partial results. The engine handles
            check-level error tracking separately.
        """
        ...

    def build_fix_command(self, **kwargs: str) -> str:
        """Build a fix command from the template with resource-specific values.
        
        Args:
            **kwargs: Values to substitute into fix_command_template.
            
        Returns:
            Formatted gcloud fix command string.
        """
        if not self.fix_command_template:
            return ""
        try:
            return self.fix_command_template.format(**kwargs)
        except KeyError as e:
            logger.warning(
                "Missing template variable %s for check %s fix command",
                e, self.id,
            )
            return self.fix_command_template

    def console_link(self, resource_type: str, project_id: str, **kwargs: str) -> str:
        """Build a Google Cloud Console URL for a resource.
        
        Args:
            resource_type: Type of resource for URL construction.
            project_id: GCP project ID.
            **kwargs: Additional URL parameters (name, zone, region, etc.)
            
        Returns:
            Cloud Console URL string.
        """
        base = "https://console.cloud.google.com"

        url_patterns: dict[str, str] = {
            "gke_cluster": "{base}/kubernetes/clusters/details/{location}/{name}/details?project={project_id}",
            "gce_instance": "{base}/compute/instancesDetail/zones/{zone}/instances/{name}?project={project_id}",
            "gcs_bucket": "{base}/storage/browser/{name}?project={project_id}",
            "cloudsql": "{base}/sql/instances/{name}/overview?project={project_id}",
            "vpc_network": "{base}/networking/networks/details/{name}?project={project_id}",
            "firewall_rule": "{base}/networking/firewalls/details/{name}?project={project_id}",
            "service_account": "{base}/iam-admin/serviceaccounts/details/{email}?project={project_id}",
            "iam": "{base}/iam-admin/iam?project={project_id}",
            "bigquery_dataset": "{base}/bigquery?project={project_id}&d={name}&p={project_id}&page=dataset",
            "pubsub_topic": "{base}/cloudpubsub/topic/detail/{name}?project={project_id}",
            "monitoring": "{base}/monitoring?project={project_id}",
            "logging": "{base}/logs?project={project_id}",
            "billing": "{base}/billing?project={project_id}",
        }

        pattern = url_patterns.get(resource_type, "{base}?project={project_id}")
        try:
            return pattern.format(base=base, project_id=project_id, **kwargs)
        except KeyError:
            return f"{base}?project={project_id}"

    def to_catalog_entry(self) -> dict[str, str]:
        """Convert this check to a catalog entry for the checks listing API.
        
        Returns:
            Dictionary suitable for CheckCatalogEntry model.
        """
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "service": self.service,
            "service_category": self.service_category,
        }

    def __repr__(self) -> str:
        return f"<Check {self.id}: {self.title}>"
