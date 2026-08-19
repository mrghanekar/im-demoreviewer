"""GCS bucket security and configuration checks.

Checks: GCS-001 through GCS-010
"""

import logging
from typing import Any

from backend.checks.base import BaseCheck
from backend.core.models import Category, CheckResult, Severity, ServiceCategory

logger = logging.getLogger(__name__)


class PublicBucket(BaseCheck):
    id = "GCS-001"
    title = "Bucket is publicly accessible"
    description = "The bucket has IAM bindings granting access to allUsers or allAuthenticatedUsers."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    service = "GCS"
    service_category = ServiceCategory.GCS
    gcloud_command = "gcloud storage buckets get-iam-policy gs://{bucket} --format=json"
    fix_command_template = (
        "gcloud storage buckets remove-iam-policy-binding gs://{bucket} "
        "--member='{member}' --role='{role}'"
    )
    references = ["https://cloud.google.com/storage/docs/public-access-prevention"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            buckets = await gcloud_runner.run(f"gcloud storage buckets list --project={project_id} --format=json")
            if not isinstance(buckets, list):
                return []
            for b in buckets:
                name = b.get("name", "") or b.get("metadata", {}).get("name", "")
                if not name:
                    continue
                try:
                    policy = await gcloud_runner.run(f"gcloud storage buckets get-iam-policy gs://{name} --format=json")
                    if not isinstance(policy, dict):
                        continue
                    for binding in policy.get("bindings", []):
                        role = binding.get("role", "")
                        for member in binding.get("members", []):
                            if member in ("allUsers", "allAuthenticatedUsers"):
                                findings.append(CheckResult(
                                    check_id=self.id, title=self.title, description=self.description,
                                    severity=self.severity, category=self.category, service=self.service,
                                    resource_name=f"gs://{name}", project_id=project_id,
                                    resource_link=self.console_link("gcs_bucket", project_id, name=name),
                                    current_state=f"'{member}' has role '{role}' — publicly accessible",
                                    recommended_state="Remove public access and enable public access prevention",
                                    fix_command=self.build_fix_command(bucket=name, member=member, role=role),
                                    references=self.references,
                                ))
                except Exception as e:
                    logger.debug("Could not get IAM policy for bucket %s: %s", name, e)
        except Exception as e:
            logger.error("GCS-001 failed: %s", e)
        return findings


class UniformBucketAccess(BaseCheck):
    id = "GCS-002"
    title = "Uniform bucket-level access not enabled"
    description = "Uniform bucket-level access simplifies permissions by disabling ACLs."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "GCS"
    service_category = ServiceCategory.GCS
    fix_command_template = "gcloud storage buckets update gs://{bucket} --uniform-bucket-level-access"
    references = ["https://cloud.google.com/storage/docs/uniform-bucket-level-access"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            buckets = await gcloud_runner.run(f"gcloud storage buckets list --project={project_id} --format=json")
            if not isinstance(buckets, list):
                return []
            for b in buckets:
                name = b.get("name", "") or b.get("metadata", {}).get("name", "")
                if not name:
                    continue
                uba = (b.get("iamConfiguration", {}) or {}).get("uniformBucketLevelAccess", {})
                if not uba:
                    meta = b.get("metadata", {})
                    uba = (meta.get("iamConfiguration", {}) or {}).get("uniformBucketLevelAccess", {})
                if not uba.get("enabled", False):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"gs://{name}", project_id=project_id,
                        resource_link=self.console_link("gcs_bucket", project_id, name=name),
                        current_state="Uniform bucket-level access is disabled (using legacy ACLs)",
                        recommended_state="Enable uniform bucket-level access",
                        fix_command=self.build_fix_command(bucket=name),
                        references=self.references,
                    ))
        except Exception as e:
            logger.error("GCS-002 failed: %s", e)
        return findings


class BucketNotCMEK(BaseCheck):
    id = "GCS-003"
    title = "Bucket not encrypted with CMEK"
    description = "The bucket uses Google-managed encryption keys instead of customer-managed (CMEK)."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "GCS"
    service_category = ServiceCategory.GCS
    fix_command_template = "gcloud storage buckets update gs://{bucket} --default-encryption-key=projects/{project_id}/locations/{location}/keyRings/KEY_RING/cryptoKeys/KEY_NAME"
    references = ["https://cloud.google.com/storage/docs/encryption/using-customer-managed-keys"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            buckets = await gcloud_runner.run(f"gcloud storage buckets list --project={project_id} --format=json")
            if not isinstance(buckets, list):
                return []
            for b in buckets:
                name = b.get("name", "") or b.get("metadata", {}).get("name", "")
                if not name:
                    continue
                encryption = b.get("encryption", {}) or b.get("metadata", {}).get("encryption", {})
                if not encryption or not encryption.get("defaultKmsKeyName"):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"gs://{name}", project_id=project_id,
                        resource_link=self.console_link("gcs_bucket", project_id, name=name),
                        current_state="Using Google-managed encryption (default)",
                        recommended_state="Configure CMEK encryption for sensitive data",
                        fix_command=self.build_fix_command(bucket=name, project_id=project_id, location="LOCATION"),
                        references=self.references,
                    ))
        except Exception as e:
            logger.error("GCS-003 failed: %s", e)
        return findings


class VersioningNotEnabled(BaseCheck):
    id = "GCS-004"
    title = "Object versioning not enabled"
    description = "Without versioning, deleted or overwritten objects cannot be recovered."
    severity = Severity.MEDIUM
    category = Category.RELIABILITY
    service = "GCS"
    service_category = ServiceCategory.GCS
    fix_command_template = "gcloud storage buckets update gs://{bucket} --versioning"
    references = ["https://cloud.google.com/storage/docs/object-versioning"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            buckets = await gcloud_runner.run(f"gcloud storage buckets list --project={project_id} --format=json")
            if not isinstance(buckets, list):
                return []
            for b in buckets:
                name = b.get("name", "") or b.get("metadata", {}).get("name", "")
                if not name:
                    continue
                versioning = b.get("versioning", {}) or b.get("metadata", {}).get("versioning", {})
                if not versioning.get("enabled", False):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"gs://{name}", project_id=project_id,
                        resource_link=self.console_link("gcs_bucket", project_id, name=name),
                        current_state="Object versioning is disabled",
                        recommended_state="Enable versioning for data protection",
                        fix_command=self.build_fix_command(bucket=name),
                        references=self.references,
                    ))
        except Exception as e:
            logger.error("GCS-004 failed: %s", e)
        return findings


class NoLifecyclePolicy(BaseCheck):
    id = "GCS-005"
    title = "No lifecycle policy configured"
    description = "Without lifecycle rules, old or unused objects accumulate and increase storage costs."
    severity = Severity.MEDIUM
    category = Category.COST
    service = "GCS"
    service_category = ServiceCategory.GCS
    fix_command_template = ""
    references = ["https://cloud.google.com/storage/docs/lifecycle"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            buckets = await gcloud_runner.run(f"gcloud storage buckets list --project={project_id} --format=json")
            if not isinstance(buckets, list):
                return []
            for b in buckets:
                name = b.get("name", "") or b.get("metadata", {}).get("name", "")
                if not name:
                    continue
                lifecycle = b.get("lifecycle", {}) or b.get("metadata", {}).get("lifecycle", {})
                rules = lifecycle.get("rule", [])
                if not rules:
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"gs://{name}", project_id=project_id,
                        resource_link=self.console_link("gcs_bucket", project_id, name=name),
                        current_state="No lifecycle rules configured",
                        recommended_state="Add lifecycle rules to transition/delete old objects",
                        fix_command="",
                        references=self.references,
                    ))
        except Exception as e:
            logger.error("GCS-005 failed: %s", e)
        return findings


class BucketLoggingNotEnabled(BaseCheck):
    id = "GCS-006"
    title = "Access logging not enabled on bucket"
    description = "Access logs track requests to bucket objects for auditing and security monitoring."
    severity = Severity.MEDIUM
    category = Category.OPERATIONS
    service = "GCS"
    service_category = ServiceCategory.GCS
    fix_command_template = "gcloud storage buckets update gs://{bucket} --log-bucket=gs://{bucket}-logs"
    references = ["https://cloud.google.com/storage/docs/access-logs"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            buckets = await gcloud_runner.run(f"gcloud storage buckets list --project={project_id} --format=json")
            if not isinstance(buckets, list):
                return []
            for b in buckets:
                name = b.get("name", "") or b.get("metadata", {}).get("name", "")
                if not name:
                    continue
                logging_conf = b.get("logging", {}) or b.get("metadata", {}).get("logging", {})
                if not logging_conf or not logging_conf.get("logBucket"):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"gs://{name}", project_id=project_id,
                        resource_link=self.console_link("gcs_bucket", project_id, name=name),
                        current_state="Access logging is not enabled",
                        recommended_state="Enable access logging to a separate log bucket",
                        fix_command=self.build_fix_command(bucket=name),
                        references=self.references,
                    ))
        except Exception as e:
            logger.error("GCS-006 failed: %s", e)
        return findings


class NoRetentionPolicy(BaseCheck):
    id = "GCS-007"
    title = "No retention policy set on bucket"
    description = "A retention policy prevents premature deletion of objects for compliance purposes."
    severity = Severity.LOW
    category = Category.SECURITY
    service = "GCS"
    service_category = ServiceCategory.GCS
    fix_command_template = "gcloud storage buckets update gs://{bucket} --retention-period=365d"
    references = ["https://cloud.google.com/storage/docs/bucket-lock"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            buckets = await gcloud_runner.run(f"gcloud storage buckets list --project={project_id} --format=json")
            if not isinstance(buckets, list):
                return []
            for b in buckets:
                name = b.get("name", "") or b.get("metadata", {}).get("name", "")
                if not name:
                    continue
                retention = b.get("retentionPolicy", {}) or b.get("metadata", {}).get("retentionPolicy", {})
                if not retention or not retention.get("retentionPeriod"):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"gs://{name}", project_id=project_id,
                        resource_link=self.console_link("gcs_bucket", project_id, name=name),
                        current_state="No retention policy configured",
                        recommended_state="Set retention policy for compliance-sensitive buckets",
                        fix_command=self.build_fix_command(bucket=name),
                        references=self.references,
                    ))
        except Exception as e:
            logger.error("GCS-007 failed: %s", e)
        return findings


class SingleRegionBucket(BaseCheck):
    id = "GCS-008"
    title = "Bucket in single region (no geo-redundancy)"
    description = "Single-region buckets lack geographic redundancy. Use multi-region or dual-region for critical data."
    severity = Severity.LOW
    category = Category.RELIABILITY
    service = "GCS"
    service_category = ServiceCategory.GCS
    fix_command_template = ""
    references = ["https://cloud.google.com/storage/docs/locations"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            buckets = await gcloud_runner.run(f"gcloud storage buckets list --project={project_id} --format=json")
            if not isinstance(buckets, list):
                return []
            for b in buckets:
                name = b.get("name", "") or b.get("metadata", {}).get("name", "")
                location = b.get("location", "") or b.get("metadata", {}).get("location", "")
                loc_type = b.get("locationType", "") or b.get("metadata", {}).get("locationType", "")
                if not name:
                    continue
                if loc_type and loc_type.lower() == "region":
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"gs://{name}", project_id=project_id,
                        resource_link=self.console_link("gcs_bucket", project_id, name=name),
                        current_state=f"Bucket is in single region: {location}",
                        recommended_state="Consider multi-region or dual-region for critical data",
                        fix_command="",
                        references=self.references,
                    ))
        except Exception as e:
            logger.error("GCS-008 failed: %s", e)
        return findings


class PublicAccessPreventionNotEnforced(BaseCheck):
    """GCS-009: Bucket public-access-prevention is not 'enforced'.

    Complementary to GCS-001 (which detects existing public bindings):
    this flags buckets where public bindings *could* be added in the future.
    """
    id = "GCS-009"
    title = "Public access prevention not enforced on bucket"
    description = "Bucket allows public access bindings to be added (publicAccessPrevention != enforced)."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "GCS"
    service_category = ServiceCategory.GCS
    fix_command_template = "gcloud storage buckets update gs://{bucket} --public-access-prevention=enforced"
    references = ["https://cloud.google.com/storage/docs/public-access-prevention"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            buckets = await gcloud_runner.run(f"gcloud storage buckets list --project={project_id} --format=json")
            if not isinstance(buckets, list):
                return []
            for b in buckets:
                name = b.get("name", "") or b.get("metadata", {}).get("name", "")
                if not name:
                    continue
                iam_config = b.get("iamConfiguration", {}) or b.get("metadata", {}).get("iamConfiguration", {})
                pap = iam_config.get("publicAccessPrevention", "")
                if pap and pap.lower() != "enforced":
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"gs://{name}", project_id=project_id,
                        resource_link=self.console_link("gcs_bucket", project_id, name=name),
                        current_state=f"Public access prevention: '{pap}' (not enforced)",
                        recommended_state="Set public access prevention to 'enforced'",
                        fix_command=self.build_fix_command(bucket=name),
                        references=self.references,
                    ))
        except Exception as e:
            logger.error("GCS-009 failed: %s", e)
        return findings


class NoObjectLock(BaseCheck):
    id = "GCS-010"
    title = "No Object Lock / retention for compliance data"
    description = "For regulatory compliance, consider using bucket lock to make retention policies immutable."
    severity = Severity.LOW
    category = Category.SECURITY
    service = "GCS"
    service_category = ServiceCategory.GCS
    fix_command_template = "gcloud storage buckets update gs://{bucket} --lock-retention-period"
    references = ["https://cloud.google.com/storage/docs/bucket-lock"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            buckets = await gcloud_runner.run(f"gcloud storage buckets list --project={project_id} --format=json")
            if not isinstance(buckets, list):
                return []
            for b in buckets:
                name = b.get("name", "") or b.get("metadata", {}).get("name", "")
                if not name:
                    continue
                retention = b.get("retentionPolicy", {}) or b.get("metadata", {}).get("retentionPolicy", {})
                if retention and retention.get("retentionPeriod") and not retention.get("isLocked"):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"gs://{name}", project_id=project_id,
                        resource_link=self.console_link("gcs_bucket", project_id, name=name),
                        current_state="Retention policy exists but is not locked (can be removed)",
                        recommended_state="Lock the retention policy for immutable compliance",
                        fix_command=self.build_fix_command(bucket=name),
                        references=self.references,
                    ))
        except Exception as e:
            logger.error("GCS-010 failed: %s", e)
        return findings


# ---------------------------------------------------------------------------
# Additional GCS checks (2026-05 catalog expansion)
# ---------------------------------------------------------------------------


class CMEKKeyInSameProject(BaseCheck):
    id = "GCS-011"
    title = "Bucket CMEK key lives in the same project as the bucket (weakens separation)"
    description = "Compromise of the project compromises both data and keys; keep KMS in a separate key project."
    severity = Severity.LOW
    category = Category.SECURITY
    service = "GCS"
    service_category = ServiceCategory.GCS
    references = ["https://cloud.google.com/kms/docs/separation-of-duties"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            buckets = await gcloud_runner.run(f"gcloud storage buckets list --project={project_id} --format=json")
        except Exception:
            return findings
        for b in (buckets if isinstance(buckets, list) else []):
            name = b.get("name", "") or b.get("metadata", {}).get("name", "")
            enc = b.get("encryption", {}) or b.get("metadata", {}).get("encryption", {})
            key = enc.get("defaultKmsKeyName", "") if isinstance(enc, dict) else ""
            if key and f"/projects/{project_id}/" in key:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"gs://{name}", project_id=project_id,
                    current_state="CMEK key is in the same project as the bucket",
                    recommended_state="Host the KMS key in a dedicated key project (separation of duties)",
                    fix_command="", references=self.references,
                ))
        return findings


class BucketNoPubSubNotifications(BaseCheck):
    id = "GCS-012"
    title = "Bucket has no Pub/Sub notifications (no event-driven monitoring)"
    description = "Notifications let downstream systems react to writes/deletes — also useful for security monitoring."
    severity = Severity.INFO
    category = Category.OPERATIONS
    service = "GCS"
    service_category = ServiceCategory.GCS
    references = ["https://cloud.google.com/storage/docs/pubsub-notifications"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            buckets = await gcloud_runner.run(f"gcloud storage buckets list --project={project_id} --format=json")
        except Exception:
            return findings
        for b in (buckets if isinstance(buckets, list) else []):
            name = b.get("name", "") or b.get("metadata", {}).get("name", "")
            if not name:
                continue
            try:
                notifs = await gcloud_runner.run(
                    f"gcloud storage buckets notifications list gs://{name} --format=json"
                )
            except Exception:
                continue
            if not isinstance(notifs, list) or len(notifs) == 0:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"gs://{name}", project_id=project_id,
                    current_state="No Pub/Sub notifications configured",
                    recommended_state="Add notifications for sensitive buckets (audit, ingest pipelines)",
                    fix_command="", references=self.references,
                ))
        return findings


import sys as _sys  # noqa: E402
from backend.checks._module_helpers import apply_required_apis as _apply  # noqa: E402
_apply(_sys.modules[__name__], ["storage.googleapis.com"])
