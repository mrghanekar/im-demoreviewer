"""Security checks for organizational policies, SCC, KMS, and related services.

Checks: SEC-001 through SEC-010
"""

import logging
from typing import Any

from backend.checks.base import BaseCheck
from backend.core.models import Category, CheckResult, Severity, ServiceCategory

logger = logging.getLogger(__name__)


class OrgPolicyDomainRestriction(BaseCheck):
    id = "SEC-001"
    title = "Org policy not enforcing domain restriction"
    description = "The iam.allowedPolicyMemberDomains constraint is not set, allowing any domain in IAM."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Security"
    service_category = ServiceCategory.SECURITY
    fix_command_template = ""
    references = ["https://cloud.google.com/resource-manager/docs/organization-policy/restricting-domains"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            result = await gcloud_runner.run(
                f"gcloud org-policies describe iam.allowedPolicyMemberDomains --project={project_id} --format=json"
            )
            if isinstance(result, dict):
                spec = result.get("spec", {})
                rules = spec.get("rules", []) if spec else []
                if rules:
                    return []
            findings.append(CheckResult(
                check_id=self.id, title=self.title, description=self.description,
                severity=self.severity, category=self.category, service=self.service,
                resource_name=f"projects/{project_id}", project_id=project_id,
                resource_link=f"https://console.cloud.google.com/iam-admin/orgpolicies/iam-allowedPolicyMemberDomains?project={project_id}",
                current_state="Domain restriction org policy is not enforced",
                recommended_state="Set iam.allowedPolicyMemberDomains to your org's domain",
                fix_command="", references=self.references,
            ))
        except Exception as e:
            logger.debug("SEC-001: Could not read org policy for %s: %s", project_id, e)
            findings.append(CheckResult(
                check_id=self.id, title=self.title, description=self.description,
                severity=self.severity, category=self.category, service=self.service,
                resource_name=f"projects/{project_id}", project_id=project_id,
                current_state="Could not read org policy (may not be configured)",
                recommended_state="Set iam.allowedPolicyMemberDomains at org level",
                fix_command="", references=self.references,
            ))
        return findings


class VPCServiceControlsNotConfigured(BaseCheck):
    id = "SEC-002"
    title = "VPC Service Controls not configured"
    description = "VPC Service Controls create a security perimeter to prevent data exfiltration."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "Security"
    service_category = ServiceCategory.SECURITY
    fix_command_template = ""
    references = ["https://cloud.google.com/vpc-service-controls/docs/overview"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        # VPC SC operates at org level; we can check if the API is enabled
        findings: list[CheckResult] = []
        try:
            services = await gcloud_runner.run(f"gcloud services list --project={project_id} --format=json --filter=name:accesscontextmanager.googleapis.com")
            if not isinstance(services, list) or len(services) == 0:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"projects/{project_id}", project_id=project_id,
                    current_state="Access Context Manager API not enabled (VPC SC requires it)",
                    recommended_state="Enable VPC Service Controls for sensitive projects",
                    fix_command="", references=self.references,
                ))
        except Exception as e:
            logger.debug("SEC-002: %s", e)
        return findings


class SCCNotEnabled(BaseCheck):
    id = "SEC-003"
    title = "Security Command Center not enabled"
    description = "SCC provides centralized security monitoring for GCP resources."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Security"
    service_category = ServiceCategory.SECURITY
    fix_command_template = "gcloud services enable securitycenter.googleapis.com --project={project_id}"
    references = ["https://cloud.google.com/security-command-center/docs/quickstart-scc-setup"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            services = await gcloud_runner.run(
                f"gcloud services list --project={project_id} --format=json --filter=name:securitycenter.googleapis.com"
            )
            if not isinstance(services, list) or len(services) == 0:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"projects/{project_id}", project_id=project_id,
                    current_state="Security Command Center API is not enabled",
                    recommended_state="Enable SCC for centralized security findings",
                    fix_command=self.build_fix_command(project_id=project_id),
                    references=self.references,
                ))
        except Exception as e:
            logger.error("SEC-003 failed: %s", e)
        return findings


# SEC-004 (CloudArmorNotProtecting) removed — NET-015 (LBNoCloudArmor) is the
# canonical check; it uses the correct loadBalancingScheme filter (EXTERNAL/
# EXTERNAL_MANAGED) instead of the brittle protocol-based filter that SEC-004 had.
#
# SEC-005 (SecretManagerNotRotated) removed — SM-001 (SecretNoRotation in
# backend/checks/secrets/secret_manager.py) is the canonical check; it lives in
# the dedicated Secret Manager service area added in catalog v2.


class WebSecurityScannerNotConfigured(BaseCheck):
    id = "SEC-007"
    title = "Web Security Scanner not configured"
    description = "Web Security Scanner helps identify vulnerabilities in App Engine, GKE, and Compute Engine web apps."
    severity = Severity.LOW
    category = Category.SECURITY
    service = "Security"
    service_category = ServiceCategory.SECURITY
    fix_command_template = "gcloud services enable websecurityscanner.googleapis.com --project={project_id}"
    references = ["https://cloud.google.com/security-command-center/docs/concepts-web-security-scanner-overview"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            services = await gcloud_runner.run(
                f"gcloud services list --project={project_id} --format=json --filter=name:websecurityscanner.googleapis.com"
            )
            if not isinstance(services, list) or len(services) == 0:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"projects/{project_id}", project_id=project_id,
                    current_state="Web Security Scanner API is not enabled",
                    recommended_state="Enable Web Security Scanner for web application vulnerability scanning",
                    fix_command=self.build_fix_command(project_id=project_id),
                    references=self.references,
                ))
        except Exception as e:
            logger.debug("SEC-007: %s", e)
        return findings


class DLPNotConfigured(BaseCheck):
    id = "SEC-008"
    title = "Cloud DLP not configured for sensitive data"
    description = "Cloud Data Loss Prevention helps discover and protect sensitive data across GCP."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "Security"
    service_category = ServiceCategory.SECURITY
    fix_command_template = "gcloud services enable dlp.googleapis.com --project={project_id}"
    references = ["https://cloud.google.com/sensitive-data-protection/docs/quickstart"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            services = await gcloud_runner.run(
                f"gcloud services list --project={project_id} --format=json --filter=name:dlp.googleapis.com"
            )
            if not isinstance(services, list) or len(services) == 0:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"projects/{project_id}", project_id=project_id,
                    current_state="Cloud DLP API is not enabled",
                    recommended_state="Enable DLP for sensitive data discovery and protection",
                    fix_command=self.build_fix_command(project_id=project_id),
                    references=self.references,
                ))
        except Exception as e:
            logger.debug("SEC-008: %s", e)
        return findings


class CASNotInUse(BaseCheck):
    id = "SEC-009"
    title = "Certificate Authority Service not in use"
    description = "CA Service provides managed private CA for issuing TLS certificates internally."
    severity = Severity.LOW
    category = Category.SECURITY
    service = "Security"
    service_category = ServiceCategory.SECURITY
    fix_command_template = "gcloud services enable privateca.googleapis.com --project={project_id}"
    references = ["https://cloud.google.com/certificate-authority-service/docs/overview"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            services = await gcloud_runner.run(
                f"gcloud services list --project={project_id} --format=json --filter=name:privateca.googleapis.com"
            )
            if not isinstance(services, list) or len(services) == 0:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"projects/{project_id}", project_id=project_id,
                    current_state="Certificate Authority Service API is not enabled",
                    recommended_state="Consider using CA Service for internal PKI",
                    fix_command=self.build_fix_command(project_id=project_id),
                    references=self.references,
                ))
        except Exception as e:
            logger.debug("SEC-009: %s", e)
        return findings


class AccessTransparencyNotEnabled(BaseCheck):
    id = "SEC-010"
    title = "Access Transparency not enabled"
    description = "Access Transparency provides logs of Google staff accessing your data."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "Security"
    service_category = ServiceCategory.SECURITY
    fix_command_template = ""
    references = ["https://cloud.google.com/assured-workloads/access-transparency/docs/overview"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            services = await gcloud_runner.run(
                f"gcloud services list --project={project_id} --format=json --filter=name:accessapproval.googleapis.com"
            )
            if not isinstance(services, list) or len(services) == 0:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"projects/{project_id}", project_id=project_id,
                    current_state="Access Approval / Access Transparency not enabled",
                    recommended_state="Enable Access Transparency for audit logging of Google staff actions",
                    fix_command="", references=self.references,
                ))
        except Exception as e:
            logger.debug("SEC-010: %s", e)
        return findings


# ---------------------------------------------------------------------------
# Additional Security checks (2026-05 catalog expansion)
# ---------------------------------------------------------------------------


class KMSKeyDestructionProtection(BaseCheck):
    """SEC-011: KMS keys without a long destruction-scheduled-duration."""
    id = "SEC-011"
    title = "KMS key has minimal destruction-scheduled-duration (24h default)"
    description = "Longer destruction delays give time to detect malicious key-destroy attempts."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "Security"
    service_category = ServiceCategory.SECURITY
    references = ["https://cloud.google.com/kms/docs/destroy-restore"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            keyrings = await gcloud_runner.run(
                f"gcloud kms keyrings list --location=- --project={project_id} --format=json"
            )
        except Exception:
            return findings
        for kr in (keyrings if isinstance(keyrings, list) else []):
            kr_name = kr.get("name", "")
            parts = kr_name.split("/")
            if len(parts) < 6:
                continue
            location, ring_id = parts[3], parts[5]
            try:
                keys = await gcloud_runner.run(
                    f"gcloud kms keys list --keyring={ring_id} --location={location} --project={project_id} --format=json"
                )
            except Exception:
                continue
            for k in (keys if isinstance(keys, list) else []):
                dur = k.get("destroyScheduledDuration", "")
                if not dur or dur == "86400s":
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=k.get("name", ""), project_id=project_id,
                        current_state=f"destroyScheduledDuration={dur or 'default 24h'}",
                        recommended_state="Set a longer destruction delay (e.g. 2592000s = 30 days)",
                        fix_command="", references=self.references,
                    ))
        return findings


class KMSRotationPeriodLong(BaseCheck):
    """SEC-012: KMS keys with rotation > 1 year or no rotation."""
    id = "SEC-012"
    title = "KMS key rotation period too long or unset"
    description = "Best practice: rotate symmetric KMS keys at most every 365 days."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "Security"
    service_category = ServiceCategory.SECURITY
    references = ["https://cloud.google.com/kms/docs/key-rotation"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            keyrings = await gcloud_runner.run(
                f"gcloud kms keyrings list --location=- --project={project_id} --format=json"
            )
        except Exception:
            return findings
        for kr in (keyrings if isinstance(keyrings, list) else []):
            kr_name = kr.get("name", "")
            parts = kr_name.split("/")
            if len(parts) < 6:
                continue
            location, ring_id = parts[3], parts[5]
            try:
                keys = await gcloud_runner.run(
                    f"gcloud kms keys list --keyring={ring_id} --location={location} --project={project_id} --format=json"
                )
            except Exception:
                continue
            for k in (keys if isinstance(keys, list) else []):
                if k.get("purpose") != "ENCRYPT_DECRYPT":
                    continue
                period = k.get("rotationPeriod", "")
                period_seconds = 0
                if isinstance(period, str) and period.endswith("s"):
                    try:
                        period_seconds = int(period[:-1])
                    except ValueError:
                        period_seconds = 0
                if not period_seconds or period_seconds > 31_536_000:
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=k.get("name", ""), project_id=project_id,
                        current_state=f"rotationPeriod={period or 'unset'}",
                        recommended_state="Set rotation period <= 31536000s (1 year)",
                        fix_command="", references=self.references,
                    ))
        return findings


class BinaryAuthorizationNotEnforced(BaseCheck):
    """SEC-013: Binary Authorization policy is dryrun (not enforced)."""
    id = "SEC-013"
    title = "Binary Authorization policy is dryrun (not enforced)"
    description = "Dryrun logs violations but still admits unsigned containers."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "Security"
    service_category = ServiceCategory.SECURITY
    references = ["https://cloud.google.com/binary-authorization/docs/overview"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            policy = await gcloud_runner.run(
                f"gcloud container binauthz policy export --project={project_id} --format=json"
            )
        except Exception:
            return findings
        if not isinstance(policy, dict):
            return findings
        mode = policy.get("defaultAdmissionRule", {}).get("enforcementMode", "")
        if mode and "DRYRUN" in mode:
            findings.append(CheckResult(
                check_id=self.id, title=self.title, description=self.description,
                severity=self.severity, category=self.category, service=self.service,
                resource_name=f"projects/{project_id}/binauthz/policy", project_id=project_id,
                current_state=f"enforcementMode={mode}",
                recommended_state="Set enforcementMode to ENFORCED_BLOCK_AND_AUDIT_LOG",
                fix_command="", references=self.references,
            ))
        return findings


class CloudArmorNoManagedRules(BaseCheck):
    """SEC-014: Cloud Armor policies without managed OWASP rules."""
    id = "SEC-014"
    title = "Cloud Armor policy has no managed OWASP/CRS rules"
    description = "Managed preconfigured WAF rules catch common OWASP attack patterns."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Security"
    service_category = ServiceCategory.SECURITY
    references = ["https://cloud.google.com/armor/docs/rule-tuning"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            policies = await gcloud_runner.run(
                f"gcloud compute security-policies list --project={project_id} --format=json"
            )
        except Exception:
            return findings
        for p in (policies if isinstance(policies, list) else []):
            name = p.get("name", "")
            rules = p.get("rules", [])
            has_managed = any(
                "evaluatePreconfiguredWaf" in str(r.get("match", {}).get("expr", {}).get("expression", ""))
                or "evaluatePreconfiguredExpr" in str(r.get("match", {}).get("expr", {}).get("expression", ""))
                for r in rules
            )
            if not has_managed:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"security-policies/{name}", project_id=project_id,
                    current_state="No preconfigured WAF rules attached",
                    recommended_state="Add managed rules: sqli-v33-stable, xss-v33-stable, etc.",
                    fix_command="", references=self.references,
                ))
        return findings


class ConfidentialVMsNotUsed(BaseCheck):
    """SEC-015: No Confidential VMs in project (informational)."""
    id = "SEC-015"
    title = "No Confidential VMs in project (consider for sensitive workloads)"
    description = "Confidential VMs encrypt memory in use via AMD SEV / Intel TDX."
    severity = Severity.INFO
    category = Category.SECURITY
    service = "Security"
    service_category = ServiceCategory.SECURITY
    references = ["https://cloud.google.com/confidential-computing/confidential-vm/docs/about-cvm"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await gcloud_runner.run(
                f"gcloud compute instances list --project={project_id} --format=json"
            )
        except Exception:
            return findings
        if not isinstance(instances, list) or len(instances) == 0:
            return findings
        if not any(i.get("confidentialInstanceConfig", {}).get("enableConfidentialCompute") for i in instances):
            findings.append(CheckResult(
                check_id=self.id, title=self.title, description=self.description,
                severity=self.severity, category=self.category, service=self.service,
                resource_name=f"projects/{project_id}", project_id=project_id,
                current_state="No instance has Confidential Compute enabled",
                recommended_state="Consider Confidential VMs for sensitive workloads",
                fix_command="", references=self.references,
            ))
        return findings


# Per-check required APIs. Checks that only call `gcloud services list` to detect
# whether a service is enabled (SEC-002/3/7/8/9/10) intentionally have no required
# APIs so they always run.
import sys as _sys  # noqa: E402
from backend.checks._module_helpers import apply_required_apis_by_id as _apply  # noqa: E402
_apply(_sys.modules[__name__], {
    "SEC-001": ["orgpolicy.googleapis.com"],
    # The "is service X enabled?" checks (SEC-002/003/007/008/009/010) all call
    # `gcloud services list` to detect their target API. They MUST NOT require
    # their target API — that's what they're detecting — but they do need
    # serviceusage itself. Without this gate, a project with serviceusage
    # disabled would surface noisy errors instead of clean SKIPPED status.
    "SEC-002": ["serviceusage.googleapis.com"],
    "SEC-003": ["serviceusage.googleapis.com"],
    "SEC-007": ["serviceusage.googleapis.com"],
    "SEC-008": ["serviceusage.googleapis.com"],
    "SEC-009": ["serviceusage.googleapis.com"],
    "SEC-010": ["serviceusage.googleapis.com"],
    "SEC-011": ["cloudkms.googleapis.com"],
    "SEC-012": ["cloudkms.googleapis.com"],
    "SEC-013": ["binaryauthorization.googleapis.com"],
    "SEC-014": ["compute.googleapis.com"],
    "SEC-015": ["compute.googleapis.com"],
})
