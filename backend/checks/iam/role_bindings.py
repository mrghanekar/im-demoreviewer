"""IAM checks related to IAM policy bindings and roles.

Checks: IAM-001, IAM-006, IAM-008, IAM-009, IAM-010, IAM-012
"""

import logging
from typing import Any, ClassVar

from backend.checks._identity import is_google_managed_agent
from backend.checks.base import BaseCheck
from backend.core.models import Category, CheckResult, Severity, ServiceCategory

logger = logging.getLogger(__name__)

PRIMITIVE_ROLES = {"roles/owner", "roles/editor"}
PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


class PrimitiveRolesInUse(BaseCheck):
    """IAM-001: Primitive roles (Owner/Editor) granted to members."""

    id = "IAM-001"
    title = "Primitive role (Owner/Editor) in use"
    description = (
        "Primitive roles (Owner, Editor) grant overly broad permissions. "
        "Use predefined or custom roles with least-privilege access instead."
    )
    severity = Severity.CRITICAL
    category = Category.SECURITY
    service = "IAM"
    service_category = ServiceCategory.IAM
    gcloud_command = "gcloud projects get-iam-policy {project_id} --format=json"
    fix_command_template = (
        "gcloud projects remove-iam-policy-binding {project_id} "
        "--member='{member}' --role='{role}'"
    )
    references = [
        "https://cloud.google.com/iam/docs/understanding-roles#primitive_roles",
        "https://cloud.google.com/iam/docs/using-deny-policies",
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.5.15", "A.8.2"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            policy = await gcloud_runner.run(
                f"gcloud projects get-iam-policy {project_id} --format=json"
            )
            if not isinstance(policy, dict):
                return []

            for binding in policy.get("bindings", []):
                role = binding.get("role", "")
                if role not in PRIMITIVE_ROLES:
                    continue
                for member in binding.get("members", []):
                    # Skip Google-managed service agents
                    if is_google_managed_agent(member):
                        continue
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"{member} -> {role}",
                        resource_link=self.console_link("iam", project_id),
                        project_id=project_id,
                        current_state=f"Member '{member}' has primitive role '{role}'",
                        recommended_state="Replace with a predefined or custom role with least privilege",
                        fix_command=self.build_fix_command(project_id=project_id, member=member, role=role),
                        references=self.references,
                    ))
        except Exception as e:
            logger.error("IAM-001 failed: %s", e)
        return findings


class AllUsersInBindings(BaseCheck):
    """IAM-009: allUsers or allAuthenticatedUsers in IAM bindings."""

    id = "IAM-009"
    title = "Public access (allUsers/allAuthenticatedUsers) in IAM policy"
    description = (
        "IAM bindings granting access to 'allUsers' or 'allAuthenticatedUsers' make "
        "project resources accessible to anyone on the internet."
    )
    severity = Severity.CRITICAL
    category = Category.SECURITY
    service = "IAM"
    service_category = ServiceCategory.IAM
    gcloud_command = "gcloud projects get-iam-policy {project_id} --format=json"
    fix_command_template = (
        "gcloud projects remove-iam-policy-binding {project_id} "
        "--member='{member}' --role='{role}'"
    )
    references = [
        "https://cloud.google.com/iam/docs/overview#all-users",
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.5.15", "A.8.3"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            policy = await gcloud_runner.run(
                f"gcloud projects get-iam-policy {project_id} --format=json"
            )
            if not isinstance(policy, dict):
                return []

            for binding in policy.get("bindings", []):
                role = binding.get("role", "")
                for member in binding.get("members", []):
                    if member in PUBLIC_MEMBERS:
                        findings.append(CheckResult(
                            check_id=self.id, title=self.title, description=self.description,
                            severity=self.severity, category=self.category, service=self.service,
                            resource_name=f"{member} -> {role}",
                            resource_link=self.console_link("iam", project_id),
                            project_id=project_id,
                            current_state=f"'{member}' has role '{role}' — public access!",
                            recommended_state="Remove public member from IAM bindings",
                            fix_command=self.build_fix_command(project_id=project_id, member=member, role=role),
                            references=self.references,
                        ))
        except Exception as e:
            logger.error("IAM-009 failed: %s", e)
        return findings


class ExternalMembersInBindings(BaseCheck):
    """IAM-008: External (non-org) members in IAM bindings."""

    id = "IAM-008"
    title = "External members in IAM bindings"
    description = (
        "IAM bindings include members from outside the organization's domain. "
        "This may be intentional for partners, but should be reviewed."
    )
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "IAM"
    service_category = ServiceCategory.IAM
    gcloud_command = "gcloud projects get-iam-policy {project_id} --format=json"
    fix_command_template = (
        "gcloud projects remove-iam-policy-binding {project_id} "
        "--member='{member}' --role='{role}'"
    )
    references = [
        "https://cloud.google.com/resource-manager/docs/organization-policy/restricting-domains",
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"CIS_GCP_V3": ["1.1"], "ISO_27001": ["A.5.16", "A.5.18"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            policy = await gcloud_runner.run(
                f"gcloud projects get-iam-policy {project_id} --format=json"
            )
            if not isinstance(policy, dict):
                return []

            for binding in policy.get("bindings", []):
                role = binding.get("role", "")
                for member in binding.get("members", []):
                    if member in PUBLIC_MEMBERS:
                        continue  # Covered by IAM-009
                    if member.startswith("deleted:"):
                        continue
                    # Check if it's external
                    if member.startswith("user:") or member.startswith("group:"):
                        # External users/groups from non-org domains
                        # (we can't know the org domain without org-level access,
                        #  so flag gmail.com and other free providers)
                        email_part = member.split(":", 1)[1] if ":" in member else member
                        if any(email_part.endswith(d) for d in ["@gmail.com", "@yahoo.com", "@hotmail.com", "@outlook.com"]):
                            findings.append(CheckResult(
                                check_id=self.id, title=self.title, description=self.description,
                                severity=self.severity, category=self.category, service=self.service,
                                resource_name=f"{member} -> {role}",
                                resource_link=self.console_link("iam", project_id),
                                project_id=project_id,
                                current_state=f"Personal email '{member}' has role '{role}'",
                                recommended_state="Use organizational accounts or enforce domain restriction",
                                fix_command=self.build_fix_command(project_id=project_id, member=member, role=role),
                                references=self.references,
                            ))
        except Exception as e:
            logger.error("IAM-008 failed: %s", e)
        return findings


class NoCustomRoles(BaseCheck):
    """IAM-010: No custom roles defined (all predefined)."""

    id = "IAM-010"
    title = "No custom IAM roles defined"
    description = (
        "Custom IAM roles allow fine-grained, least-privilege access. "
        "Using only predefined roles may grant more permissions than necessary."
    )
    severity = Severity.LOW
    category = Category.OPERATIONS
    service = "IAM"
    service_category = ServiceCategory.IAM
    gcloud_command = "gcloud iam roles list --project={project_id} --format=json"
    fix_command_template = ""
    references = [
        "https://cloud.google.com/iam/docs/creating-custom-roles",
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.5.15"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            roles = await gcloud_runner.run(
                f"gcloud iam roles list --project={project_id} --format=json"
            )
            if not isinstance(roles, list) or len(roles) == 0:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"projects/{project_id}",
                    resource_link=self.console_link("iam", project_id),
                    project_id=project_id,
                    current_state="No custom IAM roles defined in this project",
                    recommended_state="Create custom roles for least-privilege access patterns",
                    fix_command="",
                    references=self.references,
                ))
        except Exception as e:
            logger.error("IAM-010 failed: %s", e)
        return findings


class DomainRestrictedSharingNotEnforced(BaseCheck):
    """IAM-012: Domain-restricted sharing org policy not enforced."""

    id = "IAM-012"
    title = "Domain-restricted sharing not enforced"
    description = (
        "The 'iam.allowedPolicyMemberDomains' organization policy is not set. "
        "Without it, any Google account can be granted IAM roles in this project."
    )
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "IAM"
    service_category = ServiceCategory.IAM
    gcloud_command = "gcloud org-policies describe iam.allowedPolicyMemberDomains --project={project_id} --format=json"
    fix_command_template = ""
    references = [
        "https://cloud.google.com/resource-manager/docs/organization-policy/restricting-domains",
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.5.15", "A.5.18"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        # Only meaningful for projects that live under an organization.
        # Standalone projects can't have org-level policies, so flagging them
        # is a false positive that creates alert noise.
        try:
            project_meta = await gcloud_runner.run(
                f"gcloud projects describe {project_id} --format=json"
            )
        except Exception as e:
            logger.debug("IAM-012: could not describe project %s: %s", project_id, e)
            return []

        parent = (project_meta or {}).get("parent", {}) if isinstance(project_meta, dict) else {}
        if parent.get("type") != "organization":
            return []  # Not in an org; org-level policy is not applicable

        findings: list[CheckResult] = []
        try:
            result = await gcloud_runner.run(
                f"gcloud org-policies describe iam.allowedPolicyMemberDomains --project={project_id} --format=json"
            )
            if isinstance(result, dict):
                spec = result.get("spec", {}) or result.get("listPolicy", {})
                if spec.get("rules"):
                    return []  # Policy is set
        except Exception:
            # No effective policy describable — fall through to recommend setting one
            pass

        findings.append(CheckResult(
            check_id=self.id, title=self.title, description=self.description,
            severity=self.severity, category=self.category, service=self.service,
            resource_name=f"projects/{project_id}",
            resource_link=self.console_link("iam", project_id),
            project_id=project_id,
            current_state="Domain-restricted sharing org policy is not enforced",
            recommended_state="Set iam.allowedPolicyMemberDomains at the org or project level",
            fix_command="",
            references=self.references,
        ))
        return findings


class OverPermissionedServiceAccounts(BaseCheck):
    """IAM-004: Service accounts with overly broad roles."""

    id = "IAM-004"
    title = "Over-permissioned service account"
    description = (
        "Service accounts with primitive roles (Owner/Editor) or broad predefined roles "
        "violate the principle of least privilege."
    )
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "IAM"
    service_category = ServiceCategory.IAM
    gcloud_command = "gcloud projects get-iam-policy {project_id} --format=json"
    fix_command_template = (
        "gcloud projects remove-iam-policy-binding {project_id} "
        "--member='serviceAccount:{sa_email}' --role='{role}'"
    )
    references = [
        "https://cloud.google.com/iam/docs/best-practices-service-accounts#least-privilege",
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"CIS_GCP_V3": ["1.4", "1.5"], "ISO_27001": ["A.5.15", "A.8.2"]}

    OVERLY_BROAD_ROLES = {
        "roles/owner", "roles/editor",
        "roles/storage.admin", "roles/compute.admin",
        "roles/container.admin", "roles/cloudsql.admin",
        "roles/bigquery.admin", "roles/iam.admin",
    }

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            policy = await gcloud_runner.run(
                f"gcloud projects get-iam-policy {project_id} --format=json"
            )
            if not isinstance(policy, dict):
                return []

            for binding in policy.get("bindings", []):
                role = binding.get("role", "")
                if role not in self.OVERLY_BROAD_ROLES:
                    continue
                for member in binding.get("members", []):
                    if not member.startswith("serviceAccount:"):
                        continue
                    sa_email = member.replace("serviceAccount:", "")
                    # Skip Google-managed service agents
                    if is_google_managed_agent(sa_email):
                        continue
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"{sa_email} -> {role}",
                        resource_link=self.console_link("service_account", project_id, email=sa_email),
                        project_id=project_id,
                        current_state=f"SA '{sa_email}' has broad role '{role}'",
                        recommended_state="Replace with a more restrictive predefined or custom role",
                        fix_command=self.build_fix_command(project_id=project_id, sa_email=sa_email, role=role),
                        references=self.references,
                    ))
        except Exception as e:
            logger.error("IAM-004 failed: %s", e)
        return findings


# IAM-005 ("SA impersonation not used") was a duplicate signal of IAM-003
# (user-managed SA keys exist). Removed to avoid double-counting findings.


class WorkloadIdentityNotUsed(BaseCheck):
    """IAM-011: Workload Identity Federation not used."""

    id = "IAM-011"
    title = "Workload Identity Federation not configured"
    description = (
        "Workload Identity Federation allows external workloads to access GCP "
        "without service account keys. If keys exist, WIF may not be in use."
    )
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "IAM"
    service_category = ServiceCategory.IAM
    fix_command_template = ""
    references = [
        "https://cloud.google.com/iam/docs/workload-identity-federation",
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.5.17"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            # Check if any WIF pools exist
            pools = await gcloud_runner.run(
                f"gcloud iam workload-identity-pools list --project={project_id} --location=global --format=json"
            )
            if not isinstance(pools, list) or len(pools) == 0:
                # Count user-managed keys to decide severity
                accounts = await gcloud_runner.run(
                    f"gcloud iam service-accounts list --project={project_id} --format=json"
                )
                has_keys = False
                for sa in (accounts if isinstance(accounts, list) else []):
                    email = sa.get("email", "")
                    if not email:
                        continue
                    try:
                        keys = await gcloud_runner.run(
                            f"gcloud iam service-accounts keys list --iam-account={email} --managed-by=user --format=json"
                        )
                        if isinstance(keys, list) and len(keys) > 0:
                            has_keys = True
                            break
                    except Exception:
                        pass

                if has_keys:
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"projects/{project_id}",
                        resource_link=self.console_link("iam", project_id),
                        project_id=project_id,
                        current_state="No Workload Identity pools found, but SA keys exist",
                        recommended_state="Set up Workload Identity Federation for external workloads",
                        fix_command="",
                        references=self.references,
                    ))
        except Exception as e:
            logger.debug("IAM-011: Could not check WIF pools: %s", e)
        return findings


class NoOrgLevelIAMAudit(BaseCheck):
    """IAM-006: No org-level IAM audit (project-level only check placeholder)."""

    id = "IAM-006"
    title = "IAM policy not audited at organization level"
    description = (
        "IAM policies should be reviewed at the organization level for consistency. "
        "Project-level checks alone may miss inherited permissions."
    )
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "IAM"
    service_category = ServiceCategory.IAM
    fix_command_template = ""
    references = [
        "https://cloud.google.com/iam/docs/audit-logging",
    ]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.5.18"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        # This check is informational — always recommend org-level audit
        return [CheckResult(
            check_id=self.id, title=self.title, description=self.description,
            severity=Severity.INFO, category=self.category, service=self.service,
            resource_name=f"projects/{project_id}",
            resource_link=self.console_link("iam", project_id),
            project_id=project_id,
            current_state="IAM audit is being run at project level only",
            recommended_state="Run org-level scan to check inherited IAM bindings",
            fix_command="",
            references=self.references,
        )]


# ---------------------------------------------------------------------------
# Additional IAM checks (2026-05 catalog expansion)
# ---------------------------------------------------------------------------

# bigquery.googleapis.com is intentionally NOT in this list — DATA-009 owns
# BigQuery audit-log coverage so the two checks don't double-fire.
SENSITIVE_AUDITED_SERVICES = ("storage.googleapis.com", "iam.googleapis.com")


class DataAccessAuditLogsDisabled(BaseCheck):
    """IAM-013: Data Access audit logs disabled for sensitive services."""

    id = "IAM-013"
    title = "Data Access audit logs disabled for sensitive services"
    description = (
        "Without DATA_READ / DATA_WRITE audit logs on storage/bigquery/iam, "
        "you have no record of who accessed data or modified policies."
    )
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "IAM"
    service_category = ServiceCategory.IAM
    references = ["https://cloud.google.com/logging/docs/audit/configure-data-access"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"CIS_GCP_V3": ["2.1"], "ISO_27001": ["A.8.15"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            policy = await gcloud_runner.run(
                f"gcloud projects get-iam-policy {project_id} --format=json"
            )
        except Exception as e:
            logger.debug("IAM-013: %s", e)
            return findings
        if not isinstance(policy, dict):
            return findings
        audit_configs = {a.get("service"): a for a in policy.get("auditConfigs", [])}
        missing = []
        for svc in SENSITIVE_AUDITED_SERVICES:
            cfg = audit_configs.get(svc) or audit_configs.get("allServices")
            if not cfg:
                missing.append(svc)
                continue
            log_types = {c.get("logType") for c in cfg.get("auditLogConfigs", [])}
            if "DATA_READ" not in log_types and "DATA_WRITE" not in log_types:
                missing.append(svc)
        if missing:
            findings.append(CheckResult(
                check_id=self.id, title=self.title, description=self.description,
                severity=self.severity, category=self.category, service=self.service,
                resource_name=f"projects/{project_id}", project_id=project_id,
                current_state=f"DATA_READ/DATA_WRITE audit logs not configured for: {', '.join(missing)}",
                recommended_state="Enable DATA_READ and DATA_WRITE audit logs for sensitive services",
                fix_command="", references=self.references,
            ))
        return findings


class ConditionalBindingsUnused(BaseCheck):
    """IAM-014: No IAM Conditions in use (missing time/resource-bounded access)."""

    id = "IAM-014"
    title = "IAM Conditions not in use (no time/resource-bounded grants)"
    description = (
        "Conditional IAM lets you scope access by resource attribute, time of day, "
        "or other context. Projects without any conditional bindings are over-permissive."
    )
    severity = Severity.LOW
    category = Category.SECURITY
    service = "IAM"
    service_category = ServiceCategory.IAM
    references = ["https://cloud.google.com/iam/docs/conditions-overview"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.5.15"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            policy = await gcloud_runner.run(
                f"gcloud projects get-iam-policy {project_id} --format=json"
            )
        except Exception:
            return findings
        if not isinstance(policy, dict):
            return findings
        has_condition = any(b.get("condition") for b in policy.get("bindings", []))
        if not has_condition:
            findings.append(CheckResult(
                check_id=self.id, title=self.title, description=self.description,
                severity=self.severity, category=self.category, service=self.service,
                resource_name=f"projects/{project_id}", project_id=project_id,
                current_state="No conditional IAM bindings found",
                recommended_state="Use IAM Conditions for time-bound or resource-scoped grants",
                fix_command="", references=self.references,
            ))
        return findings


class ServiceAccountImpersonationGrants(BaseCheck):
    """IAM-015: SAs that can impersonate other SAs (privilege escalation chain)."""

    id = "IAM-015"
    title = "Service account can impersonate other service accounts (priv-esc chain)"
    description = (
        "Members with roles/iam.serviceAccountTokenCreator on a SA can mint tokens "
        "as that SA. Chains of impersonation can escalate to Owner."
    )
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "IAM"
    service_category = ServiceCategory.IAM
    references = ["https://cloud.google.com/iam/docs/impersonating-service-accounts"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.5.15", "A.8.2"]}

    DANGEROUS_ROLES = {"roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountUser"}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            accounts = await gcloud_runner.run(
                f"gcloud iam service-accounts list --project={project_id} --format=json"
            )
        except Exception:
            return findings
        for sa in (accounts if isinstance(accounts, list) else []):
            email = sa.get("email", "")
            if not email:
                continue
            try:
                policy = await gcloud_runner.run(
                    f"gcloud iam service-accounts get-iam-policy {email} --project={project_id} --format=json"
                )
            except Exception:
                continue
            if not isinstance(policy, dict):
                continue
            for binding in policy.get("bindings", []):
                if binding.get("role") in self.DANGEROUS_ROLES:
                    members = [m for m in binding.get("members", []) if m]
                    if members:
                        findings.append(CheckResult(
                            check_id=self.id, title=self.title, description=self.description,
                            severity=self.severity, category=self.category, service=self.service,
                            resource_name=email, project_id=project_id,
                            current_state=f"{binding.get('role')} granted to: {', '.join(members[:3])}",
                            recommended_state="Audit impersonation grants and remove unused ones",
                            fix_command="", references=self.references,
                        ))
                        break  # one finding per SA is enough
        return findings


class ShadowAdminViaSAKeyAdmin(BaseCheck):
    """IAM-016: Non-admin members can create keys for privileged SAs (shadow admin)."""

    id = "IAM-016"
    title = "Members can create keys for privileged service accounts (shadow admin)"
    description = (
        "If a non-admin can create a service account key for a SA with Owner/Editor, "
        "they effectively have Owner/Editor — even though their direct bindings look limited."
    )
    severity = Severity.CRITICAL
    category = Category.SECURITY
    service = "IAM"
    service_category = ServiceCategory.IAM
    references = ["https://cloud.google.com/iam/docs/best-practices-service-accounts"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"CIS_GCP_V3": ["1.8"], "ISO_27001": ["A.5.3", "A.8.2"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            policy = await gcloud_runner.run(
                f"gcloud projects get-iam-policy {project_id} --format=json"
            )
        except Exception:
            return findings
        if not isinstance(policy, dict):
            return findings
        # Find SAs with primitive roles
        privileged_sas: set[str] = set()
        for binding in policy.get("bindings", []):
            if binding.get("role") in PRIMITIVE_ROLES:
                for member in binding.get("members", []):
                    if member.startswith("serviceAccount:"):
                        privileged_sas.add(member.replace("serviceAccount:", ""))
        if not privileged_sas:
            return findings
        for sa_email in privileged_sas:
            try:
                sa_policy = await gcloud_runner.run(
                    f"gcloud iam service-accounts get-iam-policy {sa_email} --project={project_id} --format=json"
                )
            except Exception:
                continue
            if not isinstance(sa_policy, dict):
                continue
            for binding in sa_policy.get("bindings", []):
                if binding.get("role") in ("roles/iam.serviceAccountKeyAdmin", "roles/iam.serviceAccountAdmin"):
                    members = binding.get("members", [])
                    if members:
                        findings.append(CheckResult(
                            check_id=self.id, title=self.title, description=self.description,
                            severity=self.severity, category=self.category, service=self.service,
                            resource_name=sa_email, project_id=project_id,
                            current_state=f"{binding.get('role')} on a privileged SA granted to: {', '.join(members[:3])}",
                            recommended_state="Remove key-admin/admin grants on privileged SAs",
                            fix_command="", references=self.references,
                        ))
                        break
        return findings


# IAM role-binding checks use cloudresourcemanager.googleapis.com for get-iam-policy
import sys as _sys  # noqa: E402
from backend.checks._module_helpers import apply_required_apis as _apply  # noqa: E402
_apply(_sys.modules[__name__], ["cloudresourcemanager.googleapis.com"])
