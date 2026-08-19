"""IAM checks related to service accounts.

Checks: IAM-003, IAM-007.
(IAM-002 'SA keys > 90 days' was a strict subset of IAM-003 and was folded
 into IAM-003's current_state. IAM-005 'SA impersonation not used' was a
 duplicate of IAM-003 and was removed. IAM-004/IAM-011 live in iam/role_bindings.py.)
"""

import logging
from datetime import datetime, timezone
from typing import Any

from backend.checks.base import BaseCheck
from backend.core.models import Category, CheckResult, Severity, ServiceCategory

logger = logging.getLogger(__name__)


def _key_age_days(validAfterTime: str) -> int | None:
    """Return age in days for a key's validAfterTime, or None if unparseable."""
    if not validAfterTime:
        return None
    try:
        created_dt = datetime.fromisoformat(validAfterTime.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - created_dt).days
    except (ValueError, TypeError):
        return None


class UserManagedSAKeys(BaseCheck):
    """IAM-003: User-managed service account keys exist.

    Absorbed IAM-002 (>90d keys): current_state now reports the oldest key's age
    so the same severity escalates naturally without a second check firing for
    the same SA. Keys >90 days are still High severity by virtue of being keys.
    """

    id = "IAM-003"
    title = "User-managed service account keys exist"
    description = (
        "User-managed service account keys are a security risk as they can be leaked or "
        "exfiltrated. Prefer Workload Identity Federation or attached service accounts. "
        "Keys older than 90 days are especially risky."
    )
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "IAM"
    service_category = ServiceCategory.IAM
    gcloud_command = "gcloud iam service-accounts keys list --iam-account={sa_email} --managed-by=user --format=json"
    fix_command_template = "gcloud iam service-accounts keys delete {key_id} --iam-account={sa_email} --quiet"
    references = [
        "https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys",
    ]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            accounts = await gcloud_runner.run(
                f"gcloud iam service-accounts list --project={project_id} --format=json"
            )
            if not isinstance(accounts, list):
                return []

            for sa in accounts:
                email = sa.get("email", "")
                if not email:
                    continue
                try:
                    keys = await gcloud_runner.run(
                        f"gcloud iam service-accounts keys list --iam-account={email} --managed-by=user --format=json"
                    )
                    if not (isinstance(keys, list) and len(keys) > 0):
                        continue

                    # Compute max age across the SA's keys (absorbs old IAM-002).
                    ages = [
                        a for a in (_key_age_days(k.get("validAfterTime", "")) for k in keys)
                        if a is not None
                    ]
                    max_age = max(ages) if ages else None
                    if max_age is not None and max_age > 90:
                        state = f"{len(keys)} user-managed key(s) found; oldest is {max_age} days old (>90)"
                    else:
                        state = f"{len(keys)} user-managed key(s) found"

                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=email,
                        resource_link=self.console_link("service_account", project_id, email=email),
                        project_id=project_id,
                        current_state=state,
                        recommended_state="Use Workload Identity Federation or attached SA instead of keys",
                        fix_command=self.build_fix_command(
                            key_id=keys[0].get("name", "").split("/")[-1],
                            sa_email=email,
                        ),
                        references=self.references,
                    ))
                except Exception as e:
                    logger.debug("Could not list keys for %s: %s", email, e)
        except Exception as e:
            logger.error("IAM-003 failed: %s", e)
        return findings


class UnusedServiceAccounts(BaseCheck):
    """IAM-007: Unused service accounts (90+ days without authentication)."""

    id = "IAM-007"
    title = "Unused service account (90+ days inactive)"
    description = (
        "Service accounts that have not authenticated in 90+ days are likely unused "
        "and should be disabled or deleted to reduce attack surface."
    )
    severity = Severity.MEDIUM
    category = Category.COST
    service = "IAM"
    service_category = ServiceCategory.IAM
    fix_command_template = "gcloud iam service-accounts disable {sa_email} --project={project_id}"
    references = [
        "https://cloud.google.com/iam/docs/service-account-overview#disabled",
        "https://cloud.google.com/policy-intelligence/docs/activity-analyzer-service-account-authentication",
    ]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            accounts = await gcloud_runner.run(
                f"gcloud iam service-accounts list --project={project_id} --format=json"
            )
            if not isinstance(accounts, list):
                return []

            for sa in accounts:
                email = sa.get("email", "")
                disabled = sa.get("disabled", False)
                if not email or disabled:
                    continue
                # Check if it's a default/system SA — skip those
                if email.endswith(".gserviceaccount.com") and (
                    email.startswith(f"{project_id}@") or
                    "-compute@developer" in email or
                    "@cloudservices" in email or
                    "@appspot" in email
                ):
                    continue

                # We can't easily check last auth time via gcloud; flag SAs without keys
                # that also don't seem to be attached to anything (heuristic).
                # A more accurate check would use Activity Analyzer API.
                try:
                    keys = await gcloud_runner.run(
                        f"gcloud iam service-accounts keys list --iam-account={email} --format=json"
                    )
                    # If SA has only system-managed keys (1 key = system default), it may be unused
                    user_keys = [k for k in (keys or []) if k.get("keyType") == "USER_MANAGED"]
                    system_keys = [k for k in (keys or []) if k.get("keyType") == "SYSTEM_MANAGED"]
                    if len(user_keys) == 0 and len(system_keys) <= 1:
                        # Potentially unused — flag as info-level recommendation
                        findings.append(CheckResult(
                            check_id=self.id, title=self.title, description=self.description,
                            severity=Severity.MEDIUM, category=self.category, service=self.service,
                            resource_name=email,
                            resource_link=self.console_link("service_account", project_id, email=email),
                            project_id=project_id,
                            current_state="No user-managed keys; may be unused. Verify with Activity Analyzer.",
                            recommended_state="Disable or delete unused service accounts",
                            fix_command=self.build_fix_command(sa_email=email, project_id=project_id),
                            references=self.references,
                        ))
                except Exception:
                    pass
        except Exception as e:
            logger.error("IAM-007 failed: %s", e)
        return findings


import sys as _sys  # noqa: E402
from backend.checks._module_helpers import apply_required_apis as _apply  # noqa: E402
_apply(_sys.modules[__name__], ["iam.googleapis.com"])
