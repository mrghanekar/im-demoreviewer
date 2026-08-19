"""Memorystore (Redis & Memcached) checks.

Checks: MS-001 through MS-005
"""

import logging
from typing import Any, ClassVar

from backend.checks.base import BaseCheck
from backend.core.models import Category, CheckResult, Severity, ServiceCategory

logger = logging.getLogger(__name__)


async def _list_redis(gcloud_runner: Any, project_id: str) -> list[dict]:
    try:
        r = await gcloud_runner.run(
            f"gcloud redis instances list --region=- --project={project_id} --format=json"
        )
        return r if isinstance(r, list) else []
    except Exception as e:
        logger.debug("Memorystore Redis list failed: %s", e)
        return []


def _instance_name(r: dict) -> str:
    return r.get("name", "").split("/")[-1]


class RedisAuthDisabled(BaseCheck):
    id = "MS-001"
    title = "Memorystore Redis instance has AUTH disabled"
    description = "Without AUTH, anything that can reach the instance can read/write the cache."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Memorystore"
    service_category = ServiceCategory.MEMORYSTORE
    references = ["https://cloud.google.com/memorystore/docs/redis/about-redis-auth"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.5", "A.5.15"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for r in await _list_redis(gcloud_runner, project_id):
            name = _instance_name(r)
            if not r.get("authEnabled"):
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"redis/{name}", project_id=project_id,
                    current_state="AUTH disabled",
                    recommended_state="Enable AUTH on the instance",
                    fix_command="", references=self.references,
                ))
        return findings


class RedisNoInTransitEncryption(BaseCheck):
    id = "MS-002"
    title = "Memorystore Redis without in-transit encryption (TLS)"
    description = "Cache traffic should be TLS-encrypted, especially across VPC peerings."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Memorystore"
    service_category = ServiceCategory.MEMORYSTORE
    references = ["https://cloud.google.com/memorystore/docs/redis/about-in-transit-encryption"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.24", "A.8.21"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for r in await _list_redis(gcloud_runner, project_id):
            name = _instance_name(r)
            mode = r.get("transitEncryptionMode", "DISABLED")
            if mode == "DISABLED":
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"redis/{name}", project_id=project_id,
                    current_state="transitEncryptionMode=DISABLED",
                    recommended_state="Set to SERVER_AUTHENTICATION (TLS)",
                    fix_command="", references=self.references,
                ))
        return findings


class RedisBasicTierNoHA(BaseCheck):
    id = "MS-003"
    title = "Memorystore Redis is BASIC tier (no high availability)"
    description = "BASIC tier has no replication; an instance failure loses all data."
    severity = Severity.MEDIUM
    category = Category.RELIABILITY
    service = "Memorystore"
    service_category = ServiceCategory.MEMORYSTORE
    references = ["https://cloud.google.com/memorystore/docs/redis/redis-tiers"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.14"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for r in await _list_redis(gcloud_runner, project_id):
            name = _instance_name(r)
            if r.get("tier") == "BASIC":
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"redis/{name}", project_id=project_id,
                    current_state="Tier=BASIC (no HA, no failover)",
                    recommended_state="Use STANDARD_HA tier for production",
                    fix_command="", references=self.references,
                ))
        return findings


class RedisNoCMEK(BaseCheck):
    id = "MS-004"
    title = "Memorystore Redis not encrypted with CMEK"
    description = "For compliance, use customer-managed Cloud KMS keys for at-rest encryption."
    severity = Severity.LOW
    category = Category.SECURITY
    service = "Memorystore"
    service_category = ServiceCategory.MEMORYSTORE
    references = ["https://cloud.google.com/memorystore/docs/redis/about-cmek"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.24"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for r in await _list_redis(gcloud_runner, project_id):
            name = _instance_name(r)
            cmek = r.get("customerManagedKey")
            if not cmek:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"redis/{name}", project_id=project_id,
                    current_state="No CMEK configured",
                    recommended_state="Configure CMEK via --customer-managed-key",
                    fix_command="", references=self.references,
                ))
        return findings


class RedisNoMaintenancePolicy(BaseCheck):
    id = "MS-005"
    title = "Memorystore Redis has no maintenance window policy"
    description = "Without a maintenance window, updates may interrupt traffic at unpredictable times."
    severity = Severity.LOW
    category = Category.RELIABILITY
    service = "Memorystore"
    service_category = ServiceCategory.MEMORYSTORE
    references = ["https://cloud.google.com/memorystore/docs/redis/about-maintenance"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for r in await _list_redis(gcloud_runner, project_id):
            name = _instance_name(r)
            if not r.get("maintenancePolicy"):
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"redis/{name}", project_id=project_id,
                    current_state="No maintenancePolicy",
                    recommended_state="Set --maintenance-window-day and --maintenance-window-hour",
                    fix_command="", references=self.references,
                ))
        return findings


import sys as _sys  # noqa: E402
from backend.checks._module_helpers import apply_required_apis as _apply  # noqa: E402
_apply(_sys.modules[__name__], ["redis.googleapis.com"])
