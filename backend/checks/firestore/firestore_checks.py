"""Firestore (and Datastore-mode) checks.

Checks: FS-001 through FS-004
"""

import logging
from typing import Any, ClassVar

from backend.checks.base import BaseCheck
from backend.core.models import Category, CheckResult, Severity, ServiceCategory

logger = logging.getLogger(__name__)


async def _list_databases(gcloud_runner: Any, project_id: str) -> list[dict]:
    try:
        dbs = await gcloud_runner.run(
            f"gcloud firestore databases list --project={project_id} --format=json"
        )
        return dbs if isinstance(dbs, list) else []
    except Exception as e:
        logger.debug("Firestore databases list failed: %s", e)
        return []


def _db_id(db: dict) -> str:
    return db.get("name", "").split("/")[-1]


class FirestoreNoPITR(BaseCheck):
    id = "FS-001"
    title = "Firestore database has no Point-in-Time Recovery"
    description = "PITR provides 7 days of restore-to-microsecond protection against accidental writes."
    severity = Severity.MEDIUM
    category = Category.RELIABILITY
    service = "Firestore"
    service_category = ServiceCategory.FIRESTORE
    fix_command_template = "gcloud firestore databases update --database={name} --enable-pitr --project={project_id}"
    references = ["https://cloud.google.com/firestore/docs/use-pitr"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.13", "A.5.29"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for db in await _list_databases(gcloud_runner, project_id):
            name = _db_id(db)
            if db.get("pointInTimeRecoveryEnablement") != "POINT_IN_TIME_RECOVERY_ENABLED":
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"firestore/{name}", project_id=project_id,
                    current_state="PITR not enabled",
                    recommended_state="Enable Point-in-Time Recovery",
                    fix_command=self.build_fix_command(name=name, project_id=project_id),
                    references=self.references,
                ))
        return findings


class FirestoreNoBackupSchedule(BaseCheck):
    id = "FS-002"
    title = "Firestore database has no backup schedule"
    description = "Schedule daily or weekly backups for long-term durability beyond PITR's 7-day window."
    severity = Severity.MEDIUM
    category = Category.RELIABILITY
    service = "Firestore"
    service_category = ServiceCategory.FIRESTORE
    references = ["https://cloud.google.com/firestore/docs/backups"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.13"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for db in await _list_databases(gcloud_runner, project_id):
            name = _db_id(db)
            try:
                schedules = await gcloud_runner.run(
                    f"gcloud firestore backups schedules list --database={name} --project={project_id} --format=json"
                )
            except Exception:
                schedules = []
            if not isinstance(schedules, list) or len(schedules) == 0:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"firestore/{name}", project_id=project_id,
                    current_state="No backup schedules configured",
                    recommended_state="Configure a daily or weekly backup schedule",
                    fix_command="", references=self.references,
                ))
        return findings


class FirestoreNoDeleteProtection(BaseCheck):
    id = "FS-003"
    title = "Firestore database has no delete protection"
    description = "Delete protection prevents accidental `gcloud firestore databases delete` and similar API calls."
    severity = Severity.MEDIUM
    category = Category.RELIABILITY
    service = "Firestore"
    service_category = ServiceCategory.FIRESTORE
    fix_command_template = "gcloud firestore databases update --database={name} --delete-protection --project={project_id}"
    references = ["https://cloud.google.com/firestore/docs/manage-databases#delete-protection"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.10"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for db in await _list_databases(gcloud_runner, project_id):
            name = _db_id(db)
            if db.get("deleteProtectionState") != "DELETE_PROTECTION_ENABLED":
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"firestore/{name}", project_id=project_id,
                    current_state="Delete protection disabled",
                    recommended_state="Enable delete protection on the database",
                    fix_command=self.build_fix_command(name=name, project_id=project_id),
                    references=self.references,
                ))
        return findings


class FirestoreNoCMEK(BaseCheck):
    id = "FS-004"
    title = "Firestore database not encrypted with CMEK"
    description = "Customer-managed encryption keys give control over key lifecycle and access."
    severity = Severity.LOW
    category = Category.SECURITY
    service = "Firestore"
    service_category = ServiceCategory.FIRESTORE
    references = ["https://cloud.google.com/firestore/docs/cmek"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.24"], "DPDP": ["8(5)"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for db in await _list_databases(gcloud_runner, project_id):
            name = _db_id(db)
            cmek = db.get("cmekConfig", {}).get("kmsKeyName")
            if not cmek:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"firestore/{name}", project_id=project_id,
                    current_state="Using Google-managed encryption",
                    recommended_state="Configure CMEK at database creation time",
                    fix_command="", references=self.references,
                ))
        return findings


import sys as _sys  # noqa: E402
from backend.checks._module_helpers import apply_required_apis as _apply  # noqa: E402
_apply(_sys.modules[__name__], ["firestore.googleapis.com"])
