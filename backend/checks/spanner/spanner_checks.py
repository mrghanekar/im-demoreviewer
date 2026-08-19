"""Cloud Spanner checks.

Checks: SP-001 through SP-004
"""

import logging
from typing import Any

from backend.checks.base import BaseCheck
from backend.core.models import Category, CheckResult, Severity, ServiceCategory

logger = logging.getLogger(__name__)


async def _list_instances(gcloud_runner: Any, project_id: str) -> list[dict]:
    try:
        instances = await gcloud_runner.run(
            f"gcloud spanner instances list --project={project_id} --format=json"
        )
        return instances if isinstance(instances, list) else []
    except Exception as e:
        logger.debug("Spanner instances list failed: %s", e)
        return []


def _instance_id(i: dict) -> str:
    return i.get("name", "").split("/")[-1]


class SpannerSingleRegion(BaseCheck):
    id = "SP-001"
    title = "Spanner instance is single-region (no geo-redundancy)"
    description = "Multi-region or dual-region configs provide RPO=0 across regions."
    severity = Severity.MEDIUM
    category = Category.RELIABILITY
    service = "Spanner"
    service_category = ServiceCategory.SPANNER
    references = ["https://cloud.google.com/spanner/docs/instance-configurations"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for inst in await _list_instances(gcloud_runner, project_id):
            name = _instance_id(inst)
            config = inst.get("config", "").split("/")[-1]
            if config and config.startswith("regional-"):
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"spanner/{name}", project_id=project_id,
                    current_state=f"Single-region config: {config}",
                    recommended_state="Use a multi-region (nam-eur-asia*) or dual-region config",
                    fix_command="", references=self.references,
                ))
        return findings


class SpannerNoBackupSchedule(BaseCheck):
    id = "SP-002"
    title = "Spanner database has no backup schedule"
    description = "Schedule periodic backups to meet RPO requirements."
    severity = Severity.HIGH
    category = Category.RELIABILITY
    service = "Spanner"
    service_category = ServiceCategory.SPANNER
    references = ["https://cloud.google.com/spanner/docs/backup"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for inst in await _list_instances(gcloud_runner, project_id):
            inst_id = _instance_id(inst)
            try:
                dbs = await gcloud_runner.run(
                    f"gcloud spanner databases list --instance={inst_id} --project={project_id} --format=json"
                )
            except Exception:
                continue
            for db in (dbs if isinstance(dbs, list) else []):
                db_id = db.get("name", "").split("/")[-1]
                try:
                    schedules = await gcloud_runner.run(
                        f"gcloud spanner backup-schedules list --instance={inst_id} --database={db_id} --project={project_id} --format=json"
                    )
                except Exception:
                    schedules = []
                if not isinstance(schedules, list) or len(schedules) == 0:
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"spanner/{inst_id}/{db_id}", project_id=project_id,
                        current_state="No backup schedule",
                        recommended_state="Create a backup schedule",
                        fix_command="", references=self.references,
                    ))
        return findings


class SpannerNoCMEK(BaseCheck):
    id = "SP-003"
    title = "Spanner database not encrypted with CMEK"
    description = "Customer-managed Cloud KMS keys provide key lifecycle control."
    severity = Severity.LOW
    category = Category.SECURITY
    service = "Spanner"
    service_category = ServiceCategory.SPANNER
    references = ["https://cloud.google.com/spanner/docs/cmek"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for inst in await _list_instances(gcloud_runner, project_id):
            inst_id = _instance_id(inst)
            try:
                dbs = await gcloud_runner.run(
                    f"gcloud spanner databases list --instance={inst_id} --project={project_id} --format=json"
                )
            except Exception:
                continue
            for db in (dbs if isinstance(dbs, list) else []):
                db_id = db.get("name", "").split("/")[-1]
                cmek = db.get("encryptionConfig", {}).get("kmsKeyName")
                if not cmek:
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"spanner/{inst_id}/{db_id}", project_id=project_id,
                        current_state="Google-managed encryption",
                        recommended_state="Recreate database with CMEK encryptionConfig",
                        fix_command="", references=self.references,
                    ))
        return findings


class SpannerProcessingUnitsLow(BaseCheck):
    id = "SP-004"
    title = "Spanner instance has minimum processing units (may bottleneck production)"
    description = "100 PUs is fine for dev but production usually needs more headroom."
    severity = Severity.INFO
    category = Category.PERFORMANCE
    service = "Spanner"
    service_category = ServiceCategory.SPANNER
    references = ["https://cloud.google.com/spanner/docs/compute-capacity"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        for inst in await _list_instances(gcloud_runner, project_id):
            name = _instance_id(inst)
            pus = inst.get("processingUnits", 0)
            if pus and pus <= 100:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"spanner/{name}", project_id=project_id,
                    current_state=f"processingUnits={pus}",
                    recommended_state="Right-size based on load; consider autoscaler",
                    fix_command="", references=self.references,
                ))
        return findings


import sys as _sys  # noqa: E402
from backend.checks._module_helpers import apply_required_apis as _apply  # noqa: E402
_apply(_sys.modules[__name__], ["spanner.googleapis.com"])
