"""GCE instance security, reliability, and cost checks.

Checks: GCE-001 through GCE-015
"""

import logging
from typing import Any, ClassVar

from backend.checks.base import BaseCheck
from backend.core.models import Category, CheckResult, Severity, ServiceCategory

logger = logging.getLogger(__name__)


class GCEPublicIP(BaseCheck):
    id = "GCE-001"
    title = "Instance has external (public) IP address"
    description = "Instances with public IPs are directly exposed to the internet."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "GCE"
    service_category = ServiceCategory.GCE
    gcloud_command = "gcloud compute instances list --project={project_id} --format=json"
    fix_command_template = "gcloud compute instances delete-access-config {name} --access-config-name='External NAT' --zone={zone} --project={project_id}"
    references = ["https://cloud.google.com/compute/docs/ip-addresses/reserve-static-external-ip-address"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"CIS_GCP_V3": ["4.8"], "ISO_27001": ["A.8.20"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await gcloud_runner.run(f"gcloud compute instances list --project={project_id} --format=json")
            if not isinstance(instances, list):
                return []
            for i in instances:
                name = i.get("name", "")
                zone = i.get("zone", "").split("/")[-1]
                for nic in i.get("networkInterfaces", []):
                    for ac in nic.get("accessConfigs", []):
                        if ac.get("natIP"):
                            findings.append(CheckResult(
                                check_id=self.id, title=self.title, description=self.description,
                                severity=self.severity, category=self.category, service=self.service,
                                resource_name=f"instances/{name}", project_id=project_id,
                                resource_link=self.console_link("gce_instance", project_id, name=name, zone=zone),
                                current_state=f"External IP: {ac['natIP']}",
                                recommended_state="Remove external IP; use IAP or Cloud NAT for egress",
                                fix_command=self.build_fix_command(name=name, zone=zone, project_id=project_id),
                                references=self.references,
                            ))
                            break
        except Exception as e:
            logger.error("GCE-001 failed: %s", e)
        return findings


class GCEDefaultServiceAccount(BaseCheck):
    id = "GCE-002"
    title = "Instance using default Compute Engine service account"
    description = "The default service account has broad Editor permissions. Use a custom SA."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "GCE"
    service_category = ServiceCategory.GCE
    references = ["https://cloud.google.com/compute/docs/access/service-accounts#default_service_account"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"CIS_GCP_V3": ["4.1"], "ISO_27001": ["A.5.16", "A.8.2"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await gcloud_runner.run(f"gcloud compute instances list --project={project_id} --format=json")
            if not isinstance(instances, list):
                return []
            for i in instances:
                name = i.get("name", "")
                zone = i.get("zone", "").split("/")[-1]
                for sa in i.get("serviceAccounts", []):
                    email = sa.get("email", "")
                    if email.endswith("-compute@developer.gserviceaccount.com"):
                        findings.append(CheckResult(
                            check_id=self.id, title=self.title, description=self.description,
                            severity=self.severity, category=self.category, service=self.service,
                            resource_name=f"instances/{name}", project_id=project_id,
                            resource_link=self.console_link("gce_instance", project_id, name=name, zone=zone),
                            current_state=f"Using default compute SA: {email}",
                            recommended_state="Create and attach a custom SA with least-privilege roles",
                            fix_command="", references=self.references,
                        ))
        except Exception as e:
            logger.error("GCE-002 failed: %s", e)
        return findings


class GCEFullAPIAccess(BaseCheck):
    id = "GCE-003"
    title = "Instance has full API access scope"
    description = "cloud-platform scope grants access to all GCP APIs. Use specific scopes or IAM."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "GCE"
    service_category = ServiceCategory.GCE
    references = ["https://cloud.google.com/compute/docs/access/create-enable-service-accounts-for-instances"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"CIS_GCP_V3": ["4.2"], "ISO_27001": ["A.5.15", "A.8.2"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await gcloud_runner.run(f"gcloud compute instances list --project={project_id} --format=json")
            if not isinstance(instances, list):
                return []
            for i in instances:
                name = i.get("name", "")
                zone = i.get("zone", "").split("/")[-1]
                for sa in i.get("serviceAccounts", []):
                    scopes = sa.get("scopes", [])
                    if "https://www.googleapis.com/auth/cloud-platform" in scopes:
                        findings.append(CheckResult(
                            check_id=self.id, title=self.title, description=self.description,
                            severity=self.severity, category=self.category, service=self.service,
                            resource_name=f"instances/{name}", project_id=project_id,
                            resource_link=self.console_link("gce_instance", project_id, name=name, zone=zone),
                            current_state="Instance has full cloud-platform API access scope",
                            recommended_state="Use specific API scopes or IAM roles instead",
                            fix_command="", references=self.references,
                        ))
        except Exception as e:
            logger.error("GCE-003 failed: %s", e)
        return findings


class GCEShieldedVM(BaseCheck):
    id = "GCE-004"
    title = "Shielded VM features not enabled"
    description = "Shielded VM provides verifiable integrity with vTPM and Secure Boot."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "GCE"
    service_category = ServiceCategory.GCE
    references = ["https://cloud.google.com/compute/shielded-vm/docs/shielded-vm"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"CIS_GCP_V3": ["4.7"], "ISO_27001": ["A.8.9"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await gcloud_runner.run(f"gcloud compute instances list --project={project_id} --format=json")
            if not isinstance(instances, list):
                return []
            for i in instances:
                name = i.get("name", "")
                zone = i.get("zone", "").split("/")[-1]
                svm = i.get("shieldedInstanceConfig", {})
                if not svm or not (svm.get("enableVtpm", False) and svm.get("enableIntegrityMonitoring", False)):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"instances/{name}", project_id=project_id,
                        resource_link=self.console_link("gce_instance", project_id, name=name, zone=zone),
                        current_state="Shielded VM features not fully enabled",
                        recommended_state="Enable vTPM, Secure Boot, and Integrity Monitoring",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.error("GCE-004 failed: %s", e)
        return findings


class GCEDiskCMEK(BaseCheck):
    id = "GCE-005"
    title = "Disk not encrypted with CMEK"
    description = "Persistent disks should use customer-managed encryption keys for sensitive data."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "GCE"
    service_category = ServiceCategory.GCE
    references = ["https://cloud.google.com/compute/docs/disks/customer-managed-encryption"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"CIS_GCP_V3": ["4.6"], "ISO_27001": ["A.8.24"], "DPDP": ["8(5)"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            disks = await gcloud_runner.run(f"gcloud compute disks list --project={project_id} --format=json")
            if not isinstance(disks, list):
                return []
            for d in disks:
                name = d.get("name", "")
                enc = d.get("diskEncryptionKey", {})
                if not enc or not enc.get("kmsKeyName"):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"disks/{name}", project_id=project_id,
                        current_state="Using Google-managed encryption (default)",
                        recommended_state="Encrypt with a Cloud KMS customer-managed key",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.error("GCE-005 failed: %s", e)
        return findings


class GCESerialPortEnabled(BaseCheck):
    id = "GCE-006"
    title = "Serial port access enabled"
    description = "Interactive serial port access can be used for console access and should be disabled."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "GCE"
    service_category = ServiceCategory.GCE
    references = ["https://cloud.google.com/compute/docs/troubleshooting/troubleshooting-using-serial-console"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.9"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await gcloud_runner.run(f"gcloud compute instances list --project={project_id} --format=json")
            if not isinstance(instances, list):
                return []
            for i in instances:
                name = i.get("name", "")
                zone = i.get("zone", "").split("/")[-1]
                metadata_items = i.get("metadata", {}).get("items", [])
                for item in metadata_items:
                    if item.get("key") == "serial-port-enable" and item.get("value", "").lower() == "true":
                        findings.append(CheckResult(
                            check_id=self.id, title=self.title, description=self.description,
                            severity=self.severity, category=self.category, service=self.service,
                            resource_name=f"instances/{name}", project_id=project_id,
                            resource_link=self.console_link("gce_instance", project_id, name=name, zone=zone),
                            current_state="Serial port console access is enabled",
                            recommended_state="Disable serial port access unless needed for debugging",
                            fix_command="", references=self.references,
                        ))
        except Exception as e:
            logger.error("GCE-006 failed: %s", e)
        return findings


class GCEOSLogin(BaseCheck):
    id = "GCE-007"
    title = "OS Login not enabled"
    description = "OS Login integrates SSH key management with IAM for centralized access control."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "GCE"
    service_category = ServiceCategory.GCE
    references = ["https://cloud.google.com/compute/docs/instances/managing-instance-access"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"CIS_GCP_V3": ["4.4"], "ISO_27001": ["A.5.16", "A.8.5"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            # Check project-level metadata
            project_meta = await gcloud_runner.run(f"gcloud compute project-info describe --project={project_id} --format=json")
            if not isinstance(project_meta, dict):
                return []
            items = project_meta.get("commonInstanceMetadata", {}).get("items", [])
            os_login_enabled = any(
                item.get("key") == "enable-oslogin" and item.get("value", "").lower() == "true"
                for item in items
            )
            if not os_login_enabled:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"projects/{project_id}", project_id=project_id,
                    current_state="OS Login not enabled at project level",
                    recommended_state="Enable OS Login for centralized SSH key management via IAM",
                    fix_command=f"gcloud compute project-info add-metadata --metadata enable-oslogin=TRUE --project={project_id}",
                    references=self.references,
                ))
        except Exception as e:
            logger.error("GCE-007 failed: %s", e)
        return findings


class GCENoSnapshots(BaseCheck):
    id = "GCE-008"
    title = "No disk snapshots configured"
    description = "Regular snapshots provide point-in-time backups for disaster recovery."
    severity = Severity.MEDIUM
    category = Category.RELIABILITY
    service = "GCE"
    service_category = ServiceCategory.GCE
    references = ["https://cloud.google.com/compute/docs/disks/create-snapshots"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.13"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            schedules = await gcloud_runner.run(f"gcloud compute resource-policies list --project={project_id} --format=json")
            if not isinstance(schedules, list) or len(schedules) == 0:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"projects/{project_id}", project_id=project_id,
                    current_state="No snapshot schedules configured in this project",
                    recommended_state="Create snapshot schedules for critical disks",
                    fix_command="", references=self.references,
                ))
        except Exception as e:
            logger.error("GCE-008 failed: %s", e)
        return findings


class GCEIPForwarding(BaseCheck):
    id = "GCE-009"
    title = "IP forwarding enabled on instance"
    description = "IP forwarding allows routing traffic through the instance; only needed for NAT/router VMs."
    severity = Severity.LOW
    category = Category.SECURITY
    service = "GCE"
    service_category = ServiceCategory.GCE
    references = ["https://cloud.google.com/vpc/docs/using-routes#canipforward"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"CIS_GCP_V3": ["4.5"], "ISO_27001": ["A.8.20"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await gcloud_runner.run(f"gcloud compute instances list --project={project_id} --format=json")
            if not isinstance(instances, list):
                return []
            for i in instances:
                name = i.get("name", "")
                zone = i.get("zone", "").split("/")[-1]
                if i.get("canIpForward", False):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"instances/{name}", project_id=project_id,
                        resource_link=self.console_link("gce_instance", project_id, name=name, zone=zone),
                        current_state="IP forwarding is enabled",
                        recommended_state="Disable unless instance is a NAT gateway or router",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.error("GCE-009 failed: %s", e)
        return findings


class GCEOldMachineType(BaseCheck):
    id = "GCE-010"
    title = "Instance using legacy machine type"
    description = "Legacy N1 machine types are less cost-effective than newer N2/E2/T2D families."
    severity = Severity.LOW
    category = Category.COST
    service = "GCE"
    service_category = ServiceCategory.GCE
    references = ["https://cloud.google.com/compute/docs/machine-resource"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await gcloud_runner.run(f"gcloud compute instances list --project={project_id} --format=json")
            if not isinstance(instances, list):
                return []
            for i in instances:
                name = i.get("name", "")
                zone = i.get("zone", "").split("/")[-1]
                mt = i.get("machineType", "").split("/")[-1]
                if mt.startswith("n1-") or mt.startswith("f1-") or mt.startswith("g1-"):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"instances/{name}", project_id=project_id,
                        resource_link=self.console_link("gce_instance", project_id, name=name, zone=zone),
                        current_state=f"Machine type: {mt} (legacy generation)",
                        recommended_state="Consider N2, E2, or T2D for better price-performance",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.error("GCE-010 failed: %s", e)
        return findings


class GCEDeprecatedImages(BaseCheck):
    """GCE-011: Instance is using a deprecated or obsolete OS image."""

    id = "GCE-011"
    title = "Instance using deprecated OS image"
    description = (
        "Using deprecated or obsolete images increases security risks as they "
        "may no longer receive security patches or updates."
    )
    severity = Severity.MEDIUM
    category = Category.OPERATIONS
    service = "GCE"
    service_category = ServiceCategory.GCE
    gcloud_command = "gcloud compute instances list --format=json"
    references = ["https://cloud.google.com/compute/docs/images/create-delete-deprecate-images#deprecating_an_image"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.8"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        import asyncio
        findings: list[CheckResult] = []
        try:
            # 1. Get all instances and their zones
            instances = await gcloud_runner.run(
                f"gcloud compute instances list --project={project_id} --format='json(name,zone,disks)'"
            )
            if not isinstance(instances, list):
                return []

            # Semaphore to control concurrency of internal gcloud calls
            sem = asyncio.Semaphore(5)

            async def run_with_sem(coro):
                async with sem:
                    return await coro

            # 2. Gather all disk lookup tasks
            disk_tasks = []
            instance_map = [] # Map index to (instance_name, zone)

            for inst in instances:
                name = inst.get("name", "")
                zone = inst.get("zone", "").split("/")[-1]
                boot_disk_name = ""
                for disk in inst.get("disks", []):
                    if disk.get("boot"):
                        boot_disk_url = disk.get("source", "")
                        boot_disk_name = boot_disk_url.split("/")[-1]
                        break
                
                if boot_disk_name:
                    instance_map.append((name, zone))
                    disk_tasks.append(run_with_sem(gcloud_runner.run(
                        f"gcloud compute disks describe {boot_disk_name} --zone={zone} --project={project_id} --format='json(sourceImage)'",
                        use_cache=True
                    )))

            if not disk_tasks:
                return []

            # Run disk lookups in parallel
            disk_results = await asyncio.gather(*disk_tasks, return_exceptions=True)
            
            # 3. Identify unique images to check
            image_urls = set()
            # Map task index -> image_url (for later correlation)
            source_images = [] 

            for res in disk_results:
                if isinstance(res, dict) and res.get("sourceImage"):
                    url = res["sourceImage"]
                    image_urls.add(url)
                    source_images.append(url)
                else:
                    source_images.append(None)

            # 4. Check image deprecation status in parallel
            image_tasks = []
            sorted_urls = list(image_urls)
            url_to_status = {} # Cache

            for url in sorted_urls:
                parts = url.split("/")
                try:
                    # Extract project and name from URL: .../projects/[PROJECT]/global/images/[NAME]
                    img_project = parts[parts.index("projects") + 1]
                    img_name = parts[parts.index("images") + 1]
                    image_tasks.append(run_with_sem(gcloud_runner.run(
                        f"gcloud compute images describe {img_name} --project={img_project} --format='json(deprecated)'",
                        use_cache=True
                    )))
                except (ValueError, IndexError):
                    image_tasks.append(None)

            if image_tasks:
                # Filter out Nones for gather, but keep track of indices?
                # Actually simpler to just run valid tasks and map back.
                valid_tasks = [t for t in image_tasks if t]
                image_results = await asyncio.gather(*valid_tasks, return_exceptions=True)
                
                # Build cache map
                res_idx = 0
                for i, task in enumerate(image_tasks):
                    if task:
                        res = image_results[res_idx]
                        res_idx += 1
                        if isinstance(res, dict):
                            url_to_status[sorted_urls[i]] = res.get("deprecated")
            
            # 5. Correlate back to findings
            for i, (inst_name, zone) in enumerate(instance_map):
                img_url = source_images[i]
                if not img_url:
                    continue
                
                dep = url_to_status.get(img_url)
                if dep and dep.get("state") in ("DEPRECATED", "OBSOLETE", "DELETED"):
                    state = dep.get("state")
                    replacement = dep.get("replacement", "").split("/")[-1] or "No replacement specified"
                    
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"instances/{inst_name}", project_id=project_id,
                        resource_link=self.console_link("gce_instance", project_id, name=inst_name, zone=zone),
                        current_state=f"Boot image is {state}. Recommended replacement: {replacement}",
                        recommended_state="Re-image the instance or migrate to a supported OS version",
                        fix_command="", 
                        references=self.references,
                    ))

        except Exception as e:
            logger.error("GCE-011 failed: %s", e)
        return findings



class GCEDeletionProtection(BaseCheck):
    id = "GCE-012"
    title = "Deletion protection not enabled"
    description = "Deletion protection prevents accidental instance deletion."
    severity = Severity.LOW
    category = Category.RELIABILITY
    service = "GCE"
    service_category = ServiceCategory.GCE
    fix_command_template = "gcloud compute instances update {name} --deletion-protection --zone={zone} --project={project_id}"
    references = ["https://cloud.google.com/compute/docs/instances/preventing-accidental-vm-deletion"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await gcloud_runner.run(f"gcloud compute instances list --project={project_id} --format=json")
            if not isinstance(instances, list):
                return []
            for i in instances:
                name = i.get("name", "")
                zone = i.get("zone", "").split("/")[-1]
                if not i.get("deletionProtection", False):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"instances/{name}", project_id=project_id,
                        resource_link=self.console_link("gce_instance", project_id, name=name, zone=zone),
                        current_state="Deletion protection is not enabled",
                        recommended_state="Enable deletion protection for production instances",
                        fix_command=self.build_fix_command(name=name, zone=zone, project_id=project_id),
                        references=self.references,
                    ))
        except Exception as e:
            logger.error("GCE-012 failed: %s", e)
        return findings


class GCEPreemptibleInProd(BaseCheck):
    id = "GCE-013"
    title = "Spot/preemptible VM in use"
    description = "Spot VMs can be terminated at any time; review if running production workloads."
    severity = Severity.INFO
    category = Category.RELIABILITY
    service = "GCE"
    service_category = ServiceCategory.GCE
    references = ["https://cloud.google.com/compute/docs/instances/preemptible"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            instances = await gcloud_runner.run(f"gcloud compute instances list --project={project_id} --format=json")
            if not isinstance(instances, list):
                return []
            for i in instances:
                name = i.get("name", "")
                zone = i.get("zone", "").split("/")[-1]
                scheduling = i.get("scheduling", {})
                if scheduling.get("preemptible", False) or scheduling.get("provisioningModel") == "SPOT":
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"instances/{name}", project_id=project_id,
                        resource_link=self.console_link("gce_instance", project_id, name=name, zone=zone),
                        current_state="Instance is a Spot/Preemptible VM",
                        recommended_state="Ensure Spot VMs are not used for stateful production workloads",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.error("GCE-013 failed: %s", e)
        return findings


class GCESSHKeysInMetadata(BaseCheck):
    id = "GCE-015"
    title = "Project-wide SSH keys in metadata"
    description = "Project-wide SSH keys give access to all instances. Prefer OS Login or per-instance keys."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "GCE"
    service_category = ServiceCategory.GCE
    references = ["https://cloud.google.com/compute/docs/instances/adding-removing-ssh-keys"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"CIS_GCP_V3": ["4.3"], "ISO_27001": ["A.5.17", "A.8.5"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            project_meta = await gcloud_runner.run(f"gcloud compute project-info describe --project={project_id} --format=json")
            if not isinstance(project_meta, dict):
                return []
            items = project_meta.get("commonInstanceMetadata", {}).get("items", [])
            for item in items:
                if item.get("key") == "ssh-keys" and item.get("value", "").strip():
                    key_count = len(item["value"].strip().split("\n"))
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"projects/{project_id}", project_id=project_id,
                        current_state=f"{key_count} project-wide SSH key(s) in metadata",
                        recommended_state="Migrate to OS Login for centralized SSH key management",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.error("GCE-015 failed: %s", e)
        return findings


import sys as _sys  # noqa: E402
from backend.checks._module_helpers import apply_required_apis as _apply  # noqa: E402
_apply(_sys.modules[__name__], ["compute.googleapis.com"])
