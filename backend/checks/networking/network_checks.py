"""Networking checks for VPC, firewall, DNS, and load balancers.

Checks: NET-001 through NET-013
"""

import logging
from typing import Any, ClassVar

from backend.checks.base import BaseCheck
from backend.core.models import Category, CheckResult, Severity, ServiceCategory

logger = logging.getLogger(__name__)


def port_list_covers(ports: list[str], target: int) -> bool:
    """Whether a firewall rule's port list exposes ``target``.

    gcloud returns entries as single ports ("22") or ranges ("20-1000"), and an
    empty list means every port. Substring matching missed ranges entirely, so
    a rule allowing tcp:1-65535 from 0.0.0.0/0 looked compliant.
    """
    if not ports:
        return True
    for entry in ports:
        spec = str(entry).strip()
        if not spec:
            continue
        if "-" in spec:
            low, _, high = spec.partition("-")
            try:
                if int(low) <= target <= int(high):
                    return True
            except ValueError:
                logger.debug("Unparseable firewall port range: %r", spec)
            continue
        try:
            if int(spec) == target:
                return True
        except ValueError:
            logger.debug("Unparseable firewall port: %r", spec)
    return False


def port_list_is_unrestricted(ports: list[str]) -> bool:
    """Whether the port list effectively covers the entire port space."""
    if not ports:
        return True
    for entry in ports:
        spec = str(entry).strip()
        if "-" not in spec:
            continue
        low, _, high = spec.partition("-")
        try:
            if int(low) <= 1 and int(high) >= 65535:
                return True
        except ValueError:
            continue
    return False


class OpenFirewallSSH(BaseCheck):
    id = "NET-001"
    title = "Firewall rule allows SSH (22) from 0.0.0.0/0"
    description = "SSH open to the entire internet is a critical security risk."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    service = "Networking"
    service_category = ServiceCategory.NETWORKING
    gcloud_command = "gcloud compute firewall-rules list --project={project_id} --format=json"
    fix_command_template = "gcloud compute firewall-rules update {name} --source-ranges=RESTRICTED_CIDR --project={project_id}"
    references = ["https://cloud.google.com/vpc/docs/firewalls"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"CIS_GCP_V3": ["3.6"], "ISO_27001": ["A.8.20"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            rules = await gcloud_runner.run(f"gcloud compute firewall-rules list --project={project_id} --format=json")
            if not isinstance(rules, list):
                return []
            for r in rules:
                name = r.get("name", "")
                if r.get("direction") != "INGRESS" or r.get("disabled", False):
                    continue
                sources = r.get("sourceRanges", [])
                if "0.0.0.0/0" not in sources:
                    continue
                for allowed in r.get("allowed", []):
                    ports = allowed.get("ports", [])
                    proto = allowed.get("IPProtocol", "")
                    if proto in ("tcp", "all") and port_list_covers(ports, 22):
                        findings.append(CheckResult(
                            check_id=self.id, title=self.title, description=self.description,
                            severity=self.severity, category=self.category, service=self.service,
                            resource_name=f"firewall-rules/{name}", project_id=project_id,
                            resource_link=self.console_link("firewall_rule", project_id, name=name),
                            current_state=f"Rule '{name}' allows TCP/22 from 0.0.0.0/0",
                            recommended_state="Restrict source to specific CIDR ranges or use IAP",
                            fix_command=self.build_fix_command(name=name, project_id=project_id),
                            references=self.references,
                        ))
        except Exception as e:
            logger.error("NET-001 failed: %s", e)
        return findings


class OpenFirewallRDP(BaseCheck):
    id = "NET-002"
    title = "Firewall rule allows RDP (3389) from 0.0.0.0/0"
    description = "RDP open to the internet exposes Windows instances to brute-force attacks."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    service = "Networking"
    service_category = ServiceCategory.NETWORKING
    fix_command_template = "gcloud compute firewall-rules update {name} --source-ranges=RESTRICTED_CIDR --project={project_id}"
    references = ["https://cloud.google.com/vpc/docs/firewalls"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"CIS_GCP_V3": ["3.7"], "ISO_27001": ["A.8.20"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            rules = await gcloud_runner.run(f"gcloud compute firewall-rules list --project={project_id} --format=json")
            if not isinstance(rules, list):
                return []
            for r in rules:
                name = r.get("name", "")
                if r.get("direction") != "INGRESS" or r.get("disabled", False):
                    continue
                sources = r.get("sourceRanges", [])
                if "0.0.0.0/0" not in sources:
                    continue
                for allowed in r.get("allowed", []):
                    ports = allowed.get("ports", [])
                    proto = allowed.get("IPProtocol", "")
                    if proto in ("tcp", "all") and port_list_covers(ports, 3389):
                        findings.append(CheckResult(
                            check_id=self.id, title=self.title, description=self.description,
                            severity=self.severity, category=self.category, service=self.service,
                            resource_name=f"firewall-rules/{name}", project_id=project_id,
                            resource_link=self.console_link("firewall_rule", project_id, name=name),
                            current_state=f"Rule '{name}' allows TCP/3389 from 0.0.0.0/0",
                            recommended_state="Restrict source to specific CIDR ranges or use IAP",
                            fix_command=self.build_fix_command(name=name, project_id=project_id),
                            references=self.references,
                        ))
        except Exception as e:
            logger.error("NET-002 failed: %s", e)
        return findings


class OverlyPermissiveFirewall(BaseCheck):
    id = "NET-003"
    title = "Firewall rule allows all ports from 0.0.0.0/0"
    description = "Rules allowing all traffic from the internet defeat the purpose of firewalling."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    service = "Networking"
    service_category = ServiceCategory.NETWORKING
    references = ["https://cloud.google.com/vpc/docs/firewalls#best_practices_for_firewall_rules"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.20"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            rules = await gcloud_runner.run(f"gcloud compute firewall-rules list --project={project_id} --format=json")
            if not isinstance(rules, list):
                return []
            for r in rules:
                name = r.get("name", "")
                if r.get("direction") != "INGRESS" or r.get("disabled", False):
                    continue
                sources = r.get("sourceRanges", [])
                if "0.0.0.0/0" not in sources:
                    continue
                for allowed in r.get("allowed", []):
                    proto = allowed.get("IPProtocol", "")
                    ports = allowed.get("ports", [])
                    if proto == "all" or (
                        proto in ("tcp", "udp") and port_list_is_unrestricted(ports)
                    ):
                        findings.append(CheckResult(
                            check_id=self.id, title=self.title, description=self.description,
                            severity=self.severity, category=self.category, service=self.service,
                            resource_name=f"firewall-rules/{name}", project_id=project_id,
                            resource_link=self.console_link("firewall_rule", project_id, name=name),
                            current_state=f"Rule '{name}' allows ALL traffic from 0.0.0.0/0",
                            recommended_state="Restrict to specific ports and source ranges",
                            fix_command="", references=self.references,
                        ))
        except Exception as e:
            logger.error("NET-003 failed: %s", e)
        return findings


class DefaultNetworkExists(BaseCheck):
    id = "NET-004"
    title = "Default VPC network exists"
    description = "The default network has overly permissive firewall rules. Delete and create custom VPCs."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Networking"
    service_category = ServiceCategory.NETWORKING
    fix_command_template = "gcloud compute networks delete default --project={project_id} --quiet"
    references = ["https://cloud.google.com/vpc/docs/vpc#default-network"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"CIS_GCP_V3": ["3.1"], "ISO_27001": ["A.8.20", "A.8.22"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            networks = await gcloud_runner.run(f"gcloud compute networks list --project={project_id} --format=json")
            if not isinstance(networks, list):
                return []
            for n in networks:
                if n.get("name") == "default":
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name="networks/default", project_id=project_id,
                        resource_link=self.console_link("vpc_network", project_id, name="default"),
                        current_state="Default VPC network exists with permissive rules",
                        recommended_state="Delete default network and create custom VPCs",
                        fix_command=self.build_fix_command(project_id=project_id),
                        references=self.references,
                    ))
        except Exception as e:
            logger.error("NET-004 failed: %s", e)
        return findings


class FlowLogsDisabled(BaseCheck):
    id = "NET-005"
    title = "VPC Flow Logs not enabled on subnet"
    description = "Flow logs capture network traffic metadata for monitoring and forensics."
    severity = Severity.MEDIUM
    category = Category.OPERATIONS
    service = "Networking"
    service_category = ServiceCategory.NETWORKING
    fix_command_template = "gcloud compute networks subnets update {name} --enable-flow-logs --region={region} --project={project_id}"
    references = ["https://cloud.google.com/vpc/docs/using-flow-logs"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"CIS_GCP_V3": ["3.8"], "ISO_27001": ["A.8.15", "A.8.16"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            subnets = await gcloud_runner.run(f"gcloud compute networks subnets list --project={project_id} --format=json")
            if not isinstance(subnets, list):
                return []
            for s in subnets:
                name = s.get("name", "")
                region = s.get("region", "").split("/")[-1]
                # A subnet that had flow logs toggled off still carries a
                # logConfig block ({"enable": false}), which is truthy — so
                # testing the dict's presence marked it compliant.
                log_config = s.get("logConfig") or {}
                flow_logs_on = bool(s.get("enableFlowLogs", False)) or bool(
                    log_config.get("enable", False)
                )
                if not flow_logs_on:
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"subnets/{name} ({region})", project_id=project_id,
                        current_state=f"Flow logs disabled on subnet '{name}' in {region}",
                        recommended_state="Enable VPC flow logs for network monitoring",
                        fix_command=self.build_fix_command(name=name, region=region, project_id=project_id),
                        references=self.references,
                    ))
        except Exception as e:
            logger.error("NET-005 failed: %s", e)
        return findings


class PrivateGoogleAccess(BaseCheck):
    id = "NET-006"
    title = "Private Google Access not enabled on subnet"
    description = "Without Private Google Access, VMs without external IPs cannot reach Google APIs."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "Networking"
    service_category = ServiceCategory.NETWORKING
    fix_command_template = "gcloud compute networks subnets update {name} --enable-private-ip-google-access --region={region} --project={project_id}"
    references = ["https://cloud.google.com/vpc/docs/configure-private-google-access"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.20"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            subnets = await gcloud_runner.run(f"gcloud compute networks subnets list --project={project_id} --format=json")
            if not isinstance(subnets, list):
                return []
            for s in subnets:
                name = s.get("name", "")
                region = s.get("region", "").split("/")[-1]
                if not s.get("privateIpGoogleAccess", False):
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"subnets/{name} ({region})", project_id=project_id,
                        current_state=f"Private Google Access disabled on '{name}'",
                        recommended_state="Enable Private Google Access for internal API connectivity",
                        fix_command=self.build_fix_command(name=name, region=region, project_id=project_id),
                        references=self.references,
                    ))
        except Exception as e:
            logger.error("NET-006 failed: %s", e)
        return findings


class CloudNATNotConfigured(BaseCheck):
    id = "NET-007"
    title = "Cloud NAT not configured for VPC"
    description = "Without Cloud NAT, instances without external IPs cannot reach the internet for updates."
    severity = Severity.LOW
    category = Category.OPERATIONS
    service = "Networking"
    service_category = ServiceCategory.NETWORKING
    references = ["https://cloud.google.com/nat/docs/overview"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            routers = await gcloud_runner.run(f"gcloud compute routers list --project={project_id} --format=json")
            if not isinstance(routers, list):
                return []
            has_nat = False
            for r in routers:
                nats = r.get("nats", [])
                if nats:
                    has_nat = True
                    break
            if not has_nat and len(routers) >= 0:
                # Check if there are instances without external IPs that might need NAT
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"projects/{project_id}", project_id=project_id,
                    current_state="No Cloud NAT gateways configured",
                    recommended_state="Configure Cloud NAT for private instances needing internet access",
                    fix_command="", references=self.references,
                ))
        except Exception as e:
            logger.error("NET-007 failed: %s", e)
        return findings


class DNSSECNotEnabled(BaseCheck):
    id = "NET-008"
    title = "DNSSEC not enabled on managed DNS zone"
    description = "DNSSEC authenticates DNS responses to prevent spoofing and cache poisoning."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "Networking"
    service_category = ServiceCategory.NETWORKING
    references = ["https://cloud.google.com/dns/docs/dnssec"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"CIS_GCP_V3": ["3.3"], "ISO_27001": ["A.8.20", "A.8.21"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            zones = await gcloud_runner.run(f"gcloud dns managed-zones list --project={project_id} --format=json")
            if not isinstance(zones, list):
                return []
            for z in zones:
                name = z.get("name", "")
                dns_name = z.get("dnsName", "")
                visibility = z.get("visibility", "")
                if visibility == "private":
                    continue  # DNSSEC doesn't apply to private zones
                dnssec_config = z.get("dnssecConfig", {})
                if dnssec_config.get("state") != "on":
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"dns/{name} ({dns_name})", project_id=project_id,
                        current_state="DNSSEC is not enabled",
                        recommended_state="Enable DNSSEC for public DNS zones",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.debug("NET-008: %s", e)
        return findings


class SSLPolicyWeak(BaseCheck):
    id = "NET-009"
    title = "SSL policy allows weak TLS version or cipher profile"
    description = (
        "SSL policies should enforce TLS 1.2+ and use a MODERN or RESTRICTED profile to prevent "
        "downgrade and weak-cipher attacks. COMPATIBLE / CUSTOM profiles may permit weak ciphers."
    )
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Networking"
    service_category = ServiceCategory.NETWORKING
    references = ["https://cloud.google.com/load-balancing/docs/ssl-policies-concepts"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"CIS_GCP_V3": ["3.9"], "ISO_27001": ["A.8.24"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            policies = await gcloud_runner.run(f"gcloud compute ssl-policies list --project={project_id} --format=json")
            if not isinstance(policies, list):
                return []
            for p in policies:
                name = p.get("name", "")
                min_tls = p.get("minTlsVersion", "")
                profile = p.get("profile", "")
                weak_tls = min_tls in ("TLS_1_0", "TLS_1_1")
                weak_profile = profile in ("COMPATIBLE", "CUSTOM")
                if not (weak_tls or weak_profile):
                    continue
                reasons = []
                if weak_tls:
                    reasons.append(f"minTlsVersion={min_tls}")
                if weak_profile:
                    reasons.append(f"profile={profile}")
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"ssl-policies/{name}", project_id=project_id,
                    current_state="; ".join(reasons),
                    recommended_state="Use profile=MODERN or RESTRICTED with minTlsVersion=TLS_1_2 (or higher)",
                    fix_command="", references=self.references,
                ))
        except Exception as e:
            logger.debug("NET-009: %s", e)
        return findings


class NoCloudArmor(BaseCheck):
    id = "NET-010"
    title = "No Cloud Armor security policies defined"
    description = "Cloud Armor provides DDoS protection and WAF for HTTP(S) load balancers."
    severity = Severity.MEDIUM
    category = Category.SECURITY
    service = "Networking"
    service_category = ServiceCategory.NETWORKING
    references = ["https://cloud.google.com/armor/docs/cloud-armor-overview"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.20"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            policies = await gcloud_runner.run(f"gcloud compute security-policies list --project={project_id} --format=json")
            if not isinstance(policies, list) or len(policies) == 0:
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"projects/{project_id}", project_id=project_id,
                    current_state="No Cloud Armor security policies exist",
                    recommended_state="Create security policies for HTTP(S) load balancers",
                    fix_command="", references=self.references,
                ))
        except Exception as e:
            logger.debug("NET-010: %s", e)
        return findings


class LegacyVPNGateway(BaseCheck):
    id = "NET-011"
    title = "Classic VPN gateway in use"
    description = "Classic VPN supports only static routing. Migrate to HA VPN for SLA-backed connectivity."
    severity = Severity.MEDIUM
    category = Category.RELIABILITY
    service = "Networking"
    service_category = ServiceCategory.NETWORKING
    references = ["https://cloud.google.com/network-connectivity/docs/vpn/concepts/overview"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.14"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            gateways = await gcloud_runner.run(f"gcloud compute target-vpn-gateways list --project={project_id} --format=json")
            if isinstance(gateways, list):
                for gw in gateways:
                    name = gw.get("name", "")
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"vpn-gateways/{name}", project_id=project_id,
                        current_state=f"Classic VPN gateway '{name}' (no SLA)",
                        recommended_state="Migrate to HA VPN for 99.99% SLA",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.debug("NET-011: %s", e)
        return findings


class HTTPSRedirectMissing(BaseCheck):
    id = "NET-012"
    title = "HTTPS redirect not configured on HTTP load balancer"
    description = "HTTP traffic should be redirected to HTTPS to ensure encryption in transit."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Networking"
    service_category = ServiceCategory.NETWORKING
    references = ["https://cloud.google.com/load-balancing/docs/https/setting-up-http-https-redirect"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.24"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            url_maps = await gcloud_runner.run(f"gcloud compute url-maps list --project={project_id} --format=json")
            if not isinstance(url_maps, list):
                return []
            for um in url_maps:
                name = um.get("name", "")
                # Check for HTTP proxies without redirect
                # This is a simplified check
                if "http" in name.lower() and "https" not in name.lower():
                    findings.append(CheckResult(
                        check_id=self.id, title=self.title, description=self.description,
                        severity=self.severity, category=self.category, service=self.service,
                        resource_name=f"url-maps/{name}", project_id=project_id,
                        current_state=f"URL map '{name}' may serve HTTP without redirect",
                        recommended_state="Configure HTTP to HTTPS redirect",
                        fix_command="", references=self.references,
                    ))
        except Exception as e:
            logger.debug("NET-012: %s", e)
        return findings


# NET-013 (ExternalIPStatic) removed — BIL-003 (UnusedStaticIPs in
# backend/checks/billing/billing_checks.py) is the canonical check; it lives in
# the cost category where unused-IP findings are more discoverable.


class IdleLoadBalancer(BaseCheck):
    id = "NET-014"
    title = "Load Balancer backend service has no backends"
    description = "A backend service with no instance groups or NEGs attached is not serving traffic."
    severity = Severity.LOW
    category = Category.COST
    service = "Networking"
    service_category = ServiceCategory.NETWORKING
    references = ["https://cloud.google.com/load-balancing/docs/backend-service"]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            # Check global backend services
            services = await gcloud_runner.run(f"gcloud compute backend-services list --project={project_id} --format=json")
            if isinstance(services, list):
                for s in services:
                    name = s.get("name", "")
                    backends = s.get("backends", [])
                    # Some internal services might be auto-managed, but generally user-created ones should have backends
                    if not backends:
                        findings.append(CheckResult(
                            check_id=self.id, title=self.title, description=self.description,
                            severity=self.severity, category=self.category, service=self.service,
                            resource_name=f"backend-services/{name}", project_id=project_id,
                            current_state="Backend service has 0 backends configured",
                            recommended_state="Add backends or delete the unused load balancer components",
                            fix_command="", references=self.references,
                        ))
        except Exception as e:
            logger.debug("NET-014: %s", e)
        return findings


# ---------------------------------------------------------------------------
# Additional Networking checks (2026-05 catalog expansion)
# ---------------------------------------------------------------------------


class LBNoCloudArmor(BaseCheck):
    """NET-015: External backend services without Cloud Armor."""
    id = "NET-015"
    title = "External backend service has no Cloud Armor policy"
    description = "Internet-facing backend services should be protected by a Cloud Armor security policy."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "Networking"
    service_category = ServiceCategory.NETWORKING
    references = ["https://cloud.google.com/armor/docs/security-policy-overview"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.20"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        findings: list[CheckResult] = []
        try:
            backends = await gcloud_runner.run(
                f"gcloud compute backend-services list --project={project_id} --format=json"
            )
        except Exception:
            return findings
        for b in (backends if isinstance(backends, list) else []):
            scheme = b.get("loadBalancingScheme", "")
            if scheme not in ("EXTERNAL", "EXTERNAL_MANAGED"):
                continue
            if not b.get("securityPolicy"):
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"backend-services/{b.get('name', '')}", project_id=project_id,
                    current_state="External backend service has no securityPolicy attached",
                    recommended_state="Attach a Cloud Armor security policy",
                    fix_command="", references=self.references,
                ))
        return findings


class CertificateNearExpiry(BaseCheck):
    """NET-017: SSL certificates expiring within 30 days."""
    id = "NET-017"
    title = "SSL certificate expires within 30 days"
    description = "Renew certificates before expiry to avoid outage. Use managed certs for auto-renewal."
    severity = Severity.HIGH
    category = Category.OPERATIONS
    service = "Networking"
    service_category = ServiceCategory.NETWORKING
    references = ["https://cloud.google.com/load-balancing/docs/ssl-certificates/google-managed-certs"]
    compliance_refs: ClassVar[dict[str, list[str]]] = {"ISO_27001": ["A.8.24"]}

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        from datetime import datetime, timezone, timedelta
        findings: list[CheckResult] = []
        try:
            certs = await gcloud_runner.run(
                f"gcloud compute ssl-certificates list --project={project_id} --format=json"
            )
        except Exception:
            return findings
        threshold = datetime.now(timezone.utc) + timedelta(days=30)
        for c in (certs if isinstance(certs, list) else []):
            name = c.get("name", "")
            expire = c.get("expireTime", "")
            if not expire:
                continue
            try:
                exp_dt = datetime.fromisoformat(expire.replace("Z", "+00:00"))
            except ValueError:
                continue
            if exp_dt < threshold:
                days_left = (exp_dt - datetime.now(timezone.utc)).days
                findings.append(CheckResult(
                    check_id=self.id, title=self.title, description=self.description,
                    severity=self.severity, category=self.category, service=self.service,
                    resource_name=f"ssl-certificates/{name}", project_id=project_id,
                    current_state=f"Cert expires in {days_left} days ({expire[:10]})",
                    recommended_state="Renew or replace with a managed certificate",
                    fix_command="", references=self.references,
                ))
        return findings


import sys as _sys  # noqa: E402
from backend.checks._module_helpers import apply_required_apis as _apply  # noqa: E402
_apply(_sys.modules[__name__], ["compute.googleapis.com"])

