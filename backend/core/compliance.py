"""Compliance frameworks the check catalog maps onto.

A scan produces findings organised by service — "17 networking findings". An
auditor needs the opposite view: "what is your evidence for ISO 27001 A.8.20,
and what is failing under it?" This module defines the frameworks and the
control titles so a report can be grouped by control instead of by service.

Framework keys used in ``BaseCheck.compliance_refs`` must appear in
:data:`FRAMEWORKS`; a meta-test enforces that so a typo'd key can't silently
drop checks out of the compliance report.

Scope note for the reader of a generated report: a passing check is evidence
that one *technical control* is configured, not that the organisation is
certified. ISO 27001 and CERT-In in particular have substantial process
requirements — documented policy, management review, incident drills — that no
configuration scanner can observe. See :data:`FRAMEWORK_CAVEATS`.
"""

from typing import Final

CIS_GCP_V3: Final = "CIS_GCP_V3"
ISO_27001: Final = "ISO_27001"
CERT_IN: Final = "CERT_IN"
DPDP: Final = "DPDP"

FRAMEWORKS: Final[dict[str, str]] = {
    CIS_GCP_V3: "CIS Google Cloud Platform Foundation Benchmark v3.0",
    ISO_27001: "ISO/IEC 27001:2022 Annex A",
    CERT_IN: "CERT-In Cyber Security Directions (2022)",
    DPDP: "Digital Personal Data Protection Act, 2023 (India)",
}

FRAMEWORK_CAVEATS: Final[dict[str, str]] = {
    CIS_GCP_V3: (
        "Covers the automatable subset of the benchmark. Manual-assessment "
        "recommendations (organisational policy, key-rotation procedure "
        "evidence) are out of scope for a configuration scan."
    ),
    ISO_27001: (
        "Maps technical Annex A controls only. Clauses 4-10 (context, "
        "leadership, planning, management review) and the process-based "
        "controls in A.5 are assessed by an auditor, not by this tool."
    ),
    CERT_IN: (
        "Covers the log-retention and time-synchronisation directions that are "
        "observable in GCP configuration. The 6-hour incident-reporting "
        "obligation is a process control this tool cannot verify; for the "
        "designated point-of-contact direction the tool can only confirm that "
        "a security contact is registered in GCP, not that an incident-response "
        "process exists behind it."
    ),
    DPDP: (
        "Covers technical safeguards (encryption, access control, retention, "
        "data residency) that support Section 8(5) 'reasonable security "
        "safeguards'. Consent management, notice, grievance redressal and "
        "Data Fiduciary obligations are outside a configuration scan."
    ),
}

# Human-readable titles for the control IDs the catalog references. Only the
# controls actually used by a check need an entry; the report falls back to the
# bare ID for anything missing.
CONTROL_TITLES: Final[dict[str, dict[str, str]]] = {
    ISO_27001: {
        "A.5.3": "Segregation of duties",
        "A.5.9": "Inventory of information and other associated assets",
        "A.5.15": "Access control",
        "A.5.16": "Identity management",
        "A.5.17": "Authentication information",
        "A.5.18": "Access rights",
        "A.5.23": "Information security for use of cloud services",
        "A.5.29": "Information security during disruption",
        "A.5.30": "ICT readiness for business continuity",
        "A.5.33": "Protection of records",
        "A.8.2": "Privileged access rights",
        "A.8.3": "Information access restriction",
        "A.8.5": "Secure authentication",
        "A.8.6": "Capacity management",
        "A.8.7": "Protection against malware",
        "A.8.8": "Management of technical vulnerabilities",
        "A.8.9": "Configuration management",
        "A.8.10": "Information deletion",
        "A.8.12": "Data leakage prevention",
        "A.8.13": "Information backup",
        "A.8.14": "Redundancy of information processing facilities",
        "A.8.15": "Logging",
        "A.8.16": "Monitoring activities",
        "A.8.17": "Clock synchronisation",
        "A.8.20": "Networks security",
        "A.8.21": "Security of network services",
        "A.8.22": "Segregation of networks",
        "A.8.23": "Web filtering",
        "A.8.24": "Use of cryptography",
        "A.8.25": "Secure development life cycle",
        "A.8.26": "Application security requirements",
        "A.8.28": "Secure coding",
        "A.8.31": "Separation of development, test and production environments",
        "A.8.32": "Change management",
    },
    CERT_IN: {
        "III": "Designation of a Point of Contact to interface with CERT-In",
        "IV": "Synchronisation of ICT system clocks to NIC/NPL NTP",
        "V": "Mandatory reporting of cyber incidents within 6 hours",
        "VI": "Maintenance of ICT system logs within Indian jurisdiction for 180 days",
    },
    DPDP: {
        "8(5)": "Reasonable security safeguards to prevent personal data breach",
        "8(7)": "Erasure of personal data on withdrawal of consent or purpose completion",
        "8(8)": "Publication of Data Protection Officer / contact details",
        "16": "Restriction on transfer of personal data outside India",
    },
}


def control_title(framework: str, control_id: str) -> str:
    """Human-readable title for a control, or the bare ID if unmapped."""
    return CONTROL_TITLES.get(framework, {}).get(control_id, control_id)


def framework_title(framework: str) -> str:
    """Human-readable name of a framework, or the bare key if unknown."""
    return FRAMEWORKS.get(framework, framework)
