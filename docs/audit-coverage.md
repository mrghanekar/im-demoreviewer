# Audit Coverage

What this tool can and cannot evidence for a comprehensive GCP security audit.

It exists so nobody discovers mid-engagement that a domain the scope promised
is one the scanner was never able to see. Read the "Not covered" section before
agreeing scope — those gaps are architectural, not backlog items.

The scanner runs 234 read-only checks across 28 service areas using the
`gcloud` identity it is deployed with. Everything it knows comes from GCP
control-plane APIs. It does not read data, install agents, or touch identity
providers.

---

## Coverage by requested domain

| Domain | Coverage | Where |
|---|---|---|
| 1. Organization & project inventory | Partial | Projects are enumerated via Cloud Asset Inventory; `posture` (5) covers folder hierarchy, org policies, asset feeds, and enabled-API sprawl; REG-005 flags Asset Inventory being off. There is no standalone asset-inventory export. |
| 2. IAM & access management | Strong | `iam` (14) — primitive roles, over-permissioned and unused service accounts, user-managed SA keys and their age, privilege-escalation chains via impersonation, shadow admin via key admin, external members, domain-restricted sharing, IAM Conditions, Data Access audit logs. **MFA/SSO posture is out of reach** — see below. |
| 3. Compute & workloads | Strong | `gce` (14), `gke` (23), `cloud_run` (8), `cloud_run_jobs` (3), `cloud_functions` (6), `app_engine` (5), `composer` (4) — 63 checks. |
| 4. Network security | Strong | `networking` (15) — firewall exposure with proper port-range parsing, default network, flow logs, DNSSEC, SSL policies, Cloud Armor, HTTPS redirect, certificate expiry, VPN redundancy. |
| 5. Storage & data security | Strong | `gcs` (12), `databases` (16), `data` (13), `spanner` (4), `firestore` (4), `alloydb` (5), `memorystore` (5) — 59 checks. **Content-level sensitive-data discovery is out of reach.** |
| 6. Secrets & key management | Strong | `secret_manager` (7) plus KMS rotation and destruction-delay checks in `security`. |
| 7. Logging & monitoring | Strong | `monitoring` (10) — sinks, retention, alert policies, notification channels, uptime checks, public sinks. **SIEM integration cannot be validated** — the tool sees that a sink exists, not that anything consumes it. |
| 8. Application & API security | Added | `api_security` (6) — unrestricted API keys, keys with no API targets, wildcard referrers, keys unrotated past 365 days, API Gateway configs with no auth, and public services with no gateway in front. `iap` (3) covers IAP enforcement. Rate limiting is only partly visible: API Gateway quotas, Cloud Armor rate rules and app-level limits are not uniformly inspectable. |
| 9. Container & supply chain | Added | `artifact_registry` (6) — public repositories, container scanning disabled, missing CMEK, no cleanup policy, images with critical CVEs, legacy Container Registry still in use. Plus Binary Authorization (`security`, `gke`) and `cloud_build` (5) — fork-PR triggers, default build SA, missing approval gates, substitution overrides, public worker pools. |
| 10. AI/ML services | Partial | `vertex_ai` (7) — notebook public IPs and default SAs, public model endpoints, public Vector Search, endpoint CMEK, training jobs on public networks. Gemini API usage and model-level governance are not covered. |
| 11. Security misconfigurations & exposure | Strong | This is the tool's core purpose; every category contributes. |
| 12. Vulnerability & patch management | Added | `patch_management` (5) — OS Config API off, VMs without the agent, no patch deployment schedule, VMs with outstanding CVEs from VM Manager vulnerability reports, one-shot-only deployments. Deprecated OS images (GCE-011) and runtimes (FN-003, AE-001/005, GKE-021, CMP-003) are covered. **Full CVE enumeration is out of reach.** |
| 13. Compliance & governance | Added | Every check is tagged with the controls it is evidence for — CIS GCP Foundation v3.0, ISO/IEC 27001:2022 Annex A, CERT-In Directions 2022, DPDP Act 2023. `compliance` (6) adds CERT-In's 180-day log retention and bucket-lock requirements, DPDP data-residency checks for log buckets and resources, and the SECURITY essential-contact requirement. Reports and `GET /scans/{id}/compliance` regroup findings by control. **See the honesty note below.** |
| 14. Incident readiness | Partial | Alerting, notification channels, SCC enablement, essential contacts, Access Transparency. **The process behind them cannot be assessed.** |
| 15. Backup, DR & resilience | Strong | Automated backups, PITR, HA configuration, geo-redundancy, deletion protection, backup schedules and GKE Backup across the database and storage categories. |

---

## What the compliance mapping does and does not claim

A control marked **PASS** means the technical configuration observable from
the GCP APIs is correct. It is not a statement that the organisation satisfies
the control. ISO 27001 and CERT-In in particular have substantial process
requirements — documented policy, management review, incident drills, evidence
of periodic access review — that no configuration scanner can observe. Each
framework carries this caveat into the rendered report.

Status derivation is deliberately conservative:

- **failed** — at least one mapped check produced findings.
- **partial** — nothing failed, but some evidence could not be gathered.
- **not_assessed** — nothing under this control could be evaluated.
- **passed** — every mapped check ran and produced no findings.

A control whose checks hit a permission error reports `not_assessed`, never
`passed`. An auditor reading PASS against a control the scanner got a 403 on is
worse than no report at all.

48 checks carry no mapping. Those are cost and performance recommendations
that do not support a security control; padding them onto one would inflate
the evidence count without adding evidence.

---

## Not covered — bring another instrument

These are not gaps in the check catalog. They are outside what a read-only
`gcloud` identity querying control-plane APIs can observe, and no amount of
work on this tool will close them.

**MFA and SSO posture; inactive human users.** The scanner authenticates as a
service account against Cloud Resource Manager and friends. Enrolment state,
2SV enforcement, SSO configuration and human-user last-login live in Cloud
Identity / Workspace, behind the Admin SDK and a different authorisation
scope. Use the Admin SDK Reports API or the Cloud Identity console export.

**CVE-level OS and package vulnerability enumeration.** The tool checks that
VM Manager is enabled and surfaces the vulnerability reports it produces
(PATCH-004), and it reports critical CVE counts that Artifact Registry's own
scanner has already found (AR-005). It cannot itself enumerate packages inside
a running VM or a container image. Use Security Command Center Premium, or an
agent-based scanner.

**Sensitive-data discovery and classification.** SEC-008 checks that Cloud DLP
is configured. It does not scan bucket or table contents, so it cannot tell
you where personal data actually lives — which matters for DPDP scoping. Use
Cloud DLP / Sensitive Data Protection with its own discovery scan.

**SIEM integration validation.** The tool sees that a log sink exists and where
it points. Whether anything is ingesting, parsing and alerting on that stream
is a property of the destination system.

**Incident-response process, BCP maturity, tabletop evidence.** CERT-In's
six-hour reporting obligation, the existence of a runbook, and whether drills
happen are process assessments. The tool can confirm a SECURITY essential
contact is registered (REG-007); it cannot confirm anyone is behind it.

**Application-layer testing.** No SAST, DAST, dependency scanning, or
penetration testing. SEC-007 checks that Web Security Scanner is enabled;
running it is a separate activity.

---

## Running an audit scan

Scan at organization scope with every category selected. Then read the
compliance section of the exported report, or:

```bash
curl -s "$BASE/api/v1/scans/$SCAN_ID/compliance" | jq '.frameworks[] | {key, totals}'
```

For an Indian engagement, set the residency allow-list before scanning so
REG-004 is active — it reports nothing until an operator opts in, rather than
guessing a jurisdiction:

```
DR_DATA_RESIDENCY_ALLOWED_REGIONS='["asia-south1","asia-south2"]'
```

Check `unmapped_checks` in the compliance response and the errored/skipped
counts in the scan summary. A large errored count usually means the scanner
identity is missing a role, and those checks report `not_assessed` rather than
quietly passing.
