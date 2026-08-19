# Democratized Reviewer — Product Requirements Document

> **Version**: 1.0  
> **Last Updated**: 2026-02-07  
> **Status**: Draft  
> **Owner**: @aghanekar

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [Goals & Non-Goals](#3-goals--non-goals)
4. [User Personas](#4-user-personas)
5. [User Flows](#5-user-flows)
6. [Architecture Overview](#6-architecture-overview)
7. [Service Check Modules](#7-service-check-modules)
8. [Authentication & Authorization](#8-authentication--authorization)
9. [UI/UX Requirements](#9-uiux-requirements)
10. [Deployment & Distribution](#10-deployment--distribution)
11. [Data Persistence & Export](#11-data-persistence--export)
12. [Compliance & Frameworks](#12-compliance--frameworks)
13. [Non-Functional Requirements](#13-non-functional-requirements)
14. [Roadmap & Milestones](#14-roadmap--milestones)
15. [Appendix](#appendix)

---

## 1. Executive Summary

**Democratized Reviewer** is a self-hosted Google Cloud audit and best-practices review tool. It enables GCP administrators to scan their cloud environments (at org or project level) against a comprehensive set of checks covering security, reliability, performance, cost optimization, and operational excellence.

The tool runs as a **Cloud Run** service with a modern React-based dashboard. Administrators clone the repo, execute a setup script in **Google Cloud Shell**, and get a fully deployed review environment in minutes. All checks operate using **viewer-only IAM roles** — zero write access, zero risk.

**Key differentiators:**
- **Zero-install**: Clone → Cloud Shell → Deploy → Review
- **Read-only**: Viewer IAM roles only — safe to run in production
- **gcloud-first**: Prefers `gcloud` CLI output for transparency; falls back to API
- **Actionable**: Every finding includes severity, explanation, and copy-paste `gcloud` fix commands
- **Broad coverage**: 10+ service categories, 200+ checks at launch
- **Open & extensible**: Plugin-based check architecture for community contributions

---

## 2. Problem Statement

### The Pain

Google Cloud customers — from startups to enterprises — struggle to:

1. **Know what they don't know**: Misconfigurations silently accumulate across projects, folders, and org hierarchies.
2. **Keep up with best practices**: GCP evolves rapidly; yesterday's good config is today's vulnerability.
3. **Audit at scale**: Manually reviewing resources across 10, 50, or 500 projects is impractical.
4. **Get actionable advice**: Existing tools flag issues but don't tell you *exactly* how to fix them.
5. **Run safely**: Many audit tools require excessive permissions, creating political and security friction.

### Why Now

- Google Cloud's Security Command Center (SCC) is powerful but requires Premium tier ($$$).
- Open-source alternatives (ScoutSuite, Prowler for GCP) are CLI-only with limited GCP depth.
- Cloud admins need a **visual**, **safe**, **comprehensive** tool they can deploy in minutes.

---

## 3. Goals & Non-Goals

### Goals (v1)

| # | Goal | Success Metric |
|---|------|----------------|
| G1 | Scan a GCP project or org with viewer-only permissions | 100% of checks run with `roles/viewer` + specific read-only roles |
| G2 | Cover 10 service categories with 200+ checks | Check catalog documented and tested |
| G3 | Provide fix suggestions as copyable `gcloud` commands | Every finding includes ≥1 remediation command |
| G4 | Deploy via Cloud Shell in < 10 minutes | End-to-end setup script tested |
| G5 | Modern, responsive dashboard UI | Real-time scan progress, filterable results |
| G6 | Export results to GCS bucket | JSON + HTML report export |
| G7 | Custom best-practice categories | Security, Cost, Performance, Reliability, Operations |

### Goals (v2 — Future)

| # | Goal |
|---|------|
| G8 | CIS Google Cloud Benchmark mapping |
| G9 | SOC2 / PCI-DSS compliance mapping |
| G10 | Historical trend tracking (scan-over-scan comparison) |
| G11 | Scheduled recurring scans |
| G12 | Slack / email notifications |
| G13 | Terraform / IaC snippet generation for fixes |

### Non-Goals

- **Write operations**: The tool will NEVER modify resources. It is strictly read-only.
- **Auto-remediation**: v1 provides commands to copy, not one-click fixes.
- **Multi-cloud**: GCP only. No AWS/Azure support.
- **SaaS hosting**: This is a self-hosted tool, not a managed service.
- **Cost analysis**: We flag cost-related misconfigs (e.g., oversized instances) but don't build a full FinOps tool.

---

## 4. User Personas

### Persona 1: Cloud Admin (Primary)

- **Role**: GCP Project Admin / Org Admin
- **Context**: Manages 5–50 projects, responsible for security posture
- **Pain**: "I inherited this org and have no idea what's misconfigured"
- **Need**: Quick scan, clear findings, actionable fixes
- **Skill Level**: Comfortable with `gcloud`, Cloud Shell, basic IAM

### Persona 2: Security Engineer

- **Role**: SecOps / Compliance team member
- **Context**: Needs to audit GCP posture before compliance review
- **Pain**: "I need a report showing our security gaps for the audit"
- **Need**: Exportable reports, severity breakdown, compliance mapping
- **Skill Level**: Deep GCP knowledge, wants detailed findings

### Persona 3: Platform Team Lead

- **Role**: SRE / Platform Engineering lead
- **Context**: Maintains standards across many teams' projects
- **Pain**: "Teams keep creating public buckets and VMs with default SAs"
- **Need**: Org-level scanning, project comparison, trend tracking
- **Skill Level**: Expert, wants API access and automation

---

## 5. User Flows

### Flow 1: Initial Setup (Cloud Shell)

```
User clones repo
    → Opens Google Cloud Shell
    → Runs `./setup.sh`
    → Script prompts:
        1. "Deploy at ORG level or PROJECT level?" → user selects
        2. "Enter org ID / project ID"
        3. "Use existing service account or create new?"
            → Lists existing SAs with viewer roles
            → Or creates `democratized-reviewer-sa@<project>.iam.gserviceaccount.com`
        4. "Confirm deployment to Cloud Run in region X?"
    → Script:
        - Creates SA (if needed)
        - Grants viewer roles
        - Builds Docker image
        - Deploys to Cloud Run
        - Outputs URL
    → User opens Cloud Run URL
```

### Flow 2: Running a Scan (UI)

```
User opens dashboard
    → Landing page: "Welcome to Democratized Reviewer"
    → Step 1: Select scope
        - Org level (enter org ID) or Project level (enter project ID)
        - If org: optionally filter by folder / project list
    → Step 2: Confirm identity
        - Shows current SA and its roles
        - Validates permissions with a pre-flight check
    → Step 3: Select check categories
        - All categories (default)
        - Or pick specific: Security, GKE, GCE, Databases, etc.
    → Step 4: Run scan
        - Real-time progress bar per category
        - Live stream of findings as they come in
    → Step 5: Review results
        - Dashboard with severity breakdown (Critical/High/Medium/Low/Info)
        - Filter by category, severity, service, project
        - Each finding: description, impact, fix command, resource link
    → Step 6: Export
        - Download as JSON / HTML
        - Export to GCS bucket
```

### Flow 3: Reviewing a Finding

```
User clicks a finding
    → Expanded view shows:
        - Finding ID & title
        - Severity badge (Critical → Info)
        - Category (Security / Cost / Performance / Reliability / Operations)
        - Affected resource (with link to Cloud Console)
        - Current configuration (what's wrong)
        - Recommended configuration (what it should be)
        - Fix command (copyable gcloud command)
        - References (GCP docs, CIS benchmark ID if mapped)
```

---

## 6. Architecture Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Cloud Run Service                     │
│                                                          │
│  ┌──────────────┐     ┌──────────────────────────────┐  │
│  │   React SPA  │────▶│     FastAPI Backend           │  │
│  │  (Frontend)  │◀────│                               │  │
│  │              │     │  ┌─────────────────────────┐  │  │
│  │  - Dashboard │     │  │    Check Engine          │  │  │
│  │  - Wizard    │     │  │                          │  │  │
│  │  - Reports   │     │  │  ┌────┐ ┌────┐ ┌────┐  │  │  │
│  │  - Settings  │     │  │  │GKE │ │GCE │ │GCS │  │  │  │
│  └──────────────┘     │  │  └────┘ └────┘ └────┘  │  │  │
│                       │  │  ┌────┐ ┌────┐ ┌────┐  │  │  │
│                       │  │  │ DB │ │SEC │ │NET │  │  │  │
│                       │  │  └────┘ └────┘ └────┘  │  │  │
│                       │  │  ┌────┐ ┌────┐ ┌────┐  │  │  │
│                       │  │  │IAM │ │MON │ │BIL │  │  │  │
│                       │  │  └────┘ └────┘ └────┘  │  │  │
│                       │  └─────────────────────────┘  │  │
│                       │                               │  │
│                       │  ┌──────────────────────────┐ │  │
│                       │  │    gcloud CLI Wrapper    │ │  │
│                       │  └──────────────────────────┘ │  │
│                       └──────────────────────────────┘  │
└──────────────┬──────────────────────────┬───────────────┘
               │                          │
               ▼                          ▼
    ┌──────────────────┐      ┌──────────────────┐
    │   GCP Resources  │      │   GCS Bucket      │
    │   (read-only)    │      │   (report export) │
    └──────────────────┘      └──────────────────┘
```

### Tech Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| **Frontend** | React 18 + Vite + TypeScript | Fast dev, rich ecosystem, modern tooling |
| **UI Framework** | Tailwind CSS + shadcn/ui | Geeky, modern look with minimal effort |
| **Backend** | Python 3.12 + FastAPI | Best gcloud SDK support, async, fast |
| **GCP Interaction** | `gcloud` CLI (subprocess wrapper) | Transparency, standard output, no SDK bloat |
| **Task Queue** | FastAPI BackgroundTasks + asyncio | Lightweight, no external deps |
| **Container** | Docker (multi-stage build) | Frontend + Backend in single container |
| **Deployment** | Cloud Run (gen2) | Serverless, scales to zero, easy setup |
| **CI/CD** | GitLab CI (existing) + Cloud Build | Matches existing repo setup |
| **Export** | GCS + in-memory JSON | Session results + optional persistence |

### Directory Structure

```
democratized-reviewer/
├── setup.sh                        # Cloud Shell setup script
├── Dockerfile                      # Multi-stage build
├── docker-compose.yml              # Local development
├── README.md                       # User-facing documentation
├── PRD.md                          # This document
├── AGENTS.md                       # AI agent instructions
├── PLAN.md                         # Build plan
│
├── backend/
│   ├── main.py                     # FastAPI entrypoint
│   ├── requirements.txt            # Python dependencies
│   ├── config.py                   # App configuration
│   ├── api/
│   │   ├── __init__.py
│   │   ├── routes/
│   │   │   ├── scan.py             # Scan endpoints
│   │   │   ├── results.py          # Results endpoints
│   │   │   ├── export.py           # Export endpoints
│   │   │   ├── setup.py            # Setup/config endpoints
│   │   │   └── health.py           # Health check
│   │   └── middleware/
│   │       ├── auth.py             # Request auth
│   │       └── error_handler.py    # Global error handling
│   ├── core/
│   │   ├── __init__.py
│   │   ├── engine.py               # Check execution engine
│   │   ├── scanner.py              # Orchestrates scans
│   │   ├── models.py               # Pydantic models
│   │   └── gcloud_runner.py        # gcloud CLI wrapper
│   ├── checks/
│   │   ├── __init__.py
│   │   ├── base.py                 # Base check class
│   │   ├── registry.py             # Check auto-discovery
│   │   ├── gke/
│   │   │   ├── __init__.py
│   │   │   ├── cluster_security.py
│   │   │   ├── node_pool_config.py
│   │   │   ├── network_policy.py
│   │   │   ├── workload_identity.py
│   │   │   └── ...
│   │   ├── gce/
│   │   │   ├── __init__.py
│   │   │   ├── instance_config.py
│   │   │   ├── disk_encryption.py
│   │   │   ├── public_ip.py
│   │   │   └── ...
│   │   ├── gcs/
│   │   │   ├── __init__.py
│   │   │   ├── bucket_policy.py
│   │   │   ├── public_access.py
│   │   │   ├── encryption.py
│   │   │   └── ...
│   │   ├── databases/
│   │   │   ├── __init__.py
│   │   │   ├── cloudsql_config.py
│   │   │   ├── spanner_config.py
│   │   │   └── ...
│   │   ├── security/
│   │   │   ├── __init__.py
│   │   │   ├── org_policies.py
│   │   │   ├── vpc_service_controls.py
│   │   │   ├── security_command_center.py
│   │   │   └── ...
│   │   ├── networking/
│   │   │   ├── __init__.py
│   │   │   ├── vpc_config.py
│   │   │   ├── firewall_rules.py
│   │   │   ├── load_balancer.py
│   │   │   └── ...
│   │   ├── iam/
│   │   │   ├── __init__.py
│   │   │   ├── service_accounts.py
│   │   │   ├── role_bindings.py
│   │   │   ├── key_rotation.py
│   │   │   └── ...
│   │   ├── data/
│   │   │   ├── __init__.py
│   │   │   ├── bigquery_config.py
│   │   │   ├── pubsub_config.py
│   │   │   └── ...
│   │   ├── monitoring/
│   │   │   ├── __init__.py
│   │   │   ├── logging_config.py
│   │   │   ├── alerting.py
│   │   │   ├── uptime_checks.py
│   │   │   └── ...
│   │   └── billing/
│   │       ├── __init__.py
│   │       ├── budgets.py
│   │       ├── committed_use.py
│   │       └── ...
│   └── utils/
│       ├── __init__.py
│       ├── gcp_helpers.py
│       ├── formatting.py
│       └── report_generator.py
│
├── frontend/
│   ├── package.json
│   ├── vite.config.ts
│   ├── tsconfig.json
│   ├── tailwind.config.ts
│   ├── index.html
│   ├── public/
│   │   └── logo.svg
│   └── src/
│       ├── main.tsx
│       ├── App.tsx
│       ├── index.css
│       ├── components/
│       │   ├── ui/                 # shadcn/ui components
│       │   ├── layout/
│       │   │   ├── Header.tsx
│       │   │   ├── Sidebar.tsx
│       │   │   └── Footer.tsx
│       │   ├── wizard/
│       │   │   ├── ScopeSelector.tsx
│       │   │   ├── IdentityConfirm.tsx
│       │   │   ├── CategoryPicker.tsx
│       │   │   └── ScanLauncher.tsx
│       │   ├── dashboard/
│       │   │   ├── SeverityChart.tsx
│       │   │   ├── CategoryBreakdown.tsx
│       │   │   ├── FindingsTable.tsx
│       │   │   └── ScanProgress.tsx
│       │   └── findings/
│       │       ├── FindingCard.tsx
│       │       ├── FindingDetail.tsx
│       │       ├── FixCommand.tsx
│       │       └── ResourceLink.tsx
│       ├── pages/
│       │   ├── Home.tsx
│       │   ├── Scan.tsx
│       │   ├── Results.tsx
│       │   ├── FindingPage.tsx
│       │   └── Export.tsx
│       ├── hooks/
│       │   ├── useScan.ts
│       │   ├── useFindings.ts
│       │   └── useExport.ts
│       ├── lib/
│       │   ├── api.ts              # API client
│       │   ├── types.ts            # TypeScript types
│       │   └── utils.ts            # Utility functions
│       └── stores/
│           └── scanStore.ts        # Zustand store
│
└── tests/
    ├── backend/
    │   ├── test_engine.py
    │   ├── test_scanner.py
    │   ├── test_checks/
    │   │   └── ...
    │   └── conftest.py
    └── frontend/
        └── ...
```

---

## 7. Service Check Modules

### 7.1 GKE (Google Kubernetes Engine)

| Check ID | Check Name | Severity | Category |
|----------|-----------|----------|----------|
| GKE-001 | Cluster has legacy ABAC enabled | Critical | Security |
| GKE-002 | Cluster master is publicly accessible | High | Security |
| GKE-003 | Workload Identity not enabled | High | Security |
| GKE-004 | Network Policy not enabled | High | Security |
| GKE-005 | Pod Security Standards not enforced | Medium | Security |
| GKE-006 | Node auto-upgrade disabled | Medium | Reliability |
| GKE-007 | Node auto-repair disabled | Medium | Reliability |
| GKE-008 | Cluster not using private nodes | High | Security |
| GKE-009 | Binary Authorization not enabled | Medium | Security |
| GKE-010 | Shielded GKE Nodes not enabled | Medium | Security |
| GKE-011 | Logging/Monitoring not enabled | High | Operations |
| GKE-012 | Release channel not configured | Medium | Reliability |
| GKE-013 | Intranode visibility not enabled | Low | Operations |
| GKE-014 | Dataplane V2 not enabled | Medium | Performance |
| GKE-015 | Maintenance window not configured | Medium | Reliability |
| GKE-016 | Node pool using default service account | High | Security |
| GKE-017 | Resource quotas not defined | Medium | Cost |
| GKE-018 | Horizontal Pod Autoscaler not configured | Medium | Performance |
| GKE-019 | Cluster autoscaler not enabled | Medium | Cost |
| GKE-020 | Config Connector not enabled | Low | Operations |

### 7.2 GCE (Google Compute Engine)

| Check ID | Check Name | Severity | Category |
|----------|-----------|----------|----------|
| GCE-001 | Instance has public IP | High | Security |
| GCE-002 | Default service account in use | High | Security |
| GCE-003 | Disk not encrypted with CMEK | Medium | Security |
| GCE-004 | Serial port access enabled | Medium | Security |
| GCE-005 | OS Login not enabled | Medium | Security |
| GCE-006 | Shielded VM not enabled | Medium | Security |
| GCE-007 | IP forwarding enabled | Medium | Security |
| GCE-008 | Instance not using Confidential VM | Low | Security |
| GCE-009 | No deletion protection | Low | Reliability |
| GCE-010 | Instance running on sole-tenant node | Info | Cost |
| GCE-011 | Instance oversized (low CPU utilization) | Medium | Cost |
| GCE-012 | Persistent disk not using snapshots | Medium | Reliability |
| GCE-013 | SSH keys in project-wide metadata | High | Security |
| GCE-014 | Instance in default VPC | Medium | Security |
| GCE-015 | No labels/tags applied | Low | Operations |

### 7.3 GCS (Google Cloud Storage)

| Check ID | Check Name | Severity | Category |
|----------|-----------|----------|----------|
| GCS-001 | Bucket is publicly accessible | Critical | Security |
| GCS-002 | Uniform bucket-level access not enabled | High | Security |
| GCS-003 | Bucket not encrypted with CMEK | Medium | Security |
| GCS-004 | Versioning not enabled | Medium | Reliability |
| GCS-005 | No lifecycle policy configured | Medium | Cost |
| GCS-006 | Bucket logging not enabled | Medium | Operations |
| GCS-007 | Retention policy not set | Low | Security |
| GCS-008 | Bucket in single region (no redundancy) | Low | Reliability |
| GCS-009 | allUsers/allAuthenticatedUsers in IAM | Critical | Security |
| GCS-010 | No Object Lock for compliance data | Low | Security |

### 7.4 Databases (Cloud SQL, Spanner, AlloyDB, Firestore)

| Check ID | Check Name | Severity | Category |
|----------|-----------|----------|----------|
| DB-001 | Cloud SQL publicly accessible | Critical | Security |
| DB-002 | Cloud SQL no SSL enforcement | High | Security |
| DB-003 | Cloud SQL no automated backups | High | Reliability |
| DB-004 | Cloud SQL using default network | Medium | Security |
| DB-005 | Cloud SQL binary logging disabled | Medium | Reliability |
| DB-006 | Cloud SQL no PITR configured | Medium | Reliability |
| DB-007 | Cloud SQL no high availability | Medium | Reliability |
| DB-008 | Cloud SQL authorized networks too broad | High | Security |
| DB-009 | Cloud SQL not using CMEK | Medium | Security |
| DB-010 | Cloud SQL no maintenance window | Low | Reliability |
| DB-011 | Spanner not using CMEK | Medium | Security |
| DB-012 | Spanner no backup schedules | Medium | Reliability |
| DB-013 | Firestore no backup configured | Medium | Reliability |
| DB-014 | AlloyDB cluster no HA | Medium | Reliability |
| DB-015 | Cloud SQL database flags misconfigured | Medium | Security |

### 7.5 Security

| Check ID | Check Name | Severity | Category |
|----------|-----------|----------|----------|
| SEC-001 | Organization policy not enforcing domain restriction | High | Security |
| SEC-002 | VPC Service Controls not configured | Medium | Security |
| SEC-003 | Security Command Center not enabled | High | Security |
| SEC-007 | Web Security Scanner not configured | Low | Security |
| SEC-008 | DLP not configured for sensitive data | Medium | Security |
| SEC-009 | Certificate Authority Service not in use | Low | Security |
| SEC-010 | Access Transparency not enabled | Medium | Security |

### 7.6 Networking

| Check ID | Check Name | Severity | Category |
|----------|-----------|----------|----------|
| NET-001 | Default VPC network exists | High | Security |
| NET-002 | Firewall rule allows 0.0.0.0/0 ingress | Critical | Security |
| NET-003 | Firewall rule allows all protocols/ports | High | Security |
| NET-004 | No Cloud NAT for private instances | Medium | Security |
| NET-005 | VPC Flow Logs not enabled | Medium | Operations |
| NET-006 | DNS security (DNSSEC) not enabled | Medium | Security |
| NET-007 | Private Google Access not enabled | Medium | Security |
| NET-008 | Load balancer using HTTP (not HTTPS) | High | Security |
| NET-009 | SSL policy using weak cipher suites | Medium | Security |
| NET-010 | No Cloud CDN for static content | Low | Performance |
| NET-011 | Legacy network in use | High | Security |
| NET-012 | Subnet not using /24 or smaller | Low | Operations |

### 7.7 IAM (Identity & Access Management)

| Check ID | Check Name | Severity | Category |
|----------|-----------|----------|----------|
| IAM-001 | Primitive roles (Owner/Editor) in use | Critical | Security |
| IAM-003 | User-managed SA keys exist (reports key age in current_state) | High | Security |
| IAM-004 | Over-permissioned service accounts | High | Security |
| IAM-005 | SA impersonation not used (direct keys) | Medium | Security |
| IAM-006 | No org-level IAM audit | Medium | Security |
| IAM-007 | Unused service accounts (90+ days) | Medium | Cost |
| IAM-008 | External members in IAM bindings | High | Security |
| IAM-009 | allUsers/allAuthenticatedUsers in bindings | Critical | Security |
| IAM-010 | No custom roles (all predefined) | Low | Operations |
| IAM-011 | Workload Identity Federation not used | Medium | Security |
| IAM-012 | Domain-restricted sharing not enforced | High | Security |

### 7.8 Data Services (BigQuery, Pub/Sub, Dataflow)

| Check ID | Check Name | Severity | Category |
|----------|-----------|----------|----------|
| DATA-001 | BigQuery dataset publicly accessible | Critical | Security |
| DATA-002 | BigQuery not using CMEK | Medium | Security |
| DATA-003 | BigQuery no default table expiration | Medium | Cost |
| DATA-004 | BigQuery audit logging not configured | Medium | Operations |
| DATA-005 | Pub/Sub topic not encrypted with CMEK | Medium | Security |
| DATA-006 | Pub/Sub dead letter queue not configured | Medium | Reliability |
| DATA-007 | Pub/Sub subscription message retention too short | Low | Reliability |
| DATA-008 | Dataflow jobs not using private IPs | Medium | Security |
| DATA-009 | BigQuery Reservations not optimized | Low | Cost |
| DATA-010 | BigQuery no authorized views pattern | Medium | Security |

### 7.9 Logging & Monitoring

| Check ID | Check Name | Severity | Category |
|----------|-----------|----------|----------|
| MON-002 | No log sinks configured | Medium | Operations |
| MON-003 | Log retention below 365 days | Medium | Security |
| MON-004 | No alerting policies defined | High | Operations |
| MON-005 | No uptime checks configured | Medium | Reliability |
| MON-006 | Cloud Trace not enabled | Low | Performance |
| MON-008 | No custom dashboard for critical services | Low | Operations |
| MON-009 | Log-based metrics not defined | Low | Operations |
| MON-010 | No notification channels configured | High | Operations |

### 7.10 Billing & Cost

| Check ID | Check Name | Severity | Category |
|----------|-----------|----------|----------|
| BIL-001 | No budget alerts configured | High | Cost |
| BIL-002 | No committed use discounts (CUD) for stable workloads | Medium | Cost |
| BIL-003 | Sustained use discounts not leveraged | Low | Cost |
| BIL-004 | Billing export to BigQuery not configured | Medium | Cost |
| BIL-005 | No billing account-level alerts | Medium | Cost |
| BIL-006 | Projects without budget association | Medium | Cost |
| BIL-007 | Unused static IP addresses | Medium | Cost |
| BIL-008 | Orphaned persistent disks | Medium | Cost |
| BIL-009 | Idle load balancers | Medium | Cost |
| BIL-010 | Unattached reserved capacity | Medium | Cost |

### 7.11 Vertex AI

| Check ID | Check Name | Severity | Category |
|----------|-----------|----------|----------|
| VTX-001 | Vertex AI Workbench notebook has public IP | High | Security |
| VTX-002 | Notebook using default Compute Engine service account | High | Security |
| VTX-003 | Vertex AI Model Endpoint is publicly accessible | Medium | Security |
| VTX-004 | Vector Search Index Endpoint is public | High | Security |

---

## 8. Authentication & Authorization

### Service Account Model

The tool uses a **dedicated service account** with viewer-only permissions:

```
Service Account: democratized-reviewer-sa@<project>.iam.gserviceaccount.com
```

### Required IAM Roles

#### Deploy-side (granted automatically by `setup.sh`)

These are the **only** roles `setup.sh` grants. `roles/viewer` is a broad project-viewer role that subsumes most service-specific viewer perms (compute, container, sql, bigquery, monitoring, logging) so we don't need to enumerate every service viewer separately.

| Role | Purpose |
|------|---------|
| `roles/viewer` | Read access to most resources (transitive: container, compute, sql, bigquery, monitoring, logging, etc.) |
| `roles/iam.securityReviewer` | IAM policy review |
| `roles/cloudasset.viewer` | Cloud Asset Inventory (needed for org-scope project enumeration) |
| `roles/orgpolicy.policyViewer` | Organization policies (SEC-001, POST-001) |
| `roles/recommender.viewer` | Recommender insights (POST-004, BIL-006/007) |
| `roles/billing.viewer` | Project-level billing read (BIL-001/005). Note: for actual budget queries the SA also needs `roles/billing.viewer` on the **billing account itself** — `setup.sh` only grants project-level; the customer's billing admin must add the billing-account binding. |

#### Scan-target-side (granted via `./setup.sh --grant-on TARGET_PROJECT`)

The same 5-role bundle (deploy bundle minus `billing.viewer`) is granted on every additional scan target so the SA can read resources there.

#### Org-level (granted via `./setup.sh --grant-on-org ORG_ID`)

For whole-org scans, the SA is granted at the org node so per-project grants aren't needed:

| Role | Purpose |
|------|---------|
| `roles/viewer` | Transitive viewer on every project under the org |
| `roles/iam.securityReviewer` | Org-wide IAM policy review |
| `roles/cloudasset.viewer` | Cloud Asset Inventory at org scope |

If the engineer running `--grant-on-org` lacks Org Admin, the subcommand prints the exact gcloud commands for the customer's Org Admin to run.

### Pre-flight Permission Check

`GET /api/v1/setup/validate-scan-target?project=<id>` probes the target as the SA:

1. `gcloud projects describe <project>` — tests basic viewer access.
2. `gcloud services list --enabled --project=<project>` — tests the engine's first scan call.

If either probe fails, returns `{ok: false, suggested_command: "...gcloud add-iam-policy-binding..."}`. The wizard calls this before scan-start and renders the suggested command in an orange banner instead of allowing a scan that would 403 hundreds of times.

### Permission-storm short-circuit

If the pre-flight check is bypassed (e.g. permissions revoked between validation and scan-start, or the scan is started via API directly), the engine has a runtime guard:

- Track PERMISSION_DENIED responses across all in-flight checks.
- If ≥5 within the first 30 seconds, mark the scan `aborted` and fast-path every remaining check to SKIPPED with `error_message="Aborted: SA has no read permission..."`.
- Failure-mode scan duration goes from ~1 hour (213 checks × 30s timeout each) to ~30 seconds.

---

## 9. UI/UX Requirements

### Design Philosophy

**"Terminal meets Dashboard"** — A geeky, developer-centric aesthetic that feels like a sophisticated terminal UI evolved into a web app.

### Visual Design

- **Color Scheme**: Dark mode primary (deep charcoal `#0d1117` background, neon green `#00ff41` accents, electric blue `#58a6ff` links)
- **Typography**: Monospace headers (`JetBrains Mono`), clean sans-serif body (`Inter`)
- **Aesthetic**: Matrix-inspired scan animations, terminal-like log output, glowing badges
- **Grid-based layouts**: Card-based finding display, responsive 12-column grid

### Key UI Components

#### 1. Landing / Wizard Page
- Full-screen centered wizard with step progress indicator
- ASCII art logo or matrix-style animation background
- Steps: Scope → Identity → Categories → Launch
- Each step validates before proceeding

#### 2. Scan Progress Page
- Real-time terminal-style log output (auto-scroll)
- Category progress bars (0% → 100% per module)
- Overall progress ring/donut
- Live finding counter (Critical: X, High: Y, ...)
- Estimated time remaining

#### 3. Results Dashboard
- **Top bar**: Scan metadata (scope, time, duration, total findings)
- **Severity donut chart**: Interactive, filterable
- **Category bar chart**: Findings per service category
- **Score badge**: Overall health score (0-100) with letter grade
- **Findings table**: Sortable, filterable, searchable
  - Columns: Severity | Check ID | Title | Resource | Category | Fix Available
  - Row click → expand to detail

#### 4. Finding Detail Panel
- Slide-out panel or dedicated page
- Severity badge with color coding
- Description with markdown rendering
- Affected resource with Cloud Console link
- "Current State" vs "Recommended State" diff view
- Fix command in copyable code block with syntax highlighting
- Related documentation links

#### 5. Export Page
- Format selection (JSON / HTML report)
- GCS bucket picker or manual entry
- Download button for local files
- Export summary

### Responsive Design
- Optimized for desktop (1280px+) — primary use case
- Usable on tablet (768px+)
- Mobile: basic results view only

---

## 10. Deployment & Distribution

### Cloud Shell Setup Script (`setup.sh`)

The setup script is the primary distribution mechanism:

```bash
# User runs in Cloud Shell:
git clone <repo-url>
cd democratized-reviewer
chmod +x setup.sh
./setup.sh
```

#### Setup Script Subcommands

| Command | Purpose |
|---------|---------|
| `./setup.sh` | Interactive deploy. |
| `./setup.sh --remove` | Tear down Cloud Run service, SA, Artifact Registry repo, GCS bucket, restore org policy. |
| `./setup.sh --grant-on PROJECT_ID` | Grant the deploy SA viewer roles on an additional scan-target project. Idempotent. |
| `./setup.sh --grant-on-org ORG_ID` | Grant the deploy SA viewer roles at the org level. Requires the runner to have Org Admin; if not, prints copy-paste commands for the customer's admin. |
| `./setup.sh --help` | Show usage. |

#### Setup Script Flow

1. **Banner + system diagnostics**: detects `gcloud`, authenticated identity, current project.
2. **Target acquisition**:
   - Auto-detects the active gcloud project (override at prompt if needed).
   - Region prompt with `asia-south1` default. Validates user input against `gcloud run regions list` only if they typed something custom.
   - Detects whether the service account already exists.
   - Reads the effective `iam.allowedPolicyMemberDomains` org policy; offers to override if restricted (default: No).
3. **Service account setup** (parallel role bindings, ~3s wall-clock for 6 roles):
   - Creates SA if missing.
   - Binds 6 viewer roles on the deploy project (see Authentication section).
   - Attempts org-level bindings if the project is under an Org (best-effort; warns if it can't).
4. **API enablement**:
   - **Only enables the APIs the tool itself needs** (10 APIs: run, artifactregistry, cloudbuild, iam, aiplatform, cloudresourcemanager, cloudasset, serviceusage, orgpolicy, recommender).
   - Scan-target APIs (compute, container, kms, spanner, composer, alloydb, etc.) are NOT enabled — the engine pre-skips checks whose APIs are off. Listed informationally so the user knows what'll skip.
5. **Infrastructure**:
   - Creates Artifact Registry repo in the chosen region.
   - Creates GCS bucket `democratized-reviewer-<project>-data` with a 90-day lifecycle rule (auto-deletes scan persistence under `scans/`).
6. **Build & deploy**:
   - Always builds from source via `gcloud builds submit` into the project's Artifact Registry. Takes ~4-5 minutes on a cold build. Guarantees the deployed image matches the cloned source (no stale pre-built surprises).
   - Deploys to Cloud Run with `--memory=2Gi`, `--cpu=2`, `--timeout=3600`, `--min/max-instances=1`, `DR_MAX_CONCURRENT_CHECKS=5`.
   - `--no-allow-unauthenticated` unless the user opted into the org-policy override.
7. **Post-deploy summary**: prints Service URL, access instructions (proxy or public depending on override choice), and tips for granting additional users / billing-account permissions / demo public-access / uninstall.

### Docker Configuration

Single multi-stage Dockerfile:
- **Stage 1**: Node.js build (React frontend)
- **Stage 2**: Python runtime (FastAPI backend + built frontend)
- Includes `gcloud` CLI in final image

### Environment Variables

| Variable | Description | Default |
|----------|------------|---------|
| `DR_SCAN_SCOPE` | `org` or `project` | `project` |
| `DR_TARGET_ID` | Org ID or Project ID | (required) |
| `DR_SA_EMAIL` | Service account email | (auto-detected) |
| `DR_DEFAULT_ORG_ID` | Org ID to auto-populate in the wizard for org-scope scans | (optional) |
| `DR_GCS_EXPORT_BUCKET` | Bucket for report export + scan persistence | (optional) |
| `DR_DATA_DIR` | Local-disk fallback for scan persistence (used in tests / non-Cloud-Run runs) | (optional) |
| `DR_PORT` | Server port | `8080` |
| `DR_HOST` | Bind host | `0.0.0.0` |
| `DR_LOG_LEVEL` | Logging level | `INFO` |
| `DR_DEBUG` | Debug mode (disables HSTS, verbose tracebacks) | `false` |
| `DR_MAX_CONCURRENT_CHECKS` | Parallel check limit per project | `5` |
| `DR_MAX_CONCURRENT_PROJECTS` | Parallel project limit for org-scope scans | `4` |
| `DR_GCLOUD_TIMEOUT_SECONDS` | Per-gcloud-subprocess timeout | `30` |
| `DR_GCLOUD_TIMEOUT_LONG_SECONDS` | Long-running gcloud timeout (asset search) | `120` |
| `DR_CHECK_TIMEOUT_SECONDS` | Per-check overall timeout | `120` |
| `DR_RATE_LIMIT_GENERAL_RPM` | API rate limit (general endpoints) | `120` |
| `DR_RATE_LIMIT_SCAN_RPM` | API rate limit (scan creation) | `10` |
| `DR_AI_MODEL` | Vertex Gemini model for "Explain" button (`gemini-3-flash` or `gemini-3.1-pro`) | `gemini-3-flash` |

---

## 11. Data Persistence & Export

### Session Storage (Default)

- Scan results stored in-memory during the session
- Results available via API until the Cloud Run instance scales down
- No external database dependency

### GCS Export (Optional)

When configured, results can be exported to a GCS bucket:

```
gs://<bucket>/democratized-reviewer/
  └── scans/
      └── <scan-id>/
          ├── summary.json          # High-level summary
          ├── findings.json         # All findings
          ├── report.html           # Formatted HTML report
          └── metadata.json         # Scan config and timing
```

### Export Formats

| Format | Content | Use Case |
|--------|---------|----------|
| **JSON** | Machine-readable findings | API integration, scripts |
| **HTML** | Styled report with charts | Email to stakeholders, interactive filters |
| **PDF** | Print-ready document | Formal audit record, compliance filing |

---

## 12. Compliance & Frameworks

### v1: Custom Categories

All checks are tagged with one or more best-practice categories:

| Category | Icon | Color | Description |
|----------|------|-------|-------------|
| **Security** | 🔒 | Red | Data protection, access control, encryption |
| **Reliability** | ⚡ | Orange | HA, backups, disaster recovery |
| **Performance** | 🚀 | Blue | Resource optimization, scaling |
| **Cost** | 💰 | Green | Cost optimization, waste reduction |
| **Operations** | ⚙️ | Purple | Logging, monitoring, management |

### v2: Compliance Mapping (Future)

Each check will be mapped to:
- **CIS Google Cloud Foundation Benchmark v2.0+**
- **SOC 2 Type II** control objectives
- **PCI DSS v4.0** requirements (where applicable)

Mapping will be stored as metadata on each check:

```python
class Check:
    compliance_mapping: dict = {
        "cis_gcp": ["2.1", "2.3"],
        "soc2": ["CC6.1"],
        "pci_dss": ["2.2.1"]
    }
```

---

## 13. Non-Functional Requirements

| Requirement | Target | Notes |
|-------------|--------|-------|
| **Scan speed** (single project) | < 5 minutes | Parallel check execution |
| **Scan speed** (org, 50 projects) | < 30 minutes | Throttled API calls |
| **Cold start** (Cloud Run) | < 10 seconds | Optimize container size |
| **Container size** | < 500 MB | Multi-stage Docker build |
| **Memory usage** | < 512 MB per scan | Stream results, don't buffer |
| **Concurrent scans** | 1 per instance | Scale via Cloud Run instances |
| **API rate limiting** | Respect GCP quotas | Exponential backoff built-in |
| **Error handling** | Graceful degradation | Check failures don't stop scan |
| **Logging** | Structured JSON logs | Cloud Logging compatible |
| **Security** | No secrets in code/logs | SA key via Workload Identity |

---

## 14. Roadmap & Milestones

### Phase 1: Foundation (Weeks 1-2)
- [ ] Project scaffolding (backend + frontend)
- [ ] FastAPI app structure with health check
- [ ] Check engine architecture (base class, registry, runner)
- [ ] gcloud CLI wrapper
- [ ] React app with routing, dark theme
- [ ] Wizard UI (scope selection, SA confirmation)
- [ ] Docker multi-stage build
- [ ] `setup.sh` skeleton

### Phase 2: Core Checks (Weeks 3-4)
- [ ] GKE checks (20 checks)
- [ ] GCE checks (15 checks)
- [ ] GCS checks (10 checks)
- [ ] Security checks (10 checks)
- [ ] IAM checks (12 checks)
- [ ] Scan API endpoints (start, status, results)
- [ ] WebSocket progress streaming

### Phase 3: Extended Checks (Weeks 5-6)
- [ ] Database checks (15 checks)
- [ ] Networking checks (13 checks)
- [ ] Data services checks (10 checks)
- [ ] Monitoring checks (10 checks)
- [ ] Billing checks (10 checks)
- [ ] Fix command generation for all checks

### Phase 4: Dashboard & Reports (Weeks 7-8)
- [ ] Results dashboard (charts, tables, filters)
- [ ] Finding detail panel
- [ ] Health score calculation
- [ ] Export to JSON / HTML
- [ ] Export to GCS
- [ ] Scan history (session-level)

### Phase 5: Polish & Deploy (Weeks 9-10)
- [ ] `setup.sh` complete (interactive, tested)
- [ ] Cloud Shell deployment tested
- [ ] Error handling & edge cases
- [ ] Performance optimization
- [ ] Documentation (README, user guide)
- [ ] GitLab CI pipeline

### Phase 6: Compliance & Advanced (Future)
- [ ] CIS Benchmark mapping
- [ ] SOC2 / PCI-DSS mapping
- [ ] Historical trend tracking
- [ ] Scheduled scans
- [ ] Notifications (Slack, email)
- [ ] Terraform snippet generation

---

## Appendix

### A. Severity Definitions

| Severity | Description | Example |
|----------|------------|---------|
| **Critical** | Immediate security risk, data exposure likely | Public bucket with sensitive data |
| **High** | Significant security/reliability gap | No backups on production database |
| **Medium** | Deviation from best practice with moderate risk | CMEK not enabled, no network policy |
| **Low** | Minor improvement opportunity | Labels missing, single-region bucket |
| **Info** | Informational observation, no action required | Resource inventory, configuration note |

### C. gcloud vs API Decision Matrix

| Condition | Use gcloud | Use API |
|-----------|-----------|---------|
| Data available via `gcloud` list/describe | ✅ | |
| gcloud output requires complex parsing | | ✅ |
| Need paginated results (1000+ items) | | ✅ |
| Performance-critical bulk operations | | ✅ |
| gcloud not installed / not available | | ✅ |
| User wants to see exact command run | ✅ | |
| Default for all checks | ✅ | |

### D. References

- [GCP Security Best Practices](https://cloud.google.com/security/best-practices)
- [CIS Google Cloud Computing Foundations Benchmark](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)
- [Google Cloud Architecture Framework](https://cloud.google.com/architecture/framework)
- [GKE Hardening Guide](https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster)
- [Cloud SQL Best Practices](https://cloud.google.com/sql/docs/mysql/best-practices)
