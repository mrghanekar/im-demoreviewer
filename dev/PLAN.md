# Democratized Reviewer — Build Plan

> **Version**: 1.0  
> **Last Updated**: 2026-02-07  
> **Approach**: Phased, vertical slices — each phase delivers a working increment

---

## Build Philosophy

Each phase produces a **deployable, testable artifact**. We build vertically (one full slice through backend → frontend → deploy) rather than horizontally (all backend, then all frontend). This means we can demo after every phase.

---

## Phase 0: Project Bootstrap & Scaffolding
**Duration**: 2-3 days  
**Goal**: Empty but runnable project with all tooling configured

### Tasks

#### 0.1 Backend Scaffolding
- [ ] Create `backend/` directory structure per PRD
- [ ] Initialize `requirements.txt` with pinned dependencies:
  ```
  fastapi==0.115.*
  uvicorn[standard]==0.34.*
  pydantic==2.10.*
  google-cloud-resource-manager==1.*
  google-cloud-storage==2.*
  google-cloud-asset==3.*
  google-auth==2.*
  websockets==14.*
  httpx==0.28.*
  python-dotenv==1.*
  ```
- [ ] Create `backend/main.py` — FastAPI app factory with CORS, static files, health check
- [ ] Create `backend/config.py` — Settings via environment variables (Pydantic BaseSettings)
- [ ] Create `backend/api/routes/health.py` — `GET /api/v1/health` returns `{"status": "ok"}`
- [ ] Create `backend/core/models.py` — All Pydantic models (Scan, Finding, CheckResult, Summary, Severity enum, Category enum)
- [ ] Create `backend/checks/base.py` — `BaseCheck` abstract class with `execute()` method
- [ ] Create `backend/checks/registry.py` — Auto-discovery of checks via module inspection
- [ ] Create `backend/core/gcloud_runner.py` — Async subprocess wrapper for `gcloud` commands
- [ ] Create `backend/core/api_client.py` — Google Cloud SDK client wrapper (fallback)
- [ ] Create `backend/core/engine.py` — Check execution engine (run checks in parallel, collect results)
- [ ] Create `backend/core/scanner.py` — Scan orchestrator (manages scan lifecycle)

#### 0.2 Frontend Scaffolding
- [ ] Initialize React project: `npm create vite@latest frontend -- --template react-ts`
- [ ] Install dependencies:
  ```
  tailwindcss @tailwindcss/vite
  react-router-dom
  zustand
  @tanstack/react-query
  recharts
  react-syntax-highlighter
  lucide-react
  clsx tailwind-merge
  ```
- [ ] Configure Tailwind with custom dark theme tokens from PRD
- [ ] Install and configure shadcn/ui (button, card, badge, dialog, tabs, table, etc.)
- [ ] Create `frontend/src/lib/types.ts` — TypeScript interfaces matching backend models
- [ ] Create `frontend/src/lib/api.ts` — Fetch wrapper for backend API
- [ ] Create `frontend/src/stores/scanStore.ts` — Zustand store skeleton
- [ ] Create `frontend/src/App.tsx` — Router with placeholder pages
- [ ] Create layout components: `Header.tsx`, `Sidebar.tsx`, shell layout
- [ ] Create placeholder pages: Home, Scan, Results, Export
- [ ] Apply dark theme globally (`index.css` + Tailwind config)

#### 0.3 Docker & DevOps
- [ ] Create `Dockerfile` — Multi-stage build (Node → Python)
- [ ] Create `docker-compose.yml` — Local dev with hot reload
- [ ] Create `.dockerignore`
- [ ] Create `.env.example` — Document all environment variables
- [ ] Verify `docker build` and `docker run` work end-to-end
- [ ] Verify FastAPI serves both API and React static files

#### 0.4 Testing Setup
- [ ] Backend: `pytest` + `pytest-asyncio` + `pytest-cov` configured
- [ ] Create `tests/conftest.py` with shared fixtures
- [ ] Frontend: Vitest configured in `vite.config.ts`
- [ ] Verify `pytest` and `npm test` both pass (with placeholder tests)

### Definition of Done
- `docker-compose up` serves React UI at `/` and FastAPI at `/api/v1/health`
- Both frontend and backend have hot reload in dev mode
- CI pipeline runs tests (even if tests are trivial)

---

## Phase 1: Setup Wizard & Identity Flow
**Duration**: 3-4 days  
**Goal**: User can configure scan scope and confirm identity through the UI

### Tasks

#### 1.1 Backend — Setup API
- [ ] `GET /api/v1/setup/service-account` — Return current SA email, project, roles
  - Uses `gcloud auth list --format=json` to detect active account
  - Uses `gcloud projects get-iam-policy {project} --format=json` to list roles
- [ ] `GET /api/v1/setup/projects` — List accessible projects
  - Uses `gcloud projects list --format=json`
  - For org scope: `gcloud projects list --filter="parent.id={org_id}" --format=json`
- [ ] `GET /api/v1/setup/validate` — Pre-flight permission check
  - Checks each required role exists for the SA
  - Returns `{ "valid": bool, "missing_roles": [...], "granted_roles": [...] }`
- [ ] `GET /api/v1/setup/organizations` — List accessible orgs
  - Uses `gcloud organizations list --format=json`

#### 1.2 Frontend — Wizard UI
- [ ] **Home Page**: Landing with logo, tagline, "Start Review" CTA button
  - Matrix/terminal-style animated background (subtle)
  - ASCII art or SVG logo
- [ ] **Wizard Step 1 — Scope Selection**:
  - Toggle: "Organization" vs "Project"
  - If org: dropdown of available orgs (from API)
  - If project: dropdown of available projects (from API)
  - Search/filter on dropdowns
- [ ] **Wizard Step 2 — Identity Confirmation**:
  - Display current SA email and its roles
  - Green checkmarks for granted roles, red X for missing
  - "Re-validate" button
  - Warning banner if roles are missing (with `gcloud` commands to fix)
- [ ] **Wizard Step 3 — Category Selection**:
  - Grid of category cards (GKE, GCE, GCS, etc.) with icons
  - Select all / deselect all toggle
  - Each card shows estimated check count
  - "Select All" is default
- [ ] **Wizard Step 4 — Confirmation & Launch**:
  - Summary of selections
  - "Start Scan" button with loading state
  - Redirects to scan progress page

### Definition of Done
- User can navigate the full wizard flow
- Backend returns real data when run with gcloud credentials
- Missing permissions are clearly displayed
- "Start Scan" button creates a scan (even if checks don't run yet)

---

## Phase 2: Check Engine & First Checks
**Duration**: 5-7 days  
**Goal**: Scan engine runs real checks, first 3 service categories complete

### Tasks

#### 2.1 Check Engine Core
- [ ] Finalize `BaseCheck` with all helper methods:
  - `run_gcloud(cmd)` — async subprocess, returns parsed JSON
  - `run_api(method, **kwargs)` — SDK client fallback
  - `_console_link(resource)` — builds Cloud Console URL
  - `_build_fix_command(resource)` — template-based fix command
- [ ] `engine.py` — Run checks in parallel with concurrency limit (asyncio.Semaphore)
  - Collect results as they complete
  - Handle individual check failures gracefully
  - Emit progress events
- [ ] `scanner.py` — Full scan lifecycle:
  - Create scan record → enumerate projects (if org) → run engine per project → aggregate results → compute summary
  - WebSocket event emission for real-time progress
- [ ] Resource caching layer:
  - If multiple checks need `gcloud compute instances list`, cache the result
  - Cache keyed by (project_id, gcloud_command)
  - Cache lives only within a single scan session

#### 2.2 Scan API
- [ ] `POST /api/v1/scans` — Start a new scan
  - Body: `{ scope, target_id, categories[] }`
  - Returns scan ID, starts scan in background
- [ ] `GET /api/v1/scans/{scan_id}` — Get scan status
- [ ] `GET /api/v1/scans/{scan_id}/findings` — Get findings (with filters)
- [ ] `GET /api/v1/scans/{scan_id}/summary` — Get summary stats
- [ ] `WS /api/v1/scans/{scan_id}/stream` — WebSocket for live progress
  - Events: `check_started`, `check_completed`, `finding_discovered`, `scan_completed`

#### 2.3 IAM Checks (12 checks)
Priority service — affects all other services, richest findings.

- [ ] `IAM-001`: Primitive roles (Owner/Editor) in use
- [ ] `IAM-002`: Service account keys older than 90 days
- [ ] `IAM-003`: User-managed SA keys exist
- [ ] `IAM-004`: Over-permissioned service accounts
- [ ] `IAM-005`: SA impersonation not used
- [ ] `IAM-006`: No org-level IAM audit
- [ ] `IAM-007`: Unused service accounts (90+ days)
- [ ] `IAM-008`: External members in IAM bindings
- [ ] `IAM-009`: allUsers/allAuthenticatedUsers in bindings
- [ ] `IAM-010`: No custom roles
- [ ] `IAM-011`: Workload Identity Federation not used
- [ ] `IAM-012`: Domain-restricted sharing not enforced

Implementation approach per check:
```
gcloud projects get-iam-policy {project} --format=json
gcloud iam service-accounts list --project={project} --format=json
gcloud iam service-accounts keys list --iam-account={sa} --format=json
```

#### 2.4 Security Checks (10 checks)
- [ ] `SEC-001` through `SEC-010` (see PRD for full list)

Implementation approach:
```
gcloud org-policies list --project={project} --format=json
gcloud services list --project={project} --format=json  # Check for SCC
gcloud kms keys list --keyring={kr} --location={loc} --format=json
```

#### 2.5 GCS Checks (10 checks)
- [ ] `GCS-001` through `GCS-010` (see PRD for full list)

Implementation approach:
```
gcloud storage buckets list --project={project} --format=json
gcloud storage buckets describe gs://{bucket} --format=json
gcloud storage buckets get-iam-policy gs://{bucket} --format=json
```

#### 2.6 Tests for Phase 2
- [ ] Unit tests for each check with mock gcloud output
- [ ] Integration test: run engine with mock checks, verify parallel execution
- [ ] Integration test: scan lifecycle (create → run → complete)
- [ ] WebSocket test: verify event stream

### Definition of Done
- Running a scan executes 32 real checks (IAM + Security + GCS)
- Findings are returned via API with correct severity, category, fix commands
- WebSocket streams real-time progress
- All checks have unit tests with >80% coverage

---

## Phase 3: Dashboard UI & Remaining Core Checks
**Duration**: 7-10 days  
**Goal**: Full results dashboard, 5 more service categories

### Tasks

#### 3.1 Scan Progress Page
- [ ] Terminal-style log output panel (auto-scrolling, monospace)
  - Shows `gcloud` commands being executed
  - Shows check names as they start/complete
  - Color-coded: green=pass, red=fail, yellow=error
- [ ] Category progress bars (one per selected category)
- [ ] Overall progress ring (percentage)
- [ ] Live finding counter badges (Critical: X, High: Y, ...)
- [ ] "Cancel Scan" button

#### 3.2 Results Dashboard
- [ ] **Top summary bar**: Scan scope, duration, total findings, health score/grade
- [ ] **Severity donut chart** (Recharts): Interactive, click to filter
- [ ] **Category bar chart**: Findings per service category
- [ ] **Health score badge**: Large, centered, letter grade (A-F) with color
- [ ] **Findings table**: Full-featured data table
  - Columns: Severity (icon) | Check ID | Title | Resource | Service | Category
  - Sortable by any column
  - Filterable by severity, category, service
  - Search across title and resource name
  - Pagination (25/50/100 per page)
  - Row click → expand or navigate to detail

#### 3.3 Finding Detail View
- [ ] Slide-out panel (or dedicated route)
- [ ] Severity badge with color and icon
- [ ] Full description (markdown rendered)
- [ ] "Current State" vs "Recommended State" — side-by-side diff style
- [ ] Fix command in syntax-highlighted code block
  - Copy button (copies to clipboard)
  - "Open in Cloud Shell" link (generates Cloud Shell URL)
- [ ] Resource link → opens in Cloud Console (new tab)
- [ ] Related documentation links

#### 3.4 GKE Checks (20 checks)
- [ ] `GKE-001` through `GKE-020` (see PRD for full list)

Implementation approach:
```
gcloud container clusters list --project={project} --format=json
gcloud container clusters describe {cluster} --zone={zone} --format=json
gcloud container node-pools list --cluster={cluster} --zone={zone} --format=json
```

#### 3.5 GCE Checks (15 checks)
- [ ] `GCE-001` through `GCE-015` (see PRD for full list)

Implementation approach:
```
gcloud compute instances list --project={project} --format=json
gcloud compute disks list --project={project} --format=json
gcloud compute project-info describe --project={project} --format=json
```

#### 3.6 Networking Checks (13 checks)
- [ ] `NET-001` through `NET-013` (see PRD for full list)

Implementation approach:
```
gcloud compute networks list --project={project} --format=json
gcloud compute firewall-rules list --project={project} --format=json
gcloud compute forwarding-rules list --project={project} --format=json
gcloud dns managed-zones list --project={project} --format=json
```

#### 3.7 Database Checks (15 checks)
- [ ] `DB-001` through `DB-015` (see PRD for full list)

Implementation approach:
```
gcloud sql instances list --project={project} --format=json
gcloud sql instances describe {instance} --format=json
gcloud spanner instances list --project={project} --format=json
gcloud firestore databases list --project={project} --format=json
```

#### 3.8 Monitoring Checks (10 checks)
- [ ] `MON-001` through `MON-010` (see PRD for full list)

Implementation approach:
```
gcloud logging sinks list --project={project} --format=json
gcloud alpha monitoring policies list --project={project} --format=json
gcloud alpha monitoring channels list --project={project} --format=json
```

#### 3.9 Tests for Phase 3
- [ ] Unit tests for all new checks (65 checks)
- [ ] Frontend component tests (dashboard, charts, finding detail)
- [ ] Integration test: full scan with all categories

### Definition of Done
- Dashboard shows rich, interactive results for 97 checks
- Charts, tables, and filters work correctly
- Finding detail view shows all information including fix commands
- 7 out of 10 service categories implemented

---

## Phase 4: Remaining Checks, Export & Polish
**Duration**: 5-7 days  
**Goal**: All 10 categories complete, export functional, UI polished

### Tasks

#### 4.1 Remaining Checks

##### Data Services Checks (10 checks)
- [ ] `DATA-001` through `DATA-010` (see PRD for full list)

```
bq ls --project_id={project} --format=json
gcloud pubsub topics list --project={project} --format=json
gcloud dataflow jobs list --project={project} --format=json
```

##### Billing Checks (10 checks)
- [ ] `BIL-001` through `BIL-010` (see PRD for full list)

```
gcloud billing budgets list --billing-account={account} --format=json
gcloud compute addresses list --project={project} --filter="status=RESERVED" --format=json
gcloud compute disks list --project={project} --filter="-users:*" --format=json
```

#### 4.2 Export System
- [ ] `POST /api/v1/scans/{scan_id}/export` — Export to GCS
  - Uploads `summary.json`, `findings.json`, `report.html` to configured bucket
  - Returns GCS URIs
- [ ] `GET /api/v1/scans/{scan_id}/export/json` — Download JSON locally
- [ ] `GET /api/v1/scans/{scan_id}/export/html` — Download HTML report
- [ ] HTML report generator:
  - Self-contained HTML with embedded CSS
  - Executive summary with health score
  - Severity breakdown chart (inline SVG)
  - Full findings table with expandable details
  - Fix commands included
  - Print-friendly styling
- [ ] **Export UI page**:
  - Format selection (JSON / HTML)
  - GCS bucket input (optional)
  - Download button
  - Export progress indicator
  - "View in GCS" link after export

#### 4.3 Health Score
- [ ] Implement scoring algorithm:
  ```
  Score = 100 - (Critical × 10) - (High × 5) - (Medium × 2) - (Low × 0.5)
  Minimum: 0
  Grade: A (90-100), B (80-89), C (70-79), D (60-69), F (<60)
  ```
- [ ] Score breakdown panel showing point deductions
- [ ] Score comparison callout ("X critical findings are costing you Y points")

#### 4.4 UI Polish
- [ ] Loading skeletons on all data-fetching components
- [ ] Error boundaries with retry buttons
- [ ] Empty states ("No findings — your cloud is clean!")
- [ ] Responsive layout adjustments (tablet/desktop)
- [ ] Keyboard navigation (Tab, Enter, Escape)
- [ ] Toast notifications (scan started, scan complete, export done)
- [ ] Animated transitions between wizard steps
- [ ] Animated scan progress (pulse effects, count-up numbers)
- [ ] Favicon and meta tags
- [ ] 404 page

#### 4.5 Tests for Phase 4
- [ ] Unit tests for remaining 20 checks
- [ ] Export tests (JSON generation, HTML generation, GCS upload)
- [ ] Full E2E test: wizard → scan → results → export
- [ ] Health score calculation tests

### Definition of Done
- All 125+ checks across 10 categories are implemented
- Export to JSON, HTML, and GCS works
- Health score is calculated and displayed
- UI is polished with loading states, error handling, animations

---

## Phase 5: Deployment & setup.sh
**Duration**: 3-5 days  
**Goal**: One-command deployment from Cloud Shell

### Tasks

#### 5.1 setup.sh Script
- [x] Shebang and strict mode (`set -euo pipefail`)
- [x] Color output helpers (print_info, print_success, print_error, print_warning)
- [x] Pre-requisite checks:
  - `gcloud` CLI installed and authenticated
  - Sufficient permissions to create SA, enable APIs, deploy Cloud Run
  - Required APIs check
- [x] Interactive prompts with defaults:
  - Org Policy Override (`iam.allowedPolicyMemberDomains`) [NEW]
  - Pre-built Image selection (GitLab Registry) [NEW]
  - Scan scope: [org/project]
  - Target ID: (auto-detect or enter)
  - Service Account: [create new / select existing]
  - Cloud Run region: [select from list]
  - GCS export bucket: [create new / select existing / skip]
  - Confirm and deploy? [Y/n]
- [x] API enablement (batch enable)
- [x] Service Account creation and role binding
- [x] Cloud Build + Cloud Run deployment:
  - Supports building from source
  - Supports pre-built image via "Pull-Tag-Push" workflow (bypasses GCR/AR restriction)
  - Deploys with `allow-unauthenticated` if Org Policy override is accepted
- [x] Post-deployment:
  - Print Cloud Run URL
  - Print SA email and roles
  - Print "Getting Started" instructions
  - Verify deployment by hitting health check

#### 5.2 Uninstall Script
- [x] `setup.sh --remove` — Clean teardown
  - Delete Cloud Run service
  - Delete Container image (if locally built)
  - Remove SA role bindings
  - Delete SA (with confirmation)
  - Delete GCS export bucket
  - **Restore Org Policy** if overridden [NEW]

#### 5.3 Cloud Shell Testing

#### 5.3 Cloud Shell Testing
- [ ] Test `setup.sh` in fresh Cloud Shell environment
- [ ] Test with org-level scope
- [ ] Test with project-level scope
- [ ] Test with existing SA
- [ ] Test with new SA creation
- [ ] Test idempotency (run setup.sh twice)
- [ ] Test error recovery (interrupt mid-setup, re-run)

#### 5.4 Documentation
- [ ] Rewrite `README.md`:
  - Project description and screenshot
  - Quick start (3 commands)
  - Prerequisites
  - Configuration options
  - Architecture diagram
  - Contributing guide
  - License
- [ ] Add `CONTRIBUTING.md` with check authoring guide

### Definition of Done
- `./setup.sh` deploys working tool to Cloud Run in < 10 minutes
- `./uninstall.sh` cleanly removes everything
- README is comprehensive and accurate
- Tool works end-to-end in a fresh GCP project

---

## Phase 6: Hardening & Stretch Goals
**Duration**: Ongoing  
**Goal**: Production readiness, additional features

### Tasks

#### 6.1 Hardening
- [ ] Rate limiting on API endpoints
- [ ] Input validation on all user inputs (project IDs, org IDs)
- [ ] CSRF protection for Cloud Run deployment
- [ ] Content Security Policy headers
- [ ] Structured JSON logging (Cloud Logging compatible)
- [ ] Error tracking and alerting
- [ ] Graceful shutdown handling
- [ ] Memory profiling — ensure large scans don't OOM

#### 6.2 Performance
- [ ] Benchmark scan time per category
- [ ] Optimize slowest checks (identify bottlenecks)
- [ ] Implement resource list caching aggressively
- [ ] Consider Cloud Run min-instances for zero cold start

#### 6.3 Stretch Goals (v2 Roadmap)
- [ ] CIS Google Cloud Benchmark mapping
- [ ] SOC2 / PCI-DSS compliance mapping
- [ ] Scan history with trend charts (store in GCS)
- [ ] Scheduled recurring scans (Cloud Scheduler)
- [ ] Slack notifications on scan completion
- [ ] Email report delivery
- [ ] Terraform snippet generation for fixes
- [ ] Custom check authoring via YAML definitions
- [ ] Multi-org support (scan multiple orgs)
- [ ] RBAC for multi-user access

---

## Dependency Graph

```
Phase 0 ──► Phase 1 ──► Phase 2 ──► Phase 3 ──► Phase 4 ──► Phase 5
(scaffold)  (wizard)    (engine+    (dashboard+  (export+    (deploy)
                        3 svc)      5 svc)       2 svc)

Phase 5 ──► Phase 6
            (harden)
```

Key dependencies:
- Phase 1 depends on Phase 0 (needs running app)
- Phase 2 depends on Phase 1 (needs scope/SA config to run checks)
- Phase 3 depends on Phase 2 (dashboard needs findings data)
- Phase 4 depends on Phase 3 (export needs all checks + UI)
- Phase 5 depends on Phase 4 (deploy needs complete app)
- Phase 6 can start in parallel with Phase 5

---

## Estimated Timeline

| Phase | Duration | Cumulative |
|-------|----------|-----------|
| Phase 0: Scaffolding | 2-3 days | ~3 days |
| Phase 1: Wizard & Identity | 3-4 days | ~7 days |
| Phase 2: Engine & First Checks | 5-7 days | ~14 days |
| Phase 3: Dashboard & More Checks | 7-10 days | ~24 days |
| Phase 4: Export & Polish | 5-7 days | ~31 days |
| Phase 5: Deployment | 3-5 days | ~36 days |
| **Total (v1)** | **~5-6 weeks** | |
| Phase 6: Hardening | Ongoing | |

---

## Risk Register

| Risk | Impact | Likelihood | Mitigation |
|------|--------|-----------|------------|
| gcloud CLI not available in Cloud Run | High | Medium | Install gcloud in Docker image; test thoroughly |
| GCP API quota limits during large org scans | Medium | High | Exponential backoff, configurable concurrency |
| Some checks need roles beyond viewer | Medium | Medium | Document required roles clearly, pre-flight check |
| Cloud Run cold start affects UX | Low | High | Min instances = 1 for production use |
| Large orgs (500+ projects) timeout | High | Medium | Implement pagination, streaming, project batching |
| gcloud output format changes between versions | Medium | Low | Pin gcloud version in Docker, parse defensively |

---

## Success Criteria

### MVP (Phase 5 complete)
- [ ] Tool deploys to Cloud Run via `./setup.sh` in < 10 minutes
- [ ] Scans a single project with 125+ checks in < 5 minutes
- [ ] All findings include severity, description, and fix command
- [ ] Dashboard displays interactive charts and filterable table
- [ ] Export to JSON and HTML works
- [ ] GCS export works when configured
- [ ] All checks use viewer-only permissions
- [ ] Health score accurately reflects environment posture

### Stretch (Phase 6)
- [ ] CIS Benchmark compliance mapping
- [ ] Scan history with trend visualization
- [ ] < 30 minute scan for 50-project org
- [ ] Community-contributed checks via plugin system
