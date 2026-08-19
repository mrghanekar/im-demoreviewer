# AGENTS.md — Democratized Reviewer

> Instructions for AI agents working on this codebase. Read this file before making any changes.

---

## Project Overview

**Democratized Reviewer** is a GCP audit and best-practices review tool that runs on Cloud Run. It scans Google Cloud environments (org or project level) using viewer-only IAM roles and presents findings via a React dashboard with fix suggestions.

**Tech Stack**: Python 3.12 (FastAPI) backend + React 18 (Vite + TypeScript) frontend, deployed as a single Docker container on Cloud Run.

---

## Architecture Principles

### 1. Read-Only by Design
- **NEVER** write code that modifies GCP resources. All interactions with GCP are read-only.
- All checks use viewer/reader IAM roles only.
- Fix suggestions are output as copyable `gcloud` commands — they are NOT executed.

### 2. gcloud-Only Execution
- **Strictly** execute `gcloud` CLI commands via subprocess to gather data.
- Do NOT use `google-cloud-*` Python SDK libraries. This keeps the image small and the architecture simple.
- Always log the exact `gcloud` command executed for transparency.
- Parse JSON output (`--format=json`) from gcloud commands.

### 3. Plugin-Based Checks
- Every check is a self-contained class inheriting from `BaseCheck`.
- Checks are auto-discovered via the registry — no manual registration needed.
- Each check lives in its service category folder under `backend/checks/`.

### 4. Graceful Degradation
- A failing check must NEVER crash the scan. Catch exceptions, log the error, mark the check as `errored`, and continue.
- Missing permissions should be detected and reported, not crash the process.
- If you see >5 PERMISSION_DENIED in 30s, the `CheckEngine` short-circuits the rest of the scan to SKIPPED with a clear "SA has no read permission" message. Do NOT remove this guard — it's the difference between a 30-second clean failure and a 1-hour silent stall when the SA wasn't granted on the target project.

### 5. Don't enable scan-target APIs on the user's behalf
- `setup.sh` enables ONLY the APIs the tool itself needs to run (10 deploy APIs). It deliberately does NOT enable scan-target APIs like Spanner / Composer / KMS / Memorystore.
- Rationale: an API being disabled = the user isn't using that service. Enabling it just so a posture check can confirm "no resources" wastes IAM surface and sometimes accrues baseline cost. The engine's `required_apis` pre-skip handles disabled APIs cleanly by marking dependent checks SKIPPED with "service not active in project".
- When adding new checks: always declare `required_apis` in the module's `apply_required_apis(...)` call. Never add new APIs to `setup.sh`'s `DEPLOY_APIS` for scan reasons — only if the tool itself needs them.

### 6. Pre-flight before destructive / time-consuming operations
- New: `GET /api/v1/setup/validate-scan-target?project=<id>` probes the target as the SA before the scan starts. The wizard calls this on Launch; on failure it shows the suggested `gcloud add-iam-policy-binding` command and blocks the scan.
- Pattern: when introducing any user-action that depends on uncertain external state (permissions, network reachability, API enablement), add a cheap pre-flight probe that fails fast with the exact fix command. Avoid the "stuck for 5 minutes then mysterious failure" UX.

---

## Code Style & Conventions

### Python (Backend)

- **Python 3.12+** features are allowed (f-strings, match/case, type hints, `|` union syntax).
- **Type hints everywhere**: All function signatures must have type hints. Use Pydantic models for API contracts.
- **Async by default**: Use `async def` for all API route handlers and check execution functions.
- **Pydantic v2**: Use Pydantic v2 style (`model_validator`, `field_validator`, `ConfigDict`).
- **Naming**:
  - Files: `snake_case.py`
  - Classes: `PascalCase`
  - Functions/variables: `snake_case`
  - Constants: `UPPER_SNAKE_CASE`
  - Check IDs: `{SERVICE}-{NUMBER}` (e.g., `GKE-001`, `GCS-005`)
- **Imports**: Group as stdlib → third-party → local. Use absolute imports from project root.
- **Docstrings**: Google-style docstrings on all public functions and classes.
- **Error handling**: Use specific exceptions. Never bare `except:`. Always `except Exception as e:` minimum.
- **No secrets**: Never hardcode credentials, project IDs, or org IDs. Use environment variables.

### TypeScript (Frontend)

- **TypeScript strict mode** (`strict: true` in tsconfig).
- **Functional components only**: No class components. Use hooks.
- **Named exports**: Prefer named exports over default exports.
- **Naming**:
  - Components: `PascalCase.tsx`
  - Hooks: `useCamelCase.ts`
  - Utilities: `camelCase.ts`
  - Types/interfaces: `PascalCase` in `types.ts`
- **State management**: Zustand for global state. React Query (TanStack Query) for server state.
- **Styling**: Tailwind CSS utility classes. Use `cn()` helper from shadcn/ui for conditional classes.
- **No inline styles**: Use Tailwind classes exclusively.
- **No `any`**: Never use `any` type. Use `unknown` and narrow with type guards.

### General

- **No `console.log` in production code** — use proper logging (Python: `logging`, JS: structured logger).
- **No TODO comments without a linked issue**: If you must leave a TODO, format as `# TODO(issue-123): description`.
- **Test every check**: Each check module must have corresponding tests with mock GCP responses.

---

## Directory Structure Rules

```
backend/
├── main.py                 # FastAPI app factory — keep minimal
├── config.py               # All config via environment variables
├── api/routes/             # One file per resource (scan.py, results.py, etc.)
├── core/                   # Engine, scanner, models, gcloud_runner
├── checks/                 # GCP check modules — one folder per service
│   ├── base.py             # BaseCheck class — READ THIS FIRST
│   ├── registry.py         # Auto-discovery — don't modify unless adding features
│   └── {service}/          # Check modules grouped by GCP service
├── utils/                  # Shared utilities — keep thin
└── tests/                  # Mirror the source structure

frontend/src/
├── components/ui/          # shadcn/ui primitives — don't modify
├── components/layout/      # Shell layout components
├── components/wizard/      # Setup wizard steps
├── components/dashboard/   # Results dashboard widgets
├── components/findings/    # Finding display components
├── pages/                  # Top-level route pages
├── hooks/                  # Custom React hooks
├── lib/                    # API wrappers, utilities, types
└── stores/                 # Zustand stores
```

---

## Writing a New Check

This is the most common task. Follow this pattern exactly:

### Step 1: Create the check file

Place it in `backend/checks/{service}/` with a descriptive filename:

```python
"""Check for [what it checks].

Check ID: {SERVICE}-{NUMBER}
Severity: critical | high | medium | low | info
Category: security | reliability | performance | cost | operations
"""

from backend.checks.base import BaseCheck, CheckResult, Severity, Category


class MyNewCheck(BaseCheck):
    """One-line description of what this check does."""

    id = "{SERVICE}-{NUMBER}"
    title = "Human-readable title"
    description = "Detailed explanation of why this matters."
    severity = Severity.HIGH
    category = Category.SECURITY
    service = "{SERVICE}"
    
    # gcloud command used (for transparency)
    gcloud_command = "gcloud {service} {resource} list --format=json"
    
    # Fix command template
    fix_command_template = "gcloud {service} {resource} update {name} --enable-feature"
    
    # Documentation references
    references = [
        "https://cloud.google.com/relevant-docs-link"
    ]

    async def execute(self, project_id: str, gcloud_runner: Any) -> list[CheckResult]:
        """Run the check against a project.
        
        Args:
            project_id: The GCP project ID to scan.
            gcloud_runner: The GcloudRunner instance.
            
        Returns:
            List of CheckResult for each finding (empty if check passes).
        """
        # Step 1: Gather data
        resources = await gcloud_runner.run(
            f"gcloud {self.service} {self.resource} list --project={project_id} --format=json"
        )
        
        # Step 2: Evaluate each resource
        findings = []
        for resource in resources:
            if self._is_non_compliant(resource):
                findings.append(CheckResult(
                    check_id=self.id,
                    title=self.title,
                    severity=self.severity,
                    category=self.category,
                    resource_name=resource["name"],
                    resource_link=self._console_link(resource),
                    current_state="What's currently wrong",
                    recommended_state="What it should be",
                    fix_command=self._build_fix_command(resource),
                    references=self.references,
                    project_id=project_id,
                ))
        
        return findings
    
    def _is_non_compliant(self, resource: dict) -> bool:
        """Check if a single resource violates this check."""
        # Implement evaluation logic
        ...
    
    def _build_fix_command(self, resource: dict) -> str:
        """Build the gcloud fix command for a specific resource."""
        return self.fix_command_template.format(name=resource["name"])
    
    def _console_link(self, resource: dict) -> str:
        """Build Cloud Console URL for the resource."""
        ...
```

### Step 2: Write tests

Create `tests/backend/test_checks/test_{service}_{check_name}.py`:

```python
"""Tests for {SERVICE}-{NUMBER}: {title}."""

import pytest
from backend.checks.{service}.{module} import MyNewCheck


@pytest.fixture
def check():
    return MyNewCheck()


@pytest.fixture
def compliant_resource():
    """A resource that passes this check."""
    return { ... }


@pytest.fixture
def non_compliant_resource():
    """A resource that fails this check."""
    return { ... }


class TestMyNewCheck:
    async def test_compliant_resource_passes(self, check, compliant_resource):
        # Mock gcloud output, verify no findings
        ...

    async def test_non_compliant_resource_flagged(self, check, non_compliant_resource):
        # Mock gcloud output, verify finding generated
        ...

    def test_fix_command_is_valid(self, check, non_compliant_resource):
        # Verify the fix command is syntactically correct
        ...
```

### Step 3: Verify auto-discovery

The check will be automatically discovered by `registry.py` if:
1. It's in a file under `backend/checks/{service}/`
2. The class inherits from `BaseCheck`
3. The `id` class attribute is set

No manual registration is needed.

---

## Backend Development

### Running locally

```bash
cd backend
python -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
uvicorn main:app --reload --port 8080
```

### Key files to understand first

1. `backend/checks/base.py` — The `BaseCheck` class and `CheckResult` model
2. `backend/core/engine.py` — How checks are executed
3. `backend/core/scanner.py` — How scans are orchestrated
4. `backend/core/gcloud_runner.py` — How `gcloud` commands are executed
5. `backend/core/models.py` — All Pydantic models (Scan, Finding, Summary)

### API patterns

- All routes are async
- Use dependency injection for services (`Depends()`)
- Return Pydantic models (auto-serialized to JSON)
- Errors return `HTTPException` with appropriate status codes
- WebSocket for real-time scan progress

### gcloud Runner rules

- Always set `--format=json` for parseable output
- Always set `--project={project_id}` explicitly
- Set reasonable timeouts (30s default, 120s for large lists)
- Handle `gcloud` not being installed gracefully (fall back to API)
- Log the full command before execution
- Parse JSON output, handle empty results as empty list

---

## Frontend Development

### Running locally

```bash
cd frontend
npm install
npm run dev
```

### Key files to understand first

1. `frontend/src/lib/types.ts` — All TypeScript types matching backend models
2. `frontend/src/lib/api.ts` — API client (fetch wrapper)
3. `frontend/src/stores/scanStore.ts` — Zustand store for scan state
4. `frontend/src/App.tsx` — Routes and layout

### UI patterns

- Dark theme is the ONLY theme (no light mode toggle)
- All components use Tailwind CSS — no inline styles, no CSS modules
- Use shadcn/ui components as base — customize with Tailwind
- Charts use Recharts library
- Code blocks use syntax highlighting (react-syntax-highlighter)
- Copy buttons on all `gcloud` fix commands
- Loading states with skeleton components
- Error states with retry buttons
- All data fetching via TanStack Query (useQuery, useMutation)

### Color tokens (Tailwind config)

```
background: #0d1117
surface: #161b22
border: #30363d
text-primary: #e6edf3
text-secondary: #8b949e
accent-green: #00ff41
accent-blue: #58a6ff
accent-red: #f85149
accent-orange: #d29922
accent-purple: #bc8cff
```

---

## Docker & Deployment

### Building

```bash
docker build -t democratized-reviewer .
docker run -p 8080:8080 democratized-reviewer
```

### Dockerfile rules

- Multi-stage build: Stage 1 (Node.js → build frontend), Stage 2 (Python → serve all)
- Final image based on `python:3.12-slim`
- Install `gcloud` CLI in final image
- Copy built frontend to a `static/` directory served by FastAPI
- Keep image under 500MB
- Run as non-root user
- Use `.dockerignore` to exclude unnecessary files

### setup.sh rules

- Must be POSIX-compatible shell (#!/bin/bash)
- Must be idempotent (safe to run multiple times)
- Must check prerequisites before starting
- Must use colors for output (green=success, red=error, yellow=warning, blue=info)
- Must ask for confirmation before destructive operations
- Must handle Ctrl+C gracefully
- Must work in Google Cloud Shell environment
- Subcommands: `--remove`, `--grant-on PROJECT_ID`, `--grant-on-org ORG_ID`, `--help`. Routed by a `case` block in `main()`. Add new subcommands the same way — don't fork the deploy flow.
- IAM bindings should run in parallel (background subshells + `wait`) when there are more than 3; serial bindings stall noticeably at scale.
- Region default is hardcoded to `asia-south1` — do NOT inherit `gcloud config get-value compute/region` (Cloud Shell often defaults that to us-central1 and the prompt would lie about the actual default).
- `setup.sh` always builds from source via `gcloud builds submit`. The pre-built image option was removed because the GitLab registry was private to a specific account, so almost every cloner fell through to the build path anyway. Don't reintroduce a pre-built image path unless you publish to a public, auth-free registry (e.g. Google Artifact Registry public repo).

### Customer hand-off pattern

This tool is built to be handed to customers by Google Cloud engineers. The deploy SA only has permissions on the deploy project; scanning anything else requires explicit grants. When designing new features:

- Assume the deploy project and the scan target project are different.
- Surface permission errors with the exact `gcloud` command to fix them (see the pre-flight validation endpoint as a model).
- Don't silently rely on `gcloud config get-value project` or the deployer's identity — the SA is the one doing work at scan time.
- Failure modes should be measured in seconds, not minutes (see the 403-storm short-circuit).

---

## Testing

### Backend tests

```bash
cd backend
pytest -v --cov=backend
```

- Use `pytest` with `pytest-asyncio` for async tests
- Mock all GCP API calls — never make real API calls in tests
- Use fixtures for common resources (compliant/non-compliant)
- Test both the check logic AND the fix command output
- Aim for >80% coverage on check modules

### Frontend tests

```bash
cd frontend
npm run test
```

- Use Vitest + React Testing Library
- Test component rendering and user interactions
- Mock API calls with MSW (Mock Service Worker)
- Test wizard flow end-to-end
- Test finding display with various data states

---

## Git Workflow

- **Branch naming**: `feature/{description}`, `fix/{description}`, `check/{service}-{number}`
- **Commit messages**: Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`)
- **PR descriptions**: Include check IDs for new checks, screenshots for UI changes
- **No force pushes** to `main`
- **Squash merge** for feature branches

---

## Common Tasks Reference

| Task | What to do |
|------|-----------|
| Add a new check | Follow "Writing a New Check" section above |
| Add a new service category | Create folder in `backend/checks/`, add to category enum |
| Add a new API endpoint | Add route in `backend/api/routes/`, add to router in `main.py` |
| Add a new UI page | Add component in `frontend/src/pages/`, add route in `App.tsx` |
| Add a new UI component | Place in appropriate subfolder of `frontend/src/components/` |
| Update the check engine | Modify `backend/core/engine.py` — be careful, affects all checks |
| Add a new export format | Add handler in `backend/utils/report_generator.py` |
| Modify the setup script | Edit `setup.sh` — test in Cloud Shell before merging |

---

## Security Rules

1. **No credentials in code**: Use environment variables and service accounts only.
2. **No write operations**: Never execute `gcloud` commands that create, update, or delete resources.
3. **Sanitize all output**: Resource names may contain sensitive data — don't log full resource contents.
4. **Validate inputs**: All user inputs (project IDs, org IDs) must be validated against regex patterns.
5. **No eval/exec**: Never dynamically execute code from user input or GCP responses.
6. **Dependency pinning**: All dependencies in `requirements.txt` and `package.json` must have pinned versions.

---

## Performance Guidelines

1. **Parallel checks**: The engine runs checks concurrently within a category (configurable limit).
2. **Stream results**: Use WebSocket to stream findings to the UI as they're discovered.
3. **Respect GCP quotas**: Implement exponential backoff. Default 10 concurrent gcloud calls.
4. **Don't buffer large datasets**: Process and emit findings one at a time.
5. **Cache resource lists**: If multiple checks need the same data (e.g., list of instances), cache the gcloud call result within a scan session.
