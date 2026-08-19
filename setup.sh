#!/bin/bash
# =============================================================================
# Democratized Reviewer — High-Tech Setup Script
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Visual Engine & Styling
# ---------------------------------------------------------------------------
# Reset
NC='\033[0m'       # Text Reset

# High-Tech Palette
P_PRIMARY='\033[1;32m'    # Neon Green (Success/Highlight)
P_SECONDARY='\033[1;34m'  # Electric Blue (Headers/Info)
P_TEXT='\033[1;37m'       # Bright White (Main Text)
P_WARN='\033[1;33m'       # Yellow (Warnings)
P_ERROR='\033[1;31m'      # Red (Errors)
P_DIM='\033[0;37m'        # Dim White (Subtext)

# Helpers
# typewriter used to print one char at a time with sleep delays. That was ~3-5s
# of pure waste per script run with no useful information conveyed. Now it just
# prints the line and exits — preserves call sites, drops the latency.
typewriter() {
  local text="$1"
  local color="${3:-$NC}"
  echo -e "${color}${text}${NC}"
}

box_print() {
  local s="$*"
  local len=${#s}
  local width=$((len + 4))
  local color=$P_SECONDARY
  
  echo -e "$color"
  printf "┌"
  for ((i=0; i<width-2; i++)); do printf "─"; done
  printf "┐\n"
  printf "│ $s │\n"
  printf "└"
  for ((i=0; i<width-2; i++)); do printf "─"; done
  printf "┘$NC\n"
}

# Status indicators (Simple & Safe)
status_done() { echo -e "${P_PRIMARY}   [OK]${NC} $1"; }
status_fail() { echo -e "${P_ERROR}   [!!]${NC} $1"; }
status_wait() { echo -ne "${P_SECONDARY}   [..]${NC} $1\r"; }

confirm() {
  local msg="$1"
  echo ""
  read -rp "$(echo -e ${P_WARN}"     ${msg} [Y/n]: "${NC})" response
  if [[ "$response" != [yY]* && "$response" != "" ]]; then
     return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
print_banner() {
  clear

  # 2. Google Cloud brand mark.
  #
  # The 4-color square uses ▀ (upper-half block). Setting FG=color1 and
  # BG=color2 on a ▀ glyph paints the top half color1 and the bottom half
  # color2 in a single terminal cell. Two adjacent cells with different
  # color pairs gives the iconic Google 2×2 square in ONE text row:
  #   top-left blue · top-right red · bottom-left yellow · bottom-right green
  # That's the actual Google Cloud icon, not a hand-aligned multi-color
  # ASCII (the previous version had broken column alignment across colors).
  local CB='\033[1;34m'  # Blue
  local CR='\033[1;31m'  # Red
  local CY='\033[1;33m'  # Yellow
  local CG='\033[1;32m'  # Green
  local CW='\033[1;37m'  # Bright white
  local MARK_L='\033[34;43m▀▀▀\033[0m'   # blue top  / yellow bottom
  local MARK_R='\033[31;42m▀▀▀\033[0m'   # red top   / green bottom

  echo ""
  # "Google" with each letter rendered in its real Google brand color
  # (G blue · o red · o yellow · g blue · l green · e red). "Cloud" in white.
  printf "   %b%b   %bG%bo%bo%bg%bl%be%b %bCloud%b  ·  %bCloud Posture Audit%b\n" \
    "$MARK_L" "$MARK_R" \
    "$CB" "$CR" "$CY" "$CB" "$CG" "$CR" "$NC" \
    "$CW" "$NC" \
    "$CW" "$NC"
  echo -e "${P_DIM}   ────────────────────────────────────────────────────────────${NC}"
  echo -e "${P_DIM}   234 checks · 28 service areas · viewer-only · gemini-assisted${NC}"
  echo ""

  echo -e "${P_SECONDARY}   ${P_PRIMARY}●${P_SECONDARY}  SYSTEM READY  ·  initializing deployment sequence...${NC}"
  echo ""
}

STEP_COUNT=1
step() {
  echo ""
  echo -e "${P_SECONDARY}:: PHASE 0${STEP_COUNT} :: ${P_TEXT}$1${NC}"
  echo -e "${P_DIM}----------------------------------------${NC}"
  # set -u: post-increment of unset var triggers an error, so initialize via +=
  STEP_COUNT=$((STEP_COUNT + 1))
}

# Persistent state directory (survives different CWDs across runs)
STATE_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/democratized-reviewer"
mkdir -p "$STATE_DIR"
ORG_POLICY_STAMP="$STATE_DIR/org_policy_overridden"
ORG_POLICY_SNAPSHOT="$STATE_DIR/org_policy_original.json"
DEPLOY_STATE_FILE="$STATE_DIR/deploy_state.env"

# Defaults to satisfy set -u for vars that may not be set in --remove path
DEPLOY_PROJECT="${DEPLOY_PROJECT:-}"
CURRENT_PROJECT="${CURRENT_PROJECT:-}"
ACTIVE_ACCOUNT="${ACTIVE_ACCOUNT:-}"
ORG_ID="${ORG_ID:-}"
REGION="${REGION:-}"
OVERRIDE_ORG_POLICY="${OVERRIDE_ORG_POLICY:-false}"
# True once the service has been made publicly reachable (either via the
# org-policy override path or the post-deploy "Grant public access" prompt).
# Drives the access section in print_summary.
IS_PUBLIC="${IS_PUBLIC:-false}"
SCAN_SCOPE="${SCAN_SCOPE:-project}"
TARGET_ID="${TARGET_ID:-}"
FALLBACK_USER_EMAIL="${FALLBACK_USER_EMAIL:-}"
SA_EMAIL="${SA_EMAIL:-}"
SA_NAME="${SA_NAME:-}"
CREATE_SA="${CREATE_SA:-false}"
IMAGE="${IMAGE:-}"
# Whether Vertex AI / Gemini features are enabled for the deployed app.
# Decided in enable_apis based on Vertex AI API status + a user prompt.
# Drives: aiplatform.user role grant, DR_GEMINI_ENABLED env var, and the
# /health flag the frontend reads to hide the Explain / Cost Saving UI.
GEMINI_ENABLED="${GEMINI_ENABLED:-false}"
DATA_BUCKET="${DATA_BUCKET:-}"
# Space-separated lists of roles actually bound this run — persisted so
# --remove revokes exactly what was granted, no more and no less.
PROJECT_ROLES_GRANTED="${PROJECT_ROLES_GRANTED:-}"
ORG_ROLES_GRANTED="${ORG_ROLES_GRANTED:-}"

info()    { echo -e "${P_SECONDARY}   >>${NC} ${1}"; }
warn()    { echo -e "${P_WARN}   [!] WARNING:${NC} ${1}"; }
error()   { echo -e "${P_ERROR}   [X] CRITICAL ERROR:${NC} ${1}"; }

# Teardown must target what deploy actually created — guessing the region at
# --remove time strands a min-instances=1 Cloud Run service in any region
# other than the default. Rewritten whole after each phase so an aborted
# install still leaves an accurate record for --remove.
save_deploy_state() {
  cat > "$DEPLOY_STATE_FILE" <<EOF
DR_STATE_PROJECT='${DEPLOY_PROJECT}'
DR_STATE_REGION='${REGION}'
DR_STATE_SA_EMAIL='${SA_EMAIL}'
DR_STATE_BUCKET='${DATA_BUCKET}'
DR_STATE_ORG_ID='${ORG_ID}'
DR_STATE_PROJECT_ROLES='${PROJECT_ROLES_GRANTED}'
DR_STATE_ORG_ROLES='${ORG_ROLES_GRANTED}'
EOF
}

# Cleanup on Ctrl+C
cleanup_trap() {
  echo -e "\n${P_WARN}>> SEQUENCE ABORTED BY USER.${NC}"
  exit 130
}
trap cleanup_trap INT TERM

# ---------------------------------------------------------------------------
# Logic
# ---------------------------------------------------------------------------

check_prerequisites() {
  step "PREREQUISITE CHECKS"
  
  if command -v gcloud &> /dev/null; then
    status_done "gcloud CLI detected"
  else
    status_fail "gcloud CLI missing"
    error "Install gcloud SDK to proceed."
    exit 1
  fi

  # Cloud Shell exposes the user's identity via the metadata server even
  # before the "Authorize Cloud Shell" popup is clicked, so `gcloud auth list`
  # works where `gcloud config get-value account` may not. Try in that order.
  ACTIVE_ACCOUNT=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | head -n 1)
  if [[ -z "$ACTIVE_ACCOUNT" ]]; then
    ACTIVE_ACCOUNT=$(gcloud config get-value account 2>/dev/null || echo "")
  fi
  # Some gcloud versions echo the literal "(unset)" placeholder when no
  # account is set — treat as empty.
  [[ "$ACTIVE_ACCOUNT" == "(unset)" ]] && ACTIVE_ACCOUNT=""

  if [[ -n "$ACTIVE_ACCOUNT" ]]; then
    status_done "Identity: ${ACTIVE_ACCOUNT}"
  elif gcloud auth print-access-token >/dev/null 2>&1; then
    # Last-ditch: a token mints OK, so gcloud has working credentials even
    # though neither account-listing call surfaced an email.
    ACTIVE_ACCOUNT="implicit-auth-session"
    status_done "Identity: Implicit Auth"
  else
    status_fail "Identity verification failed"
    echo ""
    if [[ "${CLOUD_SHELL:-}" == "true" ]]; then
      echo -e "${P_ERROR}   This Cloud Shell session has no gcloud credentials. Fix:${NC}"
      echo ""
      echo -e "${P_TEXT}     1. Click 'Authorize' in the popup if it appears at the top of${NC}"
      echo -e "${P_TEXT}        the screen (Cloud Shell asks the first time you use gcloud).${NC}"
      echo -e "${P_TEXT}     2. If no popup appears, run this in the Cloud Shell terminal —${NC}"
      echo -e "${P_TEXT}        always works (URL flow):${NC}"
      echo ""
      echo -e "${P_SECONDARY}        gcloud auth login${NC}"
      echo ""
      echo -e "${P_TEXT}     Then re-run:  ./setup.sh${NC}"
    else
      echo -e "${P_ERROR}   No active gcloud account. Fix:${NC}"
      echo ""
      echo -e "${P_SECONDARY}     gcloud auth login${NC}"
      echo ""
      echo -e "${P_TEXT}   Then re-run:  ./setup.sh${NC}"
    fi
    exit 1
  fi

  CURRENT_PROJECT=$(gcloud config get-value project 2>/dev/null || echo "")
  if [[ -n "$CURRENT_PROJECT" ]]; then
    status_done "Active Project: ${CURRENT_PROJECT}"
  fi
}

prompt_configuration() {
  step "DEPLOYMENT CONFIGURATION"

  while true; do
    # Auto-detect
    if [[ -z "$DEPLOY_PROJECT" ]]; then
        DEPLOY_PROJECT="${CURRENT_PROJECT:-}"
    fi
    
    if [[ -z "$DEPLOY_PROJECT" ]]; then
      echo -e "${P_WARN}     No active project detected.${NC}"
      read -rp "   > Enter Target Project ID: " DEPLOY_PROJECT
    fi
    
    if [[ -z "$DEPLOY_PROJECT" ]]; then
       error "Target Project ID is mandatory."
       continue
    fi

    TARGET_ID="$DEPLOY_PROJECT"
    SCAN_SCOPE="project"
    
    box_print "TARGET: $DEPLOY_PROJECT"
    echo ""

    # Region — the project owner runs everything in asia-south1, so that's
    # the hardcoded default. We deliberately do NOT inherit gcloud's
    # compute/region setting because Cloud Shell projects often default
    # that to us-central1 and the prompt would silently show the wrong
    # default. User can still type any valid Cloud Run region at the prompt.
    # Skip the (~2s) `gcloud run regions list` API call when the user
    # accepts the default — only validate custom input.
    if [[ -z "$REGION" ]]; then
      DEFAULT_REGION="asia-south1"
      while true; do
        read -rp "$(echo -e ${P_WARN}"     Cloud Run region [${DEFAULT_REGION}]: "${NC})" REGION_INPUT
        REGION="${REGION_INPUT:-$DEFAULT_REGION}"
        if [[ -z "$REGION_INPUT" ]]; then
          # Accepted the default — don't pay for region validation.
          break
        fi
        if [[ -z "${_RUN_REGIONS:-}" ]]; then
          _RUN_REGIONS=$(gcloud run regions list --format="value(locationId)" 2>/dev/null || echo "")
        fi
        if [[ -z "$_RUN_REGIONS" ]]; then
          warn "Could not validate region against Cloud Run regions API; proceeding."
          break
        fi
        if echo "$_RUN_REGIONS" | grep -qx "$REGION"; then
          break
        fi
        warn "Region '${REGION}' is not a valid Cloud Run region. Try one of:"
        echo "$_RUN_REGIONS" | head -10 | sed 's/^/       /'
      done
    fi
    info "Region: ${REGION}"

    # Service Account
    SA_NAME="democratized-reviewer-sa"
    SA_EMAIL="${SA_NAME}@${DEPLOY_PROJECT}.iam.gserviceaccount.com"
    
    if gcloud iam service-accounts describe "${SA_EMAIL}" --project="${DEPLOY_PROJECT}" &>/dev/null; then
      info "Found Service Entity: ${SA_NAME}"
      CREATE_SA=false
    else
      info "Service Entity missing. Will create: ${SA_NAME}"
      CREATE_SA=true
    fi

    # Org Policy check
    ORG_POLICY_CONSTRAINT="constraints/iam.allowedPolicyMemberDomains"

    echo -e "${P_SECONDARY}   >> VALIDATING GOVERNANCE POLICIES...${NC}"

    # Only enable the orgpolicy/CRM APIs if they're actually missing — saves
    # ~1-2s on the common case where they're already on.
    _ENABLED_NOW=$(gcloud services list --enabled --project="$DEPLOY_PROJECT" \
      --filter="config.name:(orgpolicy.googleapis.com OR cloudresourcemanager.googleapis.com)" \
      --format="value(config.name)" 2>/dev/null || echo "")
    _TO_ENABLE=()
    echo "$_ENABLED_NOW" | grep -q "^orgpolicy.googleapis.com$" || _TO_ENABLE+=(orgpolicy.googleapis.com)
    echo "$_ENABLED_NOW" | grep -q "^cloudresourcemanager.googleapis.com$" || _TO_ENABLE+=(cloudresourcemanager.googleapis.com)
    if [[ ${#_TO_ENABLE[@]} -gt 0 ]]; then
      gcloud services enable "${_TO_ENABLE[@]}" --project="$DEPLOY_PROJECT" --quiet >/dev/null 2>&1 || true
    fi

    # We use --effective to see the final policy applied to this project (inherited or local)
    if POLICY_OUTPUT=$(gcloud org-policies describe "$ORG_POLICY_CONSTRAINT" --project="$DEPLOY_PROJECT" --effective --format="json"); then

       # Parse JSON properly — check if allowAll is true anywhere in the policy rules
       if command -v jq &>/dev/null; then
         ALLOW_ALL=$(echo "$POLICY_OUTPUT" | jq -r '.. | .allowAll? // empty' 2>/dev/null | grep -m1 'true' || echo "")
       else
         ALLOW_ALL=$(echo "$POLICY_OUTPUT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    def find_allow_all(obj):
        if isinstance(obj, dict):
            if obj.get('allowAll') is True: return True
            return any(find_allow_all(v) for v in obj.values())
        if isinstance(obj, list):
            return any(find_allow_all(v) for v in obj)
        return False
    print('true' if find_allow_all(data) else '')
except: print('')
" 2>/dev/null)
       fi

       if [[ -n "$ALLOW_ALL" ]]; then
          status_done "Organization Policy: $ORG_POLICY_CONSTRAINT is already [OPEN]"
          OVERRIDE_ORG_POLICY=false
       else
          warn "Organization Policy: $ORG_POLICY_CONSTRAINT is [RESTRICTED]"
          info "This constraint prevents granting access to users outside your domain."
          
          warn "Overriding this policy + granting allUsers exposes the service to the public internet."
          warn "Cloud Run IAM is the default access gate — most users should answer NO here."
          if confirm "Override policy and grant public (allUsers) invoker access?"; then
             info "Snapshotting existing policy before override..."
             # Save the original (effective) policy so we can restore it on --remove
             gcloud org-policies describe "$ORG_POLICY_CONSTRAINT" --project="$DEPLOY_PROJECT" \
                 --format=json > "$ORG_POLICY_SNAPSHOT" 2>/dev/null || echo "{}" > "$ORG_POLICY_SNAPSHOT"
             OVERRIDE_ORG_POLICY=true
             IS_PUBLIC=true
             echo "true" > "$ORG_POLICY_STAMP"
          else
             info "Keeping restrictive policy. Access will require Cloud Run IAM (gcloud run services proxy)."
             OVERRIDE_ORG_POLICY=false
             rm -f "$ORG_POLICY_STAMP"
          fi
       fi
    else
       # Command failed (e.g. API not enabled, or not in an Org)
       info "Organization Policy: $ORG_POLICY_CONSTRAINT [NOT FOUND / INHERITED]"
       info "Proceeding with default project configuration."
       OVERRIDE_ORG_POLICY=false
    fi

    # Access
    FALLBACK_USER_EMAIL=""
    if [[ "$ACTIVE_ACCOUNT" != "implicit-auth"* && -n "$ACTIVE_ACCOUNT" ]]; then
      FALLBACK_USER_EMAIL="$ACTIVE_ACCOUNT"
    fi
    
    # Confirm
    if confirm "Initialize deployment configuration?"; then
        break
    else
        echo -e "${P_WARN}   >> Configuration rejected. Resetting...${NC}"
        DEPLOY_PROJECT=""
    fi
  done
}

setup_service_account() {
  step "SERVICE ACCOUNT & IAM ROLES"

  if [[ "$CREATE_SA" == true ]]; then
    status_wait "Creating Service Account..."
    gcloud iam service-accounts create "${SA_NAME}" \
      --display-name="Democratized Reviewer Service Account" \
      --project="${DEPLOY_PROJECT}" --quiet >/dev/null 2>&1
    echo ""
    status_done "Service Account Created"
  fi

  # Read-only roles. roles/viewer covers most resource reads; the extras below
  # are services whose viewer permissions aren't subsumed by roles/viewer.
  # roles/aiplatform.user is granted LATER (only if the user opts in to
  # Gemini features during enable_apis) — not here.
  ROLES=(
    roles/viewer
    roles/iam.securityReviewer
    roles/cloudasset.viewer
    roles/orgpolicy.policyViewer
    roles/recommender.viewer
    roles/billing.viewer
  )

  info "Required Roles:"
  for role in "${ROLES[@]}"; do
    echo -e "     - ${role}"
  done

  if confirm "Grant these read-only roles to ${SA_EMAIL}?"; then
      # Fire all bindings in parallel — each one is a 1-3s round-trip and
      # they're independent, so 6 serial calls (~12s) become ~3s wall-clock.
      # Capture stderr (not just exit code) so partial-failure cases produce
      # a meaningful summary instead of silent FAILs.
      info "Binding ${#ROLES[@]} roles in parallel..."
      local _pids=() _logdir
      _logdir="$(mktemp -d -t dr-iam.XXXXXX)"
      for role in "${ROLES[@]}"; do
        (
          local _err
          if _err=$(gcloud projects add-iam-policy-binding "${TARGET_ID}" \
              --member="serviceAccount:${SA_EMAIL}" \
              --role="${role}" \
              --condition=None --quiet 2>&1 >/dev/null); then
            echo "OK ${role}" > "${_logdir}/${role//\//_}"
          else
            # Persist the stderr so the post-loop summary can show the user
            # the actual error (typically PERMISSION_DENIED with the missing
            # role on the deployer's user account).
            { echo "FAIL ${role}"; echo "$_err"; } > "${_logdir}/${role//\//_}"
          fi
        ) &
        _pids+=($!)
      done
      wait "${_pids[@]}"
      local _failed_roles=()
      local _last_err=""
      for role in "${ROLES[@]}"; do
        local outcome
        outcome=$(cat "${_logdir}/${role//\//_}" 2>/dev/null || echo "FAIL ${role}")
        if [[ "$outcome" == OK* ]]; then
          status_done "Bound: ${role}"
          PROJECT_ROLES_GRANTED="${PROJECT_ROLES_GRANTED}${PROJECT_ROLES_GRANTED:+ }${role}"
        else
          status_fail "Failed to bind: ${role}"
          _failed_roles+=("${role}")
          # Keep the most-recent error message for the post-loop banner.
          _last_err=$(tail -n +2 "${_logdir}/${role//\//_}" 2>/dev/null | head -c 400)
        fi
      done
      rm -rf "$_logdir"

      # If any bindings failed, surface a clear remediation block. Most
      # common cause: the user running setup.sh lacks
      # roles/resourcemanager.projectIamAdmin (or roles/owner) on the
      # deploy project — so they can't grant viewer roles to the SA.
      if [[ ${#_failed_roles[@]} -gt 0 ]]; then
        echo ""
        warn "${#_failed_roles[@]} of ${#ROLES[@]} role bindings failed."
        if [[ -n "$_last_err" ]]; then
          echo -e "${P_DIM}     Sample error from a failed binding:${NC}"
          echo "$_last_err" | sed 's/^/       /'
          echo ""
        fi
        echo -e "${P_WARN}   Most likely cause:${NC} the account running this script"
        echo -e "   (${ACTIVE_ACCOUNT}) lacks ${P_DIM}roles/resourcemanager.projectIamAdmin${NC}"
        echo -e "   or ${P_DIM}roles/owner${NC} on project ${P_DIM}${DEPLOY_PROJECT}${NC}."
        echo ""
        echo -e "${P_WARN}   Fix:${NC} ask a Project Owner to either"
        echo -e "     1. Grant you ${P_DIM}roles/resourcemanager.projectIamAdmin${NC} on ${DEPLOY_PROJECT}, then re-run ./setup.sh, or"
        echo "     2. Run these bindings on your behalf (one per line, paste each):"
        # Same single-line rationale as print_summary's TIPS: avoid backslash
        # continuations because Cloud Shell copy/paste mangles them.
        for role in "${_failed_roles[@]}"; do
          echo -e "        ${P_DIM}gcloud projects add-iam-policy-binding ${DEPLOY_PROJECT} --member=serviceAccount:${SA_EMAIL} --role=${role} --condition=None${NC}"
        done
        echo ""
        warn "Continuing with partial permissions — some checks will fail at scan time."
      fi

      # Single `projects describe` (was two — parent.id + parent.type separately).
      # Export ORG_ID globally so it can be passed to the app.
      _PARENT_INFO=$(gcloud projects describe "${DEPLOY_PROJECT}" \
        --format="value(parent.id,parent.type)" 2>/dev/null || echo "")
      export ORG_ID="${_PARENT_INFO%%	*}"   # split on tab (gcloud's value separator)
      PARENT_TYPE="${_PARENT_INFO##*	}"

      if [[ "$PARENT_TYPE" == "organization" && -n "$ORG_ID" ]]; then
        echo ""
        info "Project ${DEPLOY_PROJECT} belongs to Organization ${ORG_ID}."
        info "Organization-wide checks (whole-org scans, org-scope project"
        info "enumeration) need the same read-only roles at the ORGANIZATION level:"
        for role in "${ROLES[@]}"; do
          echo -e "     - ${role}"
        done
        warn "This is BROADER than the project-scoped deployment you just confirmed:"
        warn "it gives ${SA_EMAIL} read access to EVERY project under org ${ORG_ID}."

        if confirm "Grant these roles at ORGANIZATION scope (org ${ORG_ID})?"; then
          info "Binding ${#ROLES[@]} org-level roles in parallel..."
          # Same parallel pattern for org-level bindings.
          local _org_pids=() _org_logdir
          _org_logdir="$(mktemp -d -t dr-iam-org.XXXXXX)"
          for role in "${ROLES[@]}"; do
            (
              if gcloud organizations add-iam-policy-binding "${ORG_ID}" \
                --member="serviceAccount:${SA_EMAIL}" \
                --role="${role}" \
                --condition=None --quiet >/dev/null 2>&1; then
                echo "OK" > "${_org_logdir}/${role//\//_}"
              else
                echo "FAIL" > "${_org_logdir}/${role//\//_}"
              fi
            ) &
            _org_pids+=($!)
          done
          wait "${_org_pids[@]}"
          ORG_ROLES_SUCCESS=true
          for role in "${ROLES[@]}"; do
            if [[ "$(cat "${_org_logdir}/${role//\//_}" 2>/dev/null)" == "OK" ]]; then
              ORG_ROLES_GRANTED="${ORG_ROLES_GRANTED}${ORG_ROLES_GRANTED:+ }${role}"
            else
              ORG_ROLES_SUCCESS=false
            fi
          done
          rm -rf "$_org_logdir"

          if [[ "$ORG_ROLES_SUCCESS" == true ]]; then
            status_done "Organization-level permissions established."
          else
            echo ""
            echo -e "${P_WARN}   [!] NOTE FOR ORG SCANS:${NC} Project-level permissions established."
            echo -e "       Automatic Organization-level assignment failed (Insufficient Permissions)."
            echo -e "       To scan your entire Organization, you must manually grant"
            echo -e "       'Viewer' and 'Cloud Asset Viewer' to ${SA_EMAIL}"
            echo -e "       at the Organization level via Cloud Console."
          fi
        else
          info "Skipping organization-level grants. Deployment stays project-scoped."
          info "Impact: org-wide checks (whole-org scans, org-scope project"
          info "enumeration) will have no data; project-scope checks are unaffected."
          info "Grant later at any time with:  ./setup.sh --grant-on-org ${ORG_ID}"
        fi
      else
        echo ""
        echo -e "${P_WARN}   [!] NOTE FOR ORG SCANS:${NC} Project is not directly under an Organization."
        echo -e "       Manual role assignment at the Org/Folder level may be required"
        echo -e "       for multi-project scanning."
      fi
  else
      warn "Skipping role assignment."
  fi
  save_deploy_state
  echo ""
}

enable_apis() {
  step "ENABLE REQUIRED APIs"

  # We only enable APIs that Democratized Reviewer itself needs to RUN.
  # APIs for scanned services are intentionally NOT enabled here — if you
  # don't use Spanner / Composer / Memorystore / etc., you don't want their
  # APIs flipped on just so a posture check can confirm what you already
  # know. The engine pre-skips checks for disabled APIs with the message
  # "Skipped: service not active in project (API disabled: <api>)".
  DEPLOY_APIS=(
    run.googleapis.com               # Cloud Run service hosting the app
    artifactregistry.googleapis.com  # Container image storage
    cloudbuild.googleapis.com        # Build pipeline (every setup runs `gcloud builds submit`)
    iam.googleapis.com               # Service account create / role binding
    cloudresourcemanager.googleapis.com  # Project metadata + IAM-policy reads
    cloudasset.googleapis.com        # Org-scope project enumeration
    serviceusage.googleapis.com      # The engine's enabled-API pre-skip needs this
    orgpolicy.googleapis.com         # Org-policy reads (IAM-012 + POST-001)
    recommender.googleapis.com       # POST-004 + BIL-006/007
  )

  # Vertex AI is opt-in — it's the only API that's purely about UI features
  # ("Gemini Intelligence" finding explanations + "Cost Saving" tab). Enabling
  # it bills the customer for Gemini token usage every time someone clicks
  # those buttons. We check separately, prompt only if it's off, and store
  # the user's choice in GEMINI_ENABLED for downstream steps.
  GEMINI_API="aiplatform.googleapis.com"

  # Informational only — services whose checks WILL skip cleanly if absent.
  # Listed in the post-deploy summary so the user knows what to opt into later.
  SCAN_OPTIONAL_APIS=(
    compute.googleapis.com           # GCE, networking, KMS-adjacent
    container.googleapis.com         # GKE
    storage.googleapis.com           # GCS
    sqladmin.googleapis.com          # Cloud SQL
    bigquery.googleapis.com          # BigQuery
    pubsub.googleapis.com            # Pub/Sub
    dataflow.googleapis.com          # Dataflow
    dataproc.googleapis.com          # Dataproc
    cloudkms.googleapis.com          # KMS
    secretmanager.googleapis.com     # Secret Manager
    cloudfunctions.googleapis.com    # Functions
    redis.googleapis.com             # Memorystore
    firestore.googleapis.com         # Firestore
    spanner.googleapis.com           # Spanner
    iap.googleapis.com               # IAP
    composer.googleapis.com          # Composer
    binaryauthorization.googleapis.com  # BinAuthz
    monitoring.googleapis.com        # Monitoring
    logging.googleapis.com           # Logging
    cloudbilling.googleapis.com      # Budgets
    notebooks.googleapis.com         # Vertex Workbench
    alloydb.googleapis.com           # AlloyDB
    appengine.googleapis.com         # App Engine
  )

  status_wait "Scanning API Status..."
  ENABLED_APIS=$(gcloud services list --project="${DEPLOY_PROJECT}" --enabled --format="value(config.name)" 2>/dev/null || true)
  echo ""

  MISSING_DEPLOY=()
  for api in "${DEPLOY_APIS[@]}"; do
    if ! echo "$ENABLED_APIS" | grep -q "^${api}$"; then
      MISSING_DEPLOY+=("$api")
    fi
  done

  if [[ ${#MISSING_DEPLOY[@]} -eq 0 ]]; then
    status_done "Deploy APIs already active."
  else
    warn "Deploy APIs missing (${#MISSING_DEPLOY[@]}): ${MISSING_DEPLOY[*]}"
    if confirm "Enable these deploy APIs? (required for the tool to install and run)"; then
        # Batch enable in a single call — gcloud parallelizes server-side and
        # this is ~3-5x faster than per-API serial calls. We give up
        # per-API progress for the speed; the failure path lists what's missing
        # afterward by re-checking the enabled set.
        info "Enabling ${#MISSING_DEPLOY[@]} APIs in one batch..."
        if gcloud services enable "${MISSING_DEPLOY[@]}" --project="${DEPLOY_PROJECT}" --quiet >/dev/null 2>&1; then
          status_done "All deploy APIs enabled"
        else
          warn "Batch enable returned non-zero — re-checking which ones landed..."
          ENABLED_AFTER=$(gcloud services list --project="${DEPLOY_PROJECT}" --enabled --format="value(config.name)" 2>/dev/null || true)
          for api in "${MISSING_DEPLOY[@]}"; do
            if echo "$ENABLED_AFTER" | grep -q "^${api}$"; then
              status_done "${api}"
            else
              status_fail "${api} (org policy may forbid enabling — enable manually)"
            fi
          done
        fi
    else
        warn "Skipping deploy-API enablement. Build/deploy steps may fail without them."
    fi
  fi

  # Report on scan-target APIs purely informationally — never enable.
  SCAN_DISABLED=()
  for api in "${SCAN_OPTIONAL_APIS[@]}"; do
    if ! echo "$ENABLED_APIS" | grep -q "^${api}$"; then
      SCAN_DISABLED+=("$api")
    fi
  done
  if [[ ${#SCAN_DISABLED[@]} -gt 0 ]]; then
    echo ""
    info "Service APIs not enabled on this project (${#SCAN_DISABLED[@]}):"
    for api in "${SCAN_DISABLED[@]}"; do
      echo "       - ${api}"
    done
    echo -e "${P_DIM}       Checks for these services will SKIP at scan time with reason"
    echo -e "       \"service not active in project\" — no findings, no fix needed.${NC}"
    echo -e "${P_DIM}       Enable any of them later if you start using the service:"
    echo -e "       gcloud services enable <api> --project=${DEPLOY_PROJECT}${NC}"
  else
    echo ""
    status_done "All known scan-target APIs are already active."
  fi

  # ---------- Vertex AI (Gemini) opt-in ----------
  echo ""
  if echo "$ENABLED_APIS" | grep -q "^${GEMINI_API}$"; then
    status_done "Vertex AI already enabled — Gemini Intelligence + Cost Saving tab available."
    GEMINI_ENABLED=true
    # Grant predict permission to the deploy SA (idempotent — gcloud is a no-op
    # if the binding already exists).
    if gcloud projects add-iam-policy-binding "${DEPLOY_PROJECT}" \
      --member="serviceAccount:${SA_EMAIL}" \
      --role="roles/aiplatform.user" --condition=None --quiet >/dev/null 2>&1; then
      PROJECT_ROLES_GRANTED="${PROJECT_ROLES_GRANTED}${PROJECT_ROLES_GRANTED:+ }roles/aiplatform.user"
      save_deploy_state
    else
      warn "Could not grant roles/aiplatform.user to ${SA_EMAIL} — Gemini calls may fail."
    fi
  else
    echo -e "${P_TEXT}   Vertex AI (Gemini) is OFF on ${DEPLOY_PROJECT}.${NC}"
    echo -e "${P_DIM}   Enabling it powers two optional UI features:${NC}"
    echo -e "${P_DIM}     - 'Gemini Intelligence' button on each finding (plain-English explain).${NC}"
    echo -e "${P_DIM}     - 'Cost Saving' tab on the Results page (Gemini prices each resource).${NC}"
    echo -e "${P_DIM}   Both bill Gemini tokens to ${DEPLOY_PROJECT} when used.${NC}"
    echo -e "${P_DIM}   You can skip this now; the buttons will be hidden in the UI. Enabling${NC}"
    echo -e "${P_DIM}   it later just needs:  gcloud services enable ${GEMINI_API} \\${NC}"
    echo -e "${P_DIM}                          --project=${DEPLOY_PROJECT}${NC}"
    echo ""
    if confirm "Enable Vertex AI now for Gemini Intelligence + Cost Saving?"; then
      status_wait "Enabling ${GEMINI_API}..."
      if gcloud services enable "${GEMINI_API}" --project="${DEPLOY_PROJECT}" --quiet >/dev/null 2>&1; then
        echo ""
        status_done "Vertex AI enabled"
        GEMINI_ENABLED=true
        if gcloud projects add-iam-policy-binding "${DEPLOY_PROJECT}" \
          --member="serviceAccount:${SA_EMAIL}" \
          --role="roles/aiplatform.user" --condition=None --quiet >/dev/null 2>&1; then
          PROJECT_ROLES_GRANTED="${PROJECT_ROLES_GRANTED}${PROJECT_ROLES_GRANTED:+ }roles/aiplatform.user"
          save_deploy_state
        else
          warn "Could not grant roles/aiplatform.user to ${SA_EMAIL} — Gemini calls may fail."
        fi
      else
        echo ""
        status_fail "Could not enable ${GEMINI_API} (org policy may forbid). Continuing without Gemini."
        GEMINI_ENABLED=false
      fi
    else
      info "Skipping Vertex AI. Gemini Intelligence + Cost Saving will be hidden in the UI."
      GEMINI_ENABLED=false
    fi
  fi
}

setup_infrastructure() {
  step "ARTIFACT REGISTRY & STORAGE BUCKET"

  # AR
  AR_REPO="democratized-reviewer"
  AR_LOCATION="${REGION}"
  
  if ! gcloud artifacts repositories describe "${AR_REPO}" --location="${AR_LOCATION}" --project="${DEPLOY_PROJECT}" &>/dev/null; then
     info "Creating Artifact Registry..."
     gcloud artifacts repositories create "${AR_REPO}" --repository-format=docker --location="${AR_LOCATION}" --project="${DEPLOY_PROJECT}" --quiet >/dev/null 2>&1
     status_done "Registry Created"
  else
     status_done "Registry Online"
  fi
  
  IMAGE="${AR_LOCATION}-docker.pkg.dev/${DEPLOY_PROJECT}/${AR_REPO}/app:latest"

  # GCS
  DATA_BUCKET="democratized-reviewer-${DEPLOY_PROJECT}-data"
  if ! gcloud storage buckets describe "gs://${DATA_BUCKET}" --project="${DEPLOY_PROJECT}" &>/dev/null; then
     info "Creating Storage Bucket..."
     gcloud storage buckets create "gs://${DATA_BUCKET}" --location="${REGION}" --project="${DEPLOY_PROJECT}" --uniform-bucket-level-access --quiet >/dev/null 2>&1
     status_done "Storage Node Created"
  else
     status_done "Storage Node Online"
  fi

  gcloud storage buckets add-iam-policy-binding "gs://${DATA_BUCKET}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/storage.objectAdmin" --quiet >/dev/null 2>&1

  # Lifecycle: auto-delete scan persistence > 90 days old so the bucket doesn't
  # grow unbounded. The app stores scans under scans/*.json (see ScanStore).
  local lifecycle_file
  lifecycle_file="$(mktemp -t dr-lifecycle.XXXXXX.json)"
  cat > "$lifecycle_file" <<EOF
{
  "lifecycle": {
    "rule": [
      {
        "action": {"type": "Delete"},
        "condition": {"age": 90, "matchesPrefix": ["scans/"]}
      }
    ]
  }
}
EOF
  if gcloud storage buckets update "gs://${DATA_BUCKET}" \
       --lifecycle-file="$lifecycle_file" --quiet >/dev/null 2>&1; then
    status_done "Lifecycle rule applied (scans/ older than 90d auto-deleted)"
  else
    warn "Could not apply lifecycle rule to scan bucket (continuing without it)"
  fi
  rm -f "$lifecycle_file"
  save_deploy_state
}

build_and_deploy() {
  step "BUILD & DEPLOY TO CLOUD RUN"

  if ! confirm "Initiate Build & Deploy Sequence?"; then
      warn "Deployment sequence aborted by user."
      exit 0
  fi
  
  echo -e "${P_PRIMARY}   >> Deployment parameters initialized.${NC}"

  # Always build fresh from the source in this clone. The previous pre-built
  # path pulled an image from registry.gitlab.com — fragile because the
  # registry is private to a specific account and there's no auth in plain
  # Cloud Shell, so the "fallback to build" path fired for almost every user
  # anyway. Removing the option also guarantees the deployed image always
  # matches the source the user just cloned (no stale-pre-built surprises).
  info "Building image from source via Cloud Build (streaming logs)..."
  if gcloud builds submit --tag "${IMAGE}" --project="${DEPLOY_PROJECT}"; then
    status_done "Compilation Successful"
  else
    status_fail "Compilation Failed"
    exit 1
  fi

  info "Deploying to Cloud Run (Streaming Logs)..."

  # No Basic Auth — Cloud Run IAM handles access control.
  # The UI is launched directly without a password prompt.
  ENV_VARS="DR_SCAN_SCOPE=${SCAN_SCOPE}"
  ENV_VARS="${ENV_VARS},DR_TARGET_ID=${TARGET_ID}"
  ENV_VARS="${ENV_VARS},DR_LOG_LEVEL=INFO"
  ENV_VARS="${ENV_VARS},DR_SA_EMAIL=${SA_EMAIL}"
  ENV_VARS="${ENV_VARS},DR_GCS_EXPORT_BUCKET=${DATA_BUCKET}"
  ENV_VARS="${ENV_VARS},DR_GEMINI_ENABLED=${GEMINI_ENABLED}"
  # Cloud Run injects K_SERVICE but not the region, and the UI needs it to
  # print a correct "read the logs" command for this deployment.
  ENV_VARS="${ENV_VARS},DR_REGION=${REGION}"
  
  if [[ -n "$ORG_ID" ]]; then
    ENV_VARS="${ENV_VARS},DR_DEFAULT_ORG_ID=${ORG_ID}"
  fi

  # Org policy override (only if user explicitly opted in)
  if [[ "$OVERRIDE_ORG_POLICY" == true ]]; then
    local policy_file
    policy_file="$(mktemp -t dr-policy.XXXXXX.yaml)"
    cat > "$policy_file" <<EOF
name: projects/${DEPLOY_PROJECT}/policies/constraints/iam.allowedPolicyMemberDomains
spec:
  rules:
  - allowAll: true
EOF
    gcloud org-policies set-policy "$policy_file" --project="${DEPLOY_PROJECT}" --quiet >/dev/null 2>&1 || true
    rm -f "$policy_file"
  fi

  # State is in-memory (ScanStore, WebSocket queues, rate limiter).
  # Pin to a single instance to keep that consistent.
  # Memory + concurrency tuning: 1Gi was OOM'ing on real customer projects
  # because 234 checks × ~5MB of in-flight gcloud JSON each can push past
  # 1GB peak when many checks run concurrently. 2Gi + max_concurrent_checks=5
  # gives ~3x headroom and keeps CPU under 100%. Bump again if scanning very
  # large orgs.
  DEPLOY_FLAGS=(
    --image "${IMAGE}"
    --platform managed
    --region "${REGION}"
    --service-account "${SA_EMAIL}"
    --set-env-vars="${ENV_VARS},DR_MAX_CONCURRENT_CHECKS=5"
    --memory=2Gi
    --cpu=2
    --cpu-boost
    --timeout=3600
    --concurrency=80
    --min-instances=1
    --max-instances=1
    --project="${DEPLOY_PROJECT}"
  )
  if [[ "$OVERRIDE_ORG_POLICY" == true ]]; then
    DEPLOY_FLAGS+=(--allow-unauthenticated)
  else
    DEPLOY_FLAGS+=(--no-allow-unauthenticated)
  fi

  if gcloud run deploy democratized-reviewer "${DEPLOY_FLAGS[@]}"; then
      status_done "Service Endpoint Active"
      save_deploy_state
  else
      status_fail "Deployment Failed"
      exit 1
  fi

  # Public access (only when the user explicitly overrode the policy)
  if [[ "$OVERRIDE_ORG_POLICY" == true ]]; then
     gcloud run services add-iam-policy-binding democratized-reviewer \
      --member="allUsers" --role="roles/run.invoker" \
      --region="${REGION}" --project="${DEPLOY_PROJECT}" --quiet >/dev/null 2>&1 || true
  fi

  # Always grant invoker to the deploying user so they can reach the service via IAM
  if [[ -n "$FALLBACK_USER_EMAIL" ]]; then
    gcloud run services add-iam-policy-binding democratized-reviewer \
      --member="user:${FALLBACK_USER_EMAIL}" --role="roles/run.invoker" \
      --region="${REGION}" --project="${DEPLOY_PROJECT}" --quiet >/dev/null 2>&1 || true
  fi
}

# ---------------------------------------------------------------------------
# Optional: grant public access after deploy
# ---------------------------------------------------------------------------
# Some users want to bypass the `gcloud run services proxy` step and just
# share a URL. This phase offers to grant allUsers → roles/run.invoker AFTER
# the deploy completes (in addition to the build-time org-policy override
# path). Verifies via curl with retries because IAM propagation typically
# takes 10–60s.
maybe_grant_public_access() {
  # Already public via the org-policy override branch — nothing to do.
  if [[ "$IS_PUBLIC" == true ]]; then
    return
  fi

  step "PUBLIC ACCESS (OPTIONAL)"

  echo ""
  warn "Default: service is PRIVATE (Cloud Run IAM). Reach it via:"
  echo -e "     ${P_DIM}gcloud run services proxy democratized-reviewer --region ${REGION} --project ${DEPLOY_PROJECT}${NC}"
  echo -e "     then ${P_DIM}http://localhost:8080${NC}"
  echo ""
  warn "Alternative: grant allUsers the invoker role so anyone with the URL"
  warn "can browse the dashboard. Convenient for demos / one-off scans; less"
  warn "safe than the proxy. You can revoke at any time."
  echo ""

  if ! confirm "Grant public (allUsers) access now?"; then
    info "Keeping service private. Use the proxy command above to access."
    return
  fi

  status_wait "Granting allUsers → roles/run.invoker..."
  local _err
  if _err=$(gcloud run services add-iam-policy-binding democratized-reviewer \
        --member=allUsers --role=roles/run.invoker \
        --region="${REGION}" --project="${DEPLOY_PROJECT}" --quiet 2>&1 >/dev/null); then
    echo ""
    status_done "IAM binding added. Waiting for propagation..."
  else
    echo ""
    status_fail "Could not grant allUsers (likely org policy restriction):"
    echo "$_err" | head -c 400 | sed 's/^/       /'
    echo ""
    warn "If the org enforces iam.allowedPolicyMemberDomains, re-run ./setup.sh"
    warn "and accept the org-policy override prompt in Phase 02."
    return
  fi

  # Fetch the real service URL once.
  local svc_url
  svc_url=$(gcloud run services describe democratized-reviewer \
    --platform managed --region "${REGION}" --project="${DEPLOY_PROJECT}" \
    --format="value(status.url)" 2>/dev/null || echo "")
  if [[ -z "$svc_url" ]]; then
    warn "Could not read service URL — skipping verification. Test manually:"
    echo -e "     ${P_DIM}curl -i https://<your-cloud-run-url>/api/v1/health${NC}"
    IS_PUBLIC=true
    return
  fi

  # Poll /api/v1/health WITHOUT an auth header — that proves anonymous
  # access works (the whole point of allUsers grant). IAM propagation can
  # take ~10-60s so we retry with backoff.
  local attempt code
  for attempt in 1 2 3 4 5 6; do
    status_wait "Verifying public access (attempt ${attempt}/6)..."
    code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 \
      "${svc_url}/api/v1/health" 2>/dev/null || echo "000")
    if [[ "$code" == "200" ]]; then
      echo ""
      status_done "Public access verified: GET /api/v1/health → 200 OK"
      info "Service URL: ${svc_url}"
      IS_PUBLIC=true
      return
    fi
    sleep 10
  done
  echo ""
  warn "Binding added but /api/v1/health returned ${code} after ~60s of retries."
  warn "Usually just IAM propagation lag. Verify in a minute:"
  echo -e "     ${P_DIM}curl -i ${svc_url}/api/v1/health${NC}"
  # Still mark as public — the binding succeeded; propagation will catch up.
  IS_PUBLIC=true
}


print_summary() {
  SERVICE_URL=$(gcloud run services describe democratized-reviewer \
    --platform managed --region "${REGION}" --project="${DEPLOY_PROJECT}" \
    --format="value(status.url)" 2>/dev/null || echo "UNKNOWN")

  echo ""
  echo -e "${P_PRIMARY}"
  echo "╔════════════════════════════════════════════════════════════════════╗"
  echo "║               >> DEPLOYMENT SEQUENCE COMPLETE <<                   ║"
  echo "╚════════════════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
  
  echo -e "   ${P_SECONDARY}ACCESS TERMINAL:${NC}   ${P_TEXT}${SERVICE_URL}${NC}"
  echo -e "   ${P_DIM}------------------------------------------------------------${NC}"
  if [[ "$IS_PUBLIC" == true ]]; then
    echo -e "   ${P_SECONDARY}ACCESS:${NC}            ${P_WARN}PUBLIC (allUsers granted run.invoker)${NC}"
    echo -e "   ${P_DIM}                    Open the URL directly in a browser.${NC}"
  else
    echo -e "   ${P_SECONDARY}ACCESS:${NC}            Cloud Run IAM (private)"
    echo -e "   ${P_DIM}                    Reach the service via IAM-authenticated proxy:${NC}"
    echo -e "   ${P_DIM}                    gcloud run services proxy democratized-reviewer --region ${REGION} --project ${DEPLOY_PROJECT}${NC}"
    echo -e "   ${P_DIM}                    Then open http://localhost:8080${NC}"
  fi
  echo ""
  echo -e "   ${P_WARN}TIPS:${NC}"

  # IMPORTANT: print each gcloud snippet as a SINGLE LONG LINE rather than
  # using backslash-newline continuations. Multi-line shell continuations
  # rendered through bash echo/heredoc collide with terminal copy/paste
  # in subtle ways — Cloud Shell users have hit "unrecognized argument: \"
  # because the rendered output contained literal `\` characters that gcloud
  # parsed as args. One long line wraps visually but pastes cleanly.

  echo "   - Grant additional users access:"
  echo -e "     ${P_DIM}gcloud run services add-iam-policy-binding democratized-reviewer --member=user:someone@example.com --role=roles/run.invoker --region=${REGION} --project=${DEPLOY_PROJECT}${NC}"

  echo "   - Billing checks (BIL-001/005) need the SA to also have"
  echo -e "     ${P_DIM}roles/billing.viewer${NC} on the billing account itself."
  echo "     This script only grants it at the project level."

  if [[ "$IS_PUBLIC" == true ]]; then
    echo -e "   - ${P_WARN}Revoke public access${NC} (lock the dashboard back down to Cloud Run IAM):"
    echo -e "     ${P_DIM}gcloud run services remove-iam-policy-binding democratized-reviewer --member=allUsers --role=roles/run.invoker --region=${REGION} --project=${DEPLOY_PROJECT}${NC}"
  else
    echo -e "   - ${P_WARN}DEMO ACCESS${NC} (skip the proxy — open URL directly in any browser):"
    echo -e "     ${P_WARN}makes the dashboard PUBLIC to the internet; revoke afterwards${NC}"
    echo -e "     ${P_DIM}gcloud run services add-iam-policy-binding democratized-reviewer --member=allUsers --role=roles/run.invoker --region=${REGION} --project=${DEPLOY_PROJECT}${NC}"
    echo -e "     To revoke later: replace ${P_DIM}add-iam-policy-binding${NC} with ${P_DIM}remove-iam-policy-binding${NC}"
  fi

  echo "   - To uninstall:"
  echo -e "     ${P_DIM}./setup.sh --remove${NC}"
  echo ""
  
  typewriter "   >> SYSTEM READY. AWAITING INPUT." 0.03 "${P_PRIMARY}"
  echo ""
}

remove_deployment() {
  step "REMOVE DEPLOYMENT"

  # Deploys from older script versions predate the state record — fall back
  # to the old assumptions, loudly, so a wrong-region miss is visible.
  HAVE_STATE=false
  if [[ -f "$DEPLOY_STATE_FILE" ]]; then
    # shellcheck source=/dev/null
    . "$DEPLOY_STATE_FILE"
    HAVE_STATE=true
    info "Loaded deployment record: ${DEPLOY_STATE_FILE}"
  else
    warn "No deployment record found at ${DEPLOY_STATE_FILE}."
    warn "Falling back to default names/region — verify the plan below carefully."
  fi

  if [[ -z "$DEPLOY_PROJECT" ]]; then
      DEPLOY_PROJECT="${DR_STATE_PROJECT:-}"
  fi
  if [[ -z "$DEPLOY_PROJECT" ]]; then
      DEPLOY_PROJECT="${CURRENT_PROJECT:-}"
  fi

  if [[ -z "$DEPLOY_PROJECT" ]]; then
    read -rp "   > Enter Target Project ID to clean up: " DEPLOY_PROJECT
  fi

  if [[ -z "$DEPLOY_PROJECT" ]]; then
     error "Project ID is mandatory for removal."
     exit 1
  fi

  # Precedence: --region flag > recorded state > legacy default (with warning).
  if [[ -z "$REGION" ]]; then
      REGION="${DR_STATE_REGION:-}"
  fi
  if [[ -z "$REGION" ]]; then
      REGION="asia-south1"
      warn "Deployed region unknown — assuming '${REGION}'. If you deployed to a"
      warn "different region, the Cloud Run service and Artifact Registry will NOT"
      warn "be found (and the service keeps billing at min-instances=1)."
      warn "Re-run with:  ./setup.sh --remove --region <your-region>"
  fi

  SA_EMAIL="${DR_STATE_SA_EMAIL:-democratized-reviewer-sa@${DEPLOY_PROJECT}.iam.gserviceaccount.com}"
  DATA_BUCKET="${DR_STATE_BUCKET:-democratized-reviewer-${DEPLOY_PROJECT}-data}"
  if [[ -z "$ORG_ID" ]]; then
      ORG_ID="${DR_STATE_ORG_ID:-}"
  fi

  # Revoke exactly what deploy granted when we know it; otherwise fall back
  # to the full historical set (older setups granted all of these).
  PROJECT_ROLES=()
  if [[ -n "${DR_STATE_PROJECT_ROLES:-}" ]]; then
    read -r -a PROJECT_ROLES <<< "${DR_STATE_PROJECT_ROLES}"
  else
    PROJECT_ROLES=(
      roles/viewer
      roles/iam.securityReviewer
      roles/cloudasset.viewer
      roles/orgpolicy.policyViewer
      roles/recommender.viewer
      roles/billing.viewer
    )
  fi
  ORG_ROLES=()
  if [[ -n "${DR_STATE_ORG_ROLES:-}" ]]; then
    read -r -a ORG_ROLES <<< "${DR_STATE_ORG_ROLES}"
  fi

  warn "This will DELETE the following resources in project '${DEPLOY_PROJECT}':"
  echo -e "     - Cloud Run Service: democratized-reviewer (region: ${REGION})"
  echo -e "     - Artifact Registry: democratized-reviewer (region: ${REGION})"
  echo -e "     - GCS Bucket: ${DATA_BUCKET}"
  echo -e "     - Service Account: ${SA_EMAIL}"
  echo -e "     - Project IAM bindings for the service account (${#PROJECT_ROLES[@]} roles)"
  if [[ -n "$ORG_ID" && ${#ORG_ROLES[@]} -gt 0 ]]; then
    echo -e "     - Org-level IAM bindings on org ${ORG_ID} (asked separately below)"
  fi
  echo ""

  if ! confirm "Proceed with destructive removal?"; then
      exit 0
  fi

  # 1. Cloud Run
  status_wait "Deleting Cloud Run Service..."
  if gcloud run services delete democratized-reviewer --project="${DEPLOY_PROJECT}" --region="${REGION}" --quiet >/dev/null 2>&1; then
     status_done "Cloud Run Service Deleted"
  else
     warn "Cloud Run Service not found or already deleted."
  fi

  # 2. Artifact Registry
  status_wait "Deleting Artifact Registry..."
  if gcloud artifacts repositories delete democratized-reviewer --location="${REGION}" --project="${DEPLOY_PROJECT}" --quiet >/dev/null 2>&1; then
     status_done "Artifact Registry Deleted"
  else
     warn "Artifact Registry not found or already deleted."
  fi

  # 3. GCS Bucket
  status_wait "Deleting GCS Bucket..."
  if gcloud storage rm -r "gs://${DATA_BUCKET}" --project="${DEPLOY_PROJECT}" --quiet >/dev/null 2>&1; then
     status_done "GCS Bucket Deleted"
  else
     warn "GCS Bucket not found or already deleted."
  fi

  # 4. Service Account & IAM
  status_wait "Revoking Project IAM Roles..."

  _REVOKE_FAILED=()
  for role in "${PROJECT_ROLES[@]}"; do
    gcloud projects remove-iam-policy-binding "${DEPLOY_PROJECT}" \
      --member="serviceAccount:${SA_EMAIL}" \
      --role="${role}" \
      --condition=None --quiet >/dev/null 2>&1 || _REVOKE_FAILED+=("${role}")
  done
  if [[ ${#_REVOKE_FAILED[@]} -eq 0 ]]; then
    status_done "Project IAM Roles Revoked (${#PROJECT_ROLES[@]})"
  else
    echo ""
    warn "Could not revoke ${#_REVOKE_FAILED[@]} of ${#PROJECT_ROLES[@]} project-level bindings"
    warn "(binding already gone, or you lack IAM admin on ${DEPLOY_PROJECT}):"
    for role in "${_REVOKE_FAILED[@]}"; do
      echo -e "     - ${role}"
    done
  fi

  # Org-scope bindings widen the blast radius beyond this project, so they
  # get their own consent — mirroring how they were granted.
  if [[ -n "$ORG_ID" && ${#ORG_ROLES[@]} -gt 0 ]]; then
    echo ""
    warn "This deployment granted ${SA_EMAIL}"
    warn "the following roles at ORGANIZATION scope (org ${ORG_ID}):"
    for role in "${ORG_ROLES[@]}"; do
      echo -e "     - ${role}"
    done
    if confirm "Revoke these organization-level bindings on org ${ORG_ID}?"; then
      _ORG_REVOKE_FAILED=()
      for role in "${ORG_ROLES[@]}"; do
        gcloud organizations remove-iam-policy-binding "${ORG_ID}" \
          --member="serviceAccount:${SA_EMAIL}" \
          --role="${role}" \
          --condition=None --quiet >/dev/null 2>&1 || _ORG_REVOKE_FAILED+=("${role}")
      done
      if [[ ${#_ORG_REVOKE_FAILED[@]} -eq 0 ]]; then
        status_done "Organization-level bindings revoked (${#ORG_ROLES[@]})"
      else
        status_fail "Could not revoke ${#_ORG_REVOKE_FAILED[@]} org-level binding(s) — remove manually:"
        for role in "${_ORG_REVOKE_FAILED[@]}"; do
          echo -e "       ${P_DIM}gcloud organizations remove-iam-policy-binding ${ORG_ID} --member=serviceAccount:${SA_EMAIL} --role=${role} --condition=None${NC}"
        done
      fi
    else
      warn "Leaving organization-level bindings in place. Remove later with:"
      for role in "${ORG_ROLES[@]}"; do
        echo -e "       ${P_DIM}gcloud organizations remove-iam-policy-binding ${ORG_ID} --member=serviceAccount:${SA_EMAIL} --role=${role} --condition=None${NC}"
      done
    fi
  elif [[ "$HAVE_STATE" != true ]]; then
    echo ""
    warn "No deployment record — cannot tell whether org-level roles were granted."
    warn "Older versions of this script granted viewer roles at the ORG level when"
    warn "the project sat under an organization. Audit with:"
    echo -e "       ${P_DIM}gcloud organizations get-iam-policy <ORG_ID> --flatten='bindings[].members' --filter='bindings.members:${SA_EMAIL}' --format='value(bindings.role)'${NC}"
  fi

  status_wait "Deleting Service Account..."
  if gcloud iam service-accounts delete "${SA_EMAIL}" --project="${DEPLOY_PROJECT}" --quiet >/dev/null 2>&1; then
     status_done "Service Account Deleted"
  else
     warn "Service Account not found or already deleted."
  fi

  # 5. Restore Org Policy
  if [[ -f "$ORG_POLICY_STAMP" ]]; then
      echo ""
      status_wait "Restoring Organization Policy..."
      ORG_POLICY_CONSTRAINT="constraints/iam.allowedPolicyMemberDomains"
      restored=false
      # Prefer reapplying the snapshot we took before override, if it looks valid
      if [[ -s "$ORG_POLICY_SNAPSHOT" ]] && grep -q '"name"' "$ORG_POLICY_SNAPSHOT" 2>/dev/null; then
          if gcloud org-policies set-policy "$ORG_POLICY_SNAPSHOT" --project="${DEPLOY_PROJECT}" --quiet >/dev/null 2>&1; then
              status_done "Organization Policy Restored from snapshot"
              restored=true
          fi
      fi
      # Fall back to deleting the override so the policy reverts to inherited default
      if [[ "$restored" != true ]]; then
          if gcloud org-policies delete "$ORG_POLICY_CONSTRAINT" --project="${DEPLOY_PROJECT}" --quiet >/dev/null 2>&1; then
              status_done "Organization Policy override removed (now inherits parent)"
          else
              warn "Failed to restore Organization Policy (Check permissions)."
          fi
      fi
      rm -f "$ORG_POLICY_STAMP" "$ORG_POLICY_SNAPSHOT"
  fi

  rm -f "$DEPLOY_STATE_FILE"

  echo ""
  echo -e "${P_PRIMARY}>> REMOVAL COMPLETE. SYSTEM CLEAN.${NC}"
}


# ---------------------------------------------------------------------------
# Grant SA on additional scan targets (--grant-on PROJECT, --grant-on-org ORG)
# ---------------------------------------------------------------------------
# Why this exists: setup.sh only grants the SA viewer roles on the DEPLOY
# project. Scanning any other project requires the SA to have read access on
# THAT project too, otherwise every check 403s and the scan dies in a long
# storm of timeouts. These helpers let an operator (or the customer's
# org admin) extend access without re-running setup.

# Roles required on a scan-target project. Mirror of the deploy-time set so
# checks have everything they need (resource listings, IAM-policy reads,
# org-policy reads, recommender insights, asset enumeration).
SCAN_TARGET_ROLES=(
  roles/viewer
  roles/iam.securityReviewer
  roles/cloudasset.viewer
  roles/orgpolicy.policyViewer
  roles/recommender.viewer
)

# Smaller org-level set — `roles/viewer` at the org gives transitive viewer
# on every project, which is the whole point of granting at the org level.
# `cloudasset.viewer` is needed for the org-scope project enumeration call.
SCAN_TARGET_ORG_ROLES=(
  roles/viewer
  roles/iam.securityReviewer
  roles/cloudasset.viewer
)

_grant_on_project() {
  local target_project="$1"
  if [[ -z "$target_project" ]]; then
    error "--grant-on requires a project ID"
    exit 2
  fi
  # Resolve the deploy project so we can derive the SA email.
  local deploy_proj="${DEPLOY_PROJECT:-${CURRENT_PROJECT:-$(gcloud config get-value project 2>/dev/null)}}"
  if [[ -z "$deploy_proj" || "$deploy_proj" == "(unset)" ]]; then
    error "Could not determine the DEPLOY project (where the SA lives)."
    error "Set it explicitly:  DEPLOY_PROJECT=<id> ./setup.sh --grant-on $target_project"
    exit 2
  fi
  local sa="democratized-reviewer-sa@${deploy_proj}.iam.gserviceaccount.com"

  step "GRANT SCAN-TARGET ACCESS TO SERVICE ACCOUNT"
  info "Service Account: ${sa}"
  info "Scan Target Project: ${target_project}"
  info "Roles: ${SCAN_TARGET_ROLES[*]}"
  echo ""

  if ! confirm "Grant these read-only roles?"; then
    warn "Aborted by user."
    exit 0
  fi

  local _pids=() _logdir
  _logdir="$(mktemp -d -t dr-grant.XXXXXX)"
  for role in "${SCAN_TARGET_ROLES[@]}"; do
    (
      local _key="${role//\//_}"
      if gcloud projects add-iam-policy-binding "${target_project}" \
          --member="serviceAccount:${sa}" --role="${role}" \
          --condition=None --quiet >/dev/null 2>"${_logdir}/${_key}.err"; then
        echo "OK" > "${_logdir}/${_key}.status"
      else
        echo "FAIL" > "${_logdir}/${_key}.status"
      fi
    ) &
    _pids+=($!)
  done
  wait "${_pids[@]}"

  local any_failed=false
  for role in "${SCAN_TARGET_ROLES[@]}"; do
    local _key="${role//\//_}"
    if [[ "$(cat "${_logdir}/${_key}.status" 2>/dev/null)" == "OK" ]]; then
      status_done "Bound: ${role}"
    else
      status_fail "Failed to bind: ${role}"
      # Surface the first non-empty stderr line so the operator sees WHY.
      local _msg
      _msg=$(grep -v '^$' "${_logdir}/${_key}.err" 2>/dev/null | head -n 1)
      if [[ -n "$_msg" ]]; then
        echo -e "        ${P_DIM}${_msg}${NC}"
      fi
      any_failed=true
    fi
  done
  rm -rf "$_logdir"
  echo ""

  if [[ "$any_failed" == true ]]; then
    warn "One or more bindings failed. The most common cause is that the"
    warn "account running this script does not hold a role that lets it"
    warn "modify IAM on ${target_project}, e.g. roles/resourcemanager.projectIamAdmin"
    warn "or roles/owner. Hand the snippet below to someone who does:"
    echo ""
    for role in "${SCAN_TARGET_ROLES[@]}"; do
      echo -e "   ${P_DIM}gcloud projects add-iam-policy-binding ${target_project} --member=serviceAccount:${sa} --role=${role} --condition=None --quiet${NC}"
    done
    echo ""
    return 1
  fi

  status_done "Service account can now scan ${target_project}"
  info "Re-validate from the UI's scan wizard or via:"
  echo -e "     ${P_DIM}gcloud projects describe ${target_project} --impersonate-service-account=${sa}${NC}"
}

_grant_on_org() {
  local org_id="$1"
  if [[ -z "$org_id" || ! "$org_id" =~ ^[0-9]+$ ]]; then
    error "--grant-on-org requires a numeric organization ID (e.g. 123456789012)"
    exit 2
  fi
  local deploy_proj="${DEPLOY_PROJECT:-${CURRENT_PROJECT:-$(gcloud config get-value project 2>/dev/null)}}"
  if [[ -z "$deploy_proj" || "$deploy_proj" == "(unset)" ]]; then
    error "Could not determine the DEPLOY project (where the SA lives)."
    exit 2
  fi
  local sa="democratized-reviewer-sa@${deploy_proj}.iam.gserviceaccount.com"

  step "GRANT ORG-LEVEL ACCESS TO SERVICE ACCOUNT"
  info "Service Account: ${sa}"
  info "Organization: ${org_id}"
  info "Roles: ${SCAN_TARGET_ORG_ROLES[*]}"
  echo ""
  warn "Org-level role grants typically require an Org Admin running this command."
  warn "If you see 'Permission denied', hand the four-line gcloud snippet printed"
  warn "at the end to your customer's Org Admin."
  echo ""

  if ! confirm "Attempt org-level grants now?"; then
    warn "Aborted by user."
    exit 0
  fi

  local any_failed=false _errfile
  _errfile="$(mktemp -t dr-grant-org.XXXXXX.err)"
  for role in "${SCAN_TARGET_ORG_ROLES[@]}"; do
    status_wait "Binding org-level: ${role}"
    : > "$_errfile"
    if gcloud organizations add-iam-policy-binding "${org_id}" \
        --member="serviceAccount:${sa}" --role="${role}" \
        --condition=None --quiet >/dev/null 2>"$_errfile"; then
      echo ""
      status_done "Bound: ${role}"
    else
      echo ""
      status_fail "Failed: ${role}"
      local _msg
      _msg=$(grep -v '^$' "$_errfile" 2>/dev/null | head -n 1)
      if [[ -n "$_msg" ]]; then
        echo -e "        ${P_DIM}${_msg}${NC}"
      fi
      any_failed=true
    fi
  done
  rm -f "$_errfile"

  if [[ "$any_failed" == true ]]; then
    echo ""
    warn "One or more org-level bindings failed. Org-level grants require"
    warn "roles/resourcemanager.organizationAdmin on the org. Hand the"
    warn "snippet below to your customer's Org Admin:"
    echo ""
    for role in "${SCAN_TARGET_ORG_ROLES[@]}"; do
      echo -e "   ${P_DIM}gcloud organizations add-iam-policy-binding ${org_id} --member=serviceAccount:${sa} --role=${role} --condition=None --quiet${NC}"
    done
  else
    status_done "Org-level access established. The SA can now scan any project under ${org_id}."
  fi
}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
print_usage() {
  cat <<USAGE
Usage:
  ./setup.sh                          Deploy the tool (interactive).
  ./setup.sh --remove [--region R]    Tear down the deploy + SA + bucket + AR
                                      + IAM grants. Uses the region/grants
                                      recorded at deploy time; --region
                                      overrides the recorded region.
  ./setup.sh --grant-on PROJECT_ID    Grant the deploy SA viewer roles on a
                                      different scan-target project. Run once
                                      per project the customer wants scanned.
  ./setup.sh --grant-on-org ORG_ID    Grant the deploy SA viewer roles at the
                                      org level (one-shot for whole-org scans).
                                      Usually needs an Org Admin to run.
  ./setup.sh --help                   Show this message.
USAGE
}

main() {
  case "${1:-}" in
    --help|-h)
      print_usage
      exit 0
      ;;
    --grant-on)
      check_prerequisites
      _grant_on_project "${2:-}"
      exit 0
      ;;
    --grant-on-org)
      check_prerequisites
      _grant_on_org "${2:-}"
      exit 0
      ;;
    --remove)
      shift
      while [[ $# -gt 0 ]]; do
        case "$1" in
          --region)
            if [[ -z "${2:-}" ]]; then
              error "--region requires a value"
              exit 2
            fi
            REGION="$2"
            shift 2
            ;;
          *)
            error "Unknown option for --remove: $1"
            print_usage
            exit 2
            ;;
        esac
      done
      print_banner
      check_prerequisites
      remove_deployment
      exit 0
      ;;
  esac

  print_banner
  check_prerequisites

  prompt_configuration
  setup_service_account
  enable_apis
  setup_infrastructure

  build_and_deploy
  maybe_grant_public_access
  print_summary
}

main "$@"
