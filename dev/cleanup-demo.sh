#!/usr/bin/env bash
# ============================================================================
# Democratized Reviewer - Demo Resources Cleanup Script
# ============================================================================
# Tears down all intentionally misconfigured demo resources created for
# demonstration purposes. Run this after your demo is complete.
#
# Usage: bash cleanup-demo.sh
# ============================================================================

set -euo pipefail

PROJECT="democratized-reviewer"
REGION="us-central1"
ZONE="us-central1-a"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail()  { echo -e "${RED}[FAIL]${NC} $*"; }

delete_resource() {
    local desc="$1"
    shift
    info "Deleting ${desc}..."
    if "$@" 2>/dev/null; then
        ok "Deleted ${desc}"
    else
        warn "Could not delete ${desc} (may not exist)"
    fi
}

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   Democratized Reviewer - Demo Cleanup          ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
info "Target project: ${PROJECT}  |  region: ${REGION}  |  zone: ${ZONE}"
echo ""

if ! gcloud projects describe "${PROJECT}" --quiet &>/dev/null; then
    fail "Project '${PROJECT}' not found or you lack access."
    exit 1
fi
gcloud config set project "${PROJECT}" --quiet

# --- Cloud SQL (takes longest, start first) ---
info "Deleting Cloud SQL instance (this takes a few minutes)..."
gcloud sql instances delete demo-insecure-db \
    --project="${PROJECT}" --quiet 2>/dev/null &
SQL_PID=$!

# --- GCE Instances ---
delete_resource "demo-insecure-vm" \
    gcloud compute instances delete demo-insecure-vm \
    --zone="${ZONE}" --project="${PROJECT}" --quiet

delete_resource "demo-default-sa-vm" \
    gcloud compute instances delete demo-default-sa-vm \
    --zone="${ZONE}" --project="${PROJECT}" --quiet

# --- GCE Snapshots ---
delete_resource "demo-old-snapshot" \
    gcloud compute snapshots delete demo-old-snapshot \
    --project="${PROJECT}" --quiet

# --- GCE Disks ---
delete_resource "demo-unused-disk" \
    gcloud compute disks delete demo-unused-disk \
    --zone="${ZONE}" --project="${PROJECT}" --quiet

# --- Static IP ---
delete_resource "demo-unused-ip" \
    gcloud compute addresses delete demo-unused-ip \
    --region="${REGION}" --project="${PROJECT}" --quiet

# --- Firewall Rules ---
for FW in demo-allow-ssh-all demo-allow-rdp-all demo-allow-all-traffic; do
    delete_resource "firewall rule ${FW}" \
        gcloud compute firewall-rules delete "${FW}" \
        --project="${PROJECT}" --quiet
done

# --- VPC Network ---
# Need to wait a moment for instances to be fully deleted before removing network
info "Waiting for instance deletions to propagate..."
sleep 10
delete_resource "demo-insecure-vpc network" \
    gcloud compute networks delete demo-insecure-vpc \
    --project="${PROJECT}" --quiet

# --- GCS Bucket ---
delete_resource "dr-demo-insecure-bucket" \
    gcloud storage rm -r gs://dr-demo-insecure-bucket --quiet

# --- Pub/Sub ---
delete_resource "demo-insecure-sub subscription" \
    gcloud pubsub subscriptions delete demo-insecure-sub \
    --project="${PROJECT}" --quiet

delete_resource "demo-insecure-topic topic" \
    gcloud pubsub topics delete demo-insecure-topic \
    --project="${PROJECT}" --quiet

# --- BigQuery ---
delete_resource "demo_insecure_dataset dataset" \
    bq rm -r -f "${PROJECT}:demo_insecure_dataset"

# --- IAM: Remove Editor role from demo SA ---
info "Removing Editor role from demo-insecure-sa..."
gcloud projects remove-iam-policy-binding "${PROJECT}" \
    --member="serviceAccount:demo-insecure-sa@${PROJECT}.iam.gserviceaccount.com" \
    --role="roles/editor" --quiet 2>/dev/null || warn "Could not remove IAM binding"

# --- Service Account ---
delete_resource "demo-insecure-sa service account" \
    gcloud iam service-accounts delete \
    "demo-insecure-sa@${PROJECT}.iam.gserviceaccount.com" \
    --project="${PROJECT}" --quiet

# --- Wait for Cloud SQL deletion ---
info "Waiting for Cloud SQL deletion to complete..."
if wait $SQL_PID 2>/dev/null; then
    ok "Cloud SQL instance deleted"
else
    warn "Cloud SQL deletion may have failed - check console"
fi

# --- Clean up local files ---
rm -f demo-sa-key.json 2>/dev/null || true

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Demo cleanup complete!                        ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
info "Verify in Cloud Console: https://console.cloud.google.com/home/dashboard?project=${PROJECT}"
echo ""