#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
#
# Destroy all apps by calling the internal destroy-next endpoint until
# no more apps remain. Uses the API's internal service auth.
# Requires: make up-test (services running with e2e-testing-unsafe feature).
#
# Flow:
#   1. Retrieve INTERNAL_SERVICE_SECRET from the running API container
#   2. Loop calling /internal/cleanup/destroy-next-app until status "done"
#   3. Report success/failure counts

set -euo pipefail

API_URL="${API_URL:-http://127.0.0.1:8080}"
SUCCESS_COUNT=0
FAILURE_COUNT=0
FAILED_IDS=()

log() {
    echo "[destroy-all] $*"
}

error() {
    echo "[destroy-all] ERROR: $*" >&2
}

# ── Step 1: Get internal service secret ──────────────────────────
log "Retrieving INTERNAL_SERVICE_SECRET from API container..."
INTERNAL_SERVICE_SECRET=$(docker exec api printenv INTERNAL_SERVICE_SECRET 2>/dev/null || true)

if [ -z "$INTERNAL_SERVICE_SECRET" ]; then
    error "Could not retrieve INTERNAL_SERVICE_SECRET from API container"
    error "Ensure API container is running with e2e-testing-unsafe feature"
    exit 1
fi

log "Internal service secret retrieved"

# ── Step 2: Loop destroying apps until done ──────────────────────
log "Starting cleanup loop..."

while true; do
    RESPONSE=$(curl -sf -X POST "$API_URL/internal/cleanup/destroy-next-app?force=true" \
        -H "X-Internal-Service-Secret: $INTERNAL_SERVICE_SECRET" 2>&1) || {
        error "Request failed: $RESPONSE"
        FAILURE_COUNT=$((FAILURE_COUNT + 1))
        # If we got a failure, wait briefly and retry
        sleep 2
        continue
    }

    STATUS=$(echo "$RESPONSE" | jq -r '.status' 2>/dev/null || echo "error")

    if [ "$STATUS" = "deleted" ]; then
        RESOURCE_ID=$(echo "$RESPONSE" | jq -r '.resource_id' 2>/dev/null || echo "unknown")
        log "Destroyed resource $RESOURCE_ID"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    elif [ "$STATUS" = "done" ]; then
        log "No more resources to destroy"
        break
    else
        ERROR_MSG=$(echo "$RESPONSE" | jq -r '.error // "unknown error"' 2>/dev/null || echo "$RESPONSE")
        error "Destroy failed: $ERROR_MSG"
        FAILURE_COUNT=$((FAILURE_COUNT + 1))
        FAILED_IDS+=("(error: $ERROR_MSG)")
        # Brief pause before retry
        sleep 2
    fi
done

# ── Step 3: Summary ──────────────────────────────────────────────
log "Cleanup complete: $SUCCESS_COUNT destroyed, $FAILURE_COUNT failures"
if [ "$FAILURE_COUNT" -gt 0 ]; then
    error "Encountered $FAILURE_COUNT failure(s) during cleanup"
    exit 1
fi
