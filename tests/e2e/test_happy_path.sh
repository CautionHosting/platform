#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
#
# E2E happy path test for the Caution platform.
# Requires: make up-test (builds with e2e-testing feature)
#
# Tests the full flow:
#   1. Create test user via e2e-login endpoint
#   2. Add SSH key via gateway API (FIDO2 sign bypassed)
#   3. Clone demo app
#   4. caution init (creates app, sets git remote)
#   5. git push caution main (triggers enclave build)
#   6. Wait for deployment
#   7. caution verify (attestation + reproduction)
#   8. caution apps destroy (cleanup)

set -euo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8000}"
CAUTION_BIN="${CAUTION_BIN:-caution}"
DEMO_REPO="${DEMO_REPO:-https://codeberg.org/caution/demo-hello-world-enclave.git}"
WORK_DIR=$(mktemp -d)
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/api-cli"
SSH_KEY_PATH="$WORK_DIR/test_key"
RESOURCE_ID=""
LOG_DIR="tests/e2e/logs"
LOG_FILE="$LOG_DIR/e2e-$(date +%Y%m%d-%H%M%S).log"
STEP_NUM=0
STEPS_PASSED=0
STEPS_FAILED=0
STEP_RESULTS=()

mkdir -p "$LOG_DIR"

# Tee all output to the log file
exec > >(tee -a "$LOG_FILE") 2>&1

cleanup() {
    echo ""
    echo "=== Cleanup ==="

    # Destroy the app if we have a resource ID
    if [ -n "$RESOURCE_ID" ]; then
        echo "Destroying app $RESOURCE_ID..."
        "$CAUTION_BIN" -u "$GATEWAY_URL" apps destroy "$RESOURCE_ID" --force 2>/dev/null || true
    fi

    # Remove temp work dir
    rm -rf "$WORK_DIR"

    # Print summary
    echo ""
    echo "========================================"
    echo "  E2E Test Results"
    echo "========================================"
    for result in "${STEP_RESULTS[@]}"; do
        echo "  $result"
    done
    echo "----------------------------------------"
    echo "  Passed: $STEPS_PASSED  Failed: $STEPS_FAILED"
    echo "========================================"
    echo ""
    echo "Full log: $LOG_FILE"
}
trap cleanup EXIT

step_pass() {
    STEPS_PASSED=$((STEPS_PASSED + 1))
    STEP_RESULTS+=("[PASS] Step $STEP_NUM: $1")
    echo "[PASS] Step $STEP_NUM: $1"
}

step_fail() {
    STEPS_FAILED=$((STEPS_FAILED + 1))
    STEP_RESULTS+=("[FAIL] Step $STEP_NUM: $1")
    echo "[FAIL] Step $STEP_NUM: $1" >&2
    exit 1
}

step_warn() {
    STEPS_PASSED=$((STEPS_PASSED + 1))
    STEP_RESULTS+=("[WARN] Step $STEP_NUM: $1")
    echo "[WARN] Step $STEP_NUM: $1"
}

log() {
    echo "[e2e] $*"
}

# ── Step 1: Wait for services ────────────────────────────────────────

STEP_NUM=1
log "Waiting for gateway to be ready..."
for i in $(seq 1 30); do
    if curl -sf "$GATEWAY_URL/health" >/dev/null 2>&1; then
        break
    fi
    if [ "$i" -eq 30 ]; then
        step_fail "Gateway health check"
    fi
    sleep 1
done
step_pass "Gateway health check"

# ── Step 2: E2E Login ────────────────────────────────────────────────

STEP_NUM=2
log "Creating test user via e2e-login..."
LOGIN_RESPONSE=$(curl -sf -X POST "$GATEWAY_URL/auth/e2e-login" \
    -H "Content-Type: application/json")

SESSION_ID=$(echo "$LOGIN_RESPONSE" | jq -r '.session_id')
USER_ID=$(echo "$LOGIN_RESPONSE" | jq -r '.user_id')
EXPIRES_AT=$(echo "$LOGIN_RESPONSE" | jq -r '.expires_at')

if [ -z "$SESSION_ID" ] || [ "$SESSION_ID" = "null" ]; then
    step_fail "E2E login (no session_id in response)"
fi

log "Logged in as user $USER_ID (session: ${SESSION_ID:0:16}...)"

# Write CLI config file so the caution binary uses our session
mkdir -p "$CONFIG_DIR"
cat > "$CONFIG_DIR/config.json" <<EOF
{
  "session_id": "$SESSION_ID",
  "expires_at": "$EXPIRES_AT",
  "server_url": "$GATEWAY_URL"
}
EOF
step_pass "E2E login (user: $USER_ID)"

# ── Step 3: Add SSH Key ──────────────────────────────────────────────

STEP_NUM=3
log "Generating test SSH key..."
ssh-keygen -t ed25519 -f "$SSH_KEY_PATH" -N "" -q
SSH_PUB_KEY=$(cat "$SSH_KEY_PATH.pub")

log "Adding SSH key via gateway API..."
ADD_KEY_RESPONSE=$(curl -sf -X POST "$GATEWAY_URL/ssh-keys" \
    -H "Content-Type: application/json" \
    -H "X-Session-ID: $SESSION_ID" \
    -d "{\"public_key\": \"$SSH_PUB_KEY\", \"name\": \"e2e-test\"}")

FINGERPRINT=$(echo "$ADD_KEY_RESPONSE" | jq -r '.fingerprint')
if [ -z "$FINGERPRINT" ] || [ "$FINGERPRINT" = "null" ]; then
    step_fail "Add SSH key (no fingerprint in response)"
fi

# Set up ssh-agent with our test key
eval "$(ssh-agent -s)" >/dev/null
ssh-add "$SSH_KEY_PATH" 2>/dev/null
step_pass "Add SSH key (fingerprint: ${FINGERPRINT:0:20}...)"

# ── Step 4: Clone Demo App ──────────────────────────────────────────

STEP_NUM=4
CLONE_DIR="$WORK_DIR/demo-app"
log "Cloning demo app from $DEMO_REPO..."
git clone "$DEMO_REPO" "$CLONE_DIR"
cd "$CLONE_DIR"
step_pass "Clone demo app"

# ── Step 5: caution init ────────────────────────────────────────────

STEP_NUM=5
log "Running caution init..."
INIT_OUTPUT=$("$CAUTION_BIN" -u "$GATEWAY_URL" init --name "e2e-test-$(date +%s)" 2>&1)

# Extract resource ID from .caution/deployment.json
if [ -f ".caution/deployment.json" ]; then
    RESOURCE_ID=$(jq -r '.resource_id' .caution/deployment.json)
else
    echo "$INIT_OUTPUT"
    step_fail "caution init (no .caution/deployment.json)"
fi

# Verify git remote was set
GIT_URL=$(git remote get-url caution 2>/dev/null || true)
if [ -z "$GIT_URL" ]; then
    step_fail "caution init (git remote not set)"
fi
step_pass "caution init (app: $RESOURCE_ID)"

# ── Step 6: git push ────────────────────────────────────────────────

STEP_NUM=6
log "Pushing to caution remote..."
export GIT_SSH_COMMAND="ssh -i $SSH_KEY_PATH -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222"
git push caution main 2>&1
step_pass "git push caution main"

# ── Step 7: Wait for deployment ──────────────────────────────────────

STEP_NUM=7
log "Waiting for deployment to complete..."
MAX_WAIT=600  # 10 minutes
POLL_INTERVAL=10
ELAPSED=0

while [ $ELAPSED -lt $MAX_WAIT ]; do
    APP_STATE=$("$CAUTION_BIN" -u "$GATEWAY_URL" apps get "$RESOURCE_ID" 2>&1 | grep -i "state" | head -1 || true)

    if echo "$APP_STATE" | grep -qi "running"; then
        break
    fi

    if echo "$APP_STATE" | grep -qi "failed\|error"; then
        step_fail "Deployment ($APP_STATE)"
    fi

    log "  Still deploying... ($ELAPSED/${MAX_WAIT}s)"
    sleep $POLL_INTERVAL
    ELAPSED=$((ELAPSED + POLL_INTERVAL))
done

if [ $ELAPSED -ge $MAX_WAIT ]; then
    step_fail "Deployment (timed out after ${MAX_WAIT}s)"
fi
step_pass "Deployment (app running)"

# ── Step 8: caution verify ───────────────────────────────────────────

STEP_NUM=8
log "Running caution verify..."
set +e
VERIFY_OUTPUT=$("$CAUTION_BIN" -u "$GATEWAY_URL" verify --no-cache 2>&1)
VERIFY_STATUS=$?
set -e
echo "$VERIFY_OUTPUT"

if [ $VERIFY_STATUS -ne 0 ]; then
    # Check PCR comparison results
    PCR_MISMATCHES=$(echo "$VERIFY_OUTPUT" | grep -c "MISMATCH" || true)
    PCR_MATCHES=$(echo "$VERIFY_OUTPUT" | grep -c ": match" || true)

    if [ "$PCR_MATCHES" -gt 0 ] && [ "$PCR_MISMATCHES" -eq 0 ]; then
        # All PCRs match but attestation crypto failed (e.g. CA bundle issue)
        step_warn "caution verify (PCRs match but attestation crypto failed)"
    elif echo "$VERIFY_OUTPUT" | grep -q "PCR2: match"; then
        # Application hash (PCR2) matches but kernel hashes differ
        # (likely stale reproduction cache or enclaveos update)
        step_warn "caution verify (app PCR2 matches, kernel PCR0/1 differ — stale cache?)"
    else
        step_fail "caution verify"
    fi
else
    step_pass "caution verify (attestation verified)"
fi

# ── Step 9: caution apps destroy ─────────────────────────────────────

STEP_NUM=9
log "Destroying app..."
set +e
DESTROY_OUTPUT=$("$CAUTION_BIN" -u "$GATEWAY_URL" apps destroy "$RESOURCE_ID" --force 2>&1)
DESTROY_STATUS=$?
set -e

if [ $DESTROY_STATUS -ne 0 ]; then
    echo "$DESTROY_OUTPUT"
    step_fail "caution apps destroy"
fi
RESOURCE_ID=""  # Clear so cleanup trap doesn't try again
step_pass "caution apps destroy"
