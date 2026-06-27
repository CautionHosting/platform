#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
#
# E2E test for SSH-signed app get and destroy.
# Requires: make up-test (builds with e2e-testing feature)
#
# Tests the CI/CD auth path:
#   1. Create test user via e2e-login endpoint
#   2. Add SSH key via gateway API
#   3. Clone demo app
#   4. caution init (creates app, sets git remote)
#   5. git push caution main (triggers enclave build)
#   6. Wait for deployment
#   7. Backup and remove session config
#   8. caution apps get --this-is-a-ci-machine (SSH-signed, no session)
#   9. caution apps destroy --force --this-is-a-ci-machine (SSH-signed, no session)

set -euo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8000}"
API_URL="${API_URL:-http://127.0.0.1:8080}"
CAUTION_BIN="${CAUTION_BIN:-caution}"
FIXTURES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)"
WORK_DIR=$(mktemp -d)
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/caution-cli"
CONFIG_FILE="$CONFIG_DIR/config.json"
CONFIG_BACKUP="$WORK_DIR/config.json.bak"
SSH_KEY_PATH="$WORK_DIR/test_key"
RESOURCE_ID=""
LOG_DIR="tests/e2e/logs"
LOG_FILE="$LOG_DIR/e2e-$(date +%Y%m%d-%H%M%S).log"
STEP_NUM=0
STEPS_PASSED=0
STEPS_FAILED=0
STEP_RESULTS=()

mkdir -p "$LOG_DIR"

exec > >(tee -a "$LOG_FILE") 2>&1

cleanup() {
    echo ""
    echo "=== Cleanup ==="

    if [ -f "$CONFIG_BACKUP" ]; then
        echo "Restoring session config from backup..."
        mkdir -p "$CONFIG_DIR"
        cp "$CONFIG_BACKUP" "$CONFIG_FILE"
    fi

    if [ -n "$RESOURCE_ID" ]; then
        echo "Destroying app $RESOURCE_ID..."
        "$CAUTION_BIN" -u "$GATEWAY_URL" apps destroy "$RESOURCE_ID" --force 2>/dev/null || true
    fi

    rm -rf "$WORK_DIR"

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

mkdir -p "$CONFIG_DIR"
cat > "$CONFIG_FILE" <<EOF
{
  "session_id": "$SESSION_ID",
  "expires_at": "$EXPIRES_AT",
  "server_url": "$GATEWAY_URL"
}
EOF
step_pass "E2E login (user: $USER_ID)"

# Mark test user as onboarded so API onboarding middleware doesn't block requests
log "Marking test user as onboarded..."
docker exec postgres-test psql -U postgres -d caution_test -c "
UPDATE users SET email_verified_at = NOW(), payment_method_added_at = NOW() WHERE id = '$USER_ID';
" >/dev/null 2>&1 || log "  Warning: could not mark user as onboarded"

curl -sf "$API_URL/resources" -H "X-Session-ID: $SESSION_ID" >/dev/null 2>&1 || log "  Warning: could not trigger org provisioning"

ORG_ID=""
for i in $(seq 1 10); do
    ORG_ID=$(docker exec postgres-test psql -U postgres -d caution_test -t -A -c "
SELECT organization_id FROM organization_members WHERE user_id = '$USER_ID' LIMIT 1;
" 2>/dev/null | head -1 | tr -d ' \n')
    [ -n "$ORG_ID" ] && break
    sleep 1
done
log "  Org ID: $ORG_ID"

log "Seeding test credits for deploy gate..."
docker exec postgres-test psql -U postgres -d caution_test -c "
DELETE FROM credit_ledger WHERE organization_id = '$ORG_ID';
INSERT INTO credit_ledger (organization_id, user_id, delta_cents, entry_type, description)
VALUES ('$ORG_ID', '$USER_ID', 10000, 'purchase', 'e2e deploy gate seed');
" >/dev/null 2>&1 || log "  Warning: could not seed credits"

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

eval "$(ssh-agent -s)" >/dev/null
ssh-add "$SSH_KEY_PATH" 2>/dev/null
step_pass "Add SSH key (fingerprint: ${FINGERPRINT:0:20}...)"

# ── Step 4: Copy Demo App Fixture ────────────────────────────────────

STEP_NUM=4
CLONE_DIR="$WORK_DIR/demo-app"
log "Copying demo app fixture..."
cp -r "$FIXTURES_DIR/demo-app-happy-path" "$CLONE_DIR"
cd "$CLONE_DIR"
git init -b main
git -c user.email="e2e@caution.dev" -c user.name="Caution E2E" add .
git -c user.email="e2e@caution.dev" -c user.name="Caution E2E" commit -m "Initial commit" --quiet
step_pass "Copy and init demo app fixture"

# ── Step 5: caution init ────────────────────────────────────────────

STEP_NUM=5
log "Running caution init..."
INIT_OUTPUT=$("$CAUTION_BIN" -u "$GATEWAY_URL" init --name "e2e-test-$(date +%s)" 2>&1)

if [ -f ".caution/deployment.json" ]; then
    RESOURCE_ID=$(jq -r '.resource_id' .caution/deployment.json)
else
    echo "$INIT_OUTPUT"
    step_fail "caution init (no .caution/deployment.json)"
fi

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
MAX_WAIT=600
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

# ── Step 8: SSH-signed apps get ───────────────────────────────────────

STEP_NUM=8
log "Backing up session config and removing original..."
cp "$CONFIG_FILE" "$CONFIG_BACKUP"
rm -f "$CONFIG_FILE"

log "Running caution apps get with --this-is-a-ci-machine (no session)..."
set +e
GET_OUTPUT=$("$CAUTION_BIN" -u "$GATEWAY_URL" apps get "$RESOURCE_ID" --this-is-a-ci-machine 2>&1)
GET_STATUS=$?
set -e
echo "$GET_OUTPUT"

if [ $GET_STATUS -ne 0 ]; then
    step_fail "SSH-signed apps get"
fi

if ! echo "$GET_OUTPUT" | grep -qi "state"; then
    step_fail "SSH-signed apps get (output missing app state)"
fi
step_pass "SSH-signed apps get"

# ── Step 9: SSH-signed apps destroy ──────────────────────────────────

STEP_NUM=9
log "Running caution apps destroy with --this-is-a-ci-machine (no session)..."
set +e
DESTROY_OUTPUT=$("$CAUTION_BIN" -u "$GATEWAY_URL" apps destroy "$RESOURCE_ID" --force --this-is-a-ci-machine 2>&1)
DESTROY_STATUS=$?
set -e
echo "$DESTROY_OUTPUT"

if [ $DESTROY_STATUS -ne 0 ]; then
    step_fail "SSH-signed apps destroy"
fi
RESOURCE_ID=""
step_pass "SSH-signed apps destroy"
