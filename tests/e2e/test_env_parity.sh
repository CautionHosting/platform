#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
#
# E2E env parity test for the Caution platform.
# Requires: make up-test (builds with e2e-testing feature)
#
# Tests that environment variables declared in caution.hcl match
# those visible inside the running enclave.
#
# Expected env values (must match caution.hcl fixture):
#   TEST_ENV_FOO  = bar
#   TEST_ENV_HELLO = world
#   TEST_ENV_PARITY = check

set -euo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8000}"
API_URL="${API_URL:-http://127.0.0.1:8080}"
CAUTION_BIN="${CAUTION_BIN:-caution}"
FIXTURES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)"
WORK_DIR=$(mktemp -d)
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/api-cli"
SSH_KEY_PATH="$WORK_DIR/test_key"
RESOURCE_ID=""
LOG_DIR="tests/e2e/logs"
LOG_FILE="$LOG_DIR/e2e-env-parity-$(date +%Y%m%d-%H%M%S).log"
STEP_NUM=0
STEPS_PASSED=0
STEPS_FAILED=0
STEP_RESULTS=()

mkdir -p "$LOG_DIR"

exec > >(tee -a "$LOG_FILE") 2>&1

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    if [ -n "$RESOURCE_ID" ]; then
        echo "Destroying app $RESOURCE_ID..."
        "$CAUTION_BIN" -u "$GATEWAY_URL" apps destroy "$RESOURCE_ID" --force 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"
    echo ""
    echo "========================================"
    echo "  E2E Env Parity Test Results"
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
    step_fail "E2E login - no session_id"
fi
log "Session: $SESSION_ID User: $USER_ID Expires: $EXPIRES_AT"

# Write CLI config
mkdir -p "$CONFIG_DIR"
cat > "$CONFIG_DIR/config.json" <<CONFIG_EOF
{
  "default_profile": "e2e-test",
  "profiles": {
    "e2e-test": {
      "gateway_url": "$GATEWAY_URL",
      "session_id": "$SESSION_ID",
      "user_id": "$USER_ID",
      "expires_at": "$EXPIRES_AT"
    }
  }
}
CONFIG_EOF

# Mark user as onboarded so caution init doesn't block
docker exec postgres-test psql -U postgres -d caution_test -c "
  UPDATE users SET onboarded = true WHERE id = '$USER_ID';
" 2>/dev/null || step_warn "Could not mark user onboarded (non-fatal)"

step_pass "E2E login"

# ── Step 3: Add SSH Key ──────────────────────────────────────────────
STEP_NUM=3
log "Generating SSH key pair..."
ssh-keygen -t ed25519 -f "$SSH_KEY_PATH" -N "" -C "e2e-test-env-parity" >/dev/null 2>&1

SSH_PUB_KEY=$(cat "$SSH_KEY_PATH.pub")

curl -sf -X POST "$GATEWAY_URL/api/ssh-keys" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $SESSION_ID" \
    -d "$(jq -n --arg key "$SSH_PUB_KEY" '{key: $key}')" >/dev/null
step_pass "SSH key added"

# Start ssh-agent and add key
eval "$(ssh-agent -s)" >/dev/null
ssh-add "$SSH_KEY_PATH" >/dev/null 2>&1
step_pass "SSH agent started and key loaded"

# ── Step 4: Setup fixture repository ─────────────────────────────────
STEP_NUM=4
log "Setting up env-parity-test fixture..."
FIXTURE_SRC="$FIXTURES_DIR/env-parity-test"
FIXTURE_DST="$WORK_DIR/env-parity-test"

cp -r "$FIXTURE_SRC" "$FIXTURE_DST"
cd "$FIXTURE_DST"

git init
git config user.email "e2e@caution.local"
git config user.name "E2E Test"
git add -A
git commit -m "Initial commit: env-parity-test fixture"
step_pass "Fixture repository initialized"

# ── Step 5: caution init ─────────────────────────────────────────────
STEP_NUM=5
log "Running caution init..."
CAUTION_INIT_OUTPUT=$("$CAUTION_BIN" -u "$GATEWAY_URL" init 2>&1)
echo "$CAUTION_INIT_OUTPUT"

RESOURCE_ID=$(echo "$CAUTION_INIT_OUTPUT" | grep -oP '(?<=resource_id": ")[^"]+' || \
    echo "$CAUTION_INIT_OUTPUT" | grep -oP '(?<=Resource ID: )[^ ]+')

if [ -z "$RESOURCE_ID" ]; then
    step_fail "caution init - could not extract resource_id"
fi
log "Resource ID: $RESOURCE_ID"

# Also try from deployment.json
if [ -f ".caution/deployment.json" ]; then
    RESOURCE_ID=$(jq -r '.resource_id // empty' .caution/deployment.json)
    log "Resource ID from deployment.json: $RESOURCE_ID"
fi

if [ -z "$RESOURCE_ID" ]; then
    step_fail "caution init - could not determine resource_id"
fi
step_pass "caution init completed"

# ── Step 6: git push ─────────────────────────────────────────────────
STEP_NUM=6
log "Pushing to caution remote..."
GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i $SSH_KEY_PATH -p 2222" \
    git push caution main 2>&1
step_pass "git push completed"

# ── Step 7: Wait for deployment ──────────────────────────────────────
STEP_NUM=7
log "Waiting for deployment to reach running state..."
DEPLOY_TIMEOUT=600
DEPLOY_POLL_INTERVAL=10
for i in $(seq 1 $((DEPLOY_TIMEOUT / DEPLOY_POLL_INTERVAL))); do
    STATUS=$("$CAUTION_BIN" -u "$GATEWAY_URL" apps get "$RESOURCE_ID" 2>/dev/null | \
        grep -oP '(?<="state": ")[^"]+' || echo "unknown")
    log "Deployment state: $STATUS (attempt $i)"

    if [ "$STATUS" = "running" ]; then
        step_pass "Deployment reached running state"
        break
    fi
    if [ "$STATUS" = "failed" ]; then
        step_fail "Deployment failed"
    fi
    if [ "$i" -eq $((DEPLOY_TIMEOUT / DEPLOY_POLL_INTERVAL)) ]; then
        step_fail "Deployment did not reach running state within ${DEPLOY_TIMEOUT}s"
    fi
    sleep "$DEPLOY_POLL_INTERVAL"
done

# ── Step 8: Query /env and verify ────────────────────────────────────
STEP_NUM=8
log "Resolving enclave IP..."
ENCLAVE_IP=$("$CAUTION_BIN" -u "$GATEWAY_URL" apps get "$RESOURCE_ID" 2>/dev/null | \
    grep -oP '(?<="public_ip": ")[^"]+' || \
    "$CAUTION_BIN" -u "$GATEWAY_URL" apps get "$RESOURCE_ID" 2>/dev/null | \
    grep -oP '(?<=Public IP: )[^ ]+')

if [ -z "$ENCLAVE_IP" ]; then
    step_fail "Could not resolve enclave IP"
fi
log "Enclave IP: $ENCLAVE_IP"

# Query /env endpoint
ENV_RESPONSE=$(curl -sf --max-time 30 "http://${ENCLAVE_IP}:8080/env" 2>&1) || {
    step_fail "Failed to query /env endpoint"
}

log "Raw response: $ENV_RESPONSE"

# Verify expected env values
TEST_ENV_FOO=$(echo "$ENV_RESPONSE" | jq -r '.TEST_ENV_FOO // empty')
TEST_ENV_HELLO=$(echo "$ENV_RESPONSE" | jq -r '.TEST_ENV_HELLO // empty')
TEST_ENV_PARITY=$(echo "$ENV_RESPONSE" | jq -r '.TEST_ENV_PARITY // empty')

FAILED_ASSERTS=0

if [ "$TEST_ENV_FOO" != 'bar' ]; then
    echo "[FAIL] Expected TEST_ENV_FOO=bar, got '$TEST_ENV_FOO'"
    FAILED_ASSERTS=$((FAILED_ASSERTS + 1))
else
    echo "[PASS] TEST_ENV_FOO=bar"
fi

if [ "$TEST_ENV_HELLO" != '$(world)' ]; then
    echo "[FAIL] Expected TEST_ENV_HELLO=world, got '$TEST_ENV_HELLO'"
    FAILED_ASSERTS=$((FAILED_ASSERTS + 1))
else
    echo "[PASS] TEST_ENV_HELLO=world"
fi

if [ "$TEST_ENV_PARITY" != '`"ch\eck"`' ]; then
    echo "[FAIL] Expected TEST_ENV_PARITY=check, got '$TEST_ENV_PARITY'"
    FAILED_ASSERTS=$((FAILED_ASSERTS + 1))
else
    echo "[PASS] TEST_ENV_PARITY=check"
fi

if [ $FAILED_ASSERTS -gt 0 ]; then
    step_fail "$FAILED_ASSERTS env value assertion(s) failed"
fi

# Verify response is valid JSON object
echo "$ENV_RESPONSE" | jq -e 'type == "object"' >/dev/null 2>&1 || \
    step_fail "Response is not a JSON object"

step_pass "Env parity verified"

# ── Step 9: caution apps destroy ─────────────────────────────────────
STEP_NUM=9
log "Destroying app..."
"$CAUTION_BIN" -u "$GATEWAY_URL" apps destroy "$RESOURCE_ID" --force 2>&1
RESOURCE_ID=""
step_pass "App destroyed"

echo ""
echo "All steps completed successfully!"
