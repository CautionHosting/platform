#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
#
# E2E billing gates test for the Caution platform.
# Requires: make up-test-billing (starts services including metering + email)
#
# Tests billing enforcement gates:
#   1. Wait for services
#   2. Create test user
#   3. Deploy with zero credits — rejected (402)
#   4. Deploy with $20 credits — rejected (402, below $25 minimum)
#   5. Deploy with $25 credits — passes billing gate
#   6. Deploy while org is credit-suspended — rejected (402)
#   7. Unsuspend org, deploy succeeds again
#   8. Resource limit: deploy up to max_resources_per_org — succeeds
#   9. Resource limit: deploy one more — rejected (429)
#  10. Destroy a resource, deploy again — passes resource limit

set -euo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8000}"
TEST_DB_HOST="${TEST_DB_HOST:-postgres-test}"
LOG_DIR="tests/e2e/logs"
LOG_FILE="$LOG_DIR/billing-gates-$(date +%Y%m%d-%H%M%S).log"
STEP_NUM=0
STEPS_PASSED=0
STEPS_FAILED=0
STEP_RESULTS=()

# Test state
SESSION_ID=""
USER_ID=""
ORG_ID=""

mkdir -p "$LOG_DIR"

exec > >(tee -a "$LOG_FILE") 2>&1

cleanup() {
  echo ""
  echo "=== Cleanup ==="

  if [ "$STEPS_FAILED" -gt 0 ]; then
    echo ""
    echo "--- API logs (last 30 lines) ---"
    docker logs api 2>&1 | tail -n 30 || true
    echo ""
    echo "--- Gateway logs (last 20 lines) ---"
    docker logs gateway 2>&1 | tail -n 20 || true
  fi

  echo ""
  echo "========================================"
  echo "  Billing Gates E2E Test Results"
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

log() {
  echo "[billing-gates] $*"
}

# Helper: set wallet balance for test user
set_balance() {
  local cents=$1
  docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -c "
  INSERT INTO wallet_balance (user_id, balance_cents)
  VALUES ('$USER_ID', $cents)
  ON CONFLICT (user_id) DO UPDATE SET balance_cents = $cents;
  " >/dev/null 2>&1
}

# Helper: attempt deploy via gateway, return the error status from the
# streamed response body. The deploy endpoint always returns HTTP 200 and
# streams results as newline-delimited JSON. On billing/resource gate
# failure, the last line contains {"error": "...", "status": 402|429}.
# Returns the status field from the error JSON, or "ok" if no error found.
attempt_deploy() {
  # Reset app state to 'running' before each attempt so we don't get 409 Conflict
  # from a previous deploy that transitioned it to 'pending' or 'failed'.
  docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -c "
  UPDATE compute_resources SET state = 'running' WHERE id = '$APP_ID';
  " >/dev/null 2>&1

  local body
  body=$(curl -s --max-time 10 -X POST "$GATEWAY_URL/api/deploy" \
    -H "X-Session-ID: $SESSION_ID" \
    -H "Content-Type: application/json" \
    -d '{"app_id": "'"$APP_ID"'", "branch": "main", "org_id": "'"$ORG_ID"'"}' \
    2>/dev/null || true)

  # Check for error status in the streamed JSON response
  local status
  status=$(echo "$body" | grep -o '"status":[0-9]*' | tail -1 | grep -o '[0-9]*' || true)

  if [ -n "$status" ]; then
    echo "$status"
  elif echo "$body" | grep -qi "error"; then
    # Has error but no numeric status — extract what we can
    echo "error"
  else
    echo "ok"
  fi
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

# ── Step 2: Create test user ─────────────────────────────────────────

STEP_NUM=2
log "Creating test user via e2e-login..."

LOGIN_RESPONSE=$(curl -sf -X POST "$GATEWAY_URL/auth/e2e-login" \
  -H "Content-Type: application/json")

SESSION_ID=$(echo "$LOGIN_RESPONSE" | jq -r '.session_id')
USER_ID=$(echo "$LOGIN_RESPONSE" | jq -r '.user_id')

if [ -z "$SESSION_ID" ] || [ "$SESSION_ID" = "null" ]; then
  step_fail "E2E login (no session_id returned)"
fi

log "  User ID: $USER_ID"

# Get or create org
ORG_ID=$(docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -t -c "
SELECT o.id FROM organizations o
JOIN organization_members om ON om.organization_id = o.id
WHERE om.user_id = '$USER_ID' LIMIT 1;
" 2>/dev/null | tr -d ' \n' || true)

if [ -z "$ORG_ID" ] || [ "$ORG_ID" = "null" ]; then
  log "  No org found — creating test organization..."
  ORG_ID=$(docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -t -A -c "
  INSERT INTO organizations (name) VALUES ('e2e-gates-org')
  RETURNING id;
  " 2>/dev/null | head -1 | tr -d ' \n' || true)
  docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -c "
  INSERT INTO organization_members (organization_id, user_id, role)
  VALUES ('$ORG_ID', '$USER_ID', 'owner');
  " >/dev/null 2>&1 || true
fi

# Mark user as onboarded
docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -c "
UPDATE users SET email_verified_at = NOW(), payment_method_added_at = NOW() WHERE id = '$USER_ID';
" >/dev/null 2>&1

log "  Org ID: $ORG_ID"

# Set up provider account, resource type ref, and a test compute resource
# so that deploy requests reach the billing gate (which runs after resource lookup).
PROVIDER_ACCOUNT_ID=$(docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -t -A -c "
INSERT INTO provider_accounts (organization_id, provider_id, external_account_id, account_name, is_active)
SELECT '$ORG_ID', id, '123456789012', 'e2e-test-account', true
FROM providers WHERE provider_type = 'aws'
ON CONFLICT (organization_id, provider_id, external_account_id) DO UPDATE SET is_active = true
RETURNING id;
" 2>/dev/null | head -1 | tr -d ' \n')

RESOURCE_TYPE_ID=$(docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -t -A -c "
SELECT id FROM resource_types WHERE type_code = 'ec2-instance' LIMIT 1;
" 2>/dev/null | head -1 | tr -d ' \n')

# Create the test app resource that deploy requests will reference
APP_ID=$(docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -t -A -c "
INSERT INTO compute_resources (organization_id, provider_account_id, resource_type_id,
  provider_resource_id, resource_name, state, created_by)
VALUES ('$ORG_ID', '$PROVIDER_ACCOUNT_ID', '$RESOURCE_TYPE_ID',
  'i-fake-billing-gate-test', 'billing-gate-test', 'running', '$USER_ID')
RETURNING id;
" 2>/dev/null | head -1 | tr -d ' \n')

log "  Provider account: $PROVIDER_ACCOUNT_ID"
log "  Test app: $APP_ID"

step_pass "E2E login (user: ${USER_ID:0:8}..., org: ${ORG_ID:0:8}...)"

# ── Step 3: Deploy with zero credits — should be rejected ────────────

STEP_NUM=3
log "Testing deploy with zero credits..."

# Ensure no wallet balance exists
docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -c "
DELETE FROM wallet_balance WHERE user_id = '$USER_ID';
" >/dev/null 2>&1

RESULT=$(attempt_deploy)
if [ "$RESULT" = "402" ]; then
  step_pass "Zero credits: deploy rejected (402)"
else
  step_fail "Zero credits: expected 402, got $RESULT"
fi

# ── Step 4: Deploy with $20 (below $25 minimum) — should be rejected ─

STEP_NUM=4
log "Testing deploy with \$20 credits (below \$25 minimum)..."

set_balance 2000
RESULT=$(attempt_deploy)
if [ "$RESULT" = "402" ]; then
  step_pass "\$20 credits: deploy rejected (402)"
else
  step_fail "\$20 credits: expected 402, got $RESULT"
fi

# ── Step 5: Deploy with $25 — should pass billing gate ───────────────

STEP_NUM=5
log "Testing deploy with \$25 credits..."

set_balance 2500
RESULT=$(attempt_deploy)

# Should NOT be 402 — it passes the billing gate. May fail for other reasons
# (no actual repo/resource) which is fine; we're testing the gate, not the deploy.
if [ "$RESULT" != "402" ]; then
  log "  Balance 2500c: passed billing gate (result: $RESULT)"
  step_pass "\$25 credits: billing gate passed (result: $RESULT)"
else
  step_fail "\$25 credits: still rejected with 402"
fi

# ── Step 6: Deploy while credit-suspended — should be rejected ───────

STEP_NUM=6
log "Testing deploy while org is credit-suspended..."

# Suspend the org
docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -c "
UPDATE organizations SET credit_suspended_at = NOW() WHERE id = '$ORG_ID';
" >/dev/null 2>&1

# Keep balance at $25 — should still be rejected due to suspension
RESULT=$(attempt_deploy)
if [ "$RESULT" = "402" ]; then
  step_pass "Credit-suspended org: deploy rejected (402)"
else
  step_fail "Credit-suspended org: expected 402, got $RESULT"
fi

# ── Step 7: Unsuspend org, deploy passes again ───────────────────────

STEP_NUM=7
log "Testing deploy after unsuspending org..."

docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -c "
UPDATE organizations SET credit_suspended_at = NULL WHERE id = '$ORG_ID';
" >/dev/null 2>&1

RESULT=$(attempt_deploy)
if [ "$RESULT" != "402" ]; then
  log "  Unsuspended: passed billing gate (result: $RESULT)"
  step_pass "Unsuspended org: billing gate passed (result: $RESULT)"
else
  step_fail "Unsuspended org: still rejected with 402"
fi

# ── Step 8: Resource limit — fill up to max ──────────────────────────

STEP_NUM=8
log "Testing resource limit enforcement..."

# Read the max_resources_per_org from config.json in the API container
MAX_RESOURCES=$(docker exec api cat config.json 2>/dev/null | jq -r '.max_resources_per_org // 10' 2>/dev/null || echo "10")
log "  max_resources_per_org: $MAX_RESOURCES"

# Insert fake active resources up to the limit
# First clean up any existing test resources
docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -c "
DELETE FROM compute_resources WHERE organization_id = '$ORG_ID' AND resource_name LIKE 'gate-test-%';
" >/dev/null 2>&1

for i in $(seq 1 "$MAX_RESOURCES"); do
  docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -t -A -c "
  INSERT INTO compute_resources (organization_id, provider_account_id, resource_type_id,
    provider_resource_id, resource_name, state)
  VALUES ('$ORG_ID', '$PROVIDER_ACCOUNT_ID', '$RESOURCE_TYPE_ID',
    'i-gate-test-$i', 'gate-test-$i', 'running');
  " >/dev/null 2>&1
done

log "  Inserted $MAX_RESOURCES fake active resources"

# Now attempt deploy — should hit resource limit (429)
RESULT=$(attempt_deploy)
if [ "$RESULT" = "429" ]; then
  step_pass "Resource limit: deploy rejected at $MAX_RESOURCES/$MAX_RESOURCES (429)"
else
  log "  Got result: $RESULT (expected 429)"
  if [ "$RESULT" = "402" ]; then
    step_fail "Resource limit: got 402 instead of 429 (billing gate ran before resource check)"
  else
    step_fail "Resource limit: expected 429, got $RESULT"
  fi
fi

# ── Step 9: Destroy one resource, deploy passes resource limit ───────

STEP_NUM=9
log "Testing deploy after destroying one resource..."

# Mark one resource as destroyed
docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -c "
UPDATE compute_resources
SET state = 'terminated', destroyed_at = NOW()
WHERE organization_id = '$ORG_ID' AND resource_name = 'gate-test-1';
" >/dev/null 2>&1

RESULT=$(attempt_deploy)
if [ "$RESULT" != "429" ]; then
  log "  After destroy: passed resource limit (result: $RESULT)"
  step_pass "Resource freed: deploy passes resource limit (result: $RESULT)"
else
  step_fail "Resource freed: still rejected with 429 after destroying one resource"
fi

# ── Cleanup test data ────────────────────────────────────────────────

log "Cleaning up test resources..."
docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -c "
DELETE FROM compute_resources WHERE organization_id = '$ORG_ID' AND resource_name LIKE 'gate-test-%';
" >/dev/null 2>&1
