#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
#
# E2E billing gates test for the Caution platform.
# Requires: make up-test-billing (starts services including metering + email)
#
# Tests billing enforcement gates:
#   1. Wait for services
#   2. Create test user via e2e-login and claim a username (lifts the gate)
#   3. Deploy with zero credits — rejected (4xx)
#   4. Deploy with $20 credits — rejected (4xx, below $25 minimum)
#   5. Deploy with $25 credits — passes billing gate
#   6. Deploy while org is credit-suspended — rejected (4xx)
#   7. Unsuspend org, deploy succeeds again
#   8. Resource limit: deploy up to max_resources_per_org — succeeds
#   9. Resource limit: deploy one more — rejected (429)
#  10. Destroy a resource, deploy again — passes resource limit

set -euo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8000}"
TEST_DB_HOST="${TEST_DB_HOST:-postgres-test}"
FIXTURES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)"
GIT_SSH_PORT="${GIT_SSH_PORT:-2222}"
WORK_DIR=$(mktemp -d)
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
SSH_KEY_PATH="$WORK_DIR/billing-gates-test-key"

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

# Helper: set an exact derived balance for the org.
set_balance() {
  local cents=$1
  docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -c "
  DELETE FROM credit_ledger WHERE organization_id = '$ORG_ID';
  DELETE FROM usage_ledger WHERE organization_id = '$ORG_ID';
  DELETE FROM subscription_ledger WHERE organization_id = '$ORG_ID';
  " >/dev/null 2>&1

  if [ "$cents" -gt 0 ]; then
    docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -c "
    INSERT INTO credit_ledger (organization_id, delta_cents, entry_type, description)
    VALUES ('$ORG_ID', $cents, 'purchase', 'billing gate seed');
    " >/dev/null 2>&1
  fi
}

# Helper: true when RESULT holds a 4xx client-error status (e.g. 402, 403).
is_4xx() {
  case "$1" in
    4[0-9][0-9]) return 0 ;;
    *) return 1 ;;
  esac
}

# Helper: attempt deploy via gateway, return the error status from the
# streamed response body. The deploy endpoint always returns HTTP 200 and
# streams results as newline-delimited JSON. On billing/resource gate
# failure, the last line contains {"error": "...", "status": 402|429}.
# Returns the status field from the error JSON, or "ok" if no error found.
attempt_deploy() {
  # Reset the app to a deployable state before each attempt. A deploy transitions
  # the resource to 'pending' (then 'running'/'failed'); a live ('running') app
  # cannot be re-deployed in place, and a 'pending' one returns 409 DeployInProgress.
  # Reset to 'initialized' so every gate attempt starts from the same deployable state.
  docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -c "
  UPDATE compute_resources SET state = 'initialized', deploy_attempt_id = NULL WHERE id = '$APP_ID';
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
  # Link the user to the org. deploy_logic requires the authenticated user to be
  # a member of req.org_id (the org carried in the deploy request); without this
  # row it returns NotOrgMember (403) before ever reaching the balance check, so
  # the gate would deny regardless of the seeded credit amount.
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

# Generate the app resource id up front. deploy_logic resolves the commit to
# build via get_commit_sha, which runs
#   git --git-dir {data_dir}/git-repos/{app_id}.git rev-parse refs/heads/main
# The bare repo only exists once a repo has been pushed to that app over git
# SSH (the gateway does `git init --bare` on first push). So we must create the
# resource row keyed by this id AND actually push the demo fixture before any
# deploy call, otherwise deploy proceeds past the billing gate and then fails
# get_commit_sha with a 400.
APP_ID=$(docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -t -A -c "
SELECT gen_random_uuid();
" 2>/dev/null | head -1 | tr -d ' \n')

log "  Provider account: $PROVIDER_ACCOUNT_ID"
log "  Test app: $APP_ID"

# Generate an SSH key and register it for the user. The gateway authorizes a
# git push by matching the presented key's fingerprint against ssh_keys joined to
# an organization_member of the app's org (get_user_for_app_by_ssh_key), so this
# must be done before pushing. Insert directly via SQL to avoid the username gate.
ssh-keygen -t ed25519 -f "$SSH_KEY_PATH" -N "" -q
SSH_PUB_KEY=$(cat "$SSH_KEY_PATH.pub")
# ssh-keygen prints "SHA256:<base64url>"; the gateway's generate_ssh_fingerprint
# stores the bare base64url (no prefix), so strip it to match auth lookups.
FP=$(ssh-keygen -lf - <<< "$SSH_PUB_KEY" 2>/dev/null | awk '{print $2}' | sed 's/^SHA256://')
docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -c "
INSERT INTO ssh_keys (user_id, public_key, fingerprint, key_type, name)
VALUES ('$USER_ID', '$SSH_PUB_KEY', '$FP', 'ssh-ed25519', 'e2e-gates');
" >/dev/null 2>&1 || true

# Create the test app resource that deploy requests will reference (keyed by APP_ID).
# State is 'initialized' (never deployed), NOT 'running': a running/stopped app is
# live and cannot be re-deployed in place (handle_git_push rejects it with RunningApp;
# deploy_logic likewise only transitions non-live states to pending). 'initialized'
# also keeps the resource-limit count correct, since that check counts active
# (non-terminated/failed) resources excluding the deploying app itself.
docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -c "
INSERT INTO compute_resources (id, organization_id, provider_account_id, resource_type_id,
  provider_resource_id, resource_name, state, created_by)
VALUES ('$APP_ID', '$ORG_ID', '$PROVIDER_ACCOUNT_ID', '$RESOURCE_TYPE_ID',
  'i-fake-billing-gate-test', 'billing-gate-test', 'initialized', '$USER_ID');
" >/dev/null 2>&1 || true

# Seed the bare git repo for APP_ID by pushing the demo fixture over git SSH.
CLONE_DIR="$WORK_DIR/demo-app"
cp -r "$FIXTURES_DIR/demo-app-happy-path" "$CLONE_DIR"
cd "$CLONE_DIR"
git init -q -b main
git -c user.email="e2e@caution.dev" -c user.name="Caution E2E" add .
git -c user.email="e2e@caution.dev" -c user.name="Caution E2E" commit -m "Initial commit" --quiet
eval "$(ssh-agent -s)" >/dev/null
ssh-add "$SSH_KEY_PATH" 2>/dev/null
git remote add caution "ssh://git@localhost:$GIT_SSH_PORT/$APP_ID.git"
export GIT_SSH_COMMAND="ssh -i $SSH_KEY_PATH -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $GIT_SSH_PORT"
if ! git push caution HEAD:main 2>&1; then
  step_fail "git push (bare repo for APP_ID not seeded — deploy would fail get_commit_sha)"
fi
cd "$WORK_DIR"

# Claim a real username. e2e-login seeds the user in the placeholder state, and
# every protected /api route (including /api/deploy below) runs through
# username_claim_gate_middleware, which 403s `username_required` until a real
# username is claimed. Without this, deploy requests never reach the billing
# gate and every assertion below sees "username not claimed" instead.
CLAIMED_USERNAME="gate-test-$(date +%s)$RANDOM"
CLAIM_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GATEWAY_URL/user/username" \
  -H "X-Session-ID: $SESSION_ID" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$CLAIMED_USERNAME\"}")
if [ "$CLAIM_CODE" != "200" ]; then
  step_fail "Failed to claim username (HTTP $CLAIM_CODE) — protected routes stay gated"
fi
log "  Claimed username: $CLAIMED_USERNAME"

step_pass "E2E login (user: ${USER_ID:0:8}..., org: ${ORG_ID:0:8}...)"

# ── Step 3: Deploy with zero credits — should be rejected ────────────

STEP_NUM=3
log "Testing deploy with zero credits..."

# Ensure no derived balance exists
set_balance 0

RESULT=$(attempt_deploy)
if is_4xx "$RESULT"; then
  step_pass "Zero credits: deploy rejected ($RESULT)"
else
  step_fail "Zero credits: expected a 4xx, got $RESULT"
fi

# ── Step 4: Deploy with $20 (below $25 minimum) — should be rejected ─

STEP_NUM=4
log "Testing deploy with \$20 credits (below \$25 minimum)..."

set_balance 2000
RESULT=$(attempt_deploy)
if is_4xx "$RESULT"; then
  step_pass "\$20 credits: deploy rejected ($RESULT)"
else
  step_fail "\$20 credits: expected a 4xx, got $RESULT"
fi

# ── Step 5: Deploy with $25 — should pass billing gate ───────────────

STEP_NUM=5
log "Testing deploy with \$25 credits..."

set_balance 2500
RESULT=$(attempt_deploy)

# Should NOT be a 4xx — it passes the billing gate. May fail for other reasons
# (no actual repo/resource) which is fine; we're testing the gate, not the deploy.
if ! is_4xx "$RESULT"; then
  log "  Balance 2500c: passed billing gate (result: $RESULT)"
  step_pass "\$25 credits: billing gate passed (result: $RESULT)"
else
  step_fail "\$25 credits: still rejected with $RESULT"
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
if is_4xx "$RESULT"; then
  step_pass "Credit-suspended org: deploy rejected ($RESULT)"
else
  step_fail "Credit-suspended org: expected a 4xx, got $RESULT"
fi

# ── Step 7: Unsuspend org, deploy passes again ───────────────────────

STEP_NUM=7
log "Testing deploy after unsuspending org..."

docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -c "
UPDATE organizations SET credit_suspended_at = NULL WHERE id = '$ORG_ID';
" >/dev/null 2>&1

RESULT=$(attempt_deploy)
if ! is_4xx "$RESULT"; then
  log "  Unsuspended: passed billing gate (result: $RESULT)"
  step_pass "Unsuspended org: billing gate passed (result: $RESULT)"
else
  step_fail "Unsuspended org: still rejected with $RESULT"
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
