#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
#
# E2E authz-role test for the Caution platform.
# Requires: make up-test (starts gateway + api against the ephemeral test DB)
#
# Verifies state-changing handlers gate on org *role*, not just membership:
#   1. Wait for services
#   2. Create owner/member/viewer users in the same org
#   3. Deploy: viewer rejected (403), member/owner allowed past the role gate
#   4. Delete resource: member/viewer rejected (403), owner allowed
#   5. Delete cloud credential: member/viewer rejected (403), owner allowed
#   6. Set default cloud credential: member/viewer rejected (403), owner allowed
#   7. Delete payment method: member/viewer rejected (403), owner allowed
#   8. Set primary payment method: member/viewer rejected (403), owner allowed
#   9. Auto top-up: member/viewer rejected (403), owner allowed

set -euo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8000}"
TEST_DB_HOST="${TEST_DB_HOST:-postgres-test}"
LOG_DIR="tests/e2e/logs"
LOG_FILE="$LOG_DIR/authz-roles-$(date +%Y%m%d-%H%M%S).log"
STEP_NUM=0
STEPS_PASSED=0
STEPS_FAILED=0
STEP_RESULTS=()

ORG_ID=""
OWNER_SESSION=""
OWNER_USER=""
MEMBER_SESSION=""
MEMBER_USER=""
VIEWER_SESSION=""
VIEWER_USER=""

mkdir -p "$LOG_DIR"

exec > >(tee -a "$LOG_FILE") 2>&1

cleanup() {
  echo ""
  echo "=== Cleanup ==="

  if [ "$STEPS_FAILED" -gt 0 ]; then
    echo ""
    echo "--- API logs (last 30 lines) ---"
    docker logs api 2>&1 | tail -n 30 || true
  fi

  echo ""
  echo "========================================"
  echo "  Authz Roles E2E Test Results"
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
  echo "[authz-roles] $*"
}

# Helper: create an e2e test user, return "session_id user_id"
create_user() {
  local resp
  resp=$(curl -sf -X POST "$GATEWAY_URL/auth/e2e-login" -H "Content-Type: application/json")
  local sid uid
  sid=$(echo "$resp" | jq -r '.session_id')
  uid=$(echo "$resp" | jq -r '.user_id')
  echo "$sid $uid"
}

# Helper: run a curl request and print just the HTTP status code.
req_status() {
  local method="$1" path="$2" session="$3" body="${4:-}"
  if [ -n "$body" ]; then
    curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X "$method" "$GATEWAY_URL$path" \
      -H "X-Session-ID: $session" -H "Content-Type: application/json" -d "$body"
  else
    curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X "$method" "$GATEWAY_URL$path" \
      -H "X-Session-ID: $session"
  fi
}

attempt_deploy() {
  local session="$1"
  local raw http_code body
  raw=$(curl -s -w '\n%{http_code}' --max-time 10 -X POST "$GATEWAY_URL/api/deploy" \
    -H "X-Session-ID: $session" \
    -H "Content-Type: application/json" \
    -d '{"app_id": "'"$APP_ID"'", "branch": "main", "org_id": "'"$ORG_ID"'"}' \
    2>/dev/null || true)
  http_code=$(echo "$raw" | tail -1)
  body=$(echo "$raw" | sed '$d')

  # A non-200 real HTTP status (e.g. a gate that short-circuits before the
  # streamed handler runs, like the onboarding check) is the actual result.
  if [ "$http_code" != "200" ]; then
    echo "$http_code"
    return
  fi

  local status
  status=$(echo "$body" | grep -o '"status":[0-9]*' | tail -1 | grep -o '[0-9]*' || true)

  if [ -n "$status" ]; then
    echo "$status"
  elif echo "$body" | grep -qi "error"; then
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

# ── Step 2: Create owner/member/viewer users in one org ──────────────

STEP_NUM=2
log "Creating owner user + org..."
read -r OWNER_SESSION OWNER_USER <<<"$(create_user)"
if [ -z "$OWNER_SESSION" ] || [ "$OWNER_SESSION" = "null" ]; then
  step_fail "Owner e2e login (no session_id returned)"
fi

ORG_ID=$(docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -t -A -c "
INSERT INTO organizations (name) VALUES ('e2e-authz-org') RETURNING id;
" 2>/dev/null | head -1 | tr -d ' \n')

docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -c "
INSERT INTO organization_members (organization_id, user_id, role)
VALUES ('$ORG_ID', '$OWNER_USER', 'owner');
" >/dev/null 2>&1

log "  Org ID: $ORG_ID"
log "  Owner user: $OWNER_USER"

log "Creating member user..."
read -r MEMBER_SESSION MEMBER_USER <<<"$(create_user)"
docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -c "
INSERT INTO organization_members (organization_id, user_id, role)
VALUES ('$ORG_ID', '$MEMBER_USER', 'member');
" >/dev/null 2>&1
log "  Member user: $MEMBER_USER"

log "Creating viewer user..."
read -r VIEWER_SESSION VIEWER_USER <<<"$(create_user)"
docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -c "
INSERT INTO organization_members (organization_id, user_id, role)
VALUES ('$ORG_ID', '$VIEWER_USER', 'viewer');
" >/dev/null 2>&1
log "  Viewer user: $VIEWER_USER"

# Mark all three users onboarded so the unrelated onboarding gate
# (middleware::ensure_user_has_org / user_is_onboarded) doesn't 402
# them before the role check under test ever runs.
docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -c "
UPDATE users SET email_verified_at = NOW(), payment_method_added_at = NOW()
WHERE id IN ('$OWNER_USER', '$MEMBER_USER', '$VIEWER_USER');
" >/dev/null 2>&1

step_pass "Created owner/member/viewer in org ${ORG_ID:0:8}..."

# Seed a provider account, resource type, and one compute resource so
# deploy/delete requests reach the role gate rather than 404ing first.

PROVIDER_ACCOUNT_ID=$(docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -t -A -c "
INSERT INTO provider_accounts (organization_id, provider_id, external_account_id, account_name, is_active)
SELECT '$ORG_ID', id, '123456789012', 'e2e-authz-account', true
FROM providers WHERE provider_type = 'aws'
ON CONFLICT (organization_id, provider_id, external_account_id) DO UPDATE SET is_active = true
RETURNING id;
" 2>/dev/null | head -1 | tr -d ' \n')

RESOURCE_TYPE_ID=$(docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -t -A -c "
SELECT id FROM resource_types WHERE type_code = 'ec2-instance' LIMIT 1;
" 2>/dev/null | head -1 | tr -d ' \n')

APP_ID=$(docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -t -A -c "
INSERT INTO compute_resources (organization_id, provider_account_id, resource_type_id,
  provider_resource_id, resource_name, state, created_by)
VALUES ('$ORG_ID', '$PROVIDER_ACCOUNT_ID', '$RESOURCE_TYPE_ID',
  'i-fake-authz-test', 'authz-test-resource', 'running', '$OWNER_USER')
RETURNING id;
" 2>/dev/null | head -1 | tr -d ' \n')

log "  Test app resource: $APP_ID"

# ── Step 3: Deploy — viewer rejected, member/owner allowed ───────────

STEP_NUM=3
log "Testing deploy role gate..."

RESULT=$(attempt_deploy "$VIEWER_SESSION")
if [ "$RESULT" != "403" ]; then
  step_fail "Viewer deploy: expected 403, got $RESULT"
fi
log "  Viewer deploy: rejected ($RESULT)"

RESULT=$(attempt_deploy "$MEMBER_SESSION")
if [ "$RESULT" = "403" ]; then
  step_fail "Member deploy: unexpectedly rejected with 403"
fi
log "  Member deploy: passed role gate (result: $RESULT)"

RESULT=$(attempt_deploy "$OWNER_SESSION")
if [ "$RESULT" = "403" ]; then
  step_fail "Owner deploy: unexpectedly rejected with 403"
fi
log "  Owner deploy: passed role gate (result: $RESULT)"

step_pass "Deploy role gate (viewer blocked, member/owner allowed)"

# ── Step 4: Delete resource — member/viewer rejected, owner allowed ──

STEP_NUM=4
log "Testing delete_resource role gate..."

STATUS=$(req_status DELETE "/api/resources/$APP_ID" "$MEMBER_SESSION")
if [ "$STATUS" != "403" ]; then
  step_fail "Member delete_resource: expected 403, got $STATUS"
fi

STATUS=$(req_status DELETE "/api/resources/$APP_ID" "$VIEWER_SESSION")
if [ "$STATUS" != "403" ]; then
  step_fail "Viewer delete_resource: expected 403, got $STATUS"
fi

STATUS=$(req_status DELETE "/api/resources/$APP_ID" "$OWNER_SESSION")
if [ "$STATUS" = "403" ]; then
  step_fail "Owner delete_resource: unexpectedly rejected with 403"
fi
log "  Owner delete_resource: passed role gate (result: $STATUS)"

step_pass "delete_resource role gate (member/viewer blocked, owner allowed)"

# ── Step 5/6: Cloud credentials — delete + set-default ───────────────

STEP_NUM=5
log "Testing cloud-credential role gates (random id — role check runs before lookup)..."
FAKE_ID="00000000-0000-0000-0000-000000000000"

for pair in "delete:$MEMBER_SESSION" "delete:$VIEWER_SESSION"; do
  session="${pair#*:}"
  STATUS=$(req_status DELETE "/api/credentials/$FAKE_ID" "$session")
  if [ "$STATUS" != "403" ]; then
    step_fail "Non-admin delete_cloud_credential: expected 403, got $STATUS"
  fi
done
STATUS=$(req_status DELETE "/api/credentials/$FAKE_ID" "$OWNER_SESSION")
if [ "$STATUS" = "403" ]; then
  step_fail "Owner delete_cloud_credential: unexpectedly rejected with 403"
fi
log "  Owner delete_cloud_credential: passed role gate (result: $STATUS, expect 404)"
step_pass "delete_cloud_credential role gate (member/viewer blocked, owner allowed)"

STEP_NUM=6
for pair in "post:$MEMBER_SESSION" "post:$VIEWER_SESSION"; do
  session="${pair#*:}"
  STATUS=$(req_status POST "/api/credentials/$FAKE_ID/default" "$session")
  if [ "$STATUS" != "403" ]; then
    step_fail "Non-admin set_default_cloud_credential: expected 403, got $STATUS"
  fi
done
STATUS=$(req_status POST "/api/credentials/$FAKE_ID/default" "$OWNER_SESSION")
if [ "$STATUS" = "403" ]; then
  step_fail "Owner set_default_cloud_credential: unexpectedly rejected with 403"
fi
log "  Owner set_default_cloud_credential: passed role gate (result: $STATUS, expect 404)"
step_pass "set_default_cloud_credential role gate (member/viewer blocked, owner allowed)"

# ── Step 7/8/9: Billing — payment methods + auto top-up ──────────────

STEP_NUM=7
log "Testing billing role gates..."

for pair in "$MEMBER_SESSION" "$VIEWER_SESSION"; do
  STATUS=$(req_status DELETE "/api/billing/payment-methods/$FAKE_ID" "$pair")
  if [ "$STATUS" != "403" ]; then
    step_fail "Non-admin delete_payment_method: expected 403, got $STATUS"
  fi
done
STATUS=$(req_status DELETE "/api/billing/payment-methods/$FAKE_ID" "$OWNER_SESSION")
if [ "$STATUS" = "403" ]; then
  step_fail "Owner delete_payment_method: unexpectedly rejected with 403"
fi
log "  Owner delete_payment_method: passed role gate (result: $STATUS, expect 404)"
step_pass "delete_payment_method role gate (member/viewer blocked, owner allowed)"

STEP_NUM=8
for pair in "$MEMBER_SESSION" "$VIEWER_SESSION"; do
  STATUS=$(req_status POST "/api/billing/payment-methods/$FAKE_ID/set-primary" "$pair")
  if [ "$STATUS" != "403" ]; then
    step_fail "Non-admin set_primary_payment_method: expected 403, got $STATUS"
  fi
done
STATUS=$(req_status POST "/api/billing/payment-methods/$FAKE_ID/set-primary" "$OWNER_SESSION")
if [ "$STATUS" = "403" ]; then
  step_fail "Owner set_primary_payment_method: unexpectedly rejected with 403"
fi
log "  Owner set_primary_payment_method: passed role gate (result: $STATUS, expect 404)"
step_pass "set_primary_payment_method role gate (member/viewer blocked, owner allowed)"

STEP_NUM=9
AUTO_TOPUP_BODY='{"enabled": false, "amount_dollars": 0}'
for pair in "$MEMBER_SESSION" "$VIEWER_SESSION"; do
  STATUS=$(req_status PUT "/api/billing/auto-topup" "$pair" "$AUTO_TOPUP_BODY")
  if [ "$STATUS" != "403" ]; then
    step_fail "Non-admin put_auto_topup: expected 403, got $STATUS"
  fi
done
STATUS=$(req_status PUT "/api/billing/auto-topup" "$OWNER_SESSION" "$AUTO_TOPUP_BODY")
if [ "$STATUS" = "403" ]; then
  step_fail "Owner put_auto_topup: unexpectedly rejected with 403"
fi
log "  Owner put_auto_topup: passed role gate (result: $STATUS, expect 200)"
step_pass "put_auto_topup role gate (member/viewer blocked, owner allowed)"

# ── Cleanup test data ────────────────────────────────────────────────

log "Cleaning up test resources..."
docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -c "
DELETE FROM compute_resources WHERE organization_id = '$ORG_ID';
DELETE FROM provider_accounts WHERE organization_id = '$ORG_ID';
DELETE FROM organization_members WHERE organization_id = '$ORG_ID';
DELETE FROM organizations WHERE id = '$ORG_ID';
" >/dev/null 2>&1 || true
