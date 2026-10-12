#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
#
# E2E test: an API restart resets abandoned `pending` deploys to `failed`.
# Requires: make up-test (no AWS needed).
#
# Tests:
#   1. Log in, seed a pending app (with deploy_attempt_id) and a pending app
#      without one
#   2. DELETE is refused with 409 while the app is pending
#   3. Restart the API container
#   4. Attempt-owned pending app is failed with NULL deploy_attempt_id; the
#      other row is untouched
#   5. DELETE no longer returns 409

set -euo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8000}"
TEST_DB_HOST="${TEST_DB_HOST:-postgres-test}"
LOG_DIR="tests/e2e/logs"
LOG_FILE="$LOG_DIR/stuck-pending-$(date +%Y%m%d-%H%M%S).log"
STEP_NUM=0
STEPS_PASSED=0
STEPS_FAILED=0
STEP_RESULTS=()

SESSION_ID=""
USER_ID=""
ORG_ID=""
APP_ID=""
APP_ID_NO_ATTEMPT=""

mkdir -p "$LOG_DIR"

exec > >(tee -a "$LOG_FILE") 2>&1

psql_q() {
    docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -v ON_ERROR_STOP=1 -t -A -c "$1" | head -1 | tr -d ' \r\n'
}

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    if [ "$STEPS_FAILED" -gt 0 ]; then
        docker logs api 2>&1 | tail -n 30 || true
    fi
    docker exec "$TEST_DB_HOST" psql -U postgres -d caution_test -c "
DELETE FROM compute_resources WHERE id IN ('${APP_ID:-00000000-0000-0000-0000-000000000000}', '${APP_ID_NO_ATTEMPT:-00000000-0000-0000-0000-000000000000}');
" >/dev/null 2>&1 || true
    echo ""
    echo "========================================"
    echo "  Stuck Pending E2E Test Results"
    echo "========================================"
    for result in "${STEP_RESULTS[@]}"; do
        echo "  $result"
    done
    echo "----------------------------------------"
    echo "  Passed: $STEPS_PASSED  Failed: $STEPS_FAILED"
    echo "========================================"
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
    echo "[e2e] $*"
}

delete_status() {
    curl -s -o /dev/null -w '%{http_code}' --max-time 60 -X DELETE \
        "$GATEWAY_URL/api/resources/$APP_ID" -H "X-Session-ID: $SESSION_ID"
}

# ── Step 1: Login and seed ───────────────────────────────────────────

STEP_NUM=1
for i in $(seq 1 30); do
    curl -sf "$GATEWAY_URL/health" >/dev/null 2>&1 && break
    [ "$i" -eq 30 ] && step_fail "Gateway health check"
    sleep 1
done

LOGIN_RESPONSE=$(curl -sf -X POST "$GATEWAY_URL/auth/e2e-login" -H "Content-Type: application/json")
SESSION_ID=$(echo "$LOGIN_RESPONSE" | jq -r '.session_id')
USER_ID=$(echo "$LOGIN_RESPONSE" | jq -r '.user_id')
[ -n "$SESSION_ID" ] && [ "$SESSION_ID" != "null" ] || step_fail "E2E login (no session_id)"

ORG_ID=$(psql_q "SELECT o.id FROM organizations o
JOIN organization_members om ON om.organization_id = o.id
WHERE om.user_id = '$USER_ID' LIMIT 1;" || true)
if [ -z "$ORG_ID" ]; then
    ORG_ID=$(psql_q "INSERT INTO organizations (name) VALUES ('e2e-stuck-pending-org') RETURNING id;")
    psql_q "INSERT INTO organization_members (organization_id, user_id, role) VALUES ('$ORG_ID', '$USER_ID', 'owner');" >/dev/null
fi

psql_q "UPDATE users SET email_verified_at = NOW(), payment_method_added_at = NOW() WHERE id = '$USER_ID';" >/dev/null

CLAIM_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GATEWAY_URL/user/username" \
    -H "X-Session-ID: $SESSION_ID" -H 'Content-Type: application/json' \
    -d "{\"username\":\"stuck-$(date +%s)$RANDOM\"}")
[ "$CLAIM_CODE" = "200" ] || step_fail "Claim username (HTTP $CLAIM_CODE)"

PROVIDER_ACCOUNT_ID=$(psql_q "INSERT INTO provider_accounts (organization_id, provider_id, external_account_id, account_name, is_active)
SELECT '$ORG_ID', id, '123456789012', 'e2e-test-account', true
FROM providers WHERE provider_type = 'aws'
ON CONFLICT (organization_id, provider_id, external_account_id) DO UPDATE SET is_active = true
RETURNING id;")
RESOURCE_TYPE_ID=$(psql_q "SELECT id FROM resource_types WHERE type_code = 'ec2-instance' LIMIT 1;")

seed_app() {
    psql_q "INSERT INTO compute_resources (organization_id, provider_account_id, resource_type_id,
  provider_resource_id, resource_name, state, deploy_attempt_id, created_by)
VALUES ('$ORG_ID', '$PROVIDER_ACCOUNT_ID', '$RESOURCE_TYPE_ID',
  'i-fake-stuck-$1', 'stuck-pending-$1', 'pending', $2, '$USER_ID')
RETURNING id;"
}
APP_ID=$(seed_app a "gen_random_uuid()")
APP_ID_NO_ATTEMPT=$(seed_app b "NULL")
step_pass "Login + seed pending apps ($APP_ID, $APP_ID_NO_ATTEMPT)"

# ── Step 2: Wedged before restart ────────────────────────────────────

STEP_NUM=2
CODE=$(delete_status)
[ "$CODE" = "409" ] || step_fail "DELETE of pending app should be 409 before restart, got $CODE"
step_pass "DELETE refused with 409 while pending"

# ── Step 3: Restart API ──────────────────────────────────────────────

STEP_NUM=3
docker restart api >/dev/null
for i in $(seq 1 60); do
    # Only a 200 from an API-backed route proves the API is up (the gateway
    # answers /health, and 502s, while the API is still starting).
    [ "$(curl -s -o /dev/null -w '%{http_code}' -H "X-Session-ID: $SESSION_ID" "$GATEWAY_URL/api/resources")" = "200" ] && break
    [ "$i" -eq 60 ] && step_fail "API did not come back after restart"
    sleep 1
done
step_pass "API restarted"

# ── Step 4: Rows reset ───────────────────────────────────────────────

STEP_NUM=4
ROW=$(psql_q "SELECT state || ':' || COALESCE(deploy_attempt_id::text, 'null') FROM compute_resources WHERE id = '$APP_ID';")
[ "$ROW" = "failed:null" ] || step_fail "attempt-owned pending app should be failed:null, got $ROW"
ROW=$(psql_q "SELECT state FROM compute_resources WHERE id = '$APP_ID_NO_ATTEMPT';")
[ "$ROW" = "pending" ] || step_fail "pending app without attempt id should be untouched, got $ROW"
API_LOGS=$(docker logs api 2>&1)
grep -q "reset abandoned pending deploy" <<<"$API_LOGS" || step_fail "API did not log the reset"
step_pass "Abandoned pending app reset to failed; row without attempt id untouched"

# ── Step 5: Destroy no longer blocked ────────────────────────────────

STEP_NUM=5
CODE=$(delete_status)
[ "$CODE" != "409" ] || step_fail "DELETE still returns 409 after restart"
step_pass "DELETE no longer returns 409 (got $CODE)"
