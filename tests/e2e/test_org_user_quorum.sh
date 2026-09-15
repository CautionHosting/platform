#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial
#
# Opt-in authorization/discovery test. Does not prove cryptographic generation.
#
# This intentionally does not run as part of default make test-e2e. It requires:
#   RUN_ORG_USER_QUORUM_E2E=1
#   a running e2e gateway/API stack
#
# Example:
#   RUN_ORG_USER_QUORUM_E2E=1 bash tests/e2e/test_org_user_quorum.sh

set -euo pipefail

if [ "${RUN_ORG_USER_QUORUM_E2E:-}" != "1" ]; then
    echo "SKIP: set RUN_ORG_USER_QUORUM_E2E=1 to run the opt-in org-user quorum live e2e"
    exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

if [ -f "$REPO_ROOT/.env" ]; then
    set -a
    source "$REPO_ROOT/.env"
    set +a
fi

GATEWAY_URL="${GATEWAY_URL:-http://127.0.0.1:8000}"
API_URL="${API_URL:-http://127.0.0.1:8080}"
WORK_DIR=$(mktemp -d)
LOG_DIR="tests/e2e/logs"
LOG_FILE="$LOG_DIR/org-user-quorum-$(date +%Y%m%d-%H%M%S).log"
STEP_NUM=0
STEPS_PASSED=0
STEPS_FAILED=0
STEP_RESULTS=()

mkdir -p "$LOG_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1

cleanup() {
    rm -rf "$WORK_DIR"
    echo ""
    echo "========================================"
    echo "  Org User Quorum E2E Test Results"
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
    echo "[e2e] $*"
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || step_fail "Missing required command: $1"
}

require_cmd curl
require_cmd jq


STEP_NUM=1
log "Checking gateway/API readiness..."
for _ in $(seq 1 30); do
    if curl -sf "$GATEWAY_URL/health" >/dev/null && curl -sf "$API_URL/health" >/dev/null; then
        break
    fi
    sleep 1
done
curl -sf "$GATEWAY_URL/health" >/dev/null || step_fail "Gateway health check"
curl -sf "$API_URL/health" >/dev/null || step_fail "API health check"
step_pass "Gateway/API reachable"

STEP_NUM=2
log "Creating e2e user/session..."
LOGIN_RESPONSE=$(curl -sf -X POST "$GATEWAY_URL/auth/e2e-login" -H "Content-Type: application/json")
SESSION_ID=$(echo "$LOGIN_RESPONSE" | jq -r '.session_id')
USER_ID=$(echo "$LOGIN_RESPONSE" | jq -r '.user_id')

if [ -z "$SESSION_ID" ] || [ "$SESSION_ID" = "null" ] || [ -z "$USER_ID" ] || [ "$USER_ID" = "null" ]; then
    step_fail "E2E login returned session and user"
fi

step_pass "E2E login (user: $USER_ID)"

STEP_NUM=3
log "Marking user onboarded and provisioning organization membership..."
docker exec postgres-test psql -U postgres -d caution_test -c "
UPDATE users SET email_verified_at = NOW(), payment_method_added_at = NOW(), username_is_placeholder = false WHERE id = '$USER_ID';
" >/dev/null 2>&1 || step_fail "Mark e2e user onboarded"

curl -sf "$API_URL/resources" -H "X-Session-ID: $SESSION_ID" >/dev/null 2>&1 || true
ORG_ID=""
for _ in $(seq 1 10); do
    ORG_ID=$(docker exec postgres-test psql -U postgres -d caution_test -t -A -c "
SELECT organization_id FROM organization_members WHERE user_id = '$USER_ID' LIMIT 1;
" 2>/dev/null | head -1 | tr -d ' \n')
    [ -n "$ORG_ID" ] && break
    sleep 1
done

if [ -z "$ORG_ID" ]; then
    step_fail "Organization membership was provisioned"
fi
step_pass "Organization membership provisioned"

STEP_NUM=4
log "Verifying authenticated discovery contains the expected organization member..."
curl -sf "$GATEWAY_URL/api/quorum-bundles/participants" -H "X-Session-ID: $SESSION_ID" > "$WORK_DIR/participants.json" \
    || step_fail "Authenticated discovery succeeds before signature checks"
jq -e --arg user "$USER_ID" '
    type == "array" and
    ([.[] | select(.user_id == $user)] | length == 1) and
    any(.[]; .user_id == $user and .webauthn_credentials >= 1) and
    all(.[]; (keys | sort) == (["user_id", "username", "pgp_keys", "webauthn_credentials"] | sort))
' "$WORK_DIR/participants.json" >/dev/null || step_fail "Discovery returns expected member and only public selection metadata"
step_pass "Authenticated discovery contains the expected member and no credential bindings"

STEP_NUM=5
log "Verifying unsigned generation, upload, updates and deletion require signature verification..."
for operation in "POST quorum-bundles" "POST quorum-bundles/from-org-users" "PATCH quorum-bundles/$USER_ID" "DELETE quorum-bundles/$USER_ID"; do
    read -r METHOD ROUTE <<< "$operation"
    STATUS=$(curl -sS -o "$WORK_DIR/response" -w '%{http_code}' \
        -X "$METHOD" "$GATEWAY_URL/api/$ROUTE" \
        -H "X-Session-ID: $SESSION_ID" -H "Content-Type: application/json" \
        -H "X-Fido2-Signed: true" -H "X-Authenticated-User-ID: $USER_ID" \
        --data '{}')
    [ "$STATUS" = "403" ] || step_fail "Unsigned $METHOD $ROUTE returns 403 (received $STATUS)"
    [ "$(cat "$WORK_DIR/response")" = "This operation requires signature verification" ] \
        || step_fail "Rejection came from signature verification, not another gate"
done
step_pass "Unsigned generation, upload, updates and deletion rejected by the signature requirement"
log "Authorization/discovery checks passed; no cryptographic generation was tested"
