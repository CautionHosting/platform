#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial
#
# Opt-in e2e test for org-user quorum generation.
#
# This intentionally does not run as part of default make test-e2e. It requires:
#   RUN_ORG_USER_QUORUM_E2E=1
#   a running e2e gateway/API stack
#   the API container started with KEYMAKER_URL and PUBLIC_CERTIFICATE_SERVICE_URL
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
CAUTION_BIN="${CAUTION_BIN:-$REPO_ROOT/target/debug/caution}"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/caution-cli"
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

if [ ! -x "$CAUTION_BIN" ]; then
    log "Building CLI..."
    cargo build --manifest-path "$REPO_ROOT/Cargo.toml" -p cli >/dev/null
    CAUTION_BIN="$REPO_ROOT/target/debug/caution"
fi

STEP_NUM=1
log "Checking gateway/API readiness and API key-service configuration..."
for _ in $(seq 1 30); do
    if curl -sf "$GATEWAY_URL/health" >/dev/null && curl -sf "$API_URL/health" >/dev/null; then
        break
    fi
    sleep 1
done
curl -sf "$GATEWAY_URL/health" >/dev/null || step_fail "Gateway health check"
curl -sf "$API_URL/health" >/dev/null || step_fail "API health check"
if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -qx api; then
    docker exec api sh -c 'test -n "${KEYMAKER_URL:-}" && test -n "${PUBLIC_CERTIFICATE_SERVICE_URL:-}"' \
        || step_fail "API container has KEYMAKER_URL and PUBLIC_CERTIFICATE_SERVICE_URL"
fi
step_pass "Gateway/API reachable with key-service configuration"

STEP_NUM=2
log "Creating e2e user/session..."
LOGIN_RESPONSE=$(curl -sf -X POST "$GATEWAY_URL/auth/e2e-login" -H "Content-Type: application/json")
SESSION_ID=$(echo "$LOGIN_RESPONSE" | jq -r '.session_id')
USER_ID=$(echo "$LOGIN_RESPONSE" | jq -r '.user_id')
EXPIRES_AT=$(echo "$LOGIN_RESPONSE" | jq -r '.expires_at')

if [ -z "$SESSION_ID" ] || [ "$SESSION_ID" = "null" ] || [ -z "$USER_ID" ] || [ "$USER_ID" = "null" ]; then
    step_fail "E2E login returned session and user"
fi

mkdir -p "$CONFIG_DIR"
cat > "$CONFIG_DIR/config.json" <<EOF
{
  "session_id": "$SESSION_ID",
  "expires_at": "$EXPIRES_AT",
  "server_url": "$GATEWAY_URL"
}
EOF
step_pass "E2E login (user: $USER_ID)"

STEP_NUM=3
log "Marking user onboarded and provisioning organization membership..."
docker exec postgres-test psql -U postgres -d caution_test -c "
UPDATE users SET email_verified_at = NOW(), payment_method_added_at = NOW() WHERE id = '$USER_ID';
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
log "Generating org-user quorum from Caution-backed public certificate service and Keymaker..."
REPO_DIR="$WORK_DIR/test-repo"
mkdir -p "$REPO_DIR/.caution"
printf 'enclave "default" {\n  unit "default" {\n    command = "/bin/true"\n  }\n}\n' > "$REPO_DIR/caution.hcl"

set +e
OUTPUT=$(cd "$REPO_DIR" && CAUTION_E2E_UNSIGNED_REQUESTS=1 "$CAUTION_BIN" -u "$GATEWAY_URL" secret new \
    --from-org-users "$USER_ID" \
    --caution-backed \
    --threshold 1 \
    --name e2e-org-user-quorum \
    --label e2e=org-user-quorum 2>&1)
STATUS=$?
set -e

if [ $STATUS -ne 0 ]; then
    echo "$OUTPUT"
    docker logs api 2>&1 | tail -80 || true
    step_fail "CLI generated org-user quorum"
fi

if [ ! -f "$REPO_DIR/.caution/quorum-bundle.json" ]; then
    echo "$OUTPUT"
    step_fail "CLI saved .caution/quorum-bundle.json"
fi

jq -e '.version == "V1" and .shardfile and .public_key and (.keyring | length == 1)' \
    "$REPO_DIR/.caution/quorum-bundle.json" >/dev/null || step_fail "Saved quorum bundle has Keymaker V1 shape"
step_pass "CLI generated and saved Keymaker V1 org-user quorum bundle"

STEP_NUM=5
log "Verifying server persisted the quorum bundle..."
BUNDLE_COUNT=$(curl -sf "$API_URL/quorum-bundles" -H "X-Session-ID: $SESSION_ID" \
    | jq '[.[] | select(.name == "e2e-org-user-quorum")] | length')
if [ "$BUNDLE_COUNT" -lt 1 ]; then
    step_fail "Server persisted org-user quorum bundle"
fi
step_pass "Server persisted org-user quorum bundle"

if [ "$STEPS_FAILED" -ne 0 ]; then
    exit 1
fi

log "Org-user quorum e2e completed successfully"
