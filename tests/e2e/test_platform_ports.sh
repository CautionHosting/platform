#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
#
# E2E test for platform-reserved Nitro enclave ports.
# Requires: make up-test (builds with e2e-testing feature) and AWS CLI credentials.
#
# Tests:
#   1. Wait for gateway
#   2. Create test user
#   3. Add SSH key
#   4. Clone demo app and enable STEVE/e2e
#   5. Deploy app
#   6. Assert AWS security group exposes only the expected platform port
#   7. Assert STEVE is reachable on 49500
#   8. Assert Caddy routes encrypted E2P requests to STEVE

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

if [ -f "$REPO_ROOT/.env" ]; then
    set -a
    source "$REPO_ROOT/.env"
    set +a
fi

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8000}"
API_URL="${API_URL:-http://127.0.0.1:8080}"
CAUTION_BIN="${CAUTION_BIN:-caution}"
HCL_PATCHER_BIN="${HCL_PATCHER_BIN:-out/cli/hcl-patcher}"
DEMO_REPO="${DEMO_REPO:-https://codeberg.org/caution/demo-hello-world-enclave.git}"
WORK_DIR=$(mktemp -d)
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/api-cli"
SSH_KEY_PATH="$WORK_DIR/test_key"
RESOURCE_ID=""
LOG_DIR="tests/e2e/logs"
LOG_FILE="$LOG_DIR/platform-ports-$(date +%Y%m%d-%H%M%S).log"
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
    echo "  Platform Ports E2E Test Results"
    echo "========================================"
    for result in "${STEP_RESULTS[@]}"; do
        echo "  $result"
    done
    echo "----------------------------------------"
    echo "  Passed: $STEPS_PASSED  Failed: $STEPS_FAILED"
    echo "========================================"
    echo ""
    echo "Full log: $LOG_FILE"

    if [ "$STEPS_FAILED" -gt 0 ]; then
        echo "--- API logs ---"
        docker logs api 2>&1 | tail -80 || true
        echo "--- Gateway logs ---"
        docker logs gateway 2>&1 | tail -80 || true
        exit 1
    fi
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
    echo "[platform-ports-e2e] $*"
}

db_query() {
    docker exec postgres-test psql -U postgres -d caution_test -t -A -c "$1" 2>/dev/null
}

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: $1 is required for this test"
        exit 1
    fi
}

public_port_open() {
    local sg_json="$1"
    local port="$2"

    jq -e --argjson port "$port" '
      any(.SecurityGroups[].IpPermissions[]?;
        (
          any(.IpRanges[]?; .CidrIp == "0.0.0.0/0") or
          any(.Ipv6Ranges[]?; .CidrIpv6 == "::/0")
        ) and (
          .IpProtocol == "-1" or
          (
            .IpProtocol == "tcp" and
            (.FromPort // -1) <= $port and
            (.ToPort // -1) >= $port
          )
        )
      )
    ' <<<"$sg_json" >/dev/null
}

require_command aws
require_command curl
require_command git
require_command jq
require_command ssh
require_command ssh-keygen

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

mkdir -p "$CONFIG_DIR"
cat > "$CONFIG_DIR/config.json" <<EOF
{
  "session_id": "$SESSION_ID",
  "expires_at": "$EXPIRES_AT",
  "server_url": "$GATEWAY_URL"
}
EOF

docker exec postgres-test psql -U postgres -d caution_test -c "
UPDATE users SET email_verified_at = NOW(), payment_method_added_at = NOW() WHERE id = '$USER_ID';
" >/dev/null 2>&1 || log "Warning: could not mark user as onboarded"

curl -sf "$API_URL/resources" -H "X-Session-ID: $SESSION_ID" >/dev/null 2>&1 ||
    log "Warning: could not trigger org provisioning"

ORG_ID=""
for i in $(seq 1 10); do
    ORG_ID=$(db_query "SELECT organization_id FROM organization_members WHERE user_id = '$USER_ID' LIMIT 1;" | head -1 | tr -d ' \n')
    [ -n "$ORG_ID" ] && break
    sleep 1
done

if [ -z "$ORG_ID" ]; then
    step_fail "E2E login (no organization)"
fi

docker exec postgres-test psql -U postgres -d caution_test -c "
DELETE FROM credit_ledger WHERE organization_id = '$ORG_ID';
INSERT INTO credit_ledger (organization_id, user_id, delta_cents, entry_type, description)
VALUES ('$ORG_ID', '$USER_ID', 10000, 'purchase', 'e2e platform ports seed');
" >/dev/null 2>&1 || step_fail "Seed deploy credits"

step_pass "E2E login and account setup"

# ── Step 3: Add SSH Key ──────────────────────────────────────────────

STEP_NUM=3
log "Generating and adding SSH key..."
ssh-keygen -t ed25519 -f "$SSH_KEY_PATH" -N "" -q
SSH_PUB_KEY=$(cat "$SSH_KEY_PATH.pub")

ADD_KEY_RESPONSE=$(curl -sf -X POST "$GATEWAY_URL/ssh-keys" \
    -H "Content-Type: application/json" \
    -H "X-Session-ID: $SESSION_ID" \
    -d "{\"public_key\": \"$SSH_PUB_KEY\", \"name\": \"platform-ports-e2e\"}")

FINGERPRINT=$(echo "$ADD_KEY_RESPONSE" | jq -r '.fingerprint')
if [ -z "$FINGERPRINT" ] || [ "$FINGERPRINT" = "null" ]; then
    step_fail "Add SSH key"
fi

eval "$(ssh-agent -s)" >/dev/null
ssh-add "$SSH_KEY_PATH" 2>/dev/null
step_pass "Add SSH key"

# ── Step 4: Clone Demo App And Enable E2E ────────────────────────────

STEP_NUM=4
CLONE_DIR="$WORK_DIR/demo-app"
log "Cloning demo app from $DEMO_REPO..."
git clone "$DEMO_REPO" "$CLONE_DIR"
cd "$CLONE_DIR"

# Convert Procfile to caution.hcl, then patch e2e encryption
"$CAUTION_BIN" apps migrate-procfile
"$HCL_PATCHER_BIN" caution.hcl /enclave/default/network/http/e2e_encryption/enabled true --type bool
rm -f Procfile
git -c user.name="Caution E2E" -c user.email="e2e@example.com" add caution.hcl
git -c user.name="Caution E2E" -c user.email="e2e@example.com" commit -m "Enable STEVE e2e port test" >/dev/null
step_pass "Demo app prepared with e2e enabled"

# ── Step 5: Deploy App ───────────────────────────────────────────────

STEP_NUM=5
log "Running caution init..."
INIT_OUTPUT=$("$CAUTION_BIN" -u "$GATEWAY_URL" init --name "platform-ports-$(date +%s)" 2>&1)

if [ -f ".caution/deployment.json" ]; then
    RESOURCE_ID=$(jq -r '.resource_id' .caution/deployment.json)
else
    echo "$INIT_OUTPUT"
    step_fail "caution init (no .caution/deployment.json)"
fi

log "Pushing to caution remote..."
export GIT_SSH_COMMAND="ssh -i $SSH_KEY_PATH -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p ${SSH_PORT:-2222}"
git push caution main 2>&1

log "Waiting for deployment to complete..."
MAX_WAIT=900
POLL_INTERVAL=15
ELAPSED=0

while [ $ELAPSED -lt $MAX_WAIT ]; do
    APP_STATE=$("$CAUTION_BIN" -u "$GATEWAY_URL" apps get "$RESOURCE_ID" 2>&1 | grep -i "state" | head -1 || true)

    if echo "$APP_STATE" | grep -qi "running"; then
        break
    fi

    if echo "$APP_STATE" | grep -qi "failed\|error"; then
        step_fail "Deployment ($APP_STATE)"
    fi

    log "Still deploying... ($ELAPSED/${MAX_WAIT}s)"
    sleep $POLL_INTERVAL
    ELAPSED=$((ELAPSED + POLL_INTERVAL))
done

if [ $ELAPSED -ge $MAX_WAIT ]; then
    step_fail "Deployment timed out after ${MAX_WAIT}s"
fi

step_pass "Deployment running"

# ── Step 6: Assert Security Group Ports ──────────────────────────────

STEP_NUM=6
log "Loading deployed instance metadata..."
RESOURCE_ROW=$(db_query "
SELECT provider_resource_id, public_ip, COALESCE(region, '')
FROM compute_resources
WHERE id = '$RESOURCE_ID';
" | head -1)

INSTANCE_ID=$(echo "$RESOURCE_ROW" | cut -d'|' -f1)
APP_IP=$(echo "$RESOURCE_ROW" | cut -d'|' -f2)
AWS_REGION_RESOLVED=$(echo "$RESOURCE_ROW" | cut -d'|' -f3)

if [ -z "$INSTANCE_ID" ] || [ -z "$APP_IP" ]; then
    step_fail "Load deployed instance metadata"
fi

if [ -z "$AWS_REGION_RESOLVED" ]; then
    AWS_REGION_RESOLVED="${AWS_REGION:-us-west-2}"
fi

log "Instance: $INSTANCE_ID"
log "Public IP: $APP_IP"
log "Region: $AWS_REGION_RESOLVED"

SG_IDS=$(aws ec2 describe-instances \
    --region "$AWS_REGION_RESOLVED" \
    --instance-ids "$INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].SecurityGroups[].GroupId' \
    --output text)

if [ -z "$SG_IDS" ] || [ "$SG_IDS" = "None" ]; then
    step_fail "Resolve instance security groups"
fi

log "Security groups: $SG_IDS"

SG_JSON=$(aws ec2 describe-security-groups \
    --region "$AWS_REGION_RESOLVED" \
    --group-ids $SG_IDS \
    --output json)

if public_port_open "$SG_JSON" 49500; then
    log "Port 49500 is publicly allowed as expected"
else
    step_fail "Expected public ingress for STEVE port 49500"
fi

for port in 49501 49502 49503 49504; do
    if public_port_open "$SG_JSON" "$port"; then
        step_fail "Unexpected public ingress for platform port $port"
    fi
    log "Port $port is not publicly allowed"
done

step_pass "Security group platform port rules"

# ── Step 7: Assert STEVE Reachability ────────────────────────────────

STEP_NUM=7
log "Checking STEVE key exchange endpoint on 49500..."
REQUEST_JSON=$(jq -nc '{public_key_bytes: ([range(0;32)] | map(0)), nonce: ([range(0;16)] | map(0))}')
STEVE_RESPONSE="$WORK_DIR/steve-response.json"

STEVE_READY=false
for i in $(seq 1 30); do
    if curl -sf --connect-timeout 5 --max-time 10 \
        -H "Content-Type: application/json" \
        -d "$REQUEST_JSON" \
        "http://$APP_IP:49500/e2p/v1/create_shared_key" > "$STEVE_RESPONSE"; then
        if jq -e '.public_key and .signature and .enclave_encrypted_shared_key' "$STEVE_RESPONSE" >/dev/null; then
            STEVE_READY=true
            break
        fi
    fi
    log "STEVE not ready yet... ($i/30)"
    sleep 5
done

if ! $STEVE_READY; then
    echo "--- Last STEVE response ---"
    cat "$STEVE_RESPONSE" 2>/dev/null || true
    echo ""
    step_fail "STEVE endpoint reachable on 49500"
fi

step_pass "STEVE endpoint reachable on 49500"

# ── Step 8: Assert Caddy E2P Routing ─────────────────────────────────

STEP_NUM=8
log "Checking Caddy routes encrypted E2P requests to STEVE..."

APP_ROOT_STATUS=$(curl -sS --connect-timeout 5 --max-time 10 \
    -o /dev/null -w "%{http_code}" \
    "http://$APP_IP/" || true)

if [ "$APP_ROOT_STATUS" != "200" ]; then
    step_fail "App root remains routed to app upstream (HTTP $APP_ROOT_STATUS)"
fi

INVALID_E2P_BODY="$WORK_DIR/invalid-e2p-body.bin"
printf "not-a-valid-e2p-envelope" > "$INVALID_E2P_BODY"

DIRECT_STEVE_RESPONSE="$WORK_DIR/direct-steve-invalid.txt"
CADDY_E2P_RESPONSE="$WORK_DIR/caddy-e2p-invalid.txt"

DIRECT_STEVE_STATUS=$(curl -sS --connect-timeout 5 --max-time 10 \
    -o "$DIRECT_STEVE_RESPONSE" -w "%{http_code}" \
    -H "Content-Type: application/octet-stream" \
    -H "X-E2P-Key: test" \
    -H "X-E2P-Original-Method: POST" \
    --data-binary "@$INVALID_E2P_BODY" \
    "http://$APP_IP:49500/__caution_e2p_probe" || true)

if [ -z "$DIRECT_STEVE_STATUS" ] || [ "$DIRECT_STEVE_STATUS" = "000" ]; then
    step_fail "Direct STEVE invalid encrypted request"
fi

CADDY_E2P_READY=false
for i in $(seq 1 30); do
    CADDY_E2P_STATUS=$(curl -sS --connect-timeout 5 --max-time 10 \
        -o "$CADDY_E2P_RESPONSE" -w "%{http_code}" \
        -H "Content-Type: application/octet-stream" \
        -H "X-E2P-Key: test" \
        -H "X-E2P-Original-Method: POST" \
        --data-binary "@$INVALID_E2P_BODY" \
        "http://$APP_IP/__caution_e2p_probe" || true)

    if [ "$CADDY_E2P_STATUS" = "$DIRECT_STEVE_STATUS" ] &&
        cmp -s "$DIRECT_STEVE_RESPONSE" "$CADDY_E2P_RESPONSE"; then
        CADDY_E2P_READY=true
        break
    fi

    log "Caddy E2P route not ready yet... ($i/30)"
    sleep 5
done

if ! $CADDY_E2P_READY; then
    echo "--- Direct STEVE status/body ---"
    echo "$DIRECT_STEVE_STATUS"
    cat "$DIRECT_STEVE_RESPONSE" 2>/dev/null || true
    echo ""
    echo "--- Caddy E2P status/body ---"
    echo "${CADDY_E2P_STATUS:-}"
    cat "$CADDY_E2P_RESPONSE" 2>/dev/null || true
    echo ""
    step_fail "Caddy encrypted E2P route"
fi

step_pass "Caddy encrypted E2P route"
