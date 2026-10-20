#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
#
# E2E lifecycle test for app deployments (blue-green) on the Caution platform.
# AWS-backed: it builds and provisions real enclaves (three deployments), so run
# it on a host with AWS credentials, like test_happy_path.sh:
#
#   make test-e2e-app-deployments
#
# which builds the CLI and starts the test stack with
#   APP_DEPLOYMENTS_ENABLED=true MAX_CANDIDATES_PER_APP=1
# (through API_EXTRA_ENV of run-api-test). Requires: docker, curl, jq, git,
# ssh-keygen, cargo (for the soft-authenticator binary).
#
# Flow (docs/app-deployments.md describes the lifecycle):
#    1-4  Harness, as test_happy_path.sh: e2e login, SSH key, demo app
#    5    caution apps create: lifecycle is "deployments"
#    6    Push A: goes live (nothing was live); apps list and apps get show it
#    7    A push interrupted mid-transfer releases its reservation
#    8    Push B (background): busy push refused, app destroy 409, B candidate
#    8a   B's view carries bundle/TLS fields, bare verify needs -d
#    9    A stays live, stable IP unchanged, health 200
#   10    Push C: candidate limit reached, no new deployment
#   11    caution verify -d B, apps get -d B and apps get (SSH-signed CI reads)
#   12    Switch to B: session-only 403 (history unchanged), passkey-signed 200
#         (history: passkey proof, signed request completed)
#   13    Rollback to A, a stale switch is 409 (history: rejected, proof linked)
#   14    short -d IDs; destroy -d A refused (live); SSH-signed destroy -d B by
#         short ID (history: ssh_signed); unchanged push skipped
#   15    caution apps destroy: every deployment destroyed, nothing metered,
#         apps list / -a and the history
#   16    Unchanged push rebuilds HEAD and goes live (nothing is live)
#   17    Final destroy
# E2E_BYOC=1: step 5 is caution init --byoc, step 17 caution teardown --byoc. A
# failed init whose output names no provisioner deployment prints `LEAKED? BYOC
# environment ...` and exits 86: check the test account for caution-* resources.
#
# The cleanup trap waits for every background push and for the app's active
# operation, then destroys the app until the database shows it terminated. If it
# cannot, it prints `LEAKED app <id> ...` with the deployment instance IDs and
# exits 86: destroy that infrastructure manually before `down-test` drops the
# database. Step 11 fails on any `verify -d` failure; E2E_STRICT_VERIFY=0
# tolerates the environmental failures `test_happy_path.sh` tolerates and lists
# them as `ACCEPTANCE OPEN`.
# The script refuses to run against anything but a local stack.

set -euo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8000}"
API_URL="${API_URL:-http://127.0.0.1:8080}"
RP_ORIGIN="${RP_ORIGIN:-http://localhost:8000}"
CAUTION_BIN="${CAUTION_BIN:-caution}"
DB_CONTAINER="${DB_CONTAINER:-postgres-test}"
DB_NAME="${DB_NAME:-caution_test}"
API_CONTAINER="${API_CONTAINER:-api}"
# A build + provisioning takes minutes; bound each push so a hang fails the test.
PUSH_TIMEOUT="${PUSH_TIMEOUT:-2400}"
# How long the cleanup keeps trying to destroy the app before reporting a leak.
DESTROY_TIMEOUT="${DESTROY_TIMEOUT:-1200}"
# 1 (default, strict): `verify -d` must succeed and write the trust file. 0 tolerates
# the environmental failures test_happy_path.sh tolerates.
E2E_STRICT_VERIFY="${E2E_STRICT_VERIFY:-1}"
# 1: the same flow in a linked AWS account (BYOC). `caution init --byoc` replaces
# `apps create`, and `caution teardown --byoc` the final destroy. Needs the BYOC test
# account's ONPREM_AWS_ACCESS_KEY_ID/ONPREM_AWS_SECRET_ACCESS_KEY (as test_byoc.sh)
# and a stack with APP_DEPLOYMENTS_BYOC_ENABLED=true: make test-e2e-app-deployments-byoc.
E2E_BYOC="${E2E_BYOC:-0}"
ONPREM_TEST_REGION="${ONPREM_TEST_REGION:-us-east-1}"
ONPREM_PROVISIONER_IMAGE="${ONPREM_PROVISIONER_IMAGE:-codeberg.org/caution/caution-managed-on-prem-aws-provisioner:latest}"
PROVISIONER_DEPLOYMENT_ID=""
BYOC_ENVIRONMENT_UP=false
# Size of the blob of the interrupted push: large enough that the client is still
# transferring when it is killed.
INTERRUPT_MB="${INTERRUPT_MB:-128}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURES_DIR="$ROOT/tests/e2e/fixtures"
WORK_DIR=$(mktemp -d)
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/caution-cli"
CONFIG_BACKUP="$WORK_DIR/config.json.bak"
# The operator's own CLI config (shared host): saved before it is overwritten.
OPERATOR_CONFIG_BACKUP="$WORK_DIR/operator-config.json.bak"
HAD_OPERATOR_CONFIG=false
WROTE_CONFIG=false
SSH_KEY_PATH="$WORK_DIR/test_key"
RESOURCE_ID=""
ORG_ID=""
LEAKED=0
ACCEPTANCE_OPEN=()
BG_PIDS=()
LOG_DIR="$ROOT/tests/e2e/logs"
LOG_FILE="$LOG_DIR/e2e-app-deployments-$(date +%Y%m%d-%H%M%S).log"
STEP_NUM=0
STEPS_PASSED=0
STEPS_FAILED=0
STEP_RESULTS=()

mkdir -p "$LOG_DIR"

# Tee all output to the log file
exec > >(tee -a "$LOG_FILE") 2>&1

cleanup() {
    local status=$?
    # A second Ctrl-C must not skip the destroys, the config restore or the leak report.
    trap '' INT TERM
    set +e
    echo ""
    echo "=== Cleanup ==="

    # A candidate still building makes app destroy return 409: let every
    # background push finish first.
    for pid in ${BG_PIDS[@]+"${BG_PIDS[@]}"}; do
        if kill -0 "$pid" 2>/dev/null; then
            echo "Waiting for background push $pid..."
            wait "$pid" 2>/dev/null
        fi
    done

    # The destroys below use the test session.
    if [ -f "$CONFIG_BACKUP" ] && [ ! -f "$CONFIG_DIR/config.json" ]; then
        mkdir -p "$CONFIG_DIR"
        cp "$CONFIG_BACKUP" "$CONFIG_DIR/config.json"
    fi

    destroy_leftover_apps

    # The linked environment goes once its app is gone (teardown deletes its VPC).
    if [ "$BYOC_ENVIRONMENT_UP" = true ]; then
        if [ "$LEAKED" = 1 ] || [ -z "$PROVISIONER_DEPLOYMENT_ID" ]; then
            echo "LEAKED BYOC environment ${PROVISIONER_DEPLOYMENT_ID:-unknown} in $ONPREM_TEST_REGION: tear it down after destroying its app"
            LEAKED=1
        else
            echo "Tearing down BYOC environment $PROVISIONER_DEPLOYMENT_ID..."
            docker run --rm \
                -e AWS_ACCESS_KEY_ID="$ONPREM_AWS_ACCESS_KEY_ID" \
                -e AWS_SECRET_ACCESS_KEY="$ONPREM_AWS_SECRET_ACCESS_KEY" \
                ${ONPREM_AWS_SESSION_TOKEN:+-e AWS_SESSION_TOKEN="$ONPREM_AWS_SESSION_TOKEN"} \
                -e AWS_REGION="$ONPREM_TEST_REGION" -e TEARDOWN=true \
                -e DEPLOYMENT_ID="$PROVISIONER_DEPLOYMENT_ID" "$ONPREM_PROVISIONER_IMAGE" \
                || { echo "LEAKED BYOC environment $PROVISIONER_DEPLOYMENT_ID: provisioner teardown failed"; LEAKED=1; }
        fi
    fi

    if [ "$HAD_OPERATOR_CONFIG" = true ]; then
        cp "$OPERATOR_CONFIG_BACKUP" "$CONFIG_DIR/config.json"
    elif [ "$WROTE_CONFIG" = true ]; then
        rm -f "$CONFIG_DIR/config.json"
    fi

    rm -rf "$WORK_DIR"

    echo ""
    echo "========================================"
    echo "  App Deployments E2E Results"
    echo "========================================"
    for result in ${STEP_RESULTS[@]+"${STEP_RESULTS[@]}"}; do
        echo "  $result"
    done
    echo "----------------------------------------"
    echo "  Passed: $STEPS_PASSED  Failed: $STEPS_FAILED"
    for open in ${ACCEPTANCE_OPEN[@]+"${ACCEPTANCE_OPEN[@]}"}; do
        echo "  ACCEPTANCE OPEN: $open"
    done
    if [ "$LEAKED" = 1 ]; then
        echo "  LEAKED infrastructure: see the LEAKED lines above (exit 86)"
    fi
    echo "========================================"
    echo ""
    echo "Full log: $LOG_FILE"
    if [ "$LEAKED" = 1 ]; then
        exit 86
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

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

# ── Helpers ──────────────────────────────────────────────────────────

# Literal substring test (no pipe, so `pipefail` cannot turn a match into a failure).
contains() {
    [[ "$1" == *"$2"* ]]
}

# The first line of $1 that contains $2 (no pipe, so `pipefail` is not involved).
line_with() {
    local line
    while IFS= read -r line; do
        if [[ "$line" == *"$2"* ]]; then
            echo "$line"
            return 0
        fi
    done <<<"$1"
    return 1
}

# The CLI provisions and tears down the linked environment with the BYOC account's keys.
byoc_cli() {
    env AWS_ACCESS_KEY_ID="$ONPREM_AWS_ACCESS_KEY_ID" \
        AWS_SECRET_ACCESS_KEY="$ONPREM_AWS_SECRET_ACCESS_KEY" \
        ${ONPREM_AWS_SESSION_TOKEN:+AWS_SESSION_TOKEN="$ONPREM_AWS_SESSION_TOKEN"} \
        "$CAUTION_BIN" -u "$GATEWAY_URL" "$@"
}

db() {
    docker exec "$DB_CONTAINER" psql -U postgres -d "$DB_NAME" -t -A -c "$1" | tr -d ' \r'
}

# Like db, but keeps the spaces (for reports).
db_raw() {
    docker exec "$DB_CONTAINER" psql -U postgres -d "$DB_NAME" -t -A -F ' ' -c "$1"
}

# The host of a URL (http://h:p/x, ssh://git@h:p/x, git@h:path). The authority ends
# at the first /, ? or #, so an @ after it (http://evil/@localhost) is not userinfo.
url_host() {
    local url=$1
    url=${url#*://}
    url=${url%%[/?#]*}
    url=${url##*@}
    echo "${url%%:*}"
}

is_local_host() {
    [ "$1" = localhost ] || [ "$1" = 127.0.0.1 ]
}

api_get() {
    curl -sf -H "X-Session-ID: $SESSION_ID" "$GATEWAY_URL/api$1"
}

http_code() {
    curl -s -o "$WORK_DIR/last-body" -w '%{http_code}' "$@" || true
}

rows_total() {
    db "SELECT COUNT(*) FROM app_deployments WHERE app_id = '$RESOURCE_ID'"
}

rows_reserved() {
    db "SELECT COUNT(*) FROM app_deployments WHERE app_id = '$RESOURCE_ID' AND status = 'reserved'"
}

has_reserved_row() {
    [ "$(rows_reserved)" != "0" ]
}

no_reserved_row() {
    [ "$(rows_reserved)" = "0" ]
}

# The deployment holding the app's single build/provisioning operation.
active_operation_id() {
    db "SELECT id FROM app_deployments WHERE app_id = '$RESOURCE_ID' AND status IN ('reserved', 'building', 'provisioning') ORDER BY created_at DESC LIMIT 1"
}

# No build or provisioning is running (or reserved) for app $1.
no_active_operation() {
    local active
    active=$(db "SELECT COUNT(*) FROM app_deployments WHERE app_id = '$1' AND status IN ('reserved', 'building', 'provisioning')") || return 1
    [ "$active" = "0" ]
}

# App $1 is destroyed: terminated (or marked destroyed), no deployment left holding state.
app_gone() {
    local row
    row=$(db "SELECT (state::text = 'terminated' OR destroyed_at IS NOT NULL)::text || ',' || (SELECT COUNT(*) FROM app_deployments d WHERE d.app_id = compute_resources.id AND d.status <> 'destroyed' AND NOT (d.status = 'failed' AND d.cleaned_up_at IS NOT NULL))::text FROM compute_resources WHERE id = '$1'") || return 1
    [ "$row" = "true,0" ]
}

# What an operator needs to destroy a leaked app by hand: the database is dropped by down-test.
report_leak() {
    LEAKED=1
    echo "LEAKED app $1 (org ${ORG_ID:-unknown}): destroy manually before down-test"
    echo "  app (state destroyed region ip live_deployment app_network):"
    db_raw "SELECT state::text, destroyed_at IS NOT NULL, COALESCE(region, '-'), COALESCE(public_ip, '-'), COALESCE(live_deployment_id::text, '-'), COALESCE(app_network::text, '-') FROM compute_resources WHERE id = '$1'" | sed 's/^/    /'
    echo "  deployments (id status instance region state_key):"
    db_raw "SELECT id, status, COALESCE(instance_id, '-'), COALESCE(region, '-'), COALESCE(state_key, '-') FROM app_deployments WHERE app_id = '$1' AND status <> 'destroyed' ORDER BY created_at" | sed 's/^/    /'
}

# Server-side work outlives a killed client (a push the server keeps building), so
# wait for the app's active operation to clear, then destroy until the database
# shows the app destroyed. Reports a leak if it cannot.
destroy_app() {
    echo "Waiting for the active operation of app $1 (up to ${PUSH_TIMEOUT}s)..."
    wait_for "$PUSH_TIMEOUT" 10 no_active_operation "$1"
    local deadline=$((SECONDS + DESTROY_TIMEOUT))
    until app_gone "$1"; do
        if [ "$SECONDS" -ge "$deadline" ]; then
            report_leak "$1"
            return 1
        fi
        echo "Destroying app $1..."
        timeout "$DESTROY_TIMEOUT" "$CAUTION_BIN" -u "$GATEWAY_URL" apps destroy "$1" --force </dev/null
        app_gone "$1" && break
        sleep 15
    done
}

# The recorded app, and any other live app of the test org (fresh, created for this run).
destroy_leftover_apps() {
    if [ -z "$RESOURCE_ID" ] && [ -z "$ORG_ID" ]; then
        return 0
    fi
    if ! db "SELECT 1" >/dev/null 2>&1; then
        echo "LEAKED? cannot read the database ($DB_CONTAINER): check app ${RESOURCE_ID:-unknown} (org ${ORG_ID:-unknown}) and its deployments manually"
        LEAKED=1
        if [ -n "$RESOURCE_ID" ]; then
            timeout "$DESTROY_TIMEOUT" "$CAUTION_BIN" -u "$GATEWAY_URL" apps destroy "$RESOURCE_ID" --force </dev/null
        fi
        return 1
    fi
    local app
    for app in $({
        [ -n "$RESOURCE_ID" ] && echo "$RESOURCE_ID"
        [ -n "$ORG_ID" ] && db "SELECT id FROM compute_resources WHERE organization_id = '$ORG_ID' AND destroyed_at IS NULL AND state::text <> 'terminated'"
    } | sort -u); do
        if ! app_gone "$app"; then
            destroy_app "$app"
        fi
    done
}

# wait_for SECONDS INTERVAL COMMAND...: retries COMMAND until it succeeds.
wait_for() {
    local deadline=$((SECONDS + $1)) interval=$2
    shift 2
    until "$@"; do
        [ "$SECONDS" -ge "$deadline" ] && return 1
        sleep "$interval"
    done
}

# Kills a process and all its descendants, leaves first, so the SSH connection of
# a `git push` is closed abruptly.
kill_tree() {
    local child
    for child in $(pgrep -P "$1" 2>/dev/null); do
        kill_tree "$child"
    done
    kill -KILL "$1" 2>/dev/null || true
}

# Appends a visible change to the demo app and commits it.
GIT_ID=(-c user.email="e2e@caution.dev" -c user.name="Caution E2E")
commit_change() {
    sed -E "s/Deployment [^!]*!/Deployment $1!/" Containerfile > Containerfile.tmp
    mv Containerfile.tmp Containerfile
    git "${GIT_ID[@]}" add Containerfile
    git "${GIT_ID[@]}" commit -q -m "e2e change $1"
}

assert_health() {
    local code=""
    for _ in $(seq 1 24); do
        code=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 10 \
            "http://$1/.well-known/caution/health" || true)
        if [ "$code" = "200" ]; then
            return 0
        fi
        sleep 5
    done
    return 1
}

# signed_switch DEPLOYMENT EXPECTED_LIVE: a passkey-signed switch through the soft
# authenticator. Sets SWITCH_STATUS (HTTP status), SWITCH_OUT (body), SWITCH_RC.
signed_switch() {
    local body
    body=$(jq -nc --arg expected "$2" \
        '{expected_live_deployment_id: (if $expected == "" then null else $expected end), acknowledged_verification: true}')
    set +e
    SWITCH_OUT=$(GATEWAY_URL="$GATEWAY_URL" RP_ORIGIN="$RP_ORIGIN" SESSION_ID="$SESSION_ID" \
        SWITCH_PATH="/resources/$RESOURCE_ID/deployments/$1/switch" SWITCH_BODY="$body" \
        "$SWITCH_BIN" 2>"$WORK_DIR/switch.err")
    SWITCH_RC=$?
    set -e
    SWITCH_STATUS=$(sed -n 's/^HTTP \([0-9][0-9]*\)$/\1/p' "$WORK_DIR/switch.err" | tail -1)
    echo "[e2e] switch $1 (expected live: ${2:-none}) -> HTTP ${SWITCH_STATUS:-none}: $SWITCH_OUT"
    cat "$WORK_DIR/switch.err"
}

for tool in docker curl jq git ssh-keygen cargo pgrep timeout; do
    command -v "$tool" >/dev/null 2>&1 || { echo "Missing required tool: $tool" >&2; exit 1; }
done

# ── Step 1: Wait for services ────────────────────────────────────────

STEP_NUM=1
# This test pushes with StrictHostKeyChecking=no: never let it reach a real platform.
for url in "$GATEWAY_URL" "$API_URL"; do
    if ! is_local_host "$(url_host "$url")"; then
        step_fail "$url is not local (localhost or 127.0.0.1): this test only runs against the local test stack"
    fi
done
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

# The stack must run with the flag and the candidate cap this test relies on: fail
# closed when the API container's environment cannot be read.
if [ "$E2E_BYOC" = 1 ]; then
    REQUIRED_FLAGS=(APP_DEPLOYMENTS_BYOC_ENABLED=true MAX_CANDIDATES_PER_APP=1)
    MAKE_TARGET=test-e2e-app-deployments-byoc
    if [ -z "${ONPREM_AWS_ACCESS_KEY_ID:-}" ] || [ -z "${ONPREM_AWS_SECRET_ACCESS_KEY:-}" ]; then
        step_fail "E2E_BYOC=1 needs ONPREM_AWS_ACCESS_KEY_ID and ONPREM_AWS_SECRET_ACCESS_KEY (the BYOC test account)"
    fi
else
    REQUIRED_FLAGS=(APP_DEPLOYMENTS_ENABLED=true MAX_CANDIDATES_PER_APP=1)
    MAKE_TARGET=test-e2e-app-deployments
fi
if ! API_ENV=$(docker inspect "$API_CONTAINER" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null); then
    step_fail "cannot read the environment of the API container '$API_CONTAINER' (is the test stack up? run: make $MAKE_TARGET)"
fi
for setting in "${REQUIRED_FLAGS[@]}"; do
    if ! grep -qx "$setting" <<<"$API_ENV"; then
        step_fail "API container '$API_CONTAINER' lacks $setting (run: make $MAKE_TARGET)"
    fi
done
step_pass "Gateway health check, API flags"

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

# e2e-login seeds a placeholder account; every protected route below is gated by
# username_claim_gate_middleware until a real username is claimed. Claim one now.
CLAIMED_USERNAME="appdep-$(date +%s)$RANDOM"
CLAIM_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GATEWAY_URL/user/username" \
    -H "X-Session-ID: $SESSION_ID" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$CLAIMED_USERNAME\"}")
[ "$CLAIM_CODE" = "200" ] || step_fail "Failed to claim username (HTTP $CLAIM_CODE) — protected routes stay gated"
log "Claimed username: $CLAIMED_USERNAME"

# Write CLI config file so the caution binary uses our session; the cleanup puts
# the operator's own config back.
mkdir -p "$CONFIG_DIR"
if [ -f "$CONFIG_DIR/config.json" ]; then
    cp "$CONFIG_DIR/config.json" "$OPERATOR_CONFIG_BACKUP"
    HAD_OPERATOR_CONFIG=true
fi
WROTE_CONFIG=true
cat > "$CONFIG_DIR/config.json" <<EOF
{
  "session_id": "$SESSION_ID",
  "expires_at": "$EXPIRES_AT",
  "server_url": "$GATEWAY_URL"
}
EOF

# Mark test user as onboarded so API onboarding middleware doesn't block requests (402)
log "Marking test user as onboarded..."
docker exec "$DB_CONTAINER" psql -U postgres -d "$DB_NAME" -c "
UPDATE users SET email_verified_at = NOW(), payment_method_added_at = NOW() WHERE id = '$USER_ID';
" >/dev/null 2>&1 || log "  Warning: could not mark user as onboarded"

# The e2e-login seed already created this user's organization at signup, so no
# request needs to trigger organization provisioning here.

ORG_ID=""
for _ in $(seq 1 10); do
    ORG_ID=$(db "SELECT organization_id FROM organization_members WHERE user_id = '$USER_ID' LIMIT 1" 2>/dev/null | head -1 || true)
    [ -n "$ORG_ID" ] && break
    sleep 1
done
log "  Org ID: $ORG_ID"

# Seed credits for the deploy gate ($25 minimum required; three enclaves run during this test)
log "Seeding test credits for deploy gate..."
docker exec "$DB_CONTAINER" psql -U postgres -d "$DB_NAME" -c "
DELETE FROM credit_ledger WHERE organization_id = '$ORG_ID';
INSERT INTO credit_ledger (organization_id, delta_cents, entry_type, description)
VALUES ('$ORG_ID', 10000, 'purchase', 'e2e deploy gate seed');
" >/dev/null 2>&1 || log "  Warning: could not seed credits"

# BYOC deploys also need an active subscription (the subscription test_byoc.sh seeds).
if [ "$E2E_BYOC" = 1 ]; then
    log "Seeding an active subscription for the BYOC deploy gate..."
    db "
DELETE FROM subscription_ledger WHERE organization_id = '$ORG_ID';
DELETE FROM subscriptions WHERE user_id = '$USER_ID';
INSERT INTO subscriptions (
    user_id, organization_id, tier, billing_period,
    max_vcpus, max_apps, price_cents_per_cycle, status,
    started_at, current_period_start, current_period_end,
    next_billing_at, created_at, updated_at
)
VALUES (
    '$USER_ID', '$ORG_ID', 'starter', 'monthly',
    4, 2, 2900, 'active',
    NOW(), NOW(), NOW(),
    TIMESTAMPTZ '9999-12-31 23:59:59+00', NOW(), NOW()
);
" >/dev/null || step_fail "Seed an active subscription for the BYOC deploy gate (org '$ORG_ID')"
fi
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

# git pushes and the CLI's SSH-signed (--this-is-a-ci-machine) requests share this key.
export GIT_SSH_COMMAND="ssh -i $SSH_KEY_PATH -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222"
step_pass "Add SSH key (fingerprint: ${FINGERPRINT:0:20}...)"

# ── Step 4: Demo app and soft authenticator ──────────────────────────

STEP_NUM=4
CLONE_DIR="$WORK_DIR/demo-app"
log "Copying demo app fixture..."
cp -r "$FIXTURES_DIR/demo-app-happy-path" "$CLONE_DIR"
cd "$CLONE_DIR"
git init -q -b main
git "${GIT_ID[@]}" add .
git "${GIT_ID[@]}" commit -q -m "Initial commit"

# The switch is passkey-signed even in e2e builds: build the soft authenticator
# that signs it (own workspace, own target directory; see test_quorum_mock.sh).
log "Building the deployment-switch soft authenticator..."
(cd "$ROOT" && cargo build --locked --manifest-path tests/e2e/soft-authenticator/Cargo.toml --bin deployment-switch) \
    || step_fail "Build deployment-switch"
SOFT_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/tests/e2e/soft-authenticator/target}"
case "$SOFT_TARGET_DIR" in
    /*) ;;
    *) SOFT_TARGET_DIR="$ROOT/$SOFT_TARGET_DIR" ;;
esac
SWITCH_BIN="$SOFT_TARGET_DIR/debug/deployment-switch"
[ -x "$SWITCH_BIN" ] || step_fail "deployment-switch not found at $SWITCH_BIN"
step_pass "Demo app fixture and deployment-switch built"

# ── Step 5: caution apps create (brief step 1) ───────────────────────

STEP_NUM=5
if [ "$E2E_BYOC" = 1 ]; then
    CREATE_CMD="caution init --byoc"
    log "Running caution init --byoc in $ONPREM_TEST_REGION..."
    CREATE_STATUS=0
    CREATE_OUTPUT=$(byoc_cli init --byoc --yes --region "$ONPREM_TEST_REGION" \
        --name "bg-byoc-$(date +%Y%m%d%H%M%S)" 2>&1) || CREATE_STATUS=$?
    # The CLI echoes the provisioner's log, whose `[OK] Deployment ID: <id>` precedes
    # the app creation and credential registration; its own summary line comes last.
    # Its state file (~/.caution/<app>/bring-your-own-compute.json) is written only
    # after both API calls, so it holds nothing the output lacks.
    PROVISIONER_DEPLOYMENT_ID=$(grep -oE 'Deployment ID: [a-f0-9]+' <<<"$CREATE_OUTPUT" | tail -1 | awk '{print $3}' || true)
    if [ -n "$PROVISIONER_DEPLOYMENT_ID" ]; then
        BYOC_ENVIRONMENT_UP=true
    fi
    if [ "$CREATE_STATUS" != 0 ] || [ -z "$PROVISIONER_DEPLOYMENT_ID" ]; then
        echo "$CREATE_OUTPUT"
        if [ -z "$PROVISIONER_DEPLOYMENT_ID" ]; then
            echo "LEAKED? BYOC environment of a failed caution init --byoc in $ONPREM_TEST_REGION: check the test account for caution-* resources"
            LEAKED=1
        fi
        step_fail "caution init --byoc (exit $CREATE_STATUS, provisioner deployment '${PROVISIONER_DEPLOYMENT_ID:-none}')"
    fi
else
    CREATE_CMD="caution apps create"
    log "Running caution apps create..."
    CREATE_OUTPUT=$("$CAUTION_BIN" -u "$GATEWAY_URL" apps create 2>&1) || {
        echo "$CREATE_OUTPUT"
        step_fail "caution apps create"
    }
fi

if [ -f ".caution/deployment.json" ]; then
    RESOURCE_ID=$(jq -r '.resource_id' .caution/deployment.json)
else
    echo "$CREATE_OUTPUT"
    step_fail "$CREATE_CMD (no .caution/deployment.json)"
fi
GIT_URL=$(git remote get-url caution 2>/dev/null || true)
if [ -z "$GIT_URL" ] || [[ "$GIT_URL" != *"$RESOURCE_ID"* ]]; then
    step_fail "$CREATE_CMD (git remote not set)"
fi
# Pushes would go to the host the API advertises: it must be this stack (GIT_HOSTNAME=localhost).
GIT_HOST=$(url_host "$GIT_URL")
if ! is_local_host "$GIT_HOST"; then
    step_fail "git remote host is '$GIT_HOST', not local (is GIT_HOSTNAME=localhost set on the API?): refusing to push"
fi

RES_JSON=$(api_get "/resources/$RESOURCE_ID") || step_fail "GET /api/resources/$RESOURCE_ID"
LIFECYCLE=$(jq -r '.lifecycle' <<<"$RES_JSON")
if [ "$LIFECYCLE" != "deployments" ]; then
    step_fail "New app is on lifecycle '$LIFECYCLE', want 'deployments' (is ${REQUIRED_FLAGS[0]} on the API?)"
fi
step_pass "$CREATE_CMD: lifecycle is deployments (app: $RESOURCE_ID)"

# ── Step 6: Push A (brief step 2) ────────────────────────────────────

STEP_NUM=6
log "Pushing A to the caution remote (nothing is live: A goes live)..."
A_LOG="$WORK_DIR/push-a.log"
timeout "$PUSH_TIMEOUT" git push caution main </dev/null >"$A_LOG" 2>&1 || {
    cat "$A_LOG"
    step_fail "git push caution main (A)"
}
A_OUT=$(cat "$A_LOG")
echo "$A_OUT"
A_SHA=$(git rev-parse HEAD)

A_ID=$(grep -o 'Deployment: [0-9a-f-]\{36\} (live)' <<<"$A_OUT" | tail -1 | cut -d' ' -f2 || true)
if [ -z "$A_ID" ]; then
    step_fail "Push A output has no 'Deployment: <id> (live)'"
fi

DEPLOYMENTS_JSON=$(api_get "/resources/$RESOURCE_ID/deployments") || step_fail "GET deployments"
if ! jq -e --arg d "$A_ID" '.[] | select(.id == $d and .role == "live" and .status == "running")' \
    <<<"$DEPLOYMENTS_JSON" >/dev/null; then
    echo "$DEPLOYMENTS_JSON"
    step_fail "Deployments list does not show A ($A_ID) live and running"
fi
A_INSTANCE=$(jq -r --arg d "$A_ID" '.[] | select(.id == $d) | .instance_id' <<<"$DEPLOYMENTS_JSON")
RES_JSON=$(api_get "/resources/$RESOURCE_ID")
STABLE_IP=$(jq -r '.public_ip' <<<"$RES_JSON")
if [ -z "$A_INSTANCE" ] || [ "$A_INSTANCE" = "null" ] || [ -z "$STABLE_IP" ] || [ "$STABLE_IP" = "null" ]; then
    step_fail "A has no instance or the app no stable IP (instance: $A_INSTANCE, IP: $STABLE_IP)"
fi
if [ "$(jq -r '.provider_resource_id' <<<"$RES_JSON")" != "$A_INSTANCE" ] \
    || [ "$(jq -r '.live_deployment_id' <<<"$RES_JSON")" != "$A_ID" ]; then
    step_fail "App does not describe A as live (projection of provider_resource_id/live_deployment_id)"
fi
log "  A: $A_ID instance $A_INSTANCE, stable IP $STABLE_IP"

log "caution apps list and apps get show A live..."
LIST_OUT=$("$CAUTION_BIN" -u "$GATEWAY_URL" apps list </dev/null 2>&1) || {
    echo "$LIST_OUT"
    step_fail "caution apps list"
}
echo "$LIST_OUT"
LIST_LINE=$(line_with "$LIST_OUT" "$RESOURCE_ID") || step_fail "apps list has no line for $RESOURCE_ID"
for want in Running "${A_SHA:0:7}" "0 / 1"; do
    contains "$LIST_LINE" "$want" || step_fail "apps list line '$LIST_LINE' lacks '$want'"
done
GET_A_OUT=$("$CAUTION_BIN" -u "$GATEWAY_URL" apps get </dev/null 2>&1) || {
    echo "$GET_A_OUT"
    step_fail "caution apps get (checkout link)"
}
echo "$GET_A_OUT"
contains "$GET_A_OUT" "Live: ${A_ID:0:8}" || step_fail "apps get does not print 'Live: ${A_ID:0:8}'"
line_with "$GET_A_OUT" "${A_ID:0:8}  " >/dev/null || step_fail "apps get has no deployments table row for ${A_ID:0:8}"
if [ "$E2E_BYOC" = 1 ]; then
    # The network was created in the linked environment, and no deployment instance is metered
    # as fully managed. Builds keep their builder meter, as for Legacy BYOC.
    if [ "$(db "SELECT app_network->>'scope_tag' FROM compute_resources WHERE id = '$RESOURCE_ID'")" != "$PROVISIONER_DEPLOYMENT_ID" ]; then
        step_fail "App network is not in the linked environment $PROVISIONER_DEPLOYMENT_ID"
    fi
    if [ "$(db "SELECT COUNT(*) FROM tracked_resources WHERE application_id = '$RESOURCE_ID' AND COALESCE(metadata->>'resource_type', '') <> 'builder'")" != "0" ]; then
        step_fail "BYOC app has fully managed meters"
    fi
fi
step_pass "Push A: live and running (deployment $A_ID), apps list and apps get agree"

# ── Step 7: Push interrupted mid-transfer (Task 3) ───────────────────

STEP_NUM=7
log "Killing a git push client mid-transfer (${INTERRUPT_MB} MB blob)..."
ROWS_BEFORE=$(rows_total)
git checkout -q -b interrupted-push
head -c "$((INTERRUPT_MB * 1024 * 1024))" /dev/urandom > big-blob.bin
git "${GIT_ID[@]}" add big-blob.bin
git "${GIT_ID[@]}" commit -q -m "e2e interrupted push"
git push caution interrupted-push:refs/heads/interrupted-push </dev/null \
    >"$WORK_DIR/interrupted-push.log" 2>&1 &
INTERRUPTED_PID=$!
BG_PIDS+=("$INTERRUPTED_PID")
if ! wait_for 60 0.2 has_reserved_row; then
    kill_tree "$INTERRUPTED_PID"
    cat "$WORK_DIR/interrupted-push.log"
    step_fail "The push never reserved a deployment slot"
fi
kill_tree "$INTERRUPTED_PID"
wait "$INTERRUPTED_PID" 2>/dev/null || true
git checkout -q main
git branch -D -q interrupted-push
if ! wait_for 120 2 no_reserved_row; then
    step_fail "The interrupted push left its reservation behind"
fi
if [ "$(rows_total)" != "$ROWS_BEFORE" ]; then
    step_fail "The push completed before the kill and created a deployment (raise INTERRUPT_MB)"
fi
step_pass "Interrupted push released its reservation, no deployment created"

# ── Step 8: Push B, busy, app destroy 409 (brief step 3) ─────────────

STEP_NUM=8
log "Pushing B in the background (A is live: B is a candidate)..."
commit_change B
B_SHA=$(git rev-parse HEAD)
B_LOG="$WORK_DIR/push-b.log"
timeout "$PUSH_TIMEOUT" git push caution main </dev/null >"$B_LOG" 2>&1 &
B_PID=$!
BG_PIDS+=("$B_PID")

# The busy probe must come after B holds the slot, or it would take it.
B_ID=""
for _ in $(seq 1 60); do
    B_ID=$(active_operation_id)
    [ -n "$B_ID" ] && break
    kill -0 "$B_PID" 2>/dev/null || break
    sleep 1
done
if [ -z "$B_ID" ]; then
    cat "$B_LOG"
    step_fail "Push B never reserved a deployment slot (a push after an interrupted one is busy?)"
fi
log "  B reserved deployment $B_ID"

BUSY_OUT=$(git push caution HEAD:refs/heads/busy-probe </dev/null 2>&1 || true)
echo "$BUSY_OUT"
if ! contains "$BUSY_OUT" "Another build or provisioning operation is running"; then
    step_fail "Second push while B builds was not refused as busy"
fi

DELETE_CODE=$(http_code -X DELETE -H "X-Session-ID: $SESSION_ID" "$GATEWAY_URL/api/resources/$RESOURCE_ID")
if [ "$DELETE_CODE" != "409" ]; then
    cat "$WORK_DIR/last-body"
    step_fail "DELETE /api/resources/$RESOURCE_ID while B builds returned $DELETE_CODE, want 409"
fi
log "  App destroy while B builds: 409 $(cat "$WORK_DIR/last-body")"

log "Waiting for B (build and provisioning take minutes)..."
if ! wait "$B_PID"; then
    cat "$B_LOG"
    step_fail "git push caution main (B) failed"
fi
B_OUT=$(cat "$B_LOG")
echo "$B_OUT"
if ! contains "$B_OUT" "Candidate deployment: $B_ID"; then
    step_fail "Push B output has no 'Candidate deployment: $B_ID'"
fi
if ! contains "$B_OUT" "Live deployment: $A_ID (unchanged)"; then
    step_fail "Push B output has no 'Live deployment: $A_ID (unchanged)'"
fi

DEPLOYMENTS_JSON=$(api_get "/resources/$RESOURCE_ID/deployments")
B_INSTANCE=$(jq -r --arg d "$B_ID" '.[] | select(.id == $d) | .instance_id' <<<"$DEPLOYMENTS_JSON")
if ! jq -e --arg d "$B_ID" --arg sha "$B_SHA" \
    '.[] | select(.id == $d and .role == "candidate" and .status == "running" and .commit_sha == $sha)' \
    <<<"$DEPLOYMENTS_JSON" >/dev/null || [ -z "$B_INSTANCE" ] || [ "$B_INSTANCE" = "null" ]; then
    echo "$DEPLOYMENTS_JSON"
    step_fail "Deployments list does not show B ($B_ID) as a running candidate at $B_SHA"
fi
step_pass "Push B: busy push refused, app destroy 409, B is a running candidate ($B_ID)"

# ── Step 8a: Release targets and bare verify (M2) ────────────────────

STEP_NUM=8a
log "Release targets: the view carries the bundle and TLS fields; bare verify needs -d..."
B_VIEW=$(api_get "/resources/$RESOURCE_ID/deployments/$B_ID") || step_fail "GET deployment B"
[ "$(echo "$B_VIEW" | jq -r '.bundle_hash')" = "null" ] || step_fail "Demo app source has no bundle"
[ "$(echo "$B_VIEW" | jq -r '.tls_after_switch')" = "false" ] || step_fail "Host-mode candidate gets no after-switch TLS"
if "$CAUTION_BIN" -u "$GATEWAY_URL" verify --no-cache 2>"$WORK_DIR/bare-verify.err" </dev/null; then
    step_fail "Bare verify with A live and B running is refused"
fi
grep -q 'name one with -d' "$WORK_DIR/bare-verify.err" || step_fail "Bare verify names the -d fix"
step_pass "Deployment targets are explicit"

# ── Step 9: A stays live (brief step 4) ──────────────────────────────

STEP_NUM=9
RES_JSON=$(api_get "/resources/$RESOURCE_ID")
if [ "$(jq -r '.public_ip' <<<"$RES_JSON")" != "$STABLE_IP" ] \
    || [ "$(jq -r '.live_deployment_id' <<<"$RES_JSON")" != "$A_ID" ] \
    || [ "$(jq -r '.provider_resource_id' <<<"$RES_JSON")" != "$A_INSTANCE" ]; then
    echo "$RES_JSON"
    step_fail "The candidate changed the app's IP, live deployment or instance"
fi
if ! assert_health "$STABLE_IP"; then
    step_fail "http://$STABLE_IP/.well-known/caution/health is not 200"
fi
step_pass "A stays live on $STABLE_IP, health 200"

# ── Step 10: Candidate limit (brief step 5) ──────────────────────────

STEP_NUM=10
log "Pushing C to a fresh ref (limit is 1, B is a candidate)..."
ROWS_BEFORE=$(rows_total)
git checkout -q -b limit-probe
commit_change C
LIMIT_OUT=$(git push caution HEAD:refs/heads/limit-probe </dev/null 2>&1 || true)
echo "$LIMIT_OUT"
git checkout -q main
git branch -D -q limit-probe
if ! contains "$LIMIT_OUT" "Candidate limit reached (1 / 1)"; then
    step_fail "Push C was not refused with 'Candidate limit reached (1 / 1)'"
fi
if [ "$(rows_total)" != "$ROWS_BEFORE" ] || [ "$(rows_reserved)" != "0" ]; then
    step_fail "Push C created or left a deployment row"
fi
step_pass "Push C refused: candidate limit reached (1 / 1), no new deployment"

# ── Step 11: verify -d and apps get -d (brief step 6) ────────────────

STEP_NUM=11
if [ "$(git rev-parse HEAD)" != "$B_SHA" ]; then
    step_fail "Checkout is not at B's commit $B_SHA"
fi
TRUST_APP=".caution/trusted_hashes.json"
TRUST_B=".caution/deployments/$B_ID/trusted_hashes.json"
TRUST_APP_BEFORE=$(cat "$TRUST_APP" 2>/dev/null || echo "absent")

log "Running caution verify -d $B_ID (checkout at B's commit)..."
set +e
VERIFY_OUTPUT=$("$CAUTION_BIN" -u "$GATEWAY_URL" verify -d "$B_ID" --no-cache 2>&1)
VERIFY_STATUS=$?
set -e
echo "$VERIFY_OUTPUT"
if ! contains "$VERIFY_OUTPUT" "Verifying deployment $B_ID (candidate)"; then
    step_fail "verify -d did not target candidate $B_ID"
fi
if [ "$VERIFY_STATUS" -eq 0 ]; then
    if [ ! -s "$TRUST_B" ] || ! jq -e . "$TRUST_B" >/dev/null; then
        step_fail "verify -d $B_ID did not write $TRUST_B"
    fi
    VERIFY_RESULT="trust stored in $TRUST_B"
elif [ "$E2E_STRICT_VERIFY" != 1 ] && {
    contains "$VERIFY_OUTPUT" "does not include a manifest" \
        || contains "$VERIFY_OUTPUT" "private code" \
        || contains "$VERIFY_OUTPUT" "PCR2: match"
}; then
    # The same environmental limits test_happy_path.sh tolerates for `caution verify`.
    # Visible in the final summary: the trust file was not exercised.
    VERIFY_RESULT="WARN: verification incomplete in this environment, no trust file written"
    ACCEPTANCE_OPEN+=("verify -d trust file not exercised")
else
    step_fail "caution verify -d $B_ID (exit $VERIFY_STATUS, E2E_STRICT_VERIFY=$E2E_STRICT_VERIFY)"
fi
if [ "$(cat "$TRUST_APP" 2>/dev/null || echo "absent")" != "$TRUST_APP_BEFORE" ]; then
    step_fail "verify -d $B_ID created or changed the app's $TRUST_APP"
fi

log "Running caution apps get -d $B_ID --this-is-a-ci-machine (SSH-signed, no session)..."
cp "$CONFIG_DIR/config.json" "$CONFIG_BACKUP"
rm "$CONFIG_DIR/config.json"
set +e
GET_OUTPUT=$("$CAUTION_BIN" -u "$GATEWAY_URL" apps get "$RESOURCE_ID" -d "$B_ID" --this-is-a-ci-machine 2>&1)
GET_STATUS=$?
set -e
echo "$GET_OUTPUT"
if [ "$GET_STATUS" -ne 0 ] || ! contains "$GET_OUTPUT" "ID: $B_ID" || ! contains "$GET_OUTPUT" "Role: candidate"; then
    cp "$CONFIG_BACKUP" "$CONFIG_DIR/config.json"
    step_fail "caution apps get -d $B_ID --this-is-a-ci-machine"
fi

log "Running caution apps get $RESOURCE_ID --this-is-a-ci-machine (deployments table over SSH-signed ?retained=1, no history)..."
set +e
GET_APP_OUTPUT=$("$CAUTION_BIN" -u "$GATEWAY_URL" apps get "$RESOURCE_ID" --this-is-a-ci-machine </dev/null 2>&1)
GET_APP_STATUS=$?
set -e
cp "$CONFIG_BACKUP" "$CONFIG_DIR/config.json"
echo "$GET_APP_OUTPUT"
if [ "$GET_APP_STATUS" -ne 0 ] \
    || ! contains "$GET_APP_OUTPUT" "Live: ${A_ID:0:8}" \
    || ! line_with "$GET_APP_OUTPUT" "${B_ID:0:8}  " >/dev/null; then
    step_fail "caution apps get $RESOURCE_ID --this-is-a-ci-machine does not show A live and B's row"
fi
if contains "$GET_APP_OUTPUT" "Recent history:"; then
    step_fail "apps get --this-is-a-ci-machine printed Recent history (CI never calls /history)"
fi
case "$VERIFY_RESULT" in
    WARN*) step_warn "verify -d / apps get (B): $VERIFY_RESULT" ;;
    *) step_pass "verify -d B ($VERIFY_RESULT), SSH-signed apps get -d B and apps get" ;;
esac

# ── Step 12: Switch to B, signed (brief step 7) ──────────────────────

STEP_NUM=12
history_first() { api_get "/resources/$RESOURCE_ID/history?limit=5" | jq -c '.entries[0]'; }
HISTORY_BEFORE=$(api_get "/resources/$RESOURCE_ID/history?limit=10" | jq '.entries | length')
log "Switching to B with the session alone (must be refused)..."
SWITCH_PLAIN=$(jq -nc --arg a "$A_ID" '{expected_live_deployment_id: $a, acknowledged_verification: true}')
SESSION_SWITCH_CODE=$(http_code -X POST -H "X-Session-ID: $SESSION_ID" -H 'Content-Type: application/json' \
    -d "$SWITCH_PLAIN" "$GATEWAY_URL/api/resources/$RESOURCE_ID/deployments/$B_ID/switch")
SESSION_SWITCH_BODY=$(cat "$WORK_DIR/last-body")
if [ "$SESSION_SWITCH_CODE" != "403" ] || ! contains "$SESSION_SWITCH_BODY" "This operation requires signature verification"; then
    step_fail "Session-only switch returned $SESSION_SWITCH_CODE '$SESSION_SWITCH_BODY', want 403 'This operation requires signature verification'"
fi
if [ "$(api_get "/resources/$RESOURCE_ID" | jq -r '.live_deployment_id')" != "$A_ID" ]; then
    step_fail "The refused switch changed the live deployment"
fi
# The 403 never reaches the API, so it records nothing (earlier steps may already have
# recorded a refused app destroy).
HISTORY_NOW=$(api_get "/resources/$RESOURCE_ID/history?limit=10")
if [ "$(jq '.entries | length' <<<"$HISTORY_NOW")" != "$HISTORY_BEFORE" ] \
    || ! jq -e '[.entries[] | select(.operation == "switch")] | length == 0' <<<"$HISTORY_NOW" >/dev/null; then
    step_fail "The refused session-only switch changed the history (was $HISTORY_BEFORE entries): $HISTORY_NOW"
fi

log "Switching to B with a passkey signature..."
signed_switch "$B_ID" "$A_ID"
if [ "$SWITCH_RC" -ne 0 ] || [ "$SWITCH_STATUS" != "200" ]; then
    step_fail "Signed switch to B (rc $SWITCH_RC, HTTP ${SWITCH_STATUS:-none})"
fi
if [ "$(jq -r '.live_deployment_id' <<<"$SWITCH_OUT")" != "$B_ID" ] \
    || [ "$(jq -r '.previous_live_deployment_id' <<<"$SWITCH_OUT")" != "$A_ID" ] \
    || [ "$(jq -r '.stable_ip' <<<"$SWITCH_OUT")" != "$STABLE_IP" ]; then
    step_fail "Switch response does not name B live, A previous and $STABLE_IP"
fi
RES_JSON=$(api_get "/resources/$RESOURCE_ID")
if [ "$(jq -r '.live_deployment_id' <<<"$RES_JSON")" != "$B_ID" ] \
    || [ "$(jq -r '.public_ip' <<<"$RES_JSON")" != "$STABLE_IP" ] \
    || [ "$(jq -r '.provider_resource_id' <<<"$RES_JSON")" != "$B_INSTANCE" ]; then
    echo "$RES_JSON"
    step_fail "After the switch the app does not describe B (live, $STABLE_IP, $B_INSTANCE)"
fi
if ! assert_health "$STABLE_IP"; then
    step_fail "http://$STABLE_IP/.well-known/caution/health is not 200 after the switch"
fi
# The gateway completes the audit row after it answers.
switch_audited() { [ "$(history_first | jq -r '.signed_request_status')" = "200" ]; }
wait_for 30 1 switch_audited || step_fail "switch's signed request was not completed in the audit"
history_first | jq -e '.operation == "switch" and .outcome == "succeeded" and .auth_method == "passkey" and .signed_request_id != null' >/dev/null \
    || step_fail "history's first entry is not the passkey-signed switch"
step_pass "Switch to B: session-only 403, passkey-signed 200 recorded in history, same stable IP"

# ── Step 13: Rollback and stale switch (brief step 8) ────────────────

STEP_NUM=13
log "Rolling back to A (expected live: B)..."
signed_switch "$A_ID" "$B_ID"
if [ "$SWITCH_RC" -ne 0 ] || [ "$SWITCH_STATUS" != "200" ]; then
    step_fail "Rollback switch to A (rc $SWITCH_RC, HTTP ${SWITCH_STATUS:-none})"
fi
RES_JSON=$(api_get "/resources/$RESOURCE_ID")
if [ "$(jq -r '.live_deployment_id' <<<"$RES_JSON")" != "$A_ID" ] \
    || [ "$(jq -r '.public_ip' <<<"$RES_JSON")" != "$STABLE_IP" ] \
    || [ "$(jq -r '.provider_resource_id' <<<"$RES_JSON")" != "$A_INSTANCE" ]; then
    echo "$RES_JSON"
    step_fail "After the rollback the app does not describe A (live, $STABLE_IP, $A_INSTANCE)"
fi

log "Repeating the rollback (expected live: B, but A is live now)..."
signed_switch "$A_ID" "$B_ID"
if [ "$SWITCH_STATUS" != "409" ]; then
    step_fail "Stale switch returned HTTP ${SWITCH_STATUS:-none}, want 409"
fi
if [ "$(api_get "/resources/$RESOURCE_ID" | jq -r '.live_deployment_id')" != "$A_ID" ]; then
    step_fail "The stale switch changed the live deployment"
fi
history_first | jq -e '.outcome == "rejected" and .signed_request_id != null' >/dev/null \
    || step_fail "history's first entry is not the rejected stale switch with its signed request"
step_pass "Rollback to A, stale switch is 409 (rejected in history)"

# ── Step 14: Destroy deployments, unchanged push (brief step 9) ──────

STEP_NUM=14
log "Destroying the live deployment A (must be refused)..."
set +e
DESTROY_LIVE_OUTPUT=$("$CAUTION_BIN" -u "$GATEWAY_URL" apps destroy -d "$A_ID" -f 2>&1)
DESTROY_LIVE_STATUS=$?
set -e
echo "$DESTROY_LIVE_OUTPUT"
if [ "$DESTROY_LIVE_STATUS" -eq 0 ] || ! contains "$DESTROY_LIVE_OUTPUT" "The live deployment cannot be destroyed"; then
    step_fail "caution apps destroy -d A (live) was not refused with the live-deployment error"
fi
if [ "$(api_get "/resources/$RESOURCE_ID" | jq -r '.live_deployment_id')" != "$A_ID" ]; then
    step_fail "Destroying the live deployment changed the live pointer"
fi

log "Short deployment IDs: -d with the first 8 characters resolves in the linked checkout; a 2-character one is refused..."
SHORT_OUT=$("$CAUTION_BIN" -u "$GATEWAY_URL" apps get -d "${A_ID:0:8}" </dev/null 2>&1) || {
    echo "$SHORT_OUT"
    step_fail "caution apps get -d ${A_ID:0:8} (linked checkout, session)"
}
echo "$SHORT_OUT"
contains "$SHORT_OUT" "ID: $A_ID" || step_fail "apps get -d ${A_ID:0:8} did not resolve to A ($A_ID)"
set +e
TOO_SHORT_OUT=$("$CAUTION_BIN" -u "$GATEWAY_URL" apps get -d d2 </dev/null 2>&1)
TOO_SHORT_STATUS=$?
set -e
echo "$TOO_SHORT_OUT"
if [ "$TOO_SHORT_STATUS" -eq 0 ] || ! contains "$TOO_SHORT_OUT" "use the full ID or at least its first 8 characters"; then
    step_fail "apps get -d d2 was not refused with the short-ID message"
fi

log "Destroying the candidate B by its short ID, SSH-signed (--this-is-a-ci-machine, explicit app)..."
"$CAUTION_BIN" -u "$GATEWAY_URL" apps destroy "$RESOURCE_ID" -d "${B_ID:0:8}" -f --this-is-a-ci-machine </dev/null \
    || step_fail "caution apps destroy -d B (SSH-signed, short ID)"
history_first | jq -e '.operation == "deployment_destroy" and .outcome == "succeeded" and .auth_method == "ssh_signed"' >/dev/null \
    || step_fail "history's first entry is not the SSH-signed deployment destroy"
B_STATUS=$(api_get "/resources/$RESOURCE_ID/deployments" | jq -r --arg d "$B_ID" '.[] | select(.id == $d) | .status')
if [ "$B_STATUS" != "destroyed" ]; then
    step_fail "B status is '$B_STATUS' after destroy, want 'destroyed'"
fi
if [ "$(db "SELECT COUNT(*) FROM tracked_resources WHERE resource_id = '$B_INSTANCE' AND status = 'running'")" != "0" ]; then
    step_fail "B's instance $B_INSTANCE is still metered"
fi
if ! assert_health "$STABLE_IP"; then
    step_fail "Destroying B broke the live deployment: health is not 200 on $STABLE_IP"
fi

log "Pushing main again, unchanged (A live: the slot is free, nothing to deploy)..."
ROWS_BEFORE=$(rows_total)
NOOP_OUT=$(timeout "$PUSH_TIMEOUT" git push caution main </dev/null 2>&1) || {
    echo "$NOOP_OUT"
    step_fail "Unchanged push failed"
}
echo "$NOOP_OUT"
if ! contains "$NOOP_OUT" "No branch updates; skipping deployment"; then
    step_fail "Unchanged push while A is live did not skip the deployment"
fi
if [ "$(rows_total)" != "$ROWS_BEFORE" ] || [ "$(rows_reserved)" != "0" ]; then
    step_fail "Unchanged push created or left a deployment row"
fi
step_pass "short -d IDs, destroy -d A refused, SSH-signed destroy -d B ok (in history), unchanged push skipped with no row left"

# ── Step 15: caution apps destroy (brief step 10) ────────────────────

STEP_NUM=15
log "Destroying the app..."
"$CAUTION_BIN" -u "$GATEWAY_URL" apps destroy "$RESOURCE_ID" --force || step_fail "caution apps destroy (app)"
APP_ROW=$(db "SELECT state::text || ',' || (live_deployment_id IS NULL)::text FROM compute_resources WHERE id = '$RESOURCE_ID'")
if [ "$APP_ROW" != "terminated,true" ]; then
    step_fail "App after destroy is '$APP_ROW', want 'terminated,true' (state, no live deployment)"
fi
LEFT=$(db "SELECT COUNT(*) FROM app_deployments WHERE app_id = '$RESOURCE_ID' AND status <> 'destroyed'")
if [ "$LEFT" != "0" ]; then
    step_fail "$LEFT deployment(s) of the destroyed app are not 'destroyed'"
fi
METERED=$(db "SELECT COUNT(*) FROM tracked_resources WHERE application_id = '$RESOURCE_ID' AND status = 'running'")
if [ "$METERED" != "0" ]; then
    step_fail "$METERED meter(s) of the destroyed app are still running"
fi

# History and the lists, right after the destroy (step 16 revives the app).
LIST_OUT=$("$CAUTION_BIN" -u "$GATEWAY_URL" apps list </dev/null 2>&1) || {
    echo "$LIST_OUT"
    step_fail "caution apps list after the destroy"
}
echo "$LIST_OUT"
if line_with "$LIST_OUT" "$RESOURCE_ID" >/dev/null; then
    step_fail "apps list still shows the destroyed app $RESOURCE_ID"
fi
LIST_ALL_OUT=$("$CAUTION_BIN" -u "$GATEWAY_URL" apps list -a </dev/null 2>&1) || {
    echo "$LIST_ALL_OUT"
    step_fail "caution apps list -a"
}
echo "$LIST_ALL_OUT"
LIST_ALL_LINE=$(line_with "$LIST_ALL_OUT" "$RESOURCE_ID") || step_fail "apps list -a has no line for the destroyed app"
contains "$LIST_ALL_LINE" "Destroyed" || step_fail "apps list -a line '$LIST_ALL_LINE' lacks 'Destroyed'"
history_first | jq -e '.operation == "app_destroy" and .outcome == "succeeded"' >/dev/null \
    || step_fail "history's first entry is not the succeeded app destroy"
if ! api_get "/resources/$RESOURCE_ID/history?limit=50" | jq -e '
    [.entries[] | select(.operation == "switch" and .outcome == "succeeded")] as $ok
    | [.entries[] | select(.operation == "switch" and .outcome == "rejected")] as $rejected
    | ($ok | length) == 2 and ($rejected | length) == 1
      and ([.entries[] | select(.operation == "deployment_destroy")] | length) == 1' >/dev/null; then
    step_fail "history lacks the two succeeded switches, the rejected one and the deployment destroy"
fi
step_pass "App destroyed: terminated, every deployment destroyed, no live pointer, no running meter, lists and history agree"

# ── Step 16: Unchanged push rebuilds HEAD and goes live (brief step 11) ──

STEP_NUM=16
log "Pushing main again without a new commit (app terminated, nothing live)..."
REPUSH_LOG="$WORK_DIR/push-d.log"
timeout "$PUSH_TIMEOUT" git push caution main </dev/null >"$REPUSH_LOG" 2>&1 || {
    cat "$REPUSH_LOG"
    step_fail "Unchanged push after destroy failed"
}
REPUSH_OUT=$(cat "$REPUSH_LOG")
echo "$REPUSH_OUT"
if ! contains "$REPUSH_OUT" "redeploying existing remote HEAD"; then
    step_fail "Unchanged push after destroy did not rebuild the remote HEAD"
fi
D_ID=$(grep -o 'Deployment: [0-9a-f-]\{36\} (live)' <<<"$REPUSH_OUT" | tail -1 | cut -d' ' -f2 || true)
if [ -z "$D_ID" ]; then
    step_fail "Rebuild output has no 'Deployment: <id> (live)'"
fi
if [ "$D_ID" = "$A_ID" ] || [ "$D_ID" = "$B_ID" ]; then
    step_fail "The rebuild reused deployment $D_ID"
fi
RES_JSON=$(api_get "/resources/$RESOURCE_ID") || step_fail "GET /api/resources/$RESOURCE_ID after the rebuild"
if [ "$(jq -r '.live_deployment_id' <<<"$RES_JSON")" != "$D_ID" ]; then
    echo "$RES_JSON"
    step_fail "The rebuilt deployment $D_ID is not live"
fi
if ! api_get "/resources/$RESOURCE_ID/deployments" \
    | jq -e --arg d "$D_ID" '.[] | select(.id == $d and .role == "live" and .status == "running")' >/dev/null; then
    step_fail "Deployments list does not show $D_ID live and running"
fi
step_pass "Unchanged push after destroy rebuilt HEAD and went live (deployment $D_ID)"

# ── Step 17: Final destroy ───────────────────────────────────────────

STEP_NUM=17
if [ "$E2E_BYOC" = 1 ]; then
    log "Tearing down the app and its linked environment..."
    byoc_cli teardown --byoc --force || step_fail "caution teardown --byoc"
    BYOC_ENVIRONMENT_UP=false
else
    log "Destroying the app..."
    "$CAUTION_BIN" -u "$GATEWAY_URL" apps destroy "$RESOURCE_ID" --force || step_fail "caution apps destroy (final)"
fi
if [ "$(db "SELECT state::text FROM compute_resources WHERE id = '$RESOURCE_ID'")" != "terminated" ]; then
    step_fail "App is not terminated after the final destroy"
fi
RESOURCE_ID=""  # Clear so cleanup trap doesn't try again
step_pass "Final app destroy"
