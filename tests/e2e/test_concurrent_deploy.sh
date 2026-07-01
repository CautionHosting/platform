#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
#
# E2E concurrency test for the deploy path (issue #309).
# Requires: make up-test (brings up postgres-test + gateway + api)
#
# Two simultaneous `git push` must not both start a deployment. This test
# exercises the two DB-level guards that make a deploy atomic, by racing two
# concurrent psql transactions against the *exact* guarded SQL the API runs:
#
#   A. compute_resources state CAS on the destroyed-app reactivation branch
#      (api/src/main.rs `deploy_logic`): a guarded
#      `UPDATE ... SET state='pending' ... WHERE state != 'pending'` — exactly
#      one concurrent caller may win.
#   B. eif_builds slot reservation (api/src/builder.rs `execute_remote_build`):
#      a per-app `pg_advisory_xact_lock` around a check-then-insert — exactly
#      one concurrent caller may insert the active build row.
#
# Note: this validates the SQL/lock *semantics* against a live Postgres, not the
# Rust call path itself (the builder guard is unreachable through a full
# `git push` once the state CAS holds). Each transaction sleeps briefly while
# holding its snapshot/lock to force a real overlap, so a regression that drops
# either guard yields two winners and fails the test.

set -euo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8000}"
API_URL="${API_URL:-http://127.0.0.1:8080}"
CAUTION_BIN="${CAUTION_BIN:-caution}"
FIXTURES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)"
WORK_DIR=$(mktemp -d)
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/caution-cli"
RESOURCE_ID=""
ORG_ID=""
USER_ID=""
LOG_DIR="tests/e2e/logs"
LOG_FILE="$LOG_DIR/concurrent-deploy-$(date +%Y%m%d-%H%M%S).log"
STEP_NUM=0
STEPS_PASSED=0
STEPS_FAILED=0
STEP_RESULTS=()

# Fixed advisory-lock key shared by the two racers in test B (distinct from the
# capacity lock 7_650_001 in fully_managed_capacity.rs). The value only needs to
# match between racers to force contention.
ADVISORY_KEY=7650999

mkdir -p "$LOG_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1

# psql into the e2e test database.
psql_test() {
    docker exec -i postgres-test psql -U postgres -d caution_test "$@"
}

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    if [ -n "$RESOURCE_ID" ]; then
        # Remove the build rows this test created, then destroy the app.
        psql_test -c "DELETE FROM eif_builds WHERE app_id = '$RESOURCE_ID';" >/dev/null 2>&1 || true
        echo "Destroying app $RESOURCE_ID..."
        "$CAUTION_BIN" -u "$GATEWAY_URL" apps destroy "$RESOURCE_ID" --force 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"

    echo ""
    echo "========================================"
    echo "  Concurrent Deploy Test Results"
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

# ── Step 2: E2E login + onboard ──────────────────────────────────────

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

# Mark onboarded so API middleware doesn't block requests (402).
psql_test -c "
UPDATE users SET email_verified_at = NOW(), payment_method_added_at = NOW() WHERE id = '$USER_ID';
" >/dev/null 2>&1 || log "  Warning: could not mark user as onboarded"

# Trigger org provisioning, then read the org id.
curl -sf "$API_URL/resources" -H "X-Session-ID: $SESSION_ID" >/dev/null 2>&1 || true
for i in $(seq 1 10); do
    ORG_ID=$(psql_test -t -A -c "
SELECT organization_id FROM organization_members WHERE user_id = '$USER_ID' LIMIT 1;
" 2>/dev/null | head -1 | tr -d ' \n')
    [ -n "$ORG_ID" ] && break
    sleep 1
done
if [ -z "$ORG_ID" ]; then
    step_fail "Provision org for test user"
fi
step_pass "E2E login (user: $USER_ID, org: $ORG_ID)"

# ── Step 3: caution init (creates a real compute_resources row) ──────

STEP_NUM=3
CLONE_DIR="$WORK_DIR/demo-app"
cp -r "$FIXTURES_DIR/demo-app-happy-path" "$CLONE_DIR"
cd "$CLONE_DIR"
git init -b main >/dev/null
git -c user.email="e2e@caution.dev" -c user.name="Caution E2E" add .
git -c user.email="e2e@caution.dev" -c user.name="Caution E2E" commit -m "Initial commit" --quiet

INIT_OUTPUT=$("$CAUTION_BIN" -u "$GATEWAY_URL" init --name "e2e-concurrent-$(date +%s)" 2>&1)
if [ -f ".caution/deployment.json" ]; then
    RESOURCE_ID=$(jq -r '.resource_id' .caution/deployment.json)
else
    echo "$INIT_OUTPUT"
    step_fail "caution init (no .caution/deployment.json)"
fi
if [ -z "$RESOURCE_ID" ] || [ "$RESOURCE_ID" = "null" ]; then
    step_fail "caution init (no resource_id)"
fi
step_pass "caution init (app: $RESOURCE_ID)"

# ── Step 4: Race the state CAS on the destroyed-app branch ───────────
#
# Mirrors api/src/main.rs deploy_logic (was_destroyed branch). Two concurrent
# guarded UPDATEs must produce exactly one winner (UPDATE 1) and one loser
# (UPDATE 0). Without the `AND state != 'pending'` guard both would win.

STEP_NUM=4
log "Racing state CAS on destroyed-app reactivation..."

# Put the app into a destroyed state.
psql_test -c "
UPDATE compute_resources SET state = 'terminated', destroyed_at = NOW() WHERE id = '$RESOURCE_ID';
" >/dev/null

CAS_SQL="BEGIN;
SELECT pg_sleep(0.4);
UPDATE compute_resources SET destroyed_at = NULL, state = 'pending'
  WHERE id = '$RESOURCE_ID' AND organization_id = '$ORG_ID' AND state != 'pending';
COMMIT;"

CAS_OUT_A="$WORK_DIR/cas_a.out"
CAS_OUT_B="$WORK_DIR/cas_b.out"
psql_test -c "$CAS_SQL" >"$CAS_OUT_A" 2>&1 &
CAS_PID_A=$!
psql_test -c "$CAS_SQL" >"$CAS_OUT_B" 2>&1 &
CAS_PID_B=$!
wait "$CAS_PID_A" "$CAS_PID_B" || true

CAS_WINS=$(cat "$CAS_OUT_A" "$CAS_OUT_B" | grep -c '^UPDATE 1' || true)
if [ "$CAS_WINS" -ne 1 ]; then
    echo "--- racer A ---"; cat "$CAS_OUT_A"
    echo "--- racer B ---"; cat "$CAS_OUT_B"
    step_fail "State CAS produced $CAS_WINS winners (expected exactly 1)"
fi
step_pass "State CAS: exactly one concurrent reactivation won"

# ── Step 5: Race the eif_builds slot reservation ────────────────────
#
# Mirrors api/src/builder.rs execute_remote_build: a per-app advisory lock
# around a check-then-insert. Two concurrent reservations must insert exactly
# one active build row. Without the advisory lock both would pass the NOT EXISTS
# check during the overlap and insert.

STEP_NUM=5
log "Racing eif_builds slot reservation under advisory lock..."

# Clear any build rows so we start from zero active builds.
psql_test -c "DELETE FROM eif_builds WHERE app_id = '$RESOURCE_ID';" >/dev/null

RESERVE_SQL="BEGIN;
SELECT pg_advisory_xact_lock($ADVISORY_KEY);
SELECT pg_sleep(0.4);
INSERT INTO eif_builds (id, organization_id, app_id, user_id, commit_sha, procfile_hash, cache_key, builder_instance_type, status, started_at)
SELECT gen_random_uuid(), '$ORG_ID', '$RESOURCE_ID', '$USER_ID', 'deadbeefdeadbeef', 'testhash', 'testcachekey', 'm5.large', 'pending', NOW()
WHERE NOT EXISTS (
  SELECT 1 FROM eif_builds WHERE app_id = '$RESOURCE_ID' AND status IN ('pending', 'building')
);
COMMIT;"

RES_OUT_A="$WORK_DIR/reserve_a.out"
RES_OUT_B="$WORK_DIR/reserve_b.out"
psql_test -c "$RESERVE_SQL" >"$RES_OUT_A" 2>&1 &
RES_PID_A=$!
psql_test -c "$RESERVE_SQL" >"$RES_OUT_B" 2>&1 &
RES_PID_B=$!
wait "$RES_PID_A" "$RES_PID_B" || true

RES_INSERTS=$(cat "$RES_OUT_A" "$RES_OUT_B" | grep -c '^INSERT 0 1' || true)
ACTIVE_BUILDS=$(psql_test -t -A -c "
SELECT COUNT(*) FROM eif_builds WHERE app_id = '$RESOURCE_ID' AND status IN ('pending', 'building');
" | tr -d ' \n')

if [ "$RES_INSERTS" -ne 1 ] || [ "$ACTIVE_BUILDS" != "1" ]; then
    echo "--- racer A ---"; cat "$RES_OUT_A"
    echo "--- racer B ---"; cat "$RES_OUT_B"
    step_fail "Reservation inserted $RES_INSERTS rows, $ACTIVE_BUILDS active builds (expected 1 and 1)"
fi
step_pass "Reservation: exactly one concurrent build slot claimed"

log "All concurrency guards held."
