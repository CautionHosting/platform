#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
#
# E2E test for the app deployments schema (migration 056).
# Requires: make up-test (builds with e2e-testing-unsafe feature)
#
# Asserts directly against the test Postgres container:
#   1. A test user and app exist through the API
#   2. Every migration re-runs cleanly, twice (startup re-runs them all)
#   3. New apps default to the legacy lifecycle
#   4. Only one reserved/building/provisioning deployment per app
#   5. One running meter per deployment, and still one per Legacy app
#   6. Candidate capacity reservations need no VPC or EIP
#   7. Deployments record their bundle hash
#   8. deployment_events records requests and appended outcomes

set -euo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8000}"
MIGRATIONS_DIR="src/api/migrations"
LOG_DIR="tests/e2e/logs"
LOG_FILE="$LOG_DIR/e2e-app-deployments-schema-$(date +%Y%m%d-%H%M%S).log"
STEP_NUM=0
STEPS_PASSED=0
STEPS_FAILED=0
STEP_RESULTS=()

USER_ID=""
APP_ID=""

mkdir -p "$LOG_DIR"

exec > >(tee -a "$LOG_FILE") 2>&1

psql_exec() {
    docker exec postgres-test psql -U postgres -d caution_test -v ON_ERROR_STOP=1 -c "$1"
}

psql_value() {
    docker exec postgres-test psql -U postgres -d caution_test -t -A -v ON_ERROR_STOP=1 -c "$1"
}

apply_all_migrations() {
    for migration in "$MIGRATIONS_DIR"/*.sql; do
        docker exec -i postgres-test psql -U postgres -d caution_test -v ON_ERROR_STOP=1 \
            -q < "$migration" >/dev/null || return 1
    done
}

cleanup() {
    echo ""
    echo "=== Cleanup ==="

    if [ -n "$APP_ID" ]; then
        echo "Removing test rows for app $APP_ID..."
        docker exec postgres-test psql -U postgres -d caution_test -c "
DELETE FROM tracked_resources WHERE application_id = '$APP_ID';
DELETE FROM fully_managed_capacity_reservations WHERE resource_id = '$APP_ID';
DELETE FROM deployment_events WHERE app_id = '$APP_ID';
DELETE FROM app_deployments WHERE app_id = '$APP_ID';
" >/dev/null 2>&1 || true
    fi

    echo ""
    echo "========================================"
    echo "  E2E Test Results"
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

# ── Step 1: Wait for services, create a user and an app ──────────────

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

log "Creating a test user and app through the API..."
# e2e-login ignores the body and seeds a placeholder user. Protected routes stay
# gated (username claim, onboarding, org provisioning) until the setup below,
# copied from tests/e2e/test_ssh_units.sh:113-165, has run.
LOGIN_RESPONSE=$(curl -sf -X POST "$GATEWAY_URL/auth/e2e-login" -H "Content-Type: application/json") \
    || step_fail "e2e-login request"
SESSION_ID=$(echo "$LOGIN_RESPONSE" | jq -r '.session_id')
USER_ID=$(echo "$LOGIN_RESPONSE" | jq -r '.user_id')
[ -n "$SESSION_ID" ] && [ "$SESSION_ID" != "null" ] || step_fail "e2e-login returns a session"
CLAIM_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GATEWAY_URL/user/username" \
    -H "X-Session-ID: $SESSION_ID" -H 'Content-Type: application/json' \
    -d "{\"username\":\"bg-schema-$(date +%s)$RANDOM\"}")
[ "$CLAIM_CODE" = "200" ] || step_fail "Claim username (HTTP $CLAIM_CODE)"
psql_exec "UPDATE users SET email_verified_at = NOW(), payment_method_added_at = NOW() WHERE id = '$USER_ID'" \
    || step_fail "Mark test user as onboarded"
curl -sf "$GATEWAY_URL/api/resources" -H "X-Session-ID: $SESSION_ID" >/dev/null || true # provisions the org
for _ in $(seq 1 10); do
    [ -n "$(psql_value "SELECT organization_id FROM organization_members WHERE user_id = '$USER_ID' LIMIT 1")" ] && break
    sleep 1
done
# CreateResourceRequest requires a non-empty cmd (the CLI always sends one).
CREATE_RESPONSE=$(curl -s -w '\n%{http_code}' -X POST "$GATEWAY_URL/api/resources" \
    -H "X-Session-ID: $SESSION_ID" -H "Content-Type: application/json" \
    -d '{"cmd":"echo bluegreen-schema","name":"bluegreen-schema"}') || true
CREATE_CODE=$(echo "$CREATE_RESPONSE" | tail -n 1)
CREATE_BODY=$(echo "$CREATE_RESPONSE" | sed '$d')
[ "$CREATE_CODE" = "200" ] || step_fail "POST /api/resources (HTTP $CREATE_CODE): $CREATE_BODY"
APP_ID=$(echo "$CREATE_BODY" | jq -r '.id')
[ -n "$APP_ID" ] && [ "$APP_ID" != "null" ] || step_fail "POST /api/resources returns an app"
ORG_ID=$(psql_value "SELECT organization_id FROM compute_resources WHERE id = '$APP_ID'") \
    || step_fail "Look up the app's organization"
[ -n "$ORG_ID" ] || step_fail "App has an organization"
step_pass "Test app $APP_ID exists"

# ── Step 2: Migrations are idempotent ────────────────────────────────

STEP_NUM=2
log "Re-running every migration twice must succeed (startup re-runs them)..."
apply_all_migrations || step_fail "First re-run of all migrations"
apply_all_migrations || step_fail "Second re-run of all migrations"
step_pass "All migrations are idempotent"

# ── Step 3: Default lifecycle ────────────────────────────────────────

STEP_NUM=3
LIFECYCLE=$(psql_value "SELECT lifecycle FROM compute_resources WHERE id = '$APP_ID'" 2>&1) || true
[ "$LIFECYCLE" = "legacy" ] || step_fail "Default lifecycle is legacy (got: $LIFECYCLE)"
step_pass "Default lifecycle is legacy"

# ── Step 4: One active operation per app ─────────────────────────────

STEP_NUM=4
log "Only one build/provisioning operation per app..."
psql_exec "UPDATE compute_resources SET lifecycle = 'deployments' WHERE id = '$APP_ID'" \
    || step_fail "Switch the test app to the deployments lifecycle"
psql_exec "INSERT INTO app_deployments (app_id, organization_id, status) VALUES ('$APP_ID', '$ORG_ID', 'building')" \
    || step_fail "A first active operation is accepted"
if psql_exec "INSERT INTO app_deployments (app_id, organization_id, status) VALUES ('$APP_ID', '$ORG_ID', 'reserved')" 2>/dev/null; then
    step_fail "A second active operation is rejected"
fi
psql_exec "INSERT INTO app_deployments (app_id, organization_id, status) VALUES ('$APP_ID', '$ORG_ID', 'running')" \
    || step_fail "A running deployment is accepted next to an active operation"
step_pass "Partial unique index allows one active operation and any number of running deployments"

# ── Step 5: Per-deployment metering ──────────────────────────────────

STEP_NUM=5
log "Metering allows one running meter per deployment, and still one per Legacy app..."
D1=$(psql_value "INSERT INTO app_deployments (app_id, organization_id, status) VALUES ('$APP_ID', '$ORG_ID', 'running') RETURNING id" | sed -n 1p) \
    || step_fail "Insert deployment D1"
D2=$(psql_value "INSERT INTO app_deployments (app_id, organization_id, status) VALUES ('$APP_ID', '$ORG_ID', 'running') RETURNING id" | sed -n 1p) \
    || step_fail "Insert deployment D2"
psql_exec "INSERT INTO tracked_resources (resource_id, organization_id, application_id, deployment_id, provider, status, started_at, last_billed_at)
           VALUES ('i-bg-1', '$ORG_ID', '$APP_ID', '$D1', 'aws', 'running', NOW(), NOW()),
                  ('i-bg-2', '$ORG_ID', '$APP_ID', '$D2', 'aws', 'running', NOW(), NOW())" \
    || step_fail "Two running deployment meters for one app are accepted"
if psql_exec "INSERT INTO tracked_resources (resource_id, organization_id, application_id, deployment_id, provider, status, started_at, last_billed_at)
              VALUES ('i-bg-1b', '$ORG_ID', '$APP_ID', '$D1', 'aws', 'running', NOW(), NOW())" 2>/dev/null; then
    step_fail "A second running meter for one deployment is rejected"
fi
psql_exec "INSERT INTO tracked_resources (resource_id, organization_id, application_id, provider, status, started_at, last_billed_at)
           VALUES ('i-bg-legacy-1', '$ORG_ID', '$APP_ID', 'aws', 'running', NOW(), NOW())" \
    || step_fail "A running Legacy meter is accepted"
if psql_exec "INSERT INTO tracked_resources (resource_id, organization_id, application_id, provider, status, started_at, last_billed_at)
              VALUES ('i-bg-legacy-2', '$ORG_ID', '$APP_ID', 'aws', 'running', NOW(), NOW())" 2>/dev/null; then
    step_fail "Two running Legacy meters for one app are rejected"
fi
apply_all_migrations || step_fail "Migrations still re-run with two running deployment meters"
step_pass "Per-deployment metering index works and survives restart"

# ── Step 6: Candidate capacity reservations ──────────────────────────

STEP_NUM=6
psql_exec "INSERT INTO fully_managed_capacity_reservations (organization_id, resource_id, region, host_vcpus, vpcs, eips)
           VALUES ('$ORG_ID', '$APP_ID', 'us-west-2', 4, 0, 0)" || step_fail "vCPU-only reservation accepted"
step_pass "Candidate capacity reservations need no VPC or EIP"

# ── Step 7: Deployment bundle hash ───────────────────────────────────

STEP_NUM=7
[ "$(psql_value "SELECT COUNT(*) FROM information_schema.columns
                 WHERE table_name = 'app_deployments' AND column_name = 'bundle_hash'")" = "1" ] \
    || step_fail "app_deployments.bundle_hash exists"
step_pass "Deployments record their bundle hash"

# ── Step 8: Deployment events ────────────────────────────────────────

STEP_NUM=8
OPERATION=$(psql_value "SELECT gen_random_uuid()")
psql_exec "INSERT INTO deployment_events (operation_id, organization_id, app_id, operation, outcome, auth_method)
           VALUES ('$OPERATION', '$ORG_ID', '$APP_ID', 'switch', 'requested', 'passkey')" \
    || step_fail "A switch request is recorded"
if psql_exec "INSERT INTO deployment_events (operation_id, organization_id, app_id, operation, outcome)
              VALUES ('$OPERATION', '$ORG_ID', '$APP_ID', 'switch', 'requested')" 2>/dev/null; then
    step_fail "One request row per operation"
fi
psql_exec "INSERT INTO deployment_events (operation_id, organization_id, app_id, operation, outcome)
           VALUES ('$OPERATION', '$ORG_ID', '$APP_ID', 'switch', 'succeeded')" || step_fail "Outcomes append"
if psql_exec "INSERT INTO deployment_events (operation_id, organization_id, app_id, operation, outcome)
              VALUES (gen_random_uuid(), '$ORG_ID', '$APP_ID', 'rename', 'requested')" 2>/dev/null; then
    step_fail "Unknown operations are rejected"
fi
step_pass "deployment_events records requests and appended outcomes"
