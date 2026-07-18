#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
#
# E2E test for database-layer invariants of the signed_request_audit table
# and the pgp_keys soft-delete constraints.
# Requires: make up-test (builds with e2e-testing-unsafe feature)
#
# Rationale: e2e-testing-unsafe bypasses the fido2 signing middleware, so the
# signed_request_audit insert path is unreachable via HTTP in e2e. Instead
# this test asserts the migration 047 CHECK constraints and indexes directly
# against the test Postgres container, which is where two known review
# findings live:
#   1. signed_request_audit_request_method requires uppercase-only methods
#      (`^[A-Z]+$`) -- the CHECK is stricter than what any HTTP-layer
#      normalization guarantees, so a lowercase method must be rejected.
#   2. pgp_keys_active_user_fingerprint_unique is a PARTIAL unique index
#      (WHERE removed_at IS NULL) so soft-deleted keys must not block
#      re-adding the same fingerprint.
#
# Tests:
#   1. Wait for gateway, create test user via e2e-login
#   2. POSITIVE: insert a valid signed_request_audit row
#   3. NEGATIVE: request_method lowercase -> rejected
#   4. NEGATIVE: request_body_sha256 not hex -> rejected
#   5. NEGATIVE: authorization_flow bogus -> rejected
#   6. NEGATIVE: response_status set without completed_at -> rejected
#   7. Complete the row from step 2 -> accepted
#   8. pgp_keys partial-unique: duplicate active fingerprint rejected;
#      soft-deleted fingerprint may be re-added

set -euo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8000}"
LOG_DIR="tests/e2e/logs"
LOG_FILE="$LOG_DIR/e2e-pgp-audit-constraints-$(date +%Y%m%d-%H%M%S).log"
STEP_NUM=0
STEPS_PASSED=0
STEPS_FAILED=0
STEP_RESULTS=()

USER_ID=""
WORK_DIR=$(mktemp -d)
AUDIT_ROW_ID=""
PGP_KEY_ID_1=""
PGP_KEY_ID_2=""
FINGERPRINT=""

mkdir -p "$LOG_DIR"

exec > >(tee -a "$LOG_FILE") 2>&1

psql_exec() {
    docker exec postgres-test psql -U postgres -d caution_test -v ON_ERROR_STOP=1 -c "$1"
}

psql_exec_noerrstop() {
    docker exec postgres-test psql -U postgres -d caution_test -c "$1"
}

cleanup() {
    echo ""
    echo "=== Cleanup ==="

    if [ -n "$USER_ID" ]; then
        echo "Removing test rows for user $USER_ID..."
        docker exec postgres-test psql -U postgres -d caution_test -c "
DELETE FROM signed_request_audit WHERE user_id = '$USER_ID';
DELETE FROM pgp_keys WHERE user_id = '$USER_ID';
" >/dev/null 2>&1 || true
    fi

    rm -rf "$WORK_DIR"

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

# Generate a UUID via the DB. A bare SELECT under -t -A emits only the value
# (no "INSERT 0 1"-style command tag), so this parses cleanly — unlike an
# INSERT ... RETURNING, whose command tag would otherwise corrupt the id.
new_uuid() {
    docker exec postgres-test psql -U postgres -d caution_test -t -A \
        -c "SELECT gen_random_uuid();" | tr -d ' \r\n'
}

# ── Step 1: Wait for services, e2e-login ─────────────────────────────

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

log "Creating test user via e2e-login..."
LOGIN_RESPONSE=$(curl -sf -X POST "$GATEWAY_URL/auth/e2e-login" \
    -H "Content-Type: application/json")

USER_ID=$(echo "$LOGIN_RESPONSE" | jq -r '.user_id')

if [ -z "$USER_ID" ] || [ "$USER_ID" = "null" ]; then
    step_fail "E2E login (no user_id in response)"
fi
step_pass "Gateway health check + e2e login (user: $USER_ID)"

# ── Step 2: POSITIVE insert of a valid signed_request_audit row ──────

STEP_NUM=2
CHALLENGE_ID_1=$(new_uuid)
AUDIT_ROW_ID=$(new_uuid)
log "Inserting a valid signed_request_audit row (id=$AUDIT_ROW_ID, challenge_id=$CHALLENGE_ID_1)..."

if ! docker exec postgres-test psql -U postgres -d caution_test -v ON_ERROR_STOP=1 -t -A -c "
INSERT INTO signed_request_audit (
    id, user_id, signature_scheme, credential_id, credential_public_key,
    relying_party_id, request_method, request_path, request_body_sha256,
    request_body_size_bytes, challenge_id, authentication_state, assertion,
    authorization_flow, response_status, completed_at
) VALUES (
    '$AUDIT_ROW_ID', '$USER_ID', 'webauthn', '\x00'::bytea, '\x00'::bytea,
    'localhost', 'DELETE', '/pgp-keys/00000000-0000-0000-0000-000000000000',
    '$(printf '0%.0s' $(seq 1 64))',
    0, '$CHALLENGE_ID_1', '\x00'::bytea, '\x00'::bytea,
    'direct', NULL, NULL
);
" 2>err.txt; then
    cat err.txt
    step_fail "POSITIVE insert of valid signed_request_audit row"
fi
rm -f err.txt
step_pass "POSITIVE insert of valid signed_request_audit row (id: $AUDIT_ROW_ID)"

# ── Step 3: NEGATIVE - lowercase request_method rejected ─────────────

STEP_NUM=3
log "Asserting lowercase request_method is rejected by signed_request_audit_request_method..."
CHALLENGE_ID_2=$(docker exec postgres-test psql -U postgres -d caution_test -t -A -c "SELECT gen_random_uuid();" | tr -d ' \r\n')

if docker exec postgres-test psql -U postgres -d caution_test -c "
INSERT INTO signed_request_audit (
    user_id, signature_scheme, credential_id, credential_public_key,
    relying_party_id, request_method, request_path, request_body_sha256,
    request_body_size_bytes, challenge_id, authentication_state, assertion,
    authorization_flow, response_status, completed_at
) VALUES (
    '$USER_ID', 'webauthn', '\x00'::bytea, '\x00'::bytea,
    'localhost', 'delete', '/pgp-keys/00000000-0000-0000-0000-000000000000',
    '$(printf '0%.0s' $(seq 1 64))',
    0, '$CHALLENGE_ID_2', '\x00'::bytea, '\x00'::bytea,
    'direct', NULL, NULL
);
" 2>err.txt; then
    step_fail "lowercase request_method should have been rejected"
else
    if grep -q 'signed_request_audit_request_method' err.txt; then
        step_pass "lowercase request_method rejected by signed_request_audit_request_method"
    else
        cat err.txt
        step_fail "lowercase request_method rejected but for the wrong reason"
    fi
fi
rm -f err.txt

# ── Step 4: NEGATIVE - non-hex body sha256 rejected ───────────────────

STEP_NUM=4
log "Asserting non-hex request_body_sha256 is rejected by signed_request_audit_body_sha256..."
CHALLENGE_ID_3=$(docker exec postgres-test psql -U postgres -d caution_test -t -A -c "SELECT gen_random_uuid();" | tr -d ' \r\n')

if docker exec postgres-test psql -U postgres -d caution_test -c "
INSERT INTO signed_request_audit (
    user_id, signature_scheme, credential_id, credential_public_key,
    relying_party_id, request_method, request_path, request_body_sha256,
    request_body_size_bytes, challenge_id, authentication_state, assertion,
    authorization_flow, response_status, completed_at
) VALUES (
    '$USER_ID', 'webauthn', '\x00'::bytea, '\x00'::bytea,
    'localhost', 'DELETE', '/pgp-keys/00000000-0000-0000-0000-000000000000',
    'NOTHEX',
    0, '$CHALLENGE_ID_3', '\x00'::bytea, '\x00'::bytea,
    'direct', NULL, NULL
);
" 2>err.txt; then
    step_fail "non-hex request_body_sha256 should have been rejected"
else
    if grep -q 'signed_request_audit_body_sha256' err.txt; then
        step_pass "non-hex request_body_sha256 rejected by signed_request_audit_body_sha256"
    else
        cat err.txt
        step_fail "non-hex request_body_sha256 rejected but for the wrong reason"
    fi
fi
rm -f err.txt

# ── Step 5: NEGATIVE - bogus authorization_flow rejected ──────────────

STEP_NUM=5
log "Asserting bogus authorization_flow is rejected by signed_request_audit_authorization_flow..."
CHALLENGE_ID_4=$(docker exec postgres-test psql -U postgres -d caution_test -t -A -c "SELECT gen_random_uuid();" | tr -d ' \r\n')

if docker exec postgres-test psql -U postgres -d caution_test -c "
INSERT INTO signed_request_audit (
    user_id, signature_scheme, credential_id, credential_public_key,
    relying_party_id, request_method, request_path, request_body_sha256,
    request_body_size_bytes, challenge_id, authentication_state, assertion,
    authorization_flow, response_status, completed_at
) VALUES (
    '$USER_ID', 'webauthn', '\x00'::bytea, '\x00'::bytea,
    'localhost', 'DELETE', '/pgp-keys/00000000-0000-0000-0000-000000000000',
    '$(printf '0%.0s' $(seq 1 64))',
    0, '$CHALLENGE_ID_4', '\x00'::bytea, '\x00'::bytea,
    'bogus', NULL, NULL
);
" 2>err.txt; then
    step_fail "bogus authorization_flow should have been rejected"
else
    if grep -q 'signed_request_audit_authorization_flow' err.txt; then
        step_pass "bogus authorization_flow rejected by signed_request_audit_authorization_flow"
    else
        cat err.txt
        step_fail "bogus authorization_flow rejected but for the wrong reason"
    fi
fi
rm -f err.txt

# ── Step 6: NEGATIVE - response_status set without completed_at ───────

STEP_NUM=6
log "Asserting response_status without completed_at is rejected by signed_request_audit_completion..."
CHALLENGE_ID_5=$(docker exec postgres-test psql -U postgres -d caution_test -t -A -c "SELECT gen_random_uuid();" | tr -d ' \r\n')

if docker exec postgres-test psql -U postgres -d caution_test -c "
INSERT INTO signed_request_audit (
    user_id, signature_scheme, credential_id, credential_public_key,
    relying_party_id, request_method, request_path, request_body_sha256,
    request_body_size_bytes, challenge_id, authentication_state, assertion,
    authorization_flow, response_status, completed_at
) VALUES (
    '$USER_ID', 'webauthn', '\x00'::bytea, '\x00'::bytea,
    'localhost', 'DELETE', '/pgp-keys/00000000-0000-0000-0000-000000000000',
    '$(printf '0%.0s' $(seq 1 64))',
    0, '$CHALLENGE_ID_5', '\x00'::bytea, '\x00'::bytea,
    'direct', 200, NULL
);
" 2>err.txt; then
    step_fail "response_status without completed_at should have been rejected"
else
    if grep -q 'signed_request_audit_completion' err.txt; then
        step_pass "response_status without completed_at rejected by signed_request_audit_completion"
    else
        cat err.txt
        step_fail "response_status without completed_at rejected but for the wrong reason"
    fi
fi
rm -f err.txt

# ── Step 7: complete the row from step 2 ──────────────────────────────

STEP_NUM=7
log "Completing audit row $AUDIT_ROW_ID (response_status=204, completed_at=NOW())..."
if docker exec postgres-test psql -U postgres -d caution_test -v ON_ERROR_STOP=1 -c "
UPDATE signed_request_audit SET response_status = 204, completed_at = NOW() WHERE id = '$AUDIT_ROW_ID';
" 2>err.txt; then
    step_pass "completion update satisfies signed_request_audit_completion"
else
    cat err.txt
    step_fail "completion update should have succeeded"
fi
rm -f err.txt

# ── Step 8: pgp_keys partial-unique blocks a duplicate ACTIVE row ─────

STEP_NUM=8
FINGERPRINT="AAAA$(docker exec postgres-test psql -U postgres -d caution_test -t -A -c "SELECT substr(md5(random()::text), 1, 16);" | tr -d ' \r\n')"
log "Inserting first active pgp_keys row (fingerprint=$FINGERPRINT)..."

PGP_KEY_ID_1=$(new_uuid)
if ! docker exec postgres-test psql -U postgres -d caution_test -v ON_ERROR_STOP=1 -t -A -c "
INSERT INTO pgp_keys (id, user_id, public_key, fingerprint, name)
VALUES ('$PGP_KEY_ID_1', '$USER_ID', '-----BEGIN PGP PUBLIC KEY BLOCK-----test-----END PGP PUBLIC KEY BLOCK-----', '$FINGERPRINT', NULL);
" 2>err.txt; then
    cat err.txt
    step_fail "insert of first active pgp_keys row"
fi
rm -f err.txt
log "  First row id: $PGP_KEY_ID_1"

log "Asserting a second active row with the same (user_id, fingerprint) is rejected..."
if docker exec postgres-test psql -U postgres -d caution_test -c "
INSERT INTO pgp_keys (user_id, public_key, fingerprint, name)
VALUES ('$USER_ID', '-----BEGIN PGP PUBLIC KEY BLOCK-----test2-----END PGP PUBLIC KEY BLOCK-----', '$FINGERPRINT', NULL);
" 2>err.txt; then
    step_fail "duplicate active (user_id, fingerprint) should have been rejected"
else
    if grep -q 'pgp_keys_active_user_fingerprint_unique' err.txt; then
        step_pass "duplicate active (user_id, fingerprint) rejected by pgp_keys_active_user_fingerprint_unique"
    else
        cat err.txt
        step_fail "duplicate active (user_id, fingerprint) rejected but for the wrong reason"
    fi
fi
rm -f err.txt

# ── Step 9: soft-deleted row does not block re-adding the fingerprint ─

STEP_NUM=9
log "Soft-removing the first row (removed_at = NOW())..."
docker exec postgres-test psql -U postgres -d caution_test -v ON_ERROR_STOP=1 -c "
UPDATE pgp_keys SET removed_at = NOW() WHERE id = '$PGP_KEY_ID_1';
" >/dev/null

log "Asserting the same (user_id, fingerprint) can be re-added once the prior row is soft-deleted..."
PGP_KEY_ID_2=$(new_uuid)
if ! docker exec postgres-test psql -U postgres -d caution_test -v ON_ERROR_STOP=1 -t -A -c "
INSERT INTO pgp_keys (id, user_id, public_key, fingerprint, name)
VALUES ('$PGP_KEY_ID_2', '$USER_ID', '-----BEGIN PGP PUBLIC KEY BLOCK-----test3-----END PGP PUBLIC KEY BLOCK-----', '$FINGERPRINT', NULL);
" 2>err.txt; then
    cat err.txt
    step_fail "re-adding (user_id, fingerprint) after soft-delete should have succeeded"
fi
rm -f err.txt
step_pass "soft-deleted row does not block re-adding same (user_id, fingerprint) (id: $PGP_KEY_ID_2)"
