#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
#
# E2E test for PGP public key enrollment (add / list / remove).
# Requires: make up-test (builds gateway with e2e-testing-unsafe feature,
# which bypasses the FIDO2 signed-request middleware so these endpoints can
# be exercised with only an X-Session-ID header, like test_ssh_units.sh does
# for /ssh-keys).
#
# Tests:
#   1. Wait for gateway health
#   2. Create test user via e2e-login endpoint, mark onboarded
#   3. Add a valid PGP public key -> 200, capture id + fingerprint
#   4. List keys -> fingerprint/name present
#   5. Re-add same key -> 409 (duplicate active fingerprint)
#   6. Add malformed key -> 400
#   7. Add private key block -> 400
#   8. Add with name > 255 chars -> 400
#   9. Delete key -> 204, then list -> gone
#  10. Delete unknown id -> 404
#  11. Re-add same key after soft-delete -> 200; verify 2 rows in DB

set -euo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8000}"
FIXTURES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)"
WORK_DIR=$(mktemp -d)
LOG_DIR="tests/e2e/logs"
LOG_FILE="$LOG_DIR/e2e-pgp-$(date +%Y%m%d-%H%M%S).log"
STEP_NUM=0
STEPS_PASSED=0
STEPS_FAILED=0
STEP_RESULTS=()

mkdir -p "$LOG_DIR"

exec > >(tee -a "$LOG_FILE") 2>&1

cleanup() {
    echo ""
    echo "=== Cleanup ==="

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

step_warn() {
    STEPS_PASSED=$((STEPS_PASSED + 1))
    STEP_RESULTS+=("[WARN] Step $STEP_NUM: $1")
    echo "[WARN] Step $STEP_NUM: $1"
}

log() {
    echo "[e2e] $*"
}

# ── Step 1: Wait for gateway ─────────────────────────────────────────

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
if [ -z "$EXPIRES_AT" ] || [ "$EXPIRES_AT" = "null" ]; then
    step_fail "E2E login (no expires_at in response)"
fi

log "Logged in as user $USER_ID (session: ${SESSION_ID:0:16}...)"

log "Marking test user as onboarded..."
docker exec postgres-test psql -U postgres -d caution_test -c "
UPDATE users SET email_verified_at = NOW(), payment_method_added_at = NOW() WHERE id = '$USER_ID';
" >/dev/null 2>&1 || log "  Warning: could not mark user as onboarded"

step_pass "E2E login (user: $USER_ID)"

# ── Step 3: Add a valid PGP public key ───────────────────────────────

STEP_NUM=3
log "Generating a second, distinct PGP key for later use..."
export GNUPGHOME="$WORK_DIR/gnupg"
mkdir -m 700 "$GNUPGHOME"
gpg --batch --quiet --pinentry-mode loopback --passphrase '' \
    --quick-generate-key "Caution E2E Second Key (throwaway) <pgp-e2e-second@caution.test>" \
    ed25519 sign 0 >/dev/null 2>&1
SECOND_FPR=$(gpg --list-keys --with-colons | awk -F: '/^fpr:/{print $10; exit}')
gpg --armor --export "$SECOND_FPR" > "$WORK_DIR/second-public-key.asc"

log "Generating malformed and private-key fixtures..."
echo "not a pgp key, just garbage text" > "$WORK_DIR/malformed-key.txt"
gpg --batch --quiet --pinentry-mode loopback --passphrase '' \
    --armor --export-secret-keys "$SECOND_FPR" > "$WORK_DIR/private-key.asc"

log "Adding valid PGP public key via gateway API..."
ADD_KEY_RESPONSE=$(curl -sf -X POST "$GATEWAY_URL/pgp-keys" \
    -H "Content-Type: application/json" \
    -H "X-Session-ID: $SESSION_ID" \
    -d "$(jq -n --rawfile public_key "$FIXTURES_DIR/pgp/test-public-key.asc" \
        --arg name "e2e-test-key" \
        '{public_key: $public_key, name: $name}')")

FINGERPRINT=$(echo "$ADD_KEY_RESPONSE" | jq -r '.fingerprint')
KEY_ID=$(echo "$ADD_KEY_RESPONSE" | jq -r '.id')

if [ -z "$FINGERPRINT" ] || [ "$FINGERPRINT" = "null" ]; then
    step_fail "Add PGP key (no fingerprint in response)"
fi
if [ -z "$KEY_ID" ] || [ "$KEY_ID" = "null" ]; then
    step_fail "Add PGP key (no id in response)"
fi
step_pass "Add PGP key (fingerprint: ${FINGERPRINT:0:20}..., id: $KEY_ID)"

# ── Step 4: List keys ─────────────────────────────────────────────────

STEP_NUM=4
log "Listing PGP keys..."
LIST_RESPONSE=$(curl -sf "$GATEWAY_URL/pgp-keys" -H "X-Session-ID: $SESSION_ID")

FOUND_NAME=$(echo "$LIST_RESPONSE" | jq -r --arg fpr "$FINGERPRINT" '.keys[] | select(.fingerprint == $fpr) | .name')
if [ "$FOUND_NAME" != "e2e-test-key" ]; then
    step_fail "List PGP keys (expected name 'e2e-test-key', got '$FOUND_NAME')"
fi
step_pass "List PGP keys (fingerprint present with correct name)"

# ── Step 5: Re-add same key -> 409 ───────────────────────────────────

STEP_NUM=5
log "Re-adding same PGP key (expecting 409 Conflict)..."
DUP_STATUS=$(curl -s -o "$WORK_DIR/dup-response.json" -w '%{http_code}' -X POST "$GATEWAY_URL/pgp-keys" \
    -H "Content-Type: application/json" \
    -H "X-Session-ID: $SESSION_ID" \
    -d "$(jq -n --rawfile public_key "$FIXTURES_DIR/pgp/test-public-key.asc" \
        --arg name "duplicate-attempt" \
        '{public_key: $public_key, name: $name}')")

if [ "$DUP_STATUS" != "409" ]; then
    log "Response body: $(cat "$WORK_DIR/dup-response.json")"
    step_fail "Duplicate PGP key add (expected 409, got $DUP_STATUS)"
fi
step_pass "Duplicate PGP key add rejected (409)"

# ── Step 6: Add malformed key -> 400 ─────────────────────────────────

STEP_NUM=6
log "Adding malformed PGP key (expecting 400 Bad Request)..."
MALFORMED_STATUS=$(curl -s -o "$WORK_DIR/malformed-response.json" -w '%{http_code}' -X POST "$GATEWAY_URL/pgp-keys" \
    -H "Content-Type: application/json" \
    -H "X-Session-ID: $SESSION_ID" \
    -d "$(jq -n --rawfile public_key "$WORK_DIR/malformed-key.txt" \
        --arg name "malformed-attempt" \
        '{public_key: $public_key, name: $name}')")

if [ "$MALFORMED_STATUS" != "400" ]; then
    log "Response body: $(cat "$WORK_DIR/malformed-response.json")"
    step_fail "Malformed PGP key add (expected 400, got $MALFORMED_STATUS)"
fi
step_pass "Malformed PGP key add rejected (400)"

# ── Step 7: Add private key block -> 400 ─────────────────────────────

STEP_NUM=7
log "Adding a PGP private key block (expecting 400 Bad Request)..."
PRIVATE_STATUS=$(curl -s -o "$WORK_DIR/private-response.json" -w '%{http_code}' -X POST "$GATEWAY_URL/pgp-keys" \
    -H "Content-Type: application/json" \
    -H "X-Session-ID: $SESSION_ID" \
    -d "$(jq -n --rawfile public_key "$WORK_DIR/private-key.asc" \
        --arg name "private-key-attempt" \
        '{public_key: $public_key, name: $name}')")

if [ "$PRIVATE_STATUS" != "400" ]; then
    log "Response body: $(cat "$WORK_DIR/private-response.json")"
    step_fail "Private key block add (expected 400, got $PRIVATE_STATUS)"
fi
step_pass "Private key block rejected (400)"

# ── Step 8: Add with an over-long name -> 400 ────────────────────────

STEP_NUM=8
log "Adding a key with a >255 character name (expecting 400 Bad Request)..."
LONG_NAME=$(printf 'a%.0s' $(seq 1 256))
LONGNAME_STATUS=$(curl -s -o "$WORK_DIR/longname-response.json" -w '%{http_code}' -X POST "$GATEWAY_URL/pgp-keys" \
    -H "Content-Type: application/json" \
    -H "X-Session-ID: $SESSION_ID" \
    -d "$(jq -n --rawfile public_key "$WORK_DIR/second-public-key.asc" \
        --arg name "$LONG_NAME" \
        '{public_key: $public_key, name: $name}')")

if [ "$LONGNAME_STATUS" != "400" ]; then
    log "Response body: $(cat "$WORK_DIR/longname-response.json")"
    step_fail "Over-long name add (expected 400, got $LONGNAME_STATUS)"
fi
step_pass "Over-long name rejected (400)"

# ── Step 9: Delete key -> 204, then list -> gone ─────────────────────

STEP_NUM=9
log "Deleting PGP key $KEY_ID..."
DELETE_STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$GATEWAY_URL/pgp-keys/$KEY_ID" \
    -H "X-Session-ID: $SESSION_ID")

if [ "$DELETE_STATUS" != "204" ]; then
    step_fail "Delete PGP key (expected 204, got $DELETE_STATUS)"
fi

log "Confirming key no longer appears in list..."
LIST_AFTER_DELETE=$(curl -sf "$GATEWAY_URL/pgp-keys" -H "X-Session-ID: $SESSION_ID")
STILL_PRESENT=$(echo "$LIST_AFTER_DELETE" | jq -r --arg fpr "$FINGERPRINT" '[.keys[] | select(.fingerprint == $fpr)] | length')
if [ "$STILL_PRESENT" != "0" ]; then
    step_fail "Delete PGP key (key still present in list after delete)"
fi
step_pass "Delete PGP key (204, removed from list)"

# ── Step 10: Delete unknown id -> 404 ────────────────────────────────

STEP_NUM=10
RANDOM_UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen | tr '[:upper:]' '[:lower:]')
log "Deleting a non-existent PGP key ($RANDOM_UUID, expecting 404)..."
NOTFOUND_STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$GATEWAY_URL/pgp-keys/$RANDOM_UUID" \
    -H "X-Session-ID: $SESSION_ID")

if [ "$NOTFOUND_STATUS" != "404" ]; then
    step_fail "Delete unknown PGP key (expected 404, got $NOTFOUND_STATUS)"
fi
step_pass "Delete unknown PGP key rejected (404)"

# ── Step 11: Re-add same key after soft-delete -> 200 ────────────────

STEP_NUM=11
log "Re-adding the same PGP key after soft-delete (expecting 200)..."
READD_RESPONSE=$(curl -sf -X POST "$GATEWAY_URL/pgp-keys" \
    -H "Content-Type: application/json" \
    -H "X-Session-ID: $SESSION_ID" \
    -d "$(jq -n --rawfile public_key "$FIXTURES_DIR/pgp/test-public-key.asc" \
        --arg name "e2e-test-key-readded" \
        '{public_key: $public_key, name: $name}')")

READD_FINGERPRINT=$(echo "$READD_RESPONSE" | jq -r '.fingerprint')
READD_ID=$(echo "$READD_RESPONSE" | jq -r '.id')

if [ -z "$READD_FINGERPRINT" ] || [ "$READD_FINGERPRINT" = "null" ]; then
    step_fail "Re-add PGP key after soft-delete (no fingerprint in response)"
fi
if [ "$READD_FINGERPRINT" != "$FINGERPRINT" ]; then
    step_fail "Re-add PGP key after soft-delete (fingerprint mismatch)"
fi
if [ "$READD_ID" = "$KEY_ID" ]; then
    step_fail "Re-add PGP key after soft-delete (expected a new row id, got the original)"
fi

log "Verifying 2 rows exist for fingerprint $FINGERPRINT (one removed, one active)..."
ROW_COUNT=$(docker exec postgres-test psql -U postgres -d caution_test -t -A -c "
SELECT count(*) FROM pgp_keys WHERE fingerprint = '$FINGERPRINT';
" 2>/dev/null | tr -d ' \n')
REMOVED_COUNT=$(docker exec postgres-test psql -U postgres -d caution_test -t -A -c "
SELECT count(*) FROM pgp_keys WHERE fingerprint = '$FINGERPRINT' AND removed_at IS NOT NULL;
" 2>/dev/null | tr -d ' \n')
ACTIVE_COUNT=$(docker exec postgres-test psql -U postgres -d caution_test -t -A -c "
SELECT count(*) FROM pgp_keys WHERE fingerprint = '$FINGERPRINT' AND removed_at IS NULL;
" 2>/dev/null | tr -d ' \n')

if [ "$ROW_COUNT" != "2" ] || [ "$REMOVED_COUNT" != "1" ] || [ "$ACTIVE_COUNT" != "1" ]; then
    step_fail "Soft-delete row check (expected 2 total / 1 removed / 1 active, got $ROW_COUNT / $REMOVED_COUNT / $ACTIVE_COUNT)"
fi
step_pass "Re-add after soft-delete (200, 2 DB rows: 1 removed + 1 active)"
