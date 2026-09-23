#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
#
# E2E coverage for the admin-triggered WebAuthn credential reset flow:
#
#   1. Wait for gateway health
#   2. Seed a test user with a known email (no credentials yet)
#   3. Trigger reset via the internal API endpoint
#   4. Verify a token_hash row was inserted into webauthn_reset_tokens
#   5. Verify the email service captured a webauthn_reset email with a reset URL
#   6. Verify /auth/reset/begin rejects an expired token (insert known hash, expired)
#   7. Verify /auth/reset/begin rejects an already-used token
#   8. Verify /auth/reset/begin rejects a nonexistent token
#   9. Verify the public gateway does NOT route /internal/webauthn/reset (404/405)
#  10. Verify missing secret returns 401
#  11. Verify nonexistent user returns 404
#  12. Verify gateway serves /reset SPA route (200, not 404)
#
# The full redeem path (token → WebAuthn ceremony → new passkey) requires a real
# authenticator and is covered by test_webauthn_roundtrip.sh, not here.
#
# Requires: make up-test (services with the e2e-testing-unsafe feature).

set -euo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8000}"
API_URL="${API_URL:-http://127.0.0.1:8080}"
EMAIL_EXTERNAL_URL="${EMAIL_EXTERNAL_URL:-http://localhost:8082}"
DB_CONTAINER="${TEST_DB_HOST:-postgres-test}"
DB_NAME="${TEST_DB_NAME:-caution_test}"
INTERNAL_SECRET="${INTERNAL_SERVICE_SECRET:-$(docker exec api printenv INTERNAL_SERVICE_SECRET)}"
STEP_NUM=0
TOTAL_STEPS=12

log()  { echo "[webauthn-reset] $*"; }
fail() { STEP_NUM=$((STEP_NUM + 1)); echo "[webauthn-reset] ✗ step $STEP_NUM FAILED: $*" >&2; exit 1; }
pass() { STEP_NUM=$((STEP_NUM + 1)); log "✓ step $STEP_NUM: $*"; }
psql_q() { docker exec "$DB_CONTAINER" psql -U postgres -d "$DB_NAME" -qtAc "$1"; }

# ── Step 1: gateway health ───────────────────────────────────────────
for i in $(seq 1 30); do
    curl -sf -o /dev/null "$GATEWAY_URL/health" && break
    [ "$i" = 30 ] && fail "gateway never became healthy"
    sleep 1
done
pass "gateway healthy"

# ── Step 2: seed a test user with email ──────────────────────────────
STAMP=$(date +%s)
USERNAME="resettest$STAMP"
EMAIL="resettest${STAMP}@example.com"
USER_ID=$(psql_q "INSERT INTO users (username, email, is_active) VALUES ('$USERNAME', '$EMAIL', true) RETURNING id;")
[ -n "$USER_ID" ] || fail "failed to seed test user"
pass "seeded user id=$USER_ID username=$USERNAME email=$EMAIL"

# ── Step 3: trigger reset via internal endpoint ──────────────────────
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$API_URL/internal/webauthn/reset" \
    -H "Content-Type: application/json" \
    -H "X-Internal-Service-Secret: $INTERNAL_SECRET" \
    -d "{\"user_id\": \"$USER_ID\"}")
[ "$RESPONSE" = "200" ] || fail "reset endpoint returned $RESPONSE, expected 200"
pass "internal reset endpoint returned 200"

# ── Step 4: verify token_hash row was inserted ───────────────────────
TOKEN_COUNT=$(psql_q "SELECT COUNT(*) FROM webauthn_reset_tokens WHERE user_id = '$USER_ID';")
[ "$TOKEN_COUNT" -ge 1 ] || fail "no reset token found for user $USER_ID"
pass "reset token_hash row inserted (count=$TOKEN_COUNT)"

# ── Step 5: verify email was sent with a reset URL ───────────────────
SENT_EMAILS=$(curl -sf "$EMAIL_EXTERNAL_URL/sent?template=webauthn_reset")
echo "$SENT_EMAILS" | grep -q "webauthn_reset" || fail "no webauthn_reset email captured"
echo "$SENT_EMAILS" | grep -q "reset_url" || fail "email data missing reset_url field"
pass "webauthn_reset email captured with reset_url in test-mode sent-emails"

# ── Step 6: expired token rejected ───────────────────────────────────
# Insert a row with a known token_hash and already-expired timestamp.
# The handler calls hex::decode(token_hex) first, so the token must be valid hex.
# We store SHA-256 of the decoded bytes as the token_hash.
EXPIRED_RAW="aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb"
EXPIRED_HASH=$(echo -n "$EXPIRED_RAW" | xxd -r -p | sha256sum | cut -d' ' -f1)
psql_q "INSERT INTO webauthn_reset_tokens (token_hash, user_id, expires_at) VALUES ('$EXPIRED_HASH', '$USER_ID', NOW() - INTERVAL '1 hour');" >/dev/null

EXPIRED_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$GATEWAY_URL/auth/reset/begin" \
    -H "Content-Type: application/json" \
    -d "{\"token\": \"$EXPIRED_RAW\"}")
[ "$EXPIRED_RESPONSE" != "200" ] || fail "expired token should not return 200"
pass "expired token rejected (status=$EXPIRED_RESPONSE)"

# ── Step 7: used token rejected ───────────────────────────────────────
# Insert a valid but already-used token
USED_RAW="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
USED_HASH=$(echo -n "$USED_RAW" | xxd -r -p | sha256sum | cut -d' ' -f1)
psql_q "INSERT INTO webauthn_reset_tokens (token_hash, user_id, expires_at, used_at) VALUES ('$USED_HASH', '$USER_ID', NOW() + INTERVAL '24 hours', NOW());" >/dev/null

USED_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$GATEWAY_URL/auth/reset/begin" \
    -H "Content-Type: application/json" \
    -d "{\"token\": \"$USED_RAW\"}")
[ "$USED_RESPONSE" != "200" ] || fail "used token should not return 200"
pass "already-used token rejected (status=$USED_RESPONSE)"

# ── Step 8: nonexistent token rejected ────────────────────────────────
FAKE_RAW="cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe"
FAKE_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$GATEWAY_URL/auth/reset/begin" \
    -H "Content-Type: application/json" \
    -d "{\"token\": \"$FAKE_RAW\"}")
[ "$FAKE_RESPONSE" != "200" ] || fail "nonexistent token should not return 200"
pass "nonexistent token rejected (status=$FAKE_RESPONSE)"

# ── Step 9: gateway does NOT route /internal/* ───────────────────────
PUBLIC_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$GATEWAY_URL/internal/webauthn/reset" \
    -H "Content-Type: application/json" \
    -d "{\"user_id\": \"$USER_ID\"}")
# ServeDir rejects POST to an unmatched route with 405; either response denies access.
[ "$PUBLIC_RESPONSE" = "404" ] || [ "$PUBLIC_RESPONSE" = "405" ] || fail "gateway should not route /internal/* (got $PUBLIC_RESPONSE)"
pass "public gateway denies /internal/webauthn/reset (status=$PUBLIC_RESPONSE)"

# ── Step 10: missing secret returns 401 ──────────────────────────────
NO_SECRET_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$API_URL/internal/webauthn/reset" \
    -H "Content-Type: application/json" \
    -d "{\"user_id\": \"$USER_ID\"}")
[ "$NO_SECRET_RESPONSE" = "401" ] || fail "missing secret should return 401 (got $NO_SECRET_RESPONSE)"
pass "missing internal secret returns 401"

# ── Step 11: nonexistent user returns 404 ────────────────────────────
FAKE_ID="00000000-0000-0000-0000-000000000000"
NOT_FOUND_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$API_URL/internal/webauthn/reset" \
    -H "Content-Type: application/json" \
    -H "X-Internal-Service-Secret: $INTERNAL_SECRET" \
    -d "{\"user_id\": \"$FAKE_ID\"}")
[ "$NOT_FOUND_RESPONSE" = "404" ] || fail "nonexistent user should return 404 (got $NOT_FOUND_RESPONSE)"
pass "nonexistent user returns 404"

# ── Step 12: gateway serves /reset SPA route (200) ───────────────────
RESET_ROUTE_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
    "$GATEWAY_URL/reset#deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
[ "$RESET_ROUTE_RESPONSE" = "200" ] || fail "gateway /reset SPA route returned $RESET_ROUTE_RESPONSE, expected 200"
pass "gateway serves /reset SPA route (status=$RESET_ROUTE_RESPONSE)"

# ── Cleanup ───────────────────────────────────────────────────────────
psql_q "DELETE FROM webauthn_reset_tokens WHERE user_id = '$USER_ID';" >/dev/null 2>&1 || true
psql_q "DELETE FROM users WHERE id = '$USER_ID';" >/dev/null 2>&1 || true

log ""
log " RESULT: $STEP_NUM/$TOTAL_STEPS steps passed"
[ "$STEP_NUM" -eq "$TOTAL_STEPS" ] || fail "expected $TOTAL_STEPS steps but only completed $STEP_NUM"
log "✓ ALL PASS"
