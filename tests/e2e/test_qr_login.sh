#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
#
# E2E test for QR login token handling (issues #336 and #366 — split
# requester/requestee tokens, consent context, and one-shot session consumption).
# Requires: make up-test (gateway on :8000, postgres-test on caution_test).
#
# Exercises the gateway HTTP surface directly (no authenticator needed):
#   1. begin issues distinct requester/requestee tokens; URL carries requestee
#   2. context exposes only consent data and handles each token state
#   3. authenticate requires explicit confirmation without mutating the token
#   4. authenticate rejects the requester token (split boundary)
#   5. status: a completed token is returned once, then consumed (one-shot)
#   6. status: the requestee token cannot poll the session
#   7. retry-safety: a failed session fetch does NOT consume the session id

set -uo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8000}"
DB_HOST="${TEST_DB_HOST:-postgres-test}"
DB_NAME="${TEST_DB_NAME:-caution_test}"
STEPS_PASSED=0
STEPS_FAILED=0

psql_c() { docker exec -i "$DB_HOST" psql -U postgres -d "$DB_NAME" -t -A -c "$1"; }

pass() { STEPS_PASSED=$((STEPS_PASSED + 1)); echo "[PASS] $1"; }
fail() { STEPS_FAILED=$((STEPS_FAILED + 1)); echo "[FAIL] $1" >&2; }

cleanup() {
    psql_c "DELETE FROM qr_login_tokens WHERE token LIKE 'e2e-qr-%';" >/dev/null 2>&1 || true
    # Restore the table if a fault-injection step aborted mid-way.
    psql_c "ALTER TABLE IF EXISTS auth_sessions_e2ebak RENAME TO auth_sessions;" >/dev/null 2>&1 || true
    echo ""
    echo "===================================="
    echo "  QR login e2e: $STEPS_PASSED passed, $STEPS_FAILED failed"
    echo "===================================="
}
trap cleanup EXIT

echo "[e2e] waiting for gateway..."
for _ in $(seq 1 30); do
    curl -sf "$GATEWAY_URL/health" >/dev/null 2>&1 && break
    sleep 1
done

# ── 1. begin: distinct tokens, requestee in URL ──────────────────────
BEGIN=$(curl -s -X POST "$GATEWAY_URL/auth/qr-login/begin")
REQUESTER=$(echo "$BEGIN" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
URL=$(echo "$BEGIN" | sed -n 's/.*"url":"\([^"]*\)".*/\1/p')
REQUESTEE=$(echo "$URL" | sed -n 's/.*token=\([^"&]*\).*/\1/p')
VERIFICATION_CODE=$(echo "$BEGIN" | sed -n 's/.*"verification_code":"\([0-9][0-9]*\)".*/\1/p')

if [ -n "$REQUESTER" ] && [ -n "$REQUESTEE" ] && [ "$REQUESTER" != "$REQUESTEE" ] \
    && echo "$VERIFICATION_CODE" | grep -Eq '^[0-9]{6}$'; then
    pass "begin issues distinct requester and requestee tokens"
else
    fail "begin response missing valid tokens/code: $BEGIN"
fi

# ── 2. context: public consent-only data and token states ─────────────
CONTEXT_BEFORE=$(psql_c "SELECT status || '|' || COALESCE(auth_challenge_key,'<null>') || '|' || COALESCE(browser_ip_address,'<null>') FROM qr_login_tokens WHERE token='$REQUESTER';")
CONTEXT=$(curl -s -X POST "$GATEWAY_URL/auth/qr-login/context" \
    -H 'Content-Type: application/json' -d "{\"token\":\"$REQUESTEE\"}")
CONTEXT_AFTER=$(psql_c "SELECT status || '|' || COALESCE(auth_challenge_key,'<null>') || '|' || COALESCE(browser_ip_address,'<null>') FROM qr_login_tokens WHERE token='$REQUESTER';")
if echo "$CONTEXT" | grep -q "\"verification_code\":\"$VERIFICATION_CODE\"" \
    && echo "$CONTEXT" | grep -q '"created_at":"' \
    && echo "$CONTEXT" | grep -q '"expires_at":"' \
    && ! echo "$CONTEXT" | grep -Eq '"(token|url|username|session_id|ip_address|browser_ip_address|auth_challenge_key)"' \
    && [ "$CONTEXT_BEFORE" = "$CONTEXT_AFTER" ]; then
    pass "context returns only the pending consent data"
else
    fail "unexpected/mutating context response: $CONTEXT"
fi

CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GATEWAY_URL/auth/qr-login/context" \
    -H 'Content-Type: application/json' -d '{"token":"unknown"}')
[ "$CODE" = "404" ] && pass "context returns 404 for an unknown token" \
                    || fail "unknown context returned $CODE, expected 404"

CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GATEWAY_URL/auth/qr-login/context" \
    -H 'Content-Type: application/json' -d "{\"token\":\"$REQUESTER\"}")
[ "$CODE" = "404" ] && pass "requester token cannot read requestee context" \
                    || fail "requester context returned $CODE, expected 404"

for STATE in authenticated completed; do
    psql_c "UPDATE qr_login_tokens SET status='$STATE' WHERE token='$REQUESTER';" >/dev/null
    CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GATEWAY_URL/auth/qr-login/context" \
        -H 'Content-Type: application/json' -d "{\"token\":\"$REQUESTEE\"}")
    [ "$CODE" = "409" ] && pass "context returns 409 for $STATE token" \
                        || fail "$STATE context returned $CODE, expected 409"
done
psql_c "UPDATE qr_login_tokens SET status='pending', verification_code=NULL WHERE token='$REQUESTER';" >/dev/null
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GATEWAY_URL/auth/qr-login/context" \
    -H 'Content-Type: application/json' -d "{\"token\":\"$REQUESTEE\"}")
[ "$CODE" = "409" ] && pass "context returns 409 when the code is unavailable" \
                    || fail "null-code context returned $CODE, expected 409"
psql_c "UPDATE qr_login_tokens SET verification_code='$VERIFICATION_CODE', expires_at=NOW() - INTERVAL '1 second' WHERE token='$REQUESTER';" >/dev/null
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GATEWAY_URL/auth/qr-login/context" \
    -H 'Content-Type: application/json' -d "{\"token\":\"$REQUESTEE\"}")
[ "$CODE" = "410" ] && pass "context returns 410 for an expired token" \
                    || fail "expired context returned $CODE, expected 410"
psql_c "UPDATE qr_login_tokens SET expires_at=NOW() + INTERVAL '3 minutes' WHERE token='$REQUESTER';" >/dev/null

# ── 3. authenticate must be explicitly confirmed and read-only otherwise ─
BEFORE=$(psql_c "SELECT status || '|' || COALESCE(auth_challenge_key,'<null>') || '|' || COALESCE(browser_ip_address,'<null>') FROM qr_login_tokens WHERE token='$REQUESTER';")
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GATEWAY_URL/auth/qr-login/authenticate" \
    -H 'Content-Type: application/json' -d "{\"token\":\"$REQUESTEE\"}")
AFTER=$(psql_c "SELECT status || '|' || COALESCE(auth_challenge_key,'<null>') || '|' || COALESCE(browser_ip_address,'<null>') FROM qr_login_tokens WHERE token='$REQUESTER';")
if [ "$CODE" = "400" ] && [ "$BEFORE" = "$AFTER" ]; then
    pass "unconfirmed authenticate returns 400 without mutating the token"
else
    fail "unconfirmed authenticate: http=$CODE before='$BEFORE' after='$AFTER'"
fi

# ── 4. authenticate rejects the requester token (split boundary) ─────
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GATEWAY_URL/auth/qr-login/authenticate" \
    -H 'Content-Type: application/json' -d "{\"token\":\"$REQUESTER\",\"confirmed\":true}")
if [ "$CODE" = "404" ]; then
    pass "authenticate rejects requester token (404)"
else
    fail "authenticate with requester token returned $CODE, expected 404"
fi

# Seed a completed token with a real auth session so status returns expires_at.
CRED=$(psql_c "SELECT encode(credential_id, 'hex') FROM fido2_credentials LIMIT 1;")
REQ=e2e-qr-req
REE=e2e-qr-ree
SID=e2e-qr-sid
psql_c "DELETE FROM qr_login_tokens WHERE token='$REQ';" >/dev/null
if [ -n "$CRED" ]; then
    psql_c "INSERT INTO auth_sessions (session_id, credential_id, expires_at)
            VALUES ('$SID', decode('$CRED','hex'), NOW() + INTERVAL '1 hour')
            ON CONFLICT (session_id) DO UPDATE SET expires_at = EXCLUDED.expires_at;" >/dev/null
    EXPECT_EXPIRES=1
else
    EXPECT_EXPIRES=0  # no credentials registered; session fetch returns None
fi
psql_c "INSERT INTO qr_login_tokens (token, requestee_token, status, session_id, expires_at)
        VALUES ('$REQ','$REE','completed','$SID', NOW() + INTERVAL '1 hour');" >/dev/null

# ── 5. status: session returned once, then consumed (one-shot) ───────
POLL1=$(curl -s "$GATEWAY_URL/auth/qr-login/status?token=$REQ")
if echo "$POLL1" | grep -q "\"session_id\":\"$SID\""; then
    pass "first status poll returns the session id"
else
    fail "first poll missing session id: $POLL1"
fi
if [ "$EXPECT_EXPIRES" = "1" ] && ! echo "$POLL1" | grep -q '"expires_at":"2'; then
    fail "first poll missing expires_at for a real session: $POLL1"
fi

POLL2=$(curl -s "$GATEWAY_URL/auth/qr-login/status?token=$REQ")
if echo "$POLL2" | grep -q '"status":"completed"' && ! echo "$POLL2" | grep -q 'session_id'; then
    pass "second status poll consumed the session (one-shot)"
else
    fail "second poll should be completed without session id: $POLL2"
fi
DB_SID=$(psql_c "SELECT COALESCE(session_id,'<null>') FROM qr_login_tokens WHERE token='$REQ';")
[ "$DB_SID" = "<null>" ] && pass "session id nulled in db after consume" \
                         || fail "session id not nulled in db: '$DB_SID'"

# ── 6. status: requestee token cannot poll the session ───────────────
POLL_REE=$(curl -s "$GATEWAY_URL/auth/qr-login/status?token=$REE")
if echo "$POLL_REE" | grep -q '"status":"not_found"'; then
    pass "requestee token cannot poll status (not_found)"
else
    fail "requestee token poll should be not_found: $POLL_REE"
fi

# ── 7. retry-safety: a failed session fetch must NOT consume ─────────
psql_c "UPDATE qr_login_tokens SET status='completed', session_id='$SID' WHERE token='$REQ';" >/dev/null
psql_c "ALTER TABLE auth_sessions RENAME TO auth_sessions_e2ebak;" >/dev/null
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$GATEWAY_URL/auth/qr-login/status?token=$REQ")
DB_SID=$(psql_c "SELECT COALESCE(session_id,'<null>') FROM qr_login_tokens WHERE token='$REQ';")
psql_c "ALTER TABLE auth_sessions_e2ebak RENAME TO auth_sessions;" >/dev/null
if [ "$CODE" = "500" ] && [ "$DB_SID" = "$SID" ]; then
    pass "failed session fetch returns 500 without consuming the session id"
else
    fail "retry-safety: http=$CODE db_session='$DB_SID' (expected 500 and session intact)"
fi
POLL_RECOVER=$(curl -s "$GATEWAY_URL/auth/qr-login/status?token=$REQ")
if echo "$POLL_RECOVER" | grep -q "\"session_id\":\"$SID\""; then
    pass "session recovered on the poll after the transient failure"
else
    fail "session not recovered after failure: $POLL_RECOVER"
fi

[ "$STEPS_FAILED" -eq 0 ]
