#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
#
# E2E coverage for the Phase 1 WebAuthn login changes. Covers only the pieces
# that are deterministic without a real authenticator ceremony:
#
#   1. Gateway health
#   2. /auth/login/begin with an UNKNOWN username -> 200 with EMPTY
#      allowCredentials (no 404 / no distinct shape = no enumeration oracle)
#   3. /auth/login/begin with no body -> 200 (broadcast default; fresh test DB
#      has no real credentials, so allowCredentials is empty)
#   4. username-claim gate: a placeholder-username session gets 403
#      {"error":"username_required"} on a protected route
#   5. claiming a username via POST /user/username succeeds (gate-exempt)
#   6. after claiming, the same protected route is no longer gated (200)
#   7. /auth/login/begin with a KNOWN username -> allowCredentials contains
#      only that user's own credential (scoped, not broadcast)
#   8. with LOGIN_ALLOW_BROADCAST=false, no-username begin -> empty
#      allowCredentials + conditional mediation (discoverable, not broadcast)
#   9. QR cross-device login: /auth/qr-login/begin with a KNOWN username,
#      then /auth/qr-login/authenticate -> allowCredentials scoped to that
#      user (same non-resident-key support as step 7, over the QR path)
#  10. QR cross-device login: /auth/qr-login/begin with an UNKNOWN username
#      -> /auth/qr-login/authenticate returns empty allowCredentials (decoy,
#      no enumeration oracle on the QR path either)
#  11. /auth/register/begin without a `username` field -> 422 (username is a
#      required field of RegisterBeginRequest; guards the CLI<->gateway
#      contract that the CLI must send one)
#  12. re-claiming a username on an already-claimed account -> 409 with the
#      "already set your username" text the CLI matches on to break its
#      claim-retry loop (distinct from the "name taken" 409)
#
# The full assertion round-trip (scoped/broadcast/discoverable finish) needs a
# WebAuthn authenticator and is covered by the manual Chrome-virtual-authenticator
# runbook, not here.
#
# Requires: make up-test (services with the e2e-testing-unsafe feature).

set -euo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8000}"
API_URL="${API_URL:-http://localhost:8080}"
DB_CONTAINER="${TEST_DB_HOST:-postgres-test}"
DB_NAME="${TEST_DB_NAME:-caution_test}"
STEP_NUM=0
STEPS_PASSED=0

log()  { echo "[webauthn-login] $*"; }
psql_q() { docker exec "$DB_CONTAINER" psql -U postgres -d "$DB_NAME" -tAc "$1"; }

step_pass() { STEPS_PASSED=$((STEPS_PASSED + 1)); echo "[webauthn-login] ✓ Step $STEP_NUM: $*"; }
step_fail() { echo "[webauthn-login] ✗ Step $STEP_NUM FAILED: $*" >&2; exit 1; }

# ── Step 1: Gateway health ───────────────────────────────────────────
STEP_NUM=1
for i in $(seq 1 30); do
    if curl -sf -o /dev/null "$GATEWAY_URL/health"; then break; fi
    [ "$i" = 30 ] && step_fail "gateway never became healthy"
    sleep 1
done
step_pass "Gateway health check"

# ── Step 2: unknown username -> 200 + empty allowCredentials ─────────
STEP_NUM=2
BODY=$(curl -s -w '\n%{http_code}' -X POST "$GATEWAY_URL/auth/login/begin" \
    -H 'Content-Type: application/json' \
    -d '{"username":"definitely-not-a-real-user-xyz"}')
CODE=$(echo "$BODY" | tail -1)
JSON=$(echo "$BODY" | sed '$d')
[ "$CODE" = 200 ] || step_fail "unknown username returned HTTP $CODE (want 200 — a 404 would be an enumeration oracle)"
N=$(echo "$JSON" | jq '.publicKey.allowCredentials | length')
[ "$N" = 0 ] || step_fail "unknown username leaked $N allowCredentials (want 0)"
echo "$JSON" | jq -e '.session' >/dev/null || step_fail "unknown username response missing session"
step_pass "Unknown username -> 200 with empty allowCredentials (no oracle)"

# ── Step 3: no body -> 200 (broadcast default, empty on fresh DB) ────
STEP_NUM=3
BODY=$(curl -s -w '\n%{http_code}' -X POST "$GATEWAY_URL/auth/login/begin")
CODE=$(echo "$BODY" | tail -1)
JSON=$(echo "$BODY" | sed '$d')
[ "$CODE" = 200 ] || step_fail "empty-body begin returned HTTP $CODE (want 200)"
echo "$JSON" | jq -e '.publicKey.challenge' >/dev/null || step_fail "empty-body begin response missing challenge"
step_pass "Empty-body begin -> 200 (broadcast default)"

# ── Step 4: placeholder session is gated (403 username_required) ─────
STEP_NUM=4
LOGIN=$(curl -sf -X POST "$GATEWAY_URL/auth/e2e-login" -H 'Content-Type: application/json')
SESSION_ID=$(echo "$LOGIN" | jq -r '.session_id')
USER_ID=$(echo "$LOGIN" | jq -r '.user_id')
[ -n "$SESSION_ID" ] && [ "$SESSION_ID" != null ] || step_fail "e2e-login returned no session"

# Force this user into the legacy placeholder state the gate defends.
psql_q "UPDATE users SET username_is_placeholder = true WHERE id = '$USER_ID';" >/dev/null

GATED=$(curl -s -w '\n%{http_code}' "$GATEWAY_URL/passkeys" -H "X-Session-ID: $SESSION_ID")
CODE=$(echo "$GATED" | tail -1)
JSON=$(echo "$GATED" | sed '$d')
[ "$CODE" = 403 ] || step_fail "placeholder session got HTTP $CODE on /passkeys (want 403)"
ERR=$(echo "$JSON" | jq -r '.error')
[ "$ERR" = username_required ] || step_fail "gate body was '$ERR' (want username_required)"
step_pass "Placeholder session -> 403 username_required on protected route"

# ── Step 5: claiming a username succeeds (gate-exempt route) ─────────
STEP_NUM=5
CLAIMED="claimed$(date +%s)$RANDOM"
CLAIM=$(curl -s -w '\n%{http_code}' -X POST "$GATEWAY_URL/user/username" \
    -H "X-Session-ID: $SESSION_ID" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$CLAIMED\"}")
CODE=$(echo "$CLAIM" | tail -1)
[ "$CODE" = 200 ] || step_fail "claim returned HTTP $CODE (want 200); body: $(echo "$CLAIM" | sed '$d')"
IS_PLACEHOLDER=$(psql_q "SELECT username_is_placeholder FROM users WHERE id = '$USER_ID';")
[ "$IS_PLACEHOLDER" = f ] || step_fail "user still marked placeholder after claim"
step_pass "Claim username -> 200 and user no longer placeholder"

# ── Step 6: gate lifts after claim (200) ────────────────────────────
STEP_NUM=6
AFTER=$(curl -s -o /dev/null -w '%{http_code}' "$GATEWAY_URL/passkeys" -H "X-Session-ID: $SESSION_ID")
[ "$AFTER" = 200 ] || step_fail "protected route still HTTP $AFTER after claim (want 200)"
step_pass "Protected route reachable (200) after claiming username"

# ── Step 7: scoped begin with a KNOWN username -> only that user's cred ──
STEP_NUM=7
# The e2e user's dummy credential (from create_e2e_user) stores a placeholder
# public_key that isn't valid SecurityKey JSON — fine for session-join tests,
# but begin_login_handler's scoped path deserializes it for real to build the
# challenge, so it 500s. Swap in a real (but unrelated/non-secret) SecurityKey
# JSON fixture captured from a genuine dev registration; begin only needs a
# structurally valid public key, never touches the authenticator itself.
FIXTURE_PUBLIC_KEY='{"cred":{"cred_id":"KuSaAl0uO3_g-D5b5s5PUrHdgck","cred":{"type_":"ES256","key":{"EC_EC2":{"curve":"SECP256R1","x":"VTSRkyIs9sASIgLB2vWSu6xFyAvGf9lQ6GSHgiAmJlQ","y":"UFAsQBox-mvdfu4qaZYEwPKA0bmHWELgEfIUol8H0eQ"}}},"counter":0,"transports":null,"user_verified":true,"backup_eligible":true,"backup_state":true,"registration_policy":"preferred","extensions":{"cred_protect":"Ignored","hmac_create_secret":"NotRequested","appid":"NotRequested","cred_props":"Ignored"},"attestation":{"data":"None","metadata":"None"},"attestation_format":"none"}}'
psql_q "UPDATE fido2_credentials SET public_key = '$FIXTURE_PUBLIC_KEY'::bytea WHERE user_id = '$USER_ID';" >/dev/null
SCOPED_USERNAME=$(psql_q "SELECT username FROM users WHERE id = '$USER_ID';")
BODY=$(curl -s -w '\n%{http_code}' -X POST "$GATEWAY_URL/auth/login/begin" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$SCOPED_USERNAME\"}")
CODE=$(echo "$BODY" | tail -1)
JSON=$(echo "$BODY" | sed '$d')
[ "$CODE" = 200 ] || step_fail "known-username begin returned HTTP $CODE (want 200)"
N=$(echo "$JSON" | jq '.publicKey.allowCredentials | length')
[ "$N" = 1 ] || step_fail "known-username begin returned $N allowCredentials (want exactly 1, this user's own credential)"
step_pass "Known username -> 200 with exactly that user's credential (scoped, not broadcast)"

# ── Step 8: flag off -> no-username begin returns empty allowCredentials ─
# plus conditional mediation. Restart the test gateway with the flag flipped,
# then restore the default (true) so the container is left as up-test made it.
STEP_NUM=8
GATEWAY_EXTRA_ENV="-e LOGIN_ALLOW_BROADCAST=false" make run-gateway-test >/dev/null
for i in $(seq 1 30); do
    if curl -sf -o /dev/null "$GATEWAY_URL/health"; then break; fi
    [ "$i" = 30 ] && step_fail "gateway never became healthy after LOGIN_ALLOW_BROADCAST=false restart"
    sleep 1
done
BODY=$(curl -s -w '\n%{http_code}' -X POST "$GATEWAY_URL/auth/login/begin")
CODE=$(echo "$BODY" | tail -1)
JSON=$(echo "$BODY" | sed '$d')
[ "$CODE" = 200 ] || step_fail "flag-off no-username begin returned HTTP $CODE (want 200)"
N=$(echo "$JSON" | jq '.publicKey.allowCredentials | length')
[ "$N" = 0 ] || step_fail "flag-off no-username begin leaked $N allowCredentials (want 0 — broadcast must be off)"
MEDIATION=$(echo "$JSON" | jq -r '.mediation')
[ "$MEDIATION" = conditional ] || step_fail "flag-off no-username begin mediation was '$MEDIATION' (want conditional)"
step_pass "LOGIN_ALLOW_BROADCAST=false -> no-username begin is discoverable (empty allowCredentials, conditional mediation)"

# ── Step 9: QR login, known username -> scoped allowCredentials ──────
STEP_NUM=9
QR_BEGIN=$(curl -s -w '\n%{http_code}' -X POST "$GATEWAY_URL/auth/qr-login/begin" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$SCOPED_USERNAME\"}")
CODE=$(echo "$QR_BEGIN" | tail -1)
JSON=$(echo "$QR_BEGIN" | sed '$d')
[ "$CODE" = 200 ] || step_fail "qr-login/begin with known username returned HTTP $CODE (want 200)"
QR_TOKEN=$(echo "$JSON" | jq -r '.token')
[ -n "$QR_TOKEN" ] && [ "$QR_TOKEN" != null ] || step_fail "qr-login/begin response missing token"

BODY=$(curl -s -w '\n%{http_code}' -X POST "$GATEWAY_URL/auth/qr-login/authenticate" \
    -H 'Content-Type: application/json' \
    -d "{\"token\":\"$QR_TOKEN\"}")
CODE=$(echo "$BODY" | tail -1)
JSON=$(echo "$BODY" | sed '$d')
[ "$CODE" = 200 ] || step_fail "qr-login/authenticate (known username) returned HTTP $CODE (want 200)"
N=$(echo "$JSON" | jq '.publicKey.allowCredentials | length')
[ "$N" = 1 ] || step_fail "qr-login/authenticate (known username) returned $N allowCredentials (want exactly 1)"
step_pass "QR login with known username -> scoped allowCredentials (non-resident key support over QR)"

# ── Step 10: QR login, unknown username -> decoy (no oracle) ─────────
STEP_NUM=10
QR_BEGIN=$(curl -s -w '\n%{http_code}' -X POST "$GATEWAY_URL/auth/qr-login/begin" \
    -H 'Content-Type: application/json' \
    -d '{"username":"definitely-not-a-real-user-xyz"}')
CODE=$(echo "$QR_BEGIN" | tail -1)
JSON=$(echo "$QR_BEGIN" | sed '$d')
[ "$CODE" = 200 ] || step_fail "qr-login/begin with unknown username returned HTTP $CODE (want 200)"
QR_TOKEN=$(echo "$JSON" | jq -r '.token')

BODY=$(curl -s -w '\n%{http_code}' -X POST "$GATEWAY_URL/auth/qr-login/authenticate" \
    -H 'Content-Type: application/json' \
    -d "{\"token\":\"$QR_TOKEN\"}")
CODE=$(echo "$BODY" | tail -1)
JSON=$(echo "$BODY" | sed '$d')
[ "$CODE" = 200 ] || step_fail "qr-login/authenticate (unknown username) returned HTTP $CODE (want 200 — a distinct shape would be an enumeration oracle)"
N=$(echo "$JSON" | jq '.publicKey.allowCredentials | length')
[ "$N" = 0 ] || step_fail "qr-login/authenticate (unknown username) leaked $N allowCredentials (want 0)"
step_pass "QR login with unknown username -> decoy discoverable challenge (no oracle)"

make run-gateway-test >/dev/null
for i in $(seq 1 30); do
    if curl -sf -o /dev/null "$GATEWAY_URL/health"; then break; fi
    [ "$i" = 30 ] && step_fail "gateway never became healthy after restoring default flag"
    sleep 1
done

# ── Step 11: register/begin requires a username field ────────────────
STEP_NUM=11
# Guards the CLI<->gateway contract: RegisterBeginRequest requires `username`
# (no Option/default), so a begin body without it must be rejected by the Json
# extractor (422), never silently accepted. If this regresses, `caution
# register` (which now sends the field) would be the only thing keeping it honest.
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GATEWAY_URL/auth/register/begin" \
    -H 'Content-Type: application/json' -d '{"alpha_code":"nonexistent-code"}')
[ "$CODE" = 422 ] || step_fail "register/begin without username returned HTTP $CODE (want 422 — username is required)"
step_pass "register/begin without username -> 422 (username is a required field)"

# ── Step 12: re-claim on an already-claimed account -> 409 (loop guard) ──
STEP_NUM=12
# The user from steps 4-6 already claimed a username. A second claim must
# return 409 with the "already set your username" text that
# claim_username_interactively (cli/src/lib.rs) matches on to STOP its retry
# loop — otherwise the CLI would spin forever reprompting for a name that can
# never succeed. This is a different 409 from "name taken" (which should loop).
RECLAIM=$(curl -s -w '\n%{http_code}' -X POST "$GATEWAY_URL/user/username" \
    -H "X-Session-ID: $SESSION_ID" -H 'Content-Type: application/json' \
    -d '{"username":"reclaimattempt"}')
CODE=$(echo "$RECLAIM" | tail -1)
JSON=$(echo "$RECLAIM" | sed '$d')
[ "$CODE" = 409 ] || step_fail "re-claim on already-claimed account returned HTTP $CODE (want 409); body: $JSON"
echo "$JSON" | grep -qi "already set your username" \
    || step_fail "re-claim body '$JSON' lacks the 'already set your username' text the CLI matches on"
step_pass "Re-claim on already-claimed account -> 409 'already set your username' (CLI loop guard)"

echo ""
log "All $STEPS_PASSED steps passed ✓"
