#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
#
# E2E coverage for the Phase 1 WebAuthn login changes. Covers only the pieces
# that are deterministic without a real authenticator ceremony:
#
#   1. Gateway health
#   2. /auth/login/begin with an UNKNOWN username -> 200 with a NON-EMPTY
#      HMAC decoy allowCredentials + no mediation (indistinguishable from a
#      real scoped challenge = no enumeration oracle)
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
#      -> /auth/qr-login/authenticate returns a NON-EMPTY HMAC decoy
#      allowCredentials + no mediation (no enumeration oracle on the QR path either)
#  11. /auth/register/begin without a `username` field -> 422 (username is a
#      required field of RegisterBeginRequest; guards the CLI<->gateway
#      contract that the CLI must send one)
#  12. re-claiming a username on an already-claimed account -> 409 with the
#      "already set your username" text the CLI matches on to break its
#      claim-retry loop (distinct from the "name taken" 409)
#  13. HMAC decoys (Phase 2): three /auth/login/begin calls — known username
#      WITH credentials, known username with ZERO credentials, and a
#      nonexistent username — ALL return a NON-EMPTY allowCredentials and NO
#      mediation. Existence is no longer observable from begin at all (this
#      supersedes the old "only the empty cases are equalized" assertion).
#  14. Decoy stability: two /auth/login/begin calls for the SAME nonexistent
#      username return the byte-identical synthetic allowCredentials id set
#      (deterministic HMAC decoys, not per-call randomness).
#  15. Finish-side oracle closure: /auth/login/finish against an invalid
#      session, a decoy (nonexistent-username) challenge, and a real-user
#      challenge with a garbage assertion ALL return the IDENTICAL 401
#      {"error":"authentication_failed"} body — collapsing every
#      credential-verification failure into one shape.
#  16. POST /user/username with an INVALID username -> 400 (validation runs
#      before the claim logic). Pins the contract the CLI's claim loop relies on:
#      400 is a retryable validation error (reprompt), distinct from the 409
#      taken/already-claimed cases.
#  17. QR status lifecycle: a fresh /auth/qr-login/begin token queried via
#      GET /auth/qr-login/status -> 200 status "pending" with no session_id
#      (the desktop poll's starting state, before any phone authenticates).
#  18. QR status oracle: GET /auth/qr-login/status with an UNKNOWN token -> 200
#      status "not_found" (row absence is derived, NOT surfaced as a 404 — a
#      distinct status/HTTP shape would let an attacker probe token validity).
#  19. Rate limiting: the per-IP scoped-begin bucket (20/60s) returns 429 once
#      exceeded on the username-present /auth/login/begin path, while the
#      no-username (discoverable/broadcast) path is unaffected by that bucket.
#      The per-username->decoy fail-safe (10/60s) is NOT exercised here: it
#      can't be isolated from the per-IP cap using a single test-runner IP, so
#      it's covered by the Rust unit tests in handlers.rs's login_begin_tests.
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

# ── Step 2: unknown username -> 200 + non-empty HMAC decoy (no oracle) ─────────
# The scoped begin path now synthesizes a plausible non-empty allowCredentials for
# any unknown/zero-cred username (no mediation), so an unknown name is
# indistinguishable from a real one. See Step 13 for the full three-way check.
STEP_NUM=2
BODY=$(curl -s -w '\n%{http_code}' -X POST "$GATEWAY_URL/auth/login/begin" \
    -H 'Content-Type: application/json' \
    -d '{"username":"definitely-not-a-real-user-xyz"}')
CODE=$(echo "$BODY" | tail -1)
JSON=$(echo "$BODY" | sed '$d')
[ "$CODE" = 200 ] || step_fail "unknown username returned HTTP $CODE (want 200 — a 404 would be an enumeration oracle)"
N=$(echo "$JSON" | jq '.publicKey.allowCredentials | length')
[ "$N" -gt 0 ] || step_fail "unknown username returned $N allowCredentials (want > 0 — a decoy, not an empty list)"
MEDIATION=$(echo "$JSON" | jq -r '.mediation')
[ "$MEDIATION" = null ] || step_fail "unknown username begin mediation was '$MEDIATION' (want null — must match the real scoped shape)"
echo "$JSON" | jq -e '.session' >/dev/null || step_fail "unknown username response missing session"
step_pass "Unknown username -> 200 with non-empty HMAC decoy, no mediation (no oracle)"

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
# Capture the real registered credential id so later steps (13a) can prove a
# scoped response actually carries THIS user's credential, not merely a
# non-empty (possibly decoy) list.
REAL_CRED_ID=$(echo "$JSON" | jq -r '.publicKey.allowCredentials[0].id')
[ -n "$REAL_CRED_ID" ] && [ "$REAL_CRED_ID" != null ] || step_fail "known-username begin missing allowCredentials[0].id"
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

# ── Step 10: QR login, unknown username -> non-empty HMAC decoy (no oracle) ─────
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
[ "$N" -gt 0 ] || step_fail "qr-login/authenticate (unknown username) returned $N allowCredentials (want > 0 — a decoy, not an empty list)"
MEDIATION=$(echo "$JSON" | jq -r '.mediation')
[ "$MEDIATION" = null ] || step_fail "qr-login/authenticate (unknown username) mediation was '$MEDIATION' (want null)"
step_pass "QR login with unknown username -> non-empty HMAC decoy, no mediation (no oracle)"

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

# ── Step 13: HMAC decoys -> known-with-creds/known-zero-creds/unknown all
# return non-empty allowCredentials + no mediation (Phase 2, closes the oracle
# left open by the old empty-case-only equalization) ─────────────────────────
STEP_NUM=13

# (a) known username WITH credentials (still has the FIXTURE_PUBLIC_KEY
# credential planted in step 7).
BODY=$(curl -s -w '\n%{http_code}' -X POST "$GATEWAY_URL/auth/login/begin" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$SCOPED_USERNAME\"}")
CODE=$(echo "$BODY" | tail -1)
JSON=$(echo "$BODY" | sed '$d')
[ "$CODE" = 200 ] || step_fail "known-with-creds begin returned HTTP $CODE (want 200)"
N_A=$(echo "$JSON" | jq '.publicKey.allowCredentials | length')
[ "$N_A" -gt 0 ] || step_fail "known-with-creds begin returned $N_A allowCredentials (want > 0)"
# A decoy is also non-empty, so length alone can't tell a real scoped
# response from a decoy. Require the REAL credential id (captured in step 7)
# to actually be present in this response.
IDS_A=$(echo "$JSON" | jq -r '.publicKey.allowCredentials[].id')
echo "$IDS_A" | grep -qxF "$REAL_CRED_ID" \
    || step_fail "known-with-creds begin allowCredentials ids ($IDS_A) do not contain the real registered credential id ($REAL_CRED_ID) -- indistinguishable from a decoy"
MEDIATION_A=$(echo "$JSON" | jq -r '.mediation')
[ "$MEDIATION_A" = null ] || step_fail "known-with-creds begin mediation was '$MEDIATION_A' (want null)"

# (b) same real, non-placeholder user, now with ZERO credentials -> must get
# an HMAC-synthesized decoy allowCredentials, not an empty list.
psql_q "DELETE FROM fido2_credentials WHERE user_id = '$USER_ID';" >/dev/null
LEFT=$(psql_q "SELECT count(*) FROM fido2_credentials WHERE user_id = '$USER_ID';")
[ "$LEFT" = 0 ] || step_fail "test setup: user still has $LEFT credentials (want 0)"
BODY=$(curl -s -w '\n%{http_code}' -X POST "$GATEWAY_URL/auth/login/begin" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$SCOPED_USERNAME\"}")
CODE=$(echo "$BODY" | tail -1)
JSON=$(echo "$BODY" | sed '$d')
[ "$CODE" = 200 ] || step_fail "known-zero-cred begin returned HTTP $CODE (want 200)"
N_B=$(echo "$JSON" | jq '.publicKey.allowCredentials | length')
[ "$N_B" -gt 0 ] || step_fail "known-zero-cred begin returned $N_B allowCredentials (want > 0 — a decoy, not an empty list)"
MEDIATION_B=$(echo "$JSON" | jq -r '.mediation')
[ "$MEDIATION_B" = null ] || step_fail "known-zero-cred begin mediation was '$MEDIATION_B' (want null)"

# (c) nonexistent username -> same non-empty-decoy, no-mediation shape.
BODY=$(curl -s -w '\n%{http_code}' -X POST "$GATEWAY_URL/auth/login/begin" \
    -H 'Content-Type: application/json' \
    -d '{"username":"definitely-not-a-real-user-xyz"}')
CODE=$(echo "$BODY" | tail -1)
JSON=$(echo "$BODY" | sed '$d')
[ "$CODE" = 200 ] || step_fail "unknown-username begin returned HTTP $CODE (want 200)"
N_C=$(echo "$JSON" | jq '.publicKey.allowCredentials | length')
[ "$N_C" -gt 0 ] || step_fail "unknown-username begin returned $N_C allowCredentials (want > 0 — a decoy, not an empty list)"
MEDIATION_C=$(echo "$JSON" | jq -r '.mediation')
[ "$MEDIATION_C" = null ] || step_fail "unknown-username begin mediation was '$MEDIATION_C' (want null)"

step_pass "known-with-creds / known-zero-creds / unknown-username begin are all indistinguishable (non-empty allowCredentials, no mediation)"

# ── Step 14: decoy stability -> same nonexistent username -> identical
# synthetic allowCredentials across calls (deterministic HMAC, not per-call
# randomness — an attacker probing twice must see the SAME fake list) ────────
STEP_NUM=14
BODY1=$(curl -s -w '\n%{http_code}' -X POST "$GATEWAY_URL/auth/login/begin" \
    -H 'Content-Type: application/json' \
    -d '{"username":"definitely-not-a-real-user-xyz"}')
CODE1=$(echo "$BODY1" | tail -1)
JSON1=$(echo "$BODY1" | sed '$d')
[ "$CODE1" = 200 ] || step_fail "decoy-stability call 1 returned HTTP $CODE1 (want 200)"
IDS1=$(echo "$JSON1" | jq -c '(.publicKey.allowCredentials // []) | map(.id) | sort')

BODY2=$(curl -s -w '\n%{http_code}' -X POST "$GATEWAY_URL/auth/login/begin" \
    -H 'Content-Type: application/json' \
    -d '{"username":"definitely-not-a-real-user-xyz"}')
CODE2=$(echo "$BODY2" | tail -1)
JSON2=$(echo "$BODY2" | sed '$d')
[ "$CODE2" = 200 ] || step_fail "decoy-stability call 2 returned HTTP $CODE2 (want 200)"
IDS2=$(echo "$JSON2" | jq -c '(.publicKey.allowCredentials // []) | map(.id) | sort')

[ -n "$IDS1" ] && [ "$IDS1" != "[]" ] || step_fail "decoy-stability call 1 had no credential ids to compare"
[ "$IDS1" = "$IDS2" ] || step_fail "decoy allowCredentials ids differ across calls for the same username: $IDS1 vs $IDS2 (decoys must be deterministic)"
step_pass "Decoy allowCredentials ids are byte-identical across repeated begin calls for the same nonexistent username"

# ── Step 15: finish-side oracle closure -> invalid session / decoy challenge /
# real-user challenge with a garbage assertion ALL return the IDENTICAL 401
# {"error":"authentication_failed"} body (Phase 1's normalized finish
# errors — every credential-verification failure collapses to one shape, so
# a caller can't distinguish "no such session" from "bad signature" from
# "wrong user resolved from a decoy"). ────────────────────────────────────────
STEP_NUM=15
GARBAGE_ASSERTION='"response":{"authenticatorData":"AAAA","clientDataJSON":"AAAA","signature":"AAAA","userHandle":null},"type":"public-key"'

# (a) finish against a session key that was never issued.
FIN_A=$(curl -s -w '\n%{http_code}' -X POST "$GATEWAY_URL/auth/login/finish" \
    -H 'Content-Type: application/json' \
    -d "{\"session\":\"not-a-real-session-id\",\"id\":\"AAAA\",\"rawId\":\"AAAA\",$GARBAGE_ASSERTION}")
CODE_A=$(echo "$FIN_A" | tail -1)
JSON_A=$(echo "$FIN_A" | sed '$d')

# (b) finish against a decoy (nonexistent-username) begin session, with a
# garbage assertion — the discoverable path can never identify a credential
# for it, so this must fail exactly like (a).
DECOY_BEGIN_JSON=$(curl -s -X POST "$GATEWAY_URL/auth/login/begin" \
    -H 'Content-Type: application/json' \
    -d '{"username":"definitely-not-a-real-user-xyz"}')
DECOY_SESSION=$(echo "$DECOY_BEGIN_JSON" | jq -r '.session')
[ -n "$DECOY_SESSION" ] && [ "$DECOY_SESSION" != null ] || step_fail "decoy begin (step 15) missing session"
FIN_B=$(curl -s -w '\n%{http_code}' -X POST "$GATEWAY_URL/auth/login/finish" \
    -H 'Content-Type: application/json' \
    -d "{\"session\":\"$DECOY_SESSION\",\"id\":\"AAAA\",\"rawId\":\"AAAA\",$GARBAGE_ASSERTION}")
CODE_B=$(echo "$FIN_B" | tail -1)
JSON_B=$(echo "$FIN_B" | sed '$d')

# (c) finish against a REAL known-username begin session (scoped, with a
# fixture credential re-added — step 13(b) deleted the earlier one to test
# the zero-cred decoy case), with the same garbage assertion — signature
# verification fails, so this must also fail identically.
psql_q "INSERT INTO fido2_credentials (
            credential_id, user_id, public_key, name, attestation_type,
            sign_count, created_at, updated_at
        ) VALUES (
            '\\xdeadbeefcafef00d1234567890abcdef'::bytea, '$USER_ID',
            '$FIXTURE_PUBLIC_KEY'::bytea, NULL, 'e2e', 0, NOW(), NOW()
        );" >/dev/null
REAL_JSON=$(curl -s -X POST "$GATEWAY_URL/auth/login/begin" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$SCOPED_USERNAME\"}")
REAL_SESSION=$(echo "$REAL_JSON" | jq -r '.session')
[ -n "$REAL_SESSION" ] && [ "$REAL_SESSION" != null ] || step_fail "real-user begin (step 15) missing session"
FIN_C=$(curl -s -w '\n%{http_code}' -X POST "$GATEWAY_URL/auth/login/finish" \
    -H 'Content-Type: application/json' \
    -d "{\"session\":\"$REAL_SESSION\",\"id\":\"AAAA\",\"rawId\":\"AAAA\",$GARBAGE_ASSERTION}")
CODE_C=$(echo "$FIN_C" | tail -1)
JSON_C=$(echo "$FIN_C" | sed '$d')

[ "$CODE_A" = 401 ] || step_fail "invalid-session finish returned HTTP $CODE_A (want 401)"
[ "$CODE_B" = 401 ] || step_fail "decoy-challenge finish returned HTTP $CODE_B (want 401)"
[ "$CODE_C" = 401 ] || step_fail "real-user garbage-assertion finish returned HTTP $CODE_C (want 401)"
EXPECTED='{"error":"authentication_failed"}'
[ "$JSON_A" = "$EXPECTED" ] || step_fail "invalid-session finish body was '$JSON_A' (want $EXPECTED)"
[ "$JSON_B" = "$EXPECTED" ] || step_fail "decoy-challenge finish body was '$JSON_B' (want $EXPECTED)"
[ "$JSON_C" = "$EXPECTED" ] || step_fail "real-user garbage-assertion finish body was '$JSON_C' (want $EXPECTED)"
[ "$JSON_A" = "$JSON_B" ] && [ "$JSON_B" = "$JSON_C" ] \
    || step_fail "finish failure bodies are not byte-identical across cases: A='$JSON_A' B='$JSON_B' C='$JSON_C'"
step_pass "Invalid-session / decoy-challenge / real-user-bad-assertion finish all return the identical 401 authentication_failed body (oracle closed)"

# ── Step 16: claiming an INVALID username -> 400 (CLI reprompt contract) ──
STEP_NUM=16
# validate_username runs before the claim/placeholder/taken logic, so an invalid
# name (here "ab", below the 3-char minimum) returns 400. The CLI's claim loop
# treats 400 as a RETRYABLE validation error (print message + reprompt) rather
# than aborting the command; this pins that contract, distinct from the 409
# (taken/already-claimed) cases. Mint a FRESH session — step 13 deleted the
# earlier user's credential, so SESSION_ID no longer authenticates.
LOGIN2=$(curl -sf -X POST "$GATEWAY_URL/auth/e2e-login" -H 'Content-Type: application/json')
SESSION2=$(echo "$LOGIN2" | jq -r '.session_id')
[ -n "$SESSION2" ] && [ "$SESSION2" != null ] || step_fail "e2e-login (step 14) returned no session"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GATEWAY_URL/user/username" \
    -H "X-Session-ID: $SESSION2" -H 'Content-Type: application/json' \
    -d '{"username":"ab"}')
[ "$CODE" = 400 ] || step_fail "invalid username claim returned HTTP $CODE (want 400 — the CLI relies on 400 being a retryable validation error, not a fatal abort)"
step_pass "Invalid username claim -> 400 (retryable validation, distinct from 409 taken/claimed)"

# ── Step 17: fresh QR token -> status "pending" (desktop poll start state) ──
STEP_NUM=17
# GET /auth/qr-login/status is what the desktop side polls while waiting for the
# phone to authenticate. A just-issued token must report "pending" with no
# session_id yet — the starting state of the cross-device handoff. Independent
# of credential state (step 13 deleted the user's cred), so a bare begin is fine.
QR_BEGIN=$(curl -s -w '\n%{http_code}' -X POST "$GATEWAY_URL/auth/qr-login/begin" \
    -H 'Content-Type: application/json' -d '{}')
CODE=$(echo "$QR_BEGIN" | tail -1)
JSON=$(echo "$QR_BEGIN" | sed '$d')
[ "$CODE" = 200 ] || step_fail "qr-login/begin (status test) returned HTTP $CODE (want 200)"
QR_TOKEN=$(echo "$JSON" | jq -r '.token')
[ -n "$QR_TOKEN" ] && [ "$QR_TOKEN" != null ] || step_fail "qr-login/begin response missing token"
STATUS=$(curl -s -w '\n%{http_code}' "$GATEWAY_URL/auth/qr-login/status?token=$QR_TOKEN")
CODE=$(echo "$STATUS" | tail -1)
JSON=$(echo "$STATUS" | sed '$d')
[ "$CODE" = 200 ] || step_fail "qr-login/status (fresh token) returned HTTP $CODE (want 200)"
S=$(echo "$JSON" | jq -r '.status')
[ "$S" = pending ] || step_fail "qr-login/status (fresh token) status was '$S' (want pending)"
echo "$JSON" | jq -e 'has("session_id") | not' >/dev/null \
    || step_fail "qr-login/status (fresh token) leaked a session_id before authentication"
step_pass "Fresh QR token -> status pending, no session_id (desktop poll start state)"

# ── Step 18: unknown QR token -> status "not_found", 200 (no oracle) ──
STEP_NUM=18
# Row absence is DERIVED into a "not_found" status (qr_login_status_handler),
# never a 404. A distinct HTTP code or a different shape for absent-vs-pending
# would turn the poll endpoint into a token-validity oracle, so the response
# must be an ordinary 200 that only differs in the status string.
STATUS=$(curl -s -w '\n%{http_code}' "$GATEWAY_URL/auth/qr-login/status?token=definitely-not-a-real-token-xyz")
CODE=$(echo "$STATUS" | tail -1)
JSON=$(echo "$STATUS" | sed '$d')
[ "$CODE" = 200 ] || step_fail "qr-login/status (unknown token) returned HTTP $CODE (want 200 — a 404 would be a token oracle)"
S=$(echo "$JSON" | jq -r '.status')
[ "$S" = not_found ] || step_fail "qr-login/status (unknown token) status was '$S' (want not_found)"
step_pass "Unknown QR token -> 200 status not_found (no token-validity oracle)"

# ── Step 19: rate limiting -> per-IP scoped-begin cap 429s, no-username path
# is unaffected by that tighter bucket ────────────────────────────────────
STEP_NUM=19
# SCOPED_BEGIN_MAX_REQUESTS is 20/60s per IP on the username-present
# /auth/login/begin path (src/gateway/src/rate_limit.rs). Earlier steps in
# this script already issued several scoped begin calls from this same test
# IP within the window, so we don't need — and can't cleanly isolate —
# exactly 20 fresh calls here; we just flood a modest, bounded number and
# assert a 429 shows up somewhere in that flood.
#
# The separate USERNAME_BEGIN_MAX_REQUESTS (10/60s, per-username) fail-safe
# — where a real username flooded past its own budget silently gets a decoy
# instead of a 429 — is NOT asserted here: from a single test-runner IP we
# cannot send >10 requests for one username without also tripping the
# 20/IP scoped cap first, so the two effects can't be isolated in this
# black-box e2e harness. That behavior is covered by the Rust unit tests in
# handlers.rs's login_begin_tests instead.
SAW_429=0
for i in $(seq 1 25); do
    CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GATEWAY_URL/auth/login/begin" \
        -H 'Content-Type: application/json' \
        -d "{\"username\":\"rate-limit-probe-$i\"}")
    if [ "$CODE" = 429 ]; then
        SAW_429=1
        break
    fi
    [ "$CODE" = 200 ] || step_fail "scoped begin (rate-limit flood, request $i) returned unexpected HTTP $CODE (want 200 or eventually 429)"
done
[ "$SAW_429" = 1 ] || step_fail "scoped begin never returned 429 after 25 requests from one IP (want the per-IP 20/60s scoped-begin cap to trip)"
step_pass "Scoped (username-present) begin -> 429 once the per-IP cap is exceeded"

# No-username (broadcast/discoverable) begin must NOT be subject to the
# tighter scoped-begin bucket — flood it too and confirm it never 429s.
for i in $(seq 1 10); do
    CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$GATEWAY_URL/auth/login/begin")
    [ "$CODE" = 200 ] || step_fail "no-username begin (request $i, post rate-limit flood) returned HTTP $CODE (want 200 — must not share the scoped-begin cap)"
done
step_pass "No-username begin is unaffected by the scoped-begin rate limit (still 200 after the scoped flood)"

echo ""
log "All $STEPS_PASSED steps passed ✓"
