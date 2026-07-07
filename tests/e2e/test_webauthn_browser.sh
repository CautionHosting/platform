#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
#
# Full resident-passkey register + discoverable-login browser test, driven through
# the real Vue frontend via a Chrome DevTools Protocol (CDP) virtual authenticator
# (tests/e2e/browser-authenticator/cdp-passkey.mjs). Unlike test_webauthn_roundtrip.sh
# (a non-resident SecurityKey ceremony via the Rust soft-authenticator), this covers
# the branch's actual feature: username-less, discoverable login with an empty
# `allowCredentials`, resolved server-side by `userHandle`.
#
# Flow:
#   1. Wait for gateway health
#   2. Flip the gateway to LOGIN_ALLOW_BROADCAST=false (discoverable path) and
#      restore the default on exit
#   3. Seed a fresh unredeemed alpha code (beta_codes) + unique username
#   4. Install Puppeteer (npm ci)
#   5. Run the CDP register + discoverable login test
#
# Requires: make up-test (gateway with e2e-testing-unsafe), Node/npm, and the shared
# libraries Puppeteer's bundled Chromium needs (on Debian/Ubuntu: libnss3 libatk1.0-0t64
# libatk-bridge2.0-0t64 libcups2t64 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1
# libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libasound2t64 libatspi2.0-0t64).

set -euo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8000}"
DB_CONTAINER="${TEST_DB_HOST:-postgres-test}"
DB_NAME="${TEST_DB_NAME:-caution_test}"
BIN_DIR="tests/e2e/browser-authenticator"

log()  { echo "[webauthn-browser] $*"; }
fail() { echo "[webauthn-browser] ✗ $*" >&2; exit 1; }
psql_q() { docker exec "$DB_CONTAINER" psql -U postgres -d "$DB_NAME" -tAc "$1"; }

# ── Step 1: gateway health ───────────────────────────────────────────
for i in $(seq 1 30); do
    curl -sf -o /dev/null "$GATEWAY_URL/health" && break
    [ "$i" = 30 ] && fail "gateway never became healthy"
    sleep 1
done
log "gateway healthy"

# ── Step 2: flip gateway to discoverable, restore on exit ────────────
restore_gateway() { log "restoring gateway (LOGIN_ALLOW_BROADCAST default)…"; make run-gateway-test >/dev/null 2>&1 || true; }
trap restore_gateway EXIT

log "restarting gateway with LOGIN_ALLOW_BROADCAST=false…"
GATEWAY_EXTRA_ENV="-e LOGIN_ALLOW_BROADCAST=false" make run-gateway-test >/dev/null

for i in $(seq 1 30); do
    curl -sf -o /dev/null "$GATEWAY_URL/health" && break
    [ "$i" = 30 ] && fail "gateway never became healthy after restart"
    sleep 1
done
log "gateway healthy (discoverable mode)"

# ── Step 3: seed a fresh alpha code + username ───────────────────────
STAMP="$(date +%s)-$RANDOM"
ALPHA_CODE="e2e-cdp-$STAMP"
USERNAME="cdp$RANDOM$RANDOM"
psql_q "INSERT INTO beta_codes (code) VALUES ('$ALPHA_CODE');" >/dev/null
log "seeded alpha code=$ALPHA_CODE username=$USERNAME"

# ── Step 4: install Puppeteer ────────────────────────────────────────
log "installing puppeteer (npm ci)…"
( cd "$BIN_DIR" && if [ ! -d node_modules ]; then npm ci || npm install; fi )

# ── Step 5: run the CDP register + discoverable login test ──────────
log "running CDP register + discoverable login…"
BASE_URL="$GATEWAY_URL" ALPHA_CODE="$ALPHA_CODE" USERNAME="$USERNAME" \
    node "$BIN_DIR/cdp-passkey.mjs" || fail "browser round-trip failed"

log "✓ PASS"
