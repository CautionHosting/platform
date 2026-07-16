#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
#
# Full WebAuthn register + login assertion round-trip, driven by an in-process
# software passkey (webauthn-authenticator-rs SoftPasskey). Closes the gap that
# test_webauthn_login.sh documents as covered only by a "manual
# Chrome-virtual-authenticator runbook": the actual finish-side ceremony where the
# authenticator signs the challenge and the gateway verifies it.
#
# Flow:
#   1. Wait for gateway health
#   2. Seed a fresh unredeemed access code (beta_codes) + unique username
#   3. cargo build the standalone soft-authenticator helper
#   4. Run it: register/begin+finish then login/begin+finish, then assert the
#      issued session authenticates on GET /passkeys
#
# Requires: make up-test (gateway with e2e-testing-unsafe), cargo/rust toolchain.

set -euo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8000}"
DB_CONTAINER="${TEST_DB_HOST:-postgres-test}"
DB_NAME="${TEST_DB_NAME:-caution_test}"
BIN_DIR="tests/e2e/soft-authenticator"

log()  { echo "[webauthn-roundtrip] $*"; }
fail() { echo "[webauthn-roundtrip] ✗ $*" >&2; exit 1; }
psql_q() { docker exec "$DB_CONTAINER" psql -U postgres -d "$DB_NAME" -tAc "$1"; }

# ── Step 1: gateway health ───────────────────────────────────────────
for i in $(seq 1 30); do
    curl -sf -o /dev/null "$GATEWAY_URL/health" && break
    [ "$i" = 30 ] && fail "gateway never became healthy"
    sleep 1
done
log "gateway healthy"

# ── Step 2: seed a fresh access code + username ──────────────────────
STAMP=$(date +%s)
ACCESS_CODE="e2e-softauth-$STAMP"
USERNAME="softauth$STAMP"
psql_q "INSERT INTO beta_codes (code) VALUES ('$ACCESS_CODE');" >/dev/null
log "seeded access code=$ACCESS_CODE username=$USERNAME"

# ── Step 3: build the software authenticator ─────────────────────────
log "building soft-authenticator (cargo)…"
cargo build --quiet --manifest-path "$BIN_DIR/Cargo.toml" \
    || fail "cargo build failed (OpenSSL dev headers required for softpasskey/crypto)"

# ── Step 4: run the round-trip ───────────────────────────────────────
log "running register + login round-trip…"
GATEWAY_URL="$GATEWAY_URL" \
RP_ORIGIN="${RP_ORIGIN:-$GATEWAY_URL}" \
ACCESS_CODE="$ACCESS_CODE" \
USERNAME="$USERNAME" \
    "$BIN_DIR/target/debug/soft-authenticator" || fail "round-trip failed"

log "✓ PASS"
