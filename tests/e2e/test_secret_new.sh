#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
#
# E2E test for `caution secret new`.
# Requires: KEYMAKER_URL pointing to a running keymaker instance
#
# Tests:
#   1. Generate quorum in a caution repo (saves .caution/quorum-bundle.json)
#   2. Generate quorum with --no-upload
#   3. Generate quorum outside a caution repo (warns, outputs to stdout)
#   4. Generate quorum piped (raw JSON to stdout)
#   5. Generate quorum with --threshold and --max
#   6. Missing KEYMAKER_URL gives clear error
#   7. Missing keyring file gives clear error

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source .env from repo root if it exists
if [ -f "$REPO_ROOT/.env" ]; then
    set -a
    source "$REPO_ROOT/.env"
    set +a
fi

KEYMAKER_URL="${KEYMAKER_URL:?KEYMAKER_URL must be set (set in .env or environment)}"
WORK_DIR=$(mktemp -d)
LOG_DIR="tests/e2e/logs"
LOG_FILE="$LOG_DIR/secret-new-$(date +%Y%m%d-%H%M%S).log"
STEP_NUM=0
STEPS_PASSED=0
STEPS_FAILED=0
STEP_RESULTS=()

mkdir -p "$LOG_DIR"

exec > >(tee -a "$LOG_FILE") 2>&1

cleanup() {
    rm -rf "$WORK_DIR"

    echo ""
    echo "========================================"
    echo "  Secret New E2E Test Results"
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
}

log() {
    echo "[e2e] $*"
}

# Build the CLI binary once upfront
if [ -z "${CAUTION_BIN:-}" ]; then
    log "Building CLI..."
    cargo build --manifest-path "$REPO_ROOT/Cargo.toml" -p cli 2>/dev/null
    CAUTION_BIN="$REPO_ROOT/target/debug/caution"
fi

# ── Setup: Generate test PGP keyring ───────────────────────────────────

log "Generating test PGP keyring..."
export GNUPGHOME=$(mktemp -d)
gpg --batch --passphrase '' --quick-gen-key "Test Quorum <test@example.com>" rsa2048 cert 0 2>/dev/null
FINGERPRINT=$(gpg --list-keys --with-colons 2>/dev/null | grep '^fpr' | head -1 | cut -d: -f10)
gpg --batch --passphrase '' --quick-add-key "$FINGERPRINT" rsa2048 encr 0 2>/dev/null
gpg --batch --passphrase '' --quick-add-key "$FINGERPRINT" rsa2048 auth 0 2>/dev/null
gpg --armor --export "$FINGERPRINT" > "$WORK_DIR/keyring.asc"
rm -rf "$GNUPGHOME"
unset GNUPGHOME
log "Keyring generated at $WORK_DIR/keyring.asc"

# ── Step 1: Generate quorum in a caution repo ──────────────────────────

STEP_NUM=1
log "Testing secret new in a caution repo..."
REPO_DIR="$WORK_DIR/test-repo"
mkdir -p "$REPO_DIR/.caution"
touch "$REPO_DIR/Procfile"
cp "$WORK_DIR/keyring.asc" "$REPO_DIR/"

OUTPUT=$(cd "$REPO_DIR" && KEYMAKER_URL="$KEYMAKER_URL" "$CAUTION_BIN" secret new keyring.asc --no-upload 2>&1) || true

if [ -f "$REPO_DIR/.caution/quorum-bundle.json" ]; then
    # Validate it's valid JSON with expected fields
    if jq -e '.secret_recipient_public_key' "$REPO_DIR/.caution/quorum-bundle.json" >/dev/null 2>&1; then
        step_pass "Generate quorum in caution repo (saved .caution/quorum-bundle.json)"
    else
        step_fail "Generate quorum in caution repo (invalid JSON or missing fields)"
    fi
else
    echo "$OUTPUT"
    step_fail "Generate quorum in caution repo (file not created)"
fi

# ── Step 2: --no-upload skips FIDO prompt ──────────────────────────────

STEP_NUM=2
log "Testing --no-upload flag..."
rm -f "$REPO_DIR/.caution/quorum-bundle.json"

OUTPUT=$(cd "$REPO_DIR" && KEYMAKER_URL="$KEYMAKER_URL" "$CAUTION_BIN" secret new keyring.asc --no-upload 2>&1) || true

if echo "$OUTPUT" | grep -q "Saved to:"; then
    if ! echo "$OUTPUT" | grep -q "tap your key"; then
        step_pass "--no-upload skips FIDO prompt"
    else
        step_fail "--no-upload still shows FIDO prompt"
    fi
else
    echo "$OUTPUT"
    step_fail "--no-upload (unexpected output)"
fi

# ── Step 3: Not in a caution repo ─────────────────────────────────────

STEP_NUM=3
log "Testing outside a caution repo..."
NO_CAUTION_DIR="$WORK_DIR/not-a-repo"
mkdir -p "$NO_CAUTION_DIR"
cp "$WORK_DIR/keyring.asc" "$NO_CAUTION_DIR/"

OUTPUT=$(cd "$NO_CAUTION_DIR" && KEYMAKER_URL="$KEYMAKER_URL" "$CAUTION_BIN" secret new keyring.asc --no-upload 2>&1) || true

if echo "$OUTPUT" | grep -qi "not in a caution repository"; then
    # Should output JSON to stdout
    if echo "$OUTPUT" | grep -q "secret_recipient_public_key"; then
        step_pass "Not in caution repo (warns + outputs JSON to stdout)"
    else
        step_fail "Not in caution repo (warning shown but no JSON output)"
    fi
else
    echo "$OUTPUT"
    step_fail "Not in caution repo (no warning shown)"
fi

# ── Step 4: Piped output ──────────────────────────────────────────────

STEP_NUM=4
log "Testing piped output..."

JSON_OUTPUT=$(cd "$REPO_DIR" && KEYMAKER_URL="$KEYMAKER_URL" "$CAUTION_BIN" secret new keyring.asc --no-upload 2>/dev/null | jq -r '.secret_recipient_public_key' 2>/dev/null) || true

if [ -n "$JSON_OUTPUT" ] && [ "$JSON_OUTPUT" != "null" ]; then
    step_pass "Piped output (valid JSON with secret_recipient_public_key)"
else
    step_fail "Piped output (could not parse JSON)"
fi

# ── Step 5: Custom threshold and max ──────────────────────────────────

STEP_NUM=5
log "Testing --threshold and --max..."
rm -f "$REPO_DIR/.caution/quorum-bundle.json"

OUTPUT=$(cd "$REPO_DIR" && KEYMAKER_URL="$KEYMAKER_URL" "$CAUTION_BIN" secret new keyring.asc --threshold 1 --max 1 --no-upload 2>&1) || true

if echo "$OUTPUT" | grep -q "threshold=1, max=1"; then
    step_pass "Custom threshold and max"
else
    echo "$OUTPUT"
    step_fail "Custom threshold and max"
fi

# ── Step 6: Missing KEYMAKER_URL ──────────────────────────────────────

STEP_NUM=6
log "Testing missing KEYMAKER_URL..."

set +e
OUTPUT=$(cd "$REPO_DIR" && unset KEYMAKER_URL && "$CAUTION_BIN" secret new keyring.asc --no-upload 2>&1)
EXIT_CODE=$?
set -e

if [ $EXIT_CODE -ne 0 ] && echo "$OUTPUT" | grep -qi "KEYMAKER_URL"; then
    step_pass "Missing KEYMAKER_URL (clear error)"
else
    echo "$OUTPUT"
    step_fail "Missing KEYMAKER_URL (no clear error)"
fi

# ── Step 7: Missing keyring file ──────────────────────────────────────

STEP_NUM=7
log "Testing missing keyring file..."

set +e
OUTPUT=$(cd "$REPO_DIR" && KEYMAKER_URL="$KEYMAKER_URL" "$CAUTION_BIN" secret new nonexistent.asc --no-upload 2>&1)
EXIT_CODE=$?
set -e

if [ $EXIT_CODE -ne 0 ] && echo "$OUTPUT" | grep -qi "failed to read\|no such file\|not found"; then
    step_pass "Missing keyring file (clear error)"
else
    echo "$OUTPUT"
    step_fail "Missing keyring file (no clear error)"
fi
