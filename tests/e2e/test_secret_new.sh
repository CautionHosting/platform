#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
#
# E2E test for `caution secret new`.
# Requires: KEYMAKER_URL pointing to an explicitly authorized legacy V0 Keymaker,
# and ALLOW_LIVE_KEYMAKER_E2E=1 after protocol and disruptive-test approval.
# LIVE: steps 1-5 and 8 generate quorums and may reboot that service even with
# --no-upload. Local argument checks (6, 7, 9) are not live/cryptographic acceptance.
# This script does not implement the V1 proof-policy contract (tracked separately).
#
# Tests:
#   1. Generate quorum in a caution repo (saves .caution/quorum-bundle.json)
#   2. Non-TTY generation with --no-upload has no FIDO prompt (not a TTY flag test)
#   3. Generate quorum outside a caution repo (warns, outputs to stdout)
#   4. Generate quorum piped (raw JSON to stdout)
#   5. Generate quorum with --threshold and --max
#   6. Missing KEYMAKER_URL gives clear error
#   7. Missing keyring file gives clear error
#   8. CLI keygen + concatenated keyring is normalized into one armor block
#   9. Keyring without signing-capable keys is rejected

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source .env from repo root if it exists
if [ -f "$REPO_ROOT/.env" ]; then
    set -a
    source "$REPO_ROOT/.env"
    set +a
fi

if [ -z "${KEYMAKER_URL:-}" ]; then
    echo "[BLOCKED] KEYMAKER_URL must identify an authorized, compatible Keymaker" >&2
    exit 2
fi
if [ "${ALLOW_LIVE_KEYMAKER_E2E:-}" != "1" ]; then
    echo "[BLOCKED] Live legacy V0 generation requires protocol/disruption approval and ALLOW_LIVE_KEYMAKER_E2E=1; V1 acceptance is tracked in #391" >&2
    exit 2
fi
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
    local exit_code=$?
    trap - EXIT
    if [ "$exit_code" -ne 0 ]; then
        echo "[FAIL] Script stopped with exit $exit_code; later steps may be unexecuted" >&2
    elif [ "$STEPS_FAILED" -ne 0 ]; then
        exit_code=1
    fi
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
    exit "$exit_code"
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

# V0 shape only, not cryptographic verification. Reject empty/multiple documents.
valid_bundle() {
    jq -se 'length == 1 and (.[0] |
        type == "object" and
        (.public_key | type == "string" and length > 0) and
        (.keyring | type == "string" and length > 0) and
        (.shardfile | type == "string" and length > 0) and
        (.keyring_hash | type == "array") and
        (.necroproof | type == "array") and
        (.label | type == "object"))' "$1" >/dev/null 2>&1
}

generate_bundle() {
    local directory=$1
    shift
    if (cd "$directory" && KEYMAKER_URL="$KEYMAKER_URL" "$CAUTION_BIN" secret new "$@") \
        >"$WORK_DIR/stdout.json" 2>"$WORK_DIR/stderr.log"; then
        valid_bundle "$WORK_DIR/stdout.json"
    else
        local exit_code=$?
        echo "[e2e] Generation failed (exit $exit_code)" >&2
        return "$exit_code"
    fi
}

saved_bundle_matches() {
    valid_bundle "$1" &&
        jq -se 'length == 2 and .[0] == .[1]' "$1" "$WORK_DIR/stdout.json" >/dev/null 2>&1
}

# Build the CLI binary once upfront
if [ -z "${CAUTION_BIN:-}" ]; then
    log "Building CLI..."
    cargo build --manifest-path "$REPO_ROOT/Cargo.toml" -p cli 2>/dev/null
    CAUTION_BIN="$REPO_ROOT/target/debug/caution"
fi

# ── Setup: Generate test PGP keyring ───────────────────────────────────

log "Generating test PGP keyring..."
GNUPGHOME=$(mktemp -d "$WORK_DIR/gnupg.XXXXXX")
export GNUPGHOME
gpg --batch --passphrase '' --quick-gen-key "Test Quorum <test@example.com>" rsa2048 cert 0 2>/dev/null
FINGERPRINT=$(gpg --list-keys --with-colons 2>/dev/null | grep '^fpr' | head -1 | cut -d: -f10)
gpg --batch --passphrase '' --quick-add-key "$FINGERPRINT" rsa2048 encr 0 2>/dev/null
gpg --batch --passphrase '' --quick-add-key "$FINGERPRINT" rsa2048 auth 0 2>/dev/null
gpg --batch --passphrase '' --quick-add-key "$FINGERPRINT" rsa2048 sign 0 2>/dev/null
gpg --armor --export "$FINGERPRINT" > "$WORK_DIR/keyring.asc"
rm -rf "$GNUPGHOME"
unset GNUPGHOME
log "Keyring generated at $WORK_DIR/keyring.asc"

# ── Step 1: Generate quorum in a caution repo ──────────────────────────

STEP_NUM=1
log "Testing secret new in a caution repo..."
REPO_DIR="$WORK_DIR/test-repo"
mkdir -p "$REPO_DIR/.caution"
printf 'web: /bin/true\n' > "$REPO_DIR/Procfile"
cp "$WORK_DIR/keyring.asc" "$REPO_DIR/"

if generate_bundle "$REPO_DIR" keyring.asc --no-upload &&
    saved_bundle_matches "$REPO_DIR/.caution/quorum-bundle.json"; then
    step_pass "Generate quorum in caution repo (saved bundle matches stdout)"
else
    step_fail "Generate quorum in caution repo (command, JSON, or saved bundle failed)"
fi

# ── Step 2: Non-TTY --no-upload output ────────────────────────────────
# Non-TTY output returns before the upload branch in this CLI. This cannot prove
# --no-upload suppresses a TTY prompt; check only the observable behavior here.

STEP_NUM=2
log "Testing --no-upload flag..."
rm -f "$REPO_DIR/.caution/quorum-bundle.json"

if generate_bundle "$REPO_DIR" keyring.asc --no-upload &&
    saved_bundle_matches "$REPO_DIR/.caution/quorum-bundle.json" &&
    grep -q "Saved to:" "$WORK_DIR/stderr.log" &&
    ! grep -qi "tap your key" "$WORK_DIR/stderr.log"; then
    step_pass "Non-TTY --no-upload generation saves bundle without FIDO prompt"
else
    step_fail "Non-TTY --no-upload (command, bundle, or prompt assertion failed)"
fi

# ── Step 3: Not in a caution repo ─────────────────────────────────────

STEP_NUM=3
log "Testing outside a caution repo..."
NO_CAUTION_DIR="$WORK_DIR/not-a-repo"
mkdir -p "$NO_CAUTION_DIR"
cp "$WORK_DIR/keyring.asc" "$NO_CAUTION_DIR/"

if generate_bundle "$NO_CAUTION_DIR" keyring.asc --no-upload &&
    grep -qi "not in a caution repository" "$WORK_DIR/stderr.log" &&
    [ ! -e "$NO_CAUTION_DIR/.caution/quorum-bundle.json" ]; then
    step_pass "Not in caution repo (warns + outputs JSON to stdout)"
else
    step_fail "Not in caution repo (command, JSON, warning, or file assertion failed)"
fi

# ── Step 4: Piped output ──────────────────────────────────────────────

STEP_NUM=4
log "Testing piped output..."

if (cd "$REPO_DIR" && KEYMAKER_URL="$KEYMAKER_URL" "$CAUTION_BIN" secret new keyring.asc --no-upload \
        2>"$WORK_DIR/stderr.log") | valid_bundle /dev/stdin; then
    step_pass "Piped output (successful CLI and valid V0 JSON with public_key)"
else
    step_fail "Piped output (could not parse JSON)"
fi

# ── Step 5: Custom threshold and max ──────────────────────────────────

STEP_NUM=5
log "Testing --threshold and --max..."
rm -f "$REPO_DIR/.caution/quorum-bundle.json"

# V0 returns no threshold/max fields. Require completed generation and matching
# saved data, not just pre-request text. This is not a reconstruction test.
if generate_bundle "$REPO_DIR" keyring.asc --threshold 1 --max 1 --no-upload &&
    saved_bundle_matches "$REPO_DIR/.caution/quorum-bundle.json" &&
    grep -q "threshold=1, max=1" "$WORK_DIR/stderr.log"; then
    step_pass "Generation completed with custom threshold and max arguments"
else
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

# ── Step 8: CLI keygen + concatenated keyring is normalized ──────────
# `cat a.asc b.asc` produces multiple armor blocks; the rpgp-based
# Keymaker/Locksmith stack only reads the first block, so secret new must
# merge them into a single armor block before upload.

STEP_NUM=8
log "Testing CLI keygen + concatenated keyring normalization..."
MULTI_DIR="$WORK_DIR/multi-holder-repo"
mkdir -p "$MULTI_DIR/.caution"
printf '{}\n' > "$MULTI_DIR/.caution/deployment.json"

(cd "$MULTI_DIR" \
    && "$CAUTION_BIN" secret keygen --name Alice --email alice@example.com --shoot-self-in-foot alice.asc 2>/dev/null \
    && "$CAUTION_BIN" secret keygen --name Bob --email bob@example.com --shoot-self-in-foot bob.asc 2>/dev/null \
    && cat alice.asc bob.asc > keyring.asc)

BUNDLE="$MULTI_DIR/.caution/quorum-bundle.json"
if generate_bundle "$MULTI_DIR" keyring.asc --threshold 2 --max 2 --no-upload &&
    saved_bundle_matches "$BUNDLE"; then
    ARMOR_BLOCKS=$(jq '[.keyring | scan("BEGIN PGP PUBLIC KEY BLOCK")] | length' "$BUNDLE")
    if [ "$ARMOR_BLOCKS" = "1" ]; then
        step_pass "Concatenated keyring normalized into a single armor block"
    else
        step_fail "Concatenated keyring not normalized (found $ARMOR_BLOCKS armor blocks in bundle keyring)"
    fi
else
    step_fail "CLI keygen + concatenated keyring (command, JSON, or saved bundle failed)"
fi

# ── Step 9: Keyring without signing keys is rejected ──────────────────

STEP_NUM=9
log "Testing rejection of keyring without signing-capable keys..."
GNUPGHOME=$(mktemp -d "$WORK_DIR/gnupg.XXXXXX")
export GNUPGHOME
gpg --batch --passphrase '' --quick-gen-key "No Sign <nosign@example.com>" rsa2048 cert 0 2>/dev/null
NOSIGN_FPR=$(gpg --list-keys --with-colons 2>/dev/null | grep '^fpr' | head -1 | cut -d: -f10)
gpg --batch --passphrase '' --quick-add-key "$NOSIGN_FPR" rsa2048 encr 0 2>/dev/null
gpg --batch --passphrase '' --quick-add-key "$NOSIGN_FPR" rsa2048 auth 0 2>/dev/null
gpg --armor --export "$NOSIGN_FPR" > "$REPO_DIR/nosign-keyring.asc"
rm -rf "$GNUPGHOME"
unset GNUPGHOME

set +e
OUTPUT=$(cd "$REPO_DIR" && KEYMAKER_URL="$KEYMAKER_URL" "$CAUTION_BIN" secret new nosign-keyring.asc --no-upload 2>&1)
EXIT_CODE=$?
set -e

if [ $EXIT_CODE -ne 0 ] && echo "$OUTPUT" | grep -qi "no Keymaker-eligible"; then
    step_pass "Keyring without signing keys rejected with clear error"
else
    echo "$OUTPUT"
    step_fail "Keyring without signing keys was not rejected"
fi
