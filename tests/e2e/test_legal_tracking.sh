#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
#
# E2E tests for legal document tracking.
# Requires: make up-test (builds with e2e-testing feature)
#
# Tests:
#   1. Seed data has one active version per document type
#   2. Only one active row per document type (unique constraint)
#   3. User status API returns legal state
#   4. Pre-tracking user gets requires_action=false
#   5. Outdated TOS triggers requires_action=true
#   6. Outdated privacy notice triggers requires_action=true
#   7. Re-acceptance endpoint clears requires_action

set -euo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8000}"
DB_CONTAINER="${DB_CONTAINER:-postgres-test}"
DB_NAME="${DB_NAME:-caution_test}"
LOG_DIR="tests/e2e/logs"
LOG_FILE="$LOG_DIR/legal-$(date +%Y%m%d-%H%M%S).log"
STEP_NUM=0
STEPS_PASSED=0
STEPS_FAILED=0
STEP_RESULTS=()

mkdir -p "$LOG_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1

cleanup() {
    echo ""
    echo "=== Cleanup ==="

    # Remove test document versions and restore originals
    docker exec "$DB_CONTAINER" psql -U postgres -d "$DB_NAME" -c "
        BEGIN;
        UPDATE legal_documents SET is_active = false WHERE version = '2099-06-01';
        UPDATE legal_documents SET is_active = true WHERE version = '$SEED_TOS_VERSION' AND document_type = 'terms_of_service';
        UPDATE legal_documents SET is_active = true WHERE version = '$SEED_PN_VERSION' AND document_type = 'privacy_notice';
        DELETE FROM user_legal_events WHERE document_version = '2099-06-01';
        DELETE FROM legal_documents WHERE version = '2099-06-01';
        COMMIT;
    " >/dev/null 2>&1 || true

    echo ""
    echo "========================================"
    echo "  Legal Tracking Test Results"
    echo "========================================"
    for result in "${STEP_RESULTS[@]}"; do
        echo "  $result"
    done
    echo "----------------------------------------"
    echo "  Passed: $STEPS_PASSED  Failed: $STEPS_FAILED"
    echo "========================================"
    echo ""
    echo "Full log: $LOG_FILE"

    if [ "$STEPS_FAILED" -gt 0 ]; then
        exit 1
    fi
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
    echo "[legal] $*"
}

db_query() {
    docker exec "$DB_CONTAINER" psql -U postgres -d "$DB_NAME" -t -A -c "$1"
}

# Seed version placeholders (set in step 1)
SEED_TOS_VERSION=""
SEED_PN_VERSION=""
SEED_TOS_ID=""
SEED_PN_ID=""

# ── Step 1: Wait for services and read seed versions ───────────────

STEP_NUM=1
log "Waiting for gateway..."
for i in $(seq 1 30); do
    if curl -sf "$GATEWAY_URL/health" >/dev/null 2>&1; then
        break
    fi
    if [ "$i" -eq 30 ]; then
        step_fail "Gateway health check"
        exit 1
    fi
    sleep 1
done

SEED_TOS_VERSION=$(db_query "SELECT version FROM legal_documents WHERE document_type = 'terms_of_service' AND is_active = true;")
SEED_PN_VERSION=$(db_query "SELECT version FROM legal_documents WHERE document_type = 'privacy_notice' AND is_active = true;")
SEED_TOS_ID=$(db_query "SELECT id FROM legal_documents WHERE document_type = 'terms_of_service' AND is_active = true;")
SEED_PN_ID=$(db_query "SELECT id FROM legal_documents WHERE document_type = 'privacy_notice' AND is_active = true;")

if [[ -n "$SEED_TOS_VERSION" && -n "$SEED_PN_VERSION" && -n "$SEED_TOS_ID" && -n "$SEED_PN_ID" ]]; then
    step_pass "Seed data: TOS=$SEED_TOS_VERSION, PN=$SEED_PN_VERSION"
else
    step_fail "Seed data: missing active documents (TOS='$SEED_TOS_VERSION' PN='$SEED_PN_VERSION')"
    exit 1
fi

# ── Step 2: Unique constraint on active documents ──────────────────

STEP_NUM=2
log "Testing unique active constraint..."

INSERT_RESULT=$(db_query "
    INSERT INTO legal_documents (document_type, version, url, effective_at, is_active, source_commit_sha, source_path, content_sha256)
    VALUES ('terms_of_service', '2099-01-01', 'https://example.com', '2099-01-01', true,
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'terms.md',
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
" 2>&1 || true)

if echo "$INSERT_RESULT" | grep -qi "unique\|duplicate\|violates"; then
    step_pass "Unique active constraint rejected duplicate active TOS"
else
    step_fail "Unique active constraint did not reject duplicate active TOS"
    db_query "DELETE FROM legal_documents WHERE version = '2099-01-01';" >/dev/null 2>&1 || true
fi

# ── Step 3: User status API returns legal state ────────────────────

STEP_NUM=3
log "Creating test user..."
LOGIN_RESPONSE=$(curl -sf -X POST "$GATEWAY_URL/auth/e2e-login" -H "Content-Type: application/json")
SESSION_ID=$(echo "$LOGIN_RESPONSE" | jq -r '.session_id')
USER_ID=$(echo "$LOGIN_RESPONSE" | jq -r '.user_id')

if [ -z "$SESSION_ID" ] || [ "$SESSION_ID" = "null" ]; then
    step_fail "E2E login (no session_id)"
    exit 1
fi

db_query "UPDATE users SET email_verified_at = NOW(), payment_method_added_at = NOW() WHERE id = '$USER_ID';" >/dev/null

STATUS_RESPONSE=$(curl -sf "$GATEWAY_URL/api/user/status" -H "X-Session-ID: $SESSION_ID")
HAS_LEGAL=$(echo "$STATUS_RESPONSE" | jq 'has("legal")')
TOS_ACTIVE=$(echo "$STATUS_RESPONSE" | jq -r '.legal.terms_of_service.active_version')
PN_ACTIVE=$(echo "$STATUS_RESPONSE" | jq -r '.legal.privacy_notice.active_version')

if [[ "$HAS_LEGAL" == "true" && "$TOS_ACTIVE" == "$SEED_TOS_VERSION" && "$PN_ACTIVE" == "$SEED_PN_VERSION" ]]; then
    step_pass "Status API returns legal state with correct active versions"
else
    step_fail "Status API: has_legal=$HAS_LEGAL TOS=$TOS_ACTIVE PN=$PN_ACTIVE"
fi

# ── Step 4: Pre-tracking user gets requires_action=false ───────────

STEP_NUM=4
log "Testing pre-tracking user..."

# E2E users have no legal events (bypass normal registration)
TOS_ACTION=$(echo "$STATUS_RESPONSE" | jq -r '.legal.terms_of_service.requires_action')
PN_ACTION=$(echo "$STATUS_RESPONSE" | jq -r '.legal.privacy_notice.requires_action')

if [[ "$TOS_ACTION" == "false" && "$PN_ACTION" == "false" ]]; then
    step_pass "Pre-tracking user: requires_action=false for both"
else
    step_fail "Pre-tracking user: TOS=$TOS_ACTION PN=$PN_ACTION"
fi

# ── Step 5: Outdated TOS triggers requires_action ─────────────────

STEP_NUM=5
log "Testing outdated TOS detection..."

# Give user a baseline acceptance
db_query "
    INSERT INTO user_legal_events (user_id, legal_document_id, document_type, document_version, event_type, event_source)
    VALUES
        ('$USER_ID', '$SEED_TOS_ID', 'terms_of_service', '$SEED_TOS_VERSION', 'accepted', 'signup'),
        ('$USER_ID', '$SEED_PN_ID', 'privacy_notice', '$SEED_PN_VERSION', 'acknowledged', 'signup');
" >/dev/null

# Add and activate a new TOS version
db_query "
    INSERT INTO legal_documents (
        document_type, version, url, effective_at, is_active, requires_blocking_reacceptance,
        source_commit_sha, source_path, content_sha256
    )
    VALUES (
        'terms_of_service', '2099-06-01', 'https://caution.co/terms-v2.html', '2099-06-01', false, true,
        'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'terms.md',
        'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
    );
" >/dev/null

db_query "
    BEGIN;
    UPDATE legal_documents SET is_active = false WHERE document_type = 'terms_of_service' AND is_active = true;
    UPDATE legal_documents SET is_active = true WHERE document_type = 'terms_of_service' AND version = '2099-06-01';
    COMMIT;
" >/dev/null

STATUS3=$(curl -sf "$GATEWAY_URL/api/user/status" -H "X-Session-ID: $SESSION_ID")
TOS_ACTION3=$(echo "$STATUS3" | jq -r '.legal.terms_of_service.requires_action')
TOS_ACTIVE3=$(echo "$STATUS3" | jq -r '.legal.terms_of_service.active_version')
TOS_USER3=$(echo "$STATUS3" | jq -r '.legal.terms_of_service.latest_user_version')
PN_ACTION3=$(echo "$STATUS3" | jq -r '.legal.privacy_notice.requires_action')

if [[ "$TOS_ACTION3" == "true" && "$TOS_ACTIVE3" == "2099-06-01" && "$TOS_USER3" == "$SEED_TOS_VERSION" && "$PN_ACTION3" == "false" ]]; then
    step_pass "Outdated TOS: requires_action=true, PN unchanged"
else
    step_fail "Outdated TOS: action=$TOS_ACTION3 active=$TOS_ACTIVE3 user=$TOS_USER3 PN=$PN_ACTION3"
fi

# ── Step 6: Outdated privacy notice triggers requires_action ──────

STEP_NUM=6
log "Testing outdated privacy notice detection..."

# Restore TOS
db_query "
    BEGIN;
    UPDATE legal_documents SET is_active = false WHERE document_type = 'terms_of_service' AND is_active = true;
    UPDATE legal_documents SET is_active = true WHERE document_type = 'terms_of_service' AND version = '$SEED_TOS_VERSION';
    COMMIT;
" >/dev/null

# Add and activate a new privacy notice version
db_query "
    INSERT INTO legal_documents (
        document_type, version, url, effective_at, is_active, requires_acknowledgment,
        source_commit_sha, source_path, content_sha256
    )
    VALUES (
        'privacy_notice', '2099-06-01', 'https://caution.co/privacy-v2.html', '2099-06-01', false, true,
        'cccccccccccccccccccccccccccccccccccccccc', 'privacy.md',
        'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
    );
" >/dev/null

db_query "
    BEGIN;
    UPDATE legal_documents SET is_active = false WHERE document_type = 'privacy_notice' AND is_active = true;
    UPDATE legal_documents SET is_active = true WHERE document_type = 'privacy_notice' AND version = '2099-06-01';
    COMMIT;
" >/dev/null

STATUS4=$(curl -sf "$GATEWAY_URL/api/user/status" -H "X-Session-ID: $SESSION_ID")
PN_ACTION4=$(echo "$STATUS4" | jq -r '.legal.privacy_notice.requires_action')
PN_ACTIVE4=$(echo "$STATUS4" | jq -r '.legal.privacy_notice.active_version')
PN_USER4=$(echo "$STATUS4" | jq -r '.legal.privacy_notice.latest_user_version')
TOS_ACTION4=$(echo "$STATUS4" | jq -r '.legal.terms_of_service.requires_action')

if [[ "$PN_ACTION4" == "true" && "$PN_ACTIVE4" == "2099-06-01" && "$PN_USER4" == "$SEED_PN_VERSION" && "$TOS_ACTION4" == "false" ]]; then
    step_pass "Outdated privacy notice: requires_action=true, TOS unchanged"
else
    step_fail "Outdated PN: action=$PN_ACTION4 active=$PN_ACTIVE4 user=$PN_USER4 TOS=$TOS_ACTION4"
fi

# ── Step 7: Re-acceptance clears requires_action ──────────────────

STEP_NUM=7
log "Testing re-acceptance endpoint..."

# Privacy notice is still outdated from step 6
ACCEPT_RESPONSE=$(curl -sf -X POST "$GATEWAY_URL/api/legal/accept" \
    -H "X-Session-ID: $SESSION_ID" \
    -H "Content-Type: application/json" \
    -d '{"document_type": "privacy_notice"}')

ACCEPT_SUCCESS=$(echo "$ACCEPT_RESPONSE" | jq -r '.success')
ACCEPT_VERSION=$(echo "$ACCEPT_RESPONSE" | jq -r '.version')
PN_ACTION5=$(echo "$ACCEPT_RESPONSE" | jq -r '.legal.privacy_notice.requires_action')

if [[ "$ACCEPT_SUCCESS" == "true" && "$ACCEPT_VERSION" == "2099-06-01" && "$PN_ACTION5" == "false" ]]; then
    step_pass "Re-acceptance: privacy notice accepted, requires_action cleared"
else
    step_fail "Re-acceptance: success=$ACCEPT_SUCCESS version=$ACCEPT_VERSION action=$PN_ACTION5"
fi

log "All legal tracking tests complete."
