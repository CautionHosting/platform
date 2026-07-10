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
#   8. Legal notice email sender dry-runs, sends once, and dedupes
#   9. add-legal-doc-from-website.sh ingests a doc and rejects a duplicate
#  10. admin publish-legal-doc: ingest+activate+notify end-to-end
#  11. Signup event recording is unaffected by admin/legal-notice tooling
#
# Steps 9-10 exercise utils/admin and utils/add-legal-doc-from-website.sh,
# which connect via LOCAL psql (DB_HOST/DB_PORT). The test postgres
# container ("postgres-test") is only attached to the docker network used
# by the stack and has no published host port, so those tools can't reach
# it directly from the host. We run them inside a short-lived helper
# container joined to that same docker network instead (see HARNESS_*
# below) - this only changes how the *test* invokes the tools; the tools
# themselves are unmodified.

set -euo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8000}"
API_URL="${API_URL:-http://localhost:8080}"
EMAIL_EXTERNAL_URL="${EMAIL_EXTERNAL_URL:-http://localhost:8082}"
INTERNAL_SERVICE_SECRET="${INTERNAL_SERVICE_SECRET:-$(docker exec api printenv INTERNAL_SERVICE_SECRET 2>/dev/null || true)}"
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

    # Tear down the helper container/tempdirs used for steps 9-10, if any.
    if [[ -n "${HARNESS_NAME:-}" ]]; then
        docker rm -f "$HARNESS_NAME" >/dev/null 2>&1 || true
    fi
    if [[ -n "${HARNESS_DIR:-}" && -d "${HARNESS_DIR:-}" ]]; then
        rm -rf "$HARNESS_DIR" 2>/dev/null || true
    fi
    if [[ -n "${WEBSITE_DIR:-}" && -d "${WEBSITE_DIR:-}" ]]; then
        rm -rf "$WEBSITE_DIR" 2>/dev/null || true
    fi
    if [[ -n "${WEBSITE_DIR2:-}" && -d "${WEBSITE_DIR2:-}" ]]; then
        rm -rf "$WEBSITE_DIR2" 2>/dev/null || true
    fi

    # Remove test document versions and restore originals
    docker exec "$DB_CONTAINER" psql -U postgres -d "$DB_NAME" -c "
        BEGIN;
        DELETE FROM legal_email_deliveries
        WHERE batch_id IN (
            SELECT lnb.id
            FROM legal_notice_batches lnb
            WHERE lnb.terms_document_id IN (SELECT id FROM legal_documents WHERE version = '2099-06-01' OR version LIKE '2099-07-%')
               OR lnb.privacy_document_id IN (SELECT id FROM legal_documents WHERE version = '2099-06-01' OR version LIKE '2099-07-%')
        );
        DELETE FROM legal_notice_batches
        WHERE terms_document_id IN (SELECT id FROM legal_documents WHERE version = '2099-06-01' OR version LIKE '2099-07-%')
           OR privacy_document_id IN (SELECT id FROM legal_documents WHERE version = '2099-06-01' OR version LIKE '2099-07-%');
        UPDATE legal_documents SET is_active = false WHERE version = '2099-06-01' OR version LIKE '2099-07-%';
        UPDATE legal_documents SET is_active = true WHERE version = '$SEED_TOS_VERSION' AND document_type = 'terms_of_service';
        UPDATE legal_documents SET is_active = true WHERE version = '$SEED_PN_VERSION' AND document_type = 'privacy_notice';
        DELETE FROM user_legal_events WHERE document_version = '2099-06-01' OR document_version LIKE '2099-07-%';
        DELETE FROM legal_documents WHERE version = '2099-06-01' OR version LIKE '2099-07-%';
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

db_query "UPDATE users SET email = 'legal-e2e@example.com', email_verified_at = NOW(), payment_method_added_at = NOW() WHERE id = '$USER_ID';" >/dev/null

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
TOS_USER3=$(echo "$STATUS3" | jq -r '.legal.terms_of_service.accepted_version')
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
PN_USER4=$(echo "$STATUS4" | jq -r '.legal.privacy_notice.accepted_version')
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

# ── Step 8: Legal notice email sender ──────────────────────────────

STEP_NUM=8
log "Testing legal notice email sender..."

if [[ -z "$INTERNAL_SERVICE_SECRET" ]]; then
    step_fail "Legal notice sender: INTERNAL_SERVICE_SECRET unavailable"
else
    curl -sf -X DELETE "$EMAIL_EXTERNAL_URL/sent" >/dev/null 2>&1 || true

    DRY_RUN_RESPONSE=$(curl -sf -X POST "$API_URL/internal/legal-notices/send" \
        -H "X-Internal-Service-Secret: $INTERNAL_SERVICE_SECRET" \
        -H "Content-Type: application/json" \
        -d '{"dry_run": true}')

    DRY_RUN_PENDING=$(echo "$DRY_RUN_RESPONSE" | jq -r '.pending_recipient_count')
    DRY_RUN_DOCS=$(echo "$DRY_RUN_RESPONSE" | jq -r '.documents | length')

    SEND_RESPONSE=$(curl -sf -X POST "$API_URL/internal/legal-notices/send" \
        -H "X-Internal-Service-Secret: $INTERNAL_SERVICE_SECRET" \
        -H "Content-Type: application/json" \
        -d '{"dry_run": false}')

    SENT_COUNT=$(echo "$SEND_RESPONSE" | jq -r '.sent_count')
    FAILED_COUNT=$(echo "$SEND_RESPONSE" | jq -r '.failed_count')
    LEGAL_EMAIL_COUNT=$(curl -sf "$EMAIL_EXTERNAL_URL/sent?template=legal_notice" 2>/dev/null | jq '.count // 0')

    SECOND_DRY_RUN_RESPONSE=$(curl -sf -X POST "$API_URL/internal/legal-notices/send" \
        -H "X-Internal-Service-Secret: $INTERNAL_SERVICE_SECRET" \
        -H "Content-Type: application/json" \
        -d '{"dry_run": true}')
    SECOND_DRY_RUN_PENDING=$(echo "$SECOND_DRY_RUN_RESPONSE" | jq -r '.pending_recipient_count')

    if [[ "$DRY_RUN_PENDING" -ge 1 && "$DRY_RUN_DOCS" -eq 2 && "$SENT_COUNT" -ge 1 && "$FAILED_COUNT" -eq 0 && "$LEGAL_EMAIL_COUNT" -ge 1 && "$SECOND_DRY_RUN_PENDING" -eq 0 ]]; then
        step_pass "Legal notice sender: dry-run=$DRY_RUN_PENDING sent=$SENT_COUNT emails=$LEGAL_EMAIL_COUNT deduped"
    else
        step_fail "Legal notice sender: dry_run=$DRY_RUN_PENDING docs=$DRY_RUN_DOCS sent=$SENT_COUNT failed=$FAILED_COUNT emails=$LEGAL_EMAIL_COUNT second_pending=$SECOND_DRY_RUN_PENDING"
    fi
fi

# ── Steps 9-11 setup: helper container joined to the test DB network ──
#
# utils/add-legal-doc-from-website.sh and utils/admin talk to Postgres via
# LOCAL psql (DB_HOST/DB_PORT), but postgres-test has no published host
# port. We run those tools inside a throwaway container attached to the
# same docker network as postgres-test, with a *copy* of just the utils/
# scripts bind-mounted (not the whole repo) so the scripts' own
# "source ../.env" logic finds no .env file and can't pick up unrelated
# host defaults (e.g. an empty INTERNAL_SERVICE_SECRET=) that would
# clobber the values we pass in explicitly.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HARNESS_DIR=""
WEBSITE_DIR=""
WEBSITE_DIR2=""
HARNESS_NAME=""
HARNESS_READY="false"

DOCKER_NETWORK="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$DB_CONTAINER" 2>/dev/null | awk '{print $1}')"

if [[ -z "$DOCKER_NETWORK" ]]; then
    log "Could not determine docker network for $DB_CONTAINER; skipping steps 9-11."
else
    HARNESS_DIR="$(mktemp -d)"
    mkdir -p "$HARNESS_DIR/utils"
    cp "$REPO_ROOT/utils/admin" "$HARNESS_DIR/utils/admin"
    cp "$REPO_ROOT/utils/add-legal-doc-from-website.sh" "$HARNESS_DIR/utils/add-legal-doc-from-website.sh"
    chmod +x "$HARNESS_DIR/utils/admin" "$HARNESS_DIR/utils/add-legal-doc-from-website.sh"

    HARNESS_NAME="legal-e2e-harness-$$"
    WEBSITE_DIR="$(mktemp -d)"
    WEBSITE_DIR2="$(mktemp -d)"

    if docker run -d --name "$HARNESS_NAME" \
        --network "$DOCKER_NETWORK" \
        -v "$HARNESS_DIR:/harness:ro" \
        -v "$WEBSITE_DIR:/website" \
        -v "$WEBSITE_DIR2:/website2" \
        postgres:16-alpine sleep 3600 >/dev/null 2>&1; then
        if docker exec "$HARNESS_NAME" sh -c "apk add --no-cache bash git curl jq >/dev/null 2>&1 && git config --system --add safe.directory '*'"; then
            HARNESS_READY="true"
        else
            log "Failed to install tools in harness container"
        fi
    else
        log "Failed to start harness container"
    fi
fi

harness_run() {
    docker exec \
        -e DB_HOST="$DB_CONTAINER" \
        -e DB_PORT=5432 \
        -e DB_USER=postgres \
        -e DB_PASSWORD=postgres \
        -e DB_NAME="$DB_NAME" \
        -e INTERNAL_SERVICE_SECRET="$INTERNAL_SERVICE_SECRET" \
        -e API_URL="http://api:8080" \
        -w /harness \
        "$HARNESS_NAME" bash "$@"
}

make_website_repo() {
    local dir="$1"
    local content="$2"
    (
        cd "$dir"
        git init -q
        git config user.email "legal-e2e@example.com"
        git config user.name "Legal E2E"
        printf '%s\n' "$content" > terms.md
        git add terms.md
        git commit -q -m "terms update"
    )
    git -C "$dir" rev-parse HEAD
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# ── Step 9: add-legal-doc-from-website.sh ingests + dedupes ───────────

STEP_NUM=9
if [[ "$HARNESS_READY" != "true" ]]; then
    step_fail "Ingest helper: harness container unavailable"
else
    log "Testing add-legal-doc-from-website.sh ingest + dedupe..."

    COMMIT9=$(make_website_repo "$WEBSITE_DIR" "Terms of Service v2099-07-01 (e2e)")
    EXPECTED_SHA9=$(sha256_of "$WEBSITE_DIR/terms.md")

    INGEST9_OUT=$(harness_run utils/add-legal-doc-from-website.sh \
        --website-repo /website \
        --document-type terms_of_service \
        --source-path terms.md \
        --commit "$COMMIT9" \
        --version 2099-07-01 \
        --url https://example.com/terms-2099-07-01.html \
        --effective-at 2099-07-01 2>&1) && INGEST9_STATUS=0 || INGEST9_STATUS=$?

    ROW9=$(db_query "SELECT is_active, content_sha256, source_commit_sha FROM legal_documents WHERE document_type = 'terms_of_service' AND version = '2099-07-01';")
    ROW9_ACTIVE=$(echo "$ROW9" | awk -F'|' '{print $1}')
    ROW9_SHA=$(echo "$ROW9" | awk -F'|' '{print $2}')
    ROW9_COMMIT=$(echo "$ROW9" | awk -F'|' '{print $3}')

    if [[ $INGEST9_STATUS -eq 0 && "$ROW9_ACTIVE" == "f" && "$ROW9_SHA" == "$EXPECTED_SHA9" && "$ROW9_COMMIT" == "$COMMIT9" ]]; then
        step_pass "Ingest: new inactive doc with matching content_sha256 and commit"
    else
        step_fail "Ingest: status=$INGEST9_STATUS active=$ROW9_ACTIVE sha_match=$([[ "$ROW9_SHA" == "$EXPECTED_SHA9" ]] && echo yes || echo no) commit_match=$([[ "$ROW9_COMMIT" == "$COMMIT9" ]] && echo yes || echo no)"
    fi

    STEP_NUM=9
    DEDUPE9_OUT=$(harness_run utils/add-legal-doc-from-website.sh \
        --website-repo /website \
        --document-type terms_of_service \
        --source-path terms.md \
        --commit "$COMMIT9" \
        --version 2099-07-01b \
        --url https://example.com/terms-2099-07-01.html \
        --effective-at 2099-07-01 2>&1) && DEDUPE9_STATUS=0 || DEDUPE9_STATUS=$?

    if [[ $DEDUPE9_STATUS -ne 0 && "$DEDUPE9_OUT" == *"already exists"* ]]; then
        step_pass "Ingest: duplicate content_sha256 rejected"
    else
        step_fail "Ingest: duplicate not rejected (status=$DEDUPE9_STATUS out=$DEDUPE9_OUT)"
    fi
fi

# ── Step 10: admin publish-legal-doc end-to-end ────────────────────────

STEP_NUM=10
if [[ "$HARNESS_READY" != "true" ]]; then
    step_fail "publish-legal-doc: harness container unavailable"
else
    log "Testing admin publish-legal-doc end-to-end..."

    COMMIT10=$(make_website_repo "$WEBSITE_DIR2" "Terms of Service v2099-07-02 (e2e)")

    curl -sf -X DELETE "$EMAIL_EXTERNAL_URL/sent" >/dev/null 2>&1 || true

    PUBLISH10_OUT=$(harness_run utils/admin publish-legal-doc \
        --website-repo /website2 \
        --document-type terms_of_service \
        --source-path terms.md \
        --commit "$COMMIT10" \
        --version 2099-07-02 \
        --url https://example.com/terms-2099-07-02.html \
        --effective-at 2099-07-02 \
        --blocking true \
        --confirm 2>&1) && PUBLISH10_STATUS=0 || PUBLISH10_STATUS=$?

    DOC10_ID=$(printf '%s\n' "$PUBLISH10_OUT" | awk -F': *' '/^[[:space:]]*id:/ {print $2; exit}')
    ACTIVE_TOS10=$(db_query "SELECT version FROM legal_documents WHERE document_type = 'terms_of_service' AND is_active = true;")

    if [[ $PUBLISH10_STATUS -eq 0 && "$ACTIVE_TOS10" == "2099-07-02" ]]; then
        step_pass "publish-legal-doc: new TOS version activated (id=$DOC10_ID)"
    else
        step_fail "publish-legal-doc: status=$PUBLISH10_STATUS active=$ACTIVE_TOS10 out=$PUBLISH10_OUT"
    fi

    STEP_NUM=10
    STATUS10=$(curl -sf "$GATEWAY_URL/api/user/status" -H "X-Session-ID: $SESSION_ID")
    TOS_ACTION10=$(echo "$STATUS10" | jq -r '.legal.terms_of_service.requires_action')
    TOS_ACTIVE10=$(echo "$STATUS10" | jq -r '.legal.terms_of_service.active_version')

    if [[ "$TOS_ACTION10" == "true" && "$TOS_ACTIVE10" == "2099-07-02" ]]; then
        step_pass "publish-legal-doc: tracked user now requires_action=true"
    else
        step_fail "publish-legal-doc: requires_action=$TOS_ACTION10 active=$TOS_ACTIVE10"
    fi

    STEP_NUM=10
    ACCEPT10_RESPONSE=$(curl -sf -X POST "$GATEWAY_URL/api/legal/accept" \
        -H "X-Session-ID: $SESSION_ID" \
        -H "Content-Type: application/json" \
        -d '{"document_type": "terms_of_service"}')
    ACCEPT10_SUCCESS=$(echo "$ACCEPT10_RESPONSE" | jq -r '.success')
    ACCEPT10_VERSION=$(echo "$ACCEPT10_RESPONSE" | jq -r '.version')
    TOS_ACTION10B=$(echo "$ACCEPT10_RESPONSE" | jq -r '.legal.terms_of_service.requires_action')
    EVENT10_COUNT=$(db_query "SELECT COUNT(*) FROM user_legal_events WHERE user_id = '$USER_ID' AND document_version = '2099-07-02' AND occurred_at IS NOT NULL;")

    if [[ "$ACCEPT10_SUCCESS" == "true" && "$ACCEPT10_VERSION" == "2099-07-02" && "$TOS_ACTION10B" == "false" && "$EVENT10_COUNT" -ge 1 ]]; then
        step_pass "publish-legal-doc: accept clears requires_action and records event"
    else
        step_fail "publish-legal-doc accept: success=$ACCEPT10_SUCCESS version=$ACCEPT10_VERSION action=$TOS_ACTION10B events=$EVENT10_COUNT"
    fi

    STEP_NUM=10
    LEGAL_EMAIL_COUNT10=$(curl -sf "$EMAIL_EXTERNAL_URL/sent?template=legal_notice" 2>/dev/null | jq '.count // 0')

    SECOND_NOTIFY10_PENDING="unknown"
    if [[ -n "$DOC10_ID" ]]; then
        # Re-run notify through admin; dedupe must prevent a second email.
        harness_run utils/admin send-legal-notices "$DOC10_ID" --send --confirm >/dev/null 2>&1 || true
        # Read pending count from a clean API dry-run (admin pretty-prints,
        # so its stdout is not reliably line-parseable JSON).
        SECOND_NOTIFY10_PENDING=$(curl -s -X POST "$API_URL/internal/legal-notices/send" \
            -H "X-Internal-Service-Secret: $INTERNAL_SERVICE_SECRET" \
            -H "Content-Type: application/json" \
            -d "{\"dry_run\":true,\"document_ids\":[\"$DOC10_ID\"]}" 2>/dev/null \
            | jq -r '.pending_recipient_count // "unknown"') || SECOND_NOTIFY10_PENDING="unknown"
    fi
    LEGAL_EMAIL_COUNT10B=$(curl -sf "$EMAIL_EXTERNAL_URL/sent?template=legal_notice" 2>/dev/null | jq '.count // 0')

    if [[ "$LEGAL_EMAIL_COUNT10" -eq 1 && "$SECOND_NOTIFY10_PENDING" == "0" && "$LEGAL_EMAIL_COUNT10B" -eq "$LEGAL_EMAIL_COUNT10" ]]; then
        step_pass "publish-legal-doc: notice email sent exactly once and second run dedupes"
    else
        step_fail "publish-legal-doc email: first=$LEGAL_EMAIL_COUNT10 second_pending=$SECOND_NOTIFY10_PENDING second_total=$LEGAL_EMAIL_COUNT10B"
    fi
fi

# ── Step 11: signup event recording unaffected ─────────────────────────

STEP_NUM=11
log "Testing signup event recording is unaffected..."

SIGNUP_EVENT_COUNT=$(db_query "SELECT COUNT(*) FROM user_legal_events WHERE user_id = '$USER_ID' AND event_source = 'signup';")

if [[ "$SIGNUP_EVENT_COUNT" -ge 2 ]]; then
    step_pass "Signup events unaffected by admin tooling: $SIGNUP_EVENT_COUNT signup-sourced rows remain"
else
    step_fail "Signup events: expected >=2 signup-sourced rows, found $SIGNUP_EVENT_COUNT"
fi

log "All legal tracking tests complete."
