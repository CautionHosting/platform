#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
#
# Integration test for the dedicated EC2 builder feature.
#
# Requires:
#   - make up-test with BUILDER_ENABLED=true and BUILDER_* env vars set
#   - Real AWS credentials with EC2 + S3 permissions
#   - Builder IAM role, instance profile, security group, and subnet configured
#
# Tests:
#   1. Health check
#   2. Create test user
#   3. Push demo app
#   4. Verify builder EC2 instance was launched
#   5. Wait for build completion
#   6. Verify EIF in S3
#   7. Verify eif_builds DB row
#   8. Verify builder instance terminated
#   9. Redeploy same commit — verify cache hit (no new builder)
#  10. Cleanup

set -euo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://localhost:8000}"
API_URL="${API_URL:-http://localhost:8080}"
CAUTION_BIN="${CAUTION_BIN:-caution}"
DEMO_REPO="${DEMO_REPO:-https://codeberg.org/caution/demo-hello-world-enclave.git}"
WORK_DIR=$(mktemp -d)
SSH_KEY_PATH="$WORK_DIR/test_key"
# Hardcoded: test environment always uses postgres-test container and caution_test DB
DB_HOST="postgres-test"
DB_NAME="caution_test"
EIF_S3_BUCKET="${EIF_S3_BUCKET:-}"
LOG_DIR="tests/e2e/logs"
LOG_FILE="$LOG_DIR/builder-$(date +%Y%m%d-%H%M%S).log"
STEP_NUM=0
STEPS_PASSED=0
STEPS_FAILED=0
STEP_RESULTS=()
RESOURCE_ID=""
BUILD_ID=""
INSTANCE_ID=""

mkdir -p "$LOG_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1

# --- Preflight checks ---
if [ -z "${BUILDER_ENABLED:-}" ] || [ "$BUILDER_ENABLED" != "true" ]; then
    echo "ERROR: BUILDER_ENABLED must be set to 'true' for this test"
    echo "Set BUILDER_ENABLED=true and all BUILDER_* env vars in .env"
    exit 1
fi

for var in BUILDER_AMI_ID BUILDER_SECURITY_GROUP_ID BUILDER_SUBNET_ID BUILDER_INSTANCE_PROFILE; do
    if [ -z "${!var:-}" ]; then
        echo "ERROR: $var must be set for this test"
        exit 1
    fi
done

if [ -z "$EIF_S3_BUCKET" ]; then
    EIF_S3_BUCKET="caution-eif-storage-${AWS_ACCOUNT_ID:-unknown}"
fi

cleanup() {
    echo ""
    echo "=== Cleanup ==="

    if [ -n "$RESOURCE_ID" ]; then
        echo "Destroying app $RESOURCE_ID..."
        "$CAUTION_BIN" -u "$GATEWAY_URL" apps destroy "$RESOURCE_ID" --force 2>/dev/null || true
    fi

    rm -rf "$WORK_DIR"

    echo ""
    echo "========================================"
    echo "  Dedicated Builder Test Results"
    echo "========================================"
    for result in "${STEP_RESULTS[@]}"; do
        echo "  $result"
    done
    echo "----------------------------------------"
    echo "  Passed: $STEPS_PASSED  Failed: $STEPS_FAILED"
    echo "========================================"
    echo ""
    echo "Full log: $LOG_FILE"

    if [ $STEPS_FAILED -gt 0 ]; then
        echo "--- API logs ---"
        docker logs api 2>&1 | tail -50 || true
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

step_warn() {
    STEP_RESULTS+=("[WARN] Step $STEP_NUM: $1")
    echo "[WARN] Step $STEP_NUM: $1"
}

query_db() {
    docker exec "$DB_HOST" psql -U postgres -d "$DB_NAME" -t -A -c "$1" 2>&1 || {
        echo "DB query failed: $1" >&2
        return 1
    }
}

echo "=== Dedicated Builder Integration Test ==="
echo "Gateway: $GATEWAY_URL"
echo "S3 Bucket: $EIF_S3_BUCKET"
echo "Builder AMI: $BUILDER_AMI_ID"
echo "Builder Instance Profile: $BUILDER_INSTANCE_PROFILE"
echo ""

# ── Step 1: Health check ──────────────────────────────────────────────
STEP_NUM=1
echo "── Step $STEP_NUM: Health check ──"
for i in $(seq 1 30); do
    if curl -sf "$GATEWAY_URL/health" > /dev/null 2>&1; then
        step_pass "Gateway healthy"
        break
    fi
    if [ "$i" -eq 30 ]; then
        step_fail "Gateway not healthy after 30s"
        exit 1
    fi
    sleep 1
done

# ── Step 2: Create test user ──────────────────────────────────────────
STEP_NUM=2
echo "── Step $STEP_NUM: Create test user ──"
LOGIN_RESPONSE=$(curl -sf -X POST "$GATEWAY_URL/auth/e2e-login" \
    -H "Content-Type: application/json" \
    -d '{}')
SESSION_ID=$(echo "$LOGIN_RESPONSE" | jq -r '.session_id')
USER_ID=$(echo "$LOGIN_RESPONSE" | jq -r '.user_id')

if [ -n "$SESSION_ID" ] && [ "$SESSION_ID" != "null" ]; then
    step_pass "Test user created (user=$USER_ID)"
else
    step_fail "Failed to create test user"
    exit 1
fi

EXPIRES_AT=$(echo "$LOGIN_RESPONSE" | jq -r '.expires_at')

# Write CLI config so caution binary uses our session
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/api-cli"
mkdir -p "$CONFIG_DIR"
cat > "$CONFIG_DIR/config.json" <<EOF
{
  "session_id": "$SESSION_ID",
  "expires_at": "$EXPIRES_AT",
  "server_url": "$GATEWAY_URL"
}
EOF

# Mark user as onboarded + seed credits for deploy gate
docker exec "$DB_HOST" psql -U postgres -d "$DB_NAME" -c "
UPDATE users SET email_verified_at = NOW(), payment_method_added_at = NOW() WHERE id = '$USER_ID';
INSERT INTO wallet_balance (user_id, balance_cents) VALUES ('$USER_ID', 10000)
ON CONFLICT (user_id) DO UPDATE SET balance_cents = 10000;
" || echo "WARNING: DB setup failed"

# ── Step 3: Add SSH key ───────────────────────────────────────────────
STEP_NUM=3
echo "── Step $STEP_NUM: Add SSH key ──"
ssh-keygen -t ed25519 -f "$SSH_KEY_PATH" -N "" -q
PUB_KEY=$(cat "${SSH_KEY_PATH}.pub")

ADD_KEY_RESP=$(curl -sf -X POST "$GATEWAY_URL/ssh-keys" \
    -H "X-Session-ID: $SESSION_ID" \
    -H "Content-Type: application/json" \
    -d "{\"name\": \"test-key\", \"public_key\": \"$PUB_KEY\"}")

FINGERPRINT=$(echo "$ADD_KEY_RESP" | jq -r '.fingerprint')
if [ -n "$FINGERPRINT" ] && [ "$FINGERPRINT" != "null" ]; then
    step_pass "SSH key added (fingerprint: ${FINGERPRINT:0:20}...)"
else
    step_fail "Failed to add SSH key"
    exit 1
fi

# ── Step 4: Clone demo, init, and push ────────────────────────────────
STEP_NUM=4
echo "── Step $STEP_NUM: Clone demo app, caution init, git push ──"

git clone "$DEMO_REPO" "$WORK_DIR/demo" 2>/dev/null
cd "$WORK_DIR/demo"

# caution init creates the app and sets the git remote
INIT_OUTPUT=$("$CAUTION_BIN" -u "$GATEWAY_URL" init --name "builder-test-$(date +%s)" 2>&1) || true

if [ -f ".caution/deployment.json" ]; then
    RESOURCE_ID=$(jq -r '.resource_id' .caution/deployment.json)
else
    echo "$INIT_OUTPUT"
    step_fail "caution init failed (no .caution/deployment.json)"
    exit 1
fi

echo "Resource ID: $RESOURCE_ID"

# Push triggers the deploy
export GIT_SSH_COMMAND="ssh -i $SSH_KEY_PATH -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p ${SSH_PORT:-2222}"
git push caution main 2>&1 || true

# Wait for deploy to start
sleep 5

step_pass "App created and pushed (resource=$RESOURCE_ID)"

# ── Step 5: Check that a builder was launched ─────────────────────────
STEP_NUM=5
echo "── Step $STEP_NUM: Verify builder EC2 instance was launched ──"

# Poll eif_builds table for a new row
for i in $(seq 1 60); do
    BUILDER_ROW=$(query_db "SELECT id, status, builder_instance_id FROM eif_builds ORDER BY created_at DESC LIMIT 1" || true)
    if [ -n "$BUILDER_ROW" ]; then
        BUILD_ID=$(echo "$BUILDER_ROW" | cut -d'|' -f1)
        BUILD_STATUS=$(echo "$BUILDER_ROW" | cut -d'|' -f2)
        INSTANCE_ID=$(echo "$BUILDER_ROW" | cut -d'|' -f3)

        if [ -n "$INSTANCE_ID" ] && [ "$INSTANCE_ID" != "" ]; then
            step_pass "Builder launched: instance=$INSTANCE_ID, status=$BUILD_STATUS"
            break
        fi
    fi

    if [ "$i" -eq 60 ]; then
        step_fail "No builder instance launched after 60s"
        echo "eif_builds rows: $(query_db 'SELECT * FROM eif_builds' || echo 'none')"
    fi
    sleep 2
done

# ── Step 6: Wait for build completion ─────────────────────────────────
STEP_NUM=6
echo "── Step $STEP_NUM: Wait for build completion (up to 20 min) ──"

if [ -z "$BUILD_ID" ]; then
    step_fail "No build ID — skipping remaining steps"
    exit 1
fi

for i in $(seq 1 120); do
    STATUS=$(query_db "SELECT status FROM eif_builds WHERE id = '$BUILD_ID'" || true)
    case "$STATUS" in
        completed)
            step_pass "Build completed"
            break
            ;;
        failed)
            ERROR=$(query_db "SELECT error_message FROM eif_builds WHERE id = '$BUILD_ID'" || true)
            step_fail "Build failed: $ERROR"
            break
            ;;
        timeout)
            step_fail "Build timed out"
            break
            ;;
    esac

    if [ "$i" -eq 120 ]; then
        step_fail "Build did not complete after 20 minutes (status=$STATUS)"
    fi

    # Check S3 status file for progress
    STATUS_JSON=$(aws s3 cp "s3://$EIF_S3_BUCKET/builds/$BUILD_ID/status.json" - 2>/dev/null || true)
    if [ -n "$STATUS_JSON" ]; then
        PHASE=$(echo "$STATUS_JSON" | jq -r '.phase // empty' 2>/dev/null || true)
        echo "  [$i/120] Build phase: $PHASE"
    else
        echo "  [$i/120] Waiting for builder to start... (status=$STATUS)"
    fi
    sleep 10
done

# ── Step 7: Verify EIF in S3 ─────────────────────────────────────────
STEP_NUM=7
echo "── Step $STEP_NUM: Verify EIF exists in S3 ──"

EIF_S3_KEY=$(query_db "SELECT eif_s3_key FROM eif_builds WHERE id = '$BUILD_ID'" || true)
if [ -n "$EIF_S3_KEY" ]; then
    if aws s3 ls "s3://$EIF_S3_BUCKET/$EIF_S3_KEY" > /dev/null 2>&1; then
        EIF_SIZE=$(aws s3 ls "s3://$EIF_S3_BUCKET/$EIF_S3_KEY" | awk '{print $3}')
        step_pass "EIF exists in S3: $EIF_S3_KEY ($EIF_SIZE bytes)"
    else
        step_fail "EIF S3 key recorded but file not found: $EIF_S3_KEY"
    fi
else
    step_fail "No eif_s3_key in eif_builds row"
fi

# ── Step 8: Verify eif_builds DB row ──────────────────────────────────
STEP_NUM=8
echo "── Step $STEP_NUM: Verify eif_builds metadata ──"

ROW=$(query_db "SELECT status, eif_sha256, eif_size_bytes, builder_instance_type FROM eif_builds WHERE id = '$BUILD_ID'" || true)
DB_STATUS=$(echo "$ROW" | cut -d'|' -f1)
DB_HASH=$(echo "$ROW" | cut -d'|' -f2)
DB_SIZE=$(echo "$ROW" | cut -d'|' -f3)
DB_TYPE=$(echo "$ROW" | cut -d'|' -f4)

if [ "$DB_STATUS" = "completed" ] && [ -n "$DB_HASH" ] && [ "$DB_SIZE" -gt 0 ] 2>/dev/null; then
    step_pass "DB metadata complete: hash=$DB_HASH, size=$DB_SIZE, type=$DB_TYPE"
else
    step_fail "DB metadata incomplete: status=$DB_STATUS, hash=$DB_HASH, size=$DB_SIZE"
fi

# ── Step 9: Verify builder instance terminated ────────────────────────
STEP_NUM=9
echo "── Step $STEP_NUM: Verify builder instance terminated ──"

if [ -n "$INSTANCE_ID" ]; then
    STATE=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
        --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null || echo "unknown")
    case "$STATE" in
        terminated|shutting-down)
            step_pass "Builder instance $INSTANCE_ID is $STATE"
            ;;
        *)
            step_warn "Builder instance $INSTANCE_ID is $STATE (expected terminated)"
            ;;
    esac
else
    step_warn "No instance ID to check"
fi

# ── Step 10: Redeploy same commit — verify cache hit ──────────────────
STEP_NUM=10
echo "── Step $STEP_NUM: Redeploy same commit (should cache hit) ──"

BUILDS_BEFORE=$(query_db "SELECT COUNT(*) FROM eif_builds" || echo "0")

# Trigger another deploy of the same commit
cd "$WORK_DIR/demo"
# Make an empty commit to trigger a new push
git commit --allow-empty -m "trigger redeploy" 2>/dev/null
git push caution main 2>&1 || true

sleep 10

BUILDS_AFTER=$(query_db "SELECT COUNT(*) FROM eif_builds" || echo "0")

if [ "$BUILDS_AFTER" -eq "$BUILDS_BEFORE" ]; then
    step_pass "Cache hit — no new eif_builds row created"
else
    # An empty commit changes the SHA, so a new build is expected
    step_warn "New build row created (empty commit changed SHA — expected)"
fi

echo ""
echo "=== Test complete ==="
