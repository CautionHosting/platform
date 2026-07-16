#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
#
# E2E test for Paddle-backed BYOC subscription projection.
# Requires: make up-test-billing with the Paddle subscription pricing fixture.

set -euo pipefail

GATEWAY_URL="${GATEWAY_URL:-http://127.0.0.1:8000}"
METERING_URL="${METERING_URL:-http://127.0.0.1:8083}"
DB_CONTAINER="${DB_CONTAINER:-postgres-test}"
DB_NAME="${DB_NAME:-caution_test}"

pass() { printf '[PASS] %s\n' "$1"; }
fail() { printf '[FAIL] %s\n' "$1" >&2; exit 1; }
db() { docker exec "$DB_CONTAINER" psql -U postgres -d "$DB_NAME" -Atqc "$1"; }
new_uuid() { tr -d '\n' </proc/sys/kernel/random/uuid; }

wait_for() {
  local name=$1 url=$2
  for _ in $(seq 1 60); do
    curl --fail --silent --show-error --max-time 2 "$url" >/dev/null 2>&1 && return 0
    sleep 1
  done
  fail "$name did not become healthy"
}

send_webhook() {
  local payload=$1 expected_status=${2:-processed}
  local timestamp signature response
  timestamp=$(date +%s)
  signature=$(PADDLE_WEBHOOK_SECRET="$PADDLE_WEBHOOK_SECRET" \
    PADDLE_WEBHOOK_TIMESTAMP="$timestamp" \
    python3 - "$payload" <<'PY'
import hashlib, hmac, os, pathlib, sys
body = pathlib.Path(sys.argv[1]).read_bytes()
message = os.environ["PADDLE_WEBHOOK_TIMESTAMP"].encode() + b":" + body
print(hmac.new(os.environ["PADDLE_WEBHOOK_SECRET"].encode(), message, hashlib.sha256).hexdigest())
PY
  )
  response=$(curl --fail --silent --show-error --max-time 10 \
    -H 'Content-Type: application/json' \
    -H "Paddle-Signature: ts=$timestamp;h1=$signature" \
    --data-binary "@$payload" \
    "$METERING_URL/webhooks/paddle")
  jq -e --arg expected "$expected_status" '.status == $expected' <<<"$response" >/dev/null
}

payload() {
  local path=$1 event_id=$2 event_type=$3 occurred_at=$4 status=$5 intent_field=$6 intent_id=$7
  EVENT_ID="$event_id" EVENT_TYPE="$event_type" OCCURRED_AT="$occurred_at" \
  SUBSCRIPTION_STATUS="$status" INTENT_FIELD="$intent_field" INTENT_ID="$intent_id" \
  ORG_ID="$ORG_ID" python3 - "$path" <<'PY'
import json, os, pathlib, sys
custom = {
    "caution_operation": "byoc_subscription",
    "caution_organization_id": os.environ["ORG_ID"],
    "caution_tier_id": "2_enclaves",
}
field = os.environ["INTENT_FIELD"]
if field:
    custom[field] = os.environ["INTENT_ID"]
data = {
    "id": "sub_e2e_byoc",
    "customer_id": "ctm_e2e_byoc",
    "status": os.environ["SUBSCRIPTION_STATUS"],
    "items": [{"price": {"id": "pri_e2e_2"}}],
    "current_billing_period": {
        "starts_at": "2026-07-01T00:00:00Z",
        "ends_at": "2026-08-01T00:00:00Z",
    },
    "scheduled_change": None,
    "custom_data": custom,
}
body = {
    "event_id": os.environ["EVENT_ID"],
    "event_type": os.environ["EVENT_TYPE"],
    "occurred_at": os.environ["OCCURRED_AT"],
    "data": data,
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(body, separators=(",", ":")))
PY
}

wait_for gateway "$GATEWAY_URL/health"
wait_for metering "$METERING_URL/health"
pass 'gateway and metering are healthy'

LOGIN=$(curl --fail --silent --show-error -X POST "$GATEWAY_URL/auth/e2e-login" -H 'Content-Type: application/json')
SESSION_ID=$(jq -er '.session_id' <<<"$LOGIN")
USER_ID=$(jq -er '.user_id' <<<"$LOGIN")
[[ $USER_ID =~ ^[0-9a-f-]{36}$ ]] || fail 'e2e login returned an invalid user ID'
ORG_ID=$(db "SELECT organization_id FROM organization_members WHERE user_id = '$USER_ID' LIMIT 1")
if [[ -z $ORG_ID ]]; then
  ORG_ID=$(db "INSERT INTO organizations (name) VALUES ('paddle-subscriptions-e2e') RETURNING id")
  db "INSERT INTO organization_members (organization_id, user_id, role) VALUES ('$ORG_ID', '$USER_ID', 'owner')"
fi
[[ $ORG_ID =~ ^[0-9a-f-]{36}$ ]] || fail 'could not create an organization for the e2e user'
db "UPDATE users SET email_verified_at = NOW(), payment_method_added_at = NOW() WHERE id = '$USER_ID'"
pass 'created an authenticated organization owner'

PADDLE_WEBHOOK_SECRET=$(docker inspect metering | python3 -c '
import json, sys
for value in json.load(sys.stdin)[0]["Config"]["Env"]:
    if value.startswith("PADDLE_WEBHOOK_SECRET="):
        print(value.split("=", 1)[1])
        break
')
[[ -n $PADDLE_WEBHOOK_SECRET ]] || fail 'metering has no Paddle webhook secret'

CHECKOUT_INTENT_ID=$(new_uuid)
db "INSERT INTO subscription_intents
    (id, organization_id, requested_by_user_id, operation, new_tier, new_limit, status)
    VALUES ('$CHECKOUT_INTENT_ID', '$ORG_ID', '$USER_ID', 'subscribe', '2_enclaves', 2, 'provider_pending')"

TMP_DIR=$(mktemp -d /tmp/caution-paddle-e2e.XXXXXX)
trap 'rm -rf "$TMP_DIR"' EXIT
CREATED_AT='2026-07-13T12:00:00Z'
payload "$TMP_DIR/created.json" 'evt_e2e_created' 'subscription.created' "$CREATED_AT" 'active' 'caution_checkout_intent_id' "$CHECKOUT_INTENT_ID"
send_webhook "$TMP_DIR/created.json"

PROJECTED=$(db "SELECT billing_source || '|' || tier || '|' || max_apps || '|' || status || '|' || catalog_valid
                FROM subscriptions WHERE paddle_subscription_id = 'sub_e2e_byoc'")
[[ $PROJECTED == 'paddle|2_enclaves|2|active|true' ]] || fail "unexpected subscription projection: $PROJECTED"
INTENT_STATUS=$(db "SELECT status FROM subscription_intents WHERE id = '$CHECKOUT_INTENT_ID'")
[[ $INTENT_STATUS == 'applied' ]] || fail "checkout intent was not applied: $INTENT_STATUS"
pass 'signed subscription.created projected the catalog entitlement and applied its intent'

API_SUBSCRIPTION=$(curl --fail --silent --show-error "$GATEWAY_URL/api/billing/subscription" -H "X-Session-ID: $SESSION_ID")
jq -e '.subscription.source == "paddle" and .subscription.tier_id == "2_enclaves" and .subscription.enclave_limit == 2 and .subscription.status == "active"' \
  <<<"$API_SUBSCRIPTION" >/dev/null || fail 'subscription API did not expose the projected entitlement'
pass 'authenticated subscription API returned the Paddle entitlement'

# An older cancellation must not regress the provider projection or apply an intent.
STALE_CANCEL_INTENT_ID=$(new_uuid)
db "INSERT INTO subscription_intents
    (id, organization_id, requested_by_user_id, operation, subscription_id, paddle_subscription_id, status)
    SELECT '$STALE_CANCEL_INTENT_ID', '$ORG_ID', '$USER_ID', 'cancel', id, 'sub_e2e_byoc', 'provider_pending'
    FROM subscriptions WHERE paddle_subscription_id = 'sub_e2e_byoc'"
payload "$TMP_DIR/stale.json" 'evt_e2e_stale' 'subscription.canceled' '2026-07-13T11:59:59Z' 'canceled' '' ''
send_webhook "$TMP_DIR/stale.json"
[[ $(db "SELECT status FROM subscriptions WHERE paddle_subscription_id = 'sub_e2e_byoc'") == 'active' ]] || fail 'older event regressed subscription state'
[[ $(db "SELECT status FROM subscription_intents WHERE id = '$STALE_CANCEL_INTENT_ID'") == 'provider_pending' ]] || fail 'older event incorrectly applied cancellation intent'
pass 'older provider event was ignored without applying workflow side effects'

db "UPDATE subscription_intents SET status = 'canceled' WHERE id = '$STALE_CANCEL_INTENT_ID'"
CANCEL_INTENT_ID=$(new_uuid)
db "INSERT INTO subscription_intents
    (id, organization_id, requested_by_user_id, operation, subscription_id, paddle_subscription_id, status)
    SELECT '$CANCEL_INTENT_ID', '$ORG_ID', '$USER_ID', 'cancel', id, 'sub_e2e_byoc', 'provider_pending'
    FROM subscriptions WHERE paddle_subscription_id = 'sub_e2e_byoc'"
payload "$TMP_DIR/canceled.json" 'evt_e2e_canceled' 'subscription.canceled' "$CREATED_AT" 'canceled' '' ''
send_webhook "$TMP_DIR/canceled.json"
[[ $(db "SELECT status FROM subscriptions WHERE paddle_subscription_id = 'sub_e2e_byoc'") == 'canceled' ]] || fail 'equal-time cancellation did not win fail-closed precedence'
[[ $(db "SELECT status FROM subscription_intents WHERE id = '$CANCEL_INTENT_ID'") == 'applied' ]] || fail 'cancellation intent was not applied'
pass 'equal-time cancellation won fail-closed precedence and applied its intent'

send_webhook "$TMP_DIR/canceled.json" 'already_processed'
EVENT_COUNT=$(db "SELECT COUNT(*) FROM paddle_webhook_events WHERE event_id = 'evt_e2e_canceled'")
SUBSCRIPTION_COUNT=$(db "SELECT COUNT(*) FROM subscriptions WHERE paddle_subscription_id = 'sub_e2e_byoc'")
[[ $EVENT_COUNT == 1 && $SUBSCRIPTION_COUNT == 1 ]] || fail 'duplicate webhook was not idempotent'
pass 'duplicate webhook delivery was idempotent'

NULL_RESPONSE=$(curl --fail --silent --show-error "$GATEWAY_URL/api/billing/subscription" -H "X-Session-ID: $SESSION_ID")
jq -e '.subscription == null' <<<"$NULL_RESPONSE" >/dev/null || fail 'canceled subscription remained visible as active'
pass 'canceled subscription is no longer returned as an active entitlement'

printf 'Paddle subscription e2e: PASS\n'
