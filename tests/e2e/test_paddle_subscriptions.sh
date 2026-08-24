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
  local scheduled_action=${8:-}
  local subscription_id=${9:-sub_e2e_byoc}
  EVENT_ID="$event_id" EVENT_TYPE="$event_type" OCCURRED_AT="$occurred_at" \
  SUBSCRIPTION_STATUS="$status" INTENT_FIELD="$intent_field" INTENT_ID="$intent_id" \
  SCHEDULED_ACTION="$scheduled_action" \
  ORG_ID="$ORG_ID" SUBSCRIPTION_ID="$subscription_id" python3 - "$path" <<'PY'
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
    "id": os.environ["SUBSCRIPTION_ID"],
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
if os.environ["SCHEDULED_ACTION"]:
    data["scheduled_change"] = {
        "action": os.environ["SCHEDULED_ACTION"],
        "effective_at": "2026-08-01T00:00:00Z",
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

payment_failed_payload() {
  local path=$1 event_id=$2 occurred_at=$3 transaction_id=$4
  EVENT_ID="$event_id" OCCURRED_AT="$occurred_at" TRANSACTION_ID="$transaction_id" python3 - "$path" <<'PY'
import json, os, pathlib, sys
body = {
    "event_id": os.environ["EVENT_ID"],
    "event_type": "transaction.payment_failed",
    "occurred_at": os.environ["OCCURRED_AT"],
    "data": {
        "id": os.environ["TRANSACTION_ID"],
        "customer_id": "ctm_e2e_byoc",
    },
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

# A webhook carrying a tier intent must match that intent's exact persisted
# provider payload before it can clear the fail-closed pending projection.
MISMATCHED_CHANGE_INTENT_ID=$(new_uuid)
db "INSERT INTO subscription_intents
    (id, organization_id, requested_by_user_id, operation, subscription_id,
     paddle_subscription_id, old_tier, new_tier, old_limit, new_limit, status,
     provider_price_id, provider_price_cents_per_cycle, provider_proration_mode)
    SELECT '$MISMATCHED_CHANGE_INTENT_ID', '$ORG_ID', '$USER_ID', 'downgrade', id,
           'sub_e2e_byoc', '2_enclaves', '1_enclave', 2, 1, 'provider_pending',
           'pri_e2e_1', 1000, 'do_not_bill'
    FROM subscriptions WHERE paddle_subscription_id = 'sub_e2e_byoc';
    UPDATE subscriptions SET pending_tier = '1_enclave', pending_max_apps = 1
    WHERE paddle_subscription_id = 'sub_e2e_byoc'"
payload "$TMP_DIR/mismatched-change.json" 'evt_e2e_mismatched_change' 'subscription.updated' \
    '2026-07-13T12:00:20Z' 'active' 'caution_change_intent_id' "$MISMATCHED_CHANGE_INTENT_ID"
send_webhook "$TMP_DIR/mismatched-change.json"
[[ $(db "SELECT status FROM subscription_intents WHERE id = '$MISMATCHED_CHANGE_INTENT_ID'") == 'provider_pending' ]] || fail 'mismatched webhook incorrectly applied tier intent'
[[ $(db "SELECT pending_tier || '|' || pending_max_apps FROM subscriptions WHERE paddle_subscription_id = 'sub_e2e_byoc'") == '1_enclave|1' ]] || fail 'mismatched webhook cleared pending tier projection'
db "UPDATE subscription_intents SET status = 'canceled' WHERE id = '$MISMATCHED_CHANGE_INTENT_ID'"
pass 'tier intent finalization requires the exact persisted provider payload'

# A pending downgrade is fail-closed: an unrelated active event for the old
# tier cannot restore the old, higher limit.
db "UPDATE subscriptions SET pending_tier = '1_enclave', pending_max_apps = 1
    WHERE paddle_subscription_id = 'sub_e2e_byoc'"
[[ $(db "SELECT enclave_limit FROM self_managed_plans WHERE organization_id = '$ORG_ID'") == 1 ]] || fail 'pending downgrade did not lower capacity immediately'
payload "$TMP_DIR/unrelated-active.json" 'evt_e2e_unrelated_active' 'subscription.updated' \
    '2026-07-13T12:00:30Z' 'active' '' ''
send_webhook "$TMP_DIR/unrelated-active.json"
[[ $(db "SELECT enclave_limit FROM self_managed_plans WHERE organization_id = '$ORG_ID'") == 1 ]] || fail 'unrelated active event reopened pending downgrade capacity'
db "UPDATE subscriptions SET pending_tier = NULL, pending_max_apps = NULL
    WHERE paddle_subscription_id = 'sub_e2e_byoc';
    UPDATE self_managed_plans SET enclave_limit = 2 WHERE organization_id = '$ORG_ID'"
pass 'pending downgrade remains fail-closed across unrelated active events'

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

payload "$TMP_DIR/paused.json" 'evt_e2e_paused' 'subscription.updated' \
    '2026-07-13T12:10:00Z' 'paused' '' ''
send_webhook "$TMP_DIR/paused.json"
[[ $(db "SELECT s.status || '|' || p.enclave_limit
    FROM subscriptions s JOIN self_managed_plans p ON p.id = s.self_managed_plan_id
    WHERE s.paddle_subscription_id = 'sub_e2e_byoc'") == 'paused|0' ]] || fail 'paused Paddle subscription retained capacity'

payload "$TMP_DIR/reactivated.json" 'evt_e2e_reactivated' 'subscription.updated' \
    '2026-07-13T12:11:00Z' 'active' '' ''
send_webhook "$TMP_DIR/reactivated.json"
[[ $(db "SELECT enclave_limit FROM self_managed_plans WHERE organization_id = '$ORG_ID'") == 2 ]] || fail 'reactivated Paddle subscription did not restore capacity'

# Transaction failures share subscription event ordering: an older failure must
# not regress newer active authority, while a newer failure disables capacity.
FAILURE_INVOICE_ID=$(new_uuid)
FAILURE_TRANSACTION_ID='txn_e2e_payment_failure'
db "INSERT INTO invoices
    (id, paddle_transaction_id, user_id, organization_id, invoice_number,
     amount_cents, tax_amount_cents, currency, status, payment_status, billing_provider)
    VALUES ('$FAILURE_INVOICE_ID', '$FAILURE_TRANSACTION_ID', '$USER_ID', '$ORG_ID',
            'E2E-FAILURE', 1000, 0, 'USD', 'finalized', 'pending', 'paddle');
    INSERT INTO subscription_ledger
    (subscription_id, organization_id, billing_period_start, billing_period_end,
     tier, cost_hourly, invoice_id, status)
    SELECT id, '$ORG_ID', TIMESTAMPTZ '2026-07-01T00:00:00Z',
           TIMESTAMPTZ '2026-08-01T00:00:00Z', tier, 0.10,
           '$FAILURE_INVOICE_ID', 'credits_covered'
    FROM subscriptions WHERE paddle_subscription_id = 'sub_e2e_byoc'"
payment_failed_payload "$TMP_DIR/stale-payment-failed.json" 'evt_e2e_stale_payment_failed' \
    '2026-07-13T12:10:30Z' "$FAILURE_TRANSACTION_ID"
send_webhook "$TMP_DIR/stale-payment-failed.json"
[[ $(db "SELECT s.status || '|' || p.enclave_limit
    FROM subscriptions s JOIN self_managed_plans p ON p.id = s.self_managed_plan_id
    WHERE s.paddle_subscription_id = 'sub_e2e_byoc'") == 'active|2' ]] || fail 'stale payment failure regressed active authority'
payment_failed_payload "$TMP_DIR/payment-failed.json" 'evt_e2e_payment_failed' \
    '2026-07-13T12:11:30Z' "$FAILURE_TRANSACTION_ID"
send_webhook "$TMP_DIR/payment-failed.json"
[[ $(db "SELECT s.status || '|' || p.enclave_limit
    FROM subscriptions s JOIN self_managed_plans p ON p.id = s.self_managed_plan_id
    WHERE s.paddle_subscription_id = 'sub_e2e_byoc'") == 'past_due|0' ]] || fail 'new payment failure did not disable capacity'
payload "$TMP_DIR/post-failure-active.json" 'evt_e2e_post_failure_active' 'subscription.updated' \
    '2026-07-13T12:11:45Z' 'active' '' ''
send_webhook "$TMP_DIR/post-failure-active.json"
[[ $(db "SELECT s.status || '|' || p.enclave_limit
    FROM subscriptions s JOIN self_managed_plans p ON p.id = s.self_managed_plan_id
    WHERE s.paddle_subscription_id = 'sub_e2e_byoc'") == 'active|2' ]] || fail 'newer active event did not restore payment-failed authority'
pass 'payment failure ordering rejects stale regressions and fails closed for current failures'

payload "$TMP_DIR/scheduled-cancel.json" 'evt_e2e_scheduled_cancel' 'subscription.updated' \
    '2026-07-13T12:12:00Z' 'active' '' '' 'cancel'
send_webhook "$TMP_DIR/scheduled-cancel.json"
[[ $(db "SELECT s.status || '|' || p.enclave_limit
    FROM subscriptions s JOIN self_managed_plans p ON p.id = s.self_managed_plan_id
    WHERE s.paddle_subscription_id = 'sub_e2e_byoc'") == 'active|2' ]] || fail 'scheduled cancellation disabled capacity before its effective date'
pass 'paused billing disables capacity while reactivation and scheduled cancellation preserve correct entitlement timing'

# Cancellation queues only self-managed resources. The e2e API is explicitly
# configured to force after exercising canonical DNS/lock/credential teardown,
# so synthetic credentials cannot reach a real cloud account.
PROVIDER_ACCOUNT_ID=$(db "INSERT INTO provider_accounts
    (organization_id, provider_id, external_account_id, account_name)
    SELECT '$ORG_ID', id, 'paddle-e2e', 'Paddle E2E' FROM providers
    WHERE provider_type = 'aws' LIMIT 1 RETURNING id")
RESOURCE_TYPE_ID=$(db "SELECT id FROM resource_types WHERE type_code = 'ec2-instance' LIMIT 1")
SELF_MANAGED_RESOURCE_ID=$(new_uuid)
FULLY_MANAGED_RESOURCE_ID=$(new_uuid)
db "INSERT INTO compute_resources
    (id, organization_id, provider_account_id, resource_type_id,
     provider_resource_id, resource_name, state, created_by)
    VALUES
    ('$SELF_MANAGED_RESOURCE_ID', '$ORG_ID', '$PROVIDER_ACCOUNT_ID', '$RESOURCE_TYPE_ID',
     'i-self-managed-e2e', 'self-managed-e2e', 'running', '$USER_ID'),
    ('$FULLY_MANAGED_RESOURCE_ID', '$ORG_ID', '$PROVIDER_ACCOUNT_ID', '$RESOURCE_TYPE_ID',
     'i-fully-managed-e2e', 'fully-managed-e2e', 'running', '$USER_ID')"
SELF_MANAGED_CREDENTIAL_ID=$(db "INSERT INTO cloud_credentials
    (organization_id, platform, identifier, secrets_encrypted, config,
     created_by, resource_id, managed_on_prem)
    VALUES ('$ORG_ID', 'aws', 'AKIAE2ETEST', '\\x00', '{}',
            '$USER_ID', '$SELF_MANAGED_RESOURCE_ID', true)
    RETURNING id")
DELETE_STATUS=$(curl --silent --output /dev/null --write-out '%{http_code}' -X DELETE \
    "$GATEWAY_URL/api/credentials/$SELF_MANAGED_CREDENTIAL_ID" -H "X-Session-ID: $SESSION_ID")
[[ $DELETE_STATUS == 409 ]] || fail "live BYOC credential deletion returned HTTP $DELETE_STATUS instead of 409"

CANCEL_INTENT_ID=$(new_uuid)
db "INSERT INTO subscription_intents
    (id, organization_id, requested_by_user_id, operation, subscription_id, paddle_subscription_id, status)
    SELECT '$CANCEL_INTENT_ID', '$ORG_ID', '$USER_ID', 'cancel', id, 'sub_e2e_byoc', 'provider_pending'
    FROM subscriptions WHERE paddle_subscription_id = 'sub_e2e_byoc'"
db "UPDATE subscriptions SET paddle_price_id = 'pri_e2e_retired'
    WHERE paddle_subscription_id = 'sub_e2e_byoc'"
payload "$TMP_DIR/canceled.json" 'evt_e2e_canceled' 'subscription.canceled' '2026-07-13T12:12:00Z' 'canceled' '' ''
python3 - "$TMP_DIR/canceled.json" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
payload = json.loads(path.read_text())
payload["data"]["items"][0]["price"]["id"] = "pri_e2e_retired"
path.write_text(json.dumps(payload, separators=(",", ":")))
PY
send_webhook "$TMP_DIR/canceled.json"
[[ $(db "SELECT status FROM subscriptions WHERE paddle_subscription_id = 'sub_e2e_byoc'") == 'canceled' ]] || fail 'equal-time cancellation did not win fail-closed precedence'
[[ $(db "SELECT status FROM subscription_intents WHERE id = '$CANCEL_INTENT_ID'") == 'applied' ]] || fail 'cancellation intent was not applied'
[[ $(db "SELECT COALESCE(self_managed_plan_id::text, '') FROM subscriptions WHERE paddle_subscription_id = 'sub_e2e_byoc'") == '' ]] || fail 'canceled Paddle row still owns the plan'
[[ $(db "SELECT COUNT(*) FROM self_managed_termination_jobs WHERE resource_id = '$SELF_MANAGED_RESOURCE_ID'") == 1 ]] || fail 'self-managed resource was not queued for termination'
[[ $(db "SELECT COUNT(*) FROM self_managed_termination_jobs WHERE resource_id = '$FULLY_MANAGED_RESOURCE_ID'") == 0 ]] || fail 'fully managed resource was incorrectly queued for termination'
pass 'equal-time cancellation won fail-closed precedence and applied its intent'

send_webhook "$TMP_DIR/canceled.json" 'already_processed'
EVENT_COUNT=$(db "SELECT COUNT(*) FROM paddle_webhook_events WHERE event_id = 'evt_e2e_canceled'")
SUBSCRIPTION_COUNT=$(db "SELECT COUNT(*) FROM subscriptions WHERE paddle_subscription_id = 'sub_e2e_byoc'")
[[ $EVENT_COUNT == 1 && $SUBSCRIPTION_COUNT == 1 ]] || fail 'duplicate webhook was not idempotent'
pass 'duplicate webhook delivery was idempotent'

TERMINATED_RESPONSE=$(curl --fail --silent --show-error "$GATEWAY_URL/api/billing/subscription" -H "X-Session-ID: $SESSION_ID")
jq -e '.subscription.source == "paddle" and .subscription.status == "terminated" and .subscription.enclave_limit == 0' \
  <<<"$TERMINATED_RESPONSE" >/dev/null || fail 'canceled Paddle plan was not disabled'
pass 'effective cancellation disabled the linked self-managed plan'

# The durable worker must complete the canonical teardown before replacement
# billing authority is allowed.
for _ in $(seq 1 65); do
    [[ $(db "SELECT status FROM self_managed_termination_jobs WHERE resource_id = '$SELF_MANAGED_RESOURCE_ID'") == 'completed' ]] && break
    sleep 1
done
[[ $(db "SELECT status FROM self_managed_termination_jobs WHERE resource_id = '$SELF_MANAGED_RESOURCE_ID'") == 'completed' ]] || fail 'canonical self-managed teardown did not complete'
[[ $(db "SELECT state || '|' || (destroyed_at IS NOT NULL) || '|' || dns_status
    FROM compute_resources WHERE id = '$SELF_MANAGED_RESOURCE_ID'") == 'terminated|true|reserved' ]] || fail 'canonical teardown did not durably terminate the self-managed resource'
[[ $(db "SELECT state || '|' || (destroyed_at IS NULL)
    FROM compute_resources WHERE id = '$FULLY_MANAGED_RESOURCE_ID'") == 'running|true' ]] || fail 'canonical teardown changed a fully managed resource'
DELETE_STATUS=$(curl --silent --output /dev/null --write-out '%{http_code}' -X DELETE \
    "$GATEWAY_URL/api/credentials/$SELF_MANAGED_CREDENTIAL_ID" -H "X-Session-ID: $SESSION_ID")
[[ $DELETE_STATUS == 204 ]] || fail "terminated BYOC credential deletion returned HTTP $DELETE_STATUS instead of 204"
pass 'durable worker completed canonical self-managed teardown'

REPLACEMENT_INTENT_ID=$(new_uuid)
db "INSERT INTO subscription_intents
    (id, organization_id, requested_by_user_id, operation, new_tier, new_limit, status)
    VALUES ('$REPLACEMENT_INTENT_ID', '$ORG_ID', '$USER_ID', 'subscribe', '2_enclaves', 2, 'provider_pending')"
payload "$TMP_DIR/replacement.json" 'evt_e2e_replacement' 'subscription.created' \
    '2026-07-13T12:30:00Z' 'active' 'caution_checkout_intent_id' "$REPLACEMENT_INTENT_ID" '' 'sub_e2e_replacement'
send_webhook "$TMP_DIR/replacement.json"
[[ $(db "SELECT paddle_subscription_id FROM subscriptions WHERE self_managed_plan_id IS NOT NULL AND organization_id = '$ORG_ID'") == 'sub_e2e_replacement' ]] || fail 'replacement subscription did not take plan authority'

# A delayed event for the detached historical row cannot relink it or steal the
# replacement subscription's plan.
payload "$TMP_DIR/delayed-old.json" 'evt_e2e_delayed_old' 'subscription.updated' \
    '2026-07-13T12:31:00Z' 'active' '' '' '' 'sub_e2e_byoc'
send_webhook "$TMP_DIR/delayed-old.json"
[[ $(db "SELECT paddle_subscription_id FROM subscriptions WHERE self_managed_plan_id IS NOT NULL AND organization_id = '$ORG_ID'") == 'sub_e2e_replacement' ]] || fail 'delayed historical event stole replacement plan authority'
[[ $(db "SELECT COALESCE(self_managed_plan_id::text, '') FROM subscriptions WHERE paddle_subscription_id = 'sub_e2e_byoc'") == '' ]] || fail 'historical Paddle row was relinked'
pass 'replacement subscription retains authority against delayed historical events'

# Simulate an older metering binary that writes cancellation only to the legacy
# subscription projection after an operator transition has reached Paddle. The
# new worker must apply the durable manual change, not destroy resources.
ROLLING_CHANGE_ID=$(new_uuid)
db "INSERT INTO self_managed_plan_changes
        (id, organization_id, subscription_id, requested_enclave_limit,
         operator_identity, operator_reason, status)
    SELECT '$ROLLING_CHANGE_ID', '$ORG_ID', id, 7,
           'rolling-operator', 'enterprise-conversion', 'provider_pending'
    FROM subscriptions WHERE paddle_subscription_id = 'sub_e2e_replacement';
    UPDATE subscriptions SET status = 'canceled', canceled_at = NOW()
    WHERE paddle_subscription_id = 'sub_e2e_replacement'"
for _ in $(seq 1 45); do
    [[ $(db "SELECT status FROM self_managed_plan_changes WHERE id = '$ROLLING_CHANGE_ID'") == 'applied' ]] && break
    sleep 1
done
[[ $(db "SELECT COALESCE(self_managed_plan_id::text, '') FROM subscriptions WHERE paddle_subscription_id = 'sub_e2e_replacement'") == '' ]] || fail 'rolling-deployment reconciliation did not detach canceled subscription'
[[ $(db "SELECT source || '|' || enclave_limit || '|' || COALESCE(operator_identity, '')
    FROM self_managed_plans WHERE organization_id = '$ORG_ID'") == 'manual|7|rolling-operator' ]] || fail 'rolling-deployment reconciliation destroyed resources instead of applying manual authority'
[[ $(db "SELECT status FROM self_managed_plan_changes WHERE id = '$ROLLING_CHANGE_ID'") == 'applied' ]] || fail 'rolling-deployment reconciliation left manual transition pending'
pass 'rolling-deployment reconciliation preserves pending manual authority'

# Operator conversion remains nullable and is projected explicitly by the API.
db "UPDATE subscriptions SET status = 'canceled', canceled_at = NOW(), self_managed_plan_id = NULL
    WHERE paddle_subscription_id = 'sub_e2e_replacement';
    UPDATE self_managed_plans SET source = 'manual', tier = 'enterprise_contract',
        enclave_limit = NULL, operator_identity = 'e2e-operator',
        operator_reason = 'unlimited-contract', terminated_at = NULL
    WHERE organization_id = '$ORG_ID'"
UNLIMITED_RESPONSE=$(curl --fail --silent --show-error "$GATEWAY_URL/api/billing/subscription" -H "X-Session-ID: $SESSION_ID")
jq -e '.subscription.source == "manual" and .subscription.enclave_limit == null and .subscription.unlimited_enclaves == true' \
    <<<"$UNLIMITED_RESPONSE" >/dev/null || fail 'unlimited manual plan was not projected correctly'
pass 'subscription API exposes null as semantic unlimited capacity'

printf 'Paddle subscription e2e: PASS\n'
