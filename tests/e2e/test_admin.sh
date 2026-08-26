#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

set -euo pipefail

DB_CONTAINER="${TEST_DB_HOST:-postgres-test}"
DB_NAME="${TEST_DB_NAME:-caution_test}"
DB_ADDRESS=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$DB_CONTAINER")
DATABASE_URL="postgresql://postgres:postgres@${DB_ADDRESS}:5432/${DB_NAME}"
ADMIN_BINARY="${ADMIN_BINARY:-target/release/caution-admin}"
USER_ID="10000000-0000-0000-0000-000000000001"
USER_WITHOUT_EMAIL_ID="10000000-0000-0000-0000-000000000002"
ORG_ID="20000000-0000-0000-0000-000000000001"
ACCOUNT_ID="30000000-0000-0000-0000-000000000001"
APP_ID="40000000-0000-0000-0000-000000000001"
APP_ID_2="40000000-0000-0000-0000-000000000002"
SUBSCRIPTION_ID="50000000-0000-0000-0000-000000000001"
SENTINEL="ADMIN_MUST_NOT_RENDER_RAW_CONFIGURATION"

db() {
    docker exec "$DB_CONTAINER" psql -v ON_ERROR_STOP=1 -U postgres -d "$DB_NAME" -c "$1"
}

admin() {
    ENVIRONMENT=development DATABASE_URL="$DATABASE_URL" "$ADMIN_BINARY" "$@"
}

cleanup_rows() {
    db "
DELETE FROM usage_ledger WHERE organization_id = '$ORG_ID';
DELETE FROM credit_ledger WHERE organization_id = '$ORG_ID';
DELETE FROM cloud_credentials WHERE organization_id = '$ORG_ID';
DELETE FROM subscriptions WHERE id = '$SUBSCRIPTION_ID';
DELETE FROM compute_resources WHERE id IN ('$APP_ID', '$APP_ID_2');
DELETE FROM provider_accounts WHERE id = '$ACCOUNT_ID';
DELETE FROM organization_members WHERE user_id = '$USER_ID';
DELETE FROM organizations WHERE id = '$ORG_ID';
DELETE FROM users WHERE id IN ('$USER_ID', '$USER_WITHOUT_EMAIL_ID');
" >/dev/null 2>&1 || true
}
trap cleanup_rows EXIT

cleanup_rows

db "
INSERT INTO users (id, username, email)
VALUES ('$USER_ID', 'admin-pilot-alice', 'admin-pilot-alice@example.com');

INSERT INTO users (id, username)
VALUES ('$USER_WITHOUT_EMAIL_ID', 'admin-pilot-no-email');

INSERT INTO organizations (id, name)
VALUES ('$ORG_ID', 'Admin Pilot Labs');

INSERT INTO organization_members (organization_id, user_id, role)
VALUES ('$ORG_ID', '$USER_ID', 'owner');

INSERT INTO provider_accounts (
    id, organization_id, provider_id, external_account_id, account_name
)
SELECT '$ACCOUNT_ID', '$ORG_ID', id, 'admin-pilot-account', 'Admin Pilot Account'
FROM providers
WHERE provider_type = 'aws';

INSERT INTO compute_resources (
    id, organization_id, provider_account_id, resource_type_id,
    provider_resource_id, resource_name, state, region, configuration, dns_status
)
SELECT '$APP_ID', '$ORG_ID', '$ACCOUNT_ID', rt.id,
       'i-admin-pilot-1', 'admin-pilot-api', 'running', 'eu-central-1',
       jsonb_build_object('sentinel', '$SENTINEL', 'domain', 'admin-pilot.example'), 'ready'
FROM resource_types rt
JOIN providers p ON p.id = rt.provider_id
WHERE p.provider_type = 'aws' AND rt.type_code = 'ec2-instance';

INSERT INTO compute_resources (
    id, organization_id, provider_account_id, resource_type_id,
    provider_resource_id, resource_name, state, region
)
SELECT '$APP_ID_2', '$ORG_ID', '$ACCOUNT_ID', rt.id,
       'i-admin-pilot-2', 'admin-pilot-worker', 'stopped', 'eu-central-1'
FROM resource_types rt
JOIN providers p ON p.id = rt.provider_id
WHERE p.provider_type = 'aws' AND rt.type_code = 'ec2-instance';

INSERT INTO cloud_credentials (
    organization_id, platform, identifier, secrets_encrypted, config,
    resource_id, managed_on_prem, is_active, last_validated_at
)
VALUES (
    '$ORG_ID', 'aws', 'admin-pilot-credential', decode('00', 'hex'),
    jsonb_build_object('sentinel', '$SENTINEL'), '$APP_ID', true, true, NOW()
);

INSERT INTO subscriptions (
    id, user_id, organization_id, tier, max_vcpus, max_apps,
    price_cents_per_cycle, status, billing_source, pending_tier, pending_max_apps,
    current_period_end, next_billing_at
)
VALUES (
    '$SUBSCRIPTION_ID', '$USER_ID', '$ORG_ID', '3_enclaves', 0, 3,
    0, 'active', 'legacy_credits', '2_enclaves', 2,
    NOW() + INTERVAL '30 days', NOW() + INTERVAL '30 days'
);

INSERT INTO credit_ledger (organization_id, delta_cents, entry_type, description)
VALUES ('$ORG_ID', 10000, 'purchase', 'Admin explorer test credit');

INSERT INTO usage_ledger (
    organization_id, user_id, application_id, resource_id, provider,
    resource_type, quantity, unit, base_unit_cost_usd, margin_percent
)
VALUES (
    '$ORG_ID', '$USER_ID', '$APP_ID', 'admin-pilot-usage', 'aws',
    'compute', 2, 'hours', 10, 0
);
" >/dev/null

USER_SEARCH=$(admin search admin-pilot-alice@example.com --json)
jq -e --arg id "$USER_ID" '
    .[] | select(.kind == "user" and .id == $id and
                 .context == "active · admin-pilot-alice@example.com")
' <<<"$USER_SEARCH" >/dev/null

USER_WITHOUT_EMAIL_SEARCH=$(admin search admin-pilot-no-email --json)
jq -e --arg id "$USER_WITHOUT_EMAIL_ID" '
    .[] | select(.kind == "user" and .id == $id and .context == "active · no email")
' <<<"$USER_WITHOUT_EMAIL_SEARCH" >/dev/null

ORG_SEARCH=$(admin search 'Admin Pilot Labs' --json)
jq -e --arg id "$ORG_ID" '
    .[] | select(.kind == "organization" and .id == $id and .context == "active · 2 apps")
' <<<"$ORG_SEARCH" >/dev/null

APP_SEARCH=$(admin search admin-pilot-api --json)
jq -e --arg id "$APP_ID" '
    .[] | select(.kind == "app" and .id == $id and .context == "running · Admin Pilot Labs")
' <<<"$APP_SEARCH" >/dev/null

UUID_SEARCH=$(admin search "$APP_ID" --json)
jq -e --arg id "$APP_ID" '.[] | select(.id == $id)' <<<"$UUID_SEARCH" >/dev/null

USER_ORG=$(admin follow user "$USER_ID" organization --json)
jq -e --arg id "$ORG_ID" '.items[] | select(.id == $id and .role == "owner")' <<<"$USER_ORG" >/dev/null

ORG_USERS=$(admin follow organization "$ORG_ID" users --json)
jq -e --arg id "$USER_ID" '
    .items[] | select(.id == $id and .role == "owner" and
                      .context == "active · admin-pilot-alice@example.com")
' <<<"$ORG_USERS" >/dev/null

ORG_APPS=$(admin follow organization "$ORG_ID" apps --json)
jq -e --arg id "$APP_ID" '.items[] | select(.id == $id)' <<<"$ORG_APPS" >/dev/null

APP_ORG=$(admin follow app "$APP_ID" organization --json)
jq -e --arg id "$ORG_ID" '.items[] | select(.id == $id)' <<<"$APP_ORG" >/dev/null

USER_APPS=$(admin follow user "$USER_ID" apps --json)
jq -e --arg app "$APP_ID" --arg org "$ORG_ID" '
    .items[] | select(.id == $app and .role == "owner" and .via.id == $org)
' <<<"$USER_APPS" >/dev/null

USER_APPS_PAGE=$(admin follow user "$USER_ID" apps --limit 1 --json)
jq -e '.limit == 1 and .has_more == true and (.items | length) == 1' <<<"$USER_APPS_PAGE" >/dev/null

APP_USERS=$(admin follow app "$APP_ID" users --json)
jq -e --arg user "$USER_ID" --arg org "$ORG_ID" '
    .items[] | select(.id == $user and .role == "owner" and .via.id == $org and
                      .context == "active · admin-pilot-alice@example.com")
' <<<"$APP_USERS" >/dev/null

PAGE=$(admin list app --limit 1 --json)
jq -e '.limit == 1 and .has_more == true and (.items | length) == 1' <<<"$PAGE" >/dev/null

SHOW_APP=$(admin show app "$APP_ID" --json)
if grep -q "$SENTINEL" <<<"$SHOW_APP"; then
    echo "caution-admin leaked raw app configuration" >&2
    exit 1
fi
jq -e --arg org 'Admin Pilot Labs' '
    .fields[] | select(.label == "Organization" and .value == $org)
' <<<"$SHOW_APP" >/dev/null
jq -e '.fields[] | select(.label == "Mode" and .value == "BYOC")' <<<"$SHOW_APP" >/dev/null
jq -e '.fields[] | select(.label == "Domain" and .value == "admin-pilot.example")' <<<"$SHOW_APP" >/dev/null
jq -e '.fields[] | select(.label == "DNS" and .value == "ready")' <<<"$SHOW_APP" >/dev/null

SHOW_MANAGED_APP=$(admin show app "$APP_ID_2" --json)
jq -e '.fields[] | select(.label == "Mode" and .value == "Fully managed")' \
    <<<"$SHOW_MANAGED_APP" >/dev/null

SHOW_ORG=$(admin show organization "$ORG_ID" --json)
jq -e '.fields[] | select(.label == "Credit balance" and .value == "$80.00")' \
    <<<"$SHOW_ORG" >/dev/null
jq -e '.fields[] | select(.label == "BYOC plan" and .value == "3 Enclaves")' \
    <<<"$SHOW_ORG" >/dev/null
jq -e '.fields[] | select(.label == "Billing source" and .value == "Credits")' \
    <<<"$SHOW_ORG" >/dev/null
jq -e '.fields[] | select(.label == "BYOC capacity" and .value == "1 / 2 used")' \
    <<<"$SHOW_ORG" >/dev/null
jq -e '.fields[] | select(.label == "Pending change" and .value == "2 Enclaves · 2 apps")' \
    <<<"$SHOW_ORG" >/dev/null

if admin show user 00000000-0000-0000-0000-000000000000 --json >/dev/null 2>&1; then
    echo "caution-admin unexpectedly found a missing user" >&2
    exit 1
fi

if ENVIRONMENT=production DATABASE_URL="$DATABASE_URL" \
    "$ADMIN_BINARY" list user --json >/dev/null 2>&1; then
    echo "caution-admin did not refuse production" >&2
    exit 1
fi

if ENVIRONMENT=development DATABASE_URL="$DATABASE_URL" \
    "$ADMIN_BINARY" >/dev/null 2>&1; then
    echo "caution-admin entered the TUI without a TTY" >&2
    exit 1
fi

echo "caution-admin e2e passed"
