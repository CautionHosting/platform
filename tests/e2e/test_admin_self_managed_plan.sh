#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
POSTGRES_CONTAINER=${POSTGRES_CONTAINER:-postgres}
TEST_DB=self_managed_plan_admin_test
ORG_ID=22222222-2222-4222-8222-222222222222
USER_ID=11111111-1111-4111-8111-111111111111
TMP_DIR=$(mktemp -d /tmp/caution-self-managed-admin.XXXXXX)
cleanup() {
    docker exec "$POSTGRES_CONTAINER" dropdb -U postgres --if-exists "$TEST_DB" >/dev/null 2>&1 || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

docker exec "$POSTGRES_CONTAINER" dropdb -U postgres --if-exists "$TEST_DB" >/dev/null
docker exec "$POSTGRES_CONTAINER" createdb -U postgres "$TEST_DB"
for migration in "$ROOT_DIR"/src/api/migrations/*.sql; do
    docker exec -i "$POSTGRES_CONTAINER" psql -v ON_ERROR_STOP=1 -U postgres -d "$TEST_DB" <"$migration" >/dev/null
done

docker exec -i "$POSTGRES_CONTAINER" psql -v ON_ERROR_STOP=1 -U postgres -d "$TEST_DB" >/dev/null <<SQL
INSERT INTO users (id, username, email)
VALUES ('$USER_ID', 'self-managed-admin', 'self-managed-admin@example.invalid');
INSERT INTO organizations (id, name) VALUES ('$ORG_ID', 'Self-managed admin test');
INSERT INTO organization_members (organization_id, user_id, role)
VALUES ('$ORG_ID', '$USER_ID', 'owner');
INSERT INTO credit_ledger (organization_id, delta_cents, entry_type, description)
VALUES ('$ORG_ID', 5000, 'purchase', 'preservation fixture');
INSERT INTO self_managed_plans (organization_id, tier, enclave_limit, source)
VALUES ('$ORG_ID', '2_enclaves', 2, 'paddle');
INSERT INTO subscriptions (
    user_id, organization_id, tier, max_vcpus, max_apps, price_cents_per_cycle,
    status, billing_source, paddle_customer_id, paddle_subscription_id,
    paddle_price_id, catalog_version, catalog_valid, current_period_start,
    current_period_end, next_billing_at, self_managed_plan_id
)
SELECT '$USER_ID', '$ORG_ID', '2_enclaves', 0, 2, 1000,
       'active', 'paddle', 'ctm_admin_test', 'sub_admintest',
       'pri_admin_test', 1, true, NOW(), NOW() + INTERVAL '1 month',
       NOW() + INTERVAL '1 month', id
FROM self_managed_plans WHERE organization_id = '$ORG_ID';
SQL

mkdir -p "$TMP_DIR/bin"
cat >"$TMP_DIR/bin/psql" <<'PSQL'
#!/usr/bin/env bash
exec docker exec -i "$POSTGRES_CONTAINER" psql "$@"
PSQL
cat >"$TMP_DIR/bin/curl" <<'CURL'
#!/usr/bin/env bash
set -euo pipefail
output= method=GET config= url= idempotency=
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output) output=$2; shift 2 ;;
        --config) config=$2; shift 2 ;;
        -X) method=$2; shift 2 ;;
        -H) [[ $2 == Paddle-Idempotency-Key:* ]] && idempotency=${2#*: }; shift 2 ;;
        --write-out|--connect-timeout|--max-time|--data) shift 2 ;;
        --silent|--show-error) shift ;;
        http*) url=$1; shift ;;
        *) shift ;;
    esac
done
[[ -n $output && -n $config && -n $url ]]
[[ $(stat -c %a "$config") == 600 ]]
[[ $(<"$config") == *"Bearer test-paddle-key"* ]]
printf '%s|%s|%s\n' "$method" "$url" "$idempotency" >>"$CURL_LOG"
if [[ $method == POST ]]; then
    [[ $url == */subscriptions/sub_admintest/cancel ]]
    [[ $idempotency =~ ^[0-9a-f-]{36}$ ]]
    printf '{"data":{"status":"canceled"}}' >"$output"
else
    [[ $url == */subscriptions/sub_admintest ]]
    printf '{"data":{"status":"active"}}' >"$output"
fi
printf 200
CURL
chmod +x "$TMP_DIR/bin/psql" "$TMP_DIR/bin/curl"

export POSTGRES_CONTAINER TEST_DB
export PATH="$TMP_DIR/bin:$PATH"
export ADMIN_SKIP_ENV=true
export DB_HOST=localhost DB_PORT=5432 DB_NAME="$TEST_DB" DB_USER=postgres DB_PASSWORD=unused
export DB_SCHEMA=public
export PADDLE_API_URL=https://sandbox-api.paddle.com
export PADDLE_API_KEY=test-paddle-key
export CURL_LOG="$TMP_DIR/curl.log"

db() { docker exec "$POSTGRES_CONTAINER" psql -U postgres -d "$TEST_DB" -Atqc "$1"; }
fail() { printf '[FAIL] %s\n' "$1" >&2; exit 1; }
admin() {
    "$ROOT_DIR/utils/admin" set-self-managed-plan "$1" --enclaves 7 --never-expires \
        --operator test-operator@example.invalid --reason contract-test "${@:2}"
}
expect_failure() { if "$@" >/dev/null 2>&1; then echo "expected failure: $*" >&2; exit 1; fi; }

before=$(db "SELECT source || '|' || enclave_limit FROM self_managed_plans WHERE organization_id = '$ORG_ID'")
expect_failure admin self-managed-admin@example.invalid
admin self-managed-admin@example.invalid --detach-paddle >/dev/null
after_dry_run=$(db "SELECT source || '|' || enclave_limit FROM self_managed_plans WHERE organization_id = '$ORG_ID'")
[[ $after_dry_run == "$before" ]] || fail "dry run changed plan: $after_dry_run"
[[ ! -e $CURL_LOG ]] || fail "dry run contacted Paddle"

admin self-managed-admin@example.invalid --detach-paddle --confirm >/dev/null
[[ $(db "SELECT source || '|' || enclave_limit FROM self_managed_plans WHERE organization_id = '$ORG_ID'") == 'manual|7' ]]
[[ $(db "SELECT billing_source || '|' || status || '|' || paddle_subscription_id || '|' || COALESCE(self_managed_plan_id::text, '') FROM subscriptions WHERE organization_id = '$ORG_ID'") == 'paddle|canceled|sub_admintest|' ]]
[[ $(db "SELECT status FROM self_managed_plan_changes WHERE organization_id = '$ORG_ID'") == 'applied' ]]
[[ $(wc -l <"$CURL_LOG") == 2 ]]
# The exact provider-detachment command remains idempotently retryable after
# webhook-first application or process death after provider cancellation.
admin self-managed-admin@example.invalid --detach-paddle --confirm >/dev/null
[[ $(wc -l <"$CURL_LOG") == 2 ]]
[[ $(db "SELECT count(*) || '|' || sum(delta_cents) FROM credit_ledger WHERE organization_id = '$ORG_ID'") == '1|5000' ]]

"$ROOT_DIR/utils/admin" set-self-managed-plan "$ORG_ID" --unlimited --never-expires \
    --operator test-operator@example.invalid --reason unlimited-contract --confirm >/dev/null
[[ $(db "SELECT source || '|' || COALESCE(enclave_limit::text, 'unlimited') FROM self_managed_plans WHERE organization_id = '$ORG_ID'") == 'manual|unlimited' ]]
[[ $(wc -l <"$CURL_LOG") == 2 ]]

expect_failure "$ROOT_DIR/utils/admin" set-self-managed-plan "$ORG_ID" --enclaves 0 --never-expires \
    --operator test --reason invalid
expect_failure "$ROOT_DIR/utils/admin" set-self-managed-plan "$ORG_ID" --unlimited --expires-at 2020-01-01T00:00:00Z \
    --operator test --reason expired

# Composite foreign keys prevent cross-organization plan ownership.
OTHER_ORG_ID='77777777-7777-4777-8777-777777777777'
OTHER_PLAN_ID='88888888-8888-4888-8888-888888888888'
db "INSERT INTO organizations (id, name) VALUES ('$OTHER_ORG_ID', 'Other Org');
    INSERT INTO self_managed_plans
        (id, organization_id, tier, enclave_limit, source, operator_identity, operator_reason)
    VALUES ('$OTHER_PLAN_ID', '$OTHER_ORG_ID', 'enterprise_contract', 2, 'manual', 'test', 'isolation')"
expect_failure docker exec "$POSTGRES_CONTAINER" psql -v ON_ERROR_STOP=1 -U postgres -d "$DB_NAME" \
    -c "UPDATE subscriptions SET self_managed_plan_id = '$OTHER_PLAN_ID' WHERE paddle_subscription_id = 'sub_admintest'"

# Converting legacy-credit BYOC to a manual contract stops local billing and
# retains the old row only as detached history.
LEGACY_ORG_ID='99999999-9999-4999-8999-999999999999'
LEGACY_PLAN_ID='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
LEGACY_SUB_ID='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
db "INSERT INTO organizations (id, name) VALUES ('$LEGACY_ORG_ID', 'Legacy Org');
    INSERT INTO self_managed_plans (id, organization_id, tier, enclave_limit, source)
    VALUES ('$LEGACY_PLAN_ID', '$LEGACY_ORG_ID', '2_enclaves', 2, 'legacy');
    INSERT INTO subscriptions
        (id, user_id, organization_id, tier, billing_period, max_vcpus, max_apps,
         price_cents_per_cycle, current_period_start, current_period_end,
         next_billing_at, status, billing_source, self_managed_plan_id)
    VALUES ('$LEGACY_SUB_ID', '$USER_ID', '$LEGACY_ORG_ID', '2_enclaves', 'monthly', 0, 2,
            1000, NOW(), NOW() + INTERVAL '30 days', NOW(), 'active',
            'legacy_credits', '$LEGACY_PLAN_ID');
    INSERT INTO subscription_ledger
        (subscription_id, organization_id, billing_period_start, billing_period_end,
         tier, cost_hourly, status)
    VALUES ('$LEGACY_SUB_ID', '$LEGACY_ORG_ID', NOW() - INTERVAL '1 day', NULL,
            '2_enclaves', 0.10, 'credits_covered')"
"$ROOT_DIR/utils/admin" set-self-managed-plan "$LEGACY_ORG_ID" --enclaves 9 --never-expires \
    --operator test --reason enterprise-upgrade --confirm >/dev/null
[[ $(db "SELECT status || '|' || COALESCE(self_managed_plan_id::text, '') FROM subscriptions WHERE id = '$LEGACY_SUB_ID'") == 'canceled|' ]]
[[ $(db "SELECT source || '|' || enclave_limit FROM self_managed_plans WHERE id = '$LEGACY_PLAN_ID'") == 'manual|9' ]]
[[ $(db "SELECT count(*) FROM subscription_ledger WHERE subscription_id = '$LEGACY_SUB_ID' AND billing_period_end IS NULL") == '0' ]]

# The final apply must fail closed if another transition removes Paddle's
# authority after the durable intent was prepared.
RACE_ORG_ID=33333333-3333-4333-8333-333333333333
db "INSERT INTO organizations (id, name) VALUES ('$RACE_ORG_ID', 'Self-managed race test');
    INSERT INTO self_managed_plans (organization_id, tier, enclave_limit, source)
    VALUES ('$RACE_ORG_ID', '2_enclaves', 2, 'paddle');
    INSERT INTO subscriptions (
        user_id, organization_id, tier, max_vcpus, max_apps, price_cents_per_cycle,
        status, billing_source, paddle_customer_id, paddle_subscription_id,
        paddle_price_id, catalog_version, catalog_valid, current_period_start,
        current_period_end, next_billing_at, self_managed_plan_id
    )
    SELECT '$USER_ID', '$RACE_ORG_ID', '2_enclaves', 0, 2, 1000,
           'active', 'paddle', 'ctm_race_test', 'sub_racetest',
           'pri_race_test', 1, true, NOW(), NOW() + INTERVAL '1 month',
           NOW() + INTERVAL '1 month', id
    FROM self_managed_plans WHERE organization_id = '$RACE_ORG_ID';"
RACE_PROVIDER_INTENT_ID='34343434-3434-4434-8434-343434343434'
db "INSERT INTO subscription_intents
        (id, organization_id, requested_by_user_id, operation, subscription_id,
         paddle_subscription_id, new_tier, new_limit, status)
    SELECT '$RACE_PROVIDER_INTENT_ID', '$RACE_ORG_ID', '$USER_ID', 'upgrade', id,
           paddle_subscription_id, '4_enclaves', 4, 'provider_pending'
    FROM subscriptions WHERE organization_id = '$RACE_ORG_ID'"
expect_failure docker exec -i "$POSTGRES_CONTAINER" psql -q -v ON_ERROR_STOP=1 -U postgres -d "$TEST_DB" \
    -v organization_id="$RACE_ORG_ID" -v enclave_limit=9 -v expires_at= \
    -v operator_identity=race-operator -v operator_reason=race-test -v detach_paddle=true \
    -f /dev/stdin <"$ROOT_DIR/utils/admin-self-managed-plan-prepare.sql"
db "UPDATE subscription_intents SET status = 'canceled' WHERE id = '$RACE_PROVIDER_INTENT_ID'"
docker exec -i "$POSTGRES_CONTAINER" psql -q -v ON_ERROR_STOP=1 -U postgres -d "$TEST_DB" \
    -v organization_id="$RACE_ORG_ID" -v enclave_limit=9 -v expires_at= \
    -v operator_identity=race-operator -v operator_reason=race-test -v detach_paddle=true \
    <"$ROOT_DIR/utils/admin-self-managed-plan-prepare.sql" >/dev/null
RACE_CHANGE_ID=$(db "SELECT id FROM self_managed_plan_changes WHERE organization_id = '$RACE_ORG_ID'")
db "UPDATE subscriptions SET self_managed_plan_id = NULL WHERE organization_id = '$RACE_ORG_ID';
    UPDATE self_managed_plans SET source = 'manual', operator_identity = 'winner',
        operator_reason = 'competing transition' WHERE organization_id = '$RACE_ORG_ID';"
expect_failure docker exec -i "$POSTGRES_CONTAINER" psql -q -v ON_ERROR_STOP=1 -U postgres -d "$TEST_DB" \
    -v organization_id="$RACE_ORG_ID" -v change_id="$RACE_CHANGE_ID" \
    -f /dev/stdin <"$ROOT_DIR/utils/admin-self-managed-plan-apply.sql"
[[ $(db "SELECT source || '|' || enclave_limit FROM self_managed_plans WHERE organization_id = '$RACE_ORG_ID'") == 'manual|2' ]]
[[ $(db "SELECT status FROM self_managed_plan_changes WHERE id = '$RACE_CHANGE_ID'") == 'provider_pending' ]]

# Dead-letter recovery is explicit, audited, and fenced by resource state.
RECOVERY_ORG_ID='cccccccc-cccc-4ccc-8ccc-cccccccccccc'
RECOVERY_PLAN_ID='dddddddd-dddd-4ddd-8ddd-dddddddddddd'
RECOVERY_SUB_ID='eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'
RECOVERY_RESOURCE_ID='ffffffff-ffff-4fff-8fff-ffffffffffff'
RECOVERY_JOB_ID='12121212-1212-4212-8212-121212121212'
db "INSERT INTO organizations (id, name) VALUES ('$RECOVERY_ORG_ID', 'Recovery Org');
    INSERT INTO self_managed_plans
        (id, organization_id, tier, enclave_limit, source, terminated_at)
    VALUES ('$RECOVERY_PLAN_ID', '$RECOVERY_ORG_ID', '2_enclaves', 0, 'paddle', NOW());
    INSERT INTO subscriptions
        (id, user_id, organization_id, tier, billing_period, max_vcpus, max_apps,
         price_cents_per_cycle, current_period_start, current_period_end,
         next_billing_at, status, billing_source, paddle_customer_id,
         paddle_subscription_id, paddle_price_id, catalog_version, catalog_valid)
    VALUES ('$RECOVERY_SUB_ID', '$USER_ID', '$RECOVERY_ORG_ID', '2_enclaves', 'monthly', 0, 2,
            1000, NOW(), NOW() + INTERVAL '30 days', NOW(), 'canceled', 'paddle',
            'ctm_recovery', 'sub_recovery', 'pri_recovery', 1, true);
    INSERT INTO provider_accounts (organization_id, provider_id, external_account_id, account_name)
    SELECT '$RECOVERY_ORG_ID', id, 'recovery-e2e', 'Recovery E2E'
    FROM providers WHERE provider_type = 'aws' LIMIT 1;
    INSERT INTO compute_resources
        (id, organization_id, provider_account_id, resource_type_id,
         provider_resource_id, resource_name, state, created_by)
    SELECT '$RECOVERY_RESOURCE_ID', '$RECOVERY_ORG_ID', pa.id, rt.id,
           'i-recovery-e2e', 'recovery-e2e', 'running', '$USER_ID'
    FROM provider_accounts pa CROSS JOIN resource_types rt
    WHERE pa.organization_id = '$RECOVERY_ORG_ID' AND rt.type_code = 'ec2-instance' LIMIT 1;
    INSERT INTO self_managed_termination_jobs
        (id, organization_id, self_managed_plan_id, subscription_id,
         resource_id, provider_occurred_at, status, attempt_count, last_error)
    VALUES ('$RECOVERY_JOB_ID', '$RECOVERY_ORG_ID', '$RECOVERY_PLAN_ID', '$RECOVERY_SUB_ID',
            '$RECOVERY_RESOURCE_ID', NOW(), 'dead_letter', 12, 'fixture failure')"
"$ROOT_DIR/utils/admin" retry-self-managed-termination "$RECOVERY_JOB_ID" \
    --operator test-operator --reason retry-after-credential-repair --confirm >/dev/null
[[ $(db "SELECT status || '|' || attempt_count || '|' || recovery_action || '|' || recovery_operator
    FROM self_managed_termination_jobs WHERE id = '$RECOVERY_JOB_ID'") == 'retry|0|retry|test-operator' ]]
db "UPDATE self_managed_termination_jobs SET status = 'dead_letter', last_error = 'verified gone'
    WHERE id = '$RECOVERY_JOB_ID';
    UPDATE compute_resources SET state = 'terminated', destroyed_at = NOW()
    WHERE id = '$RECOVERY_RESOURCE_ID'"
"$ROOT_DIR/utils/admin" resolve-self-managed-termination "$RECOVERY_JOB_ID" \
    --operator test-operator --reason infrastructure-verified-destroyed --confirm >/dev/null
[[ $(db "SELECT status || '|' || recovery_action || '|' || (completed_at IS NOT NULL)
    FROM self_managed_termination_jobs WHERE id = '$RECOVERY_JOB_ID'") == 'completed|resolve|true' ]]

printf 'Admin self-managed plan e2e: PASS\n'
