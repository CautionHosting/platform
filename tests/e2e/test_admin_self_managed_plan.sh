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
INSERT INTO credit_ledger (user_id, organization_id, delta_cents, entry_type, description)
VALUES ('$USER_ID', '$ORG_ID', 5000, 'purchase', 'preservation fixture');
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
[[ $(db "SELECT billing_source || '|' || status || '|' || paddle_subscription_id || '|' || COALESCE(self_managed_plan_id::text, '') FROM subscriptions WHERE organization_id = '$ORG_ID'") == 'paddle|active|sub_admintest|' ]]
[[ $(db "SELECT status FROM self_managed_plan_changes WHERE organization_id = '$ORG_ID'") == 'applied' ]]
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

printf 'Admin self-managed plan e2e: PASS\n'
