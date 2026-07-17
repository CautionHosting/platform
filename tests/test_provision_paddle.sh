#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SCRIPT="$ROOT/utils/provision-paddle.sh"
TMP=$(mktemp -d)
trap '[[ ${KEEP_TMP:-0} == 1 ]] || rm -rf "$TMP"' EXIT
mkdir "$TMP/bin"
REAL_JQ=$(command -v jq)

cat >"$TMP/bin/curl" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
method=GET out= headers= url= data= auth=
while (($#)); do
  case $1 in
    -X|--request) method=$2; shift 2;;
    -o|--output) out=$2; shift 2;;
    -D|--dump-header) headers=$2; shift 2;;
    -w|--write-out) shift 2;;
    --data|--data-raw|--data-binary) data=$2; shift 2;;
    --config) auth=$(<"$2"); shift 2;;
    -H|--header|--connect-timeout|--max-time|--proto) shift 2;;
    --*) shift;;
    *) url=$1; shift;;
  esac
done
expected_auth="header = \"Authorization: Bearer $PADDLE_API_KEY\""
[[ $auth == "$expected_auth" ]] || { printf '%s\n' 'bad Authorization config' >&2; exit 91; }
printf '%s %s\n' "$method" "$url" >>"$PADDLE_STUB_STATE/requests"
[[ -z $data ]] || printf '%s\n' "$data" >>"$PADDLE_STUB_STATE/bodies"
[[ $data != *"$PADDLE_API_KEY"* ]] || exit 90
count=$(wc -l <"$PADDLE_STUB_STATE/requests")
status=200
printf '\r\n' >"$headers"
product='{"id":"pro_test","name":"Caution BYOC","tax_category":"saas","custom_data":{"caution_catalog_key":"byoc_managed_enclaves","caution_catalog_version":1}}'
price_json() { local n=$1 cents=$2; printf '{"id":"pri_test_%s","product_id":"pro_test","unit_price":{"amount":"%s","currency_code":"USD"},"billing_cycle":{"interval":"month","frequency":1},"quantity":{"minimum":1,"maximum":1},"custom_data":{"caution_catalog_key":"byoc_managed_enclaves","caution_catalog_version":1,"caution_tier_id":"%s_enclave%s","caution_enclave_limit":%s}}' "$n" "$cents" "$n" "$([[ $n == 1 ]] && printf '' || printf s)" "$n"; }
created_product=false; grep -q '^POST .*/products$' "$PADDLE_STUB_STATE/requests" 2>/dev/null && created_product=true
case "$method $url" in
  "GET "*'/products?status=active%2Carchived&per_page=200')
    if [[ ${PADDLE_STUB_MODE:-empty} == retryfail || ( ${PADDLE_STUB_MODE:-empty} == retry && ! -e $PADDLE_STUB_STATE/retried ) ]]; then touch "$PADDLE_STUB_STATE/retried"; status=429; printf 'Retry-After: 0\r\n\r\n' >"$headers"; body='{"error":{"code":"rate_limit"}}'
    elif [[ ${PADDLE_STUB_MODE:-empty} == duplicate ]]; then body="{\"data\":[$product,$product],\"meta\":{\"pagination\":{\"next\":null}}}"
    elif [[ ${PADDLE_STUB_MODE:-empty} == pagination && ! $url =~ page=2 ]]; then body='{"data":[],"meta":{"pagination":{"next":"https://sandbox-api.paddle.com/products?page=2","has_more":true}}}'
    elif [[ ${PADDLE_STUB_MODE:-empty} == has_more_false ]]; then body="{\"data\":[$product],\"meta\":{\"pagination\":{\"next\":\"https://sandbox-api.paddle.com/products?after=last\",\"has_more\":false}}}"
    elif [[ $created_product == true || ${PADDLE_STUB_MODE:-empty} =~ ^(existing|mismatch|tierdup)$ ]]; then body="{\"data\":[$product],\"meta\":{\"pagination\":{\"next\":null}}}"
    else body='{"data":[],"meta":{"pagination":{"next":null}}}'; fi;;
  "GET "*'/products?page=2') body="{\"data\":[$product],\"meta\":{\"pagination\":{\"next\":null}}}";;
  "POST "*'/products') status=201; body="{\"data\":$product}";;
  "GET "*'/prices?'*)
    prices=''; for n in 1 2 3 4 5; do cents=$((12500 + n*12500)); [[ $n == 1 ]] && cents=25000; p=$(price_json "$n" "$cents"); prices+="${prices:+,}$p"; done
    if [[ ${PADDLE_STUB_MODE:-empty} == mismatch ]]; then prices=${prices/\"amount\":\"25000\"/\"amount\":\"24999\"}; fi
    if [[ ${PADDLE_STUB_MODE:-empty} == tierdup ]]; then first=$(price_json 1 25000); prices="$prices,$first"; fi
    posts=$(grep -c '^POST .*/prices$' "$PADDLE_STUB_STATE/requests" 2>/dev/null || true)
    if [[ ${PADDLE_STUB_MODE:-empty} =~ ^(existing|mismatch|tierdup|has_more_false)$ || $posts -ge 5 ]]; then body="{\"data\":[$prices],\"meta\":{\"pagination\":{\"next\":null}}}"; else body='{"data":[],"meta":{"pagination":{"next":null}}}'; fi;;
  "POST "*'/prices') n=$(printf '%s' "$data" | "$REAL_JQ" -r '.custom_data.caution_enclave_limit'); cents=$(printf '%s' "$data" | "$REAL_JQ" -r '.unit_price.amount'); status=201; body="{\"data\":$(price_json "$n" "$cents")}";;
  *) status=500; body='{"error":{"code":"unexpected"}}';;
esac
printf '%s' "$body" >"$out"
printf '%s' "$status"
STUB
chmod +x "$TMP/bin/curl"
export REAL_JQ PADDLE_API_KEY='fixture-api-key-not-a-real-secret'

new_config() { cp "$ROOT/prices.json.example" "$1"; chmod 600 "$1"; }
run_case() { local mode=$1 state=$2; shift 2; mkdir -p "$state"; : >"$state/requests"; PADDLE_STUB_MODE=$mode PADDLE_STUB_STATE=$state PATH="$TMP/bin:$PATH" "$SCRIPT" sync-catalog --environment sandbox --config "$state/config.json" "$@"; }
fail_case() { if "$@" >"$TMP/out" 2>"$TMP/err"; then echo "expected failure: $*" >&2; exit 1; fi; }

# Dry run is GET-only and byte preserving.
s=$TMP/dry; mkdir "$s"; new_config "$s/config.json"; before=$(sha256sum "$s/config.json"); run_case empty "$s" >"$s/out" 2>"$s/err"; [[ $(sha256sum "$s/config.json") == "$before" ]]; ! grep -Eq '^(POST|PATCH|DELETE) ' "$s/requests"

# First apply creates 1+5, updates atomically with mode preserved; second is byte-idempotent.
s=$TMP/apply; mkdir "$s"; new_config "$s/config.json"; run_case empty "$s" --apply >"$s/out" 2>"$s/err"; [[ $(grep -c '^POST .*/products$' "$s/requests") == 1 ]]; [[ $(grep -c '^POST .*/prices$' "$s/requests") == 5 ]]; [[ $(stat -c %a "$s/config.json") == 600 ]]; "$REAL_JQ" -e '.paddle_catalog.product_id=="pro_test" and ([.subscription_tiers[].paddle_price_id]|all(startswith("pri_test_")))' "$s/config.json" >/dev/null
[[ $(wc -l <"$s/bodies") == 6 ]]
"$REAL_JQ" -se '.[0]=={name:"Caution BYOC",tax_category:"saas",custom_data:{caution_catalog_key:"byoc_managed_enclaves"}} and (.[1:]|length==5 and all(.product_id=="pro_test" and (.description|type=="string") and (.unit_price.amount|type=="string") and .unit_price.currency_code=="USD" and .billing_cycle=={interval:"month",frequency:1} and .quantity=={minimum:1,maximum:1} and .custom_data.caution_catalog_version==1))' "$s/bodies" >/dev/null
cp "$s/config.json" "$s/first"; run_case existing "$s" --apply >"$s/out2" 2>"$s/err2"; cmp "$s/config.json" "$s/first"; ! grep -Eq '^(POST|PATCH|DELETE) ' "$s/requests"

# Duplicate metadata and mismatches fail before config replacement.
for mode in duplicate tierdup mismatch; do s="$TMP/$mode"; mkdir "$s"; new_config "$s/config.json"; cp "$s/config.json" "$s/before"; fail_case env PADDLE_STUB_MODE=$mode PADDLE_STUB_STATE=$s PATH="$TMP/bin:$PATH" "$SCRIPT" sync-catalog --environment sandbox --config "$s/config.json" --apply; cmp "$s/config.json" "$s/before"; [[ ! -s $s/requests || $(grep -c '^POST ' "$s/requests" || true) == 0 ]]; done

# Pagination and bounded retry.
s=$TMP/page; mkdir "$s"; new_config "$s/config.json"; run_case pagination "$s" >"$s/out" 2>"$s/err"; grep -q 'page=2' "$s/requests"
s=$TMP/has-more-false; mkdir "$s"; new_config "$s/config.json"; run_case has_more_false "$s" >"$s/out" 2>"$s/err"; ! grep -q 'after=last' "$s/requests"
s=$TMP/retry; mkdir "$s"; new_config "$s/config.json"; run_case retry "$s" >"$s/out" 2>"$s/err"; [[ $(grep -c '/products?status=active%2Carchived&per_page=200' "$s/requests") == 2 ]]
s=$TMP/retryfail; mkdir "$s"; new_config "$s/config.json"; fail_case env PADDLE_STUB_MODE=retryfail PADDLE_STUB_STATE=$s PATH="$TMP/bin:$PATH" "$SCRIPT" sync-catalog --environment sandbox --config "$s/config.json"; [[ $(grep -c '/products?status=active%2Carchived&per_page=200' "$s/requests") == 4 ]]

# Production writes need confirmation, and config targets must be regular, non-symlink files.
s=$TMP/prod; mkdir "$s"; new_config "$s/config.json"; fail_case env PADDLE_STUB_MODE=empty PADDLE_STUB_STATE=$s PATH="$TMP/bin:$PATH" "$SCRIPT" sync-catalog --environment production --config "$s/config.json" --apply
ln -s "$s/config.json" "$s/link.json"; fail_case env PADDLE_STUB_MODE=empty PADDLE_STUB_STATE=$s PATH="$TMP/bin:$PATH" "$SCRIPT" sync-catalog --environment sandbox --config "$s/link.json"

# Secret is absent from all captured output and fixture files.
! grep -R -F "$PADDLE_API_KEY" "$TMP" >/dev/null
printf 'provision-paddle tests: PASS\n'
