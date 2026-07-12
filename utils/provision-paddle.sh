#!/usr/bin/env bash
set -euo pipefail

readonly PRODUCT_KEY=byoc_managed_enclaves PRODUCT_NAME='Caution BYOC'
readonly MAX_ATTEMPTS=4 MAX_RETRY_AFTER=5 CONNECT_TIMEOUT=10 TOTAL_TIMEOUT=30
readonly MAX_PAGES=100 MAX_OBJECTS=10000 MAX_BYTES=10485760
error() { printf 'provision-paddle: %s\n' "$*" >&2; exit 1; }
usage() { printf '%s\n' 'usage: provision-paddle.sh sync-catalog --environment sandbox|production --config PATH [--api-url ORIGIN] [--apply] [--confirm-production]'; }
require_commands() { local c; for c in curl jq mktemp dirname stat chmod chown mv rm sleep awk cmp wc cp flock; do command -v "$c" >/dev/null 2>&1 || error "required command not found: $c"; done; }

apply=false confirm_production=false environment= config= api_override=
[[ ${1:-} == sync-catalog ]] || { usage >&2; exit 2; }; shift
while (($#)); do case $1 in
  --environment) (($# >= 2)) || error '--environment requires a value'; environment=$2; shift 2;;
  --config) (($# >= 2)) || error '--config requires a value'; config=$2; shift 2;;
  --api-url) (($# >= 2)) || error '--api-url requires a value'; api_override=$2; shift 2;;
  --apply) apply=true; shift;; --confirm-production) confirm_production=true; shift;;
  -h|--help) usage; exit 0;; *) error "unknown option: $1";; esac; done
require_commands
case $environment in sandbox) expected_origin=https://sandbox-api.paddle.com;; production) expected_origin=https://api.paddle.com;; '') error '--environment is required';; *) error '--environment must be sandbox or production';; esac
[[ -n $config ]] || error '--config is required'; [[ -n ${PADDLE_API_KEY:-} ]] || error 'PADDLE_API_KEY is required'
# Config-file quoting and HTTP header injection are impossible for this deliberately narrow token alphabet.
[[ $PADDLE_API_KEY =~ ^[A-Za-z0-9._-]+$ ]] || error 'PADDLE_API_KEY has an invalid form'
[[ -z $api_override || $api_override == "$expected_origin" || $api_override == "$expected_origin/" ]] || error '--api-url must use the exact selected Paddle API origin'
api_origin=${api_override%/}; api_origin=${api_origin:-$expected_origin}
$apply && [[ $environment == production ]] && ! $confirm_production && error 'production --apply requires --confirm-production'
[[ ! -L $config && -f $config ]] || error 'config target must be a regular, non-symlink file'

# Hold an advisory lock for the complete transaction and validate a private snapshot.
exec 9<"$config"; flock -n 9 || error 'config is locked by another process'
initial_stat=$(stat -Lc '%d:%i:%f:%u:%g:%a' -- "$config") || error 'cannot stat config'
work_dir=$(dirname -- "$config"); snapshot=$(mktemp "$work_dir/.provision-paddle.snapshot.XXXXXX")
response_file=$(mktemp "$work_dir/.provision-paddle.response.XXXXXX"); header_file=$(mktemp "$work_dir/.provision-paddle.headers.XXXXXX"); combined_file=$(mktemp "$work_dir/.provision-paddle.data.XXXXXX"); curl_error=$(mktemp "$work_dir/.provision-paddle.curl-error.XXXXXX"); temp_config=
cleanup() { rm -f -- "$snapshot" "$response_file" "$header_file" "$combined_file" "$curl_error" ${temp_config:+"$temp_config"}; }; trap cleanup EXIT HUP INT TERM
cp -- "$config" "$snapshot"; cmp -s -- "$config" "$snapshot" || error 'config changed while taking snapshot'
if ! jq -e '.paddle_catalog|type=="object"' "$snapshot" >/dev/null 2>&1 || ! jq -e '
 . as $r | (.paddle_catalog.version|type=="number" and .>=1 and floor==.) and
 .paddle_catalog.tax_category=="saas" and .paddle_catalog.currency_code=="USD" and .paddle_catalog.billing_cycle=={interval:"month",frequency:1} and
 (.paddle_catalog.product_id==null or (.paddle_catalog.product_id|type=="string" and test("^pro_[A-Za-z0-9_]+$"))) and
 (.subscription_tiers|type=="object") and ((.subscription_tiers|keys)==["1_enclave","2_enclaves","3_enclaves","4_enclaves","5_enclaves"]) and
 ([range(1;6) as $n | $r.subscription_tiers[($n|tostring)+(if $n==1 then "_enclave" else "_enclaves" end)] | type=="object" and .enclaves==$n and (.monthly_cents|type=="number") and .monthly_cents==[25000,37500,50000,62500,75000][$n-1] and (has("annual_cents")|not) and (.paddle_price_id==null or (.paddle_price_id|type=="string" and test("^pri_[A-Za-z0-9_]+$")))]|all)' "$snapshot" >/dev/null 2>&1; then error 'config does not contain a valid five-tier Paddle catalog'; fi
version=$(jq -r '.paddle_catalog.version' "$snapshot")

request() {
 local method=$1 url=$2 body=${3:-} attempt=1 status rc retry_after trace_was_on=false
 [[ $url == "$api_origin"/* && $url != *$'\r'* && $url != *$'\n'* && $url != *'@'* ]] || error 'refusing request outside selected Paddle API origin'
 while :; do
  : >"$response_file"; : >"$header_file"; : >"$curl_error"
  [[ $- == *x* ]] && trace_was_on=true || trace_was_on=false; set +x
  # The bearer value is supplied through a protected inherited fd, never curl's argv.
  if [[ -n $body ]]; then
   status=$(curl --config /dev/fd/3 --fail-with-body --silent --show-error --no-location --proto '=https' --connect-timeout "$CONNECT_TIMEOUT" --max-time "$TOTAL_TIMEOUT" -X "$method" -H 'Accept: application/json' -H 'Content-Type: application/json' --data-binary "$body" -o "$response_file" -D "$header_file" -w '%{http_code}' "$url" 3<<<"header = \"Authorization: Bearer ${!PADDLE_KEY_NAME}\"" 2>"$curl_error") && rc=0 || rc=$?
  else
   status=$(curl --config /dev/fd/3 --fail-with-body --silent --show-error --no-location --proto '=https' --connect-timeout "$CONNECT_TIMEOUT" --max-time "$TOTAL_TIMEOUT" -X "$method" -H 'Accept: application/json' -o "$response_file" -D "$header_file" -w '%{http_code}' "$url" 3<<<"header = \"Authorization: Bearer ${!PADDLE_KEY_NAME}\"" 2>"$curl_error") && rc=0 || rc=$?
  fi
  $trace_was_on && set -x
  [[ $status =~ ^[0-9]{3}$ ]] || status=000
  if ((rc==0)) && [[ $status =~ ^2 ]]; then jq -e 'type=="object"' "$response_file" >/dev/null 2>&1 || error "Paddle returned invalid JSON for $method request"; return; fi
  if [[ $status == 429 || $status =~ ^5 ]]; then ((attempt<MAX_ATTEMPTS)) || error "Paddle $method request failed after $MAX_ATTEMPTS attempts (HTTP $status; curl exit $rc)"; retry_after=$(awk 'BEGIN{IGNORECASE=1}/^Retry-After:[[:space:]]*[0-9]+/{gsub("\r","");sub(/^[^:]+:[[:space:]]*/,"");print;exit}' "$header_file"); [[ $retry_after =~ ^[0-9]+$ ]] || retry_after=1; ((retry_after<=MAX_RETRY_AFTER)) || retry_after=$MAX_RETRY_AFTER; sleep "$retry_after"; ((attempt++)); continue; fi
  error "Paddle $method ${url#"$api_origin"} request failed (HTTP $status; curl exit $rc)"
 done
}
PADDLE_KEY_NAME=PADDLE_API_KEY
list_all() {
 local url=$1 next pages=0 objects bytes seen=$'\n'
 printf '[]' >"$combined_file"
 while [[ -n $url ]]; do
  ((++pages<=MAX_PAGES)) || error 'Paddle pagination exceeded page limit'; [[ $seen != *$'\n'"$url"$'\n'* ]] || error 'Paddle pagination cycle detected'; seen+="$url"$'\n'
  request GET "$url"; jq -e '.data|type=="array"' "$response_file" >/dev/null 2>&1 || error 'Paddle list response has an invalid data envelope'
  objects=$(jq '.data|length' "$response_file"); (($(jq 'length' "$combined_file")+objects<=MAX_OBJECTS)) || error 'Paddle pagination exceeded object limit'
  jq -s '.[0]+.[1].data' "$combined_file" "$response_file" >"$combined_file.new"; mv -- "$combined_file.new" "$combined_file"; bytes=$(wc -c <"$combined_file"); ((bytes<=MAX_BYTES)) || error 'Paddle pagination exceeded aggregate size limit'
  next=$(jq -er '.meta.pagination as $p | (if ($p.has_more? == false) then "" else ($p.next // "") end) | if type=="string" then . else error("invalid") end' "$response_file") || error 'Paddle list response has invalid pagination metadata'
  [[ -z $next || $next == "$api_origin"/* ]] || error 'Paddle pagination URL left the selected API origin'; url=$next
 done
}
validate_product() { local json=$1; jq -e --arg key "$PRODUCT_KEY" '.id|type=="string" and test("^pro_[A-Za-z0-9_]+$")' <<<"$json" >/dev/null && jq -e --arg key "$PRODUCT_KEY" '.name=="Caution BYOC" and .tax_category=="saas" and .custom_data.caution_catalog_key==$key' <<<"$json" >/dev/null || error 'Paddle product mismatch (name, tax_category, or metadata)'; }
price_fields() { jq -r --arg p "$product_id" --arg a "$cents" --arg t "$tier" --argjson n "$n" --argjson v "$version" '[if .product_id!=$p then "product" else empty end,if .unit_price.amount!=$a then "amount" else empty end,if .unit_price.currency_code!="USD" then "currency" else empty end,if .billing_cycle!={interval:"month",frequency:1} then "cycle" else empty end,if .quantity!={minimum:1,maximum:1} then "quantity" else empty end,if (.custom_data.caution_catalog_key!="byoc_managed_enclaves" or .custom_data.caution_catalog_version!=$v or .custom_data.caution_tier_id!=$t or .custom_data.caution_enclave_limit!=$n) then "metadata" else empty end]|join(",")' <<<"$1"; }

list_all "$api_origin/products?status=active%2Carchived&per_page=200"
product_count=$(jq --arg k "$PRODUCT_KEY" '[.[]|select(.custom_data.caution_catalog_key==$k)]|length' "$combined_file"); ((product_count<=1)) || error 'duplicate Paddle products have the catalog metadata'; product_id=
if ((product_count)); then product=$(jq --arg k "$PRODUCT_KEY" '.[]|select(.custom_data.caution_catalog_key==$k)' "$combined_file"); validate_product "$product"; product_id=$(jq -r '.id' <<<"$product"); printf 'reuse product %s\n' "$product_id"
elif ! $apply; then printf 'plan create product %s\n' "$PRODUCT_NAME"
else product_body=$(jq -cn --arg k "$PRODUCT_KEY" '{name:"Caution BYOC",tax_category:"saas",custom_data:{caution_catalog_key:$k}}'); request POST "$api_origin/products" "$product_body"; product=$(jq -c '.data' "$response_file"); validate_product "$product"; product_id=$(jq -r '.id' <<<"$product"); printf 'created product %s\n' "$product_id"; fi
if [[ -z $product_id ]]; then for n in {1..5}; do tier=${n}_enclaves; [[ $n == 1 ]] && tier=1_enclave; printf 'plan create price %s\n' "$tier"; done; exit; fi

sync_prices() {
 list_all "$api_origin/prices?product_id=$product_id&status=active%2Carchived&per_page=200"; prices_json=$(<"$combined_file")
 duplicate=$(jq -r --arg k "$PRODUCT_KEY" --argjson v "$version" '[.[]|select(.custom_data.caution_catalog_key==$k and .custom_data.caution_catalog_version==$v)|.custom_data.caution_tier_id]|group_by(.)[]|select(length>1)|.[0]' <<<"$prices_json" | awk 'NR==1'); [[ -z $duplicate ]] || error "duplicate Paddle prices have tier metadata: $duplicate"
 for n in {1..5}; do tier=${n}_enclaves; [[ $n == 1 ]] && tier=1_enclave; cents=$(jq -r --arg t "$tier" '.subscription_tiers[$t].monthly_cents|tostring' "$snapshot"); price=$(jq -c --arg k "$PRODUCT_KEY" --arg t "$tier" --argjson v "$version" '.[]|select(.custom_data.caution_catalog_key==$k and .custom_data.caution_catalog_version==$v and .custom_data.caution_tier_id==$t)' <<<"$prices_json"); [[ -z $price ]] && continue; fields=$(price_fields "$price"); [[ -z $fields ]] || error "Paddle price mismatch for tier $tier: $fields"; id=$(jq -er '.id|select(test("^pri_[A-Za-z0-9_]+$"))' <<<"$price") || error "Paddle price has invalid ID for tier $tier"; price_ids[$tier]=$id
 done
}
declare -A price_ids; sync_prices
for n in {1..5}; do tier=${n}_enclaves; [[ $n == 1 ]] && tier=1_enclave; [[ -n ${price_ids[$tier]:-} ]] && { printf 'reuse price %s %s\n' "$tier" "${price_ids[$tier]}"; continue; }; $apply || { printf 'plan create price %s\n' "$tier"; continue; }; cents=$(jq -r --arg t "$tier" '.subscription_tiers[$t].monthly_cents|tostring' "$snapshot"); body=$(jq -cn --arg p "$product_id" --arg a "$cents" --arg k "$PRODUCT_KEY" --arg t "$tier" --argjson n "$n" --argjson v "$version" '{product_id:$p,description:("Caution BYOC "+$t),unit_price:{amount:$a,currency_code:"USD"},billing_cycle:{interval:"month",frequency:1},quantity:{minimum:1,maximum:1},custom_data:{caution_catalog_key:$k,caution_catalog_version:$v,caution_tier_id:$t,caution_enclave_limit:$n}}'); request POST "$api_origin/prices" "$body"; created=$(jq -c '.data' "$response_file"); fields=$(price_fields "$created"); [[ -z $fields ]] || error "created Paddle price mismatch for tier $tier: $fields"; id=$(jq -er '.id|select(test("^pri_[A-Za-z0-9_]+$"))' <<<"$created") || error "created Paddle price response has invalid ID for tier $tier"; printf 'created price %s %s\n' "$tier" "$id"; done
$apply || exit 0
# Paddle has no documented idempotency-key contract for these endpoints. Stable metadata permits safe reconciliation on rerun; resources are never rolled back, archived, or deleted.
unset price_ids; declare -A price_ids; sync_prices
for n in {1..5}; do tier=${n}_enclaves; [[ $n == 1 ]] && tier=1_enclave; [[ -n ${price_ids[$tier]:-} ]] || error "final Paddle catalog is missing tier $tier"; done
[[ ! -L $config && -f $config ]] || error 'config target type changed'; [[ $(stat -Lc '%d:%i:%f:%u:%g:%a' -- "$config") == "$initial_stat" ]] || error 'config identity or metadata changed'; cmp -s -- "$config" "$snapshot" || error 'config content changed'
temp_config=$(mktemp "$work_dir/.provision-paddle.config.XXXXXX"); mode=$(stat -c %a "$snapshot"); uid=$(stat -c %u "$snapshot"); gid=$(stat -c %g "$snapshot"); chmod "$mode" "$temp_config"; chown "$uid:$gid" "$temp_config" 2>/dev/null || { [[ $(stat -c %u:%g "$temp_config") == "$uid:$gid" ]] || error 'cannot preserve config owner'; }
jq --arg product "$product_id" --arg p1 "${price_ids[1_enclave]}" --arg p2 "${price_ids[2_enclaves]}" --arg p3 "${price_ids[3_enclaves]}" --arg p4 "${price_ids[4_enclaves]}" --arg p5 "${price_ids[5_enclaves]}" '.paddle_catalog.product_id=$product|.subscription_tiers["1_enclave"].paddle_price_id=$p1|.subscription_tiers["2_enclaves"].paddle_price_id=$p2|.subscription_tiers["3_enclaves"].paddle_price_id=$p3|.subscription_tiers["4_enclaves"].paddle_price_id=$p4|.subscription_tiers["5_enclaves"].paddle_price_id=$p5' "$snapshot" >"$temp_config"
if cmp -s -- "$config" "$temp_config"; then rm "$temp_config"; temp_config=; printf 'config unchanged\n'; else mv -- "$temp_config" "$config"; temp_config=; printf 'updated config %s\n' "$config"; fi
