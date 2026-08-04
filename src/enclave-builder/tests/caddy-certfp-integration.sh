#!/bin/sh
set -eu

openssl_bin="${CADDY_TEST_OPENSSL:?CADDY_TEST_OPENSSL is required}"
port="${CADDY_TEST_PORT:?CADDY_TEST_PORT is required}"
publisher="${CADDY_TEST_PUBLISHER:?CADDY_TEST_PUBLISHER is required}"
domain="certfp.test"
test_dir="$(mktemp -d)"
server_pid=""
publisher_pid=""

cleanup() {
    if [ -n "${publisher_pid}" ]; then
        kill "${publisher_pid}" 2>/dev/null || true
        wait "${publisher_pid}" 2>/dev/null || true
    fi
    if [ -n "${server_pid}" ]; then
        kill "${server_pid}" 2>/dev/null || true
        wait "${server_pid}" 2>/dev/null || true
    fi
    rm -rf "${test_dir}"
}
trap cleanup EXIT INT TERM

cd "${test_dir}"

"${openssl_bin}" req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
    -subj "/CN=Caddy certfp test root" \
    -keyout root.key -out root.pem >/dev/null 2>&1
"${openssl_bin}" req -new -newkey rsa:2048 -nodes -sha256 \
    -subj "/CN=Caddy certfp test intermediate" \
    -keyout intermediate.key -out intermediate.csr >/dev/null 2>&1
printf '%s\n' \
    'basicConstraints=critical,CA:TRUE,pathlen:0' \
    'keyUsage=critical,keyCertSign,cRLSign' \
    'subjectKeyIdentifier=hash' \
    'authorityKeyIdentifier=keyid,issuer' >intermediate.ext
"${openssl_bin}" x509 -req -sha256 -days 1 \
    -in intermediate.csr -CA root.pem -CAkey root.key -CAcreateserial \
    -extfile intermediate.ext -out intermediate.pem >/dev/null 2>&1

issue_leaf() {
    name="$1"
    hostname="$2"
    "${openssl_bin}" req -new -newkey rsa:2048 -nodes -sha256 \
        -subj "/CN=${hostname}" \
        -keyout "${name}.key" -out "${name}.csr" >/dev/null 2>&1
    printf '%s\n' \
        'basicConstraints=critical,CA:FALSE' \
        'keyUsage=critical,digitalSignature,keyEncipherment' \
        'extendedKeyUsage=serverAuth' \
        "subjectAltName=DNS:${hostname}" >"${name}.ext"
    "${openssl_bin}" x509 -req -sha256 -days 1 \
        -in "${name}.csr" -CA intermediate.pem -CAkey intermediate.key \
        -CAcreateserial -extfile "${name}.ext" -out "${name}.pem" >/dev/null 2>&1
}

issue_leaf leaf-a "${domain}"
issue_leaf leaf-b "${domain}"
issue_leaf wrong-host wrong.test
"${openssl_bin}" req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
    -subj "/CN=${domain}" -addext "subjectAltName=DNS:${domain}" \
    -keyout untrusted.key -out untrusted.pem >/dev/null 2>&1

start_server() {
    cert="$1"
    key="$2"
    chain_args=""
    if [ "$#" -eq 3 ]; then
        chain_args="$3"
    fi
    if [ -n "${chain_args}" ]; then
        "${openssl_bin}" s_server -quiet -www -accept "127.0.0.1:${port}" \
            -cert "${cert}" -key "${key}" -cert_chain "${chain_args}" \
            >server.log 2>&1 &
    else
        "${openssl_bin}" s_server -quiet -www -accept "127.0.0.1:${port}" \
            -cert "${cert}" -key "${key}" >server.log 2>&1 &
    fi
    server_pid=$!
    sleep 1
}

stop_server() {
    kill "${server_pid}" 2>/dev/null || true
    wait "${server_pid}" 2>/dev/null || true
    server_pid=""
}

certfp() {
    "${openssl_bin}" x509 -in "$1" -noout -fingerprint -sha256 \
        | cut -d= -f2 | tr -d ': ' | tr 'A-F' 'a-f'
}

wait_for_fingerprint() {
    expected="$1"
    attempts=0
    while [ "${attempts}" -lt 12 ]; do
        if [ -f metadata.json ]; then
            if ! grep -Eq '^\{"tls":\{"mode":"caddy","domain":"certfp\.test","certfp":"[a-f0-9]{64}"\}\}$' metadata.json; then
                echo "publisher exposed invalid or partial metadata" >&2
                exit 1
            fi
            if grep -Fqx "{\"tls\":{\"mode\":\"caddy\",\"domain\":\"${domain}\",\"certfp\":\"${expected}\"}}" metadata.json; then
                return 0
            fi
        fi
        attempts=$((attempts + 1))
        sleep 1
    done
    echo "publisher did not publish expected fingerprint ${expected}" >&2
    cat publisher.log >&2 || true
    exit 1
}

CADDY_DOMAIN="${domain}" \
CADDY_TLS_ADDRESS="127.0.0.1:${port}" \
CADDY_CA_FILE="${test_dir}/root.pem" \
CADDY_METADATA_PATH="${test_dir}/metadata.json" \
CADDY_CERT_POLL_SECONDS=1 \
CADDY_CERT_WORK_DIR="${test_dir}/publisher-work" \
sh "${publisher}" >publisher.log 2>&1 &
publisher_pid=$!

start_server untrusted.pem untrusted.key
sleep 2
test ! -e metadata.json
stop_server

start_server wrong-host.pem wrong-host.key intermediate.pem
sleep 2
test ! -e metadata.json
stop_server

start_server leaf-a.pem leaf-a.key intermediate.pem
wait_for_fingerprint "$(certfp leaf-a.pem)"
stop_server

start_server leaf-b.pem leaf-b.key intermediate.pem
wait_for_fingerprint "$(certfp leaf-b.pem)"

test ! -e "metadata.json.tmp.${publisher_pid}"
