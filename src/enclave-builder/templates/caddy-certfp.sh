#!/bin/sh
set -u

caddy_domain="${CADDY_DOMAIN:?CADDY_DOMAIN is required}"
tls_address="${CADDY_TLS_ADDRESS:-127.0.0.1:443}"
ca_file="${CADDY_CA_FILE:-/etc/ssl/certs/ca-certificates.crt}"
metadata_path="${CADDY_METADATA_PATH:-/metadata.json}"
poll_seconds="${CADDY_CERT_POLL_SECONDS:-60}"
work_dir="${CADDY_CERT_WORK_DIR:-/tmp/caddy-certfp}"

mkdir -p "${work_dir}"
last_certfp=""

while true; do
    served_chain="${work_dir}/served-chain.pem"
    served_leaf="${work_dir}/served-leaf.pem"

    if /usr/bin/openssl s_client \
        -connect "${tls_address}" \
        -servername "${caddy_domain}" \
        -showcerts \
        -verify_return_error \
        -verify_hostname "${caddy_domain}" \
        -purpose sslserver \
        -CAfile "${ca_file}" \
        </dev/null >"${served_chain}" 2>"${work_dir}/s_client.err" \
        && /usr/bin/openssl x509 \
            -in "${served_chain}" \
            -out "${served_leaf}" 2>"${work_dir}/x509.err"; then
        certfp="$(
            /usr/bin/openssl x509 \
                -in "${served_leaf}" \
                -noout \
                -fingerprint \
                -sha256 \
            | cut -d= -f2 \
            | tr -d ': ' \
            | tr 'A-F' 'a-f'
        )"

        if [ -n "${certfp}" ] && [ "${certfp}" != "${last_certfp}" ]; then
            metadata_tmp="${metadata_path}.tmp.$$"
            if printf '{"tls":{"mode":"tls","domain":"%s","certfp":"%s"}}\n' \
                "${caddy_domain}" "${certfp}" >"${metadata_tmp}" \
                && mv -f "${metadata_tmp}" "${metadata_path}"; then
                last_certfp="${certfp}"
                echo "Published verified TLS certfp to ${metadata_path}"
            else
                rm -f "${metadata_tmp}"
                echo "WARNING: failed to publish TLS certfp"
            fi
        fi
    else
        echo "WARNING: enclave Caddy is not serving a trusted certificate for ${caddy_domain}"
    fi

    sleep "${poll_seconds}"
done
