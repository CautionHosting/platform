#!/usr/bin/env bash
# Successful PGP orchestration with real passkey signatures and synthetic proofs.
# Native test binaries plus a disposable PostgreSQL container; no deployment.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
CONTAINER=""
PIDS=""
cleanup() {
    for pid in $PIDS; do kill "$pid" 2>/dev/null || true; done
    for pid in $PIDS; do wait "$pid" 2>/dev/null || true; done
    if [ -n "$CONTAINER" ]; then docker rm -fv "$CONTAINER" >/dev/null; fi
    rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# API currently binds port 8080. Refuse an occupied port; never stop another stack.
python3 - <<'PY'
import socket
with socket.socket() as s: s.bind(('127.0.0.1',8080))
PY
cd "$ROOT"
# Separate artifacts keep ordinary build targets free of unsafe features.
export CARGO_TARGET_DIR="$ROOT/target/quorum-e2e"
cargo build --locked -p api -p cli -p gateway \
    --features api/e2e-testing-unsafe,cli/e2e-testing-unsafe,gateway/e2e-testing-unsafe
# Browser approval must reject arbitrary/login challenges and production builds
# must reject synthetic custody evidence even when the runtime flag is enabled.
CAUTION_UNSAFE_KEY_SERVICE_E2E=1 cargo test --locked -p gateway release_relay
CAUTION_UNSAFE_KEY_SERVICE_E2E=1 cargo test --locked -p gateway --features e2e-testing-unsafe release_relay
LOCKSMITH_SOURCE=$(cargo metadata --locked --format-version 1 | python3 -c '
import json,sys,pathlib
p=next(p for p in json.load(sys.stdin)["packages"] if p["name"]=="keymaker-models")
print(pathlib.Path(p["manifest_path"]).parents[2])')
cargo build --locked --manifest-path "$LOCKSMITH_SOURCE/Cargo.toml" \
    -p keymaker --no-default-features --features unsafe-e2e
cargo build --locked --manifest-path tests/e2e/soft-authenticator/Cargo.toml
# Actual WebAuthn verification + selected-share decryption + unchanged receiver
# transport, with deliberately synthetic Nitro evidence in an isolated process.
CAUTION_UNSAFE_KEY_SERVICE_E2E=1 cargo test --locked --manifest-path "$LOCKSMITH_SOURCE/Cargo.toml" \
    -p locksmith --lib --features unsafe-e2e release::tests
CAUTION_UNSAFE_KEY_SERVICE_E2E=1 cargo test --locked --manifest-path "$LOCKSMITH_SOURCE/Cargo.toml" \
    -p public-cert-service --lib --features unsafe-e2e release::tests
# Build from the repository so Cargo sees its private-registry configuration;
# run the resulting test binary later from the isolated fixture directory.
RECOVERY_TEST=$(cargo test -p cli --lib --locked --features e2e-testing-unsafe \
    --no-run --message-format=json | python3 -c '
import json,sys
for line in sys.stdin:
    item=json.loads(line)
    if item.get("reason")=="compiler-artifact" and item.get("executable"):
        print(item["executable"])')
mkdir -p "$WORK/policies" "$WORK/data"
cp prices.json.example "$WORK/prices.json"
cp config.json.example "$WORK/config.json"
python3 - "$WORK" <<'PY'
import json,pathlib,socket,sys
w=pathlib.Path(sys.argv[1])
(w/'policies/keymaker-pcr-policy.json').write_text(json.dumps({'sets':[{'pcrs':{str(i):'ab'*48 for i in range(3)}}]}))
(w/'policies/certificate-pcr-policy.json').write_bytes((w/'policies/keymaker-pcr-policy.json').read_bytes())
sockets=[]
for name in ['gateway','keymaker','proxy','ssh','certificate']:
    s=socket.socket(); s.bind(('127.0.0.1',0)); sockets.append(s)
    (w/(name+'.port')).write_text(str(s.getsockname()[1]))
PY
CONTAINER=$(docker run -d -p 127.0.0.1::5432 \
    -e POSTGRES_DB=caution_quorum_test -e POSTGRES_PASSWORD=postgres \
    -v "$ROOT/src/api/migrations:/migrations:ro" \
    -v "$ROOT/utils/makefile-run-migrations.sh:/migrate.sh:ro" postgres:16-alpine)
for _ in $(seq 1 60); do
    if docker exec "$CONTAINER" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; then break; fi
    sleep 1
done
docker exec -e MIGRATION_DB_HOST=127.0.0.1 -e MIGRATION_DB_NAME=caution_quorum_test \
    -e PGPASSWORD=postgres "$CONTAINER" sh /migrate.sh > "$WORK/migrations.log" 2>&1 \
    || { cat "$WORK/migrations.log"; exit 1; }
DB_PORT=$(docker port "$CONTAINER" 5432/tcp | sed 's/.*://')
GATEWAY_URL="http://localhost:$(cat "$WORK/gateway.port")"
KEYMAKER_BACKEND_URL="http://127.0.0.1:$(cat "$WORK/keymaker.port")"
KEYMAKER_URL="http://127.0.0.1:$(cat "$WORK/proxy.port")"
PUBLIC_CERTIFICATE_SERVICE_URL="http://127.0.0.1:$(cat "$WORK/certificate.port")"
"$CARGO_TARGET_DIR/debug/certificate-mock" "$WORK" > "$WORK/certificate.log" 2>&1 &
PIDS="$PIDS $!"
# Test-only intermediary: change the request before the actual local Keymaker sees it.
python3 - "$WORK" "$KEYMAKER_BACKEND_URL" <<'PYPROXY' &
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import json, sys
work, backend = Path(sys.argv[1]), sys.argv[2]
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self): self.forward(None)
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        with (work / 'keymaker-requests.jsonl').open('a') as log: log.write(json.dumps(body) + '\n')
        if (work / 'downgrade-threshold').exists(): body['threshold'] = 1
        self.forward(json.dumps(body).encode())
    def forward(self, body):
        request = Request(backend + self.path, data=body,
                          headers={'Content-Type': 'application/json'})
        try: response = urlopen(request, timeout=60)
        except HTTPError as error: response = error
        except URLError:
            self.send_error(503, 'Keymaker is not ready')
            return
        with response:
            payload = response.read()
            if body is not None and (work / 'downgrade-threshold').exists():
                (work / 'downgraded-bundle.json').write_bytes(payload)
            self.send_response(response.status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
ThreadingHTTPServer(('127.0.0.1', int((work / 'proxy.port').read_text())), Handler).serve_forever()
PYPROXY
PIDS="$PIDS $!"
# Empty environment and disposable cwd avoid loading operator credentials/config.
COMMON=(env -i "PATH=$PATH" "ENVIRONMENT=test" "AWS_EC2_METADATA_DISABLED=true" "AWS_REGION=quorum-test"
    "DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:$DB_PORT/caution_quorum_test"
    "CAUTION_DATA_DIR=$WORK/data" "CAUTION_UNSAFE_KEY_SERVICE_E2E=1"
    "KEYMAKER_URL=$KEYMAKER_URL" "KEYMAKER_PCR_POLICY_PATH=$WORK/policies/keymaker-pcr-policy.json"
    "PUBLIC_CERTIFICATE_SERVICE_URL=$PUBLIC_CERTIFICATE_SERVICE_URL"
    "PUBLIC_CERTIFICATE_PCR_POLICY_PATH=$WORK/policies/certificate-pcr-policy.json"
    "CAUTION_CA_CERT_PATH=$WORK/policies/caution-ca.asc")
cd "$WORK"
"${COMMON[@]}" KEYMAKER_LISTEN_ADDR="127.0.0.1:$(cat keymaker.port)" \
    "$CARGO_TARGET_DIR/debug/keymaker" > keymaker.log 2>&1 &
PIDS="$PIDS $!"
"${COMMON[@]}" BUILDER_AMI_ID=test BUILDER_SECURITY_GROUP_ID=test \
    BUILDER_SUBNET_ID=test BUILDER_INSTANCE_PROFILE=test \
    AWS_ENDPOINT_URL=http://127.0.0.1:9 \
    "$CARGO_TARGET_DIR/debug/api" > api.log 2>&1 &
PIDS="$PIDS $!"
"${COMMON[@]}" PORT="$(cat gateway.port)" SSH_PORT="$(cat ssh.port)" \
    RP_ID=localhost RP_ORIGINS="$GATEWAY_URL" API_SERVICE_URL=http://127.0.0.1:8080 \
    SSH_HOST_KEY_PATH="$WORK/ssh_host_key" CSRF_SECRET=quorum-test-only \
    "$CARGO_TARGET_DIR/debug/gateway" > gateway.log 2>&1 &
PIDS="$PIDS $!"
for url in "$PUBLIC_CERTIFICATE_SERVICE_URL" "$KEYMAKER_URL" http://127.0.0.1:8080 "$GATEWAY_URL"; do
    for _ in $(seq 1 60); do curl -fsS "$url/health" >/dev/null 2>&1 && break; sleep 1; done
    curl -fsS "$url/health" >/dev/null || { cat ./*.log; exit 1; }
done
docker exec "$CONTAINER" psql -U postgres -d caution_quorum_test -c \
    "INSERT INTO beta_codes(code) VALUES ('quorum-mock-test');" >/dev/null
"${COMMON[@]}" GATEWAY_URL="$GATEWAY_URL" RP_ORIGIN="$GATEWAY_URL" \
    ALPHA_CODE=quorum-mock-test USERNAME=quorummock \
    QUORUM_E2E_DIR="$WORK" \
    QUORUM_DB_CONTAINER="$CONTAINER" \
    QUORUM_CLI="$CARGO_TARGET_DIR/debug/caution" \
    "$CARGO_TARGET_DIR/debug/soft-authenticator" || { cat ./*.log; exit 1; }
# Invoke the actual CLI send-shard implementation with isolated client config.
# The certificate mock supplies app metadata only; recovery must stop before transport.
CAUTION_UNSAFE_KEY_SERVICE_E2E=1 \
KEYMAKER_PCR_POLICY_PATH="$WORK/policies/keymaker-pcr-policy.json" \
PUBLIC_CERTIFICATE_SERVICE_URL="$PUBLIC_CERTIFICATE_SERVICE_URL" \
QUORUM_RECOVERY_TEST_DIR="$WORK" \
    "$RECOVERY_TEST" --ignored --exact \
    quorum_init::tests::downloaded_bundles_require_explicit_noninteractive_holder --nocapture
# A terminal receives no JSON dump, even in a directory without app metadata.
"${COMMON[@]}" python3 - "$CARGO_TARGET_DIR/debug/caution" "$WORK" <<'PY'
import errno, json, os, pathlib, pty, subprocess, sys
cli, work = sys.argv[1], pathlib.Path(sys.argv[2])
plain = work / 'plain-terminal'
plain.mkdir()
master, slave = pty.openpty()
process = subprocess.Popen([
    cli, 'secret', 'init', str(work / 'holder.asc'), '--threshold', '1',
    '--no-upload', '--keymaker-url', os.environ['KEYMAKER_URL'],
    '--keymaker-pcr-policy', str(work / 'policies/keymaker-pcr-policy.json'),
], cwd=plain, stdin=subprocess.DEVNULL, stdout=slave, stderr=subprocess.PIPE)
os.close(slave)
# Drain stdout while the process runs so a regression cannot fill the PTY buffer.
output = bytearray()
try:
    while True:
        chunk = os.read(master, 65536)
        if not chunk:
            break
        output.extend(chunk)
except OSError as error:
    if error.errno != errno.EIO:
        raise
finally:
    os.close(master)
_, stderr = process.communicate(timeout=60)
assert process.returncode == 0, stderr.decode()
assert not output, 'terminal received bundle JSON'
assert b'Saved .caution/quorum-bundle.json' in stderr
json.loads((plain / '.caution/quorum-bundle.json').read_text())
assert (plain / '.caution/keymaker-pcr-policy.json').read_bytes() == (work / 'policies/keymaker-pcr-policy.json').read_bytes()
print('Plain-directory terminal output and persisted artifacts: OK')
PY
