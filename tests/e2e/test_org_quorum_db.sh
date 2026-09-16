#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial
# Native Rust tests against an isolated, fully migrated PostgreSQL database.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
CONTAINER=""
MOCK_PID=""
cleanup() {
    if [ -n "$MOCK_PID" ]; then kill "$MOCK_PID" 2>/dev/null || true; wait "$MOCK_PID" 2>/dev/null || true; fi
    if [ -n "$CONTAINER" ]; then docker rm -fv "$CONTAINER" >/dev/null; fi
    rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
CONTAINER=$(docker run -d -p 127.0.0.1::5432 \
    -e POSTGRES_DB=caution_quorum_test -e POSTGRES_PASSWORD=postgres \
    -v "$ROOT/src/api/migrations:/migrations:ro" \
    -v "$ROOT/utils/makefile-run-migrations.sh:/migrate.sh:ro" postgres:16-alpine)
for _ in $(seq 1 60); do
    if docker exec "$CONTAINER" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; then break; fi
    sleep 1
done
docker exec "$CONTAINER" pg_isready -h 127.0.0.1 -U postgres >/dev/null
# Use the same ordered migration runner as make migrate-test.
docker exec -e MIGRATION_DB_HOST=127.0.0.1 -e MIGRATION_DB_NAME=caution_quorum_test \
    -e PGPASSWORD=postgres "$CONTAINER" sh /migrate.sh > "$WORK/migrations.log" 2>&1 \
    || { cat "$WORK/migrations.log"; exit 1; }
PORT=$(docker port "$CONTAINER" 5432/tcp | sed 's/.*://')
python3 - "$WORK" <<'PY' &
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json, sys, time
work = Path(sys.argv[1])
(work / "requests.jsonl").touch()
(work / "policy.json").write_text(json.dumps({"sets": [{"pcrs": {str(i): "ab" * 48 for i in range(3)}}]}))
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        with (work / "requests.jsonl").open("a") as log:
            log.write(json.dumps({"path": self.path, "body": request}) + "\n")
        mode = request.get("label", {}).get("test_response", "invalid-proof")
        if mode == "timeout": time.sleep(61)
        status = int(mode) if mode in ("429", "503") else 200
        # Deliberately invalid proof: must never reach successful API storage.
        response = {"data": {"version": "V1", "bundle_id": request["bundle_id"],
            "threshold": request["threshold"], "max": request["max"],
            "label": request["label"], "keyring": request["keyring"],
            "public_key": request["keyring"][0]["OpenPGP"]["cert"], "shardfile": "synthetic"}, "necroproof": [1, 2, 3]}
        body = json.dumps(response).encode()
        try:
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError): pass
server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
(work / "url").write_text("http://127.0.0.1:" + str(server.server_port))
server.serve_forever()
PY
MOCK_PID=$!
for _ in $(seq 1 30); do [ -s "$WORK/url" ] && break; sleep 1; done
cd "$ROOT"
env -u PUBLIC_CERTIFICATE_SERVICE_URL -u PUBLIC_CERTIFICATE_PCR_POLICY_PATH -u CAUTION_CA_CERT_PATH \
    QUORUM_TEST_DATABASE_URL="postgresql://postgres:postgres@127.0.0.1:$PORT/caution_quorum_test" \
    QUORUM_TEST_REQUEST_LOG="$WORK/requests.jsonl" \
    KEYMAKER_URL="$(cat "$WORK/url")" KEYMAKER_PCR_POLICY_PATH="$WORK/policy.json" \
    cargo test -p api org_quorum::tests::database::database_contracts --locked -- --ignored --exact --test-threads=1 --nocapture
