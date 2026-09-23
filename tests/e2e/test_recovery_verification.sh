#!/usr/bin/env bash
# Production gateway plus disposable PostgreSQL; no existing services are stopped.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
CONTAINER=""
GATEWAY_PID=""
cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then cat "$WORK"/*.log 2>/dev/null || true; fi
    if [ -n "$GATEWAY_PID" ]; then kill "$GATEWAY_PID" 2>/dev/null || true; wait "$GATEWAY_PID" 2>/dev/null || true; fi
    if [ -n "$CONTAINER" ]; then docker rm -fv "$CONTAINER" >/dev/null; fi
    rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
cd "$ROOT"
cargo build --locked -p gateway
CONTAINER=$(docker run -d -p 127.0.0.1::5432 -e POSTGRES_DB=caution_quorum_test -e POSTGRES_PASSWORD=postgres \
    -v "$ROOT/src/api/migrations:/migrations:ro" -v "$ROOT/utils/makefile-run-migrations.sh:/migrate.sh:ro" postgres:16-alpine)
for _ in $(seq 1 60); do docker exec "$CONTAINER" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1 && break; sleep 1; done
docker exec -e MIGRATION_DB_HOST=127.0.0.1 -e MIGRATION_DB_NAME=caution_quorum_test -e PGPASSWORD=postgres \
    "$CONTAINER" sh /migrate.sh > "$WORK/migrations.log" 2>&1
DB_PORT=$(docker port "$CONTAINER" 5432/tcp | sed 's/.*://')
python3 - "$WORK" <<'PY'
import pathlib, socket, sys
sockets=[]
for name in ['gateway', 'ssh']:
    s=socket.socket(); s.bind(('127.0.0.1',0)); sockets.append(s)
    (pathlib.Path(sys.argv[1]) / name).write_text(str(s.getsockname()[1]))
PY
GATEWAY_URL="http://localhost:$(cat "$WORK/gateway")"
cd "$WORK"
start_gateway() {
env -i PATH="$PATH" ENVIRONMENT=test DATABASE_URL="postgresql://postgres:postgres@127.0.0.1:$DB_PORT/caution_quorum_test" \
    PORT="$(cat gateway)" SSH_PORT="$(cat ssh)" RP_ID=localhost RP_ORIGINS="$GATEWAY_URL" \
    SSH_HOST_KEY_PATH="$WORK/ssh_host_key" CAUTION_DATA_DIR="$WORK/data" CSRF_SECRET=recovery-test-only \
    "$ROOT/target/debug/gateway" > "$WORK/gateway.log" 2>&1 &
GATEWAY_PID=$!
for _ in $(seq 1 60); do curl -fsS "$GATEWAY_URL/health" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS "$GATEWAY_URL/health" >/dev/null
}
start_gateway
GATEWAY_URL="$GATEWAY_URL" QUORUM_DB_CONTAINER="$CONTAINER" \
    node "$ROOT/tests/e2e/browser-authenticator/recovery-verification.mjs"

# Exercise the real startup backfill, retaining later assertion evidence.
docker exec -i "$CONTAINER" psql -U postgres -d caution_quorum_test -v ON_ERROR_STOP=1 <<'SQL'
UPDATE fido2_credentials SET uv_verified = false
WHERE (convert_from(public_key, 'UTF8')::jsonb #>> '{cred,user_verified}') = 'true';
INSERT INTO fido2_credentials(user_id, credential_id, public_key)
SELECT user_id, decode('ff01', 'hex'), convert_to('{"cred":{"user_verified":true}}', 'UTF8')
FROM fido2_credentials LIMIT 1;
SQL
kill "$GATEWAY_PID"
wait "$GATEWAY_PID" || true
start_gateway
docker exec -i "$CONTAINER" psql -U postgres -d caution_quorum_test -v ON_ERROR_STOP=1 <<'SQL'
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM fido2_credentials WHERE uv_verified
     AND (convert_from(public_key, 'UTF8')::jsonb #>> '{cred,user_verified}') = 'true') THEN
    RAISE EXCEPTION 'valid registration evidence was not backfilled';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM fido2_credentials WHERE uv_verified
     AND (convert_from(public_key, 'UTF8')::jsonb #>> '{cred,user_verified}') = 'false') THEN
    RAISE EXCEPTION 'later assertion evidence was cleared';
  END IF;
  IF EXISTS (SELECT 1 FROM fido2_credentials WHERE credential_id = decode('ff01','hex') AND uv_verified) THEN
    RAISE EXCEPTION 'malformed credential was backfilled';
  END IF;
END $$;
SQL
echo 'Startup UV backfill: verified registration, malformed record and preserved assertion evidence passed'
