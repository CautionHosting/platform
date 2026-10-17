#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial
# App deployments concurrency, reconciliation and metering reconcile tests against an isolated,
# fully migrated PostgreSQL database (anonymous container on a random port; no test stack).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
CONTAINER=""
cleanup() {
    if [ -n "$CONTAINER" ]; then docker rm -fv "$CONTAINER" >/dev/null; fi
    rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
CONTAINER=$(docker run -d -p 127.0.0.1::5432 \
    -e POSTGRES_DB=caution_app_deployments_test -e POSTGRES_PASSWORD=postgres \
    -v "$ROOT/src/api/migrations:/migrations:ro" \
    -v "$ROOT/utils/makefile-run-migrations.sh:/migrate.sh:ro" postgres:16-alpine)
for _ in $(seq 1 60); do
    if docker exec "$CONTAINER" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; then break; fi
    sleep 1
done
docker exec "$CONTAINER" pg_isready -h 127.0.0.1 -U postgres >/dev/null
# Use the same ordered migration runner as make migrate-test.
docker exec -e MIGRATION_DB_HOST=127.0.0.1 -e MIGRATION_DB_NAME=caution_app_deployments_test \
    -e PGPASSWORD=postgres "$CONTAINER" sh /migrate.sh > "$WORK/migrations.log" 2>&1 \
    || { cat "$WORK/migrations.log"; exit 1; }
PORT=$(docker port "$CONTAINER" 5432/tcp | sed 's/.*://')
cd "$ROOT"
export APP_DEPLOYMENTS_TEST_DATABASE_URL="postgresql://postgres:postgres@127.0.0.1:$PORT/caution_app_deployments_test"
# A syntactically valid framework commit lets /deploy reach its later gates.
PLATFORM_GIT_SHA=0000000000000000000000000000000000000000 \
    cargo test -p api app_deployments::lifecycle::db_tests --locked \
    -- --ignored --test-threads=1 --nocapture
# The metering service's reconcile SQL runs against the same schema.
cargo test -p metering handlers::collection::tests --locked \
    -- --ignored --test-threads=1 --nocapture
# Replay after lifecycle fixtures have populated the schema, using the normal runner.
docker exec -e MIGRATION_DB_HOST=127.0.0.1 -e MIGRATION_DB_NAME=caution_app_deployments_test \
    -e PGPASSWORD=postgres "$CONTAINER" sh /migrate.sh > "$WORK/migrations-replay.log" 2>&1 \
    || { cat "$WORK/migrations-replay.log"; exit 1; }
