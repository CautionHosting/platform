#!/bin/sh
set -eu

: "${MIGRATION_DB_HOST:=postgres}"
: "${MIGRATION_DB_USER:=${POSTGRES_USER:-postgres}}"
: "${MIGRATION_DB_NAME:=${POSTGRES_DB:-caution}}"
export PGPASSWORD="${PGPASSWORD:-${POSTGRES_PASSWORD:-}}"
export LC_ALL=C

# Older infrastructure bundles mount only one pending file and supply a psql
# adapter which owns --single-transaction + the ledger INSERT. Their caller
# already validates the complete history and precommits the audited 051 enum.
# Preserve that protocol without nesting transactions or writing its row twice.
if [ -n "${BOOTSTRAP_LEDGER_SQL:-}" ] && [ "$(command -v psql)" = /bootstrap/psql ]; then
	set -- /migrations/*.sql
	if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
		printf '%s\n' 'Legacy migration adapter requires exactly one SQL file' >&2
		exit 1
	fi
	exec psql -X -v ON_ERROR_STOP=1 \
		-h "$MIGRATION_DB_HOST" -U "$MIGRATION_DB_USER" -d "$MIGRATION_DB_NAME" \
		-c 'SELECT pg_advisory_xact_lock(1128355156, 1296648018);' -f "$1"
fi

work=$(mktemp -d /tmp/caution-migrations.XXXXXX)
trap 'rm -rf "$work"' EXIT
trap 'exit 1' HUP INT TERM
mkdir "$work/migrations"
program=$work/run.sql
steps=$work/steps.sql

# One psql session owns the database-scoped advisory lock through validation,
# every per-file commit, and the audited enum prerequisite. Session exit (also
# on SQL failure) releases it; no helper process or shared filesystem is needed.
cat > "$program" <<'EOF'
SELECT pg_advisory_lock(1128355156, 1296648018);
CREATE TABLE IF NOT EXISTS public.caution_bootstrap_migrations (filename text PRIMARY KEY, sha256 text NOT NULL);
CREATE TEMP TABLE migration_files (filename text PRIMARY KEY, sha256 text NOT NULL);
EOF
: > "$steps"
for migration in /migrations/*.sql; do
	[ -f "$migration" ] || continue
	filename=${migration##*/}
	case "$filename" in
		*[!A-Za-z0-9_.-]*) printf '%s\n' 'Invalid migration filename' >&2; exit 1 ;;
	esac
	# Bind the ledger to the bytes executed, even if the mounted checkout changes
	# while this runner waits for another session's advisory lock.
	cp "$migration" "$work/migrations/$filename"
	checksum=$(sha256sum "$work/migrations/$filename")
	checksum=${checksum%% *}
	printf "INSERT INTO migration_files VALUES ('%s', '%s');\n" "$filename" "$checksum" >> "$program"
	cat >> "$steps" <<EOF
SELECT NOT EXISTS (SELECT FROM public.caution_bootstrap_migrations WHERE filename = '$filename') AS pending \gset
\if :pending
EOF
	# Only these audited bytes need an enum value committed before their index
	# can use it. On failure, this idempotent prerequisite may survive; all other
	# DDL and the original file's ledger entry still roll back together.
	if [ "$filename" = 051_managed_app_endpoints.sql ] &&
		[ "$checksum" = ead9734cb5cda9d25f68e9781d0b470273225e87c617199d88f7666b2a1ab84d ]; then
		printf '%s\n' "ALTER TYPE resource_state ADD VALUE IF NOT EXISTS 'terminating';" >> "$steps"
	fi
	cat >> "$steps" <<EOF
BEGIN;
\i $work/migrations/$filename
INSERT INTO public.caution_bootstrap_migrations (filename, sha256) VALUES ('$filename', '$checksum');
COMMIT;
\endif
EOF
done

cat >> "$program" <<'EOF'
DO $$
BEGIN
    IF EXISTS (
        SELECT FROM public.caution_bootstrap_migrations applied
        LEFT JOIN migration_files files USING (filename)
        WHERE files.sha256 IS DISTINCT FROM applied.sha256
    ) THEN
        RAISE EXCEPTION 'applied migration history differs: missing file or changed checksum';
    END IF;
END $$;
EOF
cat "$steps" >> "$program"

psql -X -v ON_ERROR_STOP=1 \
	-h "$MIGRATION_DB_HOST" \
	-U "$MIGRATION_DB_USER" \
	-d "$MIGRATION_DB_NAME" \
	-f "$program"
