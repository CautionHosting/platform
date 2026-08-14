: "${MIGRATION_DB_HOST:=postgres}"
: "${MIGRATION_DB_USER:=postgres}"
: "${MIGRATION_DB_NAME:=caution}"

for migration in /migrations/*.sql; do
	psql -v ON_ERROR_STOP=1 \
		-h "$MIGRATION_DB_HOST" \
		-U "$MIGRATION_DB_USER" \
		-d "$MIGRATION_DB_NAME" \
		-f "$migration" || exit 1
done
