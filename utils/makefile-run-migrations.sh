for migration in /migrations/*.sql; do
	psql -v ON_ERROR_STOP=1 -h postgres -U postgres -d caution -f "$migration" || exit 1
done
