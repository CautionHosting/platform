#!/bin/bash

set -e

COUNT="${1:-50}"
CONTAINER="${2:-postgres}"

echo "Generating $COUNT beta codes..."
echo ""

for i in $(seq 1 "$COUNT"); do
    CODE=$(openssl rand -hex 16)
    docker exec "$CONTAINER" psql -U postgres -d caution -q -c "INSERT INTO beta_codes (code) VALUES ('$CODE')"
    echo "$CODE"
done

