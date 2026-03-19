#!/bin/bash

set -e

AMOUNT_DOLLARS="${1:?Usage: $0 <amount_dollars> [count] [container]}"
COUNT="${2:-1}"
CONTAINER="${3:-postgres}"
AMOUNT_CENTS=$((AMOUNT_DOLLARS * 100))

echo "Generating $COUNT credit code(s) worth \$$AMOUNT_DOLLARS each..."
echo ""

for i in $(seq 1 "$COUNT"); do
    RAW=$(openssl rand -hex 16 | tr '[:lower:]' '[:upper:]')
    DISPLAY=$(echo "$RAW" | sed 's/.\{4\}/&-/g; s/-$//')
    docker exec "$CONTAINER" psql -U postgres -d caution -q -c "INSERT INTO credit_codes (code, amount_cents) VALUES ('$RAW', $AMOUNT_CENTS)"
    echo "$DISPLAY"
done
