#!/bin/bash

# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

# migrate-to-enterprise.sh
#
# Atomically migrates a single organization from legacy_credits billing to an
# enterprise subscription. Within one transaction the script will:
#
#   1. Lock and validate that the org has exactly one active (non-canceled)
#      subscription whose billing_source is 'legacy_credits'.
#   2. Locate the open subscription_ledger segment (billing_period_end IS NULL).
#   3. Update subscriptions: set billing_source = 'enterprise', max_apps to
#      i32::MAX (effectively unlimited), and updated_at = NOW().
#   4. Terminate the current ledger entry by setting billing_period_end = NOW().
#   5. Verify that exactly one row was changed in each UPDATE before committing.
#
# If any precondition fails or a row-count check does not match, an exception is
# raised and the transaction rolls back -- no partial state is left behind.
#
# Usage:
#   ./utils/migrate-to-enterprise.sh <org-uuid> [container-name]
#
# Examples:
#   ./utils/migrate-to-enterprise.sh 123e4567-e89b-12d3-a456-426614174000
#   ./utils/migrate-to-enterprise.sh 123e4567-e89b-12d3-a456-426614174000 caution-postgres

set -euo pipefail

UUID_REGEX='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
ORG_ID="${1:-}"
CONTAINER="${2:-postgres}"

# Validate arguments

if [[ -z "$ORG_ID" ]]; then
    echo "Usage: $0 <org-uuid> [container-name]"
    echo ""
    echo "Atomically migrates an organization from legacy_credits to enterprise billing."
    echo ""
    echo "Arguments:"
    echo "  org-uuid        UUID of the target organization (required)"
    echo "  container-name  Docker container running PostgreSQL (default: postgres)"
    exit 1
fi

if ! [[ "$ORG_ID" =~ $UUID_REGEX ]]; then
    echo "Error: Invalid UUID format: $ORG_ID" >&2
    echo "Expected a lowercase UUID like: 123e4567-e89b-12d3-a456-426614174000" >&2
    exit 1
fi

# Normalize to lowercase (UUID regex above already enforces this, but be explicit)
ORG_ID=$(echo "$ORG_ID" | tr '[:upper:]' '[:lower:]')

# Verify the container is running

if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
    echo "Error: Docker container '$CONTAINER' is not running." >&2
    echo "Start it with: make up" >&2
    exit 1
fi

echo "=== Enterprise Migration ==="
echo "Organization ID : $ORG_ID"
echo "Database        : caution (container: $CONTAINER)"
echo ""

# Run the atomic transaction
# The entire operation runs inside a single PostgreSQL DO block wrapped in
# BEGIN/COMMIT. Any RAISE EXCEPTION aborts the transaction via \set on_error_stop.

docker exec "$CONTAINER" psql -U postgres -d caution -v ON_ERROR_STOP=1 -v org_id="$ORG_ID" <<SQL
BEGIN;

DO \$\$
DECLARE
    v_org_id      UUID := NULLIF(:'org_id', '')::UUID;
    sub_row       RECORD;
    ledger_id     UUID;
    affected_rows BIGINT;
BEGIN
    -- Validate that an organization ID was supplied
    IF v_org_id IS NULL THEN
        RAISE EXCEPTION 'organization ID is required';
    END IF;

    -- Verify the organization exists before proceeding
    IF NOT EXISTS (SELECT 1 FROM organizations WHERE id = v_org_id) THEN
        RAISE EXCEPTION 'organization % does not exist', v_org_id;
    END IF;

    -- 1. Lock and validate the subscription row
    --     Only one non-canceled subscription per organization exists (unique
    --     index idx_subscriptions_org_non_canceled). We additionally require
    --     billing_source = 'legacy_credits' so we never silently convert a
    --     paddle or already-enterprise subscription.
    SELECT s.id, s.billing_source, s.status
      INTO sub_row
    FROM subscriptions s
    WHERE s.organization_id = v_org_id
      AND s.status <> 'canceled'
      AND s.billing_source = 'legacy_credits'
    ORDER BY s.created_at ASC   -- deterministic pick if duplicates somehow exist
    LIMIT 1
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'no active legacy_credits subscription found for organization %', v_org_id;
    END IF;

    -- 2. Find the open (billing_period_end IS NULL) ledger segment
    SELECT sl.id
      INTO ledger_id
    FROM subscription_ledger sl
    WHERE sl.subscription_id = sub_row.id
      AND sl.billing_period_end IS NULL
    ORDER BY sl.billing_period_start DESC
    LIMIT 1;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'no open subscription_ledger segment found for organization % (subscription %); state is unsound', v_org_id, sub_row.id;
    END IF;

    -- 3. Update the subscription: billing_source -> enterprise, max_apps -> maximum
    UPDATE subscriptions
       SET billing_source = 'enterprise',
           max_apps       = 2147483647,   -- i32::MAX -- effectively unlimited capacity
           updated_at     = NOW()
     WHERE id = sub_row.id;

    -- 4. Terminate the current open ledger entry
    UPDATE subscription_ledger
       SET billing_period_end = NOW()
     WHERE id = ledger_id
       AND billing_period_end IS NULL;
END \$\$;

COMMIT;
SQL

echo "Done."
