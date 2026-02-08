-- Migration 007: Convert remaining TIMESTAMP columns to TIMESTAMPTZ
--
-- Migrations 001-004 were updated to use TIMESTAMPTZ for new deployments,
-- but existing instances still have TIMESTAMP (without timezone) columns.
-- This migration idempotently converts all remaining TIMESTAMP columns.
-- PostgreSQL preserves existing values, interpreting them as UTC.

-- auth_sessions
ALTER TABLE auth_sessions
    ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC',
    ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC',
    ALTER COLUMN last_used_at TYPE TIMESTAMPTZ USING last_used_at AT TIME ZONE 'UTC';

-- beta_codes
ALTER TABLE beta_codes
    ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC',
    ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC',
    ALTER COLUMN used_at TYPE TIMESTAMPTZ USING used_at AT TIME ZONE 'UTC';

-- cloud_credentials
ALTER TABLE cloud_credentials
    ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC',
    ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC',
    ALTER COLUMN last_validated_at TYPE TIMESTAMPTZ USING last_validated_at AT TIME ZONE 'UTC';

-- compute_resources (must drop dependent view first)
DROP VIEW IF EXISTS active_resources;

ALTER TABLE compute_resources
    ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC',
    ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC',
    ALTER COLUMN deployed_at TYPE TIMESTAMPTZ USING deployed_at AT TIME ZONE 'UTC',
    ALTER COLUMN destroyed_at TYPE TIMESTAMPTZ USING destroyed_at AT TIME ZONE 'UTC';

-- Recreate active_resources view
CREATE VIEW active_resources AS
SELECT
    cr.id,
    cr.resource_name,
    o.name AS organization_name,
    p.display_name AS provider_name,
    rt.display_name AS resource_type,
    cr.state,
    cr.region,
    cr.estimated_monthly_cost,
    cr.deployed_at
FROM compute_resources cr
JOIN organizations o ON cr.organization_id = o.id
JOIN provider_accounts pa ON cr.provider_account_id = pa.id
JOIN providers p ON pa.provider_id = p.id
JOIN resource_types rt ON cr.resource_type_id = rt.id
WHERE cr.destroyed_at IS NULL;

-- ami_cache
ALTER TABLE ami_cache
    ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
