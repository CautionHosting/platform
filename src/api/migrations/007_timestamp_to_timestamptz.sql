-- Migration 007: Convert all TIMESTAMP columns to TIMESTAMPTZ
--
-- PostgreSQL best practice: always use TIMESTAMPTZ for timestamp storage.
-- TIMESTAMPTZ stores values in UTC internally and handles timezone conversion.
-- TIMESTAMP (without tz) has no timezone awareness and can cause subtle bugs.
--
-- Rust type mappings after this migration:
--   Gateway (time crate):  TIMESTAMPTZ <-> time::OffsetDateTime
--   API (chrono crate):    TIMESTAMPTZ <-> chrono::DateTime<Utc>
--
-- For columns already using TIMESTAMPTZ, the ALTER is a no-op.

-- auth_sessions (used by gateway for session management)
ALTER TABLE auth_sessions
    ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC',
    ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC',
    ALTER COLUMN last_used_at TYPE TIMESTAMPTZ USING last_used_at AT TIME ZONE 'UTC';

-- beta_codes
ALTER TABLE beta_codes
    ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC',
    ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC',
    ALTER COLUMN used_at TYPE TIMESTAMPTZ USING used_at AT TIME ZONE 'UTC';

-- users
ALTER TABLE users
    ALTER COLUMN email_verified_at TYPE TIMESTAMPTZ USING email_verified_at AT TIME ZONE 'UTC',
    ALTER COLUMN email_verification_token_expires_at TYPE TIMESTAMPTZ USING email_verification_token_expires_at AT TIME ZONE 'UTC',
    ALTER COLUMN payment_method_added_at TYPE TIMESTAMPTZ USING payment_method_added_at AT TIME ZONE 'UTC',
    ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC',
    ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';

-- organizations
ALTER TABLE organizations
    ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC',
    ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';

-- organization_members
ALTER TABLE organization_members
    ALTER COLUMN accepted_at TYPE TIMESTAMPTZ USING accepted_at AT TIME ZONE 'UTC',
    ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC',
    ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';

-- providers
ALTER TABLE providers
    ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC',
    ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';

-- provider_accounts
ALTER TABLE provider_accounts
    ALTER COLUMN last_sync_at TYPE TIMESTAMPTZ USING last_sync_at AT TIME ZONE 'UTC',
    ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC',
    ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';

-- resource_types
ALTER TABLE resource_types
    ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC',
    ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';

-- compute_resources depends on active_resources view — must drop/recreate
DROP VIEW IF EXISTS active_resources;

ALTER TABLE compute_resources
    ALTER COLUMN deployed_at TYPE TIMESTAMPTZ USING deployed_at AT TIME ZONE 'UTC',
    ALTER COLUMN destroyed_at TYPE TIMESTAMPTZ USING destroyed_at AT TIME ZONE 'UTC',
    ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC',
    ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';

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

-- fido2_credentials
ALTER TABLE fido2_credentials
    ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC',
    ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';

-- ssh_keys
ALTER TABLE ssh_keys
    ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC',
    ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC',
    ALTER COLUMN last_used_at TYPE TIMESTAMPTZ USING last_used_at AT TIME ZONE 'UTC';

-- cloud_credentials
ALTER TABLE cloud_credentials
    ALTER COLUMN last_validated_at TYPE TIMESTAMPTZ USING last_validated_at AT TIME ZONE 'UTC',
    ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC',
    ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';

-- ami_cache
ALTER TABLE ami_cache
    ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
