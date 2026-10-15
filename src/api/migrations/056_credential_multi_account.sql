-- Allow the same credential_id to exist across multiple users while
-- still preventing a single user from registering the same key twice.
-- Replaces the global UNIQUE on credential_id with a composite
-- (user_id, credential_id) unique constraint.
--
-- Fresh installs: 001_initial.sql no longer creates the auth_sessions FK or
-- the single-column UNIQUE, so both drops below are no-ops (IF EXISTS).
-- Existing databases: drop the dependent auth_sessions FK and the
-- single-column UNIQUE constraint first. The FK must go before the
-- constraint because it depends on the index that backs the constraint;
-- DROP INDEX alone is rejected ("constraint requires it").

ALTER TABLE auth_sessions
    DROP CONSTRAINT IF EXISTS fk_auth_sessions_credential;

ALTER TABLE fido2_credentials
    DROP CONSTRAINT IF EXISTS fido2_credentials_credential_id_key;

CREATE UNIQUE INDEX IF NOT EXISTS idx_fido2_user_credential
    ON fido2_credentials(user_id, credential_id);
