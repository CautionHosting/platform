-- Evidence that this credential has completed PIN/biometric verification.
-- Gateway startup backfills verified registrations using webauthn-rs parsing;
-- malformed/unknown serialized credentials remain false.
ALTER TABLE fido2_credentials
    ADD COLUMN IF NOT EXISTS uv_verified BOOLEAN NOT NULL DEFAULT false;
