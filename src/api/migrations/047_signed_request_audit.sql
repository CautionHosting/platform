-- Durable audit records for requests authorized with WebAuthn.
--
-- The assertion and server-side authentication state are retained so the
-- WebAuthn proof remains independently inspectable after a credential is
-- removed. Request bodies are deliberately not retained here: the exact body
-- digest and length prove which bytes were authorized without turning this
-- generic audit table into permanent storage for future secret-bearing APIs.
CREATE TABLE signed_request_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    signature_scheme VARCHAR(32) NOT NULL DEFAULT 'webauthn',
    credential_id BYTEA NOT NULL,
    credential_public_key BYTEA NOT NULL,
    relying_party_id TEXT NOT NULL,
    request_method VARCHAR(32) NOT NULL,
    request_path TEXT NOT NULL,
    request_body_sha256 CHAR(64) NOT NULL,
    request_body_size_bytes BIGINT NOT NULL,
    challenge_id UUID NOT NULL UNIQUE,
    authentication_state BYTEA NOT NULL,
    assertion BYTEA NOT NULL,
    authorization_flow VARCHAR(32) NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    response_status INTEGER,
    completed_at TIMESTAMPTZ,

    CONSTRAINT signed_request_audit_signature_scheme
        CHECK (signature_scheme = 'webauthn'),
    CONSTRAINT signed_request_audit_credential_id_size
        CHECK (octet_length(credential_id) BETWEEN 1 AND 4096),
    CONSTRAINT signed_request_audit_credential_public_key_size
        CHECK (octet_length(credential_public_key) BETWEEN 1 AND 1048576),
    CONSTRAINT signed_request_audit_relying_party_id
        CHECK (
            octet_length(relying_party_id) BETWEEN 1 AND 253
            AND relying_party_id !~ '[[:cntrl:]]'
        ),
    CONSTRAINT signed_request_audit_request_method
        CHECK (request_method ~ '^[A-Z]+$'),
    CONSTRAINT signed_request_audit_request_path
        CHECK (
            octet_length(request_path) BETWEEN 1 AND 4096
            AND request_path !~ '[[:cntrl:]]'
        ),
    CONSTRAINT signed_request_audit_body_sha256
        CHECK (request_body_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT signed_request_audit_body_size
        CHECK (request_body_size_bytes BETWEEN 0 AND 10485760),
    CONSTRAINT signed_request_audit_authentication_state_size
        CHECK (octet_length(authentication_state) BETWEEN 1 AND 1048576),
    CONSTRAINT signed_request_audit_assertion_size
        CHECK (octet_length(assertion) BETWEEN 1 AND 1048576),
    CONSTRAINT signed_request_audit_authorization_flow
        CHECK (authorization_flow IN ('direct', 'cross_device_qr')),
    CONSTRAINT signed_request_audit_response_status
        CHECK (response_status BETWEEN 100 AND 599),
    CONSTRAINT signed_request_audit_completion
        CHECK (
            (response_status IS NULL AND completed_at IS NULL)
            OR (response_status IS NOT NULL AND completed_at IS NOT NULL)
        )
);

CREATE INDEX idx_signed_request_audit_user_verified
    ON signed_request_audit(user_id, verified_at DESC);
CREATE INDEX idx_signed_request_audit_credential
    ON signed_request_audit(credential_id);
CREATE INDEX idx_signed_request_audit_incomplete
    ON signed_request_audit(verified_at)
    WHERE completed_at IS NULL;

COMMENT ON TABLE signed_request_audit IS
    'Append-only WebAuthn authorization proofs; only response_status and completed_at may be completed after insertion';
COMMENT ON COLUMN signed_request_audit.request_body_sha256 IS
    'Lowercase SHA-256 digest of the exact request body bytes; the body itself is intentionally not stored';

-- Keep every PGP enrollment lifecycle row. Removing a key makes it inactive
-- instead of deleting its normalized public certificate, name, or fingerprint.
ALTER TABLE pgp_keys
    ADD COLUMN IF NOT EXISTS removed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS added_by_signed_request_id UUID
        REFERENCES signed_request_audit(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS removed_by_signed_request_id UUID
        REFERENCES signed_request_audit(id) ON DELETE SET NULL;

ALTER TABLE pgp_keys
    DROP CONSTRAINT IF EXISTS pgp_keys_user_fingerprint_unique;

CREATE UNIQUE INDEX pgp_keys_active_user_fingerprint_unique
    ON pgp_keys(user_id, fingerprint)
    WHERE removed_at IS NULL;

CREATE INDEX idx_pgp_keys_user_removed_at
    ON pgp_keys(user_id, removed_at, created_at DESC);

COMMENT ON COLUMN pgp_keys.removed_at IS
    'Soft-removal timestamp; non-NULL rows remain available for historical audit';
