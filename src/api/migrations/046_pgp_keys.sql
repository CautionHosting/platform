-- User-owned OpenPGP public certificates.
--
-- Public key material is normalized and fingerprinted by the gateway before
-- insertion. The per-user uniqueness constraint permits the same public
-- certificate to be associated with more than one Caution account while
-- preventing duplicate enrollment on a single account.
CREATE TABLE pgp_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key TEXT NOT NULL,
    fingerprint VARCHAR(64) NOT NULL,
    name VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT pgp_keys_public_key_size
        CHECK (octet_length(public_key) <= 65536),
    CONSTRAINT pgp_keys_user_fingerprint_unique
        UNIQUE (user_id, fingerprint)
);

CREATE INDEX idx_pgp_keys_user_id ON pgp_keys(user_id);
