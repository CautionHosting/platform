-- Admin-triggered WebAuthn credential reset tokens.
--
-- When a platform admin resets a user's credentials, a single-use token is
-- generated and emailed to the user. The token allows the user to register a
-- new passkey within the expiry window. Once used or expired, the token is no
-- longer redeemable.

CREATE TABLE IF NOT EXISTS webauthn_reset_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_webauthn_reset_tokens_user_id
    ON webauthn_reset_tokens(user_id);
