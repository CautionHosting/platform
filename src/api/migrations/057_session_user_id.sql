-- Store the authenticated user directly on auth_sessions so post-login
-- resolution doesn't need to re-derive it from credential_id (which is
-- ambiguous once a single physical key can be registered to multiple
-- accounts).
--
-- Backfill: join through fido2_credentials to recover the owner. Sessions
-- whose credential no longer exists (orphaned by a user/credential delete)
-- or that resolve to more than one owner are deleted rather than left
-- with a NULL user_id.

ALTER TABLE auth_sessions
    ADD COLUMN IF NOT EXISTS user_id UUID;

UPDATE auth_sessions s
SET user_id = c.user_id
FROM fido2_credentials c
WHERE s.credential_id = c.credential_id
  AND s.user_id IS NULL;

-- Delete sessions that couldn't be resolved: orphaned credentials or
-- ambiguous (multi-owner) credentials.
DELETE FROM auth_sessions WHERE user_id IS NULL;

ALTER TABLE auth_sessions
    ALTER COLUMN user_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON auth_sessions(user_id);
