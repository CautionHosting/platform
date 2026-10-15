-- Store the authenticated user directly on auth_sessions so post-login
-- resolution doesn't need to re-derive it from credential_id (which is
-- ambiguous once a single physical key can be registered to multiple
-- accounts).
--
-- Idempotent: every statement is safe to re-run. The backfill and the
-- NOT NULL promotion are wrapped in a DO block that no-ops when the column
-- already carries values, so a partial or repeated run never deletes live
-- sessions.

ALTER TABLE auth_sessions
    ADD COLUMN IF NOT EXISTS user_id UUID;

DO
$$BEGIN
    -- Backfill: join through fido2_credentials to recover the owner. Only
    -- sessions that still have no owner (user_id IS NULL) are touched, so a
    -- re-run after the column is populated is a no-op.
    UPDATE auth_sessions s
    SET user_id = c.user_id
    FROM fido2_credentials c
    WHERE s.credential_id = c.credential_id
      AND s.user_id IS NULL;

    -- Delete sessions that couldn't be resolved: orphaned credentials or
    -- ambiguous (multi-owner) credentials.
    DELETE FROM auth_sessions WHERE user_id IS NULL;

    -- Promote to NOT NULL only once every remaining session has an owner.
    IF NOT EXISTS (SELECT 1 FROM auth_sessions WHERE user_id IS NULL) THEN
        ALTER TABLE auth_sessions
            ALTER COLUMN user_id SET NOT NULL;
    END IF;
END;$$;

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON auth_sessions(user_id);

-- Composite FK: cascade-delete sessions when their credential row is removed.
-- The old single-column FK on credential_id alone was dropped in 056 because
-- credential_id is no longer globally unique; this composite FK restores the
-- cascade using the new (user_id, credential_id) pair. Idempotent via DO block.
DO
$$BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'fk_auth_sessions_user_credential'
          AND conrelid = 'auth_sessions'::regclass
    ) THEN
        ALTER TABLE auth_sessions
            ADD CONSTRAINT fk_auth_sessions_user_credential
            FOREIGN KEY (user_id, credential_id)
            REFERENCES fido2_credentials(user_id, credential_id)
            ON DELETE CASCADE;
    END IF;
END;$$;
