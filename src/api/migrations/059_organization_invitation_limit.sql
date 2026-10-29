-- Per-organization cap on invitations sent per rolling day. Site admins can
-- raise it for larger customers.
ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS invitation_daily_limit INTEGER NOT NULL DEFAULT 10;

DO $$
BEGIN
    ALTER TABLE organizations
        ADD CONSTRAINT organizations_invitation_daily_limit_nonnegative
        CHECK (invitation_daily_limit >= 0);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

COMMENT ON COLUMN organizations.invitation_daily_limit IS
    'Maximum organization invitations sent per rolling 24 hours; raised per organization by site admins.';
