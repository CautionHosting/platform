-- Enforce the current product model: a user can belong to exactly one organization.
-- Existing duplicate memberships must be resolved before this migration is applied.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM organization_members
        GROUP BY user_id
        HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION 'cannot enforce one organization per user while duplicate memberships exist';
    END IF;
END $$;

CREATE UNIQUE INDEX idx_org_members_one_org_per_user
    ON organization_members (user_id);
