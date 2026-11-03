-- Remove the 'viewer' role. It is accepted by role validation but no route
-- grants it any access different from 'member', so it is dead weight ahead of
-- the RBAC system. Migrations re-run on every start, so this is idempotent.

-- Existing viewers become plain members. Compare through ::text so the 'viewer'
-- literal is not coerced to user_role, which fails once the value is gone.
UPDATE organization_members SET role = 'member' WHERE role::text = 'viewer';
UPDATE organization_invitations SET role = 'member' WHERE role::text = 'viewer';

DO
$$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_enum e
        JOIN pg_type t ON t.oid = e.enumtypid
        WHERE t.typname = 'user_role' AND e.enumlabel = 'viewer'
    ) THEN
        ALTER TYPE user_role RENAME TO user_role_with_viewer;
        CREATE TYPE user_role AS ENUM ('owner', 'member');

        -- Drop the default before ALTER COLUMN TYPE: the old default belongs to
        -- the old type and cannot be cast automatically.
        ALTER TABLE organization_members
            ALTER COLUMN role DROP DEFAULT;
        ALTER TABLE organization_members
            ALTER COLUMN role TYPE user_role USING role::text::user_role;
        ALTER TABLE organization_members
            ALTER COLUMN role SET DEFAULT 'member';

        ALTER TABLE organization_invitations
            ALTER COLUMN role DROP DEFAULT;
        ALTER TABLE organization_invitations
            ALTER COLUMN role TYPE user_role USING role::text::user_role;
        ALTER TABLE organization_invitations
            ALTER COLUMN role SET DEFAULT 'member';

        DROP TYPE user_role_with_viewer;
    END IF;
END
$$;
