-- Remove the 'admin' role. Its powers are being replaced by the RBAC system:
-- owners keep god powers and users carry roles. Migrations re-run on every
-- start (see utils/makefile-run-migrations.sh), so every statement is
-- idempotent.

-- Existing admins become plain members. Every organization already has an
-- owner, created at signup, so no organization is left without a manager.
-- Compare through ::text so the 'admin' literal is not coerced to user_role,
-- which would fail on a re-run once the value no longer exists.
UPDATE organization_members SET role = 'member' WHERE role::text = 'admin';
UPDATE organization_invitations SET role = 'member' WHERE role::text = 'admin';

-- PostgreSQL cannot drop a single enum value, so replace the whole type when
-- the old definition is still present.
DO
$$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_enum e
        JOIN pg_type t ON t.oid = e.enumtypid
        WHERE t.typname = 'user_role' AND e.enumlabel = 'admin'
    ) THEN
        ALTER TYPE user_role RENAME TO user_role_with_admin;
        CREATE TYPE user_role AS ENUM ('owner', 'member', 'viewer');

        -- The existing default ('member' of the old type) cannot be cast
        -- automatically during ALTER COLUMN TYPE, so drop it and re-add it
        -- against the new type.
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

        DROP TYPE user_role_with_admin;
    END IF;
END
$$;
