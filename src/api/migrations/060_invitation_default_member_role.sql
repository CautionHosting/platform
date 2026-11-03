-- Invitations must not confer ownership by default. `invite_member` binds the
-- role explicitly, but the column default is the last line of defence: any
-- insert that omits the role should create a plain user, matching
-- `organization_members.role`'s own default.
ALTER TABLE organization_invitations
    ALTER COLUMN role SET DEFAULT 'member';
