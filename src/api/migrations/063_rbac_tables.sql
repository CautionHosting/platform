-- RBAC: per-organization roles, route-based rules, and member assignments.
-- Migrations re-run on every start (see utils/makefile-run-migrations.sh), so
-- every statement is idempotent.

-- Roles belong to exactly one organization; there are no global built-ins.
CREATE TABLE IF NOT EXISTS rbac_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT rbac_roles_org_name_unique UNIQUE (organization_id, name),
    -- Referenced by rbac_member_roles so a role cannot be assigned across
    -- organizations.
    CONSTRAINT rbac_roles_org_id_unique UNIQUE (organization_id, id)
);

CREATE INDEX IF NOT EXISTS idx_rbac_roles_org ON rbac_roles(organization_id);

CREATE OR REPLACE TRIGGER rbac_roles_updated_at BEFORE UPDATE ON rbac_roles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Route-based rules: `method` + `path` (an axum route template), with an
-- effect and a precedence priority. Lower priority wins; 0 is valid.
CREATE TABLE IF NOT EXISTS rbac_role_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL REFERENCES rbac_roles(id) ON DELETE CASCADE,
    effect TEXT NOT NULL DEFAULT 'allow',
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    -- Per path-parameter allowed values, e.g. {"id": ["*"]}. The application
    -- requires this when `path` has parameters; NULL for parameterless routes.
    objects JSONB,
    priority INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT rbac_role_rules_effect_check CHECK (effect IN ('allow', 'deny')),
    CONSTRAINT rbac_role_rules_method_check CHECK (method IN
        ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', '*')),
    CONSTRAINT rbac_role_rules_path_check CHECK (path LIKE '/%'),
    CONSTRAINT rbac_role_rules_objects_check CHECK (
        objects IS NULL OR jsonb_typeof(objects) = 'object'),
    CONSTRAINT rbac_role_rules_priority_check CHECK (priority >= 0),
    CONSTRAINT rbac_role_rules_unique UNIQUE (role_id, effect, method, path)
);

CREATE INDEX IF NOT EXISTS idx_rbac_role_rules_role ON rbac_role_rules(role_id);

-- Assignment of roles to members. A member may hold any number of roles. The
-- composite foreign keys keep a role within its organization and only assigned
-- to an actual member.
CREATE TABLE IF NOT EXISTS rbac_member_roles (
    organization_id UUID NOT NULL,
    user_id UUID NOT NULL,
    role_id UUID NOT NULL,
    granted_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT rbac_member_roles_pkey PRIMARY KEY (organization_id, user_id, role_id),
    CONSTRAINT rbac_member_roles_member_fkey
        FOREIGN KEY (organization_id, user_id)
        REFERENCES organization_members (organization_id, user_id) ON DELETE CASCADE,
    CONSTRAINT rbac_member_roles_role_fkey
        FOREIGN KEY (organization_id, role_id)
        REFERENCES rbac_roles (organization_id, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_rbac_member_roles_user ON rbac_member_roles(user_id);
