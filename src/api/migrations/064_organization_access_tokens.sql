-- Organization access tokens: org-owned service credentials, bearer-presented
-- and hashed at rest. See docs/access-tokens-spec.md (D1-D13).
--
-- Migrations re-run on every start (see utils/makefile-run-migrations.sh), so
-- every statement is idempotent.

CREATE TABLE IF NOT EXISTS organization_access_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- sha256(plaintext), lowercase hex. The plaintext is shown once at mint and
    -- never stored.
    token_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    -- Attribution only; the token is org-owned, not tied to its creator's
    -- membership. Survives the creator leaving (D1, D11).
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    -- NULL means no expiry (allowed but discouraged; see D7). Defaults are
    -- applied by the application, not the schema.
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT organization_access_tokens_hash_unique UNIQUE (token_hash),
    -- Referenced by organization_access_token_roles so a token and its roles
    -- stay in the same organization.
    CONSTRAINT organization_access_tokens_org_id_unique UNIQUE (organization_id, id)
);

CREATE INDEX IF NOT EXISTS idx_organization_access_tokens_org
    ON organization_access_tokens(organization_id);

CREATE OR REPLACE TRIGGER organization_access_tokens_updated_at
    BEFORE UPDATE ON organization_access_tokens
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Roles attached to a token, chosen at mint and immutable thereafter (D2/D2a).
-- The roles themselves stay live: editing or deleting a role changes every
-- holder, tokens included. Rows are only inserted at mint and removed by
-- cascade; there is deliberately no UPDATE path.
CREATE TABLE IF NOT EXISTS organization_access_token_roles (
    organization_id UUID NOT NULL,
    token_id UUID NOT NULL,
    role_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT organization_access_token_roles_pkey
        PRIMARY KEY (organization_id, token_id, role_id),
    CONSTRAINT organization_access_token_roles_token_fkey
        FOREIGN KEY (organization_id, token_id)
        REFERENCES organization_access_tokens (organization_id, id) ON DELETE CASCADE,
    CONSTRAINT organization_access_token_roles_role_fkey
        FOREIGN KEY (organization_id, role_id)
        REFERENCES rbac_roles (organization_id, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_organization_access_token_roles_role
    ON organization_access_token_roles(role_id);
