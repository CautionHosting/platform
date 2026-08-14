CREATE TABLE IF NOT EXISTS quorum_bundles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    data JSONB NOT NULL DEFAULT '{}',
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_quorum_bundles_org ON quorum_bundles(organization_id);
CREATE OR REPLACE TRIGGER quorum_bundles_updated_at BEFORE UPDATE ON quorum_bundles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TABLE IF NOT EXISTS secrets_bundles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    data JSONB NOT NULL DEFAULT '{}',
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_secrets_bundles_org ON secrets_bundles(organization_id);
CREATE OR REPLACE TRIGGER secrets_bundles_updated_at BEFORE UPDATE ON secrets_bundles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
