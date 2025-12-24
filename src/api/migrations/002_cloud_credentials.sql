-- SPDX-FileCopyrightText: 2025 Caution SEZC
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

-- Cloud Credentials for BYOC (Bring Your Own Cloud)
-- Flexible schema to support any cloud/hosting platform

-- Extend the cloud_provider enum with additional platforms
ALTER TYPE cloud_provider ADD VALUE IF NOT EXISTS 'linode';
ALTER TYPE cloud_provider ADD VALUE IF NOT EXISTS 'vultr';
ALTER TYPE cloud_provider ADD VALUE IF NOT EXISTS 'ovh';
ALTER TYPE cloud_provider ADD VALUE IF NOT EXISTS 'baremetal';

CREATE TABLE cloud_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    platform cloud_provider NOT NULL,
    name VARCHAR(255) NOT NULL,

    -- For display/identification (not secret)
    -- AWS: access_key_id, GCP: service_account_email, Azure: client_id
    -- Token-based (DO, Hetzner, etc): first 8 chars of token
    -- Bare metal: host address
    identifier VARCHAR(255) NOT NULL,

    -- Encrypted JSON blob containing all secrets (AES-256-GCM)
    -- Structure varies by platform:
    -- AWS: {"secret_access_key": "..."}
    -- GCP: {"service_account_key": {...}}
    -- Azure: {"client_secret": "..."}
    -- Token-based: {"api_token": "..."}
    -- Bare metal: {"ssh_private_key": "...", "ssh_password": "..."}
    secrets_encrypted BYTEA NOT NULL,

    -- Non-secret platform config (stored as plain JSON)
    -- AWS: {"region": "us-west-2"}
    -- Azure: {"subscription_id": "...", "tenant_id": "..."}
    -- Bare metal: {"host": "1.2.3.4", "port": 22, "username": "root"}
    config JSONB NOT NULL DEFAULT '{}',

    default_region VARCHAR(64),
    is_default BOOLEAN NOT NULL DEFAULT false,
    is_active BOOLEAN NOT NULL DEFAULT true,
    last_validated_at TIMESTAMP,
    validation_error TEXT,

    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),

    CONSTRAINT cloud_credentials_unique_name UNIQUE (organization_id, name)
);

CREATE INDEX idx_cloud_credentials_org ON cloud_credentials(organization_id);
CREATE INDEX idx_cloud_credentials_platform ON cloud_credentials(organization_id, platform);
CREATE INDEX idx_cloud_credentials_default ON cloud_credentials(organization_id, platform, is_default) WHERE is_default = true;
CREATE INDEX idx_cloud_credentials_active ON cloud_credentials(organization_id) WHERE is_active = true;

CREATE TRIGGER cloud_credentials_updated_at BEFORE UPDATE ON cloud_credentials
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Ensure only one default credential per platform per organization
CREATE UNIQUE INDEX idx_cloud_credentials_one_default
    ON cloud_credentials(organization_id, platform)
    WHERE is_default = true;

COMMENT ON TABLE cloud_credentials IS 'Encrypted cloud provider credentials for BYOC deployments';
COMMENT ON COLUMN cloud_credentials.identifier IS 'Non-secret identifier for display (access key ID, email, truncated token, host)';
COMMENT ON COLUMN cloud_credentials.secrets_encrypted IS 'AES-256-GCM encrypted JSON blob - never returned via API';
COMMENT ON COLUMN cloud_credentials.config IS 'Non-secret platform configuration (region, tenant_id, host, port, etc)';
