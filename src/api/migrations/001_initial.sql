-- SPDX-FileCopyrightText: 2025 Caution SEZC
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

-- Cloud Resource Monitor - Initial Schema
-- PostgreSQL Database Schema for Multi-Cloud Resource Tracking
--
-- Features:
-- 1. Multi-tenancy via organizations
-- 2. Proper data types (ENUMs, TIMESTAMP)
-- 3. Foreign keys with cascade rules
-- 4. Unique constraints
-- 5. Check constraints for validation
-- 6. Comprehensive indexes
-- 7. Audit fields (created_at, updated_at, created_by)
-- 8. JSONB for flexible provider-specific data
-- 9. Multi-tenancy with organization isolation
-- 10. Event tracking and cost history
-- 11. Email verification and payment tracking
-- 12. All tables with updated_at have automatic triggers

-- ============================================
-- HELPER FUNCTIONS
-- ============================================

-- Function to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Function to check if user is fully onboarded (email verified + payment added)
-- Beta users (with beta_code_id) skip email verification AND payment
CREATE OR REPLACE FUNCTION user_is_onboarded(user_id_param UUID)
RETURNS BOOLEAN AS $$
DECLARE
    verified BOOLEAN;
BEGIN
    SELECT
        -- Beta users are fully onboarded immediately
        beta_code_id IS NOT NULL
        OR (email_verified_at IS NOT NULL AND payment_method_added_at IS NOT NULL)
    INTO verified
    FROM users
    WHERE id = user_id_param;

    RETURN COALESCE(verified, FALSE);
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- BETA CODES (for closed beta registration)
-- ============================================

CREATE TABLE beta_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(64) NOT NULL UNIQUE,
    created_by VARCHAR(255),
    expires_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    used_at TIMESTAMP  -- NULL if not yet used, set when redeemed
);

CREATE INDEX idx_beta_codes_code ON beta_codes(code);

-- Generate and insert a random beta code:
-- code=$(openssl rand -hex 16) && psql -c "INSERT INTO beta_codes (code) VALUES ('$code')" && echo "Beta code: $code"

-- ============================================
-- CORE ENTITIES
-- ============================================

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) UNIQUE,
    fido2_user_handle BYTEA UNIQUE,  -- WebAuthn user.id (32 bytes)
    is_active BOOLEAN NOT NULL DEFAULT true,

    -- Beta code used during registration (skips email verification)
    beta_code_id UUID REFERENCES beta_codes(id),

    -- Email verification
    email_verified_at TIMESTAMP,
    email_verification_token VARCHAR(255),
    email_verification_token_expires_at TIMESTAMP,

    -- Payment tracking
    stripe_customer_id VARCHAR(255) UNIQUE,
    payment_method_added_at TIMESTAMP,

    -- Audit fields
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users(email) WHERE email IS NOT NULL;
CREATE INDEX idx_users_active ON users(is_active) WHERE is_active = true;
CREATE INDEX idx_users_fido2_handle ON users(fido2_user_handle) WHERE fido2_user_handle IS NOT NULL;
CREATE INDEX idx_users_verification_token ON users(email_verification_token) WHERE email_verification_token IS NOT NULL;
CREATE INDEX idx_users_stripe_customer ON users(stripe_customer_id) WHERE stripe_customer_id IS NOT NULL;

COMMENT ON COLUMN users.email_verified_at IS 'Timestamp when user verified their email address';
COMMENT ON COLUMN users.email_verification_token IS 'Token sent via email for verification';
COMMENT ON COLUMN users.email_verification_token_expires_at IS 'Expiration time for verification token (24 hours)';
COMMENT ON COLUMN users.stripe_customer_id IS 'Stripe customer ID for billing';
COMMENT ON COLUMN users.payment_method_added_at IS 'Timestamp when user added payment method';

CREATE TRIGGER users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================
-- ORGANIZATIONS
-- ============================================

CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TRIGGER organizations_updated_at BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================
-- USER-ORGANIZATION RELATIONSHIP
-- ============================================

CREATE TYPE user_role AS ENUM ('owner', 'admin', 'member', 'viewer');

CREATE TABLE organization_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role user_role NOT NULL DEFAULT 'member',
    invited_by UUID REFERENCES users(id) ON DELETE SET NULL,
    accepted_at TIMESTAMP NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),

    CONSTRAINT organization_members_unique UNIQUE (organization_id, user_id)
);

CREATE INDEX idx_org_members_org ON organization_members(organization_id);
CREATE INDEX idx_org_members_user ON organization_members(user_id);
CREATE INDEX idx_org_members_invited_by ON organization_members(invited_by) WHERE invited_by IS NOT NULL;

CREATE TRIGGER organization_members_updated_at BEFORE UPDATE ON organization_members
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================
-- CLOUD PROVIDERS
-- ============================================

CREATE TYPE cloud_provider AS ENUM ('aws', 'gcp', 'azure', 'digitalocean', 'hetzner');

CREATE TABLE providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_type cloud_provider NOT NULL UNIQUE,
    display_name VARCHAR(100) NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

INSERT INTO providers (provider_type, display_name) VALUES
    ('aws', 'Amazon Web Services'),
    ('gcp', 'Google Cloud Platform'),
    ('azure', 'Microsoft Azure'),
    ('digitalocean', 'DigitalOcean'),
    ('hetzner', 'Hetzner');

CREATE TRIGGER providers_updated_at BEFORE UPDATE ON providers
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================
-- PROVIDER ACCOUNTS (Per Organization)
-- ============================================

CREATE TABLE provider_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider_id UUID NOT NULL REFERENCES providers(id),
    external_account_id VARCHAR(255) NOT NULL,
    account_name VARCHAR(255) NOT NULL,
    description TEXT,
    role_arn VARCHAR(512),
    is_active BOOLEAN NOT NULL DEFAULT true,
    last_sync_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),

    CONSTRAINT provider_accounts_unique UNIQUE (organization_id, provider_id, external_account_id)
);

CREATE INDEX idx_provider_accounts_org ON provider_accounts(organization_id);
CREATE INDEX idx_provider_accounts_provider ON provider_accounts(provider_id);

CREATE TRIGGER provider_accounts_updated_at BEFORE UPDATE ON provider_accounts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================
-- RESOURCE TYPES
-- ============================================

CREATE TABLE resource_types (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id UUID NOT NULL REFERENCES providers(id),
    type_code VARCHAR(100) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    category VARCHAR(100),
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),

    CONSTRAINT resource_types_unique UNIQUE (provider_id, type_code)
);

CREATE INDEX idx_resource_types_provider ON resource_types(provider_id);

INSERT INTO resource_types (provider_id, type_code, display_name, category)
SELECT id, 'ec2-instance', 'EC2 Instance', 'compute' FROM providers WHERE provider_type = 'aws'
UNION ALL
SELECT id, 'rds-instance', 'RDS Database', 'database' FROM providers WHERE provider_type = 'aws'
UNION ALL
SELECT id, 's3-bucket', 'S3 Bucket', 'storage' FROM providers WHERE provider_type = 'aws';

CREATE TRIGGER resource_types_updated_at BEFORE UPDATE ON resource_types
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================
-- COMPUTE RESOURCES
-- ============================================

CREATE TYPE resource_state AS ENUM ('pending', 'running', 'stopped', 'terminated', 'failed');

CREATE TABLE compute_resources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider_account_id UUID NOT NULL REFERENCES provider_accounts(id),
    resource_type_id UUID NOT NULL REFERENCES resource_types(id),
    provider_resource_id VARCHAR(512) NOT NULL,
    resource_name VARCHAR(255),
    state resource_state NOT NULL DEFAULT 'pending',
    region VARCHAR(100),
    public_ip VARCHAR(45),
    billing_tag VARCHAR(255),
    estimated_monthly_cost DECIMAL(12, 2),
    currency VARCHAR(3) DEFAULT 'USD',
    configuration JSONB,
    tags JSONB,
    deployed_at TIMESTAMP,
    destroyed_at TIMESTAMP,
    created_by UUID REFERENCES users(id),
    destroyed_by UUID REFERENCES users(id),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),

    CONSTRAINT compute_resources_unique UNIQUE (provider_account_id, provider_resource_id)
);

CREATE INDEX idx_resources_org ON compute_resources(organization_id);
CREATE INDEX idx_resources_provider_account ON compute_resources(provider_account_id);
CREATE INDEX idx_resources_type ON compute_resources(resource_type_id);
CREATE INDEX idx_resources_public_ip ON compute_resources(public_ip);
CREATE INDEX idx_resources_state ON compute_resources(state);
CREATE INDEX idx_resources_billing ON compute_resources(billing_tag);
CREATE INDEX idx_resources_tags ON compute_resources USING GIN (tags);
CREATE INDEX idx_resources_created_by ON compute_resources(created_by) WHERE created_by IS NOT NULL;
CREATE INDEX idx_resources_destroyed_by ON compute_resources(destroyed_by) WHERE destroyed_by IS NOT NULL;
CREATE INDEX idx_resources_active ON compute_resources(organization_id, state) WHERE destroyed_at IS NULL;
CREATE INDEX idx_resources_name ON compute_resources(organization_id, resource_name) WHERE resource_name IS NOT NULL;

CREATE TRIGGER compute_resources_updated_at BEFORE UPDATE ON compute_resources
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================
-- FIDO2 AUTHENTICATION TABLES
-- ============================================

CREATE TABLE fido2_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,
    attestation_type VARCHAR(50),
    aaguid BYTEA,
    sign_count BIGINT NOT NULL DEFAULT 0,
    transport JSONB,  -- Array of transport methods: ["usb", "nfc", "ble", "internal"]
    flags JSONB,  -- Credential flags: {"userPresent": true, "userVerified": true, ...}
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_fido2_user_id ON fido2_credentials(user_id);
CREATE INDEX idx_fido2_credential_id ON fido2_credentials(credential_id);

CREATE TRIGGER fido2_credentials_updated_at BEFORE UPDATE ON fido2_credentials
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================
-- AUTHENTICATION SESSIONS
-- ============================================

CREATE TABLE auth_sessions (
    session_id VARCHAR(255) PRIMARY KEY,
    credential_id BYTEA NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMP NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_auth_sessions_credential
        FOREIGN KEY (credential_id)
        REFERENCES fido2_credentials(credential_id)
        ON DELETE CASCADE
);

CREATE INDEX idx_sessions_credential_id ON auth_sessions(credential_id);
CREATE INDEX idx_sessions_expires ON auth_sessions(expires_at);

COMMENT ON TABLE auth_sessions IS 'Active authentication sessions - no updated_at needed';

-- ============================================
-- SSH KEYS FOR GIT AUTHENTICATION
-- ============================================

CREATE TABLE ssh_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key TEXT NOT NULL,
    fingerprint VARCHAR(255) NOT NULL UNIQUE,
    key_type VARCHAR(50) NOT NULL,  -- 'ssh-rsa', 'ssh-ed25519', etc.
    name VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ssh_keys_user_id ON ssh_keys(user_id);
CREATE INDEX idx_ssh_keys_fingerprint ON ssh_keys(fingerprint);

CREATE TRIGGER ssh_keys_updated_at BEFORE UPDATE ON ssh_keys
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================
-- HELPFUL VIEWS
-- ============================================

CREATE VIEW active_resources AS
SELECT
    cr.id,
    cr.resource_name,
    o.name AS organization_name,
    p.display_name AS provider_name,
    rt.display_name AS resource_type,
    cr.state,
    cr.region,
    cr.estimated_monthly_cost,
    cr.deployed_at
FROM compute_resources cr
JOIN organizations o ON cr.organization_id = o.id
JOIN provider_accounts pa ON cr.provider_account_id = pa.id
JOIN providers p ON pa.provider_id = p.id
JOIN resource_types rt ON cr.resource_type_id = rt.id
WHERE cr.destroyed_at IS NULL;

-- ============================================
-- AMI CACHE
-- ============================================

-- Stores AMI IDs by commit SHA to avoid rebuilding identical images
CREATE TABLE ami_cache (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_name VARCHAR(255) NOT NULL,
    commit_sha VARCHAR(64) NOT NULL,
    ami_id VARCHAR(64) NOT NULL,
    region VARCHAR(32) NOT NULL DEFAULT 'us-west-2',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),

    -- Ensure one AMI per app per commit
    UNIQUE(app_name, commit_sha, region)
);

-- Index for fast lookups
CREATE INDEX idx_ami_cache_lookup ON ami_cache(app_name, commit_sha, region);

-- Index for cleanup queries
CREATE INDEX idx_ami_cache_created_at ON ami_cache(created_at);
