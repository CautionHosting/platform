-- Migrate billing tables from user-centric to org-centric.
-- Pre-launch destructive migration: replaces user_id with organization_id as the primary lookup key.

-- 1. wallet_balance: change PK from user_id to organization_id
ALTER TABLE wallet_balance ADD COLUMN organization_id UUID REFERENCES organizations(id);
UPDATE wallet_balance wb SET organization_id = (
    SELECT organization_id FROM organization_members WHERE user_id = wb.user_id LIMIT 1
);
ALTER TABLE wallet_balance DROP CONSTRAINT wallet_balance_pkey;
ALTER TABLE wallet_balance DROP COLUMN user_id;
ALTER TABLE wallet_balance ALTER COLUMN organization_id SET NOT NULL;
ALTER TABLE wallet_balance ADD PRIMARY KEY (organization_id);

-- 2. billing_config: change PK from user_id to organization_id
ALTER TABLE billing_config ADD COLUMN organization_id UUID REFERENCES organizations(id);
UPDATE billing_config bc SET organization_id = (
    SELECT organization_id FROM organization_members WHERE user_id = bc.user_id LIMIT 1
);
ALTER TABLE billing_config DROP CONSTRAINT billing_config_pkey;
ALTER TABLE billing_config DROP COLUMN user_id;
ALTER TABLE billing_config ALTER COLUMN organization_id SET NOT NULL;
ALTER TABLE billing_config ADD PRIMARY KEY (organization_id);

-- 3. credit_ledger: replace user_id with organization_id (keep user_id as optional audit field)
ALTER TABLE credit_ledger ADD COLUMN organization_id UUID REFERENCES organizations(id);
UPDATE credit_ledger cl SET organization_id = (
    SELECT organization_id FROM organization_members WHERE user_id = cl.user_id LIMIT 1
);
ALTER TABLE credit_ledger ALTER COLUMN organization_id SET NOT NULL;
ALTER TABLE credit_ledger ALTER COLUMN user_id DROP NOT NULL;
CREATE INDEX idx_credit_ledger_org ON credit_ledger(organization_id);

-- 4. usage_records: replace user_id with organization_id (keep user_id as optional audit field)
ALTER TABLE usage_records ADD COLUMN organization_id UUID REFERENCES organizations(id);
UPDATE usage_records ur SET organization_id = (
    SELECT organization_id FROM organization_members WHERE user_id = ur.user_id LIMIT 1
);
ALTER TABLE usage_records ALTER COLUMN organization_id SET NOT NULL;
ALTER TABLE usage_records ALTER COLUMN user_id DROP NOT NULL;
CREATE INDEX idx_usage_records_org ON usage_records(organization_id);

-- 5. tracked_resources: replace user_id with organization_id (keep user_id as optional audit field)
ALTER TABLE tracked_resources ADD COLUMN organization_id UUID REFERENCES organizations(id);
UPDATE tracked_resources tr SET organization_id = (
    SELECT organization_id FROM organization_members WHERE user_id = tr.user_id LIMIT 1
);
ALTER TABLE tracked_resources ALTER COLUMN organization_id SET NOT NULL;
ALTER TABLE tracked_resources ALTER COLUMN user_id DROP NOT NULL;
CREATE INDEX idx_tracked_resources_org ON tracked_resources(organization_id);
