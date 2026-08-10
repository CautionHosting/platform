-- Add indexes on billing hot paths for query performance

-- Not used.
-- CREATE INDEX IF NOT EXISTS idx_wallet_balance_organization_id ON wallet_balance(organization_id);

--CREATE INDEX IF NOT EXISTS idx_credit_ledger_organization_id_created ON credit_ledger(organization_id, created_at);
--CREATE INDEX IF NOT EXISTS idx_subscriptions_org_status ON subscriptions(organization_id, status);
--CREATE INDEX IF NOT EXISTS idx_invoices_org_id ON invoices(organization_id);
--CREATE INDEX IF NOT EXISTS idx_billing_config_organization_id ON billing_config(organization_id);
