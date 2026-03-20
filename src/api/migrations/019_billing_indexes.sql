-- Add indexes on billing hot paths for query performance

CREATE INDEX IF NOT EXISTS idx_wallet_balance_user_id ON wallet_balance(user_id);
CREATE INDEX IF NOT EXISTS idx_credit_ledger_user_id_created ON credit_ledger(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_subscriptions_org_status ON subscriptions(organization_id, status);
CREATE INDEX IF NOT EXISTS idx_invoices_org_id ON invoices(organization_id);
CREATE INDEX IF NOT EXISTS idx_billing_config_user_id ON billing_config(user_id);
