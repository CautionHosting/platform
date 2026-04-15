CREATE OR REPLACE VIEW credit_ledger_balances AS
SELECT
    organization_id,
    SUM(delta_cents)::bigint AS credit_cents
FROM credit_ledger
GROUP BY organization_id;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'subscription_billing_events'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'subscription_ledger'
    ) THEN
        ALTER TABLE subscription_billing_events RENAME TO subscription_ledger;
    END IF;
END $$;
