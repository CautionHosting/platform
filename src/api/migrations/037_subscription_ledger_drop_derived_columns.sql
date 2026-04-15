DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'subscription_ledger'
    ) THEN
        ALTER TABLE subscription_ledger
            ALTER COLUMN billing_period_end DROP NOT NULL,
            DROP COLUMN IF EXISTS base_amount_cents,
            DROP COLUMN IF EXISTS addon_amount_cents,
            DROP COLUMN IF EXISTS total_amount_cents,
            DROP COLUMN IF EXISTS credits_applied_cents,
            DROP COLUMN IF EXISTS charged_amount_cents,
            DROP COLUMN IF EXISTS paddle_transaction_id;
    ELSIF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'subscription_billing_events'
    ) THEN
        ALTER TABLE subscription_billing_events
            ALTER COLUMN billing_period_end DROP NOT NULL,
            DROP COLUMN IF EXISTS base_amount_cents,
            DROP COLUMN IF EXISTS addon_amount_cents,
            DROP COLUMN IF EXISTS total_amount_cents,
            DROP COLUMN IF EXISTS credits_applied_cents,
            DROP COLUMN IF EXISTS charged_amount_cents,
            DROP COLUMN IF EXISTS paddle_transaction_id;
    END IF;
END $$;
