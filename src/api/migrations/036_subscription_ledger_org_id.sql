DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'subscription_ledger'
    ) THEN
        ALTER TABLE subscription_ledger
            ADD COLUMN IF NOT EXISTS organization_id UUID;

        UPDATE subscription_ledger sl
        SET organization_id = s.organization_id
        FROM subscriptions s
        WHERE sl.subscription_id = s.id
          AND sl.organization_id IS NULL;

        IF NOT EXISTS (
            SELECT 1
            FROM pg_constraint
            WHERE conname = 'subscription_ledger_organization_id_fkey'
        ) THEN
            ALTER TABLE subscription_ledger
                ADD CONSTRAINT subscription_ledger_organization_id_fkey
                FOREIGN KEY (organization_id) REFERENCES organizations(id);
        END IF;

        ALTER TABLE subscription_ledger
            ALTER COLUMN organization_id SET NOT NULL;

        ALTER TABLE subscription_ledger
            DROP COLUMN IF EXISTS user_id;

        CREATE INDEX IF NOT EXISTS idx_subscription_ledger_organization_id
            ON subscription_ledger(organization_id);
    ELSIF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'subscription_billing_events'
    ) THEN
        ALTER TABLE subscription_billing_events
            ADD COLUMN IF NOT EXISTS organization_id UUID;

        UPDATE subscription_billing_events sl
        SET organization_id = s.organization_id
        FROM subscriptions s
        WHERE sl.subscription_id = s.id
          AND sl.organization_id IS NULL;

        IF NOT EXISTS (
            SELECT 1
            FROM pg_constraint
            WHERE conname = 'subscription_billing_events_organization_id_fkey'
        ) THEN
            ALTER TABLE subscription_billing_events
                ADD CONSTRAINT subscription_billing_events_organization_id_fkey
                FOREIGN KEY (organization_id) REFERENCES organizations(id);
        END IF;

        ALTER TABLE subscription_billing_events
            ALTER COLUMN organization_id SET NOT NULL;

        ALTER TABLE subscription_billing_events
            DROP COLUMN IF EXISTS user_id;

        CREATE INDEX IF NOT EXISTS idx_subscription_billing_events_organization_id
            ON subscription_billing_events(organization_id);
    END IF;
END $$;
