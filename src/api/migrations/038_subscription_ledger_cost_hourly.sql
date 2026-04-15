DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'subscription_ledger'
    ) THEN
        ALTER TABLE subscription_ledger
            ADD COLUMN IF NOT EXISTS cost_hourly NUMERIC(20, 6);

        UPDATE subscription_ledger sl
        SET cost_hourly = ROUND((
            CASE s.tier
                WHEN 'starter' THEN 900000 * 0.9
                WHEN 'developer' THEN 1800000 * 0.9
                WHEN 'base_platform' THEN 2500000 * 0.9
                WHEN 'growth' THEN 5000000 * 0.9
                WHEN 'enterprise' THEN 10000000 * 0.9
                ELSE NULL
            END
            + ((COALESCE(s.extra_vcpu_blocks, 0) + COALESCE(s.extra_app_blocks, 0)) * 1000000 * 0.9)
        ) / 100.0 / 8760.0, 6)
        FROM subscriptions s
        WHERE sl.subscription_id = s.id
          AND sl.cost_hourly IS NULL;

        ALTER TABLE subscription_ledger
            ALTER COLUMN cost_hourly SET NOT NULL;
    ELSIF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'subscription_billing_events'
    ) THEN
        ALTER TABLE subscription_billing_events
            ADD COLUMN IF NOT EXISTS cost_hourly NUMERIC(20, 6);

        UPDATE subscription_billing_events sl
        SET cost_hourly = ROUND((
            CASE s.tier
                WHEN 'starter' THEN 900000 * 0.9
                WHEN 'developer' THEN 1800000 * 0.9
                WHEN 'base_platform' THEN 2500000 * 0.9
                WHEN 'growth' THEN 5000000 * 0.9
                WHEN 'enterprise' THEN 10000000 * 0.9
                ELSE NULL
            END
            + ((COALESCE(s.extra_vcpu_blocks, 0) + COALESCE(s.extra_app_blocks, 0)) * 1000000 * 0.9)
        ) / 100.0 / 8760.0, 6)
        FROM subscriptions s
        WHERE sl.subscription_id = s.id
          AND sl.cost_hourly IS NULL;

        ALTER TABLE subscription_billing_events
            ALTER COLUMN cost_hourly SET NOT NULL;
    END IF;
END $$;
