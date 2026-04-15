DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'usage_ledger'
    ) THEN
        ALTER TABLE usage_ledger
          DROP COLUMN IF EXISTS unit_cost_usd;

        ALTER TABLE usage_ledger
          DROP COLUMN IF EXISTS cost_usd;
    ELSIF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'usage_records'
    ) THEN
        ALTER TABLE usage_records
          DROP COLUMN IF EXISTS unit_cost_usd;

        ALTER TABLE usage_records
          DROP COLUMN IF EXISTS cost_usd;
    END IF;
END $$;
