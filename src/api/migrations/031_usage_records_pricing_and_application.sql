DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'usage_ledger'
    ) THEN
        ALTER TABLE usage_ledger
          ADD COLUMN IF NOT EXISTS application_id UUID REFERENCES compute_resources(id);

        ALTER TABLE usage_ledger
          ADD COLUMN IF NOT EXISTS base_unit_cost_usd NUMERIC(20, 6);

        ALTER TABLE usage_ledger
          ADD COLUMN IF NOT EXISTS margin_percent NUMERIC(10, 4);

        EXECUTE 'CREATE INDEX IF NOT EXISTS idx_usage_ledger_application_id ON usage_ledger(application_id)';
    ELSIF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'usage_records'
    ) THEN
        ALTER TABLE usage_records
          ADD COLUMN IF NOT EXISTS application_id UUID REFERENCES compute_resources(id);

        ALTER TABLE usage_records
          ADD COLUMN IF NOT EXISTS base_unit_cost_usd NUMERIC(20, 6);

        ALTER TABLE usage_records
          ADD COLUMN IF NOT EXISTS margin_percent NUMERIC(10, 4);

        EXECUTE 'CREATE INDEX IF NOT EXISTS idx_usage_records_application_id ON usage_records(application_id)';
    END IF;
END $$;
