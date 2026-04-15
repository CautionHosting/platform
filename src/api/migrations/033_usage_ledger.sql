DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'usage_records'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'usage_ledger'
    ) THEN
        ALTER TABLE usage_records RENAME TO usage_ledger;
    END IF;
END $$;

ALTER INDEX IF EXISTS idx_usage_records_user_id RENAME TO idx_usage_ledger_user_id;
ALTER INDEX IF EXISTS idx_usage_records_resource_id RENAME TO idx_usage_ledger_resource_id;
ALTER INDEX IF EXISTS idx_usage_records_recorded_at RENAME TO idx_usage_ledger_recorded_at;
ALTER INDEX IF EXISTS idx_usage_records_user_recorded RENAME TO idx_usage_ledger_user_recorded;
ALTER INDEX IF EXISTS idx_usage_records_org RENAME TO idx_usage_ledger_org;
ALTER INDEX IF EXISTS idx_usage_records_application_id RENAME TO idx_usage_ledger_application_id;
