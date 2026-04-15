-- Fix DOUBLE PRECISION for money columns on the legacy usage table.
-- Fresh schemas create usage_ledger directly with NUMERIC columns, so this is a compatibility step.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'usage_ledger' AND column_name = 'cost_usd'
    ) THEN
        EXECUTE $migrate_usage_ledger$
            ALTER TABLE usage_ledger
              ALTER COLUMN cost_usd TYPE NUMERIC(20, 4),
              ALTER COLUMN quantity TYPE NUMERIC(20, 6)
        $migrate_usage_ledger$;
    ELSIF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'usage_records' AND column_name = 'cost_usd'
    ) THEN
        EXECUTE $migrate_usage_records$
            ALTER TABLE usage_records
              ALTER COLUMN cost_usd TYPE NUMERIC(20, 4),
              ALTER COLUMN quantity TYPE NUMERIC(20, 6)
        $migrate_usage_records$;
    END IF;
END $$;
