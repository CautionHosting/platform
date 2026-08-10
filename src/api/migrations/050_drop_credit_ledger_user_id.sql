-- Drop user_id columns from billing tables (organization_id is now the sole identifier)

DO
$$BEGIN
    ALTER TABLE credit_ledger DROP COLUMN IF EXISTS user_id;
EXCEPTION
    WHEN undefined_column THEN NULL;
END;$$;

DROP INDEX IF EXISTS idx_credit_ledger_user;

DO
$$BEGIN
    ALTER TABLE billing_config DROP COLUMN IF EXISTS user_id;
EXCEPTION
    WHEN undefined_column THEN NULL;
END;$$;

DROP INDEX IF EXISTS idx_billing_config_user_id;
