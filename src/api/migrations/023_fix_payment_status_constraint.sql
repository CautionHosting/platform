-- Fix payment_status CHECK constraint to include 'credits_applied'
-- (used when prepaid credits fully cover a billing cycle)

DO
$$BEGIN
    ALTER TABLE invoices DROP CONSTRAINT chk_invoices_payment_status;
EXCEPTION
    WHEN undefined_object THEN NULL;
END;$$;

DO
$$BEGIN
    ALTER TABLE invoices ADD CONSTRAINT chk_invoices_payment_status
        CHECK (payment_status IN ('pending', 'succeeded', 'failed', 'credits_applied'));
EXCEPTION
    WHEN duplicate_object THEN NULL;
END;$$;
