-- Fix payment_status CHECK constraint to include 'credits_applied'
-- (used when prepaid credits fully cover a billing cycle)

ALTER TABLE invoices DROP CONSTRAINT IF EXISTS chk_invoices_payment_status;
ALTER TABLE invoices ADD CONSTRAINT chk_invoices_payment_status
    CHECK (payment_status IN ('pending', 'succeeded', 'failed', 'credits_applied'));
