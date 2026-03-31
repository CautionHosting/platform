-- Add CHECK constraints for enum-like TEXT columns

-- credit_ledger entry types
ALTER TABLE credit_ledger
    ADD CONSTRAINT chk_credit_ledger_entry_type
    CHECK (entry_type IN ('realtime_usage', 'auto_topup', 'code_redemption', 'billing_deduction', 'proration_refund', 'purchase'));

-- subscription status
ALTER TABLE subscriptions
    ADD CONSTRAINT chk_subscriptions_status
    CHECK (status IN ('active', 'past_due', 'canceled'));

-- subscription billing period
ALTER TABLE subscriptions
    ADD CONSTRAINT chk_subscriptions_billing_period
    CHECK (billing_period IN ('monthly', 'yearly', '2year'));

-- subscription billing event status
ALTER TABLE subscription_billing_events
    ADD CONSTRAINT chk_sub_billing_events_status
    CHECK (status IN ('pending', 'paid', 'payment_failed'));

-- tracked resources status
ALTER TABLE tracked_resources
    ADD CONSTRAINT chk_tracked_resources_status
    CHECK (status IN ('running', 'stopped'));

-- invoices status
ALTER TABLE invoices
    ADD CONSTRAINT chk_invoices_status
    CHECK (status IN ('draft', 'finalized', 'voided'));

-- invoices payment status
ALTER TABLE invoices
    ADD CONSTRAINT chk_invoices_payment_status
    CHECK (payment_status IN ('pending', 'succeeded', 'failed'));

-- eif_builds status
ALTER TABLE eif_builds
    ADD CONSTRAINT chk_eif_builds_status
    CHECK (status IN ('pending', 'building', 'completed', 'failed'));
