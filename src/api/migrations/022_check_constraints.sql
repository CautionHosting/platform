-- Add CHECK constraints for enum-like TEXT columns

-- credit_ledger entry types
DO
$$BEGIN
    ALTER TABLE credit_ledger
        ADD CONSTRAINT chk_credit_ledger_entry_type
        CHECK (entry_type IN ('realtime_usage', 'auto_topup', 'code_redemption', 'billing_deduction', 'proration_refund', 'purchase'));
EXCEPTION
    WHEN duplicate_object THEN NULL;
END;$$;

-- subscription status
DO
$$BEGIN
    ALTER TABLE subscriptions
        ADD CONSTRAINT chk_subscriptions_status
        CHECK (status IN ('active', 'past_due', 'canceled'));
EXCEPTION
    WHEN duplicate_object THEN NULL;
END;$$;

-- subscription billing period
DO
$$BEGIN
    ALTER TABLE subscriptions
        ADD CONSTRAINT chk_subscriptions_billing_period
        CHECK (billing_period IN ('monthly', 'yearly', '2year'));
EXCEPTION
    WHEN duplicate_object THEN NULL;
END;$$;

-- subscription billing event status
DO
$$BEGIN
    ALTER TABLE subscription_billing_events
        ADD CONSTRAINT chk_sub_billing_events_status
        CHECK (status IN ('pending', 'paid', 'payment_failed', 'credits_covered'));
EXCEPTION
    WHEN duplicate_object THEN NULL;
END;$$;

-- tracked resources status
DO
$$BEGIN
    ALTER TABLE tracked_resources
        ADD CONSTRAINT chk_tracked_resources_status
        CHECK (status IN ('running', 'stopped'));
EXCEPTION
    WHEN duplicate_object THEN NULL;
END;$$;

-- invoices status
DO
$$BEGIN
    ALTER TABLE invoices
        ADD CONSTRAINT chk_invoices_status
        CHECK (status IN ('draft', 'finalized', 'voided'));
EXCEPTION
    WHEN duplicate_object THEN NULL;
END;$$;

-- invoices payment status
DO
$$BEGIN
    ALTER TABLE invoices
        ADD CONSTRAINT chk_invoices_payment_status
        CHECK (payment_status IN ('pending', 'succeeded', 'failed'));
EXCEPTION
    WHEN duplicate_object THEN NULL;
END;$$;

-- eif_builds status
DO
$$BEGIN
    ALTER TABLE eif_builds
        ADD CONSTRAINT chk_eif_builds_status
        CHECK (status IN ('pending', 'building', 'completed', 'failed'));
EXCEPTION
    WHEN duplicate_object THEN NULL;
END;$$;
