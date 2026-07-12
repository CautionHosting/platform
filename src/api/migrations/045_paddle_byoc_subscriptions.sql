-- Paddle-backed BYOC subscriptions and local entitlement projection.

ALTER TABLE subscriptions
    ADD COLUMN IF NOT EXISTS billing_source TEXT NOT NULL DEFAULT 'legacy_credits',
    ADD COLUMN IF NOT EXISTS paddle_customer_id TEXT,
    ADD COLUMN IF NOT EXISTS paddle_subscription_id TEXT,
    ADD COLUMN IF NOT EXISTS paddle_price_id TEXT,
    ADD COLUMN IF NOT EXISTS catalog_version INTEGER,
    ADD COLUMN IF NOT EXISTS pending_tier TEXT,
    ADD COLUMN IF NOT EXISTS pending_max_apps INTEGER,
    ADD COLUMN IF NOT EXISTS provider_occurred_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS enterprise_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS catalog_valid BOOLEAN NOT NULL DEFAULT true;

ALTER TABLE subscriptions DROP CONSTRAINT IF EXISTS subscriptions_billing_source_check;
ALTER TABLE subscriptions
    ADD CONSTRAINT subscriptions_billing_source_check
    CHECK (billing_source IN ('legacy_credits', 'paddle', 'enterprise'));

ALTER TABLE subscriptions DROP CONSTRAINT IF EXISTS subscriptions_status_check;
ALTER TABLE subscriptions
    ADD CONSTRAINT subscriptions_status_check
    CHECK (status IN ('pending', 'trialing', 'active', 'past_due', 'paused', 'canceled'));

ALTER TABLE subscriptions DROP CONSTRAINT IF EXISTS subscriptions_pending_max_apps_check;
ALTER TABLE subscriptions
    ADD CONSTRAINT subscriptions_pending_max_apps_check
    CHECK (pending_max_apps IS NULL OR pending_max_apps > 0);

ALTER TABLE subscriptions DROP CONSTRAINT IF EXISTS subscriptions_paddle_fields_check;
ALTER TABLE subscriptions
    ADD CONSTRAINT subscriptions_paddle_fields_check
    CHECK (
        billing_source <> 'paddle'
        OR (
            paddle_customer_id IS NOT NULL
            AND paddle_subscription_id IS NOT NULL
            AND paddle_price_id IS NOT NULL
            AND catalog_version IS NOT NULL
        )
    ) NOT VALID;

CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_paddle_subscription
    ON subscriptions(paddle_subscription_id)
    WHERE paddle_subscription_id IS NOT NULL;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM subscriptions
        WHERE status <> 'canceled'
        GROUP BY organization_id
        HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION 'cannot enforce one non-canceled subscription per organization: reconcile duplicate legacy rows first';
    END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_org_non_canceled
    ON subscriptions(organization_id)
    WHERE status <> 'canceled';
DROP INDEX IF EXISTS idx_subscriptions_org_active;

CREATE TABLE IF NOT EXISTS subscription_intents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    subscription_id UUID REFERENCES subscriptions(id),
    requested_by_user_id UUID NOT NULL REFERENCES users(id),
    operation TEXT NOT NULL CHECK (
        operation IN ('subscribe', 'upgrade', 'downgrade', 'cancel', 'enterprise_set')
    ),
    old_tier TEXT,
    new_tier TEXT,
    old_limit INTEGER,
    new_limit INTEGER,
    paddle_transaction_id TEXT,
    paddle_subscription_id TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (
        status IN ('pending', 'provider_pending', 'applied', 'failed', 'canceled')
    ),
    failure_code TEXT,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '30 minutes',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    applied_at TIMESTAMPTZ
);

ALTER TABLE subscription_intents
    ADD COLUMN IF NOT EXISTS paddle_subscription_id TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_subscription_intents_paddle_transaction
    ON subscription_intents(paddle_transaction_id)
    WHERE paddle_transaction_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_subscription_intents_pending_org
    ON subscription_intents(organization_id, expires_at)
    WHERE status IN ('pending', 'provider_pending');
CREATE UNIQUE INDEX IF NOT EXISTS idx_subscription_intents_one_pending_org
    ON subscription_intents(organization_id)
    WHERE status IN ('pending', 'provider_pending');
