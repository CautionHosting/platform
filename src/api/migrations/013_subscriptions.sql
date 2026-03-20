-- Managed on-prem subscription tracking (local, not Paddle subscriptions)

CREATE TABLE IF NOT EXISTS subscriptions (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id               UUID NOT NULL REFERENCES users(id),
    organization_id       UUID NOT NULL REFERENCES organizations(id),
    tier                  TEXT NOT NULL,
    billing_period        TEXT NOT NULL DEFAULT 'monthly',
    max_vcpus             INTEGER NOT NULL,
    max_apps              INTEGER NOT NULL,
    price_cents_per_cycle BIGINT NOT NULL,
    extra_vcpu_blocks     INTEGER NOT NULL DEFAULT 0,
    extra_app_blocks      INTEGER NOT NULL DEFAULT 0,
    extra_block_price_cents_per_cycle BIGINT NOT NULL DEFAULT 0,
    status                TEXT NOT NULL DEFAULT 'active',
    started_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    current_period_start  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    current_period_end    TIMESTAMPTZ NOT NULL,
    canceled_at           TIMESTAMPTZ,
    cancel_at_period_end  BOOLEAN NOT NULL DEFAULT false,
    last_billed_at        TIMESTAMPTZ,
    next_billing_at       TIMESTAMPTZ NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Unique: one active subscription per org
CREATE UNIQUE INDEX idx_subscriptions_org_active
    ON subscriptions(organization_id) WHERE status IN ('active', 'past_due');

CREATE TABLE IF NOT EXISTS subscription_billing_events (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id       UUID NOT NULL REFERENCES subscriptions(id),
    user_id               UUID NOT NULL REFERENCES users(id),
    billing_period_start  TIMESTAMPTZ NOT NULL,
    billing_period_end    TIMESTAMPTZ NOT NULL,
    tier                  TEXT NOT NULL,
    base_amount_cents     BIGINT NOT NULL,
    addon_amount_cents    BIGINT NOT NULL DEFAULT 0,
    total_amount_cents    BIGINT NOT NULL,
    credits_applied_cents BIGINT NOT NULL DEFAULT 0,
    charged_amount_cents  BIGINT NOT NULL,
    paddle_transaction_id TEXT,
    invoice_id            UUID REFERENCES invoices(id),
    status                TEXT NOT NULL DEFAULT 'pending',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(subscription_id, billing_period_start)
);
