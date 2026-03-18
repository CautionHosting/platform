-- Metering tables for tracking resource usage and billing

-- Table to track resources being monitored for billing
CREATE TABLE IF NOT EXISTS tracked_resources (
    resource_id TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    provider TEXT NOT NULL,  -- aws, gcp, azure, baremetal
    instance_type TEXT,
    region TEXT,
    metadata JSONB NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'running',  -- running, stopped
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    stopped_at TIMESTAMPTZ,
    last_billed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for efficient queries
CREATE INDEX IF NOT EXISTS idx_tracked_resources_user_id ON tracked_resources(user_id);
CREATE INDEX IF NOT EXISTS idx_tracked_resources_status ON tracked_resources(status);
CREATE INDEX IF NOT EXISTS idx_tracked_resources_provider ON tracked_resources(provider);

-- Table to store usage records (for local auditing, Lago is source of truth for billing)
CREATE TABLE IF NOT EXISTS usage_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    resource_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    resource_type TEXT NOT NULL,  -- compute, storage, network, public_ip
    quantity DOUBLE PRECISION NOT NULL,
    unit TEXT NOT NULL,  -- hours, gb_hours, gb, count
    cost_usd DOUBLE PRECISION NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB NOT NULL DEFAULT '{}',
    lago_event_id TEXT,  -- Reference to Lago event if synced
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for usage records
CREATE INDEX IF NOT EXISTS idx_usage_records_user_id ON usage_records(user_id);
CREATE INDEX IF NOT EXISTS idx_usage_records_resource_id ON usage_records(resource_id);
CREATE INDEX IF NOT EXISTS idx_usage_records_recorded_at ON usage_records(recorded_at);

-- Table for billing configuration per user (spend limits, payment preferences)
CREATE TABLE IF NOT EXISTS billing_config (
    user_id UUID PRIMARY KEY REFERENCES users(id),
    billing_mode TEXT NOT NULL DEFAULT 'prepaid',  -- prepaid, postpaid
    monthly_spend_limit_cents INTEGER,  -- NULL means no limit
    payment_method TEXT,  -- paypal, crypto, card
    lago_customer_id TEXT,  -- Customer ID in Lago
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Table for wallet/credit balance (local cache, Lago is source of truth)
CREATE TABLE IF NOT EXISTS wallet_balance (
    user_id UUID PRIMARY KEY REFERENCES users(id),
    balance_cents BIGINT NOT NULL DEFAULT 0,
    currency TEXT NOT NULL DEFAULT 'USD',
    last_synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Table for payment transactions
CREATE TABLE IF NOT EXISTS payment_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    amount_cents BIGINT NOT NULL,
    currency TEXT NOT NULL DEFAULT 'USD',
    payment_method TEXT NOT NULL,  -- paypal, crypto, card
    transaction_type TEXT NOT NULL,  -- topup, invoice_payment, refund
    status TEXT NOT NULL DEFAULT 'pending',  -- pending, completed, failed
    external_transaction_id TEXT,  -- PayPal/crypto transaction ID
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_payment_transactions_user_id ON payment_transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_payment_transactions_status ON payment_transactions(status);

-- Table for invoices (local cache, Lago is source of truth)
CREATE TABLE IF NOT EXISTS invoices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    lago_invoice_id TEXT UNIQUE NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id),
    invoice_number TEXT NOT NULL,
    amount_cents BIGINT NOT NULL,
    currency TEXT NOT NULL DEFAULT 'USD',
    status TEXT NOT NULL,  -- draft, finalized, voided
    payment_status TEXT NOT NULL,  -- pending, succeeded, failed
    pdf_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    paid_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_invoices_user_id ON invoices(user_id);
CREATE INDEX IF NOT EXISTS idx_invoices_status ON invoices(status);
CREATE INDEX IF NOT EXISTS idx_invoices_payment_status ON invoices(payment_status);
