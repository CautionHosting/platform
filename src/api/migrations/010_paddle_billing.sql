-- Paddle Billing Migration
-- Replaces Lago + PayPal with Paddle as merchant of record

-- Add Paddle fields to billing_config
ALTER TABLE billing_config
  ADD COLUMN IF NOT EXISTS paddle_customer_id TEXT,
  ADD COLUMN IF NOT EXISTS paddle_subscription_id TEXT;

-- Add Paddle fields to invoices
ALTER TABLE invoices
  ADD COLUMN IF NOT EXISTS paddle_transaction_id TEXT UNIQUE,
  ADD COLUMN IF NOT EXISTS tax_amount_cents BIGINT DEFAULT 0,
  ADD COLUMN IF NOT EXISTS billing_provider TEXT DEFAULT 'lago';
ALTER TABLE invoices ALTER COLUMN lago_invoice_id DROP NOT NULL;

-- Add Paddle fields to payment_methods
ALTER TABLE payment_methods
  ADD COLUMN IF NOT EXISTS paddle_payment_method_id TEXT,
  ADD COLUMN IF NOT EXISTS card_brand VARCHAR(50);

-- Webhook idempotency table
CREATE TABLE IF NOT EXISTS paddle_webhook_events (
  event_id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  payload JSONB NOT NULL
);
