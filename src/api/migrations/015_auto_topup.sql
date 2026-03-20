-- Auto top-up: allow users to automatically refill credits when balance is low.
-- credit_suspended_at: instant suspension when credits hit $0 (separate from 7-day dunning).

ALTER TABLE billing_config
  ADD COLUMN IF NOT EXISTS auto_topup_enabled BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS auto_topup_amount_dollars INTEGER DEFAULT 0,
  ADD COLUMN IF NOT EXISTS low_balance_warned_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_auto_topup_at TIMESTAMPTZ;

ALTER TABLE organizations
  ADD COLUMN IF NOT EXISTS credit_suspended_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_billing_config_auto_topup
  ON billing_config(user_id) WHERE auto_topup_enabled = true;

-- Safety constraints
ALTER TABLE billing_config
  ADD CONSTRAINT chk_auto_topup_amount
  CHECK (auto_topup_amount_dollars >= 0 AND auto_topup_amount_dollars <= 10000);

ALTER TABLE wallet_balance
  ADD CONSTRAINT chk_balance_non_negative
  CHECK (balance_cents >= 0);
