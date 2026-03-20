-- Prepaid Credits System
-- Credit ledger for audit trail of all credit deposits and deductions

CREATE TABLE IF NOT EXISTS credit_ledger (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id               UUID NOT NULL REFERENCES users(id),
    delta_cents           BIGINT NOT NULL,
    balance_after         BIGINT NOT NULL,
    entry_type            TEXT NOT NULL,
    description           TEXT NOT NULL,
    paddle_transaction_id TEXT,
    invoice_id            UUID REFERENCES invoices(id),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_credit_ledger_user ON credit_ledger(user_id);
CREATE INDEX IF NOT EXISTS idx_credit_ledger_created ON credit_ledger(created_at DESC);
