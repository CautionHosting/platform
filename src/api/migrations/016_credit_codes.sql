CREATE TABLE IF NOT EXISTS credit_codes (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code         VARCHAR(64) NOT NULL UNIQUE,
    amount_cents BIGINT NOT NULL,
    redeemed_by  UUID REFERENCES users(id),
    redeemed_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_credit_codes_code ON credit_codes(code);
