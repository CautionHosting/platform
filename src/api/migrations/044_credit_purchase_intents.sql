-- Server-authoritative credit purchase intents
--
-- The amount of credit granted for a Paddle credit purchase must be decided by
-- the server, never by client-controlled transaction `custom_data`. When the
-- API creates a Paddle transaction for a credit purchase it records the
-- authoritative credit amount here, keyed by the Paddle transaction id. Both the
-- API completion callback and the metering webhook credit `credit_cents` from
-- this row instead of trusting the signed-but-client-authored `custom_data`.

CREATE TABLE IF NOT EXISTS credit_purchase_intents (
    paddle_transaction_id TEXT PRIMARY KEY,
    organization_id       UUID NOT NULL REFERENCES organizations(id),
    user_id               UUID NOT NULL REFERENCES users(id),
    purchase_cents        BIGINT NOT NULL,
    credit_cents          BIGINT NOT NULL,
    paddle_price_id       TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_credit_purchase_intents_org
    ON credit_purchase_intents(organization_id);

-- Enforce a durable one-payment-to-one-credit-grant invariant. Previously the
-- API and webhook paths only did a racy `SELECT EXISTS ... then INSERT`, so the
-- two could double-credit the same transaction. NULLs remain distinct, so
-- non-purchase ledger entries (usage debits, credit codes) are unaffected.
--
-- Any pre-existing double-credits (the very bug this constraint prevents) must
-- be collapsed first: ADD CONSTRAINT would otherwise fail, and migrations run
-- under `psql -f ... || true` with no ON_ERROR_STOP, which would swallow that
-- failure and silently leave the constraint absent — breaking every later
-- `ON CONFLICT (paddle_transaction_id)` insert at runtime. Keep the earliest
-- ledger row per transaction and drop the duplicate grants.
DELETE FROM credit_ledger a
USING credit_ledger b
WHERE a.paddle_transaction_id IS NOT NULL
  AND a.paddle_transaction_id = b.paddle_transaction_id
  AND (a.created_at, a.id) > (b.created_at, b.id);

-- Idempotent so re-running the migration is a no-op (ADD CONSTRAINT has no
-- IF NOT EXISTS form).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'credit_ledger_paddle_transaction_id_unique'
    ) THEN
        ALTER TABLE credit_ledger
            ADD CONSTRAINT credit_ledger_paddle_transaction_id_unique
            UNIQUE (paddle_transaction_id);
    END IF;
END $$;
