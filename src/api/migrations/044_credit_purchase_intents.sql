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
ALTER TABLE credit_ledger
    ADD CONSTRAINT credit_ledger_paddle_transaction_id_unique
    UNIQUE (paddle_transaction_id);
