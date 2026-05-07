-- Legal notice email batches and delivery audit

CREATE TABLE legal_notice_batches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    dedupe_key TEXT NOT NULL UNIQUE,
    terms_document_id UUID REFERENCES legal_documents(id),
    privacy_document_id UUID REFERENCES legal_documents(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_legal_notice_batches_has_document CHECK (
        terms_document_id IS NOT NULL OR privacy_document_id IS NOT NULL
    )
);

CREATE INDEX idx_legal_notice_batches_terms_document
    ON legal_notice_batches (terms_document_id)
    WHERE terms_document_id IS NOT NULL;

CREATE INDEX idx_legal_notice_batches_privacy_document
    ON legal_notice_batches (privacy_document_id)
    WHERE privacy_document_id IS NOT NULL;

CREATE TABLE legal_email_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID NOT NULL REFERENCES legal_notice_batches(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    status VARCHAR(20) NOT NULL,
    error TEXT,
    sent_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT legal_email_deliveries_batch_user_unique UNIQUE (batch_id, user_id),
    CONSTRAINT chk_legal_email_deliveries_status CHECK (status IN ('sent', 'failed'))
);

CREATE INDEX idx_legal_email_deliveries_batch
    ON legal_email_deliveries (batch_id, status);

CREATE INDEX idx_legal_email_deliveries_user
    ON legal_email_deliveries (user_id, created_at DESC);
