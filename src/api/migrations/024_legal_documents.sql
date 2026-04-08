-- Legal document versioning and user consent tracking
-- Supports append-only audit trail of TOS acceptance and privacy notice acknowledgment

-- Canonical registry of legal documents and their versions
CREATE TABLE legal_documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_type VARCHAR(50) NOT NULL,
    version VARCHAR(50) NOT NULL,        -- e.g. '2026-04-08'
    url TEXT NOT NULL,
    published_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    effective_at TIMESTAMPTZ NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT false,
    requires_blocking_reacceptance BOOLEAN NOT NULL DEFAULT false,
    requires_acknowledgment BOOLEAN NOT NULL DEFAULT false,
    summary_json JSONB,                  -- short bullets for UI
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT legal_documents_type_version_unique UNIQUE (document_type, version),
    CONSTRAINT chk_legal_documents_type CHECK (document_type IN ('terms_of_service', 'privacy_notice'))
);

CREATE UNIQUE INDEX idx_legal_documents_one_active_per_type
    ON legal_documents (document_type)
    WHERE is_active = true;

-- Append-only audit trail of user legal events
-- Never update or delete rows in this table
CREATE TABLE user_legal_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    document_type VARCHAR(50) NOT NULL,
    document_version VARCHAR(50) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    event_source VARCHAR(50) NOT NULL,

    CONSTRAINT chk_user_legal_events_doc_type CHECK (document_type IN ('terms_of_service', 'privacy_notice')),
    CONSTRAINT chk_user_legal_events_event_type CHECK (event_type IN ('accepted', 'acknowledged', 'declined', 'notice_shown')),
    CONSTRAINT chk_user_legal_events_event_source CHECK (event_source IN ('signup', 'login_gate', 'banner', 'settings', 'admin_override')),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT,
    session_id VARCHAR(255),

    CONSTRAINT fk_user_legal_events_document
        FOREIGN KEY (document_type, document_version)
        REFERENCES legal_documents(document_type, version)
);

CREATE INDEX idx_user_legal_events_user ON user_legal_events (user_id, document_type);
CREATE INDEX idx_user_legal_events_occurred ON user_legal_events (occurred_at);

-- Seed the initial active documents
INSERT INTO legal_documents (document_type, version, url, effective_at, is_active, requires_blocking_reacceptance, requires_acknowledgment)
VALUES
    ('terms_of_service', '2026-02-12', 'https://caution.co/terms.html', '2026-02-12', true, true, false),
    ('privacy_notice', '2026-04-03', 'https://caution.co/privacy.html', '2026-04-03', true, false, true)
ON CONFLICT (document_type, version) DO NOTHING;
