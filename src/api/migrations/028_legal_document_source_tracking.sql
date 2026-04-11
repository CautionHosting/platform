-- Tie legal document rows to immutable website source artifacts.
-- Adds source provenance on legal_documents and backfills user events so
-- acceptance records point to an exact legal_documents row.

ALTER TABLE legal_documents
    ADD COLUMN source_commit_sha TEXT,
    ADD COLUMN source_path TEXT,
    ADD COLUMN content_sha256 TEXT;

CREATE UNIQUE INDEX idx_legal_documents_type_content_sha
    ON legal_documents (document_type, content_sha256)
    WHERE content_sha256 IS NOT NULL;

ALTER TABLE user_legal_events
    ADD COLUMN legal_document_id UUID;

UPDATE user_legal_events ule
SET legal_document_id = ld.id
FROM legal_documents ld
WHERE ld.document_type = ule.document_type
  AND ld.version = ule.document_version
  AND ule.legal_document_id IS NULL;

ALTER TABLE user_legal_events
    ALTER COLUMN legal_document_id SET NOT NULL;

ALTER TABLE user_legal_events
    ADD CONSTRAINT fk_user_legal_events_legal_document_id
        FOREIGN KEY (legal_document_id)
        REFERENCES legal_documents(id);

CREATE INDEX idx_user_legal_events_document_id
    ON user_legal_events (legal_document_id);
