-- Tie legal document rows to immutable website source artifacts.
-- Adds source provenance on legal_documents and backfills user events so
-- acceptance records point to an exact legal_documents row.

ALTER TABLE legal_documents
    ADD COLUMN source_commit_sha TEXT,
    ADD COLUMN source_path TEXT,
    ADD COLUMN content_sha256 TEXT;

-- Current website source of truth:
--   repo: caution/website
--   commit: 223267415eeb26d44a1afe9fb25b28fdf3312153
UPDATE legal_documents
SET
    source_commit_sha = '223267415eeb26d44a1afe9fb25b28fdf3312153',
    source_path = 'terms.md',
    content_sha256 = '31af5848f053f0d0dd93a370495722a49955e2f7164a5d0871b6585f766bd077'
WHERE document_type = 'terms_of_service'
  AND version = '2026-02-12'
  AND source_commit_sha IS NULL;

UPDATE legal_documents
SET
    source_commit_sha = '223267415eeb26d44a1afe9fb25b28fdf3312153',
    source_path = 'privacy.md',
    content_sha256 = '6778eab23680bbcbd9f31006d9605fce091eab3fceec351b35a38b72a3c2b35c'
WHERE document_type = 'privacy_notice'
  AND version = '2026-04-03'
  AND source_commit_sha IS NULL;

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
