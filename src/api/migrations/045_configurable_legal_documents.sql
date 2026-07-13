-- Generalize legal document tracking beyond the two hardcoded types
-- (terms_of_service, privacy_notice) so a new document type can be
-- published via utils/admin without a code/schema change.

-- Drop the type whitelist CHECK constraints; legal_documents.document_type
-- and user_legal_events.document_type are now open strings. The FK from
-- user_legal_events(document_type, version) -> legal_documents(document_type, version)
-- still guarantees every event points at a real, known document.
ALTER TABLE legal_documents DROP CONSTRAINT IF EXISTS chk_legal_documents_type;
ALTER TABLE user_legal_events DROP CONSTRAINT IF EXISTS chk_user_legal_events_doc_type;

-- Optional display title per document. Falls back to a humanized
-- document_type (e.g. "terms_of_service" -> "Terms Of Service") in the
-- application when NULL, so existing rows need no backfill.
ALTER TABLE legal_documents ADD COLUMN title TEXT;

-- Replace the two fixed FK columns on legal_notice_batches with a join
-- table so a batch can reference any number of documents of any type.
CREATE TABLE legal_notice_batch_documents (
    batch_id UUID NOT NULL REFERENCES legal_notice_batches(id) ON DELETE CASCADE,
    document_id UUID NOT NULL REFERENCES legal_documents(id),
    PRIMARY KEY (batch_id, document_id)
);

CREATE INDEX idx_legal_notice_batch_documents_document
    ON legal_notice_batch_documents (document_id);

INSERT INTO legal_notice_batch_documents (batch_id, document_id)
SELECT id, terms_document_id FROM legal_notice_batches WHERE terms_document_id IS NOT NULL;

INSERT INTO legal_notice_batch_documents (batch_id, document_id)
SELECT id, privacy_document_id FROM legal_notice_batches WHERE privacy_document_id IS NOT NULL;

-- legal_notice_dedupe_key() now generates sorted-UUID keys ("<id>;<id>...")
-- instead of the old fixed "terms=<id>;privacy=<id>" format. Existing rows
-- must be renormalized to the new format now, while we still have the join
-- table to compute it from - otherwise the next send-legal-notices run for
-- an already-notified document set won't find its old-format row, creates a
-- new batch, and re-emails everyone who already got the notice.
UPDATE legal_notice_batches lnb
SET dedupe_key = normalized.dedupe_key
FROM (
    SELECT batch_id, string_agg(document_id::text, ';' ORDER BY document_id::text) AS dedupe_key
    FROM legal_notice_batch_documents
    GROUP BY batch_id
) normalized
WHERE lnb.id = normalized.batch_id;

ALTER TABLE legal_notice_batches DROP CONSTRAINT IF EXISTS chk_legal_notice_batches_has_document;
DROP INDEX IF EXISTS idx_legal_notice_batches_terms_document;
DROP INDEX IF EXISTS idx_legal_notice_batches_privacy_document;
ALTER TABLE legal_notice_batches DROP COLUMN IF EXISTS terms_document_id;
ALTER TABLE legal_notice_batches DROP COLUMN IF EXISTS privacy_document_id;
