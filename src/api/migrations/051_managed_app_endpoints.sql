-- Stable Caution-managed DNS endpoints for application resources.

ALTER TYPE resource_state ADD VALUE IF NOT EXISTS 'terminating';

ALTER TABLE compute_resources
    ADD COLUMN IF NOT EXISTS dns_status TEXT NOT NULL DEFAULT 'reserved',
    ADD COLUMN IF NOT EXISTS dns_error TEXT,
    ADD COLUMN IF NOT EXISTS dns_change_id TEXT,
    ADD COLUMN IF NOT EXISTS dns_release_not_before TIMESTAMPTZ;

ALTER TABLE compute_resources
    DROP CONSTRAINT IF EXISTS compute_resources_dns_status_check;

ALTER TABLE compute_resources
    ADD CONSTRAINT compute_resources_dns_status_check
    CHECK (dns_status IN ('reserved', 'publishing', 'ready', 'withdrawing'));

CREATE INDEX IF NOT EXISTS idx_compute_resources_dns_reconcile
    ON compute_resources (dns_status, state)
    WHERE dns_status IN ('publishing', 'withdrawing') OR state = 'terminating';
