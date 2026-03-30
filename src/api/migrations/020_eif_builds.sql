-- Dedicated builder EIF cache
-- Tracks builds and their outputs so we can reuse EIFs across deploys.

CREATE TABLE eif_builds (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),

    -- Cache key components
    commit_sha VARCHAR(64) NOT NULL,
    procfile_hash VARCHAR(64) NOT NULL,
    cache_key VARCHAR(64) NOT NULL,

    -- Build outputs
    eif_s3_key VARCHAR(512),
    eif_sha256 VARCHAR(64),
    eif_size_bytes BIGINT,
    pcrs JSONB,

    -- Builder metadata
    builder_instance_id VARCHAR(64),
    builder_instance_type VARCHAR(32),

    -- Status: pending | building | uploading | completed | failed | timeout
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    error_message TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Only one completed build per org+cache_key (failed/timed out builds don't block retries)
CREATE UNIQUE INDEX idx_eif_builds_cache_lookup
    ON eif_builds(organization_id, cache_key)
    WHERE status = 'completed';

CREATE INDEX idx_eif_builds_stale
    ON eif_builds(created_at)
    WHERE status IN ('pending', 'building');
