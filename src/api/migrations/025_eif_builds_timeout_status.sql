-- Add 'timeout' to eif_builds status CHECK constraint so the reaper can mark timed-out builds
ALTER TABLE eif_builds DROP CONSTRAINT IF EXISTS chk_eif_builds_status;
ALTER TABLE eif_builds ADD CONSTRAINT chk_eif_builds_status
    CHECK (status IN ('pending', 'building', 'completed', 'failed', 'timeout'));
