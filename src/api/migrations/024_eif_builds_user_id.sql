-- Add user_id to eif_builds so orphaned/timed-out builds can be billed
ALTER TABLE eif_builds ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES users(id);
CREATE INDEX IF NOT EXISTS idx_eif_builds_user_id ON eif_builds(user_id);
