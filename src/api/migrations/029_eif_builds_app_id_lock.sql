-- Track builds by app and allow only one active builder per app.
ALTER TABLE eif_builds
  ADD COLUMN IF NOT EXISTS app_id UUID REFERENCES compute_resources(id);

CREATE INDEX IF NOT EXISTS idx_eif_builds_app_id
  ON eif_builds(app_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_eif_builds_active_app
  ON eif_builds(app_id)
  WHERE app_id IS NOT NULL AND status IN ('pending', 'building');
