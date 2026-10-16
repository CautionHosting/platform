-- Normalize metering resource identifiers to EC2 instance ids for live usage.
-- Keep the app UUID separately on tracked_resources for compute resources.

ALTER TABLE tracked_resources
  ADD COLUMN IF NOT EXISTS application_id UUID REFERENCES compute_resources(id);

CREATE INDEX IF NOT EXISTS idx_tracked_resources_application_id
  ON tracked_resources(application_id);

-- A compute resource can have several concurrently running tracked rows: the
-- live application instance plus any builder instance for the same app. The
-- application id is therefore not unique among running rows, and a partial
-- unique index cannot be created. Drop any previously created instance.
--CREATE UNIQUE INDEX IF NOT EXISTS idx_tracked_resources_active_application
--  ON tracked_resources(application_id)
--  WHERE application_id IS NOT NULL AND status = 'running';
DROP INDEX IF EXISTS idx_tracked_resources_active_application;
