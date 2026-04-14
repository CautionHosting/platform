-- Normalize metering resource identifiers to EC2 instance ids for live usage.
-- Keep the app UUID separately on tracked_resources for compute resources.

ALTER TABLE tracked_resources
  ADD COLUMN IF NOT EXISTS application_id UUID REFERENCES compute_resources(id);

CREATE INDEX IF NOT EXISTS idx_tracked_resources_application_id
  ON tracked_resources(application_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_tracked_resources_active_application
  ON tracked_resources(application_id)
  WHERE application_id IS NOT NULL AND status = 'running';
