-- Canonical hash of the quorum bundle committed at the deployment's exact SHA
-- (`.caution/quorum-bundle.json`, the documented image input).
-- NULL: the source had no bundle; release then requires an explicit bundle.
ALTER TABLE app_deployments ADD COLUMN IF NOT EXISTS bundle_hash TEXT;
