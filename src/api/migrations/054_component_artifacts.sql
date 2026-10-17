-- Preserve the immutable component selection and EIF-paired host helper.
-- NULL is the legacy/source-build path; existing rows remain valid.
ALTER TABLE eif_builds ADD COLUMN IF NOT EXISTS component_artifacts JSONB;
