ALTER TABLE quorum_bundles ADD COLUMN name TEXT;
ALTER TABLE quorum_bundles ADD COLUMN labels JSONB NOT NULL DEFAULT '{}';
