-- SPDX-FileCopyrightText: 2025 Caution SEZC
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

-- Add last_used_at column to track when SSH keys are used for git operations

ALTER TABLE ssh_keys
ADD COLUMN last_used_at TIMESTAMP;

COMMENT ON COLUMN ssh_keys.last_used_at IS 'Timestamp of last successful authentication using this key';

-- Index for identifying stale keys
CREATE INDEX idx_ssh_keys_last_used ON ssh_keys(last_used_at) WHERE last_used_at IS NOT NULL;
