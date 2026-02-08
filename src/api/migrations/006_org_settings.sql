-- SPDX-FileCopyrightText: 2025 Caution SEZC
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

-- Add settings column to organizations table for dynamic configuration
ALTER TABLE organizations ADD COLUMN settings JSONB NOT NULL DEFAULT '{}'::jsonb;

-- Add index for settings queries
CREATE INDEX idx_organizations_settings ON organizations USING GIN (settings);

-- Add comment
COMMENT ON COLUMN organizations.settings IS 'Dynamic organization settings (require_pin, etc.)';
