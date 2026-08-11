-- SPDX-FileCopyrightText: 2025 Caution SEZC
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

-- Restructure cloud_credentials table:
-- 1. Add resource_id foreign key to link credentials to specific apps/resources
-- 2. Add managed_on_prem boolean flag
-- 3. Remove name column (replaced by resource_id linkage)

-- Add resource_id column with foreign key to compute_resources
ALTER TABLE cloud_credentials
ADD COLUMN IF NOT EXISTS resource_id UUID REFERENCES compute_resources(id) ON DELETE SET NULL;

-- Add managed_on_prem boolean flag (defaults to false for regular credentials)
ALTER TABLE cloud_credentials
ADD COLUMN IF NOT EXISTS managed_on_prem BOOLEAN NOT NULL DEFAULT false;

-- Create index for looking up credentials by resource
CREATE INDEX IF NOT EXISTS idx_cloud_credentials_resource ON cloud_credentials(resource_id) WHERE resource_id IS NOT NULL;

-- Create index for managed on-prem credentials
CREATE INDEX IF NOT EXISTS idx_cloud_credentials_managed_onprem ON cloud_credentials(organization_id) WHERE managed_on_prem = true;

-- Drop the unique constraint on name (we're removing the name column)
DO
$$BEGIN
    ALTER TABLE cloud_credentials DROP CONSTRAINT cloud_credentials_unique_name;
EXCEPTION
    WHEN undefined_object THEN NULL;
END;$$;

-- Remove the name column
DO
$$BEGIN
    ALTER TABLE cloud_credentials DROP COLUMN name;
EXCEPTION
    WHEN undefined_column THEN NULL;
END;$$;

-- Add unique constraint: only one credential per resource (if resource_id is set)
CREATE UNIQUE INDEX IF NOT EXISTS idx_cloud_credentials_unique_resource
    ON cloud_credentials(resource_id)
    WHERE resource_id IS NOT NULL;

COMMENT ON COLUMN cloud_credentials.resource_id IS 'Foreign key to compute_resources - links credential to a specific app/resource';
COMMENT ON COLUMN cloud_credentials.managed_on_prem IS 'True if this is a managed on-premises deployment credential';
