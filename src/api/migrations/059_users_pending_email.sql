-- SPDX-FileCopyrightText: 2026 Caution SEZC
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

ALTER TABLE users
ADD COLUMN IF NOT EXISTS pending_email VARCHAR(255);

COMMENT ON COLUMN users.pending_email IS 'Address awaiting verification; replaces email once its verification link is followed';
