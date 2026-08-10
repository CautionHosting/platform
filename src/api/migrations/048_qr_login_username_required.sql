-- SPDX-FileCopyrightText: 2025 Caution SEZC
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

-- Make the username column NOT NULL for QR login tokens.
-- The application now requires a username for all new QR login tokens,
-- so existing rows without a username would be invalid/stale (they should
-- have expired already given the 3-minute TTL).

ALTER TABLE qr_login_tokens 
    ALTER COLUMN username SET NOT NULL;
