-- SPDX-FileCopyrightText: 2025 Caution SEZC
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

ALTER TABLE qr_login_tokens
    ADD COLUMN IF NOT EXISTS requestee_token VARCHAR(255);

CREATE UNIQUE INDEX IF NOT EXISTS idx_qr_login_tokens_requestee_token
    ON qr_login_tokens(requestee_token)
    WHERE requestee_token IS NOT NULL;
