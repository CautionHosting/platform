-- SPDX-FileCopyrightText: 2026 Caution SEZC
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

ALTER TABLE users
    ADD COLUMN email_verification_sent_at TIMESTAMPTZ;

COMMENT ON COLUMN users.email_verification_sent_at IS 'Timestamp when the latest email verification message was sent';
