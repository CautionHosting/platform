-- SPDX-FileCopyrightText: 2025 Caution SEZC
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

ALTER TABLE qr_login_tokens
    ADD COLUMN IF NOT EXISTS verification_code VARCHAR(6);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'qr_login_tokens'::regclass
          AND conname = 'qr_login_tokens_verification_code_numeric'
    ) THEN
        ALTER TABLE qr_login_tokens
            ADD CONSTRAINT qr_login_tokens_verification_code_numeric
            CHECK (verification_code IS NULL OR verification_code ~ '^[0-9]{6}$');
    END IF;
END
$$;
