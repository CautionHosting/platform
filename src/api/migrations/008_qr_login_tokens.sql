-- SPDX-FileCopyrightText: 2025 Caution SEZC
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

CREATE TABLE qr_login_tokens (
    token VARCHAR(255) PRIMARY KEY,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    ip_address VARCHAR(45),
    browser_ip_address VARCHAR(45),
    auth_challenge_key VARCHAR(255),
    session_id VARCHAR(255),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_qr_login_tokens_status ON qr_login_tokens(status);
CREATE INDEX idx_qr_login_tokens_expires ON qr_login_tokens(expires_at);
