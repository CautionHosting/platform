-- SPDX-FileCopyrightText: 2025 Caution SEZC
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

CREATE TABLE qr_sign_tokens (
    token VARCHAR(255) PRIMARY KEY,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    challenge_id VARCHAR(255) NOT NULL,
    challenge_json TEXT NOT NULL,
    method VARCHAR(10) NOT NULL,
    path TEXT NOT NULL,
    body TEXT NOT NULL,
    body_hash VARCHAR(64) NOT NULL,
    fido2_response TEXT,
    ip_address VARCHAR(45),
    browser_ip_address VARCHAR(45),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_qr_sign_tokens_status ON qr_sign_tokens(status);
CREATE INDEX idx_qr_sign_tokens_expires ON qr_sign_tokens(expires_at);
