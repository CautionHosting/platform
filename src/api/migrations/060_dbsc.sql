-- SPDX-FileCopyrightText: 2026 Caution SEZC
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

-- Device Bound Session Credentials (DBSC) for the dashboard session. Additive
-- and nullable: sessions that never register stay unbound and resolve by their
-- raw session_id exactly as before. IF NOT EXISTS keeps re-runs a no-op
-- (utils/makefile-run-migrations.sh applies every file on each run).
ALTER TABLE auth_sessions
  ADD COLUMN IF NOT EXISTS dbsc_id                    TEXT UNIQUE,   -- non-secret DBSC session_identifier
  ADD COLUMN IF NOT EXISTS dbsc_public_key            BYTEA,         -- SEC1 P-256 point; NOT NULL = bound
  ADD COLUMN IF NOT EXISTS dbsc_challenge             TEXT,          -- single outstanding challenge, single-use
  ADD COLUMN IF NOT EXISTS dbsc_challenge_expires_at  TIMESTAMPTZ,   -- now + 5 min
  ADD COLUMN IF NOT EXISTS bound_token_hash           BYTEA UNIQUE,  -- sha256(bound_token)
  ADD COLUMN IF NOT EXISTS bound_token_expires_at     TIMESTAMPTZ,   -- min(now + 10 min, expires_at)
  ADD COLUMN IF NOT EXISTS prev_credential_hash       BYTEA,         -- sha256(credential replaced by bind/rotate)
  ADD COLUMN IF NOT EXISTS prev_credential_expires_at TIMESTAMPTZ;   -- 60 s grace for in-flight requests

CREATE INDEX IF NOT EXISTS idx_sessions_prev_credential_hash
  ON auth_sessions(prev_credential_hash) WHERE prev_credential_hash IS NOT NULL;
