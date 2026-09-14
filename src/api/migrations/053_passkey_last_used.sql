-- Passkey verification history must survive logout and session cleanup.
ALTER TABLE fido2_credentials
    ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;

-- Only retained verification evidence is suitable for historical recovery.
-- Session activity, registration and updated_at are not verification times.
UPDATE fido2_credentials AS c
SET last_used_at = GREATEST(c.last_used_at, history.last_used_at)
FROM (
    SELECT user_id, credential_id, MAX(verified_at) AS last_used_at
    FROM signed_request_audit
    GROUP BY user_id, credential_id
) AS history
WHERE c.user_id = history.user_id
  AND c.credential_id = history.credential_id;

COMMENT ON COLUMN fido2_credentials.last_used_at IS
    'Last recorded successful passkey verification for login or signing; NULL means usage unknown';
