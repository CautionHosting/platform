-- Allow the same SSH key to be used by multiple users
-- Previously: fingerprint was globally unique (one key = one user)
-- Now: fingerprint is unique per user (same key can be on multiple accounts)

-- Drop the global uniqueness constraint
ALTER TABLE ssh_keys DROP CONSTRAINT ssh_keys_fingerprint_key;

-- Add per-user uniqueness (same user can't add same key twice)
CREATE UNIQUE INDEX ssh_keys_user_fingerprint_unique ON ssh_keys(user_id, fingerprint);
