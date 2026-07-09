-- Track whether a fido2 credential is a discoverable (resident) credential.
-- Nullable: NULL means unknown (residency wasn't captured at registration
-- time, or the credential predates this column). Populated going forward via
-- the credProps registration extension when available, and opportunistically
-- backfilled to true on a successful discoverable (username-less) login.

ALTER TABLE fido2_credentials ADD COLUMN IF NOT EXISTS resident BOOLEAN;
