-- Allow deployment events to record a token actor.
--
-- `deployment_events.auth_method` was created by 058 with a CHECK limited to
-- passkey/session/ssh_signed. Organization access tokens now authorize the same
-- operations (destroy; later, switch), so 'token' joins the set.
--
-- Migrations re-run on every start, so this is written to be idempotent: drop
-- the existing check (by its auto-generated name) and re-add the widened one.

ALTER TABLE deployment_events
    DROP CONSTRAINT IF EXISTS deployment_events_auth_method_check;

ALTER TABLE deployment_events
    ADD CONSTRAINT deployment_events_auth_method_check
    CHECK (auth_method IN ('passkey', 'session', 'ssh_signed', 'token'));
