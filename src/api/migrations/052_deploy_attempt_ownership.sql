-- Ensure that only the deploy attempt which claimed a resource can mutate its pending state.

ALTER TABLE compute_resources
    ADD COLUMN IF NOT EXISTS deploy_attempt_id UUID;
