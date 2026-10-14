-- Switch and destroy history for deployments-lifecycle apps. Append-only by
-- convention (like signed_request_audit): each operation writes one
-- 'requested' row before it executes, and its outcome rows share its
-- operation_id. Reconciliation settles requests a crash left unanswered.
-- Recovery itself never reads this table.
CREATE TABLE IF NOT EXISTS deployment_events (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_id           UUID NOT NULL,
    organization_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    app_id                 UUID NOT NULL REFERENCES compute_resources(id) ON DELETE CASCADE,
    operation              TEXT NOT NULL
        CHECK (operation IN ('switch', 'deployment_destroy', 'app_destroy')),
    outcome                TEXT NOT NULL
        CHECK (outcome IN ('requested', 'succeeded', 'rejected', 'failed', 'observed')),
    -- On 'requested' rows. NULL actor: the user was deleted.
    actor_user_id          UUID REFERENCES users(id) ON DELETE SET NULL,
    auth_method            TEXT CHECK (auth_method IN ('passkey', 'session', 'ssh_signed')),
    previous_deployment_id UUID,
    target_deployment_id   UUID,
    -- Follows the audit retention policy (user deletion cascades there).
    signed_request_id      UUID REFERENCES signed_request_audit(id) ON DELETE SET NULL,
    -- The API process executing a 'requested' operation (see app_deployments::PROCESS_ID).
    owner_process_id       UUID,
    error                  TEXT,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_deployment_events_one_request
    ON deployment_events(operation_id) WHERE outcome = 'requested';
-- At most one outcome per operation, even under concurrent writers.
CREATE UNIQUE INDEX IF NOT EXISTS idx_deployment_events_one_outcome
    ON deployment_events(operation_id) WHERE outcome <> 'requested';
-- One passkey proof authorizes at most one operation.
CREATE UNIQUE INDEX IF NOT EXISTS idx_deployment_events_one_signed_request
    ON deployment_events(signed_request_id) WHERE outcome = 'requested' AND signed_request_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_deployment_events_operation
    ON deployment_events(operation_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_deployment_events_app_requests
    ON deployment_events(app_id, created_at DESC, operation_id DESC) WHERE outcome = 'requested';
