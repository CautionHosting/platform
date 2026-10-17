-- App deployments (blue-green) for apps on the deployments lifecycle.
-- utils/makefile-run-migrations.sh re-runs every migration on each start:
-- every statement below must be idempotent.

ALTER TABLE compute_resources
    ADD COLUMN IF NOT EXISTS lifecycle TEXT NOT NULL DEFAULT 'legacy';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'compute_resources_lifecycle_check') THEN
        ALTER TABLE compute_resources
            ADD CONSTRAINT compute_resources_lifecycle_check
            CHECK (lifecycle IN ('legacy', 'deployments'));
    END IF;
END $$;

-- App-level OpenTofu outputs: region, VPC, subnet, AZ, instance profile, EIP.
ALTER TABLE compute_resources ADD COLUMN IF NOT EXISTS app_network JSONB;

CREATE TABLE IF NOT EXISTS app_deployments (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id                 UUID NOT NULL REFERENCES compute_resources(id) ON DELETE CASCADE,
    organization_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    status                 TEXT NOT NULL DEFAULT 'reserved'
        CHECK (status IN ('reserved', 'building', 'provisioning', 'running',
                          'failed', 'destroying', 'destroyed')),
    failure_kind           TEXT CHECK (failure_kind IN ('provisioning', 'runtime_lost')),
    owner_process_id       UUID,
    reservation_expires_at TIMESTAMPTZ,
    pushed_by              UUID REFERENCES users(id) ON DELETE SET NULL,
    pushed_ref             TEXT,
    commit_sha             TEXT,
    commit_subject         TEXT,
    configuration          JSONB NOT NULL DEFAULT '{}'::jsonb,
    eif_s3_key             TEXT,
    instance_id            TEXT,
    instance_type          TEXT,
    region                 TEXT,
    state_key              TEXT,
    error                  TEXT,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    running_at             TIMESTAMPTZ,
    activated_at           TIMESTAMPTZ,
    failed_at              TIMESTAMPTZ,
    cleaned_up_at          TIMESTAMPTZ,
    destroyed_at           TIMESTAMPTZ,
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_app_deployments_app ON app_deployments(app_id);

-- One build/provisioning operation per app, including cache hits.
CREATE UNIQUE INDEX IF NOT EXISTS idx_app_deployments_one_active_operation
    ON app_deployments(app_id)
    WHERE status IN ('reserved', 'building', 'provisioning');

CREATE OR REPLACE TRIGGER app_deployments_updated_at
    BEFORE UPDATE ON app_deployments
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

ALTER TABLE compute_resources
    ADD COLUMN IF NOT EXISTS live_deployment_id UUID
        REFERENCES app_deployments(id) ON DELETE SET NULL;

-- Metering: one running meter per Legacy app, one per deployment otherwise.
ALTER TABLE tracked_resources
    ADD COLUMN IF NOT EXISTS deployment_id UUID REFERENCES app_deployments(id) ON DELETE SET NULL;
DROP INDEX IF EXISTS idx_tracked_resources_active_application;
DROP INDEX IF EXISTS idx_tracked_resources_active_legacy_application;
CREATE UNIQUE INDEX idx_tracked_resources_active_legacy_application
    ON tracked_resources(application_id)
    WHERE application_id IS NOT NULL AND status = 'running' AND deployment_id IS NULL
      AND COALESCE(metadata->>'resource_type', '') <> 'builder'
      AND NOT (metadata ? 'build_id');
CREATE UNIQUE INDEX IF NOT EXISTS idx_tracked_resources_active_deployment
    ON tracked_resources(deployment_id)
    WHERE deployment_id IS NOT NULL AND status = 'running';

-- Candidates reuse the app's VPC and Elastic IP, so they reserve neither.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint
               WHERE conname = 'fully_managed_capacity_reservations_vpcs_check'
                 AND pg_get_constraintdef(oid) LIKE '%> 0%') THEN
        ALTER TABLE fully_managed_capacity_reservations
            DROP CONSTRAINT fully_managed_capacity_reservations_vpcs_check;
        ALTER TABLE fully_managed_capacity_reservations
            ADD CONSTRAINT fully_managed_capacity_reservations_vpcs_check CHECK (vpcs >= 0);
    END IF;
    IF EXISTS (SELECT 1 FROM pg_constraint
               WHERE conname = 'fully_managed_capacity_reservations_eips_check'
                 AND pg_get_constraintdef(oid) LIKE '%> 0%') THEN
        ALTER TABLE fully_managed_capacity_reservations
            DROP CONSTRAINT fully_managed_capacity_reservations_eips_check;
        ALTER TABLE fully_managed_capacity_reservations
            ADD CONSTRAINT fully_managed_capacity_reservations_eips_check CHECK (eips >= 0);
    END IF;
END $$;
