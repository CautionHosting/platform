-- Fully managed regional capacity routing.

CREATE TABLE IF NOT EXISTS fully_managed_capacity_reservations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    resource_id     UUID NOT NULL REFERENCES compute_resources(id) ON DELETE CASCADE,
    region          TEXT NOT NULL,
    host_vcpus      INTEGER NOT NULL CHECK (host_vcpus > 0),
    vpcs            INTEGER NOT NULL DEFAULT 1 CHECK (vpcs > 0),
    eips            INTEGER NOT NULL DEFAULT 1 CHECK (eips > 0),
    status          TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'released', 'expired')),
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '45 minutes',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fully_managed_capacity_pending
    ON fully_managed_capacity_reservations(region, expires_at)
    WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_fully_managed_capacity_resource
    ON fully_managed_capacity_reservations(resource_id);

CREATE TRIGGER fully_managed_capacity_reservations_updated_at
    BEFORE UPDATE ON fully_managed_capacity_reservations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TABLE IF NOT EXISTS fully_managed_capacity_waitlist (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id                  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email                    TEXT NOT NULL,
    requested_enclave_vcpus  INTEGER,
    required_host_vcpus      INTEGER,
    status                   TEXT NOT NULL DEFAULT 'waiting'
        CHECK (status IN ('waiting', 'notified', 'closed')),
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    notified_at              TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_fully_managed_capacity_waitlist_status
    ON fully_managed_capacity_waitlist(status, created_at);

CREATE UNIQUE INDEX IF NOT EXISTS idx_fully_managed_capacity_waitlist_waiting_email
    ON fully_managed_capacity_waitlist(organization_id, email)
    WHERE status = 'waiting';
