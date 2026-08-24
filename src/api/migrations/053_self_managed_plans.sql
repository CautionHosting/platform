-- Authoritative self-managed/BYOC capacity, independent of billing-provider state.
BEGIN;

CREATE TABLE self_managed_plans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    tier TEXT NOT NULL,
    -- NULL is unlimited, zero disables the plan, positive values are finite limits.
    enclave_limit INTEGER,
    source TEXT NOT NULL,
    expires_at TIMESTAMPTZ,
    operator_identity TEXT,
    operator_reason TEXT,
    terminated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT self_managed_plans_one_per_org UNIQUE (organization_id),
    CONSTRAINT self_managed_plans_id_org_unique UNIQUE (id, organization_id),
    CONSTRAINT self_managed_plans_tier_nonempty CHECK (length(btrim(tier)) > 0),
    CONSTRAINT self_managed_plans_limit_check CHECK (enclave_limit IS NULL OR enclave_limit >= 0),
    CONSTRAINT self_managed_plans_source_check CHECK (source IN ('paddle', 'manual', 'legacy')),
    CONSTRAINT self_managed_plans_manual_audit_check CHECK (
        source <> 'manual'
        OR (
            operator_identity IS NOT NULL
            AND length(btrim(operator_identity)) BETWEEN 1 AND 200
            AND operator_reason IS NOT NULL
            AND length(btrim(operator_reason)) BETWEEN 1 AND 1000
        )
    ),
    CONSTRAINT self_managed_plans_terminated_check CHECK (
        terminated_at IS NULL OR enclave_limit = 0
    )
);

-- Migration 045 introduced the provider status set under a new constraint name,
-- leaving the original constraint in place on upgraded databases.
ALTER TABLE subscriptions DROP CONSTRAINT IF EXISTS chk_subscriptions_status;
ALTER TABLE subscriptions DROP CONSTRAINT IF EXISTS subscriptions_status_check;
ALTER TABLE subscriptions ADD CONSTRAINT subscriptions_status_check
    CHECK (status IN ('pending', 'trialing', 'active', 'past_due', 'paused', 'canceled'));

ALTER TABLE subscriptions ADD COLUMN self_managed_plan_id UUID;
-- Existing live tier mutations do not carry a reconstructable idempotent Paddle payload.
-- Expire local-only stale intents, then fail the rollout rather than making an
-- ambiguous provider operation unrecoverable.
UPDATE subscription_intents
SET status = 'canceled', updated_at = NOW()
WHERE operation IN ('upgrade', 'downgrade')
  AND status = 'pending' AND expires_at <= NOW();
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM subscription_intents
        WHERE operation IN ('upgrade', 'downgrade')
          AND status IN ('pending', 'provider_pending')
    ) THEN
        RAISE EXCEPTION 'cannot migrate live Paddle tier intents: reconcile them before migration 053';
    END IF;
END
$$;
-- Persist the exact Paddle mutation payload for idempotent retries across catalog changes.
ALTER TABLE subscription_intents
    ADD COLUMN provider_price_id TEXT,
    ADD COLUMN provider_price_cents_per_cycle BIGINT,
    ADD COLUMN provider_proration_mode TEXT
        CHECK (provider_proration_mode IN ('prorated_immediately', 'do_not_bill'));
CREATE UNIQUE INDEX subscriptions_id_organization_unique
    ON subscriptions(id, organization_id);
CREATE UNIQUE INDEX compute_resources_id_organization_unique
    ON compute_resources(id, organization_id);
ALTER TABLE subscriptions ADD CONSTRAINT subscriptions_plan_organization_fk
    FOREIGN KEY (self_managed_plan_id, organization_id)
    REFERENCES self_managed_plans(id, organization_id)
    ON DELETE SET NULL (self_managed_plan_id);
CREATE UNIQUE INDEX idx_subscriptions_self_managed_plan
    ON subscriptions(self_managed_plan_id)
    WHERE self_managed_plan_id IS NOT NULL;

-- Preserve existing BYOC entitlements while moving enforcement to the new table.
INSERT INTO self_managed_plans (
    organization_id, tier, enclave_limit, source, expires_at,
    operator_identity, operator_reason, terminated_at
)
SELECT DISTINCT ON (s.organization_id)
    s.organization_id,
    s.tier,
    CASE
        WHEN s.status = 'canceled' THEN 0
        WHEN s.billing_source = 'paddle'
             AND (s.status <> 'active' OR NOT s.catalog_valid) THEN 0
        WHEN s.billing_source = 'enterprise' AND s.tier = 'enterprise_unlimited' THEN NULL
        ELSE GREATEST(s.max_apps, 0)
    END,
    CASE s.billing_source
        WHEN 'paddle' THEN 'paddle'
        WHEN 'enterprise' THEN 'manual'
        ELSE 'legacy'
    END,
    s.enterprise_expires_at,
    CASE WHEN s.billing_source = 'enterprise' THEN 'migration' ELSE NULL END,
    CASE WHEN s.billing_source = 'enterprise' THEN 'pre-existing enterprise entitlement' ELSE NULL END,
    CASE WHEN s.status = 'canceled' THEN COALESCE(s.canceled_at, s.updated_at) ELSE NULL END
FROM subscriptions s
ORDER BY s.organization_id, (s.status <> 'canceled') DESC, s.created_at DESC
ON CONFLICT (organization_id) DO NOTHING;

UPDATE subscriptions s
SET self_managed_plan_id = p.id
FROM self_managed_plans p
WHERE p.organization_id = s.organization_id
  AND s.self_managed_plan_id IS NULL
  AND s.id = (
      SELECT latest.id FROM subscriptions latest
      WHERE latest.organization_id = s.organization_id
      ORDER BY (latest.status <> 'canceled') DESC, latest.created_at DESC
      LIMIT 1
  );

-- Canceled provider rows remain immutable billing history, not owners of plans.
UPDATE subscriptions
SET self_managed_plan_id = NULL
WHERE status = 'canceled' AND self_managed_plan_id IS NOT NULL;

CREATE TABLE self_managed_plan_changes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    subscription_id UUID NOT NULL,
    requested_enclave_limit INTEGER,
    requested_expires_at TIMESTAMPTZ,
    operator_identity TEXT NOT NULL CHECK (length(btrim(operator_identity)) BETWEEN 1 AND 200),
    operator_reason TEXT NOT NULL CHECK (length(btrim(operator_reason)) BETWEEN 1 AND 1000),
    status TEXT NOT NULL CHECK (status IN ('pending', 'provider_pending', 'applied', 'failed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    applied_at TIMESTAMPTZ,
    CONSTRAINT self_managed_plan_changes_subscription_org_fk
        FOREIGN KEY (subscription_id, organization_id)
        REFERENCES subscriptions(id, organization_id) ON DELETE CASCADE,
    CONSTRAINT self_managed_plan_changes_limit_check
        CHECK (requested_enclave_limit IS NULL OR requested_enclave_limit > 0)
);
CREATE UNIQUE INDEX idx_self_managed_plan_changes_live_org
    ON self_managed_plan_changes(organization_id)
    WHERE status IN ('pending', 'provider_pending');

CREATE TABLE self_managed_termination_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    self_managed_plan_id UUID NOT NULL,
    subscription_id UUID NOT NULL,
    resource_id UUID NOT NULL,
    provider_occurred_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'processing', 'retry', 'completed', 'dead_letter')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    lease_expires_at TIMESTAMPTZ,
    lease_token UUID,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    recovery_action TEXT CHECK (recovery_action IN ('retry', 'resolve')),
    recovery_operator TEXT CHECK (recovery_operator IS NULL OR length(btrim(recovery_operator)) BETWEEN 1 AND 200),
    recovery_reason TEXT CHECK (recovery_reason IS NULL OR length(btrim(recovery_reason)) BETWEEN 1 AND 1000),
    recovered_at TIMESTAMPTZ,
    CONSTRAINT self_managed_termination_jobs_recovery_audit_check
        CHECK ((recovery_action IS NULL AND recovery_operator IS NULL
                AND recovery_reason IS NULL AND recovered_at IS NULL)
            OR (recovery_action IS NOT NULL AND recovery_operator IS NOT NULL
                AND recovery_reason IS NOT NULL AND recovered_at IS NOT NULL)),
    CONSTRAINT self_managed_termination_jobs_plan_org_fk
        FOREIGN KEY (self_managed_plan_id, organization_id)
        REFERENCES self_managed_plans(id, organization_id) ON DELETE CASCADE,
    CONSTRAINT self_managed_termination_jobs_subscription_org_fk
        FOREIGN KEY (subscription_id, organization_id)
        REFERENCES subscriptions(id, organization_id) ON DELETE CASCADE,
    CONSTRAINT self_managed_termination_jobs_resource_org_fk
        FOREIGN KEY (resource_id, organization_id)
        REFERENCES compute_resources(id, organization_id) ON DELETE CASCADE,
    UNIQUE (subscription_id, resource_id)
);
CREATE INDEX idx_self_managed_termination_jobs_ready
    ON self_managed_termination_jobs(next_attempt_at, created_at)
    WHERE status IN ('pending', 'retry');

-- During a rolling deployment, an older metering process may still update only
-- subscriptions. Keep linked provider plans fail-closed until all writers use
-- the new plan projection; the application also performs the same projection.
CREATE FUNCTION sync_linked_self_managed_plan() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.self_managed_plan_id IS NULL THEN
        RETURN NEW;
    END IF;

    IF NEW.billing_source = 'paddle' THEN
        UPDATE self_managed_plans
        SET tier = COALESCE(NEW.pending_tier, NEW.tier),
            enclave_limit = CASE
                WHEN NEW.status = 'active' AND NEW.catalog_valid THEN
                    CASE WHEN NEW.pending_max_apps IS NULL THEN NEW.max_apps
                         ELSE LEAST(NEW.max_apps, NEW.pending_max_apps) END
                ELSE 0
            END,
            terminated_at = CASE
                WHEN NEW.status = 'canceled' THEN COALESCE(terminated_at, NEW.canceled_at, NOW())
                WHEN NEW.status = 'active' THEN NULL
                ELSE terminated_at
            END,
            updated_at = NOW()
        WHERE id = NEW.self_managed_plan_id
          AND organization_id = NEW.organization_id
          AND source = 'paddle';
    ELSIF NEW.billing_source = 'legacy_credits' THEN
        UPDATE self_managed_plans
        SET tier = NEW.tier,
            enclave_limit = CASE WHEN NEW.status IN ('active', 'past_due')
                                 THEN GREATEST(NEW.max_apps, 0) ELSE 0 END,
            terminated_at = CASE WHEN NEW.status = 'canceled'
                                 THEN COALESCE(terminated_at, NEW.canceled_at, NOW())
                                 ELSE terminated_at END,
            updated_at = NOW()
        WHERE id = NEW.self_managed_plan_id
          AND organization_id = NEW.organization_id
          AND source = 'legacy';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER subscriptions_sync_linked_self_managed_plan
AFTER INSERT OR UPDATE OF tier, max_apps, pending_tier, pending_max_apps,
    status, catalog_valid, canceled_at, self_managed_plan_id
ON subscriptions
FOR EACH ROW EXECUTE FUNCTION sync_linked_self_managed_plan();

COMMIT;
