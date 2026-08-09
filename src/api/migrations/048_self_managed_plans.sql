-- Authoritative self-managed/BYOC capacity, independent of billing-provider state.

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

ALTER TABLE subscriptions
    ADD COLUMN IF NOT EXISTS self_managed_plan_id UUID REFERENCES self_managed_plans(id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_self_managed_plan
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
    subscription_id UUID REFERENCES subscriptions(id),
    requested_enclave_limit INTEGER,
    requested_expires_at TIMESTAMPTZ,
    operator_identity TEXT NOT NULL CHECK (length(btrim(operator_identity)) BETWEEN 1 AND 200),
    operator_reason TEXT NOT NULL CHECK (length(btrim(operator_reason)) BETWEEN 1 AND 1000),
    status TEXT NOT NULL CHECK (status IN ('pending', 'provider_pending', 'applied', 'failed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    applied_at TIMESTAMPTZ,
    CONSTRAINT self_managed_plan_changes_limit_check
        CHECK (requested_enclave_limit IS NULL OR requested_enclave_limit > 0)
);

CREATE UNIQUE INDEX idx_self_managed_plan_changes_live_org
    ON self_managed_plan_changes(organization_id)
    WHERE status IN ('pending', 'provider_pending');

CREATE TABLE self_managed_termination_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    self_managed_plan_id UUID NOT NULL REFERENCES self_managed_plans(id) ON DELETE CASCADE,
    subscription_id UUID REFERENCES subscriptions(id),
    resource_id UUID NOT NULL REFERENCES compute_resources(id) ON DELETE CASCADE,
    provider_occurred_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'processing', 'retry', 'completed')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    lease_expires_at TIMESTAMPTZ,
    lease_token UUID,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    UNIQUE (subscription_id, resource_id)
);

CREATE INDEX idx_self_managed_termination_jobs_ready
    ON self_managed_termination_jobs(next_attempt_at, created_at)
    WHERE status IN ('pending', 'retry');
