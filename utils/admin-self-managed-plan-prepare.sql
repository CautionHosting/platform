\set ON_ERROR_STOP on
BEGIN;
SELECT pg_advisory_xact_lock(hashtextextended(:'organization_id', 0));
SELECT set_config('admin.organization_id', :'organization_id', true);
SELECT set_config('admin.enclave_limit', :'enclave_limit', true);
SELECT set_config('admin.expires_at', :'expires_at', true);
SELECT set_config('admin.operator_identity', :'operator_identity', true);
SELECT set_config('admin.operator_reason', :'operator_reason', true);
SELECT set_config('admin.detach_paddle', :'detach_paddle', true);

DO $body$
DECLARE
    v_plan_id UUID;
    v_subscription_id UUID;
    v_provider_id TEXT;
    v_source TEXT;
    v_existing self_managed_plan_changes%ROWTYPE;
BEGIN
    SELECT id, source INTO v_plan_id, v_source
    FROM self_managed_plans
    WHERE organization_id = current_setting('admin.organization_id')::uuid
    FOR UPDATE;

    SELECT id, paddle_subscription_id INTO v_subscription_id, v_provider_id
    FROM subscriptions
    WHERE organization_id = current_setting('admin.organization_id')::uuid
      AND self_managed_plan_id = v_plan_id
      AND billing_source = 'paddle'
      AND status <> 'canceled'
    FOR UPDATE;

    IF v_subscription_id IS NOT NULL THEN
        IF current_setting('admin.detach_paddle') <> 'true' THEN
            RAISE EXCEPTION 'active Paddle plan requires --detach-paddle';
        END IF;

        SELECT * INTO v_existing
        FROM self_managed_plan_changes
        WHERE organization_id = current_setting('admin.organization_id')::uuid
          AND status IN ('pending', 'provider_pending')
        FOR UPDATE;

        IF FOUND THEN
            IF v_existing.subscription_id IS DISTINCT FROM v_subscription_id
               OR v_existing.requested_enclave_limit IS DISTINCT FROM NULLIF(current_setting('admin.enclave_limit'), '')::integer
               OR v_existing.requested_expires_at IS DISTINCT FROM NULLIF(current_setting('admin.expires_at'), '')::timestamptz
               OR v_existing.operator_identity <> current_setting('admin.operator_identity')
               OR v_existing.operator_reason <> current_setting('admin.operator_reason') THEN
                RAISE EXCEPTION 'a different self-managed plan change is already pending';
            END IF;
        ELSE
            INSERT INTO self_managed_plan_changes (
                organization_id, subscription_id, requested_enclave_limit,
                requested_expires_at, operator_identity, operator_reason, status
            ) VALUES (
                current_setting('admin.organization_id')::uuid, v_subscription_id,
                NULLIF(current_setting('admin.enclave_limit'), '')::integer,
                NULLIF(current_setting('admin.expires_at'), '')::timestamptz,
                current_setting('admin.operator_identity'), current_setting('admin.operator_reason'), 'provider_pending'
            );
        END IF;
    ELSE
        INSERT INTO self_managed_plans (
            organization_id, tier, enclave_limit, source, expires_at,
            operator_identity, operator_reason, terminated_at, updated_at
        ) VALUES (
            current_setting('admin.organization_id')::uuid, 'enterprise_contract',
            NULLIF(current_setting('admin.enclave_limit'), '')::integer, 'manual',
            NULLIF(current_setting('admin.expires_at'), '')::timestamptz,
            current_setting('admin.operator_identity'), current_setting('admin.operator_reason'), NULL, NOW()
        )
        ON CONFLICT (organization_id) DO UPDATE SET
            tier = EXCLUDED.tier,
            enclave_limit = EXCLUDED.enclave_limit,
            source = 'manual',
            expires_at = EXCLUDED.expires_at,
            operator_identity = EXCLUDED.operator_identity,
            operator_reason = EXCLUDED.operator_reason,
            terminated_at = NULL,
            updated_at = NOW();

        UPDATE subscriptions
        SET self_managed_plan_id = NULL, updated_at = NOW()
        WHERE organization_id = current_setting('admin.organization_id')::uuid
          AND status = 'canceled';
    END IF;
END
$body$;

SELECT COALESCE(c.id::text, '') || '|' || COALESCE(s.paddle_subscription_id, '') || '|' ||
       CASE WHEN c.id IS NULL THEN 'applied' ELSE c.status END
FROM (SELECT 1) seed
LEFT JOIN self_managed_plan_changes c
  ON c.organization_id = current_setting('admin.organization_id')::uuid
 AND c.status IN ('pending', 'provider_pending')
LEFT JOIN subscriptions s ON s.id = c.subscription_id;
COMMIT;
