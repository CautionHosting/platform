\set ON_ERROR_STOP on
BEGIN;
SELECT pg_advisory_xact_lock(hashtextextended(:'organization_id', 0));
SELECT set_config('admin.organization_id', :'organization_id', true);
SELECT set_config('admin.change_id', :'change_id', true);

DO $body$
DECLARE
    v_change self_managed_plan_changes%ROWTYPE;
    v_subscription subscriptions%ROWTYPE;
    v_plan self_managed_plans%ROWTYPE;
BEGIN
    SELECT * INTO v_change
    FROM self_managed_plan_changes
    WHERE id = current_setting('admin.change_id')::uuid
      AND organization_id = current_setting('admin.organization_id')::uuid
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'self-managed plan change not found';
    END IF;
    IF v_change.status = 'applied' THEN
        RETURN;
    END IF;
    IF v_change.status <> 'provider_pending' THEN
        RAISE EXCEPTION 'self-managed plan change is not provider-pending';
    END IF;

    SELECT * INTO v_subscription
    FROM subscriptions
    WHERE id = v_change.subscription_id
    FOR UPDATE;
    IF NOT FOUND
       OR v_subscription.organization_id <> v_change.organization_id
       OR v_subscription.billing_source <> 'paddle'
       OR v_subscription.paddle_subscription_id IS NULL
       OR v_subscription.self_managed_plan_id IS NULL THEN
        RAISE EXCEPTION 'Paddle subscription no longer controls the requested plan';
    END IF;

    SELECT * INTO v_plan
    FROM self_managed_plans
    WHERE id = v_subscription.self_managed_plan_id
      AND organization_id = v_change.organization_id
    FOR UPDATE;
    IF NOT FOUND OR v_plan.source <> 'paddle' THEN
        RAISE EXCEPTION 'organization plan is no longer controlled by Paddle';
    END IF;

    INSERT INTO self_managed_plans (
        organization_id, tier, enclave_limit, source, expires_at,
        operator_identity, operator_reason, terminated_at, updated_at
    ) VALUES (
        current_setting('admin.organization_id')::uuid, 'enterprise_contract',
        v_change.requested_enclave_limit, 'manual', v_change.requested_expires_at,
        v_change.operator_identity, v_change.operator_reason, NULL, NOW()
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
    SET self_managed_plan_id = NULL,
        status = 'canceled',
        canceled_at = COALESCE(canceled_at, NOW()),
        cancel_at_period_end = false,
        updated_at = NOW()
    WHERE id = v_change.subscription_id
      AND self_managed_plan_id = v_plan.id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Paddle subscription control link changed during apply';
    END IF;

    UPDATE self_managed_plan_changes
    SET status = 'applied', applied_at = NOW(), updated_at = NOW()
    WHERE id = v_change.id;
END
$body$;
COMMIT;
