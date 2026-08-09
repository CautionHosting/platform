\set ON_ERROR_STOP on
BEGIN;
SELECT pg_advisory_xact_lock(hashtextextended(:'organization_id', 0));
SELECT set_config('admin.organization_id', :'organization_id', true);
SELECT set_config('admin.change_id', :'change_id', true);

DO $body$
DECLARE
    v_change self_managed_plan_changes%ROWTYPE;
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
    SET self_managed_plan_id = NULL, updated_at = NOW()
    WHERE id = v_change.subscription_id;

    UPDATE self_managed_plan_changes
    SET status = 'applied', applied_at = NOW(), updated_at = NOW()
    WHERE id = v_change.id;
END
$body$;
COMMIT;
