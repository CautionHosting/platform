CREATE OR REPLACE VIEW usage_ledger_balances AS
SELECT
    organization_id,
    SUM(ROUND(quantity * base_unit_cost_usd * (1 + margin_percent / 100) * 100))::bigint AS debit_cents
FROM usage_ledger
GROUP BY organization_id;

CREATE OR REPLACE VIEW subscription_ledger_balances AS
SELECT
    organization_id,
    SUM(ROUND(
        EXTRACT(EPOCH FROM COALESCE(billing_period_end, NOW()) - billing_period_start)
        / 3600
        * cost_hourly
        * 100
    )) AS debit_cents
FROM subscription_ledger
GROUP BY organization_id;

CREATE OR REPLACE VIEW debit_ledger_balances AS
SELECT DISTINCT
    organization_id,
    SUM(COALESCE(u.debit_cents, 0) + COALESCE(s.debit_cents, 0))
FROM usage_ledger_balances u
LEFT JOIN subscription_ledger_balances s USING (organization_id)
GROUP BY organization_id;
