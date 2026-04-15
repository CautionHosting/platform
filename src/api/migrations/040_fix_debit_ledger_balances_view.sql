CREATE OR REPLACE VIEW debit_ledger_balances AS
WITH all_organizations AS (
    SELECT organization_id FROM usage_ledger_balances
    UNION
    SELECT organization_id FROM subscription_ledger_balances
)
SELECT
    org.organization_id,
    (COALESCE(u.debit_cents, 0) + COALESCE(s.debit_cents, 0))::bigint AS debit_cents
FROM all_organizations org
LEFT JOIN usage_ledger_balances u USING (organization_id)
LEFT JOIN subscription_ledger_balances s USING (organization_id);
