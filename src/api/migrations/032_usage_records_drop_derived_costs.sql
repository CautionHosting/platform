ALTER TABLE usage_records
  DROP COLUMN IF EXISTS unit_cost_usd;

ALTER TABLE usage_records
  DROP COLUMN IF EXISTS cost_usd;
