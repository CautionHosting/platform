ALTER TABLE usage_records
  ADD COLUMN IF NOT EXISTS application_id UUID REFERENCES compute_resources(id);

ALTER TABLE usage_records
  ADD COLUMN IF NOT EXISTS base_unit_cost_usd NUMERIC(20, 6);

ALTER TABLE usage_records
  ADD COLUMN IF NOT EXISTS margin_percent NUMERIC(10, 4);

ALTER TABLE usage_records
  ADD COLUMN IF NOT EXISTS unit_cost_usd NUMERIC(20, 6);

CREATE INDEX IF NOT EXISTS idx_usage_records_application_id
  ON usage_records(application_id);
