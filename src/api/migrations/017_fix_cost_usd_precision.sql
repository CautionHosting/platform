-- Fix DOUBLE PRECISION for money columns — floating point causes rounding errors
-- NUMERIC(20, 4) gives exact decimal arithmetic for financial calculations

ALTER TABLE usage_records
  ALTER COLUMN cost_usd TYPE NUMERIC(20, 4),
  ALTER COLUMN quantity TYPE NUMERIC(20, 6);
