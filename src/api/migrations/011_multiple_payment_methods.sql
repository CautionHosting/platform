-- Multiple payment methods: add is_primary flag

ALTER TABLE payment_methods
  ADD COLUMN IF NOT EXISTS is_primary BOOLEAN NOT NULL DEFAULT false;

-- Migrate existing active methods to primary
UPDATE payment_methods SET is_primary = true WHERE is_active = true;
