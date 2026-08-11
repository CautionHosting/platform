-- Multiple payment methods: add is_primary flag

ALTER TABLE payment_methods
  ADD COLUMN IF NOT EXISTS is_primary BOOLEAN NOT NULL DEFAULT false;
