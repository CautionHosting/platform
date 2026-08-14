-- Dunning: track payment failure and escalation stage per organization
-- All statements use IF NOT EXISTS - safe to run multiple times

ALTER TABLE organizations ADD COLUMN IF NOT EXISTS payment_failed_at TIMESTAMPTZ;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS dunning_stage TEXT NOT NULL DEFAULT 'none';
-- dunning_stage values: 'none', 'warning_sent', 'reminder_sent', 'suspended'
