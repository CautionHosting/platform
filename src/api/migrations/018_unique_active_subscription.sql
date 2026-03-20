-- Prevent duplicate active subscriptions per organization.
-- Only one subscription with status 'active' or 'past_due' is allowed per org.
CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_one_active_per_org
    ON subscriptions (organization_id)
    WHERE status IN ('active', 'past_due');
