-- Additional indexes for billing/metering query performance

-- eif_builds: looked up by org and filtered by status
CREATE INDEX IF NOT EXISTS idx_eif_builds_org ON eif_builds(organization_id);
CREATE INDEX IF NOT EXISTS idx_eif_builds_status ON eif_builds(status);
CREATE INDEX IF NOT EXISTS idx_eif_builds_cache ON eif_builds(cache_key) WHERE status = 'completed';

-- subscriptions: looked up by user_id
CREATE INDEX IF NOT EXISTS idx_subscriptions_user ON subscriptions(user_id);

-- usage_records: date range queries for billing periods
CREATE INDEX IF NOT EXISTS idx_usage_records_user_recorded ON usage_records(user_id, recorded_at);

-- invoices: date range queries
CREATE INDEX IF NOT EXISTS idx_invoices_created ON invoices(created_at);

-- compute_resources: org + state for resource limit checks
CREATE INDEX IF NOT EXISTS idx_resources_org_active ON compute_resources(organization_id)
    WHERE state NOT IN ('terminated', 'failed') AND destroyed_at IS NULL;
