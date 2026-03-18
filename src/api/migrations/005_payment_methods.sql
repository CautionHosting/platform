-- Payment methods table for storing vaulted payment tokens (PayPal, etc.)

CREATE TABLE IF NOT EXISTS payment_methods (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    payment_type VARCHAR(50) NOT NULL,  -- 'paypal', 'card'
    provider_token TEXT NOT NULL,  -- PayPal payment token or similar
    last4 VARCHAR(4),  -- Last 4 digits for card
    email VARCHAR(255),  -- PayPal email
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_payment_methods_org ON payment_methods(organization_id);
CREATE INDEX IF NOT EXISTS idx_payment_methods_active ON payment_methods(organization_id, is_active) WHERE is_active = true;

CREATE TRIGGER payment_methods_updated_at BEFORE UPDATE ON payment_methods
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Add organization_id to invoices table for consistency
ALTER TABLE invoices ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id);

-- Create index for org-based invoice queries
CREATE INDEX IF NOT EXISTS idx_invoices_org ON invoices(organization_id) WHERE organization_id IS NOT NULL;
