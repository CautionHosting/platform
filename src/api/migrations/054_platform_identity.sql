-- A platform is the installation backed by this database, not an API process.
-- Replaying migrations or restoring this database must preserve its identity.
CREATE TABLE IF NOT EXISTS platform_identity (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    id UUID NOT NULL DEFAULT gen_random_uuid()
        CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid)
);

INSERT INTO platform_identity (singleton) VALUES (TRUE)
ON CONFLICT (singleton) DO NOTHING;
