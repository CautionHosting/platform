-- Persist the AWS account scope selected when each builder is launched.
-- NULL scope is reserved for rows created before this migration.
ALTER TABLE eif_builds
    ADD COLUMN IF NOT EXISTS builder_credential_id UUID,
    ADD COLUMN IF NOT EXISTS builder_uses_customer_credentials BOOLEAN,
    ADD COLUMN IF NOT EXISTS builder_region VARCHAR(64);

DO
$$BEGIN
    ALTER TABLE eif_builds
        ADD CONSTRAINT chk_eif_builds_builder_credential
        CHECK (
            builder_uses_customer_credentials IS DISTINCT FROM true
            OR builder_credential_id IS NOT NULL
        );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END;$$;
