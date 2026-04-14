// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result, bail};
use uuid::Uuid;

/// Upsert a tracked resource row for a compute resource that should accrue
/// real-time metering. If a stopped row is resumed, reset billing timestamps so
/// downtime is not charged.
pub async fn upsert_tracked_resource(
    state: &crate::AppState,
    resource_id: &str,
    organization_id: Uuid,
    user_id: Option<Uuid>,
    application_id: Uuid,
    provider: &str,
    instance_type: Option<&str>,
    region: Option<&str>,
    metadata: &serde_json::Value,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO tracked_resources (
            resource_id, organization_id, user_id, application_id, provider, instance_type, region,
            metadata, status, started_at, last_billed_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'running', NOW(), NOW())
        ON CONFLICT (resource_id) DO UPDATE SET
            organization_id = EXCLUDED.organization_id,
            user_id = COALESCE(EXCLUDED.user_id, tracked_resources.user_id),
            application_id = EXCLUDED.application_id,
            provider = EXCLUDED.provider,
            instance_type = COALESCE(EXCLUDED.instance_type, tracked_resources.instance_type),
            region = COALESCE(EXCLUDED.region, tracked_resources.region),
            metadata = EXCLUDED.metadata,
            status = 'running',
            started_at = CASE
                WHEN tracked_resources.status = 'running' THEN tracked_resources.started_at
                ELSE NOW()
            END,
            stopped_at = NULL,
            last_billed_at = CASE
                WHEN tracked_resources.status = 'running' THEN tracked_resources.last_billed_at
                ELSE NOW()
            END
        "#,
    )
    .bind(resource_id)
    .bind(organization_id)
    .bind(user_id)
    .bind(application_id)
    .bind(provider)
    .bind(instance_type)
    .bind(region)
    .bind(metadata)
    .execute(&state.db)
    .await
    .context("Failed to upsert tracked resource")?;

    Ok(())
}

/// Ask the metering service to collect any final usage and stop tracking a
/// resource. Falls back to the configured internal service secret.
pub async fn stop_tracked_resource(
    internal_service_secret: Option<&str>,
    resource_id: &str,
) -> Result<()> {
    let metering_service_url =
        std::env::var("METERING_SERVICE_URL").unwrap_or_else(|_| "http://metering:8083".to_string());
    let internal_secret = internal_service_secret
        .context("INTERNAL_SERVICE_SECRET must be set to stop tracked resources safely")?;

    let response = reqwest::Client::new()
        .post(format!(
            "{}/api/resources/{}/untrack",
            metering_service_url, resource_id
        ))
        .header("x-internal-service-secret", internal_secret)
        .send()
        .await
        .context("Failed to call metering untrack endpoint")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        bail!("Metering untrack returned {}: {}", status, body);
    }

    Ok(())
}
