// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use dterror::{BoxError, CtxError, Location, ResultExt};
use uuid::Uuid;

/// Failure modes for [`upsert_tracked_resource`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum UpsertTrackedResourceError {
    #[error(
        "Failed to query cloud credentials for organization '{organization_id}' and application '{application_id}' [{location}]"
    )]
    QueryCloudCredentials {
        organization_id: Uuid,
        application_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Failed to upsert tracked resource '{resource_id}' [{location}]")]
    Upsert {
        #[context(borrow = str)]
        resource_id: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Upsert a tracked resource row for a compute resource that should accrue
/// real-time metering. If a stopped row is resumed, reset billing timestamps so
/// downtime is not charged.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip_all, err, fields(resource_id = %resource_id))]
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
) -> Result<(), UpsertTrackedResourceError> {
    use UpsertTrackedResourceErrorCtx as Ctx;

    // BYOC runners must not enter managed metering on deploy or unsuspend.
    // Inactive credentials do not transfer ownership to the platform.
    let is_byoc_runner: bool = sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1 FROM cloud_credentials
            WHERE organization_id = $1 AND resource_id = $2 AND managed_on_prem = true
        )",
    )
    .bind(organization_id)
    .bind(application_id)
    .fetch_one(&state.db)
    .await
    .with_context(Ctx::query_cloud_credentials(
        organization_id,
        application_id,
    ))?;
    if is_byoc_runner {
        return Ok(());
    }

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
    .with_context(Ctx::upsert(resource_id))?;

    Ok(())
}

/// Failure modes for [`stop_tracked_resource`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum StopTrackedResourceError {
    #[error("INTERNAL_SERVICE_SECRET must be set to stop tracked resources safely [{location}]")]
    MissingSecret { location: Location },

    #[error("Failed to call metering untrack endpoint [{location}]")]
    SendRequest {
        #[context(borrow = str)]
        resource_id: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Metering untrack returned {status}: {body} [{location}]")]
    UntrackFailed {
        status: reqwest::StatusCode,
        body: String,
        location: Location,
    },
}

/// Ask the metering service to collect any final usage and stop tracking a
/// resource. Falls back to the configured internal service secret.
#[tracing::instrument(skip_all, err, fields(resource_id = %resource_id))]
pub async fn stop_tracked_resource(
    internal_service_secret: Option<&str>,
    resource_id: &str,
) -> Result<(), StopTrackedResourceError> {
    use StopTrackedResourceErrorCtx as Ctx;

    let metering_service_url = std::env::var("METERING_SERVICE_URL")
        .unwrap_or_else(|_| "http://metering:8083".to_string());
    let internal_secret =
        internal_service_secret.ok_or_else(|| StopTrackedResourceError::MissingSecret {
            location: std::panic::Location::caller(),
        })?;

    let response = reqwest::Client::new()
        .post(format!(
            "{}/api/resources/{}/untrack",
            metering_service_url, resource_id
        ))
        .header("x-internal-service-secret", internal_secret)
        .send()
        .await
        .with_context(Ctx::send_request(resource_id))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(StopTrackedResourceError::UntrackFailed {
            status,
            body,
            location: std::panic::Location::caller(),
        });
    }

    Ok(())
}
