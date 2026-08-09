// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct DestroyNextQuery {
    #[serde(default)]
    force: bool,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum DestroyNextResponse {
    Deleted { resource_id: Uuid },
    Empty,
    Error { error: String },
}

/// Internal e2e cleanup endpoint. This intentionally remains test-feature-only at routing time.
pub async fn destroy_next_app(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DestroyNextQuery>,
) -> Response {
    let resource: Option<(Uuid, Uuid, String, String, String)> = match sqlx::query_as(
        "SELECT id, organization_id, COALESCE(resource_name, 'unnamed'),
                provider_resource_id, COALESCE(region, 'us-west-2')
         FROM compute_resources WHERE destroyed_at IS NULL
         ORDER BY created_at LIMIT 1",
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(row) => row,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(DestroyNextResponse::Error {
                    error: e.to_string(),
                }),
            )
                .into_response();
        }
    };
    let Some((resource_id, org_id, resource_name, provider_resource_id, resource_region)) =
        resource
    else {
        return Json(DestroyNextResponse::Empty).into_response();
    };

    let (aws_credentials, asg_name) =
        credentials_for_resource(&state, org_id, resource_id, &resource_region, false).await;
    let terraform_result = crate::deployment::destroy_app_with_credentials(
        org_id,
        resource_id,
        resource_name,
        aws_credentials,
        asg_name,
    )
    .await;
    if let Err(e) = terraform_result {
        if !query.force {
            return (
                StatusCode::BAD_GATEWAY,
                Json(DestroyNextResponse::Error {
                    error: format!("Terraform destroy failed: {}", e),
                }),
            )
                .into_response();
        }
        tracing::warn!(resource_id = %resource_id, error = %e, "force-cleaning failed cloud destroy");
    }
    match finish_resource_termination(&state, org_id, resource_id, &provider_resource_id).await {
        Ok(()) => Json(DestroyNextResponse::Deleted { resource_id }).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(DestroyNextResponse::Error { error }),
        )
            .into_response(),
    }
}

/// Production internal endpoint used only by durable self-managed termination jobs.
pub async fn terminate_self_managed_resource(
    State(state): State<Arc<AppState>>,
    Path((job_id, resource_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let lease_token = headers
        .get("x-termination-lease-token")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "Termination lease token required".to_string(),
            )
        })?;
    let resource: Option<(
        Uuid,
        String,
        String,
        String,
        Option<chrono::DateTime<chrono::Utc>>,
    )> = sqlx::query_as(
        "SELECT p.organization_id, COALESCE(cr.resource_name, 'unnamed'), cr.provider_resource_id,
                    COALESCE(cr.region, 'us-west-2'), cr.destroyed_at
             FROM self_managed_termination_jobs j
             JOIN self_managed_plans p ON p.id = j.self_managed_plan_id
             JOIN compute_resources cr ON cr.id = j.resource_id
             WHERE j.id = $1 AND j.resource_id = $2
               AND j.status = 'processing' AND j.lease_token = $3
               AND j.lease_expires_at > NOW()
               AND p.source = 'paddle' AND p.enclave_limit = 0
               AND p.terminated_at IS NOT NULL
               AND cr.organization_id = p.organization_id
               AND EXISTS (
                   SELECT 1 FROM subscriptions s
                   WHERE s.id = j.subscription_id
                     AND s.billing_source = 'paddle' AND s.status = 'canceled'
               )
               AND EXISTS (
                   SELECT 1 FROM cloud_credentials cc
                   WHERE cc.resource_id = cr.id AND cc.managed_on_prem = true
               )",
    )
    .bind(job_id)
    .bind(resource_id)
    .bind(lease_token)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let Some((org_id, resource_name, provider_resource_id, region, destroyed_at)) = resource else {
        return Err((
            StatusCode::CONFLICT,
            "Termination job is not authorized for this resource".to_string(),
        ));
    };
    if destroyed_at.is_some() {
        return Ok(Json(
            serde_json::json!({ "terminated": true, "already_terminated": true }),
        ));
    }

    let (credentials, asg_name) =
        credentials_for_resource(&state, org_id, resource_id, &region, true).await;
    let credentials = credentials.ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Self-managed cloud credentials are unavailable".to_string(),
        )
    })?;
    crate::deployment::destroy_app_with_credentials(
        org_id,
        resource_id,
        resource_name,
        Some(credentials),
        asg_name,
    )
    .await
    .map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("Cloud destroy failed: {}", e),
        )
    })?;

    finish_resource_termination(&state, org_id, resource_id, &provider_resource_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(serde_json::json!({ "terminated": true })))
}

async fn credentials_for_resource(
    state: &AppState,
    org_id: Uuid,
    resource_id: Uuid,
    region: &str,
    require_self_managed: bool,
) -> (Option<crate::deployment::AwsCredentials>, Option<String>) {
    if let Some(encryptor) = state.encryptor.as_ref()
        && let Ok(Some(credential)) =
            crate::cloud_credentials::get_credential_by_resource(&state.db, org_id, resource_id)
                .await
        && credential.managed_on_prem
        && let Ok(Some(secrets)) = crate::cloud_credentials::get_credential_secrets(
            &state.db,
            encryptor,
            org_id,
            credential.id,
        )
        .await
    {
        let configured_region = credential.config["aws_region"]
            .as_str()
            .unwrap_or(region)
            .to_string();
        let credentials = crate::deployment::AwsCredentials {
            access_key_id: secrets["aws_access_key_id"]
                .as_str()
                .unwrap_or("")
                .to_string(),
            secret_access_key: secrets["aws_secret_access_key"]
                .as_str()
                .unwrap_or("")
                .to_string(),
            region: configured_region,
        };
        return (
            Some(credentials),
            credential.config["asg_name"]
                .as_str()
                .map(ToString::to_string),
        );
    }
    if require_self_managed {
        (None, None)
    } else {
        (
            Some(crate::fully_managed_capacity::platform_credentials_for_region(region)),
            None,
        )
    }
}

async fn finish_resource_termination(
    state: &AppState,
    org_id: Uuid,
    resource_id: Uuid,
    provider_resource_id: &str,
) -> Result<(), String> {
    sqlx::query(
        "UPDATE compute_resources
         SET destroyed_at = NOW(), state = $1, public_ip = NULL, region = NULL
         WHERE id = $2 AND organization_id = $3",
    )
    .bind(crate::types::ResourceState::Terminated)
    .bind(resource_id)
    .bind(org_id)
    .execute(&state.db)
    .await
    .map_err(|e| e.to_string())?;

    if let Err(error) = crate::metering::stop_tracked_resource(
        state.internal_service_secret.as_deref(),
        provider_resource_id,
    )
    .await
    {
        tracing::error!(resource_id = %resource_id, error = %error, "failed to stop metering after termination");
        let _ = sqlx::query(
            "UPDATE tracked_resources SET status = 'stopped', stopped_at = NOW()
             WHERE resource_id = $1 AND status = 'running'",
        )
        .bind(provider_resource_id)
        .execute(&state.db)
        .await;
    }
    Ok(())
}
