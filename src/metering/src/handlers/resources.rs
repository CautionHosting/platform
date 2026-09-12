// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use dterror::{BoxError, CtxError, Location, ResultExt as _};
use std::sync::Arc;

use crate::types::*;
use crate::AppState;

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum TrackResourceError {
    #[error("could not track resource [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for TrackResourceError {
    fn into_response(self) -> Response {
        tracing::error!(?self, "track resource error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal error"})),
        )
            .into_response()
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum UntrackResourceError {
    #[error("could not untrack resource [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for UntrackResourceError {
    fn into_response(self) -> Response {
        tracing::error!(?self, "untrack resource error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal error"})),
        )
            .into_response()
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ListTrackedResourcesError {
    #[error("could not list tracked resources [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for ListTrackedResourcesError {
    fn into_response(self) -> Response {
        tracing::error!(?self, "list tracked resources error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal error"})),
        )
            .into_response()
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct TrackResourceRequest {
    resource_id: String,
    organization_id: uuid::Uuid,
    #[serde(default)]
    user_id: Option<uuid::Uuid>,
    #[serde(default)]
    application_id: Option<uuid::Uuid>,
    provider: Provider,
    instance_type: Option<String>,
    region: Option<String>,
    metadata: Option<serde_json::Value>,
}

#[tracing::instrument(skip_all, err, fields(resource_id = %req.resource_id))]
pub(crate) async fn track_resource(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TrackResourceRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), TrackResourceError> {
    use TrackResourceErrorCtx as Ctx;

    let metadata = req.metadata.unwrap_or(serde_json::json!({}));

    sqlx::query(
        r#"
        INSERT INTO tracked_resources (resource_id, organization_id, user_id, application_id, provider, instance_type, region, metadata, status, started_at, last_billed_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'running', NOW(), NOW())
        ON CONFLICT (resource_id) DO UPDATE SET
            organization_id = EXCLUDED.organization_id,
            user_id = COALESCE(EXCLUDED.user_id, tracked_resources.user_id),
            application_id = COALESCE(EXCLUDED.application_id, tracked_resources.application_id),
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
    .bind(&req.resource_id)
    .bind(req.organization_id)
    .bind(req.user_id)
    .bind(req.application_id)
    .bind(req.provider.as_str())
    .bind(&req.instance_type)
    .bind(&req.region)
    .bind(&metadata)
    .execute(&state.pool)
    .await
    .with_context(Ctx::database())?;

    tracing::info!("Now tracking resource: {}", req.resource_id);
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({"status": "tracking"})),
    ))
}

#[tracing::instrument(skip_all, err, fields(resource_id = %resource_id))]
pub(crate) async fn untrack_resource(
    State(state): State<Arc<AppState>>,
    Path(resource_id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), UntrackResourceError> {
    use UntrackResourceErrorCtx as Ctx;

    if let Err(e) =
        super::collection::collect_resource_usage(&state, &resource_id, std::time::Duration::ZERO)
            .await
    {
        tracing::warn!("Failed to collect final usage for {}: {}", resource_id, e);
    }

    sqlx::query(
        r#"
        UPDATE tracked_resources
        SET status = 'stopped', stopped_at = NOW()
        WHERE resource_id = $1
        "#,
    )
    .bind(&resource_id)
    .execute(&state.pool)
    .await
    .with_context(Ctx::database())?;

    tracing::info!("Stopped tracking resource: {}", resource_id);
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({"status": "stopped"})),
    ))
}

#[tracing::instrument(skip_all, err)]
pub(crate) async fn list_tracked_resources(
    State(state): State<Arc<AppState>>,
) -> Result<(StatusCode, Json<serde_json::Value>), ListTrackedResourcesError> {
    use ListTrackedResourcesErrorCtx as Ctx;

    let resources = sqlx::query_as::<_, TrackedResource>(
        r#"
        SELECT resource_id, organization_id, user_id, application_id, provider, instance_type, region, metadata, status, started_at, stopped_at, last_billed_at
        FROM tracked_resources
        WHERE status = 'running'
        ORDER BY started_at DESC
        "#,
    )
    .fetch_all(&state.pool)
    .await
    .with_context(Ctx::database())?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({"resources": resources})),
    ))
}
