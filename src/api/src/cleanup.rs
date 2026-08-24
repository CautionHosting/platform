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
    pub force: bool,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status")]
pub enum DestroyNextResponse {
    #[serde(rename = "deleted")]
    Deleted { resource_id: Uuid },
    #[serde(rename = "done")]
    Done,
    #[serde(rename = "error")]
    Error { error: String },
}

impl IntoResponse for DestroyNextResponse {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            DestroyNextResponse::Deleted { .. } => (StatusCode::OK, Json(&self)),
            DestroyNextResponse::Done => (StatusCode::OK, Json(&self)),
            DestroyNextResponse::Error { .. } => (StatusCode::INTERNAL_SERVER_ERROR, Json(&self)),
        };
        (status, body).into_response()
    }
}

#[cfg(feature = "e2e-testing-unsafe")]
pub async fn destroy_next_app(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DestroyNextQuery>,
) -> Response {
    tracing::info!("destroy_next_app called (force={})", query.force);

    let resource = match sqlx::query_scalar::<_, Uuid>(
        "SELECT cr.id
         FROM compute_resources cr
         WHERE cr.destroyed_at IS NULL
         ORDER BY cr.created_at ASC
         LIMIT 1",
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(opt) => opt,
        Err(e) => {
            tracing::error!("Database query failed in destroy_next_app: {:?}", e);
            return DestroyNextResponse::Error {
                error: "Database query failed".to_string(),
            }
            .into_response();
        }
    };

    let Some(resource_id) = resource else {
        tracing::info!("destroy_next_app: no resources to destroy");
        return DestroyNextResponse::Done.into_response();
    };

    if let Err(error) =
        crate::resources::destroy_resource_by_id(&state, resource_id, query.force).await
    {
        tracing::error!(resource_id = %resource_id, error = %error, "destroy_next_app failed");
        return DestroyNextResponse::Error {
            error: error.to_string(),
        }
        .into_response();
    }

    tracing::info!("Resource {} terminated", resource_id);

    DestroyNextResponse::Deleted { resource_id }.into_response()
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

    let organization_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT organization_id FROM self_managed_termination_jobs
         WHERE id = $1 AND resource_id = $2",
    )
    .bind(job_id)
    .bind(resource_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let organization_id = organization_id.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            "Termination job was not found".to_string(),
        )
    })?;

    let mut authorization = state
        .db
        .begin()
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(organization_id.to_string())
        .execute(&mut *authorization)
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let destroyed_at: Option<Option<chrono::DateTime<chrono::Utc>>> = sqlx::query_scalar(
        "SELECT cr.destroyed_at
         FROM self_managed_termination_jobs j
         JOIN self_managed_plans p
           ON p.id = j.self_managed_plan_id AND p.organization_id = j.organization_id
         JOIN subscriptions s
           ON s.id = j.subscription_id AND s.organization_id = j.organization_id
         JOIN compute_resources cr
           ON cr.id = j.resource_id AND cr.organization_id = j.organization_id
         WHERE j.id = $1 AND j.resource_id = $2 AND j.organization_id = $3
           AND j.status = 'processing' AND j.lease_token = $4
           AND j.lease_expires_at > NOW()
           AND p.source = 'paddle' AND p.enclave_limit = 0
           AND p.terminated_at IS NOT NULL
           AND s.billing_source = 'paddle' AND s.status = 'canceled'
           AND EXISTS (
               SELECT 1 FROM cloud_credentials cc
               WHERE cc.resource_id = cr.id AND cc.organization_id = j.organization_id
                 AND cc.managed_on_prem = true
           )
         FOR UPDATE OF j, p, s, cr",
    )
    .bind(job_id)
    .bind(resource_id)
    .bind(organization_id)
    .bind(lease_token)
    .fetch_optional(&mut *authorization)
    .await
    .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let Some(destroyed_at) = destroyed_at else {
        return Err((
            StatusCode::CONFLICT,
            "Termination job is not authorized for this resource".to_string(),
        ));
    };
    if destroyed_at.is_none() {
        sqlx::query(
            "UPDATE compute_resources
             SET state = 'terminating', deploy_attempt_id = NULL, updated_at = NOW()
             WHERE id = $1 AND organization_id = $2 AND destroyed_at IS NULL
               AND state <> 'terminated'",
        )
        .bind(resource_id)
        .bind(organization_id)
        .execute(&mut *authorization)
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    }
    authorization
        .commit()
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    if destroyed_at.is_some() {
        return Ok(Json(
            serde_json::json!({ "terminated": true, "already_terminated": true }),
        ));
    }

    #[cfg(feature = "e2e-testing-unsafe")]
    let force = std::env::var("E2E_SELF_MANAGED_TERMINATION_FORCE")
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    #[cfg(not(feature = "e2e-testing-unsafe"))]
    let force = false;

    crate::resources::destroy_resource_by_id(&state, resource_id, force)
        .await
        .map_err(|error| {
            (
                StatusCode::BAD_GATEWAY,
                format!("Cloud destroy failed: {error}"),
            )
        })?;
    Ok(Json(serde_json::json!({ "terminated": true })))
}
