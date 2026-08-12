use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
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
