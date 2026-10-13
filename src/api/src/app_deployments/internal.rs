// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Gateway-facing endpoints, mounted behind `internal_auth_middleware`.

use super::admission;
use crate::AppState;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use uuid::Uuid;

#[derive(serde::Deserialize)]
pub(crate) struct ReserveRequest {
    pub(crate) org_id: Uuid,
    pub(crate) user_id: Uuid,
}

pub(crate) async fn reserve_handler(
    State(state): State<Arc<AppState>>,
    Path(app_id): Path<Uuid>,
    Json(request): Json<ReserveRequest>,
) -> Response {
    match admission::reserve(&state.db, request.org_id, app_id, request.user_id).await {
        Ok(deployment_id) => {
            Json(serde_json::json!({ "deployment_id": deployment_id })).into_response()
        }
        Err(error) => {
            tracing::warn!(app_id = %app_id, error = %error, "deployment reservation rejected");
            let (status, message) = error.client_response();
            (status, Json(serde_json::json!({ "error": message }))).into_response()
        }
    }
}

pub(crate) async fn release_handler(
    State(state): State<Arc<AppState>>,
    Path(deployment_id): Path<Uuid>,
) -> StatusCode {
    match admission::release_reservation(&state.db, deployment_id).await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(error) => {
            tracing::error!(deployment_id = %deployment_id, error = %error, "failed to release reservation");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}
