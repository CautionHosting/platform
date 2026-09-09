// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::db;
use crate::types::AppState;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use dterror::{BoxError, CtxError, Location, ResultExt};
use time::Duration;

/// Error type for the e2e login handler. Single-variant enum (source + location
/// only, no context fields) because an error carrying only boxed source +
/// location must be an enum per the dterror convention.
#[derive(Debug, thiserror::Error, CtxError)]
pub enum E2eLoginError {
    #[error("database query failed [{location:?}]")]
    DatabaseQuery {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

impl IntoResponse for E2eLoginError {
    fn into_response(self) -> Response {
        tracing::error!(?self, "E2E login error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "An internal error occurred",
        )
            .into_response()
    }
}

#[tracing::instrument(skip_all, err(Debug))]
pub async fn e2e_login_handler(State(state): State<AppState>) -> Result<Response, E2eLoginError> {
    use E2eLoginErrorCtx as Ctx;

    tracing::warn!("E2E login: creating test user (this endpoint only exists in e2e builds)");

    let (user_id, credential_id) = db::create_e2e_user(&state.db)
        .await
        .with_context(Ctx::database_query())?;

    let session_id = db::generate_session_id();
    let expires_at = time::OffsetDateTime::now_utc() + Duration::hours(state.session_timeout_hours);
    db::create_auth_session(&state.db, &session_id, &credential_id, expires_at)
        .await
        .with_context(Ctx::database_query())?;

    let body = serde_json::json!({
        "session_id": session_id,
        "user_id": user_id.to_string(),
        "expires_at": expires_at.to_string(),
    });

    Ok(Json(body).into_response())
}
