// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::db;
use crate::handlers::AppError;
use crate::types::AppState;
use axum::{extract::State, response::{IntoResponse, Response}, Json};
use time::Duration;

#[tracing::instrument(skip_all, err(Debug))]
pub async fn e2e_login_handler(State(state): State<AppState>) -> Result<Response, AppError> {
    tracing::warn!("E2E login: creating test user (this endpoint only exists in e2e builds)");

    let (user_id, credential_id) = db::create_e2e_user(&state.db).await?;

    let session_id = db::generate_session_id();
    let expires_at = time::OffsetDateTime::now_utc() + Duration::hours(state.session_timeout_hours);
    db::create_auth_session(&state.db, &session_id, &credential_id, expires_at).await?;

    let body = serde_json::json!({
        "session_id": session_id,
        "user_id": user_id.to_string(),
        "expires_at": expires_at.to_string(),
    });

    Ok(Json(body).into_response())
}
