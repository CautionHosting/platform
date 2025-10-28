// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    extract::{Request, State},
    http::{HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::db;
use crate::types::AppState;

pub async fn fido2_auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, Response> {
    if req.uri().path() == "/health" {
        return Ok(next.run(req).await);
    }

    let session_id = req
        .headers()
        .get("X-Session-ID")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            (StatusCode::UNAUTHORIZED, "Missing session ID").into_response()
        })?;

    let credential_id = db::validate_auth_session(&state.db, &session_id)
        .await
        .map_err(|e| {
            tracing::error!("Session validation error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Session validation failed").into_response()
        })?
        .ok_or_else(|| {
            (StatusCode::UNAUTHORIZED, "Invalid or expired session").into_response()
        })?;

    let user_id = db::get_user_id_by_credential(&state.db, &credential_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get user ID for credential: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to resolve user").into_response()
        })?;

    req.headers_mut().insert(
        "X-Authenticated-User-ID",
        HeaderValue::from_str(&user_id.to_string()).unwrap(),
    );

    tracing::debug!(
        "Authenticated request - session: {}, credential: {}, user_id: {}",
        session_id,
        hex::encode(&credential_id),
        user_id
    );

    Ok(next.run(req).await)
}
