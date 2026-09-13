// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct WebauthnResetRequest {
    pub user_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct WebauthnResetResponse {
    pub status: &'static str,
    pub message: String,
}

impl IntoResponse for WebauthnResetResponse {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(&self)).into_response()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WebauthnResetError {
    #[error("user not found")]
    UserNotFound,
    #[error("user has no email address configured")]
    UserHasNoEmail,
    #[error("failed to query database")]
    Database(#[source] sqlx::Error),
    #[error("failed to send email notification")]
    EmailFailed,
}

impl IntoResponse for WebauthnResetError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            WebauthnResetError::UserNotFound => (StatusCode::NOT_FOUND, "user not found"),
            WebauthnResetError::UserHasNoEmail => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "user has no email address configured",
            ),
            WebauthnResetError::Database(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            WebauthnResetError::EmailFailed => {
                (StatusCode::BAD_GATEWAY, "email service unavailable")
            }
        };
        (status, body).into_response()
    }
}

/// Token TTL in seconds (24 hours).
const TOKEN_TTL_SECONDS: i64 = 86_400;

#[tracing::instrument(skip_all, fields(user_id = %req.user_id))]
pub async fn reset_webauthn_credentials(
    State(state): State<Arc<AppState>>,
    Json(req): Json<WebauthnResetRequest>,
) -> Result<Response, WebauthnResetError> {
    // Generate a 32-byte cryptographic random token (CPU-bound, fast).
    let mut token_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token_bytes);

    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(TOKEN_TTL_SECONDS);

    // All DB operations are atomic: user lookup, token invalidation/insertion,
    // and credential deletion share a single transaction. If any step fails the
    // entire operation rolls back — no partial state is visible to other readers.
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!("Failed to begin reset token transaction: {:?}", e);
        WebauthnResetError::Database(e)
    })?;

    // Verify user exists and has an email (inside tx).
    let user: Option<(Uuid, Option<String>)> =
        sqlx::query_as("SELECT id, email FROM users WHERE id = $1")
            .bind(req.user_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("Database error looking up user for reset: {:?}", e);
                WebauthnResetError::Database(e)
            })?;

    let (user_id, user_email) = match user {
        None => return Err(WebauthnResetError::UserNotFound),
        Some((_, None)) => return Err(WebauthnResetError::UserHasNoEmail),
        Some((id, Some(email))) => (id, email),
    };

    // Invalidate any prior unused tokens for this user by marking them used.
    sqlx::query(
        "UPDATE webauthn_reset_tokens SET used_at = NOW() WHERE user_id = $1 AND used_at IS NULL",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("Failed to invalidate prior reset tokens: {:?}", e);
        WebauthnResetError::Database(e)
    })?;

    // Insert the new token (hashed).
    let token_hash = hex::encode(Sha256::digest(token_bytes));
    sqlx::query(
        "INSERT INTO webauthn_reset_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
    )
    .bind(&token_hash)
    .bind(user_id)
    .bind(expires_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("Failed to insert reset token: {:?}", e);
        WebauthnResetError::Database(e)
    })?;

    // Delete existing credentials atomically with the token insertion.
    sqlx::query("DELETE FROM fido2_credentials WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!(
                user_id = %user_id,
                error = ?e,
                "Failed to delete credentials during reset"
            );
            WebauthnResetError::Database(e)
        })?;

    tx.commit().await.map_err(|e| {
        tracing::error!("Failed to commit reset token transaction: {:?}", e);
        WebauthnResetError::Database(e)
    })?;

    // Send the reset email.
    let token_hex = hex::encode(&token_bytes);
    let frontend_url =
        std::env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:8000".to_string());
    let reset_url = format!("{}/reset#{}", frontend_url.trim_end_matches('/'), token_hex);

    let email_service_url =
        std::env::var("EMAIL_SERVICE_URL").unwrap_or_else(|_| "http://email:8082".to_string());

    let email_request = serde_json::json!({
        "to": user_email,
        "template": "webauthn_reset",
        "data": {
            "reset_url": reset_url,
            "expires_at": expires_at.to_rfc3339(),
        }
    });

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(client) => client,
        Err(e) => {
            tracing::error!(
                "Failed to build HTTP client for webauthn reset email: {:?}",
                e
            );
            return Err(WebauthnResetError::EmailFailed);
        }
    };

    let email_sent = match client
        .post(format!("{}/send", email_service_url))
        .json(&email_request)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            let body: serde_json::Value = response.json().await.unwrap_or_default();
            body.get("success")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        }
        Ok(response) => {
            tracing::error!(
                "Email service returned {} while sending webauthn reset email",
                response.status()
            );
            false
        }
        Err(e) => {
            tracing::error!("Failed to call email service for webauthn reset: {:?}", e);
            false
        }
    };

    if !email_sent {
        return Err(WebauthnResetError::EmailFailed);
    }

    Ok(WebauthnResetResponse {
        status: "ok",
        message: format!("Reset email sent to user {}", user_id),
    }
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_ttl_is_24_hours() {
        assert_eq!(TOKEN_TTL_SECONDS, 86_400);
    }

    #[tokio::test]
    async fn test_user_not_found_returns_404() {
        let err = WebauthnResetError::UserNotFound;
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_user_has_no_email_returns_422() {
        let err = WebauthnResetError::UserHasNoEmail;
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_database_error_returns_500() {
        let err = WebauthnResetError::Database(sqlx::Error::RowNotFound);
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_email_failed_returns_502() {
        let err = WebauthnResetError::EmailFailed;
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn test_request_deserialization() {
        let json = r#"{"user_id": "550e8400-e29b-41d4-a716-446655440000"}"#;
        let req: WebauthnResetRequest = serde_json::from_str(json).unwrap();
        assert_eq!(
            req.user_id.to_string(),
            "550e8400-e29b-41d4-a716-446655440000"
        );
    }
}
