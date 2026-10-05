// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Duration, Utc};
use dterror::{BoxError, CtxError, Location, ResultExt};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::sync::Arc;
use uuid::Uuid;

use crate::validated_types;
use crate::validated_types::UpdateUserRequest;
use crate::{AppState, AuthContext};

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct UpdateUserResponse {
    #[serde(flatten)]
    pub user: User,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_email_sent: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct EmailServiceResponse {
    success: bool,
}

/// Failure modes for [`get_current_user`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum GetCurrentUserError {
    #[error("user {user_id} not found [{location}]")]
    NotFound {
        user_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for GetCurrentUserError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            GetCurrentUserError::NotFound { .. } => (StatusCode::NOT_FOUND, "not found"),
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(user_id = %auth.user_id))]
pub async fn get_current_user(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<User>, GetCurrentUserError> {
    use GetCurrentUserErrorCtx as Ctx;

    let user = sqlx::query_as::<_, User>(
        "SELECT id,
                username,
                email,
                email_verified_at IS NOT NULL AS email_verified,
                is_active,
                created_at,
                updated_at
         FROM users WHERE id = $1",
    )
    .bind(auth.user_id)
    .fetch_one(&state.db)
    .await
    .with_context(Ctx::not_found(auth.user_id))?;

    Ok(Json(user))
}

/// Failure modes for [`update_current_user`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum UpdateCurrentUserError {
    #[error("at least one field is required [{location}]")]
    InvalidRequest { location: Location },

    #[error("could not read verification email throttle state [{location}]")]
    ThrottleQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("verification email recently sent [{location}]")]
    Throttled { location: Location },

    #[error("username is required [{location}]")]
    MissingUsername { location: Location },

    #[error("could not update user [{location}]")]
    Update {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for UpdateCurrentUserError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            UpdateCurrentUserError::InvalidRequest { .. } => {
                (StatusCode::BAD_REQUEST, "bad request")
            }
            UpdateCurrentUserError::ThrottleQuery { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            UpdateCurrentUserError::Throttled { .. } => {
                (StatusCode::TOO_MANY_REQUESTS, "too many requests")
            }
            UpdateCurrentUserError::MissingUsername { .. } => {
                (StatusCode::BAD_REQUEST, "bad request")
            }
            UpdateCurrentUserError::Update { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(user_id = %auth.user_id))]
pub async fn update_current_user(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    validated_types::Validated(payload): validated_types::Validated<UpdateUserRequest>,
) -> Result<Json<UpdateUserResponse>, UpdateCurrentUserError> {
    use UpdateCurrentUserErrorCtx as Ctx;

    if payload.username.is_none() && payload.email.is_none() {
        return Err(UpdateCurrentUserError::InvalidRequest {
            location: std::panic::Location::caller(),
        });
    }

    let username = payload.username.as_deref();
    let new_email = payload.email.as_deref().and_then(|email| {
        let trimmed = email.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    });

    if new_email.is_some() {
        let last_sent_at: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT email_verification_sent_at
             FROM users
             WHERE id = $1",
        )
        .bind(auth.user_id)
        .fetch_optional(&state.db)
        .await
        .with_context(Ctx::throttle_query())?
        .flatten();

        if let crate::onboarding::EmailVerificationThrottle::Throttled { retry_after: _ } =
            crate::onboarding::EmailVerificationThrottle::new(last_sent_at, Utc::now())
        {
            return Err(UpdateCurrentUserError::Throttled {
                location: std::panic::Location::caller(),
            });
        }
    }

    let mut verification_token: Option<String> = None;

    let user = match payload.email.as_deref() {
        None => {
            let Some(username) = username else {
                return Err(UpdateCurrentUserError::MissingUsername {
                    location: std::panic::Location::caller(),
                });
            };
            sqlx::query_as::<_, User>(
                "UPDATE users
                 SET username = $1
                 WHERE id = $2
                 RETURNING id,
                           username,
                           email,
                           email_verified_at IS NOT NULL AS email_verified,
                           is_active,
                           created_at,
                           updated_at",
            )
            .bind(username)
            .bind(auth.user_id)
            .fetch_one(&state.db)
            .await
        }
        Some(email_update) if email_update.trim().is_empty() => {
            sqlx::query_as::<_, User>(
                "UPDATE users
             SET username = COALESCE($1, username),
                 email = NULL,
                 email_verified_at = NULL,
                 email_verification_token = NULL,
                 email_verification_token_expires_at = NULL
             WHERE id = $2
             RETURNING id,
                       username,
                       email,
                       email_verified_at IS NOT NULL AS email_verified,
                       is_active,
                       created_at,
                       updated_at",
            )
            .bind(username)
            .bind(auth.user_id)
            .fetch_one(&state.db)
            .await
        }
        Some(email_update) => {
            let email = email_update.trim();
            let token = Uuid::new_v4().to_string();
            let expires_at = Utc::now() + Duration::hours(24);
            let user = sqlx::query_as::<_, User>(
                "UPDATE users
                 SET username = COALESCE($1, username),
                     email = $2,
                     email_verified_at = NULL,
                     email_verification_token = $3,
                     email_verification_token_expires_at = $4,
                     email_verification_sent_at = NOW()
                 WHERE id = $5
                 RETURNING id,
                           username,
                           email,
                           email_verified_at IS NOT NULL AS email_verified,
                           is_active,
                           created_at,
                           updated_at",
            )
            .bind(username)
            .bind(email)
            .bind(&token)
            .bind(expires_at)
            .bind(auth.user_id)
            .fetch_one(&state.db)
            .await;
            verification_token = Some(token);
            user
        }
    }
    .with_context(Ctx::update())?;

    let mut verification_email_sent = None;

    // Send verification email for the new address
    if let (Some(email), Some(token)) = (&new_email, &verification_token) {
        let email_service_url =
            std::env::var("EMAIL_SERVICE_URL").unwrap_or_else(|_| "http://email:8082".to_string());

        let client = reqwest::Client::new();
        let email_request = serde_json::json!({
            "email": email,
            "token": token,
            "user_id": auth.user_id,
        });

        match client
            .post(format!("{}/send-verification", email_service_url))
            .json(&email_request)
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status();
                if !status.is_success() {
                    tracing::error!(
                        "Email service returned error while sending verification email: {}",
                        status
                    );
                    verification_email_sent = Some(false);
                } else {
                    match response.json::<EmailServiceResponse>().await {
                        Ok(email_response) if email_response.success => {
                            verification_email_sent = Some(true);
                        }
                        Ok(_) => {
                            tracing::error!(
                                "Email service reported unsuccessful verification email delivery"
                            );
                            verification_email_sent = Some(false);
                        }
                        Err(e) => {
                            tracing::error!(
                                "Failed to parse email service verification response: {:?}",
                                e
                            );
                            verification_email_sent = Some(false);
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to send verification email on email change: {:?}", e);
                verification_email_sent = Some(false);
            }
        }
    }

    Ok(Json(UpdateUserResponse {
        user,
        verification_email_sent,
    }))
}

/// Failure modes for [`delete_current_user`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum DeleteCurrentUserError {
    #[error("could not deactivate user [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for DeleteCurrentUserError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            DeleteCurrentUserError::Query { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(user_id = %auth.user_id))]
pub async fn delete_current_user(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<StatusCode, DeleteCurrentUserError> {
    use DeleteCurrentUserErrorCtx as Ctx;

    sqlx::query("UPDATE users SET is_active = false WHERE id = $1")
        .bind(auth.user_id)
        .execute(&state.db)
        .await
        .with_context(Ctx::query())?;

    Ok(StatusCode::NO_CONTENT)
}
