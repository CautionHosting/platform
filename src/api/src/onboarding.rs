// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    Json,
    extract::{Extension, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use crate::validation::validate_email;
use crate::{AppState, AuthContext};

pub(crate) const EMAIL_VERIFICATION_RESEND_COOLDOWN: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum EmailVerificationThrottle {
    Allowed,
    Throttled { retry_after: Duration },
}

impl EmailVerificationThrottle {
    pub(crate) fn new(last_sent_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> Self {
        let Some(last_sent_at) = last_sent_at else {
            return Self::Allowed;
        };

        let elapsed = now
            .signed_duration_since(last_sent_at)
            .to_std()
            .unwrap_or(Duration::ZERO);

        match EMAIL_VERIFICATION_RESEND_COOLDOWN.checked_sub(elapsed) {
            Some(retry_after) if !retry_after.is_zero() => Self::Throttled { retry_after },
            _ => Self::Allowed,
        }
    }
}

pub(crate) fn email_verification_throttled_message(retry_after: Duration) -> String {
    let retry_after_minutes = retry_after.as_secs().div_ceil(60);
    format!(
        "Verification email recently sent. Try again in {} minute{}.",
        retry_after_minutes,
        if retry_after_minutes == 1 { "" } else { "s" }
    )
}

#[derive(Debug, Serialize)]
pub struct UserStatus {
    pub email_verified: bool,
    pub payment_method_added: bool,
    pub onboarding_complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legal: Option<crate::legal::UserLegalStatus>,
}

#[derive(Debug, Deserialize)]
pub struct SendVerificationRequest {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct SendVerificationResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Deserialize)]
pub struct VerifyEmailQuery {
    pub token: String,
}

impl std::fmt::Debug for VerifyEmailQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyEmailQuery")
            .field("token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Serialize)]
pub struct VerifyEmailResponse {
    pub success: bool,
    pub message: String,
}

pub async fn get_user_status(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<UserStatus>, StatusCode> {
    let result: Option<(
        Option<DateTime<Utc>>,
        Option<DateTime<Utc>>,
        Option<uuid::Uuid>,
    )> = sqlx::query_as(
        "SELECT email_verified_at, payment_method_added_at, beta_code_id
         FROM users
         WHERE id = $1",
    )
    .bind(auth.user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to get user status: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let (email_verified_at, payment_method_added_at, alpha_code_id) =
        result.ok_or(StatusCode::NOT_FOUND)?;

    // Alpha users skip email verification AND payment
    let is_alpha_user = alpha_code_id.is_some();
    let email_verified = is_alpha_user || email_verified_at.is_some();

    let payment_method_added = is_alpha_user || payment_method_added_at.is_some();
    let onboarding_complete = email_verified && payment_method_added;

    // Legal status is best-effort in the status endpoint — if the legal_documents
    // table doesn't exist yet (migration not run), return None rather than failing auth checks.
    let legal = match crate::legal::get_user_legal_status(&state.db, auth.user_id).await {
        Ok(status) => Some(status),
        Err(e) => {
            tracing::warn!("Failed to fetch legal status: {:?}", e);
            None
        }
    };

    Ok(Json(UserStatus {
        email_verified,
        payment_method_added,
        onboarding_complete,
        legal,
    }))
}

pub async fn send_verification_email(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(payload): Json<SendVerificationRequest>,
) -> Result<Json<SendVerificationResponse>, StatusCode> {
    if let Err(e) = validate_email(&payload.email) {
        return Ok(Json(SendVerificationResponse {
            success: false,
            message: format!("Invalid email: {}", e),
        }));
    }

    let token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + ChronoDuration::hours(24);

    let update_result = sqlx::query(
        "UPDATE users
         SET email = $1,
             email_verification_token = $2,
             email_verification_token_expires_at = $3,
             email_verification_sent_at = NOW()
         WHERE id = $4
           AND (email_verification_sent_at IS NULL
                OR email_verification_sent_at <= NOW() - INTERVAL '5 minutes')",
    )
    .bind(&payload.email)
    .bind(&token)
    .bind(expires_at)
    .bind(auth.user_id)
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to update user with verification token: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if update_result.rows_affected() == 0 {
        let last_sent_at: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT email_verification_sent_at
             FROM users
             WHERE id = $1",
        )
        .bind(auth.user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get verification email throttle state: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .flatten();

        if let EmailVerificationThrottle::Throttled { retry_after } =
            EmailVerificationThrottle::new(last_sent_at, Utc::now())
        {
            return Ok(Json(SendVerificationResponse {
                success: false,
                message: email_verification_throttled_message(retry_after),
            }));
        }

        tracing::error!(
            "Failed to update verification email token for authenticated user {}",
            auth.user_id
        );
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let email_service_url =
        std::env::var("EMAIL_SERVICE_URL").unwrap_or_else(|_| "http://email:8082".to_string());

    let client = reqwest::Client::new();
    let email_request = serde_json::json!({
        "email": payload.email,
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
            if response.status().is_success() {
                tracing::info!("Verification email sent to {}", payload.email);
                Ok(Json(SendVerificationResponse {
                    success: true,
                    message: format!("Verification email sent to {}", payload.email),
                }))
            } else {
                tracing::error!("Email service returned error: {:?}", response.status());
                Ok(Json(SendVerificationResponse {
                    success: false,
                    message: "Failed to send email".to_string(),
                }))
            }
        }
        Err(e) => {
            tracing::error!("Failed to call email service: {:?}", e);
            Ok(Json(SendVerificationResponse {
                success: false,
                message: "Failed to send email".to_string(),
            }))
        }
    }
}

pub async fn verify_email(
    State(state): State<Arc<AppState>>,
    Query(params): Query<VerifyEmailQuery>,
) -> Result<Response, StatusCode> {
    let result: Option<(uuid::Uuid, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, email_verification_token_expires_at
         FROM users
         WHERE email_verification_token = $1
           AND email_verified_at IS NULL",
    )
    .bind(&params.token)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to find verification token: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let (user_id, expires_at) = match result {
        Some(r) => r,
        None => {
            return Ok((
                StatusCode::BAD_REQUEST,
                "Invalid or expired verification token",
            )
                .into_response());
        }
    };

    if Utc::now() > expires_at {
        return Ok((StatusCode::BAD_REQUEST, "Verification token has expired").into_response());
    }

    sqlx::query(
        "UPDATE users
         SET email_verified_at = NOW(),
             email_verification_token = NULL,
             email_verification_token_expires_at = NULL
         WHERE id = $1",
    )
    .bind(user_id)
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to mark email as verified: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::info!("Email verified for user {}", user_id);

    if let Err(e) = crate::provisioning::initialize_user_account(&state.db, user_id).await {
        tracing::error!("Failed to initialize account for user {}: {:?}", user_id, e);
    } else {
        tracing::info!(
            "Account initialized for user {} after email verification",
            user_id
        );
    }

    let frontend_url =
        std::env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:8000".to_string());

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Email Verified</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>
body {{
  font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  margin: 0;
  background: radial-gradient(circle at 50% 25%, white 0%, transparent 60%) no-repeat, #E8F4FC;
}}
.card {{
  background: white;
  border-radius: 12px;
  padding: 3rem;
  max-width: 440px;
  width: 100%;
  text-align: center;
  border: 1px solid #eee;
}}
h1 {{
  font-size: 1.25rem;
  font-weight: 600;
  color: #0f0f0f;
  margin: 0 0 1.5rem;
}}
a {{
  display: inline-block;
  padding: 0.7rem 1.5rem;
  background: #0f0f0f;
  color: white;
  text-decoration: none;
  border-radius: 8px;
  font-family: inherit;
  font-size: 0.95rem;
  font-weight: 500;
  transition: background-color 0.15s ease;
}}
a:hover {{ background: #333; }}
</style>
</head>
<body>
<div class="card">
  <h1>Your email has been successfully verified.</h1>
  <a href="{frontend_url}/login">Go to Login</a>
</div>
</body>
</html>"#
    );

    Ok((StatusCode::OK, [("content-type", "text/html")], html).into_response())
}

pub async fn check_onboarding_status(db: &PgPool, user_id: uuid::Uuid) -> Result<bool, StatusCode> {
    let result: Option<bool> = sqlx::query_scalar("SELECT user_is_onboarded($1)")
        .bind(user_id)
        .fetch_optional(db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to check onboarding status: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(result.unwrap_or(false))
}

#[cfg(test)]
mod tests {
    use super::EmailVerificationThrottle;
    use chrono::{Duration as ChronoDuration, TimeZone, Utc};
    use std::time::Duration;

    #[test]
    fn email_verification_throttle_allows_first_send() {
        let now = Utc.with_ymd_and_hms(2026, 7, 4, 12, 0, 0).unwrap();

        assert_eq!(
            EmailVerificationThrottle::new(None, now),
            EmailVerificationThrottle::Allowed
        );
    }

    #[test]
    fn email_verification_throttle_blocks_recent_send() {
        let now = Utc.with_ymd_and_hms(2026, 7, 4, 12, 0, 0).unwrap();
        let last_sent_at = now - ChronoDuration::minutes(2);

        assert_eq!(
            EmailVerificationThrottle::new(Some(last_sent_at), now),
            EmailVerificationThrottle::Throttled {
                retry_after: Duration::from_secs(180),
            }
        );
    }

    #[test]
    fn email_verification_throttle_allows_after_cooldown() {
        let now = Utc.with_ymd_and_hms(2026, 7, 4, 12, 0, 0).unwrap();
        let last_sent_at = now - ChronoDuration::minutes(5);

        assert_eq!(
            EmailVerificationThrottle::new(Some(last_sent_at), now),
            EmailVerificationThrottle::Allowed
        );
    }
}
