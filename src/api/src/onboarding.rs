// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    extract::{Extension, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{Duration, Local, NaiveDateTime};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, FromRow};
use std::sync::Arc;
use uuid::Uuid;

use crate::{AppState, AuthContext};

#[derive(Debug, Serialize, FromRow)]
pub struct UserStatus {
    pub email_verified: bool,
    pub payment_method_added: bool,
    pub onboarding_complete: bool,
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

#[derive(Debug, Deserialize)]
pub struct VerifyEmailQuery {
    pub token: String,
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
    let result: Option<(Option<NaiveDateTime>, Option<NaiveDateTime>)> = sqlx::query_as(
        "SELECT email_verified_at, payment_method_added_at
         FROM users
         WHERE id = $1"
    )
    .bind(auth.user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to get user status: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let (email_verified_at, payment_method_added_at) = result
        .ok_or(StatusCode::NOT_FOUND)?;

    let email_verified = email_verified_at.is_some();

    let skip_payment = std::env::var("SKIP_PAYMENT_REQUIREMENT")
        .unwrap_or_else(|_| "false".to_string())
        .parse::<bool>()
        .unwrap_or(false);

    let payment_method_added = skip_payment || payment_method_added_at.is_some();
    let onboarding_complete = email_verified && payment_method_added;

    Ok(Json(UserStatus {
        email_verified,
        payment_method_added,
        onboarding_complete,
    }))
}

pub async fn send_verification_email(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(payload): Json<SendVerificationRequest>,
) -> Result<Json<SendVerificationResponse>, StatusCode> {
    if !payload.email.contains('@') {
        return Ok(Json(SendVerificationResponse {
            success: false,
            message: "Invalid email format".to_string(),
        }));
    }

    let token = Uuid::new_v4().to_string();
    let expires_at = Local::now().naive_local() + Duration::hours(24);

    sqlx::query(
        "UPDATE users
         SET email = $1,
             email_verification_token = $2,
             email_verification_token_expires_at = $3
         WHERE id = $4"
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

    let email_service_url = std::env::var("EMAIL_SERVICE_URL")
        .unwrap_or_else(|_| "http://email:8082".to_string());

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
    let result: Option<(i64, NaiveDateTime)> = sqlx::query_as(
        "SELECT id, email_verification_token_expires_at
         FROM users
         WHERE email_verification_token = $1
           AND email_verified_at IS NULL"
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

    if Local::now().naive_local() > expires_at {
        return Ok((
            StatusCode::BAD_REQUEST,
            "Verification token has expired",
        )
            .into_response());
    }

    sqlx::query(
        "UPDATE users
         SET email_verified_at = NOW(),
             email_verification_token = NULL,
             email_verification_token_expires_at = NULL
         WHERE id = $1"
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
        tracing::info!("Account initialized for user {} after email verification", user_id);
    }

    let frontend_url = std::env::var("FRONTEND_URL")
        .unwrap_or_else(|_| "http://localhost:3000".to_string());

    let html = format!(r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Email Verified</title>
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    min-height: 100vh;
                    margin: 0;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                }}
                .card {{
                    background: white;
                    border-radius: 16px;
                    padding: 40px;
                    max-width: 500px;
                    text-align: center;
                    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
                }}
                .success-icon {{
                    width: 80px;
                    height: 80px;
                    border-radius: 50%;
                    background: #48bb78;
                    color: white;
                    font-size: 48px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    margin: 0 auto 24px;
                }}
                h1 {{ color: #333; margin-bottom: 16px; }}
                p {{ color: #666; line-height: 1.6; }}
                .btn {{
                    display: inline-block;
                    margin-top: 24px;
                    padding: 14px 32px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    text-decoration: none;
                    border-radius: 8px;
                    font-weight: 600;
                }}
            </style>
        </head>
        <body>
            <div class="card">
                <div class="success-icon">✓</div>
                <h1>Email Verified!</h1>
                <p>Your email has been successfully verified.</p>
                <p>If you have your onboarding tab open, it will automatically advance to the next step.</p>
                <p>Otherwise, you can continue onboarding by logging in again.</p>
                <a href="{}/login" class="btn">Go to Login</a>
            </div>
        </body>
        </html>
    "#, frontend_url);

    Ok((
        StatusCode::OK,
        [("content-type", "text/html")],
        html,
    )
        .into_response())
}

pub async fn check_onboarding_status(db: &PgPool, user_id: i64) -> Result<bool, StatusCode> {
    let skip_payment = std::env::var("SKIP_PAYMENT_REQUIREMENT")
        .unwrap_or_else(|_| "false".to_string())
        .parse::<bool>()
        .unwrap_or(false);

    if skip_payment {
        tracing::debug!("Skipping onboarding check for user {} (dev mode)", user_id);
        return Ok(true);
    }

    let result: Option<bool> = sqlx::query_scalar(
        "SELECT user_is_onboarded($1)"
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to check onboarding status: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(result.unwrap_or(false))
}
