// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Duration, Utc};
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
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub async fn get_current_user(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<User>, StatusCode> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, username, email, is_active, created_at, updated_at
         FROM users WHERE id = $1",
    )
    .bind(auth.user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(Json(user))
}

pub async fn update_current_user(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    validated_types::Validated(payload): validated_types::Validated<UpdateUserRequest>,
) -> Result<Json<User>, StatusCode> {
    if payload.username.is_none() && payload.email.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut query_builder = sqlx::QueryBuilder::new("UPDATE users SET ");
    let mut has_updates = false;

    if let Some(username) = &payload.username {
        if has_updates {
            query_builder.push(", ");
        }
        query_builder.push("username = ");
        query_builder.push_bind(username);
        has_updates = true;
    }

    let new_email = payload.email.clone();
    let mut verification_token: Option<String> = None;

    if let Some(email) = &new_email {
        if has_updates {
            query_builder.push(", ");
        }
        query_builder.push("email = ");
        query_builder.push_bind(email);

        // Generate verification token and reset verified status
        let token = Uuid::new_v4().to_string();
        let expires_at = Utc::now() + Duration::hours(24);
        query_builder.push(", email_verified_at = NULL, email_verification_token = ");
        query_builder.push_bind(token.clone());
        query_builder.push(", email_verification_token_expires_at = ");
        query_builder.push_bind(expires_at);
        verification_token = Some(token);
        has_updates = true;
    }

    query_builder.push(" WHERE id = ");
    query_builder.push_bind(auth.user_id);
    query_builder.push(" RETURNING id, username, email, is_active, created_at, updated_at");

    let user = query_builder
        .build_query_as::<User>()
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

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

        if let Err(e) = client
            .post(format!("{}/send-verification", email_service_url))
            .json(&email_request)
            .send()
            .await
        {
            tracing::error!("Failed to send verification email on email change: {:?}", e);
        }
    }

    Ok(Json(user))
}

pub async fn delete_current_user(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<StatusCode, StatusCode> {
    sqlx::query("UPDATE users SET is_active = false WHERE id = $1")
        .bind(auth.user_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}
