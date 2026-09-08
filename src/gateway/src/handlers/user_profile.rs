// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::db;
use crate::types::*;
use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct ClaimUsernameRequest {
    pub username: String,
}

#[derive(Debug, Serialize)]
pub struct UsernameStatusResponse {
    pub username: String,
    pub username_is_placeholder: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum UsernameClaimError {
    #[error("Invalid username: {0}")]
    InvalidUsername(String),
    #[error("This username is already taken.")]
    UsernameTaken,
    #[error("You have already set your username.")]
    AlreadyClaimed,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for UsernameClaimError {
    fn into_response(self) -> Response {
        match self {
            Self::InvalidUsername(_) => (StatusCode::BAD_REQUEST, self.to_string()).into_response(),
            Self::UsernameTaken | Self::AlreadyClaimed => {
                (StatusCode::CONFLICT, self.to_string()).into_response()
            }
            Self::Internal(ref err) => {
                tracing::error!(?err, "Username claim error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal error occurred",
                )
                    .into_response()
            }
        }
    }
}

/// Returns the authenticated user's current username and whether it is
/// still the auto-generated placeholder assigned at signup. Used by the
/// dashboard to decide whether to show the one-time username claim prompt.
#[tracing::instrument(skip_all, err)]
pub async fn get_username_status_handler(
    State(state): State<AppState>,
    Extension(AuthenticatedUserId(user_id)): Extension<AuthenticatedUserId>,
) -> Result<Json<UsernameStatusResponse>, UsernameClaimError> {
    let (username, username_is_placeholder) =
        db::get_username_status(&state.db, user_id).await?;

    Ok(Json(UsernameStatusResponse {
        username,
        username_is_placeholder,
    }))
}

/// One-time username claim: a placeholder account (`u_<base64>`) may set a
/// real, immutable username exactly once. Subsequent attempts fail with
/// `AlreadyClaimed` since `db::claim_username` only updates rows that are
/// still marked as a placeholder.
#[tracing::instrument(skip_all, err)]
pub async fn claim_username_handler(
    State(state): State<AppState>,
    Extension(AuthenticatedUserId(user_id)): Extension<AuthenticatedUserId>,
    Json(req): Json<ClaimUsernameRequest>,
) -> Result<Json<UsernameStatusResponse>, UsernameClaimError> {
    let username = req.username.trim().to_lowercase();
    crate::validation::validate_username(&username)
        .map_err(|e| UsernameClaimError::InvalidUsername(e.to_string()))?;

    let claimed = db::claim_username(&state.db, user_id, &username)
        .await
        .map_err(|e| {
            if db::is_username_taken_error(&e) {
                UsernameClaimError::UsernameTaken
            } else {
                UsernameClaimError::Internal(e)
            }
        })?;

    if !claimed {
        return Err(UsernameClaimError::AlreadyClaimed);
    }

    Ok(Json(UsernameStatusResponse {
        username,
        username_is_placeholder: false,
    }))
}
