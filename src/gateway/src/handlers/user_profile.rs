// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::db::{self, DbErrorKind};
use crate::types::*;
use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use dterror::{BoxError, CtxError, Location, ResultExt};
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

/// Strict dterror convention: every variant carries `#[location]`; source-bearing
/// variants use `.with_context(Ctx::…)` at call sites; source-less (domain)
/// variants are hand-built with `std::panic::Location::caller()`.
#[derive(Debug, thiserror::Error, CtxError)]
pub enum UsernameClaimError {
    #[error("invalid username [{location}]")]
    InvalidUsername {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("This username is already taken. [{location}]")]
    UsernameTaken {
        #[location]
        location: Location,
    },

    #[error("You have already set your username. [{location}]")]
    AlreadyClaimed {
        #[location]
        location: Location,
    },

    #[error("internal error [{location}]")]
    Internal {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

impl IntoResponse for UsernameClaimError {
    fn into_response(self) -> Response {
        match self {
            Self::InvalidUsername { .. } => (
                StatusCode::BAD_REQUEST,
                "The requested username is invalid.",
            )
                .into_response(),
            Self::UsernameTaken { .. } => {
                (StatusCode::CONFLICT, "This username is already taken.").into_response()
            }
            Self::AlreadyClaimed { .. } => {
                (StatusCode::CONFLICT, "You have already set your username.").into_response()
            }
            Self::Internal { .. } => {
                tracing::error!(?self, "Username claim error");
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
    use UsernameClaimErrorCtx as Ctx;

    let (username, username_is_placeholder) = db::get_username_status(&state.db, user_id)
        .await
        .with_context(Ctx::internal())?;

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
    if let Err(source) = crate::validation::validate_username(&username) {
        return Err(UsernameClaimError::InvalidUsername {
            location: std::panic::Location::caller(),
            source: Box::new(source),
        });
    }

    let claimed = match db::claim_username(&state.db, user_id, &username).await {
        Ok(claimed) => claimed,
        Err(e) if e.kind == DbErrorKind::UsernameTaken => {
            return Err(UsernameClaimError::UsernameTaken {
                location: std::panic::Location::caller(),
            });
        }
        Err(source) => {
            return Err(UsernameClaimError::Internal {
                source: Box::new(source),
                location: std::panic::Location::caller(),
            });
        }
    };

    if !claimed {
        return Err(UsernameClaimError::AlreadyClaimed {
            location: std::panic::Location::caller(),
        });
    }

    Ok(Json(UsernameStatusResponse {
        username,
        username_is_placeholder: false,
    }))
}
