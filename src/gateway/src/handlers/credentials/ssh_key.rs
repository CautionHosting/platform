// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::db;
use crate::types::*;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use dterror::{BoxError, CtxError, Location, ResultExt};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Input/validation failure shared by all SSH-key handlers (malformed or
/// missing authenticated user ID, invalid public key, unparsable key type).
///
/// This is a leaf error: it derives only `thiserror::Error` (no `CtxError`)
/// because every variant is source-less. The typed inner error is carried as an
/// UNMARKED plain field rather than a boxed `#[source]` — a documented deviation
/// mirroring `PasskeyError::Auth`: the surrounding handlers need the concrete
/// `ValidationError` preserved so [`SshKeyInputError::client_message`] can forward
/// its `Display` byte-for-byte, which a boxed dyn-error source would erase. The
/// `CtxError` derive also cannot be applied here because it requires at least one
/// source-bearing variant. Variants are hand-built with
/// `std::panic::Location::caller()`; the client-facing body comes from
/// [`SshKeyInputError::client_message`], not from `Display` (which carries a
/// `[{location}]` suffix for logs only).
#[derive(Debug, thiserror::Error)]
#[allow(clippy::enum_variant_names)]
pub enum SshKeyInputError {
    #[error("missing or invalid authenticated user ID [{location}]")]
    InvalidUserId { location: dterror::Location },

    /// The typed inner error is deliberate (deviating from the boxed `BoxError`
    /// source used by the surrounding handlers): it must be preserved so
    /// [`SshKeyInputError::client_message`] can forward its `Display`. It is
    /// therefore an UNMARKED plain field, not `#[source]`.
    #[error("{validation_error} [{location}]")]
    InvalidPublicKey {
        validation_error: crate::validation::ValidationError,

        location: dterror::Location,
    },

    #[error("failed to parse SSH key type [{location}]")]
    InvalidKeyType { location: dterror::Location },
}

impl SshKeyInputError {
    /// Client-facing message, byte-identical to what the handlers sent before the
    /// typed-error migration. The `Display` impl adds a `[{location}]` log suffix;
    /// this method returns the clean body that reaches the client.
    fn client_message(&self) -> String {
        match self {
            Self::InvalidUserId { .. } => "missing or invalid authenticated user ID".to_string(),
            Self::InvalidKeyType { .. } => "failed to parse SSH key type".to_string(),
            Self::InvalidPublicKey {
                ref validation_error,
                ..
            } => format!("{validation_error}"),
        }
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum AddSshKeyError {
    /// Hand-built at call sites: the inner [`SshKeyInputError`] is an unmarked
    /// typed field (not `#[source]`), so this variant is not constructible through
    /// the context machinery.
    #[error("{source} [{location}]")]
    Input {
        source: SshKeyInputError,

        #[location]
        location: Location,
    },

    #[error("database error [{location}]")]
    Database {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum ListSshKeysError {
    /// Hand-built at call sites; see [`AddSshKeyError::Input`] for why the inner
    /// error is an unmarked typed field.
    #[error("{source} [{location}]")]
    Input {
        source: SshKeyInputError,

        #[location]
        location: Location,
    },

    #[error("database error [{location}]")]
    Database {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum DeleteSshKeyError {
    #[error("missing or invalid authenticated user ID [{location}]")]
    InvalidUserId {
        #[location]
        location: Location,
    },

    #[error("SSH key not found [{location}]")]
    NotFound {
        #[location]
        location: Location,
    },

    #[error("database error [{location}]")]
    Database {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

impl IntoResponse for AddSshKeyError {
    fn into_response(self) -> Response {
        match self {
            Self::Input { source, .. } => {
                (StatusCode::BAD_REQUEST, source.client_message()).into_response()
            }
            Self::Database { .. } => {
                tracing::error!(?self, "SSH key add error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal error occurred",
                )
                    .into_response()
            }
        }
    }
}

impl IntoResponse for ListSshKeysError {
    fn into_response(self) -> Response {
        match self {
            Self::Input { source, .. } => {
                (StatusCode::BAD_REQUEST, source.client_message()).into_response()
            }
            Self::Database { .. } => {
                tracing::error!(?self, "SSH key list error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal error occurred",
                )
                    .into_response()
            }
        }
    }
}

impl IntoResponse for DeleteSshKeyError {
    fn into_response(self) -> Response {
        match self {
            Self::InvalidUserId { .. } => (
                StatusCode::BAD_REQUEST,
                "missing or invalid authenticated user ID",
            )
                .into_response(),
            Self::NotFound { .. } => (StatusCode::NOT_FOUND, "SSH key not found").into_response(),
            Self::Database { .. } => {
                tracing::error!(?self, "SSH key delete error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal error occurred",
                )
                    .into_response()
            }
        }
    }
}

/// Extract the authenticated user ID from the middleware-injected header.
#[tracing::instrument(skip_all)]
fn parse_user_id(headers: &axum::http::HeaderMap) -> Option<Uuid> {
    headers
        .get("X-Authenticated-User-ID")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
}

#[derive(Debug, Deserialize)]
pub struct AddSshKeyRequest {
    pub public_key: String,
    pub name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AddSshKeyResponse {
    pub id: Uuid,
    pub fingerprint: String,
}

#[derive(Debug, Serialize)]
pub struct ListSshKeysResponse {
    pub keys: Vec<crate::db::SshKeyInfo>,
}

#[tracing::instrument(skip_all, err(Debug))]
pub async fn add_ssh_key_handler(
    State(state): State<AppState>,
    user_id_header: axum::http::HeaderMap,
    Json(req): Json<AddSshKeyRequest>,
) -> Result<Json<AddSshKeyResponse>, AddSshKeyError> {
    use AddSshKeyErrorCtx as Ctx;

    let user_id = parse_user_id(&user_id_header).ok_or_else(|| AddSshKeyError::Input {
        source: SshKeyInputError::InvalidUserId {
            location: std::panic::Location::caller(),
        },
        location: std::panic::Location::caller(),
    })?;

    crate::validation::validate_ssh_public_key(&req.public_key).map_err(|e| {
        AddSshKeyError::Input {
            source: SshKeyInputError::InvalidPublicKey {
                validation_error: e,
                location: std::panic::Location::caller(),
            },
            location: std::panic::Location::caller(),
        }
    })?;

    let key_type = req
        .public_key
        .split_whitespace()
        .next()
        .ok_or_else(|| AddSshKeyError::Input {
            source: SshKeyInputError::InvalidKeyType {
                location: std::panic::Location::caller(),
            },
            location: std::panic::Location::caller(),
        })?;

    let added = db::add_ssh_key(
        &state.db,
        user_id,
        &req.public_key,
        key_type,
        req.name.as_deref(),
    )
    .await
    .with_context(Ctx::database())?;

    tracing::debug!("SSH key added");

    Ok(Json(AddSshKeyResponse {
        id: added.id,
        fingerprint: added.fingerprint,
    }))
}

#[tracing::instrument(skip_all, err(Debug))]
pub async fn list_ssh_keys_handler(
    State(state): State<AppState>,
    user_id_header: axum::http::HeaderMap,
) -> Result<Json<ListSshKeysResponse>, ListSshKeysError> {
    use ListSshKeysErrorCtx as Ctx;

    let user_id = parse_user_id(&user_id_header).ok_or_else(|| ListSshKeysError::Input {
        source: SshKeyInputError::InvalidUserId {
            location: std::panic::Location::caller(),
        },
        location: std::panic::Location::caller(),
    })?;

    let keys = db::list_ssh_keys(&state.db, user_id)
        .await
        .with_context(Ctx::database())?;

    Ok(Json(ListSshKeysResponse { keys }))
}

#[tracing::instrument(skip_all, err(Debug))]
pub async fn delete_ssh_key_handler(
    State(state): State<AppState>,
    user_id_header: axum::http::HeaderMap,
    Path(fingerprint): Path<String>,
) -> Result<StatusCode, DeleteSshKeyError> {
    use DeleteSshKeyErrorCtx as Ctx;

    let user_id =
        parse_user_id(&user_id_header).ok_or_else(|| DeleteSshKeyError::InvalidUserId {
            location: std::panic::Location::caller(),
        })?;

    let deleted = db::delete_ssh_key(&state.db, user_id, &fingerprint)
        .await
        .with_context(Ctx::database())?;

    if deleted {
        tracing::debug!("SSH key deleted");
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(DeleteSshKeyError::NotFound {
            location: std::panic::Location::caller(),
        })
    }
}
