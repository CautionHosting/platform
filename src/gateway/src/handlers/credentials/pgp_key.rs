// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::types::*;
use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddPgpKeyRequest {
    pub public_key: String,
    pub name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AddPgpKeyResponse {
    pub id: Uuid,
    pub fingerprint: String,
}

#[derive(Debug, Serialize)]
pub struct ListPgpKeysResponse {
    pub keys: Vec<crate::db::PgpKeyInfo>,
}

/// Leaf error: location is Debug-only because the Display of this type feeds
/// client-facing bodies via `AddPgpKeyError`'s transparent forwarding.
#[derive(Debug, thiserror::Error)]
#[error("Verified signed request audit ID is missing")]
pub struct MissingSignedRequestAuditError {
    pub(crate) location: dterror::Location,
}

#[tracing::instrument(skip_all, err)]
fn signed_request_audit_id(
    signed_request: Option<Extension<VerifiedSignedRequestId>>,
) -> Result<Option<Uuid>, MissingSignedRequestAuditError> {
    #[cfg(feature = "e2e-testing-unsafe")]
    {
        Ok(signed_request.map(|Extension(VerifiedSignedRequestId(id))| id))
    }

    #[cfg(not(feature = "e2e-testing-unsafe"))]
    {
        signed_request
            .map(|Extension(VerifiedSignedRequestId(id))| Some(id))
            .ok_or(MissingSignedRequestAuditError {
                location: std::panic::Location::caller(),
            })
    }
}

/// Leaf error: location is Debug-only because the `Duplicate` variant's Display
/// reaches clients via `IntoResponse`; other variants forward the source's Display.
#[derive(Debug, thiserror::Error)]
pub enum AddPgpKeyError {
    #[error("{source}")]
    InvalidPublicKey {
        #[source]
        source: crate::pgp::ParsePgpPublicKeyError,
        location: dterror::Location,
    },

    #[error("{source}")]
    InvalidName {
        #[source]
        source: crate::pgp::ValidatePgpKeyNameError,
        location: dterror::Location,
    },

    #[error("This PGP public key is already registered to your account")]
    Duplicate { location: dterror::Location },

    #[error("{source}")]
    MissingSignedRequestAudit {
        #[source]
        source: MissingSignedRequestAuditError,
        location: dterror::Location,
    },

    #[error("Unable to store PGP public key for user {user_id}")]
    Database {
        user_id: Uuid,
        #[source]
        source: crate::db::DbError,
        location: dterror::Location,
    },
}

impl IntoResponse for AddPgpKeyError {
    fn into_response(self) -> Response {
        match self {
            error @ (Self::InvalidPublicKey { .. } | Self::InvalidName { .. }) => {
                (StatusCode::BAD_REQUEST, error.to_string()).into_response()
            }
            error @ Self::Duplicate { .. } => {
                (StatusCode::CONFLICT, error.to_string()).into_response()
            }
            error @ (Self::MissingSignedRequestAudit { .. } | Self::Database { .. }) => {
                tracing::error!(?error, "Failed to add PGP public key");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal error occurred",
                )
                    .into_response()
            }
        }
    }
}

#[tracing::instrument(skip_all, err)]
pub async fn add_pgp_key_handler(
    State(state): State<AppState>,
    Extension(AuthenticatedUserId(user_id)): Extension<AuthenticatedUserId>,
    signed_request: Option<Extension<VerifiedSignedRequestId>>,
    Json(req): Json<AddPgpKeyRequest>,
) -> Result<Json<AddPgpKeyResponse>, AddPgpKeyError> {
    let signed_request_id = signed_request_audit_id(signed_request).map_err(|source| {
        AddPgpKeyError::MissingSignedRequestAudit {
            source,
            location: std::panic::Location::caller(),
        }
    })?;
    let public_key = crate::pgp::parse_public_key(&req.public_key).map_err(|source| {
        AddPgpKeyError::InvalidPublicKey {
            source,
            location: std::panic::Location::caller(),
        }
    })?;
    if let Some(name) = req.name.as_deref() {
        crate::pgp::validate_key_name(name).map_err(|source| AddPgpKeyError::InvalidName {
            source,
            location: std::panic::Location::caller(),
        })?;
    }
    let name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty());

    let key_id = match crate::db::add_pgp_key(
        &state.db,
        user_id,
        public_key.armored(),
        public_key.fingerprint(),
        name,
        signed_request_id,
    )
    .await
    {
        Ok(key_id) => key_id,
        Err(e) if e.kind == crate::db::DbErrorKind::PgpKeyDuplicate => {
            return Err(AddPgpKeyError::Duplicate {
                location: std::panic::Location::caller(),
            });
        }
        Err(source) => {
            return Err(AddPgpKeyError::Database {
                user_id,
                source,
                location: std::panic::Location::caller(),
            });
        }
    };

    tracing::info!(
        user_id = %user_id,
        fingerprint = %public_key.fingerprint(),
        "PGP public key added"
    );

    Ok(Json(AddPgpKeyResponse {
        id: key_id,
        fingerprint: public_key.fingerprint().to_string(),
    }))
}

/// Leaf error: internal-only Display (logged via IntoResponse's generic 500).
#[derive(Debug, thiserror::Error)]
#[error("failed to list PGP keys [{location}]")]
pub struct ListPgpKeysError {
    #[source]
    source: crate::db::DbError,
    location: dterror::Location,
}

impl IntoResponse for ListPgpKeysError {
    fn into_response(self) -> Response {
        tracing::error!(?self, "Failed to list PGP keys");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "An internal error occurred",
        )
            .into_response()
    }
}

#[tracing::instrument(skip_all, err(Debug))]
pub async fn list_pgp_keys_handler(
    State(state): State<AppState>,
    Extension(AuthenticatedUserId(user_id)): Extension<AuthenticatedUserId>,
) -> Result<Json<ListPgpKeysResponse>, ListPgpKeysError> {
    let keys = crate::db::list_pgp_keys(&state.db, user_id)
        .await
        .map_err(|source| ListPgpKeysError {
            source,
            location: std::panic::Location::caller(),
        })?;
    Ok(Json(ListPgpKeysResponse { keys }))
}

/// Leaf error: location is Debug-only because the `NotFound` variant's Display
/// reaches clients via `IntoResponse`; other variants forward the source's Display.
#[derive(Debug, thiserror::Error)]
pub enum RemovePgpKeyHandlerError {
    #[error("PGP public key not found")]
    NotFound { location: dterror::Location },

    #[error("{source}")]
    MissingSignedRequestAudit {
        #[source]
        source: MissingSignedRequestAuditError,
        location: dterror::Location,
    },

    #[error("{source}")]
    Database {
        #[source]
        source: crate::db::RemovePgpKeyError,
        location: dterror::Location,
    },
}

impl IntoResponse for RemovePgpKeyHandlerError {
    fn into_response(self) -> Response {
        match self {
            error @ Self::NotFound { .. } => {
                (StatusCode::NOT_FOUND, error.to_string()).into_response()
            }
            error @ (Self::MissingSignedRequestAudit { .. } | Self::Database { .. }) => {
                tracing::error!(?error, "Failed to remove PGP public key");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal error occurred",
                )
                    .into_response()
            }
        }
    }
}

#[tracing::instrument(skip_all, err)]
pub async fn remove_pgp_key_handler(
    State(state): State<AppState>,
    Extension(AuthenticatedUserId(user_id)): Extension<AuthenticatedUserId>,
    signed_request: Option<Extension<VerifiedSignedRequestId>>,
    Path(key_id): Path<Uuid>,
) -> Result<StatusCode, RemovePgpKeyHandlerError> {
    let signed_request_id = signed_request_audit_id(signed_request).map_err(|source| {
        RemovePgpKeyHandlerError::MissingSignedRequestAudit {
            source,
            location: std::panic::Location::caller(),
        }
    })?;
    let fingerprint = crate::db::remove_pgp_key(&state.db, user_id, key_id, signed_request_id)
        .await
        .map_err(|source| RemovePgpKeyHandlerError::Database {
            source,
            location: std::panic::Location::caller(),
        })?
        .ok_or_else(|| RemovePgpKeyHandlerError::NotFound {
            location: std::panic::Location::caller(),
        })?;

    tracing::info!(
        user_id = %user_id,
        key_id = %key_id,
        fingerprint = %fingerprint,
        "PGP public key removed"
    );

    Ok(StatusCode::NO_CONTENT)
}
