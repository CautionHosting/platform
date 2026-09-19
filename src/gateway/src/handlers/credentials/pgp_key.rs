// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::types::*;
use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use dterror::{CtxError, ResultExt};
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

/// Leaf error: source-less, so it stays a plain `thiserror` type (no `CtxError`
/// derive). Its Display never reaches clients: the handlers that receive it box
/// it as a `#[source]` behind their own fixed, generic bodies.
#[derive(Debug, thiserror::Error)]
#[error("verified signed request audit ID is missing [{location}]")]
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

/// Handler error: `IntoResponse` maps every variant to an explicit status with a
/// fixed, generic body; inner errors are preserved only as boxed sources for logs.
#[derive(Debug, thiserror::Error, dterror::CtxError)]
pub enum AddPgpKeyError {
    #[error("invalid PGP public key [{location}]")]
    InvalidPublicKey {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("invalid key name [{location}]")]
    InvalidName {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("This PGP public key is already registered to your account [{location}]")]
    Duplicate { location: dterror::Location },

    #[error("verified signed request audit ID is missing [{location}]")]
    MissingSignedRequestAudit {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("unable to store PGP public key for user {user_id} [{location}]")]
    Database {
        user_id: Uuid,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },
}

impl IntoResponse for AddPgpKeyError {
    fn into_response(self) -> Response {
        match self {
            error @ (Self::InvalidPublicKey { .. } | Self::InvalidName { .. }) => {
                tracing::warn!(?error, "Rejected PGP key request: invalid input");
                (
                    StatusCode::BAD_REQUEST,
                    "The submitted PGP key or key name is invalid.",
                )
                    .into_response()
            }
            Self::Duplicate { .. } => (
                StatusCode::CONFLICT,
                "This PGP public key is already registered to your account",
            )
                .into_response(),
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
    use AddPgpKeyErrorCtx as Ctx;

    let signed_request_id =
        signed_request_audit_id(signed_request).with_context(Ctx::missing_signed_request_audit())?;
    let public_key =
        crate::pgp::parse_public_key(&req.public_key).with_context(Ctx::invalid_public_key())?;
    if let Some(name) = req.name.as_deref() {
        crate::pgp::validate_key_name(name).with_context(Ctx::invalid_name())?;
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
            return Err(AddPgpKeyError::from_context(
                AddPgpKeyErrorCtx::database(user_id),
                std::panic::Location::caller(),
                Box::new(source),
            ));
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
/// Source-less context means there is nothing for the `CtxError` derive to
/// generate, so this stays a plain `thiserror` type hand-built at the call site.
#[derive(Debug, thiserror::Error)]
#[error("failed to list PGP keys [{location}]")]
pub struct ListPgpKeysError {
    location: dterror::Location,
    #[source]
    source: dterror::BoxError,
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
            location: std::panic::Location::caller(),
            source: Box::new(source),
        })?;
    Ok(Json(ListPgpKeysResponse { keys }))
}

/// Handler error: `IntoResponse` maps every variant to an explicit status with a
/// fixed, generic body; inner errors are preserved only as boxed sources for logs.
#[derive(Debug, thiserror::Error, dterror::CtxError)]
pub enum RemovePgpKeyHandlerError {
    #[error("PGP public key not found [{location}]")]
    NotFound { location: dterror::Location },

    #[error("verified signed request audit ID is missing [{location}]")]
    MissingSignedRequestAudit {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("database error [{location}]")]
    Database {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },
}

impl IntoResponse for RemovePgpKeyHandlerError {
    fn into_response(self) -> Response {
        match self {
            Self::NotFound { .. } => {
                (StatusCode::NOT_FOUND, "PGP public key not found").into_response()
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
    use RemovePgpKeyHandlerErrorCtx as Ctx;

    let signed_request_id =
        signed_request_audit_id(signed_request).with_context(Ctx::missing_signed_request_audit())?;
    let fingerprint = crate::db::remove_pgp_key(&state.db, user_id, key_id, signed_request_id)
        .await
        .with_context(Ctx::database())?
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
