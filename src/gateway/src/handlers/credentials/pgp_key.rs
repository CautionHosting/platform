// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::handlers::AppError;
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

#[derive(Debug, thiserror::Error)]
#[error("Verified signed request audit ID is missing")]
pub struct MissingSignedRequestAuditError;

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
            .ok_or(MissingSignedRequestAuditError)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AddPgpKeyError {
    #[error(transparent)]
    InvalidPublicKey(#[from] crate::pgp::ParsePgpPublicKeyError),

    #[error(transparent)]
    InvalidName(#[from] crate::pgp::ValidatePgpKeyNameError),

    #[error("This PGP public key is already registered to your account")]
    Duplicate,

    #[error(transparent)]
    MissingSignedRequestAudit(#[from] MissingSignedRequestAuditError),

    #[error("Unable to store PGP public key for user {user_id}")]
    Database {
        user_id: Uuid,
        #[source]
        source: sqlx::Error,
    },
}

impl IntoResponse for AddPgpKeyError {
    fn into_response(self) -> Response {
        match self {
            error @ (Self::InvalidPublicKey(_) | Self::InvalidName(_)) => {
                (StatusCode::BAD_REQUEST, error.to_string()).into_response()
            }
            error @ Self::Duplicate => (StatusCode::CONFLICT, error.to_string()).into_response(),
            error @ (Self::MissingSignedRequestAudit(_) | Self::Database { .. }) => {
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
    let signed_request_id = signed_request_audit_id(signed_request)?;
    let public_key = crate::pgp::parse_public_key(&req.public_key)?;
    if let Some(name) = req.name.as_deref() {
        crate::pgp::validate_key_name(name)?;
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
        Err(source)
            if source.as_database_error().is_some_and(|error| {
                error.is_unique_violation()
                    && matches!(
                        error.constraint(),
                        Some(
                            "pgp_keys_user_fingerprint_unique"
                                | "pgp_keys_active_user_fingerprint_unique"
                        )
                    )
            }) =>
        {
            return Err(AddPgpKeyError::Duplicate);
        }
        Err(source) => return Err(AddPgpKeyError::Database { user_id, source }),
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

#[tracing::instrument(skip_all, err(Debug))]
pub async fn list_pgp_keys_handler(
    State(state): State<AppState>,
    Extension(AuthenticatedUserId(user_id)): Extension<AuthenticatedUserId>,
) -> Result<Json<ListPgpKeysResponse>, AppError> {
    let keys = crate::db::list_pgp_keys(&state.db, user_id).await?;
    Ok(Json(ListPgpKeysResponse { keys }))
}

#[derive(Debug, thiserror::Error)]
pub enum RemovePgpKeyHandlerError {
    #[error("PGP public key not found")]
    NotFound,

    #[error(transparent)]
    MissingSignedRequestAudit(#[from] MissingSignedRequestAuditError),

    #[error(transparent)]
    Database(#[from] crate::db::RemovePgpKeyError),
}

impl IntoResponse for RemovePgpKeyHandlerError {
    fn into_response(self) -> Response {
        match self {
            error @ Self::NotFound => (StatusCode::NOT_FOUND, error.to_string()).into_response(),
            error @ (Self::MissingSignedRequestAudit(_) | Self::Database(_)) => {
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
    let signed_request_id = signed_request_audit_id(signed_request)?;
    let fingerprint = crate::db::remove_pgp_key(&state.db, user_id, key_id, signed_request_id)
        .await?
        .ok_or(RemovePgpKeyHandlerError::NotFound)?;

    tracing::info!(
        user_id = %user_id,
        key_id = %key_id,
        fingerprint = %fingerprint,
        "PGP public key removed"
    );

    Ok(StatusCode::NO_CONTENT)
}
