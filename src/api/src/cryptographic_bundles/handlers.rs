// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial

//! HTTP handlers for cryptographic bundles: `/quorum-bundles` and
//! `/secrets-bundles`.

use super::{CreateBundleRequest, QuorumBundle, SecretsBundle, UpdateBundleRequest};
use crate::{AppState, AuthContext, get_user_primary_org, org_quorum};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use dterror::{BoxError, CtxError, Location, ResultExt};
use std::sync::Arc;
use uuid::Uuid;

/// Failure modes for [`list_quorum_bundles`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ListQuorumBundlesError {
    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to list quorum bundles [{location}]")]
    List {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for ListQuorumBundlesError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            ListQuorumBundlesError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            ListQuorumBundlesError::List { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        sentry_middleware::error_response(status, body, self)
    }
}

#[tracing::instrument(skip_all, err(Debug), fields(user_id = %auth.user_id))]
pub(crate) async fn list_quorum_bundles(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<QuorumBundle>>, ListQuorumBundlesError> {
    use ListQuorumBundlesErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    let items = super::list_quorum_bundles(&state.db, org_id)
        .await
        .with_context(Ctx::list())?;
    Ok(Json(items))
}

/// Failure modes for [`create_quorum_bundle`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum CreateQuorumBundleError {
    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("uploaded quorum bundle failed verification [{location}]")]
    VerifyUpload {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to store quorum bundle [{location}]")]
    Store {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for CreateQuorumBundleError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            CreateQuorumBundleError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "unable to resolve organization",
            ),
            CreateQuorumBundleError::VerifyUpload { source, .. } => {
                verify_upload_response(source.downcast_ref())
            }
            CreateQuorumBundleError::Store { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "unable to store quorum bundle",
            ),
        };
        sentry_middleware::error_response(status, body, self)
    }
}

/// Client status and text for a failed upload verification.
fn verify_upload_response(
    error: Option<&org_quorum::VerifyUploadError>,
) -> (StatusCode, &'static str) {
    use org_quorum::VerifyUploadError as V;
    match error {
        Some(V::PolicyPath { .. } | V::Policy { .. }) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "key-service configuration is unavailable",
        ),
        Some(
            V::LegacyOptIn { .. }
            | V::LegacyParse { .. }
            | V::Parse { .. }
            | V::Proof { .. }
            | V::InvalidBundle { .. }
            | V::Keyring { .. }
            | V::PublicKey { .. },
        )
        | None => (StatusCode::BAD_REQUEST, "invalid quorum bundle"),
    }
}

#[tracing::instrument(skip_all, err(Debug), fields(user_id = %auth.user_id))]
pub(crate) async fn create_quorum_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<CreateBundleRequest>,
) -> Result<Json<QuorumBundle>, CreateQuorumBundleError> {
    use CreateQuorumBundleErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    org_quorum::verify_upload(&req.data, req.allow_legacy).with_context(Ctx::verify_upload())?;
    let bundle = super::create_quorum_bundle(&state.db, org_id, auth.user_id, req)
        .await
        .with_context(Ctx::store())?;
    Ok(Json(bundle))
}

/// Failure modes for [`get_quorum_bundle`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetQuorumBundleError {
    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("quorum bundle {bundle_id} not found [{location}]")]
    NotFound { bundle_id: Uuid, location: Location },

    #[error("failed to get quorum bundle [{location}]")]
    Get {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for GetQuorumBundleError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            GetQuorumBundleError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            GetQuorumBundleError::NotFound { .. } => {
                (StatusCode::NOT_FOUND, "Quorum bundle not found")
            }
            GetQuorumBundleError::Get { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        sentry_middleware::error_response(status, body, self)
    }
}

#[tracing::instrument(skip_all, err(Debug), fields(bundle_id = %id))]
pub(crate) async fn get_quorum_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<QuorumBundle>, GetQuorumBundleError> {
    use GetQuorumBundleErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    let bundle = super::get_quorum_bundle(&state.db, org_id, id)
        .await
        .with_context(Ctx::get())?
        .ok_or_else(|| GetQuorumBundleError::NotFound {
            bundle_id: id,
            location: std::panic::Location::caller(),
        })?;

    Ok(Json(bundle))
}

/// Failure modes for [`update_quorum_bundle`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum UpdateQuorumBundleError {
    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("uploaded quorum bundle failed verification [{location}]")]
    VerifyUpload {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to update quorum bundle [{location}]")]
    Update {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("quorum bundle {bundle_id} not found [{location}]")]
    NotFound { bundle_id: Uuid, location: Location },
}

impl IntoResponse for UpdateQuorumBundleError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            UpdateQuorumBundleError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "unable to resolve organization",
            ),
            UpdateQuorumBundleError::VerifyUpload { source, .. } => {
                verify_upload_response(source.downcast_ref())
            }
            UpdateQuorumBundleError::Update { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "unable to update quorum bundle",
            ),
            UpdateQuorumBundleError::NotFound { .. } => {
                (StatusCode::NOT_FOUND, "quorum bundle not found")
            }
        };
        sentry_middleware::error_response(status, body, self)
    }
}

#[tracing::instrument(skip_all, err(Debug), fields(bundle_id = %id))]
pub(crate) async fn update_quorum_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateBundleRequest>,
) -> Result<Json<QuorumBundle>, UpdateQuorumBundleError> {
    use UpdateQuorumBundleErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    if let Some(data) = &req.data {
        org_quorum::verify_upload(data, req.allow_legacy).with_context(Ctx::verify_upload())?;
    }
    let bundle = super::update_quorum_bundle(&state.db, org_id, id, req)
        .await
        .with_context(Ctx::update())?
        .ok_or_else(|| UpdateQuorumBundleError::NotFound {
            bundle_id: id,
            location: std::panic::Location::caller(),
        })?;

    Ok(Json(bundle))
}

/// Failure modes for [`delete_quorum_bundle`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum DeleteQuorumBundleError {
    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("quorum bundle {bundle_id} not found [{location}]")]
    NotFound { bundle_id: Uuid, location: Location },

    #[error("failed to delete quorum bundle [{location}]")]
    Delete {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for DeleteQuorumBundleError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            DeleteQuorumBundleError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            DeleteQuorumBundleError::NotFound { .. } => {
                (StatusCode::NOT_FOUND, "Quorum bundle not found")
            }
            DeleteQuorumBundleError::Delete { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        sentry_middleware::error_response(status, body, self)
    }
}

#[tracing::instrument(skip_all, err(Debug), fields(bundle_id = %id))]
pub(crate) async fn delete_quorum_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, DeleteQuorumBundleError> {
    use DeleteQuorumBundleErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    let deleted = super::delete_quorum_bundle(&state.db, org_id, id)
        .await
        .with_context(Ctx::delete())?;

    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(DeleteQuorumBundleError::NotFound {
            bundle_id: id,
            location: std::panic::Location::caller(),
        })
    }
}

/// Failure modes for [`list_secrets_bundles`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ListSecretsBundlesError {
    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to list secrets bundles [{location}]")]
    List {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for ListSecretsBundlesError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            ListSecretsBundlesError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            ListSecretsBundlesError::List { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        sentry_middleware::error_response(status, body, self)
    }
}

#[tracing::instrument(skip_all, err(Debug), fields(user_id = %auth.user_id))]
pub(crate) async fn list_secrets_bundles(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<SecretsBundle>>, ListSecretsBundlesError> {
    use ListSecretsBundlesErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    let items = super::list_secrets_bundles(&state.db, org_id)
        .await
        .with_context(Ctx::list())?;
    Ok(Json(items))
}

/// Failure modes for [`create_secrets_bundle`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum CreateSecretsBundleError {
    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to create secrets bundle [{location}]")]
    Create {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for CreateSecretsBundleError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            CreateSecretsBundleError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            CreateSecretsBundleError::Create { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        sentry_middleware::error_response(status, body, self)
    }
}

#[tracing::instrument(skip_all, err(Debug), fields(user_id = %auth.user_id))]
pub(crate) async fn create_secrets_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<CreateBundleRequest>,
) -> Result<Json<SecretsBundle>, CreateSecretsBundleError> {
    use CreateSecretsBundleErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    let bundle = super::create_secrets_bundle(&state.db, org_id, auth.user_id, req)
        .await
        .with_context(Ctx::create())?;
    Ok(Json(bundle))
}

/// Failure modes for [`get_secrets_bundle`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetSecretsBundleError {
    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("secrets bundle {bundle_id} not found [{location}]")]
    NotFound { bundle_id: Uuid, location: Location },

    #[error("failed to get secrets bundle [{location}]")]
    Get {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for GetSecretsBundleError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            GetSecretsBundleError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            GetSecretsBundleError::NotFound { .. } => {
                (StatusCode::NOT_FOUND, "Secrets bundle not found")
            }
            GetSecretsBundleError::Get { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        sentry_middleware::error_response(status, body, self)
    }
}

#[tracing::instrument(skip_all, err(Debug), fields(bundle_id = %id))]
pub(crate) async fn get_secrets_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<SecretsBundle>, GetSecretsBundleError> {
    use GetSecretsBundleErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    let bundle = super::get_secrets_bundle(&state.db, org_id, id)
        .await
        .with_context(Ctx::get())?
        .ok_or_else(|| GetSecretsBundleError::NotFound {
            bundle_id: id,
            location: std::panic::Location::caller(),
        })?;

    Ok(Json(bundle))
}

/// Failure modes for [`update_secrets_bundle`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum UpdateSecretsBundleError {
    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("secrets bundle {bundle_id} not found [{location}]")]
    NotFound { bundle_id: Uuid, location: Location },

    #[error("failed to update secrets bundle [{location}]")]
    Update {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for UpdateSecretsBundleError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            UpdateSecretsBundleError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            UpdateSecretsBundleError::NotFound { .. } => {
                (StatusCode::NOT_FOUND, "Secrets bundle not found")
            }
            UpdateSecretsBundleError::Update { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        sentry_middleware::error_response(status, body, self)
    }
}

#[tracing::instrument(skip_all, err(Debug), fields(bundle_id = %id))]
pub(crate) async fn update_secrets_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateBundleRequest>,
) -> Result<Json<SecretsBundle>, UpdateSecretsBundleError> {
    use UpdateSecretsBundleErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    let bundle = super::update_secrets_bundle(&state.db, org_id, id, req)
        .await
        .with_context(Ctx::update())?
        .ok_or_else(|| UpdateSecretsBundleError::NotFound {
            bundle_id: id,
            location: std::panic::Location::caller(),
        })?;

    Ok(Json(bundle))
}

/// Failure modes for [`delete_secrets_bundle`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum DeleteSecretsBundleError {
    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("secrets bundle {bundle_id} not found [{location}]")]
    NotFound { bundle_id: Uuid, location: Location },

    #[error("failed to delete secrets bundle [{location}]")]
    Delete {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for DeleteSecretsBundleError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            DeleteSecretsBundleError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            DeleteSecretsBundleError::NotFound { .. } => {
                (StatusCode::NOT_FOUND, "Secrets bundle not found")
            }
            DeleteSecretsBundleError::Delete { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        sentry_middleware::error_response(status, body, self)
    }
}

#[tracing::instrument(skip_all, err(Debug), fields(bundle_id = %id))]
pub(crate) async fn delete_secrets_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, DeleteSecretsBundleError> {
    use DeleteSecretsBundleErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    let deleted = super::delete_secrets_bundle(&state.db, org_id, id)
        .await
        .with_context(Ctx::delete())?;

    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(DeleteSecretsBundleError::NotFound {
            bundle_id: id,
            location: std::panic::Location::caller(),
        })
    }
}
