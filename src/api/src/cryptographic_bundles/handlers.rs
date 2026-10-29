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
use caution_error::Opaque;
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
#[derive(Debug, thiserror::Error, CtxError, caution_error::ProviderError)]
pub(crate) enum CreateQuorumBundleError {
    #[error("could not look up the primary organization")]
    PrimaryOrgLookup {
        #[provide]
        opaque: Opaque,
        #[provide]
        #[location]
        location: Location,
        #[source]
        source: crate::GetUserPrimaryOrgError,
    },

    #[error("invalid quorum bundle")]
    UnverifiedBundle {
        #[provide]
        #[location]
        location: Location,
        #[source]
        source: org_quorum::VerifyUploadError,
    },

    #[error("key-service configuration is unavailable")]
    KeyServiceUnavailable {
        #[provide]
        #[location]
        location: Location,
        #[source]
        source: org_quorum::VerifyUploadError,
    },

    #[error("failed to store quorum bundle")]
    Store {
        #[provide]
        opaque: Opaque,
        #[provide]
        #[location]
        location: Location,
        #[source]
        source: super::CreateQuorumBundleError,
    },
}

impl IntoResponse for CreateQuorumBundleError {
    fn into_response(self) -> Response {
        let status = match &self {
            CreateQuorumBundleError::PrimaryOrgLookup { .. }
            | CreateQuorumBundleError::Store { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            CreateQuorumBundleError::UnverifiedBundle { .. } => StatusCode::BAD_REQUEST,
            CreateQuorumBundleError::KeyServiceUnavailable { .. } => {
                StatusCode::SERVICE_UNAVAILABLE
            }
        };
        let fallback = match &self {
            CreateQuorumBundleError::PrimaryOrgLookup { .. } => "unable to resolve organization",
            CreateQuorumBundleError::Store { .. } => "unable to store quorum bundle",
            CreateQuorumBundleError::UnverifiedBundle { .. }
            | CreateQuorumBundleError::KeyServiceUnavailable { .. } => "",
        };
        error_response(status, self, fallback)
    }
}

/// Sends an error as a structured report and reports it to Sentry. `fallback`
/// is the client text when the error (or its root) is opaque.
fn error_response(
    status: StatusCode,
    error: impl caution_error::ProviderError,
    fallback: &'static str,
) -> Response {
    let report = caution_error::ErrorReport::from_error_with(&error, fallback);
    sentry_middleware::error_response_provider(status, Json(report), error)
}

/// Whether an upload verification failure is the key service's fault, not the
/// upload's.
///
/// A policy failure means the platform cannot check the proof at all, so the
/// upload is neither accepted nor rejected on its own merits.
fn is_key_service_unavailable(error: &org_quorum::VerifyUploadError) -> bool {
    use org_quorum::VerifyUploadError as V;
    matches!(error, V::PolicyPath { .. } | V::Policy { .. })
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
        .with_context(Ctx::primary_org_lookup(Opaque))?;

    org_quorum::verify_upload(&req.data, req.allow_legacy).map_err(|source| {
        let location = std::panic::Location::caller();
        if is_key_service_unavailable(&source) {
            CreateQuorumBundleError::KeyServiceUnavailable { location, source }
        } else {
            CreateQuorumBundleError::UnverifiedBundle { location, source }
        }
    })?;
    let bundle = super::create_quorum_bundle(&state.db, org_id, auth.user_id, req)
        .await
        .with_context(Ctx::store(Opaque))?;
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
#[derive(Debug, thiserror::Error, CtxError, caution_error::ProviderError)]
pub(crate) enum UpdateQuorumBundleError {
    #[error("could not look up the primary organization")]
    PrimaryOrgLookup {
        #[provide]
        opaque: Opaque,
        #[provide]
        #[location]
        location: Location,
        #[source]
        source: crate::GetUserPrimaryOrgError,
    },

    #[error("invalid quorum bundle")]
    UnverifiedBundle {
        #[provide]
        #[location]
        location: Location,
        #[source]
        source: org_quorum::VerifyUploadError,
    },

    #[error("key-service configuration is unavailable")]
    KeyServiceUnavailable {
        #[provide]
        #[location]
        location: Location,
        #[source]
        source: org_quorum::VerifyUploadError,
    },

    #[error("failed to update quorum bundle")]
    Update {
        #[provide]
        opaque: Opaque,
        #[provide]
        #[location]
        location: Location,
        #[source]
        source: super::UpdateQuorumBundleError,
    },

    #[error("quorum bundle {bundle_id} not found")]
    NotFound {
        bundle_id: Uuid,
        #[provide]
        #[location]
        location: Location,
    },
}

impl IntoResponse for UpdateQuorumBundleError {
    fn into_response(self) -> Response {
        let status = match &self {
            UpdateQuorumBundleError::PrimaryOrgLookup { .. }
            | UpdateQuorumBundleError::Update { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            UpdateQuorumBundleError::UnverifiedBundle { .. } => StatusCode::BAD_REQUEST,
            UpdateQuorumBundleError::KeyServiceUnavailable { .. } => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            UpdateQuorumBundleError::NotFound { .. } => StatusCode::NOT_FOUND,
        };
        let fallback = match &self {
            UpdateQuorumBundleError::PrimaryOrgLookup { .. } => "unable to resolve organization",
            UpdateQuorumBundleError::Update { .. } => "unable to update quorum bundle",
            UpdateQuorumBundleError::UnverifiedBundle { .. }
            | UpdateQuorumBundleError::KeyServiceUnavailable { .. }
            | UpdateQuorumBundleError::NotFound { .. } => "",
        };
        error_response(status, self, fallback)
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
        .with_context(Ctx::primary_org_lookup(Opaque))?;

    if let Some(data) = &req.data {
        org_quorum::verify_upload(data, req.allow_legacy).map_err(|source| {
            let location = std::panic::Location::caller();
            if is_key_service_unavailable(&source) {
                UpdateQuorumBundleError::KeyServiceUnavailable { location, source }
            } else {
                UpdateQuorumBundleError::UnverifiedBundle { location, source }
            }
        })?;
    }
    let bundle = super::update_quorum_bundle(&state.db, org_id, id, req)
        .await
        .with_context(Ctx::update(Opaque))?
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

#[cfg(test)]
mod tests {
    use super::{CreateQuorumBundleError, UpdateQuorumBundleError, is_key_service_unavailable};
    use crate::org_quorum::VerifyUploadError;
    use axum::body::to_bytes;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use caution_error::{ErrorReport, Note, Warning};
    use dterror::BoxError;

    const REGENERATE: &str =
        "Re-generate the bundle with `caution quorum init`, then upload it again.";
    const KEY_SERVICE_UNAVAILABLE: &str =
        "The key service could not check the payload, so nothing was stored.";
    const RETRY_KEY_SERVICE: &str = "Retry when the key service is healthy.";

    /// The error a callee produces when the upload is not a proofed bundle.
    fn parse_failure() -> VerifyUploadError {
        VerifyUploadError::Parse {
            location: std::panic::Location::caller(),
            source: source(),
        }
    }

    /// The error a callee produces when the key service has no policy.
    fn missing_policy() -> VerifyUploadError {
        VerifyUploadError::PolicyPath {
            location: std::panic::Location::caller(),
            source: source(),
        }
    }

    fn source() -> BoxError {
        Box::new(std::io::Error::other("no policy at that path"))
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body is collected");
        serde_json::from_slice(&bytes).expect("body is an error report")
    }

    fn unverified_create() -> CreateQuorumBundleError {
        CreateQuorumBundleError::UnverifiedBundle {
            location: std::panic::Location::caller(),
            source: parse_failure(),
        }
    }

    #[tokio::test]
    async fn an_unverified_upload_reports_the_reason_and_the_fix() {
        let error = unverified_create();

        assert_eq!(error.to_string(), "invalid quorum bundle");

        let report = ErrorReport::from_error(&error);
        assert_eq!(report.error, "invalid quorum bundle");
        assert_eq!(report.errors.len(), 3, "the callee, then its own source");
        assert_eq!(report.errors[1].error, "expected proofed v1 quorum bundle");
        assert_eq!(report.errors[1].notes, vec![Note::from(REGENERATE)]);
        assert!(report.errors[1].warnings.is_empty());
        assert!(
            caution_error::location(&error).is_some(),
            "location provided"
        );

        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            response
                .extensions()
                .get::<sentry_middleware::SentryReportable>()
                .is_some(),
            "the error is reported"
        );
        let body = body_json(response).await;
        assert_eq!(body["error"], "invalid quorum bundle");
        assert_eq!(
            body["errors"][1]["error"],
            "expected proofed v1 quorum bundle"
        );
        assert_eq!(body["errors"][1]["notes"][0], REGENERATE);
    }

    #[tokio::test]
    async fn a_missing_key_service_policy_warns_that_nothing_was_stored() {
        let error = CreateQuorumBundleError::KeyServiceUnavailable {
            location: std::panic::Location::caller(),
            source: missing_policy(),
        };

        assert_eq!(
            error.to_string(),
            "key-service configuration is unavailable"
        );

        let report = ErrorReport::from_error(&error);
        assert_eq!(
            report.errors[1].error,
            "required key-service endpoint or trust policy is not configured"
        );
        assert_eq!(
            report.errors[1].warnings,
            vec![Warning::from(KEY_SERVICE_UNAVAILABLE)]
        );
        assert_eq!(
            report.errors[1].notes,
            vec![Note::from(RETRY_KEY_SERVICE)],
            "the retry condition is the instruction"
        );

        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = body_json(response).await;
        assert_eq!(body["error"], "key-service configuration is unavailable");
        assert_eq!(body["errors"][1]["warnings"][0], KEY_SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn an_update_failure_carries_the_same_split() {
        let unverified = UpdateQuorumBundleError::UnverifiedBundle {
            location: std::panic::Location::caller(),
            source: parse_failure(),
        };
        let unverified = unverified.into_response();
        assert_eq!(unverified.status(), StatusCode::BAD_REQUEST);
        let body = body_json(unverified).await;
        assert_eq!(body["error"], "invalid quorum bundle");
        assert_eq!(body["errors"][1]["notes"][0], REGENERATE);

        let missing_policy = UpdateQuorumBundleError::KeyServiceUnavailable {
            location: std::panic::Location::caller(),
            source: missing_policy(),
        };
        let missing_policy = missing_policy.into_response();
        assert_eq!(missing_policy.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = body_json(missing_policy).await;
        assert_eq!(body["errors"][1]["warnings"][0], KEY_SERVICE_UNAVAILABLE);

        let not_found = UpdateQuorumBundleError::NotFound {
            bundle_id: uuid::Uuid::nil(),
            location: std::panic::Location::caller(),
        };
        let not_found = not_found.into_response();
        assert_eq!(not_found.status(), StatusCode::NOT_FOUND);
        let body = body_json(not_found).await;
        assert_eq!(
            body["error"],
            "quorum bundle 00000000-0000-0000-0000-000000000000 not found"
        );
        assert_eq!(
            body["errors"].as_array().map(Vec::len),
            Some(1),
            "a leaf error has one link"
        );
    }

    #[test]
    fn only_a_policy_failure_blames_the_key_service() {
        use VerifyUploadError as V;

        for key_service in [
            missing_policy(),
            VerifyUploadError::Policy {
                location: std::panic::Location::caller(),
                source: source(),
            },
        ] {
            assert!(
                is_key_service_unavailable(&key_service),
                "the platform cannot check the proof: {key_service}"
            );
        }

        let upload_faults = [
            parse_failure(),
            V::LegacyOptIn {
                location: std::panic::Location::caller(),
            },
            V::LegacyParse {
                location: std::panic::Location::caller(),
                source: source(),
            },
            V::Proof {
                location: std::panic::Location::caller(),
                source: source(),
            },
            V::InvalidBundle {
                location: std::panic::Location::caller(),
            },
            V::Keyring {
                location: std::panic::Location::caller(),
                source: source(),
            },
            V::PublicKey {
                location: std::panic::Location::caller(),
                source: source(),
            },
        ];
        for upload_fault in upload_faults {
            assert!(
                !is_key_service_unavailable(&upload_fault),
                "the upload is at fault: {upload_fault}"
            );
        }
    }

    #[test]
    fn a_lookup_failure_is_withheld() {
        let error = CreateQuorumBundleError::PrimaryOrgLookup {
            opaque: caution_error::Opaque,
            location: std::panic::Location::caller(),
            source: crate::GetUserPrimaryOrgError::NotFound {
                location: std::panic::Location::caller(),
            },
        };
        assert!(
            caution_error::ErrorReport::from_error(&error)
                .errors
                .is_empty(),
            "a 500 root is opaque",
        );
    }
}
