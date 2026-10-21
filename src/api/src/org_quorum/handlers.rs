// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial

//! HTTP handlers for org quorum bundles, mounted under `/quorum-bundles`.

use super::{
    GenerateOrgQuorumBundleRequest, OrgQuorumError, OrgQuorumMember, generate_org_quorum_bundle,
    list_participants,
};
use crate::{AppState, AuthContext, cryptographic_bundles::QuorumBundle, get_user_primary_org};
use axum::{
    Extension, Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use dterror::{BoxError, CtxError, Location, ResultExt};
use std::sync::Arc;
use uuid::Uuid;

/// Failure modes for [`list_org_quorum_participants`]: one variant per fallible
/// branch. Both callees return their own typed errors, boxed here at the boundary.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ListOrgQuorumParticipantsError {
    #[error("could not look up the primary organization for user {user_id} [{location}]")]
    PrimaryOrgLookup {
        user_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to list quorum participants for organization {org_id} [{location}]")]
    ListParticipants {
        org_id: Uuid,
        user_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for ListOrgQuorumParticipantsError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            ListOrgQuorumParticipantsError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "unable to resolve organization",
            ),
            ListOrgQuorumParticipantsError::ListParticipants { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "unable to list quorum participants",
            ),
        };
        sentry_middleware::error_response(status, body, self)
    }
}

#[tracing::instrument(skip_all, err(Debug), fields(user_id = %auth.user_id))]
pub(crate) async fn list_org_quorum_participants(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<OrgQuorumMember>>, ListOrgQuorumParticipantsError> {
    use ListOrgQuorumParticipantsErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup(auth.user_id))?;

    let participants = list_participants(&state.db, org_id)
        .await
        .with_context(Ctx::list_participants(org_id, auth.user_id))?;
    Ok(Json(participants))
}

/// Failure modes for [`create_org_user_quorum_bundle`]: one variant per fallible
/// branch. Bundle generation has many client-visible failure modes, so its
/// client status and text are carried through rather than flattened into one.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum CreateOrgUserQuorumBundleError {
    #[error("could not look up the primary organization for user {user_id} [{location}]")]
    PrimaryOrgLookup {
        user_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to generate a quorum bundle for organization {org_id} [{location}]")]
    Generate {
        org_id: Uuid,
        user_id: Uuid,
        status: StatusCode,
        message: &'static str,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl CreateOrgUserQuorumBundleError {
    /// Capture the callee's client status and text so the HTTP response stays honest.
    #[track_caller]
    fn generate(org_id: Uuid, user_id: Uuid, source: OrgQuorumError) -> Self {
        let (status, message) = source.client_response();
        Self::Generate {
            org_id,
            user_id,
            status,
            message,
            location: std::panic::Location::caller(),
            source: Box::new(source),
        }
    }
}

impl IntoResponse for CreateOrgUserQuorumBundleError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            CreateOrgUserQuorumBundleError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "unable to resolve organization",
            ),
            CreateOrgUserQuorumBundleError::Generate {
                status, message, ..
            } => (*status, *message),
        };
        sentry_middleware::error_response(status, body, self)
    }
}

#[tracing::instrument(skip_all, err(Debug), fields(user_id = %auth.user_id))]
pub(crate) async fn create_org_user_quorum_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<GenerateOrgQuorumBundleRequest>,
) -> Result<Json<QuorumBundle>, CreateOrgUserQuorumBundleError> {
    use CreateOrgUserQuorumBundleErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup(auth.user_id))?;

    let bundle = generate_org_quorum_bundle(&state.db, org_id, auth.user_id, req)
        .await
        .map_err(|source| CreateOrgUserQuorumBundleError::generate(org_id, auth.user_id, source))?;
    Ok(Json(bundle))
}
