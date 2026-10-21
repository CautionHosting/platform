// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial

//! HTTP handlers for org quorum bundles, mounted under `/quorum-bundles`.

use super::{
    AssembleRequestError, GenerateOrgQuorumBundleError, GenerateOrgQuorumBundleRequest,
    OrgQuorumMember, PostError, ResolveHoldersError, SendError, certificates::DeriveError,
    generate_org_quorum_bundle, list_participants,
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
/// branch. Generation has many failure modes, so the handler downcasts its boxed
/// source to choose the client status; the callee itself is status-free.
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
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for CreateOrgUserQuorumBundleError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            CreateOrgUserQuorumBundleError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "unable to resolve organization",
            ),
            CreateOrgUserQuorumBundleError::Generate { source, .. } => {
                generate_client_response(source.downcast_ref())
            }
        };
        sentry_middleware::error_response(status, body, self)
    }
}

/// Client status and text for a failed generation, chosen from the callee's error.
fn generate_client_response(
    error: Option<&GenerateOrgQuorumBundleError>,
) -> (StatusCode, &'static str) {
    use GenerateOrgQuorumBundleError as E;
    match error {
        Some(E::ValidateRequest { .. }) => (StatusCode::BAD_REQUEST, "invalid quorum request"),
        Some(E::ClientPolicy { .. }) => (
            StatusCode::BAD_REQUEST,
            "invalid client Keymaker PCR policy",
        ),
        Some(E::ResolveHolders { source, .. }) => {
            use ResolveHoldersError as R;
            match source.downcast_ref::<R>() {
                Some(
                    R::NotMember { .. }
                    | R::PgpKeyMissing { .. }
                    | R::Credentials { .. }
                    | R::Keyring { .. },
                ) => (StatusCode::BAD_REQUEST, "invalid quorum holder selection"),
                Some(
                    R::MembershipQuery { .. } | R::PgpKeyQuery { .. } | R::CredentialsQuery { .. },
                )
                | None => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
            }
        }
        Some(E::KeymakerUrl { .. } | E::PolicyPath { .. } | E::LoadPolicy { .. }) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "key-service configuration is unavailable",
        ),
        Some(E::ClientBuild { .. } | E::Encode { .. } | E::Store { .. }) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
        Some(E::Derive { source, .. }) => {
            use DeriveError as D;
            match source.downcast_ref::<D>() {
                Some(D::Send { source, .. }) => send_client_response(source.downcast_ref()),
                Some(
                    D::ServiceUrl { .. }
                    | D::PolicyPath { .. }
                    | D::Policy { .. }
                    | D::CaPath { .. }
                    | D::CaRead { .. }
                    | D::CaParse { .. }
                    | D::CaPrivate { .. }
                    | D::Token { .. }
                    | D::IssuanceRequest { .. },
                ) => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "certificate-service configuration is unavailable",
                ),
                Some(D::VerifyProof { .. } | D::VerifyCertificates { .. }) | None => (
                    StatusCode::BAD_GATEWAY,
                    "certificate-service response could not be verified; generation was not retried",
                ),
            }
        }
        Some(E::AssembleRequest { source, .. }) => {
            use AssembleRequestError as A;
            match source.downcast_ref::<A>() {
                Some(A::Keyring { .. }) => {
                    (StatusCode::BAD_REQUEST, "invalid quorum holder selection")
                }
                Some(A::MissingDerived { .. } | A::UnexpectedDerived { .. }) | None => (
                    StatusCode::BAD_GATEWAY,
                    "key service returned an invalid response; generation was not retried",
                ),
            }
        }
        Some(E::VerifyProof { .. } | E::CheckResponse { .. }) => (
            StatusCode::BAD_GATEWAY,
            "key service returned an invalid response; generation was not retried",
        ),
        Some(E::Post { source, .. }) => match source.downcast_ref::<PostError>() {
            Some(PostError::Send { source, .. }) => send_client_response(source.downcast_ref()),
            None => (
                StatusCode::BAD_GATEWAY,
                "key-service request failed; generation was not retried",
            ),
        },
        Some(E::ClientPolicyProof { .. }) => (
            StatusCode::CONFLICT,
            "Keymaker proof does not satisfy the client's trusted Keymaker policy",
        ),
        None => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

/// Client status and text for a failed key-service call.
fn send_client_response(error: Option<&SendError>) -> (StatusCode, &'static str) {
    use SendError as S;
    match error {
        Some(S::RequestTimeout { .. } | S::ResponseTimeout { .. }) => (
            StatusCode::GATEWAY_TIMEOUT,
            "key service timed out; generation was not retried",
        ),
        Some(S::Upstream {
            upstream_status, ..
        }) => match upstream_status {
            429 => (
                StatusCode::TOO_MANY_REQUESTS,
                "key service is rate limited; generation was not retried",
            ),
            503 => (
                StatusCode::SERVICE_UNAVAILABLE,
                "key service is unavailable; generation was not retried",
            ),
            _ => (
                StatusCode::BAD_GATEWAY,
                "key service returned an error; generation was not retried",
            ),
        },
        Some(S::Request { .. } | S::Response { .. }) | None => (
            StatusCode::BAD_GATEWAY,
            "key-service request failed; generation was not retried",
        ),
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
        .with_context(Ctx::generate(org_id, auth.user_id))?;
    Ok(Json(bundle))
}
