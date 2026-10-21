// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial

//! HTTP handlers for org quorum bundles, mounted under `/quorum-bundles`.

use super::{OrgQuorumMember, list_participants};
use crate::{AppState, AuthContext, get_user_primary_org};
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
