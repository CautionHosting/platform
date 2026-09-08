// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    extract::{Query, State},
    Json,
};

use crate::db;
use crate::types::*;

use super::register::begin_registration_challenge;
use super::super::{RegisterBeginResponse, RegisterError};

#[tracing::instrument(skip_all, err)]
pub async fn invite_preview_handler(
    State(state): State<AppState>,
    Query(params): Query<InvitePreviewQuery>,
) -> Result<Json<InvitePreviewResponse>, RegisterError> {
    let token = params.token.trim();
    if token.is_empty() {
        return Err(RegisterError::InvalidInvitation);
    }

    let token_hash = db::hash_invitation_token(token).ok_or(RegisterError::InvalidInvitation)?;
    let invitation = db::get_valid_invitation(&state.db, &token_hash)
        .await
        .map_err(|e| RegisterError::Internal(e))?
        .ok_or(RegisterError::InvalidInvitation)?;

    Ok(Json(InvitePreviewResponse {
        email: invitation.email,
        organization_name: invitation.organization_name,
        expires_at: invitation.expires_at.to_string(),
    }))
}

#[tracing::instrument(skip_all, err)]
pub async fn begin_invite_register_handler(
    State(state): State<AppState>,
    Json(req): Json<InviteRegisterBeginRequest>,
) -> Result<Json<RegisterBeginResponse>, RegisterError> {
    let token = req.token.trim();
    if token.is_empty() {
        return Err(RegisterError::InvalidInvitation);
    }

    let token_hash = db::hash_invitation_token(token).ok_or(RegisterError::InvalidInvitation)?;
    let invitation = db::get_valid_invitation(&state.db, &token_hash)
        .await
        .map_err(|e| RegisterError::Internal(e))?
        .ok_or(RegisterError::InvalidInvitation)?;

    // Validate username if provided, otherwise use email
    let username_for_registration = if let Some(username) = req.username {
        let username = username.trim().to_lowercase();
        crate::validation::validate_username(&username)
            .map_err(|e| RegisterError::InvalidUsername(e.to_string()))?;
        username
    } else {
        invitation.email.clone()
    };

    begin_registration_challenge(
        &state,
        username_for_registration,
        PendingRegistrationKind::OrganizationInvite {
            invitation_id: invitation.id,
            token_hash,
        },
    )
    .await
}
