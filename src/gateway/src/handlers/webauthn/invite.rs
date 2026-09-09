// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    extract::{Query, State},
    Json,
};

use crate::db;
use crate::types::*;

use super::super::{RegisterBeginResponse, RegisterError, RegisterErrorCtx as Ctx};
use super::register::begin_registration_challenge;
use dterror::ResultExt;

#[tracing::instrument(skip_all, err)]
pub async fn invite_preview_handler(
    State(state): State<AppState>,
    Query(params): Query<InvitePreviewQuery>,
) -> Result<Json<InvitePreviewResponse>, RegisterError> {
    let token = params.token.trim();
    if token.is_empty() {
        return Err(RegisterError::InvalidInvitation {
            location: std::panic::Location::caller(),
        });
    }

    let token_hash = db::hash_invitation_token(token).ok_or(RegisterError::InvalidInvitation {
        location: std::panic::Location::caller(),
    })?;
    let invitation = db::get_valid_invitation(&state.db, &token_hash)
        .await
        .with_context(Ctx::internal())?
        .ok_or(RegisterError::InvalidInvitation {
            location: std::panic::Location::caller(),
        })?;

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
        return Err(RegisterError::InvalidInvitation {
            location: std::panic::Location::caller(),
        });
    }

    let token_hash = db::hash_invitation_token(token).ok_or(RegisterError::InvalidInvitation {
        location: std::panic::Location::caller(),
    })?;
    let invitation = db::get_valid_invitation(&state.db, &token_hash)
        .await
        .with_context(Ctx::internal())?
        .ok_or(RegisterError::InvalidInvitation {
            location: std::panic::Location::caller(),
        })?;

    // Validate username if provided, otherwise use email
    let username_for_registration = if let Some(username) = req.username {
        let username = username.trim().to_lowercase();
        if let Err(e) = crate::validation::validate_username(&username) {
            return Err(RegisterError::InvalidUsername {
                username_error: e.to_string(),
                location: std::panic::Location::caller(),
            });
        }
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
