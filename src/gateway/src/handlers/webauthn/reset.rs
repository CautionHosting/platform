// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use time::Duration;
use uuid::Uuid;
use webauthn_rs::prelude::*;
use webauthn_rs_proto::{ResidentKeyRequirement, UserVerificationPolicy};

use crate::db;
use crate::types::*;
use sha2::Digest as _;

use crate::handlers::{
    build_auth_cookies, read_credprops_rk, relax_registration_extensions, MAX_PENDING_CHALLENGES,
    RegisterBeginResponse, RegisterError,
};

#[derive(Debug, Deserialize)]
pub struct ResetRegisterBeginRequest {
    pub token: String,
}

/// Begin a WebAuthn registration ceremony using a valid reset token.
/// The token identifies an existing user whose credentials were cleared by an admin.
#[tracing::instrument(skip_all, err)]
pub async fn begin_reset_register_handler(
    State(state): State<AppState>,
    Json(req): Json<ResetRegisterBeginRequest>,
) -> Result<Json<RegisterBeginResponse>, RegisterError> {
    let token_hex = req.token.trim();
    if token_hex.is_empty() {
        return Err(RegisterError::InvalidInvitation);
    }

    let token_bytes = hex::decode(token_hex).map_err(|_| RegisterError::InvalidInvitation)?;

    let user_id = db::get_valid_reset_token(&state.db, &token_bytes)
        .await
        .map_err(|e| RegisterError::Internal(e))?
        .ok_or(RegisterError::InvalidInvitation)?;

    let token_hash = hex::encode(sha2::Sha256::digest(&token_bytes));

    // Fetch the user's registration info (username + fido2 handle).
    let registration_user = db::get_registration_user(&state.db, user_id)
        .await
        .map_err(|e| RegisterError::Internal(e))?;
    let user_handle = registration_user.fido2_user_handle.ok_or_else(|| {
        RegisterError::Internal(anyhow::anyhow!("User is missing a WebAuthn handle"))
    })?;
    let user_unique_id = Uuid::from_slice(&user_handle).map_err(|e| {
        RegisterError::Internal(anyhow::anyhow!("Failed to parse FIDO2 user handle: {}", e))
    })?;

    let (mut ccr, reg_state) = state
        .webauthn
        .start_securitykey_registration(
            user_unique_id,
            &registration_user.username,
            &registration_user.username,
            None,
            None,
            None,
        )
        .map_err(|e| {
            RegisterError::Internal(anyhow::anyhow!("Failed to start registration: {}", e))
        })?;

    if let Some(ref mut auth_sel) = ccr.public_key.authenticator_selection {
        auth_sel.user_verification = UserVerificationPolicy::Preferred;
        auth_sel.resident_key = Some(ResidentKeyRequirement::Preferred);
    }
    relax_registration_extensions(&mut ccr.public_key.extensions);

    let state_key = Uuid::new_v4().to_string();
    let pending = PendingPasskeyRegistration {
        reg_state,
        user_id,
        name: None,
        expires_at: time::OffsetDateTime::now_utc() + Duration::minutes(2),
        token_hash: Some(token_hash),
    };

    {
        let mut reg_states = state.passkey_reg_states.write().await;
        if reg_states.len() >= MAX_PENDING_CHALLENGES {
            return Err(RegisterError::TooManyPending);
        }
        reg_states.insert(state_key.clone(), pending);
    }

    Ok(Json(RegisterBeginResponse {
        challenge: ccr,
        session: state_key,
    }))
}

/// Finish a WebAuthn registration ceremony initiated via reset token.
/// Marks the token as used and saves the new credential.
#[tracing::instrument(skip_all, err)]
pub async fn finish_reset_register_handler(
    State(state): State<AppState>,
    Json(req): Json<serde_json::Value>,
) -> Result<Response, RegisterError> {
    let session_key = req
        .get("session")
        .and_then(|v| v.as_str())
        .ok_or(RegisterError::NoRegistrationState)?
        .to_string();

    let pending = state
        .passkey_reg_states
        .write()
        .await
        .remove(&session_key)
        .ok_or(RegisterError::NoRegistrationState)?;

    if time::OffsetDateTime::now_utc() > pending.expires_at {
        return Err(RegisterError::ChallengeExpired);
    }

    let reg_response: RegisterPublicKeyCredential =
        serde_json::from_value(req.clone()).map_err(|e| {
            RegisterError::Internal(anyhow::anyhow!(
                "Failed to parse registration response: {}",
                e
            ))
        })?;

    let seckey = state
        .webauthn
        .finish_securitykey_registration(&reg_response, &pending.reg_state)
        .map_err(|e| {
            RegisterError::Internal(anyhow::anyhow!("Failed to finish registration: {}", e))
        })?;

    let credential_id = seckey.cred_id().clone();

    let passkey_json = serde_json::to_vec(&seckey)
        .map_err(|e| RegisterError::Internal(anyhow::anyhow!("Failed to serialize credential: {}", e)))?;
    let transports = req
        .get("transports")
        .cloned()
        .filter(|value| value.is_array());
    let resident = read_credprops_rk(&reg_response);

    // Atomic: credential check + INSERT + token mark-used + session creation in a
    // single transaction. If any step fails the entire operation rolls back.
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| RegisterError::Internal(anyhow::anyhow!(e)))?;

    if db::credential_exists(&mut *tx, &credential_id)
        .await
        .map_err(|e| RegisterError::Internal(e))?
    {
        return Err(RegisterError::CredentialAlreadyRegistered);
    }

    db::save_fido2_credential(
        &mut *tx,
        &credential_id,
        pending.user_id,
        &passkey_json,
        None,
        Some("none"),
        None,
        0,
        transports,
        None,
        resident,
    )
    .await
    .map_err(|e| RegisterError::Internal(e))?;

    // Mark the reset token as used and verify it was still valid.
    // If a concurrent reset invalidated this specific token between begin and
    // finish, or if it expired during the ceremony window, rows_affected will
    // be 0 and we roll back (credential not saved).
    let token_hash = pending.token_hash.as_deref().ok_or_else(|| {
        RegisterError::Internal(anyhow::anyhow!(
            "reset registration state missing token_hash"
        ))
    })?;

    let rows_affected = db::consume_reset_token(&mut *tx, token_hash)
        .await
        .map_err(|e| RegisterError::Internal(e))?;

    if rows_affected == 0 {
        return Err(RegisterError::InvalidInvitation);
    }

    let session_id = db::generate_session_id();
    let csrf_token = crate::csrf::derive_csrf_token(&session_id, &state.csrf_secret);
    let expires_at = time::OffsetDateTime::now_utc() + Duration::hours(state.session_timeout_hours);

    db::create_auth_session(&mut *tx, &session_id, &credential_id, expires_at)
        .await
        .map_err(|e| RegisterError::Internal(e))?;

    tx.commit()
        .await
        .map_err(|e| RegisterError::Internal(anyhow::anyhow!(e)))?;

    let credential_id_hex = hex::encode(&credential_id);

    let response_body = RegisterFinishResponse {
        status: "success".to_string(),
        credential_id: credential_id_hex,
        expires_at: expires_at.to_string(),
    };

    let secure = std::env::var("ENVIRONMENT")
        .map(|e| e != "development")
        .unwrap_or(true);
    let (session_cookie, csrf_cookie) = build_auth_cookies(
        &session_id,
        &csrf_token,
        state.session_timeout_hours,
        secure,
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&session_cookie).unwrap(),
    );
    headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&csrf_cookie).unwrap(),
    );

    let body = serde_json::to_string(&response_body)
        .map_err(|e| RegisterError::Internal(anyhow::anyhow!("Failed to serialize response: {}", e)))?;

    Ok((StatusCode::OK, headers, body).into_response())
}
