// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use dterror::{BoxError, CtxError, Location, ResultExt};
use serde::Deserialize;
use time::Duration;
use uuid::Uuid;
use webauthn_rs::prelude::*;
use webauthn_rs_proto::{ResidentKeyRequirement, UserVerificationPolicy};

use crate::db;
use crate::types::*;
use sha2::Digest as _;

use crate::handlers::{
    build_auth_cookies, read_credprops_rk, relax_registration_extensions, DomainError,
    RegisterBeginResponse, MAX_PENDING_CHALLENGES,
};

/// Error type for the reset-token registration flow only. Deliberately its own
/// type (rather than reusing `RegisterError`): this flow has no alpha code and
/// no invitation — it is scoped entirely by a single admin-issued reset token,
/// so the token failure mode is named `InvalidToken`, not `InvalidInvitation`.
/// Strict dterror convention: every variant carries `#[location]`; source-bearing
/// variants use `.with_context(Ctx::…)` at call sites; source-less (domain)
/// variants are hand-built with `std::panic::Location::caller()`.
#[derive(Debug, thiserror::Error, CtxError)]
pub enum ResetRegisterError {
    #[error("This token is invalid, expired, or has already been used. [{location}]")]
    InvalidToken {
        #[location]
        location: Location,
    },

    #[error("Registration challenge has expired. Please try again. [{location}]")]
    ChallengeExpired {
        #[location]
        location: Location,
    },

    #[error("No matching registration state found. Please start over. [{location}]")]
    NoRegistrationState {
        #[location]
        location: Location,
    },

    #[error("This security key is already registered. Each key can only be registered once. [{location}]")]
    CredentialAlreadyRegistered {
        #[location]
        location: Location,
    },

    #[error("Too many pending registrations. Please try again later. [{location}]")]
    TooManyPending {
        #[location]
        location: Location,
    },

    #[error("User is missing a WebAuthn handle and cannot re-register [{location}]")]
    MissingWebauthnHandle {
        #[location]
        location: Location,
    },

    #[error("Invalid registration request body. [{location}]")]
    InvalidPayload {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("internal error [{location}]")]
    Internal {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

impl IntoResponse for ResetRegisterError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::InvalidToken { .. } => (
                StatusCode::BAD_REQUEST,
                "This token is invalid, expired, or has already been used.".to_string(),
            ),
            Self::InvalidPayload { .. } => (
                StatusCode::BAD_REQUEST,
                "Invalid registration request body.".to_string(),
            ),
            Self::ChallengeExpired { .. } => (
                StatusCode::GONE,
                "Registration challenge has expired. Please try again.".to_string(),
            ),
            Self::NoRegistrationState { .. } => (
                StatusCode::GONE,
                "No matching registration state found. Please start over.".to_string(),
            ),
            Self::MissingWebauthnHandle { .. } => {
                tracing::error!(?self, "Reset registration error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal error occurred".to_string(),
                )
            }
            Self::CredentialAlreadyRegistered { .. } => (
                StatusCode::CONFLICT,
                "This security key is already registered. Each key can only be registered once."
                    .to_string(),
            ),
            Self::TooManyPending { .. } => (
                StatusCode::TOO_MANY_REQUESTS,
                "Too many pending registrations. Please try again later.".to_string(),
            ),
            Self::Internal { .. } => {
                tracing::error!(?self, "Reset registration error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal error occurred".to_string(),
                )
            }
        };
        (status, message).into_response()
    }
}

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
) -> Result<Json<RegisterBeginResponse>, ResetRegisterError> {
    use ResetRegisterErrorCtx as Ctx;

    let token_hex = req.token.trim();
    if token_hex.is_empty() {
        return Err(ResetRegisterError::InvalidToken {
            location: std::panic::Location::caller(),
        });
    }

    let token_bytes = hex::decode(token_hex).map_err(|_| ResetRegisterError::InvalidToken {
        location: std::panic::Location::caller(),
    })?;

    let user_id = db::get_valid_reset_token(&state.db, &token_bytes)
        .await
        .with_context(Ctx::internal())?
        .ok_or(ResetRegisterError::InvalidToken {
            location: std::panic::Location::caller(),
        })?;

    let token_hash = hex::encode(sha2::Sha256::digest(&token_bytes));

    // Fetch the user's registration info (username + fido2 handle).
    let registration_user = db::get_registration_user(&state.db, user_id)
        .await
        .with_context(Ctx::internal())?;
    let user_handle =
        registration_user
            .fido2_user_handle
            .ok_or(ResetRegisterError::MissingWebauthnHandle {
                location: std::panic::Location::caller(),
            })?;
    let user_unique_id = Uuid::from_slice(&user_handle).with_context(Ctx::internal())?;

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
        .with_context(Ctx::internal())?;

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
            return Err(ResetRegisterError::TooManyPending {
                location: std::panic::Location::caller(),
            });
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
) -> Result<Response, ResetRegisterError> {
    use ResetRegisterErrorCtx as Ctx;

    let session_key = req
        .get("session")
        .and_then(|v| v.as_str())
        .ok_or(ResetRegisterError::NoRegistrationState {
            location: std::panic::Location::caller(),
        })?
        .to_string();

    let pending = state
        .passkey_reg_states
        .write()
        .await
        .remove(&session_key)
        .ok_or(ResetRegisterError::NoRegistrationState {
            location: std::panic::Location::caller(),
        })?;

    if time::OffsetDateTime::now_utc() > pending.expires_at {
        return Err(ResetRegisterError::ChallengeExpired {
            location: std::panic::Location::caller(),
        });
    }

    let reg_response: RegisterPublicKeyCredential =
        serde_json::from_value(req.clone()).with_context(Ctx::invalid_payload())?;

    let seckey = state
        .webauthn
        .finish_securitykey_registration(&reg_response, &pending.reg_state)
        .with_context(Ctx::internal())?;

    let credential_id = seckey.cred_id().clone();

    let passkey_json = serde_json::to_vec(&seckey).with_context(Ctx::internal())?;
    let transports = req
        .get("transports")
        .cloned()
        .filter(|value| value.is_array());
    let resident = read_credprops_rk(&reg_response);

    // Atomic: credential check + INSERT + token mark-used + session creation in a
    // single transaction. If any step fails the entire operation rolls back.
    let mut tx = state.db.begin().await.with_context(Ctx::internal())?;

    if db::credential_exists(&mut *tx, &credential_id)
        .await
        .with_context(Ctx::internal())?
    {
        return Err(ResetRegisterError::CredentialAlreadyRegistered {
            location: std::panic::Location::caller(),
        });
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
    .with_context(Ctx::internal())?;

    // Mark the reset token as used and verify it was still valid.
    // If a concurrent reset invalidated this specific token between begin and
    // finish, or if it expired during the ceremony window, rows_affected will
    // be 0 and we roll back (credential not saved).
    let token_hash = pending
        .token_hash
        .as_deref()
        .ok_or_else(|| ResetRegisterError::Internal {
            source: Box::new(DomainError("reset registration state missing token_hash")),
            location: std::panic::Location::caller(),
        })?;

    let rows_affected = db::consume_reset_token(&mut *tx, token_hash)
        .await
        .with_context(Ctx::internal())?;

    if rows_affected == 0 {
        return Err(ResetRegisterError::InvalidToken {
            location: std::panic::Location::caller(),
        });
    }

    let session_id = db::generate_session_id();
    let csrf_token = crate::csrf::derive_csrf_token(&session_id, &state.csrf_secret);
    let expires_at = time::OffsetDateTime::now_utc() + Duration::hours(state.session_timeout_hours);

    db::create_auth_session(&mut *tx, &session_id, &credential_id, expires_at)
        .await
        .with_context(Ctx::internal())?;

    tx.commit().await.with_context(Ctx::internal())?;

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

    let body = serde_json::to_string(&response_body).with_context(Ctx::internal())?;

    Ok((StatusCode::OK, headers, body).into_response())
}
