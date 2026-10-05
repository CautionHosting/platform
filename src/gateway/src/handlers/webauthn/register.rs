// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use time::Duration;
use uuid::Uuid;
use webauthn_rs::prelude::*;
use webauthn_rs_proto::{ResidentKeyRequirement, UserVerificationPolicy};

use crate::db::{self, DbErrorKind};
use crate::types::*;

use super::super::{
    build_auth_cookies, read_credprops_rk, relax_registration_extensions, RegisterBeginResponse,
    RegisterError, RegisterErrorCtx as Ctx, MAX_PENDING_CHALLENGES,
};
use dterror::ResultExt;

#[tracing::instrument(skip_all, err)]
pub async fn begin_register_handler(
    State(state): State<AppState>,
    Json(req): Json<crate::types::RegisterBeginRequest>,
) -> Result<Json<RegisterBeginResponse>, RegisterError> {
    tracing::debug!("Registration started with alpha code");

    let alpha_code_id = db::validate_alpha_code(&state.db, &req.alpha_code)
        .await
        .with_context(Ctx::internal())?
        .ok_or(RegisterError::InvalidAccessCode {
            location: std::panic::Location::caller(),
        })?;

    tracing::debug!("Alpha code validated: id={}", alpha_code_id);

    let username = req.username.trim().to_lowercase();
    if let Err(source) = crate::validation::validate_username(&username) {
        return Err(RegisterError::InvalidUsername {
            location: std::panic::Location::caller(),
            source: Box::new(source),
        });
    }

    begin_registration_challenge(
        &state,
        username,
        PendingRegistrationKind::AlphaCode { alpha_code_id },
    )
    .await
}

#[tracing::instrument(skip_all, err)]
pub(crate) async fn begin_registration_challenge(
    state: &AppState,
    username: String,
    kind: PendingRegistrationKind,
) -> Result<Json<RegisterBeginResponse>, RegisterError> {
    // Fetch ALL existing credential IDs to pass as excludeCredentials
    // This prevents the same authenticator from registering multiple accounts
    let existing_cred_ids = db::get_all_credential_ids(&state.db)
        .await
        .with_context(Ctx::internal())?;
    let exclude_credentials: Vec<CredentialID> = existing_cred_ids
        .into_iter()
        .map(CredentialID::from)
        .collect();

    tracing::debug!(
        "Excluding {} existing credentials from registration",
        exclude_credentials.len()
    );

    let user_unique_id = Uuid::new_v4();

    let (mut ccr, reg_state) = state
        .webauthn
        .start_securitykey_registration(
            user_unique_id,
            &username,
            &username,
            Some(exclude_credentials).filter(|v| !v.is_empty()),
            None,
            None,
        )
        .with_context(Ctx::challenge_failed())?;

    // Override authenticator selection to be maximally compatible:
    // - UV Preferred: authenticators that support PIN/biometric will use it, but won't block
    //   basic authenticators. Organizations can require PIN later via security settings.
    // - Resident key Preferred: allows password managers (which create discoverable credentials)
    //   while still accepting hardware keys that don't support credential storage.
    // - Clear extensions: start_securitykey_registration sets credProtect to
    //   UserVerificationRequired which conflicts with UV Preferred and causes Firefox/Chrome
    //   to reject PIN-less smart cards and password manager registration.
    if let Some(ref mut auth_sel) = ccr.public_key.authenticator_selection {
        auth_sel.user_verification = UserVerificationPolicy::Preferred;
        auth_sel.resident_key = Some(ResidentKeyRequirement::Preferred);
    }
    relax_registration_extensions(&mut ccr.public_key.extensions);

    tracing::debug!(
        "Registration challenge created for RP {}",
        ccr.public_key.rp.id
    );

    let state_key = user_unique_id.to_string();
    let pending = crate::types::PendingRegistration {
        reg_state,
        kind,
        username,
        expires_at: time::OffsetDateTime::now_utc() + Duration::minutes(2),
    };
    {
        let mut reg_states = state.reg_states.write().await;
        if reg_states.len() >= MAX_PENDING_CHALLENGES {
            return Err(RegisterError::TooManyPending {
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

#[tracing::instrument(skip_all, err)]
pub(crate) async fn finish_register_handler(
    State(state): State<AppState>,
    connect_info: ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> Result<Response, RegisterError> {
    let session_key = req
        .get("session")
        .and_then(|v| v.as_str())
        .ok_or(RegisterError::NoRegistrationState {
            location: std::panic::Location::caller(),
        })?
        .to_string();

    let pending = state
        .reg_states
        .read()
        .await
        .get(&session_key)
        .cloned()
        .ok_or(RegisterError::NoRegistrationState {
            location: std::panic::Location::caller(),
        })?;

    // Check if the registration challenge has expired
    if time::OffsetDateTime::now_utc() > pending.expires_at {
        state.reg_states.write().await.remove(&session_key);
        return Err(RegisterError::ChallengeExpired {
            location: std::panic::Location::caller(),
        });
    }

    let reg_response: RegisterPublicKeyCredential =
        serde_json::from_value(req.clone()).with_context(Ctx::invalid_payload())?;

    let seckey = state
        .webauthn
        .finish_securitykey_registration(&reg_response, &pending.reg_state)
        .with_context(Ctx::challenge_failed())?;

    let credential_id = seckey.cred_id().clone();
    if db::credential_exists(&state.db, &credential_id)
        .await
        .with_context(Ctx::internal())?
    {
        tracing::warn!("Registration rejected - credential already registered");
        return Err(RegisterError::CredentialAlreadyRegistered {
            location: std::panic::Location::caller(),
        });
    }

    state.reg_states.write().await.remove(&session_key);

    let user_unique_id = Uuid::parse_str(&session_key).with_context(Ctx::internal())?;

    let legal = db::SignupLegalContext {
        ip_address: Some(connect_info.0.ip().to_string()),
        user_agent: headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
    };

    let user_id = match pending.kind {
        PendingRegistrationKind::AlphaCode { alpha_code_id } => {
            let user_id = match db::create_user(
                &state.db,
                &user_unique_id.as_bytes()[..],
                alpha_code_id,
                &pending.username,
                &legal,
            )
            .await
            {
                Ok(user_id) => user_id,
                Err(e) if e.kind == DbErrorKind::UsernameTaken => {
                    return Err(RegisterError::UsernameTaken {
                        location: std::panic::Location::caller(),
                    });
                }
                Err(e) if e.kind == DbErrorKind::AlphaCodeUnavailable => {
                    return Err(RegisterError::InvalidAccessCode {
                        location: std::panic::Location::caller(),
                    });
                }
                Err(source) => {
                    return Err(RegisterError::Internal {
                        source: Box::new(source),
                        location: std::panic::Location::caller(),
                    });
                }
            };

            tracing::debug!("User registered and alpha code redeemed");
            user_id
        }
        PendingRegistrationKind::OrganizationInvite {
            invitation_id,
            token_hash,
        } => {
            let user_id = match db::accept_invitation_and_create_user(
                &state.db,
                invitation_id,
                &token_hash,
                &user_unique_id.as_bytes()[..],
                &pending.username,
                &legal,
            )
            .await
            {
                Ok(user_id) => user_id,
                Err(e) if e.kind == DbErrorKind::UsernameTaken => {
                    return Err(RegisterError::UsernameTaken {
                        location: std::panic::Location::caller(),
                    });
                }
                Err(source) => {
                    return Err(RegisterError::Internal {
                        source: Box::new(source),
                        location: std::panic::Location::caller(),
                    });
                }
            };

            tracing::debug!("User registered from organization invitation");
            user_id
        }
    };

    let passkey_json = serde_json::to_vec(&seckey).with_context(Ctx::internal())?;
    let resident = read_credprops_rk(&reg_response);

    db::save_fido2_credential(
        &state.db,
        &credential_id,
        user_id,
        &passkey_json,
        None,
        Some("none"),
        None,
        0,
        None,
        None,
        resident,
    )
    .await
    .with_context(Ctx::internal())?;

    let credential_id_hex = hex::encode(&credential_id);

    let session_id = db::generate_session_id();
    let csrf_token = crate::csrf::derive_csrf_token(&session_id, &state.csrf_secret);
    let expires_at = time::OffsetDateTime::now_utc() + Duration::hours(state.session_timeout_hours);

    db::create_auth_session(&state.db, &session_id, &credential_id, expires_at)
        .await
        .with_context(Ctx::internal())?;

    tracing::debug!(
        "Registration complete with automatic session creation (expires in {} hours)",
        state.session_timeout_hours
    );

    // Build the response (session_id is in Set-Cookie header, not body)
    let response_body = RegisterFinishResponse {
        status: "success".to_string(),
        credential_id: credential_id_hex,
        expires_at: expires_at.to_string(),
    };

    // Check if we're in production (HTTPS) - use secure cookies
    let secure = std::env::var("ENVIRONMENT")
        .map(|e| e != "development")
        .unwrap_or(true);
    let (session_cookie, csrf_cookie) = build_auth_cookies(
        &session_id,
        &csrf_token,
        state.session_timeout_hours,
        secure,
    );

    let body = serde_json::to_string(&response_body).with_context(Ctx::internal())?;

    // Use HeaderMap with append to properly set multiple Set-Cookie headers
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

    Ok((StatusCode::OK, headers, body).into_response())
}
