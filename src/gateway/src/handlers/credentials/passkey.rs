// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::db;
use crate::handlers::{
    authenticate_session, read_credprops_rk, relax_registration_extensions, MAX_PENDING_CHALLENGES,
    RegisterBeginResponse, SignRequestError,
};
use crate::types::*;
use axum::{
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use time::Duration;
use uuid::Uuid;
use webauthn_rs::prelude::*;
use webauthn_rs_proto::{ResidentKeyRequirement, UserVerificationPolicy};

#[derive(Debug, Serialize)]
pub struct PasskeySummary {
    pub id: Uuid,
    pub name: Option<String>,
    pub credential_id: String,
    pub kind: String,
    pub transports: Vec<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub is_current_session: bool,
}

#[derive(Debug, Serialize)]
pub struct PasskeyFinishResponse {
    pub status: String,
    pub credential_id: String,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyBeginRequest {
    pub name: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum PasskeyError {
    #[error("No matching passkey registration state found. Please start over.")]
    NoRegistrationState,
    #[error("Passkey registration challenge has expired. Please try again.")]
    ChallengeExpired,
    #[error("This passkey is already registered.")]
    CredentialAlreadyRegistered,
    #[error("Too many pending passkey registrations. Please try again later.")]
    TooManyPending,
    #[error("Passkey not found.")]
    CredentialNotFound,
    #[error("You must keep at least one passkey on your account.")]
    LastCredential,
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Forbidden(String),
    #[error(transparent)]
    Auth(#[from] SignRequestError),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for PasskeyError {
    fn into_response(self) -> Response {
        match self {
            Self::Auth(err) => err.into_response(),
            Self::NoRegistrationState => (StatusCode::GONE, self.to_string()).into_response(),
            Self::ChallengeExpired => (StatusCode::GONE, self.to_string()).into_response(),
            Self::CredentialAlreadyRegistered => {
                (StatusCode::CONFLICT, self.to_string()).into_response()
            }
            Self::TooManyPending => {
                (StatusCode::TOO_MANY_REQUESTS, self.to_string()).into_response()
            }
            Self::CredentialNotFound => (StatusCode::NOT_FOUND, self.to_string()).into_response(),
            Self::LastCredential => (StatusCode::CONFLICT, self.to_string()).into_response(),
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, message).into_response(),
            Self::Forbidden(message) => (StatusCode::FORBIDDEN, message).into_response(),
            Self::Internal(err) => {
                tracing::error!(?err, "Passkey management error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal error occurred",
                )
                    .into_response()
            }
        }
    }
}

#[tracing::instrument(skip_all)]
fn parse_transports(transport: Option<&serde_json::Value>) -> Vec<String> {
    transport
        .and_then(|value| value.as_array())
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

#[tracing::instrument(skip_all)]
fn passkey_kind_from_transports(transports: &[String]) -> &'static str {
    if transports.is_empty() {
        "Authenticator"
    } else if transports.iter().any(|transport| transport == "internal") {
        "Passkey"
    } else {
        "Security key"
    }
}

#[tracing::instrument(skip_all)]
fn get_session_id_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("X-Session-ID")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| crate::csrf::get_cookie(headers, "caution_session"))
}

#[tracing::instrument(skip_all, err)]
pub async fn list_passkeys_handler(
    State(state): State<AppState>,
    Extension(AuthenticatedUserId(user_id)): Extension<AuthenticatedUserId>,
    headers: HeaderMap,
) -> Result<Json<Vec<PasskeySummary>>, PasskeyError> {
    let current_session_credential = if let Some(session_id) = get_session_id_from_headers(&headers)
    {
        db::validate_auth_session(&state.db, &session_id).await?
    } else {
        None
    };

    let mut credentials = db::list_user_credentials(&state.db, user_id).await?;

    if let Some(current) = current_session_credential.as_deref() {
        let has_current = credentials
            .iter()
            .any(|credential| credential.credential_id.as_slice() == current);

        if !has_current {
            if let Some(current_credential) =
                db::get_user_credential_by_credential_id(&state.db, user_id, current).await?
            {
                credentials.push(current_credential);
            }
        }

        credentials.sort_by(|a, b| {
            let a_current = a.credential_id.as_slice() == current;
            let b_current = b.credential_id.as_slice() == current;
            b_current
                .cmp(&a_current)
                .then_with(|| b.created_at.cmp(&a.created_at))
        });
    }

    let passkeys = credentials
        .into_iter()
        .map(|credential| {
            let transports = parse_transports(credential.transport.as_ref());
            PasskeySummary {
                id: credential.id,
                name: credential.name,
                credential_id: hex::encode(&credential.credential_id),
                kind: passkey_kind_from_transports(&transports).to_string(),
                transports,
                created_at: credential.created_at.to_string(),
                last_used_at: credential.last_used_at.map(|value| value.to_string()),
                is_current_session: current_session_credential
                    .as_deref()
                    .map(|current| current == credential.credential_id.as_slice())
                    .unwrap_or(false),
            }
        })
        .collect();

    Ok(Json(passkeys))
}

#[tracing::instrument(skip_all, err)]
pub async fn begin_add_passkey_handler(
    State(state): State<AppState>,
    Extension(AuthenticatedUserId(user_id)): Extension<AuthenticatedUserId>,
    Json(req): Json<PasskeyBeginRequest>,
) -> Result<Json<RegisterBeginResponse>, PasskeyError> {
    let name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            crate::validation::validate_passkey_name(value)
                .map_err(|e| PasskeyError::BadRequest(e.to_string()))?;
            Ok::<String, PasskeyError>(value.to_string())
        })
        .transpose()?;

    let registration_user = db::get_registration_user(&state.db, user_id).await?;
    let user_handle = registration_user
        .fido2_user_handle
        .ok_or_else(|| anyhow::anyhow!("User is missing a WebAuthn handle"))?;
    let user_unique_id = Uuid::from_slice(&user_handle)
        .map_err(|e| anyhow::anyhow!("Failed to parse FIDO2 user handle: {}", e))?;

    let existing_cred_ids = db::get_all_credential_ids(&state.db).await?;
    let exclude_credentials: Vec<CredentialID> = existing_cred_ids
        .into_iter()
        .map(CredentialID::from)
        .collect();

    let (mut ccr, reg_state) = state
        .webauthn
        .start_securitykey_registration(
            user_unique_id,
            &registration_user.username,
            &registration_user.username,
            Some(exclude_credentials).filter(|v| !v.is_empty()),
            None,
            None,
        )
        .map_err(|e| anyhow::anyhow!("Failed to start passkey registration: {}", e))?;

    if let Some(ref mut auth_sel) = ccr.public_key.authenticator_selection {
        auth_sel.user_verification = UserVerificationPolicy::Preferred;
        auth_sel.resident_key = Some(ResidentKeyRequirement::Preferred);
    }
    relax_registration_extensions(&mut ccr.public_key.extensions);

    let state_key = Uuid::new_v4().to_string();
    let pending = PendingPasskeyRegistration {
        reg_state,
        user_id,
        name,
        expires_at: time::OffsetDateTime::now_utc() + Duration::minutes(2),
        token_hash: None,
    };

    {
        let mut reg_states = state.passkey_reg_states.write().await;
        if reg_states.len() >= MAX_PENDING_CHALLENGES {
            return Err(PasskeyError::TooManyPending);
        }
        reg_states.insert(state_key.clone(), pending);
    }

    Ok(Json(RegisterBeginResponse {
        challenge: ccr,
        session: state_key,
    }))
}

#[tracing::instrument(skip_all, err)]
pub async fn finish_add_passkey_handler(
    State(state): State<AppState>,
    Extension(AuthenticatedUserId(user_id)): Extension<AuthenticatedUserId>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<PasskeyFinishResponse>, PasskeyError> {
    let session_key = req
        .get("session")
        .and_then(|v| v.as_str())
        .ok_or(PasskeyError::NoRegistrationState)?
        .to_string();

    let pending = state
        .passkey_reg_states
        .write()
        .await
        .remove(&session_key)
        .ok_or(PasskeyError::NoRegistrationState)?;

    if time::OffsetDateTime::now_utc() > pending.expires_at {
        return Err(PasskeyError::ChallengeExpired);
    }

    if pending.user_id != user_id {
        return Err(PasskeyError::Forbidden(
            "Passkey registration does not belong to this session.".to_string(),
        ));
    }

    let reg_response: RegisterPublicKeyCredential =
        serde_json::from_value(req.clone()).map_err(|e| {
            PasskeyError::BadRequest(format!("Failed to parse registration response: {}", e))
        })?;

    let seckey = state
        .webauthn
        .finish_securitykey_registration(&reg_response, &pending.reg_state)
        .map_err(|e| anyhow::anyhow!("Failed to finish passkey registration: {}", e))?;

    let credential_id = seckey.cred_id().clone();
    if db::credential_exists(&state.db, &credential_id).await? {
        return Err(PasskeyError::CredentialAlreadyRegistered);
    }

    let passkey_json = serde_json::to_vec(&seckey)
        .map_err(|e| anyhow::anyhow!("Failed to serialize credential: {}", e))?;
    let transports = req
        .get("transports")
        .cloned()
        .filter(|value| value.is_array());
    let resident = read_credprops_rk(&reg_response);

    db::save_fido2_credential(
        &state.db,
        &credential_id,
        user_id,
        &passkey_json,
        pending.name.as_deref(),
        Some("none"),
        None,
        0,
        transports,
        None,
        resident,
    )
    .await?;

    Ok(Json(PasskeyFinishResponse {
        status: "success".to_string(),
        credential_id: hex::encode(&credential_id),
    }))
}

#[tracing::instrument(skip_all, err)]
pub async fn delete_passkey_handler(
    State(state): State<AppState>,
    Extension(AuthenticatedUserId(user_id)): Extension<AuthenticatedUserId>,
    headers: HeaderMap,
    Path(passkey_id): Path<Uuid>,
) -> Result<StatusCode, PasskeyError> {
    authenticate_session(&state, &headers).await?;
    let credentials = db::list_user_credentials(&state.db, user_id).await?;
    if !credentials
        .iter()
        .any(|credential| credential.id == passkey_id)
    {
        return Err(PasskeyError::CredentialNotFound);
    }

    if credentials.len() <= 1 {
        return Err(PasskeyError::LastCredential);
    }

    let deleted = db::delete_user_credential(&state.db, user_id, passkey_id).await?;
    if deleted == 0 {
        return Err(PasskeyError::CredentialNotFound);
    }

    Ok(StatusCode::NO_CONTENT)
}
