// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::db;
use crate::handlers::{
    authenticate_session, read_credprops_rk, relax_registration_extensions, RegisterBeginResponse,
    SignRequestError, MAX_PENDING_CHALLENGES,
};
use crate::types::*;
use axum::{
    extract::{Extension, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use dterror::{BoxError, CtxError, Location, ResultExt};
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

#[derive(Debug, thiserror::Error, CtxError)]
pub enum PasskeyError {
    #[error("No matching passkey registration state found. Please start over. [{location}]")]
    NoRegistrationState {
        #[location]
        location: Location,
    },

    #[error("Passkey registration challenge has expired. Please try again. [{location}]")]
    ChallengeExpired {
        #[location]
        location: Location,
    },

    #[error("This passkey is already registered. [{location}]")]
    CredentialAlreadyRegistered {
        #[location]
        location: Location,
    },

    #[error("Too many pending passkey registrations. Please try again later. [{location}]")]
    TooManyPending {
        #[location]
        location: Location,
    },

    #[error("Passkey not found. [{location}]")]
    CredentialNotFound {
        #[location]
        location: Location,
    },

    #[error("You must keep at least one passkey on your account. [{location}]")]
    LastCredential {
        #[location]
        location: Location,
    },

    #[error("{message} [{location}]")]
    BadRequest {
        message: String,

        #[location]
        location: Location,
    },

    #[error("{message} [{location}]")]
    Forbidden {
        message: String,

        #[location]
        location: Location,
    },

    /// Auth failure forwarded from `authenticate_session`. The typed inner error
    /// is deliberate (deviating from the usual boxed `BoxError` source): the
    /// `SignRequestError`'s own `IntoResponse` drives the client-facing status
    /// and body, so it must be preserved rather than erased into a boxed
    /// dyn-error. The field is therefore NOT marked `#[source]`: the `CtxError`
    /// derive's `from_context` assigns a boxed dyn-error to any `#[source]`
    /// field, which cannot hold the typed inner error. The variant carries no
    /// generated `Ctx` constructor and is hand-built with `.map_err(...)`.
    #[error("authentication failed [{location}]")]
    Auth {
        #[location]
        location: Location,

        source: SignRequestError,
    },

    #[error("user is missing a WebAuthn handle [{location}]")]
    MissingWebAuthnHandle {
        #[location]
        location: Location,
    },

    #[error("internal error [{location}]")]
    Internal {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

impl IntoResponse for PasskeyError {
    fn into_response(self) -> Response {
        match self {
            Self::Auth { source, .. } => source.into_response(),
            Self::NoRegistrationState { .. } => (
                StatusCode::GONE,
                "No matching passkey registration state found. Please start over.",
            )
                .into_response(),
            Self::ChallengeExpired { .. } => (
                StatusCode::GONE,
                "Passkey registration challenge has expired. Please try again.",
            )
                .into_response(),
            Self::CredentialAlreadyRegistered { .. } => {
                (StatusCode::CONFLICT, "This passkey is already registered.").into_response()
            }
            Self::TooManyPending { .. } => (
                StatusCode::TOO_MANY_REQUESTS,
                "Too many pending passkey registrations. Please try again later.",
            )
                .into_response(),
            Self::CredentialNotFound { .. } => {
                (StatusCode::NOT_FOUND, "Passkey not found.").into_response()
            }
            Self::LastCredential { .. } => (
                StatusCode::CONFLICT,
                "You must keep at least one passkey on your account.",
            )
                .into_response(),
            Self::BadRequest { message, .. } => (StatusCode::BAD_REQUEST, message).into_response(),
            Self::Forbidden { message, .. } => (StatusCode::FORBIDDEN, message).into_response(),
            Self::MissingWebAuthnHandle { .. } => {
                tracing::error!("user is missing a WebAuthn handle");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal error occurred",
                )
                    .into_response()
            }
            Self::Internal { ref source, .. } => {
                tracing::error!(?source, "Passkey management error");
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
    use PasskeyErrorCtx as Ctx;

    let current_session_credential = if let Some(session_id) = get_session_id_from_headers(&headers)
    {
        db::validate_auth_session(&state.db, &session_id)
            .await
            .with_context(Ctx::internal())?
    } else {
        None
    };

    let mut credentials = db::list_user_credentials(&state.db, user_id)
        .await
        .with_context(Ctx::internal())?;

    if let Some(current) = current_session_credential.as_deref() {
        let has_current = credentials
            .iter()
            .any(|credential| credential.credential_id.as_slice() == current);

        if !has_current {
            if let Some(current_credential) =
                db::get_user_credential_by_credential_id(&state.db, user_id, current)
                    .await
                    .with_context(Ctx::internal())?
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
    use PasskeyErrorCtx as Ctx;

    let name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            crate::validation::validate_passkey_name(value).map_err(|e| {
                PasskeyError::BadRequest {
                    message: e.to_string(),
                    location: std::panic::Location::caller(),
                }
            })?;
            Ok::<String, PasskeyError>(value.to_string())
        })
        .transpose()?;

    let registration_user = db::get_registration_user(&state.db, user_id)
        .await
        .with_context(Ctx::internal())?;
    let user_handle =
        registration_user
            .fido2_user_handle
            .ok_or_else(|| PasskeyError::MissingWebAuthnHandle {
                location: std::panic::Location::caller(),
            })?;
    let user_unique_id = Uuid::from_slice(&user_handle).with_context(Ctx::internal())?;

    let existing_cred_ids = db::get_all_credential_ids(&state.db)
        .await
        .with_context(Ctx::internal())?;
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
        name,
        expires_at: time::OffsetDateTime::now_utc() + Duration::minutes(2),
        token_hash: None,
    };

    {
        let mut reg_states = state.passkey_reg_states.write().await;
        if reg_states.len() >= MAX_PENDING_CHALLENGES {
            return Err(PasskeyError::TooManyPending {
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
pub async fn finish_add_passkey_handler(
    State(state): State<AppState>,
    Extension(AuthenticatedUserId(user_id)): Extension<AuthenticatedUserId>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<PasskeyFinishResponse>, PasskeyError> {
    use PasskeyErrorCtx as Ctx;

    let session_key = req
        .get("session")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PasskeyError::NoRegistrationState {
            location: std::panic::Location::caller(),
        })?
        .to_string();

    let pending = state
        .passkey_reg_states
        .write()
        .await
        .remove(&session_key)
        .ok_or_else(|| PasskeyError::NoRegistrationState {
            location: std::panic::Location::caller(),
        })?;

    if time::OffsetDateTime::now_utc() > pending.expires_at {
        return Err(PasskeyError::ChallengeExpired {
            location: std::panic::Location::caller(),
        });
    }

    if pending.user_id != user_id {
        return Err(PasskeyError::Forbidden {
            message: "Passkey registration does not belong to this session.".to_string(),
            location: std::panic::Location::caller(),
        });
    }

    let reg_response: RegisterPublicKeyCredential =
        serde_json::from_value(req.clone()).map_err(|e| PasskeyError::BadRequest {
            message: format!("Failed to parse registration response: {}", e),
            location: std::panic::Location::caller(),
        })?;

    let seckey = state
        .webauthn
        .finish_securitykey_registration(&reg_response, &pending.reg_state)
        .with_context(Ctx::internal())?;

    let credential_id = seckey.cred_id().clone();
    if db::credential_exists(&state.db, &credential_id)
        .await
        .with_context(Ctx::internal())?
    {
        return Err(PasskeyError::CredentialAlreadyRegistered {
            location: std::panic::Location::caller(),
        });
    }

    let passkey_json = serde_json::to_vec(&seckey).with_context(Ctx::internal())?;
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
    .await
    .with_context(Ctx::internal())?;

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
    use PasskeyErrorCtx as Ctx;

    authenticate_session(&state, &headers)
        .await
        .map_err(|source| PasskeyError::Auth {
            location: std::panic::Location::caller(),
            source,
        })?;
    let credentials = db::list_user_credentials(&state.db, user_id)
        .await
        .with_context(Ctx::internal())?;
    if !credentials
        .iter()
        .any(|credential| credential.id == passkey_id)
    {
        return Err(PasskeyError::CredentialNotFound {
            location: std::panic::Location::caller(),
        });
    }

    if credentials.len() <= 1 {
        return Err(PasskeyError::LastCredential {
            location: std::panic::Location::caller(),
        });
    }

    let deleted = db::delete_user_credential(&state.db, user_id, passkey_id)
        .await
        .with_context(Ctx::internal())?;
    if deleted == 0 {
        return Err(PasskeyError::CredentialNotFound {
            location: std::panic::Location::caller(),
        });
    }

    Ok(StatusCode::NO_CONTENT)
}
