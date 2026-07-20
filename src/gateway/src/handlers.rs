// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    extract::{ConnectInfo, Extension, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, Duration};
use uuid::Uuid;
use webauthn_rs::prelude::*;
use webauthn_rs_proto::{ResidentKeyRequirement, UserVerificationPolicy};
#[cfg(test)]
use webauthn_rs_proto::Mediation;

/// Clear the `credProtect` extension (which forces UV=Required and conflicts
/// with our UV=Preferred authenticator selection, rejecting PIN-less smart
/// cards and password-manager registrations) while keeping `credProps`
/// requested, so the browser reports whether it created a resident
/// (discoverable) credential. Read back at finish time via
/// `extensions.cred_props.rk` and stored on the credential row.
fn relax_registration_extensions(
    extensions: &mut Option<webauthn_rs_proto::RequestRegistrationExtensions>,
) {
    if let Some(ext) = extensions.as_mut() {
        ext.cred_protect = None;
        ext.cred_props = Some(true);
    }
}

/// Read the (unsigned, browser-reported) resident-key hint from a
/// registration response's client extension outputs, if present. See
/// `relax_registration_extensions` — `None` here just means the browser
/// didn't report it; residency capture falls back to backfill-on-login.
fn read_credprops_rk(reg_response: &RegisterPublicKeyCredential) -> Option<bool> {
    reg_response.extensions.cred_props.as_ref().and_then(|cp| cp.rk)
}

/// Maximum number of pending challenges per store to prevent OOM from abuse
const MAX_PENDING_CHALLENGES: usize = 10_000;

use crate::db;
use crate::decoy;
use crate::types::*;
use base64::Engine as _;

pub struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // Log full error details server-side
        tracing::error!("Application error: {:?}", self.0);
        // Return generic message to client to avoid leaking internal details
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "An internal error occurred",
        )
            .into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    #[error("invalid or expired session: {0}")]
    InvalidSession(String),
    #[error("authentication challenge has expired")]
    ChallengeExpired,
    #[error("your organization requires PIN verification")]
    PinRequired,
    #[error("failed to parse pubkey credential")]
    ParsePubkeyCredential {
        #[source]
        source: serde_json::Error,
    },
    #[error("could not find user ID for: {provided_bytes:?}")]
    DbGetUserIdByCredential {
        provided_bytes: Vec<u8>,
        #[source]
        source: anyhow::Error,
    },
    #[error("could not get public key for user {user_id}")]
    DbGetPublicKeyForCredential {
        user_id: Uuid,
        #[source]
        source: anyhow::Error,
    },
    #[error("could not find PIN verification info for user {user_id}")]
    DbUserPinRequired {
        user_id: Uuid,
        #[source]
        source: sqlx::Error,
    },
    #[error("could not update fido2 credentials for user {user_id}")]
    DbUpdateFido2Credential {
        user_id: Uuid,
        #[source]
        source: anyhow::Error,
    },
    #[error("could not create auth session for user {user_id}")]
    DbCreateAuthSession {
        user_id: Uuid,
        #[source]
        source: anyhow::Error,
    },
    #[error("could not complete QR login token for user {user_id}")]
    DbCompleteQrLoginToken {
        user_id: Uuid,
        #[source]
        source: anyhow::Error,
    },
    #[error("could not get security key for user {user_id}")]
    ParseSecurityKey {
        user_id: Uuid,
        #[source]
        source: serde_json::Error,
    },
    #[error("security key authentication could not be finalized for user {user_id}")]
    FinishSecurityKeyAuthentication {
        user_id: Uuid,
        #[source]
        source: WebauthnError,
    },
    #[error("could not identify discoverable credential from assertion")]
    IdentifyDiscoverableCredential {
        #[source]
        source: WebauthnError,
    },
    #[error("discoverable authentication could not be finalized for user {user_id}")]
    FinishDiscoverableAuthentication {
        user_id: Uuid,
        #[source]
        source: WebauthnError,
    },
    #[error("could not serialize security credential result for user {user_id}")]
    SerializeSecurityKey {
        user_id: Uuid,
        #[source]
        source: serde_json::Error,
    },
    #[error("could not serialize login finish response")]
    SerializeLoginFinishResponse {
        user_id: Uuid,
        #[source]
        source: serde_json::Error,
    },
    #[error("resolved credential belongs to a different user than the login was scoped to")]
    UnexpectedCredentialOwner {
        expected_user_id: Option<Uuid>,
        actual_user_id: Uuid,
    },
}

/// Fixed body returned for every credential-verification failure at the
/// login/QR-login finish endpoints (unknown credential, bad signature,
/// decoy/scope rejection, expired/invalid session, etc). These outcomes are
/// intentionally collapsed into one byte-for-byte identical status+body so a
/// caller cannot distinguish "no such credential" from "bad signature" from
/// "session expired" — that distinction is exactly the username-enumeration
/// oracle the decoy-challenge mechanism exists to close.
const GENERIC_AUTH_FAILURE_BODY: &str = r#"{"error":"authentication_failed"}"#;

fn generic_auth_failure_response() -> (StatusCode, HeaderMap, &'static str) {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    (StatusCode::UNAUTHORIZED, headers, GENERIC_AUTH_FAILURE_BODY)
}

impl IntoResponse for LoginError {
    fn into_response(self) -> Response {
        match self {
            // Session/challenge lifecycle errors are folded into the same
            // generic 401 as credential-verification failures below: the
            // frontend only checks `response.ok` on the finish calls and
            // shows a generic message, so distinguishing "session expired"
            // from "bad credential" would just reopen the oracle at a
            // different layer.
            Self::InvalidSession(_) | Self::ChallengeExpired => {
                tracing::debug!(?self, "Login finish: session/challenge error");
                generic_auth_failure_response().into_response()
            }
            Self::PinRequired => (StatusCode::FORBIDDEN, self.to_string()).into_response(),
            Self::ParsePubkeyCredential { source: _ } => {
                (StatusCode::BAD_REQUEST, self.to_string()).into_response()
            }
            // Every credential-verification outcome — unknown credential,
            // failed signature verification, and decoy/scope rejection —
            // collapses to the same generic 401 response so none of them is
            // distinguishable from another by status code or body. These are
            // expected client-side authentication failures, not internal
            // errors, so they're logged at debug/warn, not error.
            Self::UnexpectedCredentialOwner { .. } => {
                tracing::debug!(?self, "Login finish: decoy/scope rejection");
                generic_auth_failure_response().into_response()
            }
            Self::DbGetUserIdByCredential { .. } => {
                tracing::error!(?self, "Login finish: credential not found");
                generic_auth_failure_response().into_response()
            }
            Self::DbGetPublicKeyForCredential { .. } | Self::ParseSecurityKey { .. } => {
                tracing::warn!(?self, "Login finish: credential lookup/parse failure");
                generic_auth_failure_response().into_response()
            }
            Self::IdentifyDiscoverableCredential { .. } => {
                tracing::error!(?self, "Login finish: could not identify discoverable credential");
                generic_auth_failure_response().into_response()
            }
            Self::FinishSecurityKeyAuthentication { .. }
            | Self::FinishDiscoverableAuthentication { .. } => {
                tracing::warn!(?self, "Login finish: signature verification failed");
                generic_auth_failure_response().into_response()
            }
            _ => {
                tracing::error!(?self, "Login error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "an internal error occurred".to_string(),
                )
                    .into_response()
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum QrLoginError {
    #[error("QR login confirmation is required")]
    ConfirmationRequired,
    #[error("QR login token not found")]
    TokenNotFound,
    #[error("QR login token has expired")]
    TokenExpired,
    #[error("QR login token in unexpected state: {0}")]
    UnexpectedState(String),
    #[error("QR login token already claimed")]
    AlreadyClaimed,
    #[error("could not create QR login token")]
    DbCreateToken {
        #[source]
        source: anyhow::Error,
    },
    #[error("could not query QR login token")]
    DbGetToken {
        #[source]
        source: anyhow::Error,
    },
    #[error("could not claim QR login token")]
    DbClaimToken {
        #[source]
        source: anyhow::Error,
    },
    #[error("could not query auth session")]
    DbGetSession {
        #[source]
        source: anyhow::Error,
    },
    #[error("could not format QR login timestamp")]
    FormatTimestamp {
        #[source]
        source: time::error::Format,
    },
    #[error("could not fetch credentials")]
    DbGetCredentials {
        #[source]
        source: anyhow::Error,
    },
    #[error("could not deserialize credential")]
    DeserializeCredential {
        #[source]
        source: serde_json::Error,
    },
    #[error("could not start authentication challenge")]
    StartAuthentication {
        #[source]
        source: WebauthnError,
    },
    #[error("could not build username-scoped challenge")]
    ScopedChallenge {
        #[source]
        source: anyhow::Error,
    },
    #[error("Rate limit exceeded. Please try again later.")]
    RateLimited,
}

impl IntoResponse for QrLoginError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::ConfirmationRequired => (StatusCode::BAD_REQUEST, self.to_string()),
            Self::TokenNotFound => (StatusCode::NOT_FOUND, self.to_string()),
            Self::TokenExpired => (StatusCode::GONE, self.to_string()),
            Self::UnexpectedState(_) | Self::AlreadyClaimed => {
                (StatusCode::CONFLICT, self.to_string())
            }
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, self.to_string()),
            _ => {
                tracing::error!(?self, "QR login error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "an internal error occurred".into(),
                )
            }
        };
        (status, message).into_response()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SignRequestError {
    #[error("missing session")]
    MissingSession,
    #[error("invalid or expired session: {0}")]
    InvalidSession(String),
    #[error("missing CSRF token for session: {0}")]
    CsrfMissing(String),
    #[error("invalid CSRF token for session: {0}")]
    CsrfInvalid(String),
    #[error("{0}")]
    Internal(String),
}

impl IntoResponse for SignRequestError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::MissingSession | Self::InvalidSession(_) => {
                (StatusCode::UNAUTHORIZED, self.to_string())
            }
            Self::CsrfMissing(_) | Self::CsrfInvalid(_) => {
                (StatusCode::FORBIDDEN, self.to_string())
            }
            Self::Internal(ref e) => {
                tracing::error!("Sign request error: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "an internal error occurred".into(),
                )
            }
        };
        (status, message).into_response()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterBeginResponse {
    #[serde(flatten)]
    pub challenge: CreationChallengeResponse,
    pub session: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterFinishRequestCli {
    #[serde(flatten)]
    pub credential: serde_json::Value,
    pub session: String,
}

pub async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    #[error("This access code is invalid or has already been used.")]
    InvalidAccessCode,
    #[error("This invitation link is invalid, expired, or has already been used.")]
    InvalidInvitation,
    #[error("Registration challenge has expired. Please try again.")]
    ChallengeExpired,
    #[error("No matching registration state found. Please start over.")]
    NoRegistrationState,
    #[error("This security key is already registered. Each key can only be registered once.")]
    CredentialAlreadyRegistered,
    #[error("Too many pending registrations. Please try again later.")]
    TooManyPending,
    #[error("Invalid username: {0}")]
    InvalidUsername(String),
    #[error("This username is already taken.")]
    UsernameTaken,
    #[error("{0}")]
    Internal(#[source] anyhow::Error),
}

impl IntoResponse for RegisterError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::InvalidAccessCode | Self::InvalidInvitation => {
                (StatusCode::BAD_REQUEST, self.to_string())
            }
            Self::ChallengeExpired | Self::NoRegistrationState => {
                (StatusCode::GONE, self.to_string())
            }
            Self::CredentialAlreadyRegistered => (StatusCode::CONFLICT, self.to_string()),
            Self::TooManyPending => (StatusCode::TOO_MANY_REQUESTS, self.to_string()),
            Self::InvalidUsername(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            Self::UsernameTaken => (StatusCode::CONFLICT, self.to_string()),
            Self::Internal(ref err) => {
                tracing::error!(?err, "Registration error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal error occurred".into(),
                )
            }
        };
        (status, message).into_response()
    }
}

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

fn passkey_kind_from_transports(transports: &[String]) -> &'static str {
    if transports.is_empty() {
        "Authenticator"
    } else if transports.iter().any(|transport| transport == "internal") {
        "Passkey"
    } else {
        "Security key"
    }
}

fn get_session_id_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("X-Session-ID")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| crate::csrf::get_cookie(headers, "caution_session"))
}

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

#[derive(Debug, Deserialize)]
pub struct ClaimUsernameRequest {
    pub username: String,
}

#[derive(Debug, Serialize)]
pub struct UsernameStatusResponse {
    pub username: String,
    pub username_is_placeholder: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum UsernameClaimError {
    #[error("Invalid username: {0}")]
    InvalidUsername(String),
    #[error("This username is already taken.")]
    UsernameTaken,
    #[error("You have already set your username.")]
    AlreadyClaimed,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for UsernameClaimError {
    fn into_response(self) -> Response {
        match self {
            Self::InvalidUsername(_) => (StatusCode::BAD_REQUEST, self.to_string()).into_response(),
            Self::UsernameTaken | Self::AlreadyClaimed => {
                (StatusCode::CONFLICT, self.to_string()).into_response()
            }
            Self::Internal(ref err) => {
                tracing::error!(?err, "Username claim error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal error occurred",
                )
                    .into_response()
            }
        }
    }
}

/// Returns the authenticated user's current username and whether it is
/// still the auto-generated placeholder assigned at signup. Used by the
/// dashboard to decide whether to show the one-time username claim prompt.
pub async fn get_username_status_handler(
    State(state): State<AppState>,
    Extension(AuthenticatedUserId(user_id)): Extension<AuthenticatedUserId>,
) -> Result<Json<UsernameStatusResponse>, UsernameClaimError> {
    let (username, username_is_placeholder) =
        db::get_username_status(&state.db, user_id).await?;

    Ok(Json(UsernameStatusResponse {
        username,
        username_is_placeholder,
    }))
}

/// One-time username claim: a placeholder account (`u_<base64>`) may set a
/// real, immutable username exactly once. Subsequent attempts fail with
/// `AlreadyClaimed` since `db::claim_username` only updates rows that are
/// still marked as a placeholder.
pub async fn claim_username_handler(
    State(state): State<AppState>,
    Extension(AuthenticatedUserId(user_id)): Extension<AuthenticatedUserId>,
    Json(req): Json<ClaimUsernameRequest>,
) -> Result<Json<UsernameStatusResponse>, UsernameClaimError> {
    let username = req.username.trim().to_lowercase();
    crate::validation::validate_username(&username)
        .map_err(|e| UsernameClaimError::InvalidUsername(e.to_string()))?;

    let claimed = db::claim_username(&state.db, user_id, &username)
        .await
        .map_err(|e| {
            if db::is_username_taken_error(&e) {
                UsernameClaimError::UsernameTaken
            } else {
                UsernameClaimError::Internal(e)
            }
        })?;

    if !claimed {
        return Err(UsernameClaimError::AlreadyClaimed);
    }

    Ok(Json(UsernameStatusResponse {
        username,
        username_is_placeholder: false,
    }))
}

pub async fn begin_register_handler(
    State(state): State<AppState>,
    Json(req): Json<crate::types::RegisterBeginRequest>,
) -> Result<Json<RegisterBeginResponse>, RegisterError> {
    tracing::debug!("Registration started with alpha code");

    let alpha_code_id = db::validate_alpha_code(&state.db, &req.alpha_code)
        .await
        .map_err(|e| RegisterError::Internal(e))?
        .ok_or(RegisterError::InvalidAccessCode)?;

    tracing::debug!("Alpha code validated: id={}", alpha_code_id);

    let username = req.username.trim().to_lowercase();
    crate::validation::validate_username(&username)
        .map_err(|e| RegisterError::InvalidUsername(e.to_string()))?;

    begin_registration_challenge(
        &state,
        username,
        PendingRegistrationKind::AlphaCode { alpha_code_id },
    )
    .await
}

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

async fn begin_registration_challenge(
    state: &AppState,
    username: String,
    kind: PendingRegistrationKind,
) -> Result<Json<RegisterBeginResponse>, RegisterError> {
    // Fetch ALL existing credential IDs to pass as excludeCredentials
    // This prevents the same authenticator from registering multiple accounts
    let existing_cred_ids = db::get_all_credential_ids(&state.db)
        .await
        .map_err(|e| RegisterError::Internal(e))?;
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
        .map_err(|e| {
            RegisterError::Internal(anyhow::anyhow!("Failed to start registration: {}", e))
        })?;

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
            return Err(RegisterError::TooManyPending);
        }
        reg_states.insert(state_key.clone(), pending);
    }

    Ok(Json(RegisterBeginResponse {
        challenge: ccr,
        session: state_key,
    }))
}

/// Build auth cookies for session and CSRF protection
fn build_auth_cookies(
    session_id: &str,
    csrf_token: &str,
    max_age_hours: i64,
    secure: bool,
) -> (String, String) {
    // Session cookie: HTTP-only, Secure, SameSite=Strict
    let session_cookie = Cookie::build(("caution_session", session_id.to_string()))
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Strict)
        .max_age(cookie::time::Duration::hours(max_age_hours))
        .build();

    // CSRF cookie: NOT HTTP-only (so JS can read it), Secure, SameSite=Strict
    let csrf_cookie = Cookie::build(("caution_csrf", csrf_token.to_string()))
        .path("/")
        .http_only(false)
        .secure(secure)
        .same_site(SameSite::Strict)
        .max_age(cookie::time::Duration::hours(max_age_hours))
        .build();

    (session_cookie.to_string(), csrf_cookie.to_string())
}

pub async fn finish_register_handler(
    State(state): State<AppState>,
    connect_info: ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> Result<Response, RegisterError> {
    let session_key = req
        .get("session")
        .and_then(|v| v.as_str())
        .ok_or(RegisterError::NoRegistrationState)?
        .to_string();

    let pending = state
        .reg_states
        .read()
        .await
        .get(&session_key)
        .cloned()
        .ok_or(RegisterError::NoRegistrationState)?;

    // Check if the registration challenge has expired
    if time::OffsetDateTime::now_utc() > pending.expires_at {
        state.reg_states.write().await.remove(&session_key);
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
    if db::credential_exists(&state.db, &credential_id)
        .await
        .map_err(|e| RegisterError::Internal(e))?
    {
        tracing::warn!("Registration rejected - credential already registered");
        return Err(RegisterError::CredentialAlreadyRegistered);
    }

    state.reg_states.write().await.remove(&session_key);

    let user_unique_id = Uuid::parse_str(&session_key)
        .map_err(|e| RegisterError::Internal(anyhow::anyhow!("Failed to parse user ID: {}", e)))?;

    let legal = db::SignupLegalContext {
        ip_address: Some(connect_info.0.ip().to_string()),
        user_agent: headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
    };

    let user_id = match pending.kind {
        PendingRegistrationKind::AlphaCode { alpha_code_id } => {
            let user_id = db::create_user(
                &state.db,
                &user_unique_id.as_bytes()[..],
                alpha_code_id,
                &pending.username,
                &legal,
            )
            .await
            .map_err(|e| {
                if db::is_username_taken_error(&e) {
                    RegisterError::UsernameTaken
                } else {
                    RegisterError::Internal(anyhow::anyhow!("Failed to create user: {}", e))
                }
            })?;

            db::redeem_alpha_code(&state.db, alpha_code_id)
                .await
                .map_err(|e| {
                    RegisterError::Internal(anyhow::anyhow!("Failed to redeem alpha code: {}", e))
                })?;

            tracing::debug!("User registered and alpha code redeemed");
            user_id
        }
        PendingRegistrationKind::OrganizationInvite {
            invitation_id,
            token_hash,
        } => {
            let user_id = db::accept_invitation_and_create_user(
                &state.db,
                invitation_id,
                &token_hash,
                &user_unique_id.as_bytes()[..],
                &pending.username,
                &legal,
            )
            .await
            .map_err(|e| {
                if db::is_username_taken_error(&e) {
                    RegisterError::UsernameTaken
                } else {
                    RegisterError::Internal(anyhow::anyhow!(
                        "Failed to accept organization invitation: {}",
                        e
                    ))
                }
            })?;

            tracing::debug!("User registered from organization invitation");
            user_id
        }
    };

    let passkey_json = serde_json::to_vec(&seckey).map_err(|e| {
        RegisterError::Internal(anyhow::anyhow!("Failed to serialize credential: {}", e))
    })?;
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
    .map_err(|e| RegisterError::Internal(e))?;

    let credential_id_hex = hex::encode(&credential_id);

    let session_id = db::generate_session_id();
    let csrf_token = crate::csrf::derive_csrf_token(&session_id, &state.csrf_secret);
    let expires_at = time::OffsetDateTime::now_utc() + Duration::hours(state.session_timeout_hours);

    db::create_auth_session(&state.db, &session_id, &credential_id, expires_at)
        .await
        .map_err(|e| RegisterError::Internal(e))?;

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

    let body = serde_json::to_string(&response_body).map_err(|e| {
        RegisterError::Internal(anyhow::anyhow!("Failed to serialize response: {}", e))
    })?;

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

/// Normalize a caller-supplied optional username for login lookup: trim,
/// lowercase, and treat an all-whitespace/empty value the same as "absent"
/// so callers don't have to special-case `Some("")`.
fn normalize_login_username(username: Option<String>) -> Option<String> {
    username
        .map(|u| u.trim().to_lowercase())
        .filter(|u| !u.is_empty())
}

/// Deserialize a set of stored `public_key` blobs into `SecurityKey`s for use
/// as an `allowCredentials` list.
fn deserialize_security_keys(public_keys: &[Vec<u8>]) -> Result<Vec<SecurityKey>, anyhow::Error> {
    public_keys
        .iter()
        .enumerate()
        .map(|(i, cred_bytes)| {
            serde_json::from_slice(cred_bytes).map_err(|e| {
                tracing::error!("Failed to deserialize credential {}", i);
                anyhow::anyhow!("Failed to deserialize credential: {}", e)
            })
        })
        .collect()
}

/// Real, throwaway-generated `SecurityKey`s (serialized the same way
/// `finish_securitykey_registration` output is stored — see
/// `finish_passkey_registration_handler`), used ONLY to size decoy-path CPU
/// work to match the real path. Their private key material corresponds to
/// no real user, is never checked against a real challenge, and is never
/// returned to a client. Two algorithms (ES256 and RS256 — the two the
/// gateway's `Webauthn` instance accepts, see `COSEAlgorithm::secure_algs()`
/// / `main.rs`) are alternated in `equalize_decoy_work` so the decoy's
/// per-credential JSON/COSE-deserialize cost isn't systematically cheaper
/// than a real account that holds RSA credentials (whose much larger
/// modulus costs more to base64-decode and parse than an EC point).
const DECOY_TIMING_FIXTURE_ES256: &[u8] = br#"{"cred":{"cred_id":"7ySFchbdsv8y8B5oR-1cxOlY5Trjo1auESH25Co0nTI","cred":{"type_":"ES256","key":{"EC_EC2":{"curve":"SECP256R1","x":"SveqzIeBhZDl0phwAvHY0rAIEdeTphQu4ReAuCzq8bs","y":"6mm9arrmm2MqgpwkdTvN0-X-cduiZd4zAQdvDuEDO7M"}}},"counter":0,"transports":null,"user_verified":false,"backup_eligible":false,"backup_state":false,"registration_policy":"preferred","extensions":{"cred_protect":"Ignored","hmac_create_secret":"NotRequested","appid":"NotRequested","cred_props":"Ignored"},"attestation":{"data":"Self_","metadata":"None"},"attestation_format":"packed"}}"#;
const DECOY_TIMING_FIXTURE_RS256: &[u8] = br#"{"cred":{"cred_id":"Zf6IREgEOMUe8fugN_Td2VjbdNuKDMDBbp3kgUjn4kk","cred":{"type_":"RS256","key":{"RSA":{"n":"BYLwR4Q78LFZmPfF5N_7iQg8FYJ2gB8t7W0Wqtwte6v0-aDMmCNhEu1eikRqosqqPyPOUhSfVy7f8e6gFHGznMhHt7c2IS687B9aH57XV78ySjitd55wLeMhzMdRFZxKcPja1IhyZ_yesU6aJFBWvRujd4Ufqj__WEs4IkJetjeT6KlpBQy67AQozbqcDvtq4NokcpfGLGbimMTEkGMyzARY28jyzgvJj82EZwzUC8LMEa5CYIbKZUIeZwMpaA63OoFexxJt9vCMAPathraD6A4yiwDswJ9bMKekblYDqJBpwAmJFnHK5nEpHNkGkXobhXel5pBw9RJ0DY8cjKe1uA","e":[1,0,1]}}},"counter":0,"transports":null,"user_verified":false,"backup_eligible":false,"backup_state":false,"registration_policy":"preferred","extensions":{"cred_protect":"Ignored","hmac_create_secret":"NotRequested","appid":"NotRequested","cred_props":"Ignored"},"attestation":{"data":"Self_","metadata":"None"},"attestation_format":"packed"}}"#;

/// Both decoy timing fixtures, in the order `equalize_decoy_work` alternates
/// them. Panics at process startup (see `validate_decoy_timing_fixtures`,
/// called from `main`) if either ever fails to deserialize, rather than
/// silently degrading the decoy path's timing-equalization at request time.
const DECOY_TIMING_FIXTURES: [&[u8]; 2] = [DECOY_TIMING_FIXTURE_ES256, DECOY_TIMING_FIXTURE_RS256];

/// Called once from `main` at startup: fail fast (panic via `expect`) if
/// either `DECOY_TIMING_FIXTURE_*` constant ever fails to deserialize — e.g.
/// format drift on a future `webauthn-rs` upgrade — rather than letting
/// `equalize_decoy_work`'s per-request fail-open path silently reopen the
/// timing side-channel it exists to close.
pub fn validate_decoy_timing_fixtures() {
    for fixture in DECOY_TIMING_FIXTURES {
        deserialize_security_keys(&[fixture.to_vec()])
            .expect("DECOY_TIMING_FIXTURE failed to deserialize at startup");
    }
}

/// Perform throwaway deserialize + auth-challenge-build work on the decoy
/// path, sized to match the real branch's dominant per-credential cost
/// (JSON/COSE deserialize + `start_securitykey_authentication`'s O(N)
/// build), so begin-login response latency stops leaking whether a
/// username exists or how many credentials it has. Alternates the ES256 and
/// RS256 fixtures so the decoy path isn't systematically cheaper than a real
/// account holding RSA credentials. Never stores or returns its result — the
/// real `AuthState::Discoverable{Decoy}` from
/// `start_discoverable_authentication` is what actually gets persisted, so a
/// decoy still can never complete a ceremony. Fails open: both fixtures are
/// validated once at startup (`validate_decoy_timing_fixtures`), so a
/// per-request deserialize error here would mean in-process corruption, not
/// format drift — log and skip rather than fail the login-begin request.
fn equalize_decoy_work(state: &AppState, n: usize) {
    let blobs: Vec<Vec<u8>> = (0..n)
        .map(|i| DECOY_TIMING_FIXTURES[i % DECOY_TIMING_FIXTURES.len()].to_vec())
        .collect();
    match deserialize_security_keys(&blobs) {
        Ok(keys) => {
            let result = state.webauthn.start_securitykey_authentication(&keys);
            std::hint::black_box(result);
        }
        Err(e) => {
            tracing::warn!(
                "Decoy timing-equalization fixture failed to deserialize: {:?}",
                e
            );
        }
    }
}

/// Username scope recorded on an `AuthState::Discoverable` challenge, checked
/// against the resolved user at finish time. Only ever meaningfully set by
/// `scoped_or_decoy_challenge` (i.e. a username was supplied for this
/// challenge) — the plain broadcast/discoverable login (no username at all)
/// always uses `Unscoped`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsernameScope {
    /// No username was supplied for this challenge — any resolved user is
    /// acceptable, since nothing was scoped to begin with.
    Unscoped,
    /// A username was supplied but the challenge is a decoy: either the
    /// username didn't resolve to any user (`expected_user_id: None`) or it
    /// resolved to a user with zero registered credentials
    /// (`expected_user_id: Some`). Either way this challenge must never
    /// successfully authenticate as any user — that's the whole point of a
    /// decoy: it looks identical to a real scoped challenge but can't be
    /// completed.
    Decoy { expected_user_id: Option<Uuid> },
}

/// Verifies a resolved discoverable-auth user is consistent with the
/// username scope recorded when the challenge began (Finding 1: a
/// username-scoped decoy challenge must not silently authenticate whichever
/// resident credential the browser/authenticator happens to return).
fn check_username_scope(
    scope: &UsernameScope,
    resolved_user_id: Uuid,
) -> Result<(), LoginError> {
    match scope {
        UsernameScope::Unscoped => Ok(()),
        UsernameScope::Decoy { expected_user_id } => {
            if *expected_user_id == Some(resolved_user_id) {
                Ok(())
            } else {
                Err(LoginError::UnexpectedCredentialOwner {
                    expected_user_id: *expected_user_id,
                    actual_user_id: resolved_user_id,
                })
            }
        }
    }
}

/// Overwrite a freshly-started discoverable-auth challenge's client-facing
/// shape to match a real username-scoped challenge, so a decoy is
/// indistinguishable from a real account: a non-empty, per-username-stable,
/// HMAC-synthesized `allowCredentials` list, no `mediation`, and
/// `UserVerificationPolicy::Preferred` — exactly what the real scoped branch
/// of `scoped_or_decoy_challenge` produces. The underlying `auth_state`
/// (the actual server-side challenge from `start_discoverable_authentication`)
/// is untouched and real; only the response sent to the client is reshaped.
/// The synthesized credential IDs never exist in server state, so they can
/// never complete a ceremony — and `check_username_scope` additionally
/// rejects any resident credential a decoy challenge does resolve to.
fn apply_decoy_shape(
    rcr: &mut RequestChallengeResponse,
    csrf_secret: &str,
    normalized_username: &str,
) {
    rcr.public_key.allow_credentials =
        decoy::synthesize_allow_credentials(csrf_secret, normalized_username);
    rcr.mediation = None;
    rcr.public_key.user_verification = UserVerificationPolicy::Preferred;
}

/// Start a real (never-completable) discoverable-auth ceremony and reshape
/// its response to the decoy shape via `apply_decoy_shape`, recording
/// `expected_user_id` on the returned `UsernameScope::Decoy` so
/// `check_username_scope` rejects it at finish regardless of which resident
/// credential the browser returns. Shared by both decoy call sites in
/// `scoped_or_decoy_challenge`: the natural decoy (unknown username, or a
/// known username with zero credentials) and the forced decoy (a username
/// that tripped the per-username rate limit, whether or not it's real).
///
/// `equalize` controls whether `equalize_decoy_work` runs: skip it
/// (`false`) only when `username` is provably not a real account by format
/// alone (e.g. fails `validate_username`) — there's no real per-credential
/// cost to match in that case, and it saves the crypto work.
async fn force_decoy_challenge(
    state: &AppState,
    username: &str,
    expected_user_id: Option<Uuid>,
    equalize: bool,
) -> anyhow::Result<(RequestChallengeResponse, AuthState)> {
    let (mut rcr, auth_state) = state.webauthn.start_discoverable_authentication().map_err(|e| {
        tracing::error!("Failed to start decoy challenge: {:?}", e);
        anyhow::anyhow!("Failed to start authentication: {}", e)
    })?;
    apply_decoy_shape(&mut rcr, &state.csrf_secret, username);
    if equalize {
        equalize_decoy_work(state, rcr.public_key.allow_credentials.len());
    }

    Ok((
        rcr,
        AuthState::Discoverable {
            auth_state,
            scope: UsernameScope::Decoy { expected_user_id },
        },
    ))
}

/// Build a username-scoped `allowCredentials` challenge for a known username
/// with credentials, or a synthesized decoy challenge otherwise (unknown
/// username, or known username with zero registered credentials) — same
/// shape either way (non-empty `allowCredentials`, no `mediation`,
/// `user_verification: Preferred`), so the caller can't use this to
/// enumerate usernames. Shared by the direct login-begin path and the QR
/// cross-device login path.
///
/// Format pre-check (before rate limiting or DB work): a username that
/// fails `validate_username` (too short/long, disallowed characters) can
/// never belong to a real account — registration enforces the same rule —
/// so there is no real per-credential cost to equalize against and no
/// benefit to spending a per-username rate-limit bucket on it (that map is
/// keyed by raw username string, so accepting arbitrary garbage here would
/// let a prober grow it unboundedly). Route straight to the same decoy
/// shape everything else gets, skipping `equalize_decoy_work`.
///
/// Per-username rate limiting (enumeration defense item #3): before doing
/// ANY DB work, check `state.username_begin_limiter` keyed by the
/// (already-normalized) username. If that username has been requested too
/// many times in the window, short-circuit straight to a forced decoy
/// (`force_decoy_challenge`) WITHOUT touching the DB — this deliberately
/// runs ahead of the real-vs-decoy branching below so a flooded username
/// (real or not) always degrades to "looks real but can never
/// authenticate" rather than a hard error. Because this check lives inside
/// `scoped_or_decoy_challenge` rather than in `begin_login_handler`, the QR
/// cross-device begin path (`qr_login_authenticate_handler`, which also
/// calls this function) inherits the same per-username cap automatically.
async fn scoped_or_decoy_challenge(
    state: &AppState,
    username: &str,
) -> anyhow::Result<(RequestChallengeResponse, AuthState)> {
    if crate::validation::validate_username(username).is_err() {
        return force_decoy_challenge(state, username, None, false).await;
    }

    if !state.username_begin_limiter.check_rate_limit(username).await {
        tracing::warn!(
            "Per-username begin-login rate limit exceeded; forcing decoy response"
        );
        return force_decoy_challenge(state, username, None, true).await;
    }

    let user_id = db::get_user_id_by_username(&state.db, username).await?;

    // Timing equalization: always issue the same shape of DB work (a user
    // lookup followed by a credential fetch keyed on a real/plausible user
    // id) regardless of whether the username resolved, so the number and
    // kind of DB round trips can't themselves leak existence over a timing
    // side-channel. For an unknown username there's no real user id to
    // fetch credentials for, so we query a random UUID instead — it can
    // never match a row in `fido2_credentials` (whose `user_id` is a real
    // FK), so the query costs the same indexed lookup and returns empty,
    // and the result is discarded.
    //
    // SCOPE OF THIS EQUALIZATION: it only equalizes the *DB round trips*
    // (count and kind of queries) on a single gateway replica/process. The
    // dominant remaining CPU cost is `deserialize_security_keys` over N
    // credential blobs plus `start_securitykey_authentication`'s O(N) build:
    // the real-user branch below runs that over the user's actual credential
    // blobs, while the decoy branch (`force_decoy_challenge` ->
    // `equalize_decoy_work`) now runs the SAME deserialize + auth-build work
    // over N copies of a throwaway fixture (`DECOY_TIMING_FIXTURE`), sized to
    // the same allowCredentials count the decoy shape advertises — closing
    // the gap for that dominant cost. This is still not a hard constant-time
    // guarantee overall: scheduler/OS-level jitter, cache effects, and other
    // lower-order timing sources remain out of scope.
    let credential_lookup_id = user_id.unwrap_or_else(Uuid::new_v4);
    let public_keys = db::get_credential_public_keys_by_user_id(&state.db, credential_lookup_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch credentials for scoped login: {:?}", e);
            anyhow::anyhow!("Failed to fetch credentials: {}", e)
        })?;
    let allow_credentials = match user_id {
        Some(_) => deserialize_security_keys(&public_keys)?,
        None => Vec::new(),
    };

    if user_id.is_some() && !allow_credentials.is_empty() {
        tracing::debug!(
            "Starting username-scoped authentication challenge with {} credentials",
            allow_credentials.len()
        );

        let (mut rcr, auth_state) = state
            .webauthn
            .start_securitykey_authentication(&allow_credentials)
            .map_err(|e| {
                tracing::error!("Failed to start scoped authentication: {:?}", e);
                anyhow::anyhow!("Failed to start authentication: {}", e)
            })?;
        rcr.public_key.user_verification = UserVerificationPolicy::Preferred;
        return Ok((rcr, AuthState::SecurityKey(auth_state)));
    }

    // Decoy path: either the username doesn't resolve to any user, or it
    // resolves to a user with zero registered credentials. Both cases are
    // indistinguishable from each other AND from the real scoped response
    // above — same non-empty `allowCredentials` shape, no `mediation`,
    // Preferred UV. `force_decoy_challenge` starts a real server-side
    // challenge + state (so a probing client can't tell this apart from a
    // real ceremony start) and reshapes the client-facing response.
    // `expected_user_id` is either no such user (`None`) or the user is
    // known but has zero credentials (`Some`) — either way finish must
    // always reject, regardless of which resident credential the browser
    // returns.
    force_decoy_challenge(state, username, user_id, true).await
}

/// `POST /auth/login/begin`. Tolerates an absent/empty JSON body (treated as
/// `{ "username": null }`) since axum's `Json` extractor rejects those.
///
/// - `username` present & non-empty, and matches a user with ≥1 registered
///   credential -> username-scoped `allowCredentials` (that user's
///   credentials only), no `mediation`, `user_verification: Preferred`.
/// - `username` present & non-empty, but no such user, or a known user with
///   zero credentials -> a decoy challenge with the SAME shape: a non-empty,
///   deterministically HMAC-synthesized `allowCredentials` list (see
///   `decoy::synthesize_allow_credentials`), no `mediation`,
///   `user_verification: Preferred`. Never a 404, and never distinguishable
///   by shape from the real-user case above — the existence of the username
///   is unanswerable from this response. The synthesized IDs never exist in
///   server state, so a decoy can never complete a ceremony
///   (`check_username_scope` enforces this at finish).
/// - `username` absent/empty:
///   - `login_allow_broadcast == true` (default) -> legacy broadcast:
///     `allowCredentials` = every credential in the DB, byte-for-byte
///     unchanged behavior.
///   - `login_allow_broadcast == false` -> discoverable: empty
///     `allowCredentials`, `mediation: "conditional"` (set automatically by
///     `start_discoverable_authentication`).
pub async fn begin_login_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    body: axum::body::Bytes,
) -> Result<Response, AppError> {
    let username: Option<String> = normalize_login_username(if body.is_empty() {
        None
    } else {
        serde_json::from_slice::<LoginBeginRequest>(&body)
            .ok()
            .and_then(|r| r.username)
    });

    let (rcr, auth_state) = if let Some(username) = username {
        // Tighter per-IP budget on top of the blanket global limiter (item
        // #3 of the enumeration defense): a scoped-begin request does more
        // per-call work (a DB lookup) than a plain broadcast begin, and is
        // the shape an enumeration attacker actually wants to spam. A hard
        // 429 here is safe — it's keyed by IP, not by username, so it can't
        // leak whether any particular username exists.
        if !state
            .scoped_begin_limiter
            .check_rate_limit(&addr.ip().to_string())
            .await
        {
            tracing::warn!("Scoped begin-login rate limit exceeded for IP: {}", addr.ip());
            return Ok((
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded. Please try again later.",
            )
                .into_response());
        }

        // Username-scoped fallback path (e.g. CLI / non-resident keys).
        // `scoped_or_decoy_challenge` additionally enforces a per-username
        // budget and forces a decoy (never a 429) once that's exceeded.
        scoped_or_decoy_challenge(&state, &username).await?
    } else if state.login_allow_broadcast {
        // Legacy behavior: broadcast every credential in the DB. Kept
        // byte-for-byte unchanged pending the Phase 3 flip.
        let all_public_keys = db::get_all_credential_public_keys(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("Failed to fetch credentials from DB: {:?}", e);
                anyhow::anyhow!("Failed to fetch credentials: {}", e)
            })?;

        tracing::debug!("Found {} credentials in database", all_public_keys.len());

        let allow_credentials = deserialize_security_keys(&all_public_keys)?;

        tracing::debug!(
            "Starting authentication challenge with {} credentials",
            allow_credentials.len()
        );

        // Use securitykey auth which allows flexible UV policy (unlike passkey which requires UV)
        let (mut rcr, auth_state) = state
            .webauthn
            .start_securitykey_authentication(&allow_credentials)
            .map_err(|e| {
                tracing::error!("Failed to start authentication: {:?}", e);
                anyhow::anyhow!("Failed to start authentication: {}", e)
            })?;

        // Always use Preferred - we enforce PIN requirement in finish_login based on org settings
        // This allows the authenticator to decide, and we validate server-side
        rcr.public_key.user_verification = UserVerificationPolicy::Preferred;

        tracing::debug!(
            "Authentication challenge created for RP {} with {} allowed credentials",
            rcr.public_key.rp_id,
            rcr.public_key.allow_credentials.len()
        );

        (rcr, AuthState::SecurityKey(auth_state))
    } else {
        // Primary path: username-less discoverable / conditional UI login.
        let (rcr, auth_state) = state.webauthn.start_discoverable_authentication().map_err(|e| {
            tracing::error!("Failed to start discoverable authentication: {:?}", e);
            anyhow::anyhow!("Failed to start authentication: {}", e)
        })?;
        (
            rcr,
            AuthState::Discoverable {
                auth_state,
                scope: UsernameScope::Unscoped,
            },
        )
    };

    let session_key = Uuid::new_v4().to_string();
    let pending = PendingAuthentication {
        auth_state,
        expires_at: time::OffsetDateTime::now_utc() + Duration::minutes(2),
    };
    {
        let mut auth_states = state.auth_states.write().await;
        if auth_states.len() >= MAX_PENDING_CHALLENGES {
            return Err(anyhow::anyhow!("Too many pending logins").into());
        }
        auth_states.insert(session_key.clone(), pending);
    }

    Ok(Json(LoginBeginResponse {
        challenge: rcr,
        session: session_key,
    })
    .into_response())
}

pub async fn finish_login_handler(
    State(state): State<AppState>,
    Json(req): Json<serde_json::Value>,
) -> Result<Response, LoginError> {
    let session_key = req
        .get("session")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LoginError::InvalidSession("missing session field".into()))?
        .to_string();

    // Remove (rather than read+clone then remove) so this is the single
    // source of truth for challenge consumption — a session can only be
    // finished once, and we don't need `AuthState` to be droppable-and-reused.
    let pending = {
        let mut auth_states = state.auth_states.write().await;
        auth_states.remove(&session_key)
    }
    .ok_or_else(|| LoginError::InvalidSession(session_key.clone()))?;

    // Check if the authentication challenge has expired.
    if time::OffsetDateTime::now_utc() > pending.expires_at {
        return Err(LoginError::ChallengeExpired);
    }

    let auth_response: PublicKeyCredential = serde_json::from_value(req.clone())
        .map_err(|source| LoginError::ParsePubkeyCredential { source })?;

    tracing::debug!("Received authentication response");

    let (user_id, credential_id_bytes, mut seckey, auth_result) = match pending.auth_state {
        AuthState::SecurityKey(auth_state) => {
            // Legacy / username-scoped path: resolve the user from the
            // asserted credential's rawId, exactly as before.
            let credential_id_bytes = auth_response.raw_id.as_ref().to_vec();
            tracing::debug!("Credential ID: {}", hex::encode(&credential_id_bytes));

            let user_id = db::get_user_id_by_credential(&state.db, &credential_id_bytes)
                .await
                .map_err(|source| LoginError::DbGetUserIdByCredential {
                    provided_bytes: credential_id_bytes.clone(),
                    source,
                })?;

            let cred_bytes = db::get_credential_public_key(&state.db, &credential_id_bytes)
                .await
                .map_err(|source| LoginError::DbGetPublicKeyForCredential { user_id, source })?;
            let seckey: SecurityKey = serde_json::from_slice(&cred_bytes)
                .map_err(|source| LoginError::ParseSecurityKey { user_id, source })?;

            tracing::debug!("Credential fetched, performing securitykey authentication");

            let auth_result = state
                .webauthn
                .finish_securitykey_authentication(&auth_response, &auth_state)
                .map_err(|source| LoginError::FinishSecurityKeyAuthentication { user_id, source })?;

            (user_id, credential_id_bytes, seckey, auth_result)
        }
        AuthState::Discoverable { auth_state, scope } => {
            // Primary path: resolve the user from the assertion's userHandle,
            // then reload the credential by its rawId to reuse the rest of
            // the (PIN check / counter update / session creation) pipeline
            // unchanged.
            let (_user_handle, cred_id) = state
                .webauthn
                .identify_discoverable_authentication(&auth_response)
                .map_err(|source| LoginError::IdentifyDiscoverableCredential { source })?;
            let credential_id_bytes = cred_id.to_vec();
            tracing::debug!(
                "Discoverable credential ID: {}",
                hex::encode(&credential_id_bytes)
            );

            let user_id = db::get_user_id_by_credential(&state.db, &credential_id_bytes)
                .await
                .map_err(|source| LoginError::DbGetUserIdByCredential {
                    provided_bytes: credential_id_bytes.clone(),
                    source,
                })?;

            let cred_bytes = db::get_credential_public_key(&state.db, &credential_id_bytes)
                .await
                .map_err(|source| LoginError::DbGetPublicKeyForCredential { user_id, source })?;
            let seckey: SecurityKey = serde_json::from_slice(&cred_bytes)
                .map_err(|source| LoginError::ParseSecurityKey { user_id, source })?;

            // SecurityKey -> Credential -> Passkey -> DiscoverableKey, per
            // webauthn-rs 0.5's discoverable-auth API (needs the
            // `danger-credential-internals` feature for the Credential
            // conversions).
            let credential: Credential = seckey.clone().into();
            let passkey: Passkey = credential.into();
            let discoverable_key: DiscoverableKey = passkey.into();

            tracing::debug!("Credential fetched, performing discoverable authentication");

            let auth_result = state
                .webauthn
                .finish_discoverable_authentication(&auth_response, auth_state, &[discoverable_key])
                .map_err(|source| LoginError::FinishDiscoverableAuthentication { user_id, source })?;

            // Ceremony is consumed (challenge validated) at this point even
            // if the scope check below rejects it, so a decoy challenge can't
            // be completed by authenticating as a different resident user
            // (Finding 1). The rejection is intentionally byte-for-byte
            // identical to every other credential-verification failure (see
            // `LoginError::into_response`) to avoid a username-enumeration
            // oracle.
            check_username_scope(&scope, user_id)?;

            // Opportunistic residency backfill: a successful discoverable
            // finish proves the authenticator surfaced this credential via
            // userHandle, i.e. it's resident. Best-effort — never fail the
            // login over this.
            if let Err(e) =
                db::mark_credential_resident_if_unknown(&state.db, &credential_id_bytes).await
            {
                tracing::warn!("Failed to backfill credential resident flag: {:?}", e);
            }

            (user_id, credential_id_bytes, seckey, auth_result)
        }
    };

    tracing::debug!(
        user_verified = auth_result.user_verified(),
        "Authentication successful"
    );

    // Check if user's org requires PIN verification.
    let requires_pin = db::user_requires_pin(&state.db, user_id)
        .await
        .map_err(|source| LoginError::DbUserPinRequired { user_id, source })?;
    if requires_pin && !auth_result.user_verified() {
        tracing::warn!(
            "User {} login rejected: org requires PIN but user_verified=false",
            user_id
        );
        return Err(LoginError::PinRequired);
    }

    if auth_result.needs_update() {
        let update_result = seckey.update_credential(&auth_result);

        if let Some(true) = update_result {
            let updated_key_json = serde_json::to_vec(&seckey)
                .map_err(|source| LoginError::SerializeSecurityKey { user_id, source })?;

            db::update_fido2_credential(
                &state.db,
                &credential_id_bytes,
                &updated_key_json,
                auth_result.counter(),
            )
            .await
            .map_err(|source| LoginError::DbUpdateFido2Credential { user_id, source })?;
        }
    }

    let session_id = db::generate_session_id();
    let csrf_token = crate::csrf::derive_csrf_token(&session_id, &state.csrf_secret);
    let expires_at = time::OffsetDateTime::now_utc() + Duration::hours(state.session_timeout_hours);

    db::create_auth_session(&state.db, &session_id, &credential_id_bytes, expires_at)
        .await
        .map_err(|source| LoginError::DbCreateAuthSession { user_id, source })?;

    let credential_id_hex = hex::encode(&credential_id_bytes);
    tracing::debug!(
        "Login complete (session expires in {} hours)",
        state.session_timeout_hours
    );

    // Build the response (session_id is in Set-Cookie header, not body)
    let response_body = LoginFinishResponse {
        expires_at: expires_at.to_string(),
        credential_id: credential_id_hex,
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

    let body = serde_json::to_string(&response_body)
        .map_err(|source| LoginError::SerializeLoginFinishResponse { user_id, source })?;

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

#[derive(Debug, Deserialize)]
pub struct AddSshKeyRequest {
    pub public_key: String,
    pub name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AddSshKeyResponse {
    pub id: Uuid,
    pub fingerprint: String,
}

#[derive(Debug, Serialize)]
pub struct ListSshKeysResponse {
    pub keys: Vec<crate::db::SshKeyInfo>,
}

pub async fn add_ssh_key_handler(
    State(state): State<AppState>,
    user_id_header: axum::http::HeaderMap,
    Json(req): Json<AddSshKeyRequest>,
) -> Result<Json<AddSshKeyResponse>, AppError> {
    let user_id = user_id_header
        .get("X-Authenticated-User-ID")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid user ID"))?;

    crate::validation::validate_ssh_public_key(&req.public_key)
        .map_err(|e| anyhow::anyhow!("Invalid SSH public key: {}", e))?;

    let key_type = req
        .public_key
        .trim()
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow::anyhow!("Failed to parse key type"))?;

    let key_id = crate::db::add_ssh_key(
        &state.db,
        user_id,
        &req.public_key,
        key_type,
        req.name.as_deref(),
    )
    .await?;

    let fingerprint = crate::db::generate_ssh_fingerprint(&req.public_key)?;

    tracing::debug!("SSH key added");

    Ok(Json(AddSshKeyResponse {
        id: key_id,
        fingerprint,
    }))
}

pub async fn list_ssh_keys_handler(
    State(state): State<AppState>,
    user_id_header: axum::http::HeaderMap,
) -> Result<Json<ListSshKeysResponse>, AppError> {
    let user_id = user_id_header
        .get("X-Authenticated-User-ID")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid user ID"))?;

    let keys = crate::db::list_ssh_keys(&state.db, user_id).await?;

    Ok(Json(ListSshKeysResponse { keys }))
}

pub async fn delete_ssh_key_handler(
    State(state): State<AppState>,
    user_id_header: axum::http::HeaderMap,
    Path(fingerprint): Path<String>,
) -> Result<StatusCode, AppError> {
    let user_id = user_id_header
        .get("X-Authenticated-User-ID")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid user ID"))?;

    let deleted = crate::db::delete_ssh_key(&state.db, user_id, &fingerprint).await?;

    if deleted {
        tracing::debug!("SSH key deleted");
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(anyhow::anyhow!("SSH key not found").into())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddPgpKeyRequest {
    pub public_key: String,
    pub name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AddPgpKeyResponse {
    pub id: Uuid,
    pub fingerprint: String,
}

#[derive(Debug, Serialize)]
pub struct ListPgpKeysResponse {
    pub keys: Vec<crate::db::PgpKeyInfo>,
}

#[derive(Debug, thiserror::Error)]
#[error("Verified signed request audit ID is missing")]
pub struct MissingSignedRequestAuditError;

fn signed_request_audit_id(
    signed_request: Option<Extension<VerifiedSignedRequestId>>,
) -> Result<Option<Uuid>, MissingSignedRequestAuditError> {
    #[cfg(feature = "e2e-testing-unsafe")]
    {
        Ok(signed_request.map(|Extension(VerifiedSignedRequestId(id))| id))
    }

    #[cfg(not(feature = "e2e-testing-unsafe"))]
    {
        signed_request
            .map(|Extension(VerifiedSignedRequestId(id))| Some(id))
            .ok_or(MissingSignedRequestAuditError)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AddPgpKeyError {
    #[error(transparent)]
    InvalidPublicKey(#[from] crate::pgp::ParsePgpPublicKeyError),

    #[error(transparent)]
    InvalidName(#[from] crate::pgp::ValidatePgpKeyNameError),

    #[error("This PGP public key is already registered to your account")]
    Duplicate,

    #[error(transparent)]
    MissingSignedRequestAudit(#[from] MissingSignedRequestAuditError),

    #[error("Unable to store PGP public key for user {user_id}")]
    Database {
        user_id: Uuid,
        #[source]
        source: sqlx::Error,
    },
}

impl IntoResponse for AddPgpKeyError {
    fn into_response(self) -> Response {
        match self {
            error @ (Self::InvalidPublicKey(_) | Self::InvalidName(_)) => {
                (StatusCode::BAD_REQUEST, error.to_string()).into_response()
            }
            error @ Self::Duplicate => (StatusCode::CONFLICT, error.to_string()).into_response(),
            error @ (Self::MissingSignedRequestAudit(_) | Self::Database { .. }) => {
                tracing::error!(?error, "Failed to add PGP public key");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal error occurred",
                )
                    .into_response()
            }
        }
    }
}

pub async fn add_pgp_key_handler(
    State(state): State<AppState>,
    Extension(AuthenticatedUserId(user_id)): Extension<AuthenticatedUserId>,
    signed_request: Option<Extension<VerifiedSignedRequestId>>,
    Json(req): Json<AddPgpKeyRequest>,
) -> Result<Json<AddPgpKeyResponse>, AddPgpKeyError> {
    let signed_request_id = signed_request_audit_id(signed_request)?;
    let public_key = crate::pgp::parse_public_key(&req.public_key)?;
    if let Some(name) = req.name.as_deref() {
        crate::pgp::validate_key_name(name)?;
    }
    let name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty());

    let key_id = match crate::db::add_pgp_key(
        &state.db,
        user_id,
        public_key.armored(),
        public_key.fingerprint(),
        name,
        signed_request_id,
    )
    .await
    {
        Ok(key_id) => key_id,
        Err(source)
            if source.as_database_error().is_some_and(|error| {
                error.is_unique_violation()
                    && matches!(
                        error.constraint(),
                        Some(
                            "pgp_keys_user_fingerprint_unique"
                                | "pgp_keys_active_user_fingerprint_unique"
                        )
                    )
            }) =>
        {
            return Err(AddPgpKeyError::Duplicate);
        }
        Err(source) => return Err(AddPgpKeyError::Database { user_id, source }),
    };

    tracing::info!(
        user_id = %user_id,
        fingerprint = %public_key.fingerprint(),
        "PGP public key added"
    );

    Ok(Json(AddPgpKeyResponse {
        id: key_id,
        fingerprint: public_key.fingerprint().to_string(),
    }))
}

pub async fn list_pgp_keys_handler(
    State(state): State<AppState>,
    Extension(AuthenticatedUserId(user_id)): Extension<AuthenticatedUserId>,
) -> Result<Json<ListPgpKeysResponse>, AppError> {
    let keys = crate::db::list_pgp_keys(&state.db, user_id).await?;
    Ok(Json(ListPgpKeysResponse { keys }))
}

#[derive(Debug, thiserror::Error)]
pub enum RemovePgpKeyHandlerError {
    #[error("PGP public key not found")]
    NotFound,

    #[error(transparent)]
    MissingSignedRequestAudit(#[from] MissingSignedRequestAuditError),

    #[error(transparent)]
    Database(#[from] crate::db::RemovePgpKeyError),
}

impl IntoResponse for RemovePgpKeyHandlerError {
    fn into_response(self) -> Response {
        match self {
            error @ Self::NotFound => (StatusCode::NOT_FOUND, error.to_string()).into_response(),
            error @ (Self::MissingSignedRequestAudit(_) | Self::Database(_)) => {
                tracing::error!(?error, "Failed to remove PGP public key");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal error occurred",
                )
                    .into_response()
            }
        }
    }
}

pub async fn remove_pgp_key_handler(
    State(state): State<AppState>,
    Extension(AuthenticatedUserId(user_id)): Extension<AuthenticatedUserId>,
    signed_request: Option<Extension<VerifiedSignedRequestId>>,
    Path(key_id): Path<Uuid>,
) -> Result<StatusCode, RemovePgpKeyHandlerError> {
    let signed_request_id = signed_request_audit_id(signed_request)?;
    let fingerprint = crate::db::remove_pgp_key(&state.db, user_id, key_id, signed_request_id)
        .await?
        .ok_or(RemovePgpKeyHandlerError::NotFound)?;

    tracing::info!(
        user_id = %user_id,
        key_id = %key_id,
        fingerprint = %fingerprint,
        "PGP public key removed"
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Create a sign challenge for the given credential. Returns (challenge_response, challenge_id).
/// Stores PendingSignChallenge in state.sign_challenges.
async fn create_sign_challenge(
    state: &AppState,
    credential_id: &[u8],
    method: String,
    path: String,
    body_hash: String,
    flow: SignedRequestFlow,
    expires_minutes: i64,
) -> Result<(webauthn_rs_proto::RequestChallengeResponse, String), SignRequestError> {
    let user_id = db::get_user_id_by_credential(&state.db, credential_id)
        .await
        .map_err(|e| SignRequestError::Internal(e.to_string()))?;
    let requires_pin = db::user_requires_pin(&state.db, user_id)
        .await
        .map_err(|e| SignRequestError::Internal(e.to_string()))?;

    let cred_bytes = db::get_credential_public_key(&state.db, credential_id)
        .await
        .map_err(|e| SignRequestError::Internal(e.to_string()))?;
    let seckey: SecurityKey = serde_json::from_slice(&cred_bytes).map_err(|e| {
        SignRequestError::Internal(format!("Failed to deserialize credential: {}", e))
    })?;

    let (mut rcr, auth_state) = state
        .webauthn
        .start_securitykey_authentication(&[seckey])
        .map_err(|e| {
            SignRequestError::Internal(format!("Failed to start signing challenge: {}", e))
        })?;

    if requires_pin {
        rcr.public_key.user_verification = UserVerificationPolicy::Required;
    } else {
        rcr.public_key.user_verification = UserVerificationPolicy::Preferred;
    }

    let challenge_id = Uuid::new_v4();
    let pending = crate::types::PendingSignChallenge {
        challenge_id,
        auth_state,
        user_id,
        method,
        path,
        body_hash,
        flow,
        expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(expires_minutes),
    };

    {
        let mut sign_challenges = state.sign_challenges.write().await;
        if sign_challenges.len() >= MAX_PENDING_CHALLENGES {
            return Err(SignRequestError::Internal(
                "Too many pending sign challenges".to_string(),
            ));
        }
        sign_challenges.insert(challenge_id.to_string(), pending);
    }

    Ok((rcr, challenge_id.to_string()))
}

/// Resolve session ID from headers (X-Session-ID or caution_session cookie),
/// validate it, and enforce CSRF for cookie-based auth. Returns credential_id.
async fn authenticate_session(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<Vec<u8>, SignRequestError> {
    let (session_id, using_header_auth) = if let Some(header_session) = headers
        .get("X-Session-ID")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
    {
        (header_session, true)
    } else if let Some(cookie_session) = crate::csrf::get_cookie(headers, "caution_session") {
        (cookie_session, false)
    } else {
        return Err(SignRequestError::MissingSession);
    };

    let credential_id = db::validate_auth_session(&state.db, &session_id)
        .await
        .map_err(|e| SignRequestError::Internal(e.to_string()))?
        .ok_or_else(|| SignRequestError::InvalidSession(session_id.clone()))?;

    if !using_header_auth {
        let expected_csrf = crate::csrf::derive_csrf_token(&session_id, &state.csrf_secret);
        let csrf_header = headers
            .get("X-CSRF-Token")
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| SignRequestError::CsrfMissing(session_id.clone()))?;
        if !crate::csrf::constant_time_compare(&expected_csrf, csrf_header) {
            return Err(SignRequestError::CsrfInvalid(session_id.clone()));
        }
    }

    Ok(credential_id)
}

fn get_rp_origin() -> String {
    std::env::var("RP_ORIGINS")
        .unwrap_or_else(|_| "http://localhost:8000".to_string())
        .split(',')
        .next()
        .unwrap_or("http://localhost:8000")
        .trim()
        .to_string()
}

pub async fn begin_sign_request_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<crate::types::SignChallengeRequest>,
) -> Result<Json<crate::types::SignChallengeResponse>, SignRequestError> {
    let credential_id = authenticate_session(&state, &headers).await?;

    let (rcr, challenge_id) = create_sign_challenge(
        &state,
        &credential_id,
        req.method,
        req.path,
        req.body_hash,
        SignedRequestFlow::Direct,
        2,
    )
    .await?;

    Ok(Json(crate::types::SignChallengeResponse {
        challenge: rcr,
        challenge_id,
    }))
}

/// Build cookies that clear auth state (for logout)
fn build_logout_cookies(secure: bool) -> (String, String) {
    // Set cookies with immediate expiration to clear them
    let session_cookie = Cookie::build(("caution_session", ""))
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Strict)
        .max_age(cookie::time::Duration::ZERO)
        .build();

    let csrf_cookie = Cookie::build(("caution_csrf", ""))
        .path("/")
        .http_only(false)
        .secure(secure)
        .same_site(SameSite::Strict)
        .max_age(cookie::time::Duration::ZERO)
        .build();

    (session_cookie.to_string(), csrf_cookie.to_string())
}

// QR Login handlers

#[derive(Debug, Deserialize)]
pub struct QrLoginStatusQuery {
    pub token: String,
}

fn qr_login_url_for_origin(origin: &str, requestee_token: &str) -> String {
    format!("{origin}/qr-login?token={requestee_token}")
}

fn qr_login_url(requestee_token: &str) -> String {
    qr_login_url_for_origin(&get_rp_origin(), requestee_token)
}

pub async fn qr_login_begin_handler(
    State(state): State<AppState>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
    body: axum::body::Bytes,
) -> Result<Json<crate::types::QrLoginBeginResponse>, QrLoginError> {
    let username: Option<String> = normalize_login_username(if body.is_empty() {
        None
    } else {
        serde_json::from_slice::<crate::types::QrLoginBeginRequest>(&body)
            .ok()
            .and_then(|r| r.username)
    });

    let token = db::generate_session_id();
    let requestee_token = db::generate_session_id();
    let verification_code = db::generate_qr_login_verification_code();
    let expires_at = time::OffsetDateTime::now_utc() + Duration::minutes(3);
    let ip_address = connect_info.0.ip().to_string();

    let url = qr_login_url(&requestee_token);

    db::create_qr_login_token(
        &state.db,
        &token,
        &requestee_token,
        Some(&ip_address),
        expires_at,
        username.as_deref(),
        &verification_code,
    )
    .await
    .map_err(|source| QrLoginError::DbCreateToken { source })?;

    Ok(Json(crate::types::QrLoginBeginResponse {
        token,
        url,
        verification_code,
        expires_at: expires_at.to_string(),
    }))
}

pub async fn qr_login_context_handler(
    State(state): State<AppState>,
    Json(req): Json<crate::types::QrLoginContextRequest>,
) -> Result<Json<crate::types::QrLoginContextResponse>, QrLoginError> {
    let row = db::get_qr_login_token_by_requestee_token(&state.db, &req.token)
        .await
        .map_err(|source| QrLoginError::DbGetToken { source })?
        .ok_or(QrLoginError::TokenNotFound)?;

    if time::OffsetDateTime::now_utc() > row.expires_at {
        return Err(QrLoginError::TokenExpired);
    }

    if !matches!(QrStatus::from_db(&row.status), Some(QrStatus::Pending)) {
        return Err(QrLoginError::AlreadyClaimed);
    }

    let verification_code = row.verification_code.ok_or_else(|| {
        QrLoginError::UnexpectedState("QR login token has no verification code".to_string())
    })?;
    let created_at = row
        .created_at
        .format(&Rfc3339)
        .map_err(|source| QrLoginError::FormatTimestamp { source })?;
    let expires_at = row
        .expires_at
        .format(&Rfc3339)
        .map_err(|source| QrLoginError::FormatTimestamp { source })?;

    Ok(Json(crate::types::QrLoginContextResponse {
        verification_code,
        created_at,
        expires_at,
    }))
}

pub async fn qr_login_status_handler(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<QrLoginStatusQuery>,
) -> Result<Json<crate::types::QrLoginStatusResponse>, QrLoginError> {
    let row = db::get_qr_login_token(&state.db, &query.token)
        .await
        .map_err(|source| QrLoginError::DbGetToken { source })?;

    let Some(row) = row else {
        return Ok(Json(crate::types::QrLoginStatusResponse {
            status: QrStatus::NotFound,
            session_id: None,
            expires_at: None,
        }));
    };

    if time::OffsetDateTime::now_utc() > row.expires_at {
        return Ok(Json(crate::types::QrLoginStatusResponse {
            status: QrStatus::Expired,
            session_id: None,
            expires_at: None,
        }));
    }

    let Some(status) = QrStatus::from_db(&row.status) else {
        tracing::warn!("QR login token has unknown DB status: {}", row.status);
        return Ok(Json(crate::types::QrLoginStatusResponse {
            status: QrStatus::NotFound,
            session_id: None,
            expires_at: None,
        }));
    };

    if status == QrStatus::Completed {
        if let Some(sid) = row.session_id.clone() {
            // Fetch the session BEFORE consuming, so a failure here leaves the
            // session_id intact and the next poll can retry.
            let session = db::get_auth_session(&state.db, &sid)
                .await
                .map_err(|source| QrLoginError::DbGetSession { source })?;

            let session_expires = session.map(|s| s.expires_at.to_string());

            // Consume last: atomically NULLs session_id and confirms we won any
            // concurrent-poll race. Only hand back the session if we did.
            let consumed = db::consume_qr_login_session_id(&state.db, &query.token)
                .await
                .map_err(|source| QrLoginError::DbGetToken { source })?;

            if consumed.is_some() {
                return Ok(Json(crate::types::QrLoginStatusResponse {
                    status: QrStatus::Completed,
                    session_id: Some(sid),
                    expires_at: session_expires,
                }));
            }

            // consume returned None: another poll already took the session id
            // (one-shot), or it was cleared. The token is terminal-completed
            // with nothing left to hand back.
            tracing::debug!(
                "QR login status completed but session id already consumed (token: {})",
                query.token
            );
        }

        return Ok(Json(crate::types::QrLoginStatusResponse {
            status: QrStatus::Completed,
            session_id: None,
            expires_at: None,
        }));
    }

    Ok(Json(crate::types::QrLoginStatusResponse {
        status,
        session_id: None,
        expires_at: None,
    }))
}

pub async fn qr_login_authenticate_handler(
    State(state): State<AppState>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
    Json(req): Json<crate::types::QrLoginAuthenticateRequest>,
) -> Result<Json<crate::types::QrLoginAuthenticateResponse>, QrLoginError> {
    // A scan alone must never allocate a WebAuthn challenge or claim the token.
    if !req.confirmed {
        return Err(QrLoginError::ConfirmationRequired);
    }

    // Verify requestee token exists and is pending
    let row = db::get_qr_login_token_by_requestee_token(&state.db, &req.token)
        .await
        .map_err(|source| QrLoginError::DbGetToken { source })?
        .ok_or(QrLoginError::TokenNotFound)?;

    if time::OffsetDateTime::now_utc() > row.expires_at {
        return Err(QrLoginError::TokenExpired);
    }

    match QrStatus::from_db(&row.status) {
        Some(QrStatus::Pending) => {}
        Some(QrStatus::Authenticated) | Some(QrStatus::Completed) => {
            return Err(QrLoginError::AlreadyClaimed)
        }
        _ => return Err(QrLoginError::UnexpectedState(row.status)),
    }

    // A username stored on the token (from qr_login_begin_handler) scopes the
    // challenge to that user's own credentials — needed for non-resident/
    // legacy keys, which phone platform authenticators normally don't need.
    // Otherwise mirror begin_login_handler's flag-driven behavior: broadcast
    // when the flag is on (unchanged), otherwise discoverable.
    let (rcr, auth_state) = if let Some(username) = row.username.as_deref() {
        // Same per-IP scoped-begin budget as begin_login_handler: this branch
        // does the same username-scoped DB lookup and is the same enumeration
        // shape, just reached via the QR flow instead of /auth/login/begin.
        let ip = connect_info.0.ip();
        if !state.scoped_begin_limiter.check_rate_limit(&ip.to_string()).await {
            tracing::warn!("Scoped begin-login rate limit exceeded for IP: {}", ip);
            return Err(QrLoginError::RateLimited);
        }

        scoped_or_decoy_challenge(&state, username)
            .await
            .map_err(|source| QrLoginError::ScopedChallenge { source })?
    } else if state.login_allow_broadcast {
        let all_public_keys = db::get_all_credential_public_keys(&state.db)
            .await
            .map_err(|source| QrLoginError::DbGetCredentials { source })?;

        let mut allow_credentials = Vec::new();
        for cred_bytes in all_public_keys.iter() {
            let seckey: webauthn_rs::prelude::SecurityKey = serde_json::from_slice(cred_bytes)
                .map_err(|source| QrLoginError::DeserializeCredential { source })?;
            allow_credentials.push(seckey);
        }

        let (mut rcr, auth_state) = state
            .webauthn
            .start_securitykey_authentication(&allow_credentials)
            .map_err(|source| QrLoginError::StartAuthentication { source })?;

        rcr.public_key.user_verification = webauthn_rs_proto::UserVerificationPolicy::Preferred;
        (rcr, AuthState::SecurityKey(auth_state))
    } else {
        let (rcr, auth_state) = state
            .webauthn
            .start_discoverable_authentication()
            .map_err(|source| QrLoginError::StartAuthentication { source })?;
        (
            rcr,
            AuthState::Discoverable {
                auth_state,
                scope: UsernameScope::Unscoped,
            },
        )
    };

    let session_key = uuid::Uuid::new_v4().to_string();
    let pending = PendingAuthentication {
        auth_state,
        expires_at: time::OffsetDateTime::now_utc() + Duration::minutes(3),
    };

    // Atomically claim token, then insert auth state under the same write guard
    let browser_ip = connect_info.0.ip().to_string();
    let claimed = db::claim_qr_login_token(&state.db, &req.token, &session_key, Some(&browser_ip))
        .await
        .map_err(|source| QrLoginError::DbClaimToken { source })?;
    if !claimed {
        return Err(QrLoginError::AlreadyClaimed);
    }
    {
        let mut auth_states = state.auth_states.write().await;
        if auth_states.len() >= MAX_PENDING_CHALLENGES {
            return Err(QrLoginError::UnexpectedState(
                "Too many pending challenges".to_string(),
            ));
        }
        auth_states.insert(session_key.clone(), pending);
    }

    Ok(Json(crate::types::QrLoginAuthenticateResponse {
        challenge: rcr,
        session: session_key,
        token: req.token,
    }))
}

pub async fn qr_login_authenticate_finish_handler(
    State(state): State<AppState>,
    Json(req): Json<crate::types::QrLoginAuthenticateFinishRequest>,
) -> Result<Json<serde_json::Value>, LoginError> {
    let token = req.token;
    let session_key = req.session;

    // Verify requestee token is authenticated and session key matches
    let row = db::get_qr_login_token_by_requestee_token(&state.db, &token)
        .await
        .map_err(|e| LoginError::InvalidSession(e.to_string()))?
        .ok_or_else(|| LoginError::InvalidSession("invalid QR login token".into()))?;

    match QrStatus::from_db(&row.status) {
        Some(QrStatus::Authenticated) => {}
        other => {
            tracing::warn!(
                "QR login finish called with unexpected token status: {:?} (token: {})",
                other,
                token
            );
            return Err(LoginError::InvalidSession(format!(
                "QR login token in unexpected state: {}",
                row.status
            )));
        }
    }

    if row.auth_challenge_key.as_deref() != Some(&session_key) {
        tracing::warn!(
            "QR login finish session key mismatch: expected {:?}, got {:?} (token: {})",
            row.auth_challenge_key,
            session_key,
            token
        );
        return Err(LoginError::InvalidSession("session key mismatch".into()));
    }

    // Take the pending auth state (single write guard for get + remove)
    let pending = {
        let mut auth_states = state.auth_states.write().await;
        auth_states
            .remove(&session_key)
            .ok_or_else(|| LoginError::InvalidSession(session_key.clone()))?
    };

    if time::OffsetDateTime::now_utc() > pending.expires_at {
        return Err(LoginError::ChallengeExpired);
    }

    let auth_response: webauthn_rs::prelude::PublicKeyCredential =
        serde_json::from_value(req.credential)
            .map_err(|source| LoginError::ParsePubkeyCredential { source })?;

    let (user_id, credential_id_bytes, mut seckey, auth_result) = match pending.auth_state {
        AuthState::SecurityKey(auth_state) => {
            let credential_id_bytes = auth_response.raw_id.as_ref().to_vec();

            let user_id = db::get_user_id_by_credential(&state.db, &credential_id_bytes)
                .await
                .map_err(|source| LoginError::DbGetUserIdByCredential {
                    provided_bytes: credential_id_bytes.clone(),
                    source,
                })?;

            let cred_bytes = db::get_credential_public_key(&state.db, &credential_id_bytes)
                .await
                .map_err(|source| LoginError::DbGetPublicKeyForCredential { user_id, source })?;
            let seckey: webauthn_rs::prelude::SecurityKey = serde_json::from_slice(&cred_bytes)
                .map_err(|source| LoginError::ParseSecurityKey { user_id, source })?;

            let auth_result = state
                .webauthn
                .finish_securitykey_authentication(&auth_response, &auth_state)
                .map_err(|source| LoginError::FinishSecurityKeyAuthentication { user_id, source })?;

            (user_id, credential_id_bytes, seckey, auth_result)
        }
        AuthState::Discoverable { auth_state, scope } => {
            let (_user_handle, cred_id) = state
                .webauthn
                .identify_discoverable_authentication(&auth_response)
                .map_err(|source| LoginError::IdentifyDiscoverableCredential { source })?;
            let credential_id_bytes = cred_id.to_vec();

            let user_id = db::get_user_id_by_credential(&state.db, &credential_id_bytes)
                .await
                .map_err(|source| LoginError::DbGetUserIdByCredential {
                    provided_bytes: credential_id_bytes.clone(),
                    source,
                })?;

            let cred_bytes = db::get_credential_public_key(&state.db, &credential_id_bytes)
                .await
                .map_err(|source| LoginError::DbGetPublicKeyForCredential { user_id, source })?;
            let seckey: webauthn_rs::prelude::SecurityKey = serde_json::from_slice(&cred_bytes)
                .map_err(|source| LoginError::ParseSecurityKey { user_id, source })?;

            let credential: Credential = seckey.clone().into();
            let passkey: Passkey = credential.into();
            let discoverable_key: DiscoverableKey = passkey.into();

            let auth_result = state
                .webauthn
                .finish_discoverable_authentication(&auth_response, auth_state, &[discoverable_key])
                .map_err(|source| LoginError::FinishDiscoverableAuthentication { user_id, source })?;

            // See the equivalent check in `finish_login_handler` (Finding 1):
            // ceremony is consumed above regardless of outcome.
            check_username_scope(&scope, user_id)?;

            if let Err(e) =
                db::mark_credential_resident_if_unknown(&state.db, &credential_id_bytes).await
            {
                tracing::warn!("Failed to backfill credential resident flag: {:?}", e);
            }

            (user_id, credential_id_bytes, seckey, auth_result)
        }
    };

    // Check PIN requirement
    let requires_pin = db::user_requires_pin(&state.db, user_id)
        .await
        .map_err(|source| LoginError::DbUserPinRequired { user_id, source })?;
    if requires_pin && !auth_result.user_verified() {
        return Err(LoginError::PinRequired);
    }

    if auth_result.needs_update() {
        let update_result = seckey.update_credential(&auth_result);
        if let Some(true) = update_result {
            let updated_key_json = serde_json::to_vec(&seckey)
                .map_err(|source| LoginError::SerializeSecurityKey { user_id, source })?;
            db::update_fido2_credential(
                &state.db,
                &credential_id_bytes,
                &updated_key_json,
                auth_result.counter(),
            )
            .await
            .map_err(|source| LoginError::DbUpdateFido2Credential { user_id, source })?;
        }
    }

    // Create auth session (NO cookies — CLI uses header auth)
    let session_id = db::generate_session_id();
    let expires_at = time::OffsetDateTime::now_utc() + Duration::hours(state.session_timeout_hours);

    db::create_auth_session(&state.db, &session_id, &credential_id_bytes, expires_at)
        .await
        .map_err(|source| LoginError::DbCreateAuthSession { user_id, source })?;

    // Mark token completed
    db::complete_qr_login_token(&state.db, &token, &session_id)
        .await
        .map_err(|source| LoginError::DbCompleteQrLoginToken { user_id, source })?;

    tracing::debug!("QR login complete for user {}", user_id);

    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Authentication complete. You can close this tab."
    })))
}

// QR Sign handlers (mid-session signing via phone)

#[derive(Debug, thiserror::Error)]
pub enum QrSignError {
    #[error("QR sign token not found")]
    TokenNotFound,
    #[error("QR sign token has expired")]
    TokenExpired,
    #[error("QR sign token in unexpected state: {0}")]
    UnexpectedState(String),
    #[error("{0}")]
    Internal(String),
}

impl IntoResponse for QrSignError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::TokenNotFound => (StatusCode::NOT_FOUND, self.to_string()),
            Self::TokenExpired => (StatusCode::GONE, self.to_string()),
            Self::UnexpectedState(_) => (StatusCode::CONFLICT, self.to_string()),
            Self::Internal(_) => {
                tracing::error!(?self, "QR sign error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "an internal error occurred".into(),
                )
            }
        };
        (status, message).into_response()
    }
}

#[derive(Debug, Deserialize)]
pub struct QrSignStatusQuery {
    pub token: String,
}

pub async fn qr_sign_begin_handler(
    State(state): State<AppState>,
    connect_info: ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<crate::types::QrSignChallengeRequest>,
) -> Result<Json<crate::types::QrSignBeginResponse>, SignRequestError> {
    let credential_id = authenticate_session(&state, &headers).await?;

    let (rcr, challenge_id) = create_sign_challenge(
        &state,
        &credential_id,
        req.method.clone(),
        req.path.clone(),
        req.body_hash.clone(),
        SignedRequestFlow::CrossDeviceQr,
        3,
    )
    .await?;

    let token = db::generate_session_id();
    let expires_at = time::OffsetDateTime::now_utc() + Duration::minutes(3);
    let ip_address = connect_info.0.ip().to_string();

    let challenge_json = serde_json::to_string(&rcr)
        .map_err(|e| SignRequestError::Internal(format!("Failed to serialize challenge: {}", e)))?;

    db::create_qr_sign_token(
        &state.db,
        &token,
        &challenge_id,
        &challenge_json,
        &req.method,
        &req.path,
        &req.body,
        &req.body_hash,
        Some(&ip_address),
        expires_at,
    )
    .await
    .map_err(|e| SignRequestError::Internal(e.to_string()))?;

    let url = format!("{}/qr-sign?token={}", get_rp_origin(), token);

    Ok(Json(crate::types::QrSignBeginResponse {
        challenge_id,
        token,
        url,
        expires_at: expires_at.to_string(),
    }))
}

pub async fn qr_sign_status_handler(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<QrSignStatusQuery>,
) -> Result<Json<crate::types::QrSignStatusResponse>, QrSignError> {
    let row = db::get_qr_sign_token(&state.db, &query.token)
        .await
        .map_err(|e| QrSignError::Internal(e.to_string()))?;

    let Some(row) = row else {
        return Ok(Json(crate::types::QrSignStatusResponse {
            status: QrStatus::NotFound,
            fido2_response: None,
            challenge_id: None,
        }));
    };

    if time::OffsetDateTime::now_utc() > row.expires_at {
        return Ok(Json(crate::types::QrSignStatusResponse {
            status: QrStatus::Expired,
            fido2_response: None,
            challenge_id: None,
        }));
    }

    let status = QrStatus::from_db(&row.status).unwrap_or(QrStatus::NotFound);

    if status == QrStatus::Completed {
        return Ok(Json(crate::types::QrSignStatusResponse {
            status: QrStatus::Completed,
            fido2_response: row.fido2_response,
            challenge_id: Some(row.challenge_id),
        }));
    }

    Ok(Json(crate::types::QrSignStatusResponse {
        status,
        fido2_response: None,
        challenge_id: None,
    }))
}

pub async fn qr_sign_authenticate_handler(
    State(state): State<AppState>,
    connect_info: ConnectInfo<std::net::SocketAddr>,
    Json(req): Json<crate::types::QrSignAuthenticateRequest>,
) -> Result<Json<crate::types::QrSignAuthenticateResponse>, QrSignError> {
    let row = db::get_qr_sign_token(&state.db, &req.token)
        .await
        .map_err(|e| QrSignError::Internal(e.to_string()))?
        .ok_or(QrSignError::TokenNotFound)?;

    if time::OffsetDateTime::now_utc() > row.expires_at {
        return Err(QrSignError::TokenExpired);
    }

    match QrStatus::from_db(&row.status) {
        Some(QrStatus::Pending) => {}
        other => return Err(QrSignError::UnexpectedState(format!("{:?}", other))),
    }

    let browser_ip = connect_info.0.ip().to_string();
    let claimed = db::claim_qr_sign_token(&state.db, &req.token, Some(&browser_ip))
        .await
        .map_err(|e| QrSignError::Internal(e.to_string()))?;
    if !claimed {
        return Err(QrSignError::UnexpectedState("already claimed".into()));
    }

    let challenge: webauthn_rs_proto::RequestChallengeResponse =
        serde_json::from_str(&row.challenge_json).map_err(|e| {
            QrSignError::Internal(format!("Failed to deserialize challenge: {}", e))
        })?;

    Ok(Json(crate::types::QrSignAuthenticateResponse {
        challenge,
        token: req.token,
    }))
}

pub async fn qr_sign_authenticate_finish_handler(
    State(state): State<AppState>,
    Json(req): Json<crate::types::QrSignAuthenticateFinishRequest>,
) -> Result<Json<serde_json::Value>, QrSignError> {
    let row = db::get_qr_sign_token(&state.db, &req.token)
        .await
        .map_err(|e| QrSignError::Internal(e.to_string()))?
        .ok_or(QrSignError::TokenNotFound)?;

    if time::OffsetDateTime::now_utc() > row.expires_at {
        return Err(QrSignError::TokenExpired);
    }

    match QrStatus::from_db(&row.status) {
        Some(QrStatus::Authenticated) => {}
        other => return Err(QrSignError::UnexpectedState(format!("{:?}", other))),
    }

    // base64url-encode the assertion — same format fido2_sign_middleware expects in X-Fido2-Response
    let credential_json = serde_json::to_vec(&req.credential)
        .map_err(|e| QrSignError::Internal(format!("Failed to serialize credential: {}", e)))?;
    let fido2_response = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&credential_json);

    db::complete_qr_sign_token(&state.db, &req.token, &fido2_response)
        .await
        .map_err(|e| QrSignError::Internal(e.to_string()))?;

    tracing::debug!("QR sign token completed");

    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Signing approved. You can close this tab."
    })))
}

#[cfg(feature = "e2e-testing-unsafe")]
pub async fn e2e_login_handler(State(state): State<AppState>) -> Result<Response, AppError> {
    tracing::warn!("E2E login: creating test user (this endpoint only exists in e2e builds)");

    let (user_id, credential_id) = db::create_e2e_user(&state.db).await?;

    let session_id = db::generate_session_id();
    let expires_at = time::OffsetDateTime::now_utc() + Duration::hours(state.session_timeout_hours);
    db::create_auth_session(&state.db, &session_id, &credential_id, expires_at).await?;

    let body = serde_json::json!({
        "session_id": session_id,
        "user_id": user_id.to_string(),
        "expires_at": expires_at.to_string(),
    });

    Ok(Json(body).into_response())
}

pub async fn logout_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Response, AppError> {
    // Get session from header (CLI) or cookie (browser)
    let session_id = headers
        .get("X-Session-ID")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| crate::csrf::get_cookie(&headers, "caution_session"));

    // Delete session from database if we found one
    let mut deletion_failed = false;
    if let Some(session_id) = session_id {
        if let Err(e) = db::delete_auth_session(&state.db, &session_id).await {
            tracing::error!("Failed to delete session during logout: {:?}", e);
            deletion_failed = true;
        }
    }

    // Build response with cleared cookies (clear even on error so client is logged out)
    let secure = std::env::var("ENVIRONMENT")
        .map(|e| e != "development")
        .unwrap_or(true);
    let (session_cookie, csrf_cookie) = build_logout_cookies(secure);

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

    if deletion_failed {
        Ok((
            StatusCode::INTERNAL_SERVER_ERROR,
            headers,
            r#"{"error":"Failed to delete session"}"#,
        )
            .into_response())
    } else {
        Ok((StatusCode::OK, headers, r#"{"status":"logged_out"}"#).into_response())
    }
}

#[cfg(test)]
mod tests {
    use super::qr_login_url_for_origin;

    #[test]
    fn qr_login_url_uses_requestee_token_only() {
        let requester_token = "requester-token";
        let requestee_token = "requestee-token";

        let url = qr_login_url_for_origin("https://caution.example", requestee_token);

        assert_eq!(
            url,
            "https://caution.example/qr-login?token=requestee-token"
        );
        assert!(url.contains(requestee_token));
        assert!(!url.contains(requester_token));
    }
}

#[cfg(test)]
mod login_begin_tests {
    use super::*;

    // --- normalize_login_username -------------------------------------
    //
    // These are the pure pieces of the `begin_login_handler` username
    // branching that don't need a DB or a webauthn ceremony, so they're
    // covered here as plain unit tests. The DB-backed branches (scoped
    // lookup returns only that user's creds, broadcast-vs-discoverable
    // selection driven by `login_allow_broadcast`, unknown username ->
    // empty allowCredentials with 200, discoverable finish round-trip via
    // `identify_discoverable_authentication` / `finish_discoverable_authentication`,
    // and the username-claim gate end-to-end) require a live Postgres
    // instance and a webauthn ceremony (or a stored/replayed one) to
    // exercise meaningfully. This crate has no `#[sqlx::test]`/ephemeral-DB
    // harness wired up today (no other test in `gateway` hits a live DB —
    // see `db.rs`'s and `rate_limit.rs`'s test modules, which are all
    // pure/in-memory), and no Postgres is available in this sandbox to add
    // and validate one. Those scenarios are best covered as gateway.rs
    // integration/e2e coverage (following the shell-script pattern under
    // `tests/e2e/*.sh`, run via `make up-test` per the caution-local-dev
    // skill) — flagged here rather than left silently uncovered.

    #[test]
    fn normalizes_present_username() {
        assert_eq!(
            normalize_login_username(Some("  Alice  ".to_string())),
            Some("alice".to_string())
        );
    }

    #[test]
    fn treats_empty_string_as_absent() {
        assert_eq!(normalize_login_username(Some("".to_string())), None);
    }

    #[test]
    fn treats_whitespace_only_as_absent() {
        assert_eq!(normalize_login_username(Some("   ".to_string())), None);
    }

    #[test]
    fn absent_stays_absent() {
        assert_eq!(normalize_login_username(None), None);
    }

    #[test]
    fn lowercases_mixed_case() {
        assert_eq!(
            normalize_login_username(Some("BoB".to_string())),
            Some("bob".to_string())
        );
    }

    // --- deserialize_security_keys -------------------------------------

    #[test]
    fn deserialize_security_keys_empty_list_is_ok() {
        let result = deserialize_security_keys(&[]);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn deserialize_security_keys_rejects_garbage() {
        let garbage = vec![b"not valid json".to_vec()];
        assert!(deserialize_security_keys(&garbage).is_err());
    }

    // --- check_username_scope -------------------------------------------
    //
    // Guards the discoverable-auth finish paths against resolving to a user
    // other than the one a username-scoped challenge expected (Finding 1:
    // decoy/zero-cred challenges must not silently authenticate whichever
    // resident credential the browser happens to return). `Unscoped` (no
    // username was ever supplied — plain broadcast/discoverable login) must
    // allow any resolved user; `Decoy` (a username was supplied, whether
    // unknown or known-zero-cred) must never succeed.

    #[test]
    fn check_username_scope_allows_unscoped_login() {
        let resolved = Uuid::new_v4();
        assert!(check_username_scope(&UsernameScope::Unscoped, resolved).is_ok());
    }

    #[test]
    fn check_username_scope_rejects_decoy_for_unknown_username() {
        // Username didn't resolve to any user at all: no expected_user_id,
        // but must still always reject, not just no-op like `Unscoped`.
        let resolved = Uuid::new_v4();
        let err = check_username_scope(&UsernameScope::Decoy { expected_user_id: None }, resolved)
            .unwrap_err();
        assert!(matches!(
            err,
            LoginError::UnexpectedCredentialOwner { expected_user_id: None, actual_user_id }
            if actual_user_id == resolved
        ));
    }

    #[test]
    fn check_username_scope_rejects_decoy_for_known_zero_cred_user_mismatch() {
        let expected = Uuid::new_v4();
        let resolved = Uuid::new_v4();
        let err = check_username_scope(
            &UsernameScope::Decoy { expected_user_id: Some(expected) },
            resolved,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            LoginError::UnexpectedCredentialOwner { expected_user_id: Some(e), actual_user_id }
            if e == expected && actual_user_id == resolved
        ));
    }

    #[test]
    fn check_username_scope_allows_decoy_matching_expected_user() {
        // Can't practically happen (the zero-cred decoy's user has no
        // credentials to resolve to), but if the expected user ever does
        // match the resolved one, it should be honored rather than rejected.
        let user = Uuid::new_v4();
        assert!(
            check_username_scope(&UsernameScope::Decoy { expected_user_id: Some(user) }, user)
                .is_ok()
        );
    }

    // --- apply_decoy_shape -----------------------------------------------
    //
    // `scoped_or_decoy_challenge` itself needs a live Postgres + a real
    // `Webauthn` instance (see the DB-backed-branches note above), but the
    // decoy *response-shaping* step it delegates to is pure: it just
    // mutates an already-built `RequestChallengeResponse`. That's covered
    // directly here without needing a DB or a webauthn ceremony, which is
    // what actually enforces the closed oracle: after this call, a
    // known-with-credentials response and a decoy response must be
    // byte-for-byte identical in shape (non-empty allowCredentials, no
    // mediation, Preferred UV).

    fn dummy_discoverable_rcr() -> RequestChallengeResponse {
        // Mirrors what `start_discoverable_authentication` hands back
        // before `apply_decoy_shape` overwrites it: empty allowCredentials
        // and `mediation: Conditional`.
        RequestChallengeResponse {
            public_key: webauthn_rs_proto::PublicKeyCredentialRequestOptions {
                challenge: vec![0u8; 32].into(),
                timeout: None,
                rp_id: "example.com".to_string(),
                allow_credentials: Vec::new(),
                user_verification: UserVerificationPolicy::Required,
                hints: None,
                extensions: None,
            },
            mediation: Some(Mediation::Conditional),
        }
    }

    #[test]
    fn apply_decoy_shape_produces_non_empty_allow_credentials() {
        let mut rcr = dummy_discoverable_rcr();
        apply_decoy_shape(&mut rcr, "secret", "nobody");
        assert!(!rcr.public_key.allow_credentials.is_empty());
    }

    #[test]
    fn apply_decoy_shape_clears_mediation() {
        let mut rcr = dummy_discoverable_rcr();
        apply_decoy_shape(&mut rcr, "secret", "nobody");
        assert!(rcr.mediation.is_none());
    }

    #[test]
    fn apply_decoy_shape_sets_preferred_user_verification() {
        let mut rcr = dummy_discoverable_rcr();
        apply_decoy_shape(&mut rcr, "secret", "nobody");
        assert_eq!(rcr.public_key.user_verification, UserVerificationPolicy::Preferred);
    }

    #[test]
    fn apply_decoy_shape_stable_across_calls_for_same_username() {
        let mut a = dummy_discoverable_rcr();
        let mut b = dummy_discoverable_rcr();
        apply_decoy_shape(&mut a, "secret", "alice");
        apply_decoy_shape(&mut b, "secret", "alice");
        let ids_a: Vec<_> = a.public_key.allow_credentials.iter().map(|c| c.id.as_ref().to_vec()).collect();
        let ids_b: Vec<_> = b.public_key.allow_credentials.iter().map(|c| c.id.as_ref().to_vec()).collect();
        assert_eq!(ids_a, ids_b, "decoy for a given username must be stable across calls");
    }

    #[test]
    fn apply_decoy_shape_matches_real_scoped_response_shape() {
        // Simulates the real-user branch's shape: non-empty allowCredentials,
        // no mediation, Preferred UV — built independently of
        // `apply_decoy_shape` to assert the two are indistinguishable.
        let mut real = dummy_discoverable_rcr();
        real.public_key.allow_credentials = vec![webauthn_rs_proto::AllowCredentials {
            type_: "public-key".to_string(),
            id: vec![1, 2, 3].into(),
            transports: None,
        }];
        real.mediation = None;
        real.public_key.user_verification = UserVerificationPolicy::Preferred;

        let mut decoy_rcr = dummy_discoverable_rcr();
        apply_decoy_shape(&mut decoy_rcr, "secret", "someone");

        assert!(!real.public_key.allow_credentials.is_empty());
        assert!(!decoy_rcr.public_key.allow_credentials.is_empty());
        assert_eq!(real.mediation.is_none(), decoy_rcr.mediation.is_none());
        assert!(decoy_rcr.mediation.is_none());
        assert_eq!(
            real.public_key.user_verification,
            decoy_rcr.public_key.user_verification
        );
    }

    #[test]
    fn decoy_timing_fixtures_round_trip_through_deserialize_security_keys() {
        // Guards against future format drift (e.g. a webauthn-rs upgrade
        // changing `SecurityKey`'s serde shape) silently breaking
        // `equalize_decoy_work` in CI before `validate_decoy_timing_fixtures`
        // would catch it at startup in a real deployment.
        for fixture in DECOY_TIMING_FIXTURES {
            assert!(deserialize_security_keys(&[fixture.to_vec()]).is_ok());
        }
    }

    #[test]
    fn validate_decoy_timing_fixtures_does_not_panic() {
        validate_decoy_timing_fixtures();
    }

    // --- per-username rate limiting (enumeration defense item #3) --------
    //
    // `scoped_or_decoy_challenge` checks `state.username_begin_limiter`
    // BEFORE any DB work, so the forced-decoy branch is exercisable without
    // a live Postgres: build an `AppState` around a lazy (never-connecting)
    // pool via `PgPoolOptions::connect_lazy`, which is safe here specifically
    // because a tripped username limiter short-circuits before the first
    // query would ever be issued.

    fn test_app_state(username_limiter_max: u32) -> AppState {
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let rp_origin = Url::parse("https://example.com").unwrap();
        let webauthn = WebauthnBuilder::new("example.com", &rp_origin)
            .unwrap()
            .rp_name("Test RP")
            .build()
            .unwrap();
        let db = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://user:pass@localhost/nonexistent")
            .expect("connect_lazy does not actually connect");

        AppState {
            db,
            webauthn,
            relying_party_id: "example.com".to_string(),
            api_service_url: String::new(),
            metering_service_url: String::new(),
            reg_states: Arc::new(RwLock::new(HashMap::new())),
            passkey_reg_states: Arc::new(RwLock::new(HashMap::new())),
            auth_states: Arc::new(RwLock::new(HashMap::new())),
            sign_challenges: Arc::new(RwLock::new(HashMap::new())),
            session_timeout_hours: 24,
            internal_service_secret: None,
            csrf_secret: "test-secret".to_string(),
            login_allow_broadcast: true,
            scoped_begin_limiter: crate::rate_limit::RateLimiter::new(1000, 60),
            username_begin_limiter: crate::rate_limit::RateLimiter::new(username_limiter_max, 60),
        }
    }

    #[tokio::test]
    async fn username_limiter_trips_after_budget_exhausted() {
        let state = test_app_state(3);

        for _ in 0..3 {
            assert!(state.username_begin_limiter.check_rate_limit("alice").await);
        }
        assert!(!state.username_begin_limiter.check_rate_limit("alice").await);
    }

    #[tokio::test]
    async fn username_limiter_is_independent_per_username() {
        let state = test_app_state(1);

        assert!(state.username_begin_limiter.check_rate_limit("alice").await);
        assert!(!state.username_begin_limiter.check_rate_limit("alice").await);

        // "bob" has his own untouched budget.
        assert!(state.username_begin_limiter.check_rate_limit("bob").await);
    }

    #[tokio::test]
    async fn scoped_or_decoy_challenge_forces_decoy_when_username_limiter_exceeded() {
        // Budget of 1: the first call is allowed through to the (never
        // reached, thanks to the lazy pool) DB path; the second call must
        // be forced to a decoy WITHOUT touching the DB.
        let state = test_app_state(1);

        // Exhaust the budget directly rather than via a real DB-backed call.
        assert!(state.username_begin_limiter.check_rate_limit("realuser").await);
        assert!(!state.username_begin_limiter.check_rate_limit("realuser").await);

        let (rcr, auth_state) = scoped_or_decoy_challenge(&state, "realuser")
            .await
            .expect("forced decoy must not touch the DB and so must not error");

        assert!(
            !rcr.public_key.allow_credentials.is_empty(),
            "forced decoy must still carry a non-empty allowCredentials list"
        );
        assert!(rcr.mediation.is_none());
        assert_eq!(rcr.public_key.user_verification, UserVerificationPolicy::Preferred);

        match auth_state {
            AuthState::Discoverable { scope, .. } => {
                assert!(
                    matches!(scope, UsernameScope::Decoy { expected_user_id: None }),
                    "a forced decoy never did the DB lookup, so expected_user_id must be None"
                );
            }
            AuthState::SecurityKey(_) => {
                panic!("forced decoy must never produce a real SecurityKey auth state")
            }
        }
    }

    #[tokio::test]
    async fn scoped_or_decoy_challenge_forced_decoy_matches_natural_decoy_shape() {
        // The forced-decoy response (limiter tripped) must be shape-identical
        // to the natural decoy response `apply_decoy_shape` produces
        // (non-empty allowCredentials, no mediation, Preferred UV) — an
        // observer must not be able to tell "rate limited" apart from
        // "unknown username" apart from "known but zero creds".
        let state = test_app_state(1);
        assert!(state.username_begin_limiter.check_rate_limit("someone").await);
        assert!(!state.username_begin_limiter.check_rate_limit("someone").await);

        let (forced_rcr, _) = scoped_or_decoy_challenge(&state, "someone").await.unwrap();

        let mut natural_rcr = dummy_discoverable_rcr();
        apply_decoy_shape(&mut natural_rcr, &state.csrf_secret, "someone");

        assert_eq!(
            forced_rcr.public_key.allow_credentials.len(),
            natural_rcr.public_key.allow_credentials.len()
        );
        assert_eq!(forced_rcr.mediation.is_none(), natural_rcr.mediation.is_none());
        assert_eq!(
            forced_rcr.public_key.user_verification,
            natural_rcr.public_key.user_verification
        );
    }

    #[tokio::test]
    async fn scoped_or_decoy_challenge_invalid_username_format_still_returns_decoy_shape() {
        // A username that fails `validate_username` (too short here) can
        // never be a real account, so this must short-circuit to a decoy
        // WITHOUT touching the per-username limiter or the (never-connecting)
        // DB pool, while still returning the same shape as every other decoy.
        let state = test_app_state(1000);

        let (rcr, auth_state) = scoped_or_decoy_challenge(&state, "ab")
            .await
            .expect("invalid-format username must not touch the DB and so must not error");

        assert!(!rcr.public_key.allow_credentials.is_empty());
        assert!(rcr.mediation.is_none());
        assert_eq!(rcr.public_key.user_verification, UserVerificationPolicy::Preferred);

        match auth_state {
            AuthState::Discoverable { scope, .. } => {
                assert!(matches!(scope, UsernameScope::Decoy { expected_user_id: None }));
            }
            AuthState::SecurityKey(_) => {
                panic!("invalid-format username must never produce a real SecurityKey auth state")
            }
        }

        // The per-username limiter budget must be untouched by the
        // format-invalid short-circuit (it never got a chance to grow the
        // limiter's key space for this garbage username).
        assert!(
            state.username_begin_limiter.check_rate_limit("ab").await,
            "format short-circuit must not have consumed a rate-limit slot for this username"
        );
    }
}
