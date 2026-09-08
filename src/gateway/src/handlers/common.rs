// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::*;

/// Clear the `credProtect` extension (which forces UV=Required and conflicts
/// with our UV=Preferred authenticator selection, rejecting PIN-less smart
/// cards and password-manager registrations) while keeping `credProps`
/// requested, so the browser reports whether it created a resident
/// (discoverable) credential. Read back at finish time via
/// `extensions.cred_props.rk` and stored on the credential row.
#[tracing::instrument(skip_all)]
pub(crate) fn relax_registration_extensions(
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
#[tracing::instrument(skip_all)]
pub(crate) fn read_credprops_rk(reg_response: &RegisterPublicKeyCredential) -> Option<bool> {
    reg_response.extensions.cred_props.as_ref().and_then(|cp| cp.rk)
}

/// Maximum number of pending challenges per store to prevent OOM from abuse
pub(crate) const MAX_PENDING_CHALLENGES: usize = 10_000;

#[derive(Debug)]
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

#[tracing::instrument(skip_all)]
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

#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    #[error("This access code is invalid or has already been used.")]
    InvalidAccessCode,
    #[error("This token is invalid, expired, or has already been used.")]
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

/// Build auth cookies for session and CSRF protection
#[tracing::instrument(skip_all)]
pub(crate) fn build_auth_cookies(
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
