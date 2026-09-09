// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use dterror::{BoxError, CtxError, Location};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::*;

/// A simple domain error for cases where no concrete underlying error type
/// exists (e.g. a missing field, a rate-limit threshold exceeded). Implements
/// `Display + Error` so it satisfies `Into<BoxError>`.
#[derive(Debug)]
pub(crate) struct DomainError(pub(crate) &'static str);

impl std::fmt::Display for DomainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for DomainError {}

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
    reg_response
        .extensions
        .cred_props
        .as_ref()
        .and_then(|cp| cp.rk)
}

/// Maximum number of pending challenges per store to prevent OOM from abuse
pub(crate) const MAX_PENDING_CHALLENGES: usize = 10_000;

#[derive(Debug, thiserror::Error, CtxError)]
pub enum LoginError {
    #[error("invalid or expired session: {session_id} [{location}]")]
    InvalidSession {
        session_id: String,

        #[location]
        location: Location,
    },

    #[error("authentication challenge has expired [{location}]")]
    ChallengeExpired {
        #[location]
        location: Location,
    },

    #[error("your organization requires PIN verification [{location}]")]
    PinRequired {
        #[location]
        location: Location,
    },

    #[error("failed to parse pubkey credential [{location}]")]
    ParsePubkeyCredential {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("could not find user ID for: {provided_bytes:?} [{location}]")]
    DbGetUserIdByCredential {
        provided_bytes: Vec<u8>,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("could not get public key for user {user_id} [{location}]")]
    DbGetPublicKeyForCredential {
        user_id: Uuid,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("could not find PIN verification info for user {user_id} [{location}]")]
    DbUserPinRequired {
        user_id: Uuid,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("could not update fido2 credentials for user {user_id} [{location}]")]
    DbUpdateFido2Credential {
        user_id: Uuid,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("could not create auth session for user {user_id} [{location}]")]
    DbCreateAuthSession {
        user_id: Uuid,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("could not get security key for user {user_id} [{location}]")]
    ParseSecurityKey {
        user_id: Uuid,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("security key authentication could not be finalized for user {user_id} [{location}]")]
    FinishSecurityKeyAuthentication {
        user_id: Uuid,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("could not identify discoverable credential from assertion [{location}]")]
    IdentifyDiscoverableCredential {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("discoverable authentication could not be finalized for user {user_id} [{location}]")]
    FinishDiscoverableAuthentication {
        user_id: Uuid,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("could not serialize security credential result for user {user_id} [{location}]")]
    SerializeSecurityKey {
        user_id: Uuid,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("could not serialize login finish response [{location}]")]
    SerializeLoginFinishResponse {
        user_id: Uuid,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error(
        "resolved credential belongs to a different user than the login was scoped to [{location}]"
    )]
    UnexpectedCredentialOwner {
        expected_user_id: Option<Uuid>,
        actual_user_id: Uuid,

        #[location]
        location: Location,
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
pub(crate) fn generic_auth_failure_response() -> (StatusCode, HeaderMap, &'static str) {
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
            Self::InvalidSession { .. } | Self::ChallengeExpired { .. } => {
                tracing::debug!(?self, "Login finish: session/challenge error");
                generic_auth_failure_response().into_response()
            }
            Self::PinRequired { .. } => (
                StatusCode::FORBIDDEN,
                "your organization requires PIN verification",
            )
                .into_response(),
            Self::ParsePubkeyCredential { .. } => {
                (StatusCode::BAD_REQUEST, "failed to parse pubkey credential").into_response()
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
                tracing::error!(
                    ?self,
                    "Login finish: could not identify discoverable credential"
                );
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
                    "an internal error occurred",
                )
                    .into_response()
            }
        }
    }
}

/// Error type for the sign-request session validation helper
/// (`authenticate_session`) and the direct sign-challenge endpoint. Strict
/// dterror convention: every variant carries `#[location]`; source-bearing
/// variants use `.with_context(Ctx::internal())` at call sites; source-less
/// (domain) variants are hand-built with `std::panic::Location::caller()`.
#[derive(Debug, thiserror::Error, CtxError)]
pub enum SignRequestError {
    #[error("missing session [{location}]")]
    MissingSession {
        #[location]
        location: Location,
    },

    #[error("invalid or expired session: {session_id} [{location}]")]
    InvalidSession {
        session_id: String,

        #[location]
        location: Location,
    },

    #[error("missing CSRF token for session: {session_id} [{location}]")]
    CsrfMissing {
        session_id: String,

        #[location]
        location: Location,
    },

    #[error("invalid CSRF token for session: {session_id} [{location}]")]
    CsrfInvalid {
        session_id: String,

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

impl IntoResponse for SignRequestError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::MissingSession { .. } => {
                (StatusCode::UNAUTHORIZED, "missing session".to_string())
            }
            Self::InvalidSession { ref session_id, .. } => (
                StatusCode::UNAUTHORIZED,
                format!("invalid or expired session: {session_id}"),
            ),
            Self::CsrfMissing { ref session_id, .. } => (
                StatusCode::FORBIDDEN,
                format!("missing CSRF token for session: {session_id}"),
            ),
            Self::CsrfInvalid { ref session_id, .. } => (
                StatusCode::FORBIDDEN,
                format!("invalid CSRF token for session: {session_id}"),
            ),
            Self::Internal { .. } => {
                tracing::error!(?self, "Sign request error");
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

#[derive(Debug, thiserror::Error, CtxError)]
pub enum RegisterError {
    #[error("This access code is invalid or has already been used. [{location}]")]
    InvalidAccessCode {
        #[location]
        location: Location,
    },

    #[error("This token is invalid, expired, or has already been used. [{location}]")]
    InvalidInvitation {
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

    #[error("Invalid username: {username_error} [{location}]")]
    InvalidUsername {
        username_error: String,

        #[location]
        location: Location,
    },

    #[error("This username is already taken. [{location}]")]
    UsernameTaken {
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

impl IntoResponse for RegisterError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::InvalidAccessCode { .. } => (
                StatusCode::BAD_REQUEST,
                "This access code is invalid or has already been used.".to_string(),
            ),
            Self::InvalidInvitation { .. } => (
                StatusCode::BAD_REQUEST,
                "This token is invalid, expired, or has already been used.".to_string(),
            ),
            Self::ChallengeExpired { .. } => (
                StatusCode::GONE,
                "Registration challenge has expired. Please try again.".to_string(),
            ),
            Self::NoRegistrationState { .. } => (
                StatusCode::GONE,
                "No matching registration state found. Please start over.".to_string(),
            ),
            Self::CredentialAlreadyRegistered { .. } => (
                StatusCode::CONFLICT,
                "This security key is already registered. Each key can only be registered once."
                    .to_string(),
            ),
            Self::TooManyPending { .. } => (
                StatusCode::TOO_MANY_REQUESTS,
                "Too many pending registrations. Please try again later.".to_string(),
            ),
            Self::InvalidUsername {
                ref username_error, ..
            } => (
                StatusCode::BAD_REQUEST,
                format!("Invalid username: {username_error}"),
            ),
            Self::UsernameTaken { .. } => (
                StatusCode::CONFLICT,
                "This username is already taken.".to_string(),
            ),
            // An unparseable registration body is a client error: earlier
            // rounds deliberately reclassified this from the generic 500 to a
            // 400 with an explicit message. Keep that accepted behavior.
            Self::InvalidPayload { .. } => (
                StatusCode::BAD_REQUEST,
                "Invalid registration request body.".to_string(),
            ),
            Self::Internal { .. } => {
                tracing::error!(?self, "Registration error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal error occurred".to_string(),
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
