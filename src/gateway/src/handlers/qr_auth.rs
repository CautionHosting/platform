// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::db;
use crate::types::*;
use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::Engine as _;
use dterror::{BoxError, CtxError, Location};
use serde::Deserialize;
use time::Duration;
use uuid::Uuid;
use webauthn_rs::prelude::*;
use webauthn_rs_proto::UserVerificationPolicy;

use super::{
    check_username_scope, generic_auth_failure_response, normalize_login_username,
    scoped_or_decoy_challenge, DomainError, SignRequestError, SignRequestErrorCtx as Ctx,
    MAX_PENDING_CHALLENGES,
};
use dterror::ResultExt;

/// Error type for the QR login ceremony's finish step only. Mirrors the
/// behavior of `LoginError::into_response`: every credential-verification and
/// session-lifecycle failure collapses into the same byte-for-byte identical
/// generic 401 (see `GENERIC_AUTH_FAILURE_BODY` in `handlers/common.rs`) so
/// the cross-device finish endpoint can't become a username-enumeration
/// oracle. Kept as its own type because several of its variants (`TokenNotFound`
/// style lookup failures, token completion) describe the QR-token lifecycle,
/// not the direct cookie-login one. Strict dterror convention: every variant
/// carries `#[location]`; source-bearing variants use `.with_context(Ctx::…)`
/// at call sites; source-less (domain) variants are hand-built with
/// `std::panic::Location::caller()`.
#[derive(Debug, thiserror::Error, CtxError)]
pub enum QrLoginFinishError {
    #[error("invalid or expired QR login session: {reason} [{location}]")]
    InvalidSession {
        reason: String,

        #[location]
        location: Location,
    },

    #[error("authentication challenge has expired [{location}]")]
    ChallengeExpired {
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

    #[error("could not get public key for user {user_id} [{location}]")]
    DbGetPublicKeyForCredential {
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

    #[error(
        "resolved credential belongs to a different user than the login was scoped to [{location}]"
    )]
    UnexpectedCredentialOwner {
        expected_user_id: Option<Uuid>,
        actual_user_id: Uuid,

        #[location]
        location: Location,
    },

    #[error("your organization requires PIN verification [{location}]")]
    PinRequired {
        #[location]
        location: Location,
    },

    #[error("could not serialize security credential result for user {user_id} [{location}]")]
    SerializeSecurityKey {
        user_id: Uuid,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("could not query PIN verification info for user {user_id} [{location}]")]
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

    #[error("could not complete QR login token for user {user_id} [{location}]")]
    DbCompleteQrLoginToken {
        user_id: Uuid,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

impl IntoResponse for QrLoginFinishError {
    fn into_response(self) -> Response {
        match self {
            // Session/challenge lifecycle errors are folded into the same
            // generic 401 as credential-verification failures (same oracle
            // rationale as `LoginError::into_response`).
            Self::InvalidSession { .. } | Self::ChallengeExpired { .. } => {
                tracing::debug!(?self, "QR login finish: session/challenge error");
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
            // Every credential-verification outcome collapses to the same
            // generic 401 response so none of them is distinguishable from
            // another by status code or body.
            Self::UnexpectedCredentialOwner { .. } => {
                tracing::debug!(?self, "QR login finish: decoy/scope rejection");
                generic_auth_failure_response().into_response()
            }
            Self::DbGetPublicKeyForCredential { .. } | Self::ParseSecurityKey { .. } => {
                tracing::warn!(?self, "QR login finish: credential lookup/parse failure");
                generic_auth_failure_response().into_response()
            }
            Self::IdentifyDiscoverableCredential { .. } => {
                tracing::error!(
                    ?self,
                    "QR login finish: could not identify discoverable credential"
                );
                generic_auth_failure_response().into_response()
            }
            Self::FinishSecurityKeyAuthentication { .. }
            | Self::FinishDiscoverableAuthentication { .. } => {
                tracing::warn!(?self, "QR login finish: signature verification failed");
                generic_auth_failure_response().into_response()
            }
            _ => {
                tracing::error!(?self, "QR login error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "an internal error occurred",
                )
                    .into_response()
            }
        }
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum QrLoginError {
    #[error("QR login token not found [{location}]")]
    TokenNotFound {
        #[location]
        location: Location,
    },

    #[error("QR login token has expired [{location}]")]
    TokenExpired {
        #[location]
        location: Location,
    },

    #[error("QR login token in unexpected state: {status} [{location}]")]
    UnexpectedState {
        status: String,

        #[location]
        location: Location,
    },

    #[error("QR login token already claimed [{location}]")]
    AlreadyClaimed {
        #[location]
        location: Location,
    },

    #[error("username is required for QR login [{location}]")]
    MissingUsername {
        #[location]
        location: Location,
    },

    #[error("could not create QR login token [{location}]")]
    DbCreateToken {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("could not query QR login token [{location}]")]
    DbGetToken {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("could not claim QR login token [{location}]")]
    DbClaimToken {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("could not query auth session [{location}]")]
    DbGetSession {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("could not build username-scoped challenge [{location}]")]
    ScopedChallenge {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Rate limit exceeded. Please try again later. [{location}]")]
    RateLimited {
        #[location]
        location: Location,
    },
}

impl IntoResponse for QrLoginError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::TokenNotFound { .. } => (
                StatusCode::NOT_FOUND,
                "QR login token not found".to_string(),
            ),
            Self::TokenExpired { .. } => {
                (StatusCode::GONE, "QR login token has expired".to_string())
            }
            Self::UnexpectedState { ref status, .. } => (
                StatusCode::CONFLICT,
                format!("QR login token in unexpected state: {status}"),
            ),
            Self::AlreadyClaimed { .. } => (
                StatusCode::CONFLICT,
                "QR login token already claimed".to_string(),
            ),
            Self::MissingUsername { .. } => (
                StatusCode::BAD_REQUEST,
                "username is required for QR login".to_string(),
            ),
            Self::RateLimited { .. } => (
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded. Please try again later.".to_string(),
            ),
            _ => {
                tracing::error!(?self, "QR login error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "an internal error occurred".to_string(),
                )
            }
        };
        (status, message).into_response()
    }
}

/// Create a sign challenge for the given credential. Returns (challenge_response, challenge_id).
/// Stores PendingSignChallenge in state.sign_challenges.
#[tracing::instrument(skip_all, err)]
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
        .with_context(Ctx::internal())?;
    let requires_pin = db::user_requires_pin(&state.db, user_id)
        .await
        .with_context(Ctx::internal())?;

    let cred_bytes = db::get_credential_public_key(&state.db, credential_id)
        .await
        .with_context(Ctx::internal())?;
    let seckey: SecurityKey = serde_json::from_slice(&cred_bytes).with_context(Ctx::internal())?;

    let (mut rcr, auth_state) = state
        .webauthn
        .start_securitykey_authentication(&[seckey])
        .with_context(Ctx::internal())?;

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
            return Err(SignRequestError::Internal {
                location: std::panic::Location::caller(),
                source: Box::new(DomainError("too many pending sign challenges")),
            });
        }
        sign_challenges.insert(challenge_id.to_string(), pending);
    }

    Ok((rcr, challenge_id.to_string()))
}

/// Resolve session ID from headers (X-Session-ID or caution_session cookie),
/// validate it, and enforce CSRF for cookie-based auth. Returns credential_id.
#[tracing::instrument(skip_all, err)]
pub(crate) async fn authenticate_session(
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
        return Err(SignRequestError::MissingSession {
            location: std::panic::Location::caller(),
        });
    };

    let credential_id = db::validate_auth_session(&state.db, &session_id)
        .await
        .with_context(Ctx::internal())?
        .ok_or_else(|| SignRequestError::InvalidSession {
            session_id: session_id.clone(),
            location: std::panic::Location::caller(),
        })?;

    if !using_header_auth {
        let expected_csrf = crate::csrf::derive_csrf_token(&session_id, &state.csrf_secret);
        let csrf_header = headers
            .get("X-CSRF-Token")
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| SignRequestError::CsrfMissing {
                session_id: session_id.clone(),
                location: std::panic::Location::caller(),
            })?;
        if !crate::csrf::constant_time_compare(&expected_csrf, csrf_header) {
            return Err(SignRequestError::CsrfInvalid {
                session_id: session_id.clone(),
                location: std::panic::Location::caller(),
            });
        }
    }

    Ok(credential_id)
}

#[tracing::instrument(skip_all)]
fn get_rp_origin() -> String {
    std::env::var("RP_ORIGINS")
        .unwrap_or_else(|_| "http://localhost:8000".to_string())
        .split(',')
        .next()
        .unwrap_or("http://localhost:8000")
        .trim()
        .to_string()
}

#[tracing::instrument(skip_all, err)]
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

// QR Login handlers

#[derive(Debug, Deserialize)]
pub struct QrLoginStatusQuery {
    pub token: String,
}

#[tracing::instrument(skip_all)]
fn qr_login_url_for_origin(origin: &str, requestee_token: &str) -> String {
    format!("{origin}/qr-login?token={requestee_token}")
}

#[tracing::instrument(skip_all)]
fn qr_login_url(requestee_token: &str) -> String {
    qr_login_url_for_origin(&get_rp_origin(), requestee_token)
}

#[tracing::instrument(skip_all, err)]
pub async fn qr_login_begin_handler(
    State(state): State<AppState>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
    body: axum::body::Bytes,
) -> Result<Json<crate::types::QrLoginBeginResponse>, QrLoginError> {
    use QrLoginErrorCtx as QrCtx;

    // Parse request body and validate username is present and non-empty.
    let Some(username) = normalize_login_username(
        serde_json::from_slice::<crate::types::QrLoginBeginRequest>(&body)
            .ok()
            .map(|r| r.username),
    ) else {
        return Err(QrLoginError::MissingUsername {
            location: std::panic::Location::caller(),
        });
    };

    let token = db::generate_session_id();
    let requestee_token = db::generate_session_id();
    let expires_at = time::OffsetDateTime::now_utc() + Duration::minutes(3);
    let ip_address = connect_info.0.ip().to_string();

    let url = qr_login_url(&requestee_token);

    db::create_qr_login_token(
        &state.db,
        &token,
        &requestee_token,
        Some(&ip_address),
        expires_at,
        &username,
    )
    .await
    .with_context(QrCtx::db_create_token())?;

    Ok(Json(crate::types::QrLoginBeginResponse {
        token,
        url,
        expires_at: expires_at.to_string(),
    }))
}

#[tracing::instrument(skip_all, err)]
pub async fn qr_login_status_handler(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<QrLoginStatusQuery>,
) -> Result<Json<crate::types::QrLoginStatusResponse>, QrLoginError> {
    use QrLoginErrorCtx as QrCtx;

    let row = db::get_qr_login_token(&state.db, &query.token)
        .await
        .with_context(QrCtx::db_get_token())?;

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
                .with_context(QrCtx::db_get_session())?;

            let session_expires = session.map(|s| s.expires_at.to_string());

            // Consume last: atomically NULLs session_id and confirms we won any
            // concurrent-poll race. Only hand back the session if we did.
            let consumed = db::consume_qr_login_session_id(&state.db, &query.token)
                .await
                .with_context(QrCtx::db_get_token())?;

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

#[tracing::instrument(skip_all, err)]
pub async fn qr_login_authenticate_handler(
    State(state): State<AppState>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
    Json(req): Json<crate::types::QrLoginAuthenticateRequest>,
) -> Result<Json<crate::types::QrLoginAuthenticateResponse>, QrLoginError> {
    use QrLoginErrorCtx as QrCtx;

    // Verify requestee token exists and is pending
    let row = db::get_qr_login_token_by_requestee_token(&state.db, &req.token)
        .await
        .with_context(QrCtx::db_get_token())?
        .ok_or_else(|| QrLoginError::TokenNotFound {
            location: std::panic::Location::caller(),
        })?;

    if time::OffsetDateTime::now_utc() > row.expires_at {
        return Err(QrLoginError::TokenExpired {
            location: std::panic::Location::caller(),
        });
    }

    match QrStatus::from_db(&row.status) {
        Some(QrStatus::Pending) => {}
        Some(QrStatus::Authenticated) | Some(QrStatus::Completed) => {
            return Err(QrLoginError::AlreadyClaimed {
                location: std::panic::Location::caller(),
            })
        }
        _ => {
            return Err(QrLoginError::UnexpectedState {
                status: row.status,
                location: std::panic::Location::caller(),
            })
        }
    }

    // A username stored on the token scopes the challenge to that user's own
    // credentials — needed for non-resident/legacy keys.
    let (rcr, auth_state) = {
        let ip = connect_info.0.ip();
        if !state
            .scoped_begin_limiter
            .check_rate_limit(&ip.to_string())
            .await
        {
            tracing::warn!("Scoped begin-login rate limit exceeded for IP: {}", ip);
            return Err(QrLoginError::RateLimited {
                location: std::panic::Location::caller(),
            });
        }

        scoped_or_decoy_challenge(&state, &row.username)
            .await
            .with_context(QrCtx::scoped_challenge())?
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
        .with_context(QrCtx::db_claim_token())?;
    if !claimed {
        return Err(QrLoginError::AlreadyClaimed {
            location: std::panic::Location::caller(),
        });
    }
    {
        let mut auth_states = state.auth_states.write().await;
        if auth_states.len() >= MAX_PENDING_CHALLENGES {
            return Err(QrLoginError::UnexpectedState {
                status: "Too many pending challenges".to_string(),
                location: std::panic::Location::caller(),
            });
        }
        auth_states.insert(session_key.clone(), pending);
    }

    Ok(Json(crate::types::QrLoginAuthenticateResponse {
        challenge: rcr,
        session: session_key,
        token: req.token,
    }))
}

#[tracing::instrument(skip_all, err)]
pub async fn qr_login_authenticate_finish_handler(
    State(state): State<AppState>,
    Json(req): Json<crate::types::QrLoginAuthenticateFinishRequest>,
) -> Result<Json<serde_json::Value>, QrLoginFinishError> {
    use QrLoginFinishErrorCtx as FinishCtx;

    let token = req.token;
    let session_key = req.session;

    // Verify requestee token is authenticated and session key matches
    let row = match db::get_qr_login_token_by_requestee_token(&state.db, &token).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return Err(QrLoginFinishError::InvalidSession {
                reason: "invalid QR login token".into(),
                location: std::panic::Location::caller(),
            });
        }
        Err(e) => {
            return Err(QrLoginFinishError::InvalidSession {
                reason: e.to_string(),
                location: std::panic::Location::caller(),
            });
        }
    };

    match QrStatus::from_db(&row.status) {
        Some(QrStatus::Authenticated) => {}
        other => {
            tracing::warn!(
                "QR login finish called with unexpected token status: {:?} (token: {})",
                other,
                token
            );
            return Err(QrLoginFinishError::InvalidSession {
                reason: format!("QR login token in unexpected state: {}", row.status),
                location: std::panic::Location::caller(),
            });
        }
    }

    if row.auth_challenge_key.as_deref() != Some(&session_key) {
        tracing::warn!(
            "QR login finish session key mismatch: expected {:?}, got {:?} (token: {})",
            row.auth_challenge_key,
            session_key,
            token
        );
        return Err(QrLoginFinishError::InvalidSession {
            reason: "session key mismatch".into(),
            location: std::panic::Location::caller(),
        });
    }

    // Take the pending auth state (single write guard for get + remove)
    let pending = {
        let mut auth_states = state.auth_states.write().await;
        auth_states
            .remove(&session_key)
            .ok_or_else(|| QrLoginFinishError::InvalidSession {
                reason: session_key.clone(),
                location: std::panic::Location::caller(),
            })?
    };

    if time::OffsetDateTime::now_utc() > pending.expires_at {
        return Err(QrLoginFinishError::ChallengeExpired {
            location: std::panic::Location::caller(),
        });
    }

    let auth_response: webauthn_rs::prelude::PublicKeyCredential =
        serde_json::from_value(req.credential).with_context(FinishCtx::parse_pubkey_credential())?;

    let (user_id, credential_id_bytes, mut seckey, auth_result) = match pending.auth_state {
        AuthState::SecurityKey(auth_state) => {
            let credential_id_bytes = auth_response.raw_id.as_ref().to_vec();

            let user_id = match db::get_user_id_by_credential(&state.db, &credential_id_bytes).await
            {
                Ok(user_id) => user_id,
                Err(source) => {
                    tracing::debug!(?source, "QR login finish: credential not found");
                    return Err(QrLoginFinishError::UnexpectedCredentialOwner {
                        expected_user_id: None,
                        actual_user_id: Uuid::nil(),
                        location: std::panic::Location::caller(),
                    });
                }
            };

            let cred_bytes = db::get_credential_public_key(&state.db, &credential_id_bytes)
                .await
                .with_context(FinishCtx::db_get_public_key_for_credential(user_id))?;
            let seckey: webauthn_rs::prelude::SecurityKey = serde_json::from_slice(&cred_bytes)
                .with_context(FinishCtx::parse_security_key(user_id))?;

            let auth_result = state
                .webauthn
                .finish_securitykey_authentication(&auth_response, &auth_state)
                .with_context(FinishCtx::finish_security_key_authentication(user_id))?;

            (user_id, credential_id_bytes, seckey, auth_result)
        }
        AuthState::Discoverable { auth_state, scope } => {
            let (_user_handle, cred_id) = state
                .webauthn
                .identify_discoverable_authentication(&auth_response)
                .with_context(FinishCtx::identify_discoverable_credential())?;
            let credential_id_bytes = cred_id.to_vec();

            let user_id = match db::get_user_id_by_credential(&state.db, &credential_id_bytes).await
            {
                Ok(user_id) => user_id,
                Err(source) => {
                    tracing::debug!(?source, "QR login finish: credential not found");
                    return Err(QrLoginFinishError::UnexpectedCredentialOwner {
                        expected_user_id: None,
                        actual_user_id: Uuid::nil(),
                        location: std::panic::Location::caller(),
                    });
                }
            };

            let cred_bytes = db::get_credential_public_key(&state.db, &credential_id_bytes)
                .await
                .with_context(FinishCtx::db_get_public_key_for_credential(user_id))?;
            let seckey: webauthn_rs::prelude::SecurityKey = serde_json::from_slice(&cred_bytes)
                .with_context(FinishCtx::parse_security_key(user_id))?;

            let credential: Credential = seckey.clone().into();
            let passkey: Passkey = credential.into();
            let discoverable_key: DiscoverableKey = passkey.into();

            let auth_result = state
                .webauthn
                .finish_discoverable_authentication(&auth_response, auth_state, &[discoverable_key])
                .with_context(FinishCtx::finish_discoverable_authentication(user_id))?;

            // See the equivalent check in `finish_login_handler` (Finding 1):
            // ceremony is consumed above regardless of outcome.
            if let Some((expected_user_id, actual_user_id)) = check_username_scope(&scope, user_id)
            {
                return Err(QrLoginFinishError::UnexpectedCredentialOwner {
                    expected_user_id,
                    actual_user_id,
                    location: std::panic::Location::caller(),
                });
            }

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
        .with_context(FinishCtx::db_user_pin_required(user_id))?;
    if requires_pin && !auth_result.user_verified() {
        return Err(QrLoginFinishError::PinRequired {
            location: std::panic::Location::caller(),
        });
    }

    if auth_result.needs_update() {
        let update_result = seckey.update_credential(&auth_result);
        if let Some(true) = update_result {
            let updated_key_json = serde_json::to_vec(&seckey)
                .with_context(FinishCtx::serialize_security_key(user_id))?;
            db::update_fido2_credential(
                &state.db,
                &credential_id_bytes,
                &updated_key_json,
                auth_result.counter(),
            )
            .await
            .with_context(FinishCtx::db_update_fido2_credential(user_id))?;
        }
    }

    // Create auth session (NO cookies — CLI uses header auth)
    let session_id = db::generate_session_id();
    let expires_at = time::OffsetDateTime::now_utc() + Duration::hours(state.session_timeout_hours);

    db::create_auth_session(&state.db, &session_id, &credential_id_bytes, expires_at)
        .await
        .with_context(FinishCtx::db_create_auth_session(user_id))?;

    // Mark token completed
    db::complete_qr_login_token(&state.db, &token, &session_id)
        .await
        .with_context(FinishCtx::db_complete_qr_login_token(user_id))?;

    tracing::debug!("QR login complete for user {}", user_id);

    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Authentication complete. You can close this tab."
    })))
}

// QR Sign handlers (mid-session signing via phone)

/// Error type for the cross-device sign flow. Strict dterror convention: every
/// variant carries `#[location]`; source-bearing variants use
/// `.with_context(Ctx::internal())` at call sites; source-less (domain)
/// variants are hand-built with `std::panic::Location::caller()`.
#[derive(Debug, thiserror::Error, CtxError)]
pub enum QrSignError {
    #[error("QR sign token not found [{location}]")]
    TokenNotFound {
        #[location]
        location: Location,
    },

    #[error("QR sign token has expired [{location}]")]
    TokenExpired {
        #[location]
        location: Location,
    },

    #[error("QR sign token in unexpected state: {status} [{location}]")]
    UnexpectedState {
        status: String,

        #[location]
        location: Location,
    },

    #[error("QR sign internal error [{location}]")]
    Internal {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

impl IntoResponse for QrSignError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::TokenNotFound { .. } => {
                (StatusCode::NOT_FOUND, "QR sign token not found".to_string())
            }
            Self::TokenExpired { .. } => {
                (StatusCode::GONE, "QR sign token has expired".to_string())
            }
            Self::UnexpectedState { ref status, .. } => (
                StatusCode::CONFLICT,
                format!("QR sign token in unexpected state: {status}"),
            ),
            Self::Internal { .. } => {
                tracing::error!(?self, "QR sign error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "an internal error occurred".to_string(),
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

#[tracing::instrument(skip_all, err)]
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

    let challenge_json = serde_json::to_string(&rcr).with_context(Ctx::internal())?;

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
    .with_context(Ctx::internal())?;

    let url = format!("{}/qr-sign?token={}", get_rp_origin(), token);

    Ok(Json(crate::types::QrSignBeginResponse {
        challenge_id,
        token,
        url,
        expires_at: expires_at.to_string(),
    }))
}

#[tracing::instrument(skip_all, err)]
pub async fn qr_sign_status_handler(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<QrSignStatusQuery>,
) -> Result<Json<crate::types::QrSignStatusResponse>, QrSignError> {
    use QrSignErrorCtx as SignCtx;

    let row = db::get_qr_sign_token(&state.db, &query.token)
        .await
        .with_context(SignCtx::internal())?;

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

#[tracing::instrument(skip_all, err)]
pub async fn qr_sign_authenticate_handler(
    State(state): State<AppState>,
    connect_info: ConnectInfo<std::net::SocketAddr>,
    Json(req): Json<crate::types::QrSignAuthenticateRequest>,
) -> Result<Json<crate::types::QrSignAuthenticateResponse>, QrSignError> {
    use QrSignErrorCtx as SignCtx;

    let row = db::get_qr_sign_token(&state.db, &req.token)
        .await
        .with_context(SignCtx::internal())?
        .ok_or_else(|| QrSignError::TokenNotFound {
            location: std::panic::Location::caller(),
        })?;

    if time::OffsetDateTime::now_utc() > row.expires_at {
        return Err(QrSignError::TokenExpired {
            location: std::panic::Location::caller(),
        });
    }

    match QrStatus::from_db(&row.status) {
        Some(QrStatus::Pending) => {}
        other => {
            return Err(QrSignError::UnexpectedState {
                status: format!("{:?}", other),
                location: std::panic::Location::caller(),
            })
        }
    }

    let browser_ip = connect_info.0.ip().to_string();
    let claimed = db::claim_qr_sign_token(&state.db, &req.token, Some(&browser_ip))
        .await
        .with_context(SignCtx::internal())?;
    if !claimed {
        return Err(QrSignError::UnexpectedState {
            status: "already claimed".into(),
            location: std::panic::Location::caller(),
        });
    }

    let challenge: webauthn_rs_proto::RequestChallengeResponse =
        serde_json::from_str(&row.challenge_json).with_context(SignCtx::internal())?;

    Ok(Json(crate::types::QrSignAuthenticateResponse {
        challenge,
        token: req.token,
    }))
}

#[tracing::instrument(skip_all, err)]
pub async fn qr_sign_authenticate_finish_handler(
    State(state): State<AppState>,
    Json(req): Json<crate::types::QrSignAuthenticateFinishRequest>,
) -> Result<Json<serde_json::Value>, QrSignError> {
    use QrSignErrorCtx as SignCtx;

    let row = db::get_qr_sign_token(&state.db, &req.token)
        .await
        .with_context(SignCtx::internal())?
        .ok_or_else(|| QrSignError::TokenNotFound {
            location: std::panic::Location::caller(),
        })?;

    if time::OffsetDateTime::now_utc() > row.expires_at {
        return Err(QrSignError::TokenExpired {
            location: std::panic::Location::caller(),
        });
    }

    match QrStatus::from_db(&row.status) {
        Some(QrStatus::Authenticated) => {}
        other => {
            return Err(QrSignError::UnexpectedState {
                status: format!("{:?}", other),
                location: std::panic::Location::caller(),
            })
        }
    }

    // base64url-encode the assertion — same format fido2_sign_middleware expects in X-Fido2-Response
    let credential_json = serde_json::to_vec(&req.credential).with_context(SignCtx::internal())?;
    let fido2_response = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&credential_json);

    db::complete_qr_sign_token(&state.db, &req.token, &fido2_response)
        .await
        .with_context(SignCtx::internal())?;

    tracing::debug!("QR sign token completed");

    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Signing approved. You can close this tab."
    })))
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
