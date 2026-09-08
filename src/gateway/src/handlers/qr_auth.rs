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
use serde::Deserialize;
use time::Duration;
use uuid::Uuid;
use webauthn_rs::prelude::*;
use webauthn_rs_proto::UserVerificationPolicy;

use super::{
    check_username_scope, normalize_login_username, scoped_or_decoy_challenge, LoginError,
    MAX_PENDING_CHALLENGES, SignRequestError,
};

#[derive(Debug, thiserror::Error)]
pub enum QrLoginError {
    #[error("QR login token not found")]
    TokenNotFound,
    #[error("QR login token has expired")]
    TokenExpired,
    #[error("QR login token in unexpected state: {0}")]
    UnexpectedState(String),
    #[error("QR login token already claimed")]
    AlreadyClaimed,
    #[error("username is required for QR login")]
    MissingUsername,
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
            Self::TokenNotFound => (StatusCode::NOT_FOUND, self.to_string()),
            Self::TokenExpired => (StatusCode::GONE, self.to_string()),
            Self::UnexpectedState(_) | Self::AlreadyClaimed => {
                (StatusCode::CONFLICT, self.to_string())
            }
            Self::MissingUsername => (StatusCode::BAD_REQUEST, self.to_string()),
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
    // Parse request body and validate username is present and non-empty.
    let Some(username) = normalize_login_username(
        serde_json::from_slice::<crate::types::QrLoginBeginRequest>(&body)
            .ok()
            .map(|r| r.username),
    ) else {
        return Err(QrLoginError::MissingUsername);
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
    .map_err(|source| QrLoginError::DbCreateToken { source })?;

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

#[tracing::instrument(skip_all, err)]
pub async fn qr_login_authenticate_handler(
    State(state): State<AppState>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
    Json(req): Json<crate::types::QrLoginAuthenticateRequest>,
) -> Result<Json<crate::types::QrLoginAuthenticateResponse>, QrLoginError> {
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

    // A username stored on the token scopes the challenge to that user's own
    // credentials — needed for non-resident/legacy keys.
    let (rcr, auth_state) = {
        let ip = connect_info.0.ip();
        if !state.scoped_begin_limiter.check_rate_limit(&ip.to_string()).await {
            tracing::warn!("Scoped begin-login rate limit exceeded for IP: {}", ip);
            return Err(QrLoginError::RateLimited);
        }

        scoped_or_decoy_challenge(&state, &row.username)
            .await
            .map_err(|source| QrLoginError::ScopedChallenge { source })?
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

#[tracing::instrument(skip_all, err)]
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

#[tracing::instrument(skip_all, err)]
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

#[tracing::instrument(skip_all, err)]
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

#[tracing::instrument(skip_all, err)]
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
