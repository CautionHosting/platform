// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    extract::{State, Path},
    http::{StatusCode, header, HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
    Json,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use webauthn_rs::prelude::*;
use webauthn_rs_proto::{ResidentKeyRequirement, UserVerificationPolicy};
use time::{Duration, format_description::well_known::Rfc3339};
use serde::{Serialize, Deserialize};

use crate::db;
use crate::types::*;

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
    #[error("invalid or expired session")]
    InvalidSession,
    #[error("authentication challenge has expired")]
    ChallengeExpired,
    #[error("your organization requires PIN verification")]
    PinRequired,
    #[error("{0}")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for LoginError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::InvalidSession | Self::ChallengeExpired => {
                (StatusCode::UNAUTHORIZED, self.to_string())
            }
            Self::PinRequired => {
                (StatusCode::FORBIDDEN, self.to_string())
            }
            Self::Internal(ref e) => {
                tracing::error!("Login error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "an internal error occurred".into())
            }
        };
        (status, message).into_response()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SignRequestError {
    #[error("missing session")]
    MissingSession,
    #[error("invalid or expired session")]
    InvalidSession,
    #[error("missing CSRF token")]
    CsrfMissing,
    #[error("invalid CSRF token")]
    CsrfInvalid,
    #[error("{0}")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for SignRequestError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::MissingSession | Self::InvalidSession => {
                (StatusCode::UNAUTHORIZED, self.to_string())
            }
            Self::CsrfMissing | Self::CsrfInvalid => {
                (StatusCode::FORBIDDEN, self.to_string())
            }
            Self::Internal(ref e) => {
                tracing::error!("Sign request error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "an internal error occurred".into())
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

pub async fn begin_register_handler(
    State(state): State<AppState>,
    Json(req): Json<crate::types::RegisterBeginRequest>,
) -> Result<Json<RegisterBeginResponse>, AppError> {
    tracing::debug!("Registration started with alpha code");

    let alpha_code_id = db::validate_alpha_code(&state.db, &req.alpha_code)
        .await?
        .ok_or_else(|| anyhow::anyhow!("This alpha code is invalid or has already been used."))?;

    tracing::debug!("Alpha code validated: id={}", alpha_code_id);

    // Fetch ALL existing credential IDs to pass as excludeCredentials
    // This prevents the same authenticator from registering multiple accounts
    let existing_cred_ids = db::get_all_credential_ids(&state.db).await?;
    let exclude_credentials: Vec<CredentialID> = existing_cred_ids
        .into_iter()
        .map(CredentialID::from)
        .collect();

    tracing::debug!("Excluding {} existing credentials from registration", exclude_credentials.len());

    let user_unique_id = uuid::Uuid::new_v4();
    let user_name = format!("user_{}", user_unique_id);

    let (mut ccr, reg_state) = state
        .webauthn
        .start_passkey_registration(
            user_unique_id,
            &user_name,
            &user_name,
            Some(exclude_credentials).filter(|v| !v.is_empty()),
        )
        .map_err(|e| anyhow::anyhow!("Failed to start registration: {}", e))?;

    // Override authenticator selection to be maximally compatible:
    // - UV Preferred: authenticators that support PIN/biometric will set it up, but won't block
    //   basic authenticators. Organizations can require PIN later via security settings.
    // - Resident key Preferred: allows password managers (which create discoverable credentials)
    //   while still accepting hardware keys that don't support credential storage.
    // - Clear extensions: start_passkey_registration sets credProtect to UserVerificationRequired
    //   which conflicts with UV Preferred and causes Chrome to reject password manager registration.
    if let Some(ref mut auth_sel) = ccr.public_key.authenticator_selection {
        auth_sel.user_verification = UserVerificationPolicy::Preferred;
        auth_sel.resident_key = Some(ResidentKeyRequirement::Preferred);
    }
    ccr.public_key.extensions = None;

    tracing::debug!("Registration challenge created for RP {}", ccr.public_key.rp.id);

    let state_key = user_unique_id.to_string();
    let pending = crate::types::PendingRegistration {
        reg_state,
        alpha_code_id,
        expires_at: time::OffsetDateTime::now_utc() + Duration::minutes(2),
    };
    state.reg_states.write().await.insert(state_key.clone(), pending);

    Ok(Json(RegisterBeginResponse {
        challenge: ccr,
        session: state_key,
    }))
}

/// Build auth cookies for session and CSRF protection
fn build_auth_cookies(session_id: &str, csrf_token: &str, max_age_hours: i64, secure: bool) -> (String, String) {
    // Session cookie: HTTP-only, Secure, SameSite=Lax
    let session_cookie = Cookie::build(("caution_session", session_id.to_string()))
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
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
    Json(req): Json<serde_json::Value>,
) -> Result<Response, AppError> {
    let session_key = req.get("session")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing session field"))?
        .to_string();

    let pending = state.reg_states.read().await
        .get(&session_key)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("No matching registration state found"))?;

    // Check if the registration challenge has expired
    if time::OffsetDateTime::now_utc() > pending.expires_at {
        state.reg_states.write().await.remove(&session_key);
        return Err(anyhow::anyhow!("Registration challenge has expired").into());
    }

    let reg_response: RegisterPublicKeyCredential = serde_json::from_value(req.clone())
        .map_err(|e| anyhow::anyhow!("Failed to parse registration response: {}", e))?;

    let passkey = state
        .webauthn
        .finish_passkey_registration(&reg_response, &pending.reg_state)
        .map_err(|e| anyhow::anyhow!("Failed to finish registration: {}", e))?;

    let credential_id = passkey.cred_id().clone();
    if db::credential_exists(&state.db, &credential_id).await? {
        tracing::warn!("Registration rejected - credential already registered");
        return Err(anyhow::anyhow!(
            "This security key is already registered. Each key can only be registered once."
        ).into());
    }

    state.reg_states.write().await.remove(&session_key);

    let user_unique_id = uuid::Uuid::parse_str(&session_key)
        .map_err(|e| anyhow::anyhow!("Failed to parse user ID: {}", e))?;

    let user_id = db::create_user(&state.db, &user_unique_id.as_bytes()[..], pending.alpha_code_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create user: {}", e))?;

    db::redeem_alpha_code(&state.db, pending.alpha_code_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to redeem alpha code: {}", e))?;

    tracing::debug!("User registered and alpha code redeemed");

    let passkey_json = serde_json::to_vec(&passkey)
        .map_err(|e| anyhow::anyhow!("Failed to serialize passkey: {}", e))?;

    db::save_fido2_credential(
        &state.db,
        &credential_id,
        user_id,
        &passkey_json,
        Some("none"),
        None,
        0,
        None,
        None,
    )
    .await?;

    let credential_id_hex = hex::encode(&credential_id);

    let session_id = db::generate_session_id();
    let csrf_token = crate::csrf::derive_csrf_token(&session_id, &crate::csrf::get_csrf_secret());
    let expires_at = time::OffsetDateTime::now_utc() + Duration::hours(state.session_timeout_hours);

    db::create_auth_session(&state.db, &session_id, &credential_id, expires_at).await?;

    tracing::debug!("Registration complete with automatic session creation (expires in {} hours)", state.session_timeout_hours);

    // Build the response (session_id is in Set-Cookie header, not body)
    let response_body = RegisterFinishResponse {
        status: "success".to_string(),
        credential_id: credential_id_hex,
        expires_at: expires_at.format(&Rfc3339).unwrap_or_else(|_| expires_at.to_string()),
    };

    // Check if we're in production (HTTPS) - use secure cookies
    let secure = std::env::var("ENVIRONMENT").map(|e| e != "development").unwrap_or(true);
    let (session_cookie, csrf_cookie) = build_auth_cookies(&session_id, &csrf_token, state.session_timeout_hours, secure);

    let body = serde_json::to_string(&response_body)
        .map_err(|e| anyhow::anyhow!("Failed to serialize response: {}", e))?;

    // Use HeaderMap with append to properly set multiple Set-Cookie headers
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.append(header::SET_COOKIE, HeaderValue::from_str(&session_cookie).unwrap());
    headers.append(header::SET_COOKIE, HeaderValue::from_str(&csrf_cookie).unwrap());

    Ok((StatusCode::OK, headers, body).into_response())
}

pub async fn begin_login_handler(
    State(state): State<AppState>,
) -> Result<Json<LoginBeginResponse>, AppError> {

    let all_credential_ids: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT credential_id FROM fido2_credentials"
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to fetch credentials from DB: {:?}", e);
        anyhow::anyhow!("Failed to fetch credentials: {}", e)
    })?;

    tracing::debug!("Found {} credentials in database", all_credential_ids.len());

    let mut allow_credentials = Vec::new();
    for (i, cred_id_bytes) in all_credential_ids.iter().enumerate() {
        let cred_bytes = db::get_credential_public_key(&state.db, cred_id_bytes)
            .await
            .map_err(|e| {
                tracing::error!("Failed to get credential {}: {:?}", i, e);
                anyhow::anyhow!("Failed to get credential: {}", e)
            })?;

        // Use SecurityKey for flexible UV policy (Passkey enforces UV=Required)
        let seckey: SecurityKey = serde_json::from_slice(&cred_bytes)
            .map_err(|e| {
                tracing::error!("Failed to deserialize credential {}", i);
                anyhow::anyhow!("Failed to deserialize credential: {}", e)
            })?;

        allow_credentials.push(seckey);
    }

    tracing::debug!("Starting authentication challenge with {} credentials", allow_credentials.len());

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

    let session_key = uuid::Uuid::new_v4().to_string();
    let pending = PendingAuthentication {
        auth_state,
        expires_at: time::OffsetDateTime::now_utc() + Duration::minutes(2),
    };
    state.auth_states.write().await.insert(session_key.clone(), pending);

    Ok(Json(LoginBeginResponse {
        challenge: rcr,
        session: session_key,
    }))
}

pub async fn finish_login_handler(
    State(state): State<AppState>,
    Json(req): Json<serde_json::Value>,
) -> Result<Response, LoginError> {
    let session_key = req.get("session")
        .and_then(|v| v.as_str())
        .ok_or(LoginError::InvalidSession)?
        .to_string();

    let pending = state.auth_states.read().await
        .get(&session_key)
        .cloned()
        .ok_or(LoginError::InvalidSession)?;

    // Check if the authentication challenge has expired.
    if time::OffsetDateTime::now_utc() > pending.expires_at {
        state.auth_states.write().await.remove(&session_key);
        return Err(LoginError::ChallengeExpired);
    }

    let auth_state = pending.auth_state;

    let auth_response: PublicKeyCredential = serde_json::from_value(req.clone())
        .map_err(|e| anyhow::anyhow!("Failed to parse auth response: {}", e))?;

    tracing::debug!("Received authentication response");

    let credential_id_bytes = auth_response.raw_id.as_ref().to_vec();
    tracing::debug!("Credential ID: {}", hex::encode(&credential_id_bytes));

    let user_id = db::get_user_id_by_credential(&state.db, &credential_id_bytes).await?;

    let cred_bytes = db::get_credential_public_key(&state.db, &credential_id_bytes).await?;
    let mut seckey: SecurityKey = serde_json::from_slice(&cred_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize credential: {}", e))?;

    tracing::debug!("Credential fetched, performing securitykey authentication");

    let auth_result = state
        .webauthn
        .finish_securitykey_authentication(&auth_response, &auth_state)
        .map_err(|e| {
            tracing::error!("Authentication failed: {:?}", e);
            anyhow::anyhow!("Failed to finish authentication: {}", e)
        })?;

    tracing::debug!("Authentication successful, user_verified={}", auth_result.user_verified());

    // Check if user's org requires PIN verification.
    let requires_pin = db::user_requires_pin(&state.db, user_id).await?;
    if requires_pin && !auth_result.user_verified() {
        tracing::warn!("User {} login rejected: org requires PIN but user_verified=false", user_id);
        return Err(LoginError::PinRequired);
    }

    if auth_result.needs_update() {
        let update_result = seckey.update_credential(&auth_result);

        if let Some(true) = update_result {
            let updated_key_json = serde_json::to_vec(&seckey)
                .map_err(|e| anyhow::anyhow!("Failed to serialize updated credential: {}", e))?;

            db::update_fido2_credential(
                &state.db,
                &credential_id_bytes,
                &updated_key_json,
                auth_result.counter(),
            )
            .await?;
        }
    }

    state.auth_states.write().await.remove(&session_key);

    let session_id = db::generate_session_id();
    let csrf_token = crate::csrf::derive_csrf_token(&session_id, &crate::csrf::get_csrf_secret());
    let expires_at = time::OffsetDateTime::now_utc() + Duration::hours(state.session_timeout_hours);

    db::create_auth_session(&state.db, &session_id, &credential_id_bytes, expires_at).await?;

    let credential_id_hex = hex::encode(&credential_id_bytes);
    tracing::debug!("Login complete (session expires in {} hours)", state.session_timeout_hours);

    // Build the response (session_id is in Set-Cookie header, not body)
    let response_body = LoginFinishResponse {
        expires_at: expires_at.format(&Rfc3339).unwrap_or_else(|_| expires_at.to_string()),
        credential_id: credential_id_hex,
    };

    // Check if we're in production (HTTPS) - use secure cookies
    let secure = std::env::var("ENVIRONMENT").map(|e| e != "development").unwrap_or(true);
    let (session_cookie, csrf_cookie) = build_auth_cookies(&session_id, &csrf_token, state.session_timeout_hours, secure);

    let body = serde_json::to_string(&response_body)
        .map_err(|e| anyhow::anyhow!("Failed to serialize response: {}", e))?;

    // Use HeaderMap with append to properly set multiple Set-Cookie headers
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.append(header::SET_COOKIE, HeaderValue::from_str(&session_cookie).unwrap());
    headers.append(header::SET_COOKIE, HeaderValue::from_str(&csrf_cookie).unwrap());

    Ok((StatusCode::OK, headers, body).into_response())
}

#[derive(Debug, Deserialize)]
pub struct AddSshKeyRequest {
    pub public_key: String,
    pub name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AddSshKeyResponse {
    pub id: uuid::Uuid,
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
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid user ID"))?;

    crate::validation::validate_ssh_public_key(&req.public_key)
        .map_err(|e| anyhow::anyhow!("Invalid SSH public key: {}", e))?;

    let key_type = req.public_key.trim().split_whitespace().next()
        .ok_or_else(|| anyhow::anyhow!("Failed to parse key type"))?;

    let key_id = crate::db::add_ssh_key(
        &state.db,
        user_id,
        &req.public_key,
        key_type,
        req.name.as_deref(),
    )
    .await?;

    let fingerprint = crate::db::generate_ssh_fingerprint(&req.public_key);

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
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
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
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid user ID"))?;

    let deleted = crate::db::delete_ssh_key(&state.db, user_id, &fingerprint).await?;

    if deleted {
        tracing::debug!("SSH key deleted");
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(anyhow::anyhow!("SSH key not found").into())
    }
}

pub async fn begin_sign_request_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<crate::types::SignChallengeRequest>,
) -> Result<Json<crate::types::SignChallengeResponse>, SignRequestError> {
    // Support both header auth (CLI) and cookie auth (browser).
    let (session_id, using_header_auth) = if let Some(header_session) = headers
        .get("X-Session-ID")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
    {
        (header_session, true)
    } else if let Some(cookie_session) = crate::csrf::get_cookie(&headers, "caution_session") {
        (cookie_session, false)
    } else {
        return Err(SignRequestError::MissingSession);
    };

    let credential_id = db::validate_auth_session(&state.db, &session_id)
        .await?
        .ok_or(SignRequestError::InvalidSession)?;

    // Validate CSRF for cookie-based auth (browser).
    if !using_header_auth {
        let secret = crate::csrf::get_csrf_secret();
        let expected_csrf = crate::csrf::derive_csrf_token(&session_id, &secret);
        let csrf_header = headers
            .get("X-CSRF-Token")
            .and_then(|h| h.to_str().ok())
            .ok_or(SignRequestError::CsrfMissing)?;
        if !crate::csrf::constant_time_compare(&expected_csrf, csrf_header) {
            return Err(SignRequestError::CsrfInvalid);
        }
    }

    let user_id = db::get_user_id_by_credential(&state.db, &credential_id).await?;
    let requires_pin = db::user_requires_pin(&state.db, user_id).await?;

    let cred_bytes = db::get_credential_public_key(&state.db, &credential_id).await?;
    let seckey: SecurityKey = serde_json::from_slice(&cred_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize credential: {}", e))?;

    let (mut rcr, auth_state) = state
        .webauthn
        .start_securitykey_authentication(&[seckey])
        .map_err(|e| anyhow::anyhow!("Failed to start signing challenge: {}", e))?;

    // Set user verification based on org settings
    if requires_pin {
        rcr.public_key.user_verification = UserVerificationPolicy::Required;
    } else {
        // Use Preferred when PIN not required - authenticator decides
        rcr.public_key.user_verification = UserVerificationPolicy::Preferred;
    }

    let challenge_id = uuid::Uuid::new_v4().to_string();
    let pending = crate::types::PendingSignChallenge {
        auth_state,
        user_id,
        method: req.method,
        path: req.path,
        body_hash: req.body_hash,
        expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(2),
    };

    state.sign_challenges.write().await.insert(challenge_id.clone(), pending);

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
        .same_site(SameSite::Lax)
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
    let secure = std::env::var("ENVIRONMENT").map(|e| e != "development").unwrap_or(true);
    let (session_cookie, csrf_cookie) = build_logout_cookies(secure);

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.append(header::SET_COOKIE, HeaderValue::from_str(&session_cookie).unwrap());
    headers.append(header::SET_COOKIE, HeaderValue::from_str(&csrf_cookie).unwrap());

    if deletion_failed {
        Ok((StatusCode::INTERNAL_SERVER_ERROR, headers, r#"{"error":"Failed to delete session"}"#).into_response())
    } else {
        Ok((StatusCode::OK, headers, r#"{"status":"logged_out"}"#).into_response())
    }
}
