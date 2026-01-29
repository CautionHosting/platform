// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, StatusCode, Method},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Sha256, Digest};
use std::panic::Location;
use webauthn_rs::prelude::*;

use crate::db;
use crate::types::AppState;

#[derive(Debug)]
pub enum CsrfValidationErrorKind {
    MissingHeader,
    TokenMismatch,
}

#[derive(Debug, thiserror::Error)]
#[error("CSRF validation failed ({kind:?}) [{location}]")]
pub struct CsrfValidationError {
    kind: CsrfValidationErrorKind,
    location: &'static Location<'static>,
}

impl CsrfValidationError {
    #[track_caller]
    fn with_kind(kind: CsrfValidationErrorKind) -> Self {
        Self {
            kind,
            location: Location::caller(),
        }
    }

    /// Returns a generic message safe to show to end users.
    /// Specific error details are logged server-side via the Display impl.
    pub fn user_message(&self) -> &'static str {
        "Request validation failed"
    }
}

/// Validate CSRF token for state-changing requests from browser.
/// The CSRF token must be derived from the session ID, ensuring it's bound to the session.
///
/// `using_header_auth` indicates whether the request was authenticated via X-Session-ID header (CLI).
/// CSRF validation is only required for cookie-based auth (browser).
fn validate_csrf(req: &Request, session_id: &str, using_header_auth: bool) -> Result<(), CsrfValidationError> {
    use CsrfValidationErrorKind as ErrorKind;

    // Only validate CSRF for state-changing methods
    if matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        return Ok(());
    }

    // CLI clients use X-Session-ID header and don't need CSRF protection
    // (they can't be victim of CSRF attacks as browsers won't send the header)
    if using_header_auth {
        return Ok(());
    }

    // Derive the expected CSRF token from the session
    let secret = crate::csrf::get_csrf_secret();
    let expected_csrf = crate::csrf::derive_csrf_token(session_id, &secret);

    // Get CSRF token from header (sent by JavaScript)
    let csrf_header = req
        .headers()
        .get("X-CSRF-Token")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| CsrfValidationError::with_kind(ErrorKind::MissingHeader))?;

    // Use constant-time comparison to prevent timing attacks
    if !crate::csrf::constant_time_compare(&expected_csrf, csrf_header) {
        return Err(CsrfValidationError::with_kind(ErrorKind::TokenMismatch));
    }

    Ok(())
}

pub async fn fido2_auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, Response> {
    if req.uri().path() == "/health" {
        return Ok(next.run(req).await);
    }

    // SECURITY: Never trust X-Authenticated-User-ID from external requests.
    // This header should only be set by this middleware after authentication.
    // Strip it if present to prevent authentication bypass attacks.
    req.headers_mut().remove("X-Authenticated-User-ID");

    // Try to get session ID from X-Session-ID header (CLI) or cookie (browser)
    // Track which auth method is being used for CSRF validation
    let (session_id, using_header_auth) = if let Some(header_session) = req
        .headers()
        .get("X-Session-ID")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
    {
        (header_session, true)
    } else if let Some(cookie_session) = crate::csrf::get_cookie(req.headers(), "caution_session") {
        (cookie_session, false)
    } else {
        return Err((StatusCode::UNAUTHORIZED, "Missing session ID").into_response());
    };

    // Validate session FIRST to ensure the auth method claim is legitimate
    let credential_id = db::validate_auth_session(&state.db, &session_id)
        .await
        .map_err(|e| {
            tracing::error!("Session validation error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Session validation failed").into_response()
        })?
        .ok_or_else(|| {
            (StatusCode::UNAUTHORIZED, "Invalid or expired session").into_response()
        })?;

    // Now that session is validated, check CSRF for cookie-based auth
    validate_csrf(&req, &session_id, using_header_auth).map_err(|e| {
        tracing::warn!("{}", e);
        (StatusCode::FORBIDDEN, e.user_message()).into_response()
    })?;

    let user_id = db::get_user_id_by_credential(&state.db, &credential_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get user ID for credential: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to resolve user").into_response()
        })?;

    req.headers_mut().insert(
        "X-Authenticated-User-ID",
        HeaderValue::from_str(&user_id.to_string()).unwrap(),
    );

    tracing::debug!(
        "Authenticated request - session: {}, credential: {}, user_id: {}",
        session_id,
        hex::encode(&credential_id),
        user_id
    );

    Ok(next.run(req).await)
}

pub async fn fido2_sign_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, Response> {
    // SECURITY: Strip X-Authenticated-User-ID to prevent bypass attacks
    req.headers_mut().remove("X-Authenticated-User-ID");

    let challenge_id = match req.headers().get("X-Fido2-Challenge-Id") {
        Some(h) => h.to_str().map_err(|_| {
            (StatusCode::BAD_REQUEST, "Invalid challenge ID header").into_response()
        })?.to_string(),
        None => return Ok(next.run(req).await),
    };

    let auth_response_b64 = req
        .headers()
        .get("X-Fido2-Response")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            (StatusCode::BAD_REQUEST, "Missing X-Fido2-Response header").into_response()
        })?;

    let auth_response_json = URL_SAFE_NO_PAD.decode(auth_response_b64).map_err(|_| {
        (StatusCode::BAD_REQUEST, "Invalid base64 in X-Fido2-Response").into_response()
    })?;

    let auth_response: PublicKeyCredential = serde_json::from_slice(&auth_response_json)
        .map_err(|e| {
            tracing::error!("Failed to parse FIDO response: {}", e);
            (StatusCode::BAD_REQUEST, "Invalid FIDO response format").into_response()
        })?;

    let pending = state
        .sign_challenges
        .write()
        .await
        .remove(&challenge_id)
        .ok_or_else(|| {
            (StatusCode::UNAUTHORIZED, "Invalid or expired challenge").into_response()
        })?;

    if time::OffsetDateTime::now_utc() > pending.expires_at {
        return Err((StatusCode::UNAUTHORIZED, "Challenge expired").into_response());
    }

    let method = req.method().as_str();
    let path = req.uri().path();

    if pending.method != method || pending.path != path {
        tracing::error!(
            "Request mismatch: expected {} {} but got {} {}",
            pending.method, pending.path, method, path
        );
        return Err((StatusCode::FORBIDDEN, "Request does not match signed challenge").into_response());
    }

    let (parts, body) = req.into_parts();
    let body_bytes = axum::body::to_bytes(body, 10 * 1024 * 1024)
        .await
        .map_err(|_| (StatusCode::BAD_REQUEST, "Failed to read body").into_response())?;

    let body_hash = hex::encode(Sha256::digest(&body_bytes));
    if pending.body_hash != body_hash {
        tracing::error!("Body hash mismatch: expected {} got {}", pending.body_hash, body_hash);
        return Err((StatusCode::FORBIDDEN, "Body does not match signed hash").into_response());
    }

    let credential_id_bytes = auth_response.raw_id.as_ref().to_vec();
    tracing::debug!(
        "Verifying FIDO2 signature with credential: {}",
        hex::encode(&credential_id_bytes)
    );
    let passkey_bytes = db::get_credential_public_key(&state.db, &credential_id_bytes)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get credential {}: {}", hex::encode(&credential_id_bytes), e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to verify signature").into_response()
        })?;

    let _passkey: Passkey = serde_json::from_slice(&passkey_bytes).map_err(|e| {
        tracing::error!("Failed to deserialize passkey: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Failed to verify signature").into_response()
    })?;

    state
        .webauthn
        .finish_passkey_authentication(&auth_response, &pending.auth_state)
        .map_err(|e| {
            tracing::error!("FIDO signature verification failed: {:?}", e);
            (StatusCode::UNAUTHORIZED, "Invalid signature").into_response()
        })?;

    tracing::info!(
        "FIDO2-signed request verified - user: {}, credential: {}, path: {}",
        pending.user_id,
        hex::encode(&credential_id_bytes),
        pending.path
    );

    let mut req = Request::from_parts(parts, Body::from(body_bytes));
    req.headers_mut().insert(
        "X-Authenticated-User-ID",
        HeaderValue::from_str(&pending.user_id.to_string()).unwrap(),
    );
    req.headers_mut().insert(
        "X-Fido2-Signed",
        HeaderValue::from_static("true"),
    );

    Ok(next.run(req).await)
}
