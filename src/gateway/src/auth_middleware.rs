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
use webauthn_rs::prelude::*;

use crate::db;
use crate::types::AppState;

/// Extract session ID from cookie header
fn get_session_from_cookie(req: &Request) -> Option<String> {
    req.headers()
        .get("cookie")
        .and_then(|h| h.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';')
                .map(|s| s.trim())
                .find(|s| s.starts_with("caution_session="))
                .map(|s| s.trim_start_matches("caution_session=").to_string())
        })
}

/// Extract CSRF token from cookie header
fn get_csrf_from_cookie(req: &Request) -> Option<String> {
    req.headers()
        .get("cookie")
        .and_then(|h| h.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';')
                .map(|s| s.trim())
                .find(|s| s.starts_with("caution_csrf="))
                .map(|s| s.trim_start_matches("caution_csrf=").to_string())
        })
}

/// Constant-time comparison to prevent timing attacks.
/// XORs each byte pair and ORs differences into accumulator.
/// Takes same time regardless of where mismatch occurs.
fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Validate CSRF token for state-changing requests from browser.
/// The CSRF token must be derived from the session ID, ensuring it's bound to the session.
fn validate_csrf(req: &Request) -> Result<(), &'static str> {
    // Only validate CSRF for state-changing methods when using cookie auth
    if matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        return Ok(());
    }

    // If using X-Session-ID header (CLI), skip CSRF validation
    if req.headers().contains_key("X-Session-ID") {
        return Ok(());
    }

    // Get session ID to derive expected CSRF token
    let session_id = get_session_from_cookie(req)
        .ok_or("Missing session cookie")?;

    // Derive the expected CSRF token from the session
    let expected_csrf = crate::handlers::derive_csrf_token(&session_id, &get_csrf_secret());

    // Get CSRF token from header (sent by JavaScript)
    let csrf_header = req
        .headers()
        .get("X-CSRF-Token")
        .and_then(|h| h.to_str().ok())
        .ok_or("Missing X-CSRF-Token header")?;

    // Use constant-time comparison to prevent timing attacks
    if !constant_time_compare(&expected_csrf, csrf_header) {
        return Err("CSRF token mismatch");
    }

    Ok(())
}

/// Get CSRF secret for token derivation
fn get_csrf_secret() -> String {
    std::env::var("INTERNAL_SERVICE_SECRET")
        .or_else(|_| std::env::var("CSRF_SECRET"))
        .unwrap_or_else(|_| "dev-csrf-secret-do-not-use-in-production".to_string())
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
    let session_id = req
        .headers()
        .get("X-Session-ID")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| get_session_from_cookie(&req))
        .ok_or_else(|| {
            (StatusCode::UNAUTHORIZED, "Missing session ID").into_response()
        })?;

    // Validate CSRF for cookie-based auth on state-changing requests
    validate_csrf(&req).map_err(|e| {
        tracing::warn!("CSRF validation failed: {}", e);
        (StatusCode::FORBIDDEN, e).into_response()
    })?;

    let credential_id = db::validate_auth_session(&state.db, &session_id)
        .await
        .map_err(|e| {
            tracing::error!("Session validation error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Session validation failed").into_response()
        })?
        .ok_or_else(|| {
            (StatusCode::UNAUTHORIZED, "Invalid or expired session").into_response()
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
    req: Request,
    next: Next,
) -> Result<Response, Response> {
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
