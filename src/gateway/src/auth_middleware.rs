// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};
use ssh_key::{PublicKey as SshPublicKey, SshSig};
use std::error::Error;
use std::panic::Location;
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::db;
use crate::types::{AppState, AuthenticatedUserId};

const SSH_SIGNING_NAMESPACE: &str = "caution-api";
const SSH_SIGNATURE_WINDOW_SECS: i64 = 300;
const SSH_SIGNATURE_HEADER: &str = "X-Caution-SSH-Signature";
const SSH_FINGERPRINT_HEADER: &str = "X-Caution-SSH-Key-Fingerprint";
const SSH_TIMESTAMP_HEADER: &str = "X-Caution-SSH-Timestamp";
const SSH_AUTHENTICATED_HEADER: &str = "X-Caution-SSH-Signed";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SshSignatureHeaderState {
    None,
    Partial,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
enum SshSignedRequestErrorKind {
    #[error("incomplete authentication headers")]
    IncompleteHeaders,
    #[error("missing authentication header")]
    MissingHeader,
    #[error("invalid authentication header")]
    InvalidHeader,
    #[error("unsupported endpoint")]
    UnsupportedEndpoint,
    #[error("invalid resource ID")]
    InvalidResourceId,
    #[error("invalid timestamp")]
    InvalidTimestamp,
    #[error("expired timestamp")]
    ExpiredTimestamp,
    #[error("read body")]
    ReadBody,
    #[error("load public key")]
    LoadPublicKey,
    #[error("unknown key")]
    UnknownKey,
    #[error("parse public key")]
    ParsePublicKey,
    #[error("decode signature")]
    DecodeSignature,
    #[error("parse signature")]
    ParseSignature,
    #[error("verify signature")]
    VerifySignature,
    #[error("authorize key")]
    AuthorizeKey,
    #[error("unauthorized key")]
    UnauthorizedKey,
}

#[derive(Debug, thiserror::Error)]
#[error("Unable to verify SSH-signed request: {kind} [{location}]")]
struct SshSignedRequestError {
    kind: SshSignedRequestErrorKind,
    location: &'static Location<'static>,
    status: StatusCode,
    user_message: &'static str,
    header: Option<&'static str>,
    path: Option<String>,
    fingerprint: Option<String>,

    #[source]
    source: Option<Box<dyn Error + Send + Sync + 'static>>,
}

impl SshSignedRequestError {
    #[track_caller]
    fn new(
        kind: SshSignedRequestErrorKind,
        status: StatusCode,
        user_message: &'static str,
    ) -> Self {
        Self {
            kind,
            location: Location::caller(),
            status,
            user_message,
            header: None,
            path: None,
            fingerprint: None,
            source: None,
        }
    }

    fn with_header(mut self, header: &'static str) -> Self {
        self.header = Some(header);
        self
    }

    fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    fn with_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.fingerprint = Some(fingerprint.into());
        self
    }

    fn with_source<E>(mut self, source: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        self.source = Some(Box::new(source));
        self
    }

    fn with_boxed_source(mut self, source: Box<dyn Error + Send + Sync + 'static>) -> Self {
        self.source = Some(source);
        self
    }

    fn into_response(self) -> Response {
        (self.status, self.user_message).into_response()
    }
}

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
fn validate_csrf(
    req: &Request,
    session_id: &str,
    using_header_auth: bool,
    csrf_secret: &str,
) -> Result<(), CsrfValidationError> {
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
    let expected_csrf = crate::csrf::derive_csrf_token(session_id, csrf_secret);

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

    // If the request was already authenticated by the signing middleware,
    // trust its X-Authenticated-User-ID and skip session-based auth.
    // These marker headers are safe to trust here because fido2_sign_middleware
    // strips them from incoming requests before setting them after verification.
    if req.headers().get("X-Fido2-Signed").is_some()
        || req.headers().get(SSH_AUTHENTICATED_HEADER).is_some()
    {
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
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Session validation failed",
            )
                .into_response()
        })?
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid or expired session").into_response())?;

    // Now that session is validated, check CSRF for cookie-based auth
    validate_csrf(&req, &session_id, using_header_auth, &state.csrf_secret).map_err(|e| {
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
    req.extensions_mut().insert(AuthenticatedUserId(user_id));

    tracing::debug!("Authenticated request - user_id: {}", user_id);

    Ok(next.run(req).await)
}

fn ssh_signature_header_state(req: &Request) -> SshSignatureHeaderState {
    let present = [
        req.headers().contains_key(SSH_SIGNATURE_HEADER),
        req.headers().contains_key(SSH_FINGERPRINT_HEADER),
        req.headers().contains_key(SSH_TIMESTAMP_HEADER),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();

    match present {
        0 => SshSignatureHeaderState::None,
        3 => SshSignatureHeaderState::Complete,
        _ => SshSignatureHeaderState::Partial,
    }
}

fn is_ssh_signed_resource_request(method: &Method, path: &str) -> bool {
    if !matches!(*method, Method::GET | Method::DELETE) {
        return false;
    }

    path.strip_prefix("/resources/")
        .is_some_and(|resource_id| !resource_id.is_empty() && !resource_id.contains('/'))
}

fn header_str<'a>(
    req: &'a Request,
    header: &'static str,
) -> Result<&'a str, SshSignedRequestError> {
    use SshSignedRequestErrorKind as ErrorKind;

    let value = req.headers().get(header).ok_or_else(|| {
        SshSignedRequestError::new(
            ErrorKind::MissingHeader,
            StatusCode::BAD_REQUEST,
            "Missing SSH authentication header",
        )
        .with_header(header)
    })?;

    value.to_str().map_err(|source| {
        SshSignedRequestError::new(
            ErrorKind::InvalidHeader,
            StatusCode::BAD_REQUEST,
            "Invalid SSH authentication header",
        )
        .with_header(header)
        .with_source(source)
    })
}

fn ssh_signed_resource_id(method: &Method, path: &str) -> Result<Uuid, SshSignedRequestError> {
    use SshSignedRequestErrorKind as ErrorKind;

    if !matches!(*method, Method::GET | Method::DELETE) {
        return Err(SshSignedRequestError::new(
            ErrorKind::UnsupportedEndpoint,
            StatusCode::FORBIDDEN,
            "SSH authentication is not supported for this endpoint",
        )
        .with_path(format!("{} {}", method, path)));
    }

    let Some(resource_id) = path.strip_prefix("/resources/") else {
        return Err(SshSignedRequestError::new(
            ErrorKind::UnsupportedEndpoint,
            StatusCode::FORBIDDEN,
            "SSH authentication is not supported for this endpoint",
        )
        .with_path(format!("{} {}", method, path)));
    };

    if resource_id.contains('/') {
        return Err(SshSignedRequestError::new(
            ErrorKind::UnsupportedEndpoint,
            StatusCode::FORBIDDEN,
            "SSH authentication is not supported for this endpoint",
        )
        .with_path(format!("{} {}", method, path)));
    }

    Uuid::parse_str(resource_id).map_err(|source| {
        SshSignedRequestError::new(
            ErrorKind::InvalidResourceId,
            StatusCode::BAD_REQUEST,
            "Invalid resource ID",
        )
        .with_path(path)
        .with_source(source)
    })
}

fn validate_ssh_timestamp(timestamp: &str) -> Result<(), SshSignedRequestError> {
    use SshSignedRequestErrorKind as ErrorKind;

    let timestamp = timestamp.parse::<i64>().map_err(|source| {
        SshSignedRequestError::new(
            ErrorKind::InvalidTimestamp,
            StatusCode::BAD_REQUEST,
            "Invalid SSH authentication timestamp",
        )
        .with_source(source)
    })?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    if timestamp > now + SSH_SIGNATURE_WINDOW_SECS
        || timestamp < now.saturating_sub(SSH_SIGNATURE_WINDOW_SECS)
    {
        return Err(SshSignedRequestError::new(
            ErrorKind::ExpiredTimestamp,
            StatusCode::UNAUTHORIZED,
            "SSH authentication timestamp expired",
        ));
    }
    Ok(())
}

fn canonical_ssh_request(
    method: &Method,
    path_query: &str,
    timestamp: &str,
    body: &[u8],
) -> String {
    let body_hash = hex::encode(Sha256::digest(body));
    format!(
        "caution-ssh-http-v1\n{}\n{}\n{}\n{}\n",
        method.as_str(),
        path_query,
        timestamp,
        body_hash
    )
}

fn ssh_signed_request_error_response(error: SshSignedRequestError) -> Response {
    if error.status.is_server_error() {
        tracing::error!("{:?}", error);
    } else {
        tracing::warn!("{}", error);
    }
    error.into_response()
}

async fn verify_ssh_signed_request(
    state: &AppState,
    req: Request,
) -> Result<Request, SshSignedRequestError> {
    use SshSignedRequestErrorKind as ErrorKind;

    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req
        .uri()
        .query()
        .map(|query| format!("?{}", query))
        .unwrap_or_default();
    let path_query = format!("{}{}", path, query);
    let resource_id = ssh_signed_resource_id(&method, &path)?;

    let fingerprint = header_str(&req, SSH_FINGERPRINT_HEADER)?.to_string();
    let timestamp = header_str(&req, SSH_TIMESTAMP_HEADER)?.to_string();
    let signature = header_str(&req, SSH_SIGNATURE_HEADER)?.to_string();
    validate_ssh_timestamp(&timestamp)?;

    let (parts, body) = req.into_parts();
    let body_bytes = axum::body::to_bytes(body, 10 * 1024 * 1024)
        .await
        .map_err(|source| {
            SshSignedRequestError::new(
                ErrorKind::ReadBody,
                StatusCode::BAD_REQUEST,
                "Failed to read body",
            )
            .with_path(path_query.clone())
            .with_source(source)
        })?;
    let payload = canonical_ssh_request(&method, &path_query, &timestamp, &body_bytes);

    let public_key = db::get_ssh_public_key_by_fingerprint(&state.db, &fingerprint)
        .await
        .map_err(|source| {
            SshSignedRequestError::new(
                ErrorKind::LoadPublicKey,
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to verify SSH signature",
            )
            .with_fingerprint(fingerprint.clone())
            .with_boxed_source(source.into_boxed_dyn_error())
        })?
        .ok_or_else(|| {
            SshSignedRequestError::new(
                ErrorKind::UnknownKey,
                StatusCode::UNAUTHORIZED,
                "Unknown SSH key",
            )
            .with_fingerprint(fingerprint.clone())
        })?;

    let public_key = SshPublicKey::from_openssh(&public_key).map_err(|source| {
        SshSignedRequestError::new(
            ErrorKind::ParsePublicKey,
            StatusCode::UNAUTHORIZED,
            "Invalid SSH key",
        )
        .with_fingerprint(fingerprint.clone())
        .with_source(source)
    })?;
    let signature_bytes = URL_SAFE_NO_PAD.decode(signature).map_err(|source| {
        SshSignedRequestError::new(
            ErrorKind::DecodeSignature,
            StatusCode::BAD_REQUEST,
            "Invalid SSH signature encoding",
        )
        .with_fingerprint(fingerprint.clone())
        .with_source(source)
    })?;
    let signature = SshSig::from_pem(&signature_bytes).map_err(|source| {
        SshSignedRequestError::new(
            ErrorKind::ParseSignature,
            StatusCode::UNAUTHORIZED,
            "Invalid SSH signature",
        )
        .with_fingerprint(fingerprint.clone())
        .with_source(source)
    })?;
    public_key
        .verify(SSH_SIGNING_NAMESPACE, payload.as_bytes(), &signature)
        .map_err(|source| {
            SshSignedRequestError::new(
                ErrorKind::VerifySignature,
                StatusCode::UNAUTHORIZED,
                "Invalid SSH signature",
            )
            .with_fingerprint(fingerprint.clone())
            .with_source(source)
        })?;

    let (user_id, _org_id) =
        db::get_user_for_app_by_ssh_key(&state.db, &fingerprint, &resource_id.to_string())
            .await
            .map_err(|source| {
                SshSignedRequestError::new(
                    ErrorKind::AuthorizeKey,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to authorize SSH key",
                )
                .with_fingerprint(fingerprint.clone())
                .with_path(path_query.clone())
                .with_boxed_source(source.into_boxed_dyn_error())
            })?
            .ok_or_else(|| {
                SshSignedRequestError::new(
                    ErrorKind::UnauthorizedKey,
                    StatusCode::FORBIDDEN,
                    "SSH key is not authorized for this app",
                )
                .with_fingerprint(fingerprint.clone())
                .with_path(path_query.clone())
            })?;

    if let Err(e) = db::update_ssh_key_last_used(&state.db, &fingerprint).await {
        tracing::warn!("Failed to update SSH key last_used_at: {:?}", e);
    }

    let mut req = Request::from_parts(parts, Body::from(body_bytes));
    req.headers_mut().insert(
        "X-Authenticated-User-ID",
        HeaderValue::from_str(&user_id.to_string()).unwrap(),
    );
    req.headers_mut()
        .insert(SSH_AUTHENTICATED_HEADER, HeaderValue::from_static("true"));
    req.extensions_mut().insert(AuthenticatedUserId(user_id));

    tracing::info!(
        "SSH-signed request verified - user: {}, resource: {}, path: {}",
        user_id,
        resource_id,
        path_query
    );

    Ok(req)
}

fn incomplete_ssh_headers_error(req: &Request) -> SshSignedRequestError {
    SshSignedRequestError::new(
        SshSignedRequestErrorKind::IncompleteHeaders,
        StatusCode::BAD_REQUEST,
        "Missing SSH authentication header",
    )
    .with_path(format!("{} {}", req.method(), req.uri().path()))
}

pub async fn fido2_sign_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, Response> {
    // SECURITY: Strip headers to prevent bypass attacks from external requests.
    // These headers are only set internally by this middleware after verification.
    req.headers_mut().remove("X-Authenticated-User-ID");
    req.headers_mut().remove("X-Fido2-Signed");
    req.headers_mut().remove(SSH_AUTHENTICATED_HEADER);

    if is_ssh_signed_resource_request(req.method(), req.uri().path()) {
        match ssh_signature_header_state(&req) {
            SshSignatureHeaderState::Complete => {
                let req = verify_ssh_signed_request(&state, req)
                    .await
                    .map_err(ssh_signed_request_error_response)?;
                return Ok(next.run(req).await);
            }
            SshSignatureHeaderState::Partial => {
                return Err(ssh_signed_request_error_response(
                    incomplete_ssh_headers_error(&req),
                ));
            }
            SshSignatureHeaderState::None => {}
        }
    }

    // In e2e test mode, skip all FIDO2 signing requirements.
    // Requests will still be authenticated by fido2_auth_middleware (session check).
    #[cfg(feature = "e2e-testing-unsafe")]
    {
        return Ok(next.run(req).await);
    }

    // Paths that require signature for write operations
    #[allow(unreachable_code)]
    let path = req.uri().path();
    let method = req.method();
    let requires_signature = (path.contains("/organizations/")
        && path.ends_with("/settings")
        && (method == "PATCH" || method == "PUT"))
        || (path.starts_with("/ssh-keys") && (method == "POST" || method == "DELETE"))
        || (path == "/passkeys/register/begin" && method == "POST")
        || (path.starts_with("/passkeys/") && method == "DELETE");

    let challenge_id = match req.headers().get("X-Fido2-Challenge-Id") {
        Some(h) => h
            .to_str()
            .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid challenge ID header").into_response())?
            .to_string(),
        None => {
            if requires_signature {
                return Err((
                    StatusCode::FORBIDDEN,
                    "This operation requires signature verification",
                )
                    .into_response());
            }
            return Ok(next.run(req).await);
        }
    };

    let auth_response_b64 = req
        .headers()
        .get("X-Fido2-Response")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            (StatusCode::BAD_REQUEST, "Missing X-Fido2-Response header").into_response()
        })?;

    let auth_response_json = URL_SAFE_NO_PAD.decode(auth_response_b64).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid base64 in X-Fido2-Response",
        )
            .into_response()
    })?;

    let auth_response: PublicKeyCredential =
        serde_json::from_slice(&auth_response_json).map_err(|e| {
            tracing::error!("Failed to parse FIDO response: {}", e);
            (StatusCode::BAD_REQUEST, "Invalid FIDO response format").into_response()
        })?;

    // SECURITY: Remove-then-check is intentional. Atomically removing the challenge
    // before checking expiry prevents replay attacks — even an expired challenge is
    // consumed and cannot be retried. Checking expiry first would introduce a TOCTOU
    // race where a concurrent request could use the same challenge between the check
    // and removal. The user must request a fresh challenge regardless.
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
            pending.method,
            pending.path,
            method,
            path
        );
        return Err((
            StatusCode::FORBIDDEN,
            "Request does not match signed challenge",
        )
            .into_response());
    }

    let (parts, body) = req.into_parts();
    let body_bytes = axum::body::to_bytes(body, 10 * 1024 * 1024)
        .await
        .map_err(|_| (StatusCode::BAD_REQUEST, "Failed to read body").into_response())?;

    let body_hash = hex::encode(Sha256::digest(&body_bytes));
    if pending.body_hash != body_hash {
        tracing::error!(
            "Body hash mismatch: expected {} got {}",
            pending.body_hash,
            body_hash
        );
        return Err((StatusCode::FORBIDDEN, "Body does not match signed hash").into_response());
    }

    let credential_id_bytes = auth_response.raw_id.as_ref().to_vec();
    tracing::debug!(
        "Verifying FIDO2 signature with credential: {}",
        hex::encode(&credential_id_bytes)
    );
    let cred_bytes = db::get_credential_public_key(&state.db, &credential_id_bytes)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to get credential {}: {}",
                hex::encode(&credential_id_bytes),
                e
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to verify signature",
            )
                .into_response()
        })?;

    // Use SecurityKey for flexible UV policy (Passkey enforces UV=Required)
    let _seckey: SecurityKey = serde_json::from_slice(&cred_bytes).map_err(|e| {
        tracing::error!("Failed to deserialize credential: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to verify signature",
        )
            .into_response()
    })?;

    state
        .webauthn
        .finish_securitykey_authentication(&auth_response, &pending.auth_state)
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
    req.headers_mut()
        .insert("X-Fido2-Signed", HeaderValue::from_static("true"));
    req.extensions_mut()
        .insert(AuthenticatedUserId(pending.user_id));

    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESOURCE_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn request_with_ssh_headers(headers: &[&'static str]) -> Request {
        let mut req = axum::http::Request::builder()
            .uri(format!("/resources/{RESOURCE_ID}"))
            .body(Body::empty())
            .unwrap();

        for header in headers {
            req.headers_mut()
                .insert(*header, HeaderValue::from_static("test"));
        }

        req
    }

    #[test]
    fn ssh_signature_header_state_requires_complete_set() {
        let req = request_with_ssh_headers(&[]);
        assert_eq!(
            ssh_signature_header_state(&req),
            SshSignatureHeaderState::None
        );

        let req = request_with_ssh_headers(&[SSH_SIGNATURE_HEADER]);
        assert_eq!(
            ssh_signature_header_state(&req),
            SshSignatureHeaderState::Partial
        );

        let req = request_with_ssh_headers(&[
            SSH_SIGNATURE_HEADER,
            SSH_FINGERPRINT_HEADER,
            SSH_TIMESTAMP_HEADER,
        ]);
        assert_eq!(
            ssh_signature_header_state(&req),
            SshSignatureHeaderState::Complete
        );
    }

    #[test]
    fn ssh_signed_resource_request_is_narrowly_allowlisted() {
        let resource_path = format!("/resources/{RESOURCE_ID}");

        assert!(is_ssh_signed_resource_request(&Method::GET, &resource_path));
        assert!(is_ssh_signed_resource_request(
            &Method::DELETE,
            &resource_path
        ));
        assert!(is_ssh_signed_resource_request(
            &Method::GET,
            "/resources/not-a-uuid"
        ));

        assert!(!is_ssh_signed_resource_request(
            &Method::POST,
            &resource_path
        ));
        assert!(!is_ssh_signed_resource_request(&Method::GET, "/ssh-keys"));
        assert!(!is_ssh_signed_resource_request(
            &Method::GET,
            &format!("{resource_path}/logs")
        ));
    }

    #[test]
    fn validate_ssh_timestamp_rejects_bad_or_expired_values() {
        let error = validate_ssh_timestamp("not-a-timestamp").unwrap_err();
        assert_eq!(error.kind, SshSignedRequestErrorKind::InvalidTimestamp);
        assert_eq!(error.status, StatusCode::BAD_REQUEST);

        let expired =
            time::OffsetDateTime::now_utc().unix_timestamp() - SSH_SIGNATURE_WINDOW_SECS - 60;
        let error = validate_ssh_timestamp(&expired.to_string()).unwrap_err();
        assert_eq!(error.kind, SshSignedRequestErrorKind::ExpiredTimestamp);
        assert_eq!(error.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn canonical_ssh_request_includes_method_path_timestamp_and_body_hash() {
        let payload = canonical_ssh_request(
            &Method::DELETE,
            "/resources/550e8400-e29b-41d4-a716-446655440000?force=true",
            "123",
            b"abc",
        );

        assert_eq!(
            payload,
            "caution-ssh-http-v1\nDELETE\n/resources/550e8400-e29b-41d4-a716-446655440000?force=true\n123\nba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n"
        );
    }
}
