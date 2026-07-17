// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;

use crate::request_id::RequestId;
use crate::types::{AppState, AuthenticatedUserId};

const MAX_BODY_SIZE: usize = 10 * 1024 * 1024; // 10MB

#[derive(Debug, thiserror::Error)]
#[error("failed to construct backend URL")]
pub struct BuildTargetUrlError(#[from] url::ParseError);

fn build_api_target_url(
    api_service_url: &str,
    path: &str,
    query: Option<&str>,
) -> Result<reqwest::Url, BuildTargetUrlError> {
    let query = query.map(|q| format!("?{q}")).unwrap_or_default();
    Ok(reqwest::Url::parse(&format!(
        "{api_service_url}{path}{query}"
    ))?)
}

fn is_internal_api_target(target_url: &reqwest::Url) -> bool {
    let path = target_url.path();

    // Canonical, segment-aware, case-insensitive check on the parsed path.
    // Catches "//internal/...", "/INTERNAL/...", and ".."-normalized forms
    // that reqwest::Url already collapses.
    let canonical_first_segment_internal = target_url
        .path_segments()
        .into_iter()
        .flatten()
        .find(|segment| !segment.is_empty())
        .is_some_and(|segment| segment.eq_ignore_ascii_case("internal"));

    // Do not rely on the backend router (axum/matchit) staying non-decoding as
    // the safety net for encoded lookalikes like "/%2finternal", "/%69nternal",
    // or "/internal;matrix". Fold percent-encoding and backslashes here the way
    // a decoding intermediary or a future router change might. Preserve the
    // conservative folded-root check, then also resolve dot segments with a
    // root-clamped stack before checking the normalized root. This can only ever
    // add blocking, so it is independent of downstream routing behavior.
    let decoded = percent_encoding::percent_decode_str(path).decode_utf8_lossy();
    let mut decoded_segments = Vec::new();
    let mut first_folded_segment = None;

    for raw_segment in decoded.split(['/', '\\']) {
        let segment = raw_segment.split(';').next().unwrap_or(raw_segment);
        if first_folded_segment.is_none() && !segment.is_empty() {
            first_folded_segment = Some(segment);
        }

        match segment {
            "" | "." => {}
            ".." => {
                decoded_segments.pop();
            }
            _ => decoded_segments.push(segment),
        }
    }

    let decoded_first_segment_internal = first_folded_segment
        .is_some_and(|segment| segment.eq_ignore_ascii_case("internal"))
        || decoded_segments
            .first()
            .is_some_and(|segment| segment.eq_ignore_ascii_case("internal"));

    canonical_first_segment_internal || decoded_first_segment_internal
}

/// Proxy webhooks to the metering service (no auth — verified by signature)
pub async fn metering_proxy_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Result<Response, Response> {
    let client = &state.http_client;

    let path = req.uri().path();
    let target_url = format!("{}{}", state.metering_service_url, path);

    tracing::debug!("Proxying webhook to metering: {}", target_url);

    // Only forward headers needed for webhook signature verification
    const ALLOWED_WEBHOOK_HEADERS: &[&str] =
        &["content-type", "content-length", "paddle-signature"];

    let headers = req.headers().clone();
    let method = req.method().clone();

    let body_bytes = axum::body::to_bytes(req.into_body(), MAX_BODY_SIZE)
        .await
        .map_err(|e| {
            tracing::error!("Failed to read webhook body: {:?}", e);
            (StatusCode::BAD_REQUEST, "Failed to read request body").into_response()
        })?;

    let mut proxy_req = client.request(method, &target_url);
    for (key, value) in headers.iter() {
        if ALLOWED_WEBHOOK_HEADERS.contains(&key.as_str()) {
            proxy_req = proxy_req.header(key, value);
        }
    }
    // Set the real peer IP ourselves rather than forwarding any client-supplied
    // x-forwarded-for — metering's webhook rate limiter keys on this header, and
    // trusting a client-controlled value would let one bucket be shared (or
    // spoofed) across callers.
    proxy_req = proxy_req.header("x-forwarded-for", addr.ip().to_string());
    if !body_bytes.is_empty() {
        proxy_req = proxy_req.body(body_bytes.to_vec());
    }

    let proxy_response = proxy_req.send().await.map_err(|e| {
        tracing::error!("Metering proxy request failed: {:?}", e);
        (StatusCode::BAD_GATEWAY, "Metering service unavailable").into_response()
    })?;

    let status = proxy_response.status();
    let resp_headers = proxy_response.headers().clone();
    let resp_body = proxy_response.bytes().await.map_err(|e| {
        tracing::error!("Failed to read metering response: {:?}", e);
        (StatusCode::BAD_GATEWAY, "Failed to read metering response").into_response()
    })?;

    let mut response = Response::builder().status(status);
    for (key, value) in resp_headers.iter() {
        response = response.header(key, value);
    }
    response.body(Body::from(resp_body)).map_err(|e| {
        tracing::error!("Failed to build response: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to build response",
        )
            .into_response()
    })
}

pub async fn proxy_handler(
    State(state): State<AppState>,
    req: Request,
) -> Result<Response, Response> {
    let path = req.uri().path();
    let target_url = build_api_target_url(&state.api_service_url, path, req.uri().query())
        .map_err(|e| {
            tracing::error!(raw_path = %path, error = ?e, "Failed to construct backend URL");
            (StatusCode::BAD_GATEWAY, "Backend service unavailable").into_response()
        })?;

    let session_id_header = req.headers().get("X-Session-ID").cloned();
    let content_type_header = req.headers().get("Content-Type").cloned();
    // Read authenticated user from middleware extension, not from headers.
    // This prevents spoofing on routes where auth middleware doesn't run.
    let authenticated_user = req.extensions().get::<AuthenticatedUserId>().cloned();
    let request_id = req.extensions().get::<RequestId>().cloned();

    let method = req.method().clone();

    // This block deliberately runs inside proxy_handler, i.e. AFTER the /api
    // sign/auth/username-gate middleware, not before it. Every unauthenticated
    // /api/* request is already rejected with 401 by fido2_auth_middleware
    // before it reaches here, so an internal path returns the same 401 as any
    // other unauth /api path — internal routes are not singled out to an
    // unauthenticated prober. Rejecting internal paths pre-auth would instead
    // make them the one /api surface answering 404 while everything else
    // answers 401, which *acknowledges* them more, against the "public gateway
    // never reveals internal paths" invariant. The 404 here matters only once a
    // request is authenticated (unavoidably distinguishable), as a defense-in-
    // depth backstop should the API ever be exposed without the auth layer.
    if is_internal_api_target(&target_url) {
        tracing::warn!(
            method = %method,
            raw_path = %path,
            canonical_path = %target_url.path(),
            user_id = ?authenticated_user.as_ref().map(|AuthenticatedUserId(id)| id),
            request_id = ?request_id.as_ref().map(|RequestId(id)| id),
            "Blocked public request to internal API route"
        );
        return Err(StatusCode::NOT_FOUND.into_response());
    }

    tracing::debug!("Proxying request to: {}", target_url);

    let mut proxy_req = state.http_client.request(method, target_url);

    if let Some(session_id) = session_id_header {
        proxy_req = proxy_req.header("X-Session-ID", session_id);
    }

    if let Some(AuthenticatedUserId(user_id)) = authenticated_user {
        proxy_req = proxy_req.header("X-Authenticated-User-ID", user_id.to_string());
        // Include internal service secret for authenticated requests
        if let Some(ref secret) = state.internal_service_secret {
            proxy_req = proxy_req.header("X-Internal-Service-Secret", secret.clone());
        }
    }

    if let Some(content_type) = content_type_header {
        proxy_req = proxy_req.header("Content-Type", content_type);
    }

    if let Some(RequestId(id)) = request_id {
        proxy_req = proxy_req.header("X-Request-Id", id);
    }

    let body_bytes = axum::body::to_bytes(req.into_body(), MAX_BODY_SIZE)
        .await
        .map_err(|e| {
            tracing::error!("Failed to read request body: {:?}", e);
            (StatusCode::BAD_REQUEST, "Failed to read request body").into_response()
        })?;

    if !body_bytes.is_empty() {
        proxy_req = proxy_req.body(body_bytes.to_vec());
    }

    let proxy_response = proxy_req.send().await.map_err(|e| {
        tracing::error!("Proxy request failed: {:?}", e);
        (StatusCode::BAD_GATEWAY, "Backend service unavailable").into_response()
    })?;

    let status = proxy_response.status();
    let headers = proxy_response.headers().clone();

    let body_bytes = proxy_response.bytes().await.map_err(|e| {
        tracing::error!("Failed to read proxy response body: {:?}", e);
        (StatusCode::BAD_GATEWAY, "Failed to read backend response").into_response()
    })?;

    let mut response = Response::builder().status(status);

    const ALLOWED_RESPONSE_HEADERS: &[&str] = &[
        "content-type",
        "content-length",
        "content-encoding",
        "cache-control",
        "etag",
        "last-modified",
        "vary",
        "x-request-id",
        // The proxy client does not follow redirects (would leak the internal
        // secret). Relay Location so the caller follows any 3xx itself.
        "location",
    ];

    for (key, value) in headers.iter() {
        if ALLOWED_RESPONSE_HEADERS.contains(&key.as_str()) {
            response = response.header(key, value);
        }
    }

    response.body(Body::from(body_bytes)).map_err(|e| {
        tracing::error!("Failed to build response: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to build response",
        )
            .into_response()
    })
}

#[cfg(test)]
mod tests {
    use super::{build_api_target_url, is_internal_api_target};

    const API_SERVICE_URL: &str = "http://api:8080";

    fn target(path: &str) -> reqwest::Url {
        build_api_target_url(API_SERVICE_URL, path, None).expect("target URL should parse")
    }

    #[test]
    fn blocks_canonical_internal_paths() {
        for path in [
            "/internal",
            "/internal/",
            "/internal/legal-notices/send",
            "/foo/../internal/org/00000000-0000-0000-0000-000000000000/suspend",
            "/foo/%2e%2e/internal/legal-notices/send",
            "/foo/%2E%2E/internal/legal-notices/send",
            "/foo\\..\\internal\\legal-notices\\send",
            "//internal/legal-notices/send",
            "///internal/legal-notices/send",
            "/INTERNAL/legal-notices/send",
            "/Internal/org/00000000-0000-0000-0000-000000000000/suspend",
        ] {
            let target_url = target(path);
            assert!(
                is_internal_api_target(&target_url),
                "expected {path:?} to canonicalize to a blocked target, got {:?}",
                target_url.path()
            );
        }
    }

    #[test]
    fn allows_non_internal_paths_and_lookalikes() {
        for path in [
            "/internalized",
            "/internals",
            "/foo/internal",
            "/foo//internal",
            "/user/status",
            "/legal/active-documents",
        ] {
            let target_url = target(path);
            assert!(
                !is_internal_api_target(&target_url),
                "expected {path:?} to remain allowed, got {:?}",
                target_url.path()
            );
        }
    }

    // Percent-/matrix-encoded lookalikes are blocked conservatively at the
    // gateway (folded like a decoding intermediary would), so the guarantee
    // does not depend on the backend router staying non-decoding.
    #[test]
    fn blocks_encoded_and_matrix_lookalikes() {
        for path in [
            "/%69nternal/legal-notices/send",  // %69 = 'i'
            "/%49nternal/legal-notices/send",  // %49 = 'I'
            "/%2finternal/legal-notices/send", // %2f = '/'
            "/%2Finternal/legal-notices/send",
            "/%5Cinternal/legal-notices/send", // %5c = '\'
            "/internal%2f../legal-notices/send",
            "/internal;param/legal-notices/send", // matrix param
            "/foo%2f..%2f%69nternal/legal-notices/send",
            "/foo%2f%2e%2e%2f%69nternal/legal-notices/send",
            "/foo%5c..%5c%49nternal/legal-notices/send",
            "/foo/..;param/%69nternal/legal-notices/send",
        ] {
            let target_url = target(path);
            assert!(
                is_internal_api_target(&target_url),
                "expected encoded lookalike {path:?} to be blocked, got canonical {:?}",
                target_url.path()
            );
        }
    }

    // Double-encoding is the conservative stopping point: a single decode of
    // "/%2569nternal" yields "/%69nternal", still not literally "internal", so
    // it is forwarded. Reaching an internal handler this way would require a
    // downstream layer to decode twice, which nothing here does.
    #[test]
    fn does_not_recursively_decode() {
        let target_url = target("/%2569nternal/send"); // %25='%', so -> "%69nternal"
        assert!(!is_internal_api_target(&target_url));
    }

    #[test]
    fn allows_encoded_internal_segments_that_are_not_at_normalized_root() {
        for path in [
            "/foo%2f%69nternal/legal-notices/send",
            "/foo%2f..%2finternalized/legal-notices/send",
        ] {
            let target_url = target(path);
            assert!(
                !is_internal_api_target(&target_url),
                "expected {path:?} to remain allowed, got {:?}",
                target_url.path()
            );
        }
    }

    #[test]
    fn ignores_internal_text_in_query_values() {
        let target_url = build_api_target_url(
            API_SERVICE_URL,
            "/user/status",
            Some("next=/internal/legal-notices/send"),
        )
        .expect("target URL should parse");

        assert_eq!(target_url.path(), "/user/status");
        assert!(!is_internal_api_target(&target_url));
    }
}
