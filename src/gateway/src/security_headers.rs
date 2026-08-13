// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::http::HeaderValue;
use axum::{extract::Request, middleware::Next, response::Response};

const DASHBOARD_CSP: &str = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval' https://cdn.paddle.com https://*.paddle.com https://public.profitwell.com https://*.profitwell.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' https://*.paddle.com https://public.profitwell.com https://*.profitwell.com; frame-src https://*.paddle.com";
const VERIFIER_CSP: &str = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' https:; worker-src 'self'; frame-src 'none'";

fn content_security_policy(path: &str) -> &'static str {
    if path == "/verify" || path == "/verify-e2ee" || path.starts_with("/verify-e2ee/") {
        VERIFIER_CSP
    } else {
        DASHBOARD_CSP
    }
}

pub async fn security_headers_middleware(req: Request, next: Next) -> Response {
    let content_security_policy = content_security_policy(req.uri().path());
    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    headers.insert(
        "strict-transport-security",
        HeaderValue::from_static("max-age=63072000; includeSubDomains"),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "referrer-policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(content_security_policy),
    );
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_csp_allows_https_attestation_endpoints() {
        assert_eq!(content_security_policy("/verify"), VERIFIER_CSP);
        assert!(VERIFIER_CSP.contains("connect-src 'self' https:"));
    }

    #[test]
    fn e2ee_verifier_csp_covers_pages_workers_and_wasm() {
        for path in [
            "/verify-e2ee",
            "/verify-e2ee/",
            "/verify-e2ee/client/version/enclave-sw.js",
            "/verify-e2ee/client/version/xwing/client.wasm",
            "/verify-e2ee/client/version/targets/hash/",
        ] {
            assert_eq!(content_security_policy(path), VERIFIER_CSP, "{path}");
        }
        assert!(VERIFIER_CSP.contains("worker-src 'self'"));
        assert_eq!(content_security_policy("/verify-e2ee-other"), DASHBOARD_CSP);
    }

    #[test]
    fn dashboard_csp_remains_restricted() {
        assert_eq!(content_security_policy("/dashboard"), DASHBOARD_CSP);
        assert!(!DASHBOARD_CSP.contains("connect-src 'self' https:;"));
        assert!(!DASHBOARD_CSP.contains("worker-src"));
    }
}
