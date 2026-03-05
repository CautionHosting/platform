// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! CSRF protection utilities.
//!
//! This module provides functions for generating and validating CSRF tokens
//! that are cryptographically bound to user sessions using HMAC-SHA256.

use axum::http::HeaderMap;
use axum_extra::extract::CookieJar;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Extract a cookie value by name from headers using axum_extra's CookieJar.
///
/// This properly handles cookie parsing according to RFC 6265.
pub fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    CookieJar::from_headers(headers)
        .get(name)
        .map(|c| c.value().to_string())
}

/// Get CSRF secret from environment variables.
///
/// Requires `CSRF_SECRET` to be set. Panics if not configured.
pub fn get_csrf_secret() -> String {
    std::env::var("CSRF_SECRET")
        .expect("CSRF_SECRET environment variable must be set")
}

/// Derive a CSRF token from a session ID using HMAC-SHA256.
///
/// This cryptographically binds the CSRF token to the session,
/// ensuring a token from one session cannot be used with another.
///
/// # Arguments
/// * `session_id` - The session ID to derive the token from
/// * `secret` - The HMAC secret key
///
/// # Returns
/// A hex-encoded CSRF token
pub fn derive_csrf_token(session_id: &str, secret: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(session_id.as_bytes());
    mac.update(b":csrf"); // domain separation
    hex::encode(mac.finalize().into_bytes())
}

/// Perform constant-time string comparison to prevent timing attacks.
///
/// Uses the `subtle` crate's audited constant-time comparison.
/// Returns `true` if the strings are equal, `false` otherwise.
pub fn constant_time_compare(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_csrf_token_deterministic() {
        let token1 = derive_csrf_token("session123", "secret");
        let token2 = derive_csrf_token("session123", "secret");
        assert_eq!(token1, token2);
    }

    #[test]
    fn test_derive_csrf_token_different_sessions() {
        let token1 = derive_csrf_token("session123", "secret");
        let token2 = derive_csrf_token("session456", "secret");
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_derive_csrf_token_different_secrets() {
        let token1 = derive_csrf_token("session123", "secret1");
        let token2 = derive_csrf_token("session123", "secret2");
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_derive_csrf_token_is_hex() {
        let token = derive_csrf_token("session", "secret");
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
        // HMAC-SHA256 produces 32 bytes = 64 hex chars
        assert_eq!(token.len(), 64);
    }

    #[test]
    fn test_derive_csrf_token_empty_session() {
        let token = derive_csrf_token("", "secret");
        assert_eq!(token.len(), 64);
        // Should differ from a non-empty session
        let token2 = derive_csrf_token("x", "secret");
        assert_ne!(token, token2);
    }

    #[test]
    fn test_derive_csrf_token_empty_secret() {
        let token = derive_csrf_token("session", "");
        assert_eq!(token.len(), 64);
    }

    #[test]
    fn test_constant_time_compare_equal() {
        assert!(constant_time_compare("hello", "hello"));
        assert!(constant_time_compare("", ""));
        assert!(constant_time_compare(
            "a".repeat(1000).as_str(),
            "a".repeat(1000).as_str()
        ));
    }

    #[test]
    fn test_constant_time_compare_not_equal() {
        assert!(!constant_time_compare("hello", "world"));
        assert!(!constant_time_compare("hello", "Hello"));
        assert!(!constant_time_compare("hello", "hello!"));
        assert!(!constant_time_compare("hello", "hell"));
        assert!(!constant_time_compare("", "x"));
    }

    #[test]
    fn test_constant_time_compare_different_lengths() {
        assert!(!constant_time_compare("short", "a much longer string"));
        assert!(!constant_time_compare("a much longer string", "short"));
    }

    #[test]
    fn test_csrf_token_wrong_secret_rejected() {
        let token = derive_csrf_token("session123", "correct-secret");
        let forged = derive_csrf_token("session123", "wrong-secret");
        assert!(!constant_time_compare(&token, &forged));
    }

    #[test]
    fn test_get_cookie_from_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", "session_id=abc123; other=xyz".parse().unwrap());
        assert_eq!(get_cookie(&headers, "session_id"), Some("abc123".to_string()));
        assert_eq!(get_cookie(&headers, "other"), Some("xyz".to_string()));
        assert_eq!(get_cookie(&headers, "missing"), None);
    }

    #[test]
    fn test_get_cookie_no_cookie_header() {
        let headers = HeaderMap::new();
        assert_eq!(get_cookie(&headers, "session_id"), None);
    }
}
