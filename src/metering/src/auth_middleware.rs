// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    extract::State,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

use crate::AppState;

#[derive(Debug, thiserror::Error)]
pub(crate) enum LoadSecretError {
    #[error("INTERNAL_SERVICE_SECRET must be set for the metering service [{location}]")]
    Missing { location: dterror::Location },
}

#[tracing::instrument(skip_all, err)]
pub(crate) fn load_internal_service_secret() -> Result<String, LoadSecretError> {
    std::env::var("INTERNAL_SERVICE_SECRET")
        .ok()
        .map(|secret| secret.trim().to_string())
        .filter(|secret| !secret.is_empty())
        .ok_or(LoadSecretError::Missing {
            location: std::panic::Location::caller(),
        })
}

#[tracing::instrument(skip_all)]
pub(crate) fn has_valid_internal_service_secret(
    configured_secret: &str,
    provided_secret: Option<&str>,
) -> bool {
    matches!(provided_secret, Some(secret) if secret == configured_secret)
}

/// Internal service auth middleware — checks x-internal-service-secret header.
#[tracing::instrument(skip_all)]
pub(crate) async fn internal_auth_middleware(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let provided = headers
        .get("x-internal-service-secret")
        .and_then(|h| h.to_str().ok());

    if has_valid_internal_service_secret(&state.internal_service_secret, provided) {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or missing internal service secret",
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn load_internal_service_secret_accepts_non_empty_value() {
        let guard = env_lock().lock().expect("env lock");
        // SAFETY: test serialized by env_lock mutex, no concurrent env access.
        unsafe {
            std::env::set_var("INTERNAL_SERVICE_SECRET", "super-secret");
        }
        let secret = load_internal_service_secret().expect("secret should load");
        assert_eq!(secret, "super-secret");
        drop(guard);
    }

    #[test]
    fn load_internal_service_secret_rejects_missing_value() {
        let guard = env_lock().lock().expect("env lock");
        // SAFETY: test serialized by env_lock mutex, no concurrent env access.
        unsafe {
            std::env::remove_var("INTERNAL_SERVICE_SECRET");
        }
        let err = load_internal_service_secret().expect_err("missing secret should fail");
        assert!(err
            .to_string()
            .contains("INTERNAL_SERVICE_SECRET must be set"));
        drop(guard);
    }

    #[test]
    fn load_internal_service_secret_rejects_empty_value() {
        let guard = env_lock().lock().expect("env lock");
        // SAFETY: test serialized by env_lock mutex, no concurrent env access.
        unsafe {
            std::env::set_var("INTERNAL_SERVICE_SECRET", "   ");
        }
        let err = load_internal_service_secret().expect_err("empty secret should fail");
        assert!(err
            .to_string()
            .contains("INTERNAL_SERVICE_SECRET must be set"));
        drop(guard);
    }

    #[test]
    fn has_valid_internal_service_secret_requires_exact_match() {
        assert!(has_valid_internal_service_secret("secret", Some("secret")));
        assert!(!has_valid_internal_service_secret("secret", Some("wrong")));
        assert!(!has_valid_internal_service_secret("secret", None));
    }
}
