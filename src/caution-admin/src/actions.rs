// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use dterror::{BoxError, CtxError, Location, ResultExt as _};
use uuid::Uuid;

/// Reset all WebAuthn credentials for a user by calling the API's internal endpoint.
///
/// Reads `API_SERVICE_URL` and `INTERNAL_SERVICE_SECRET` from the environment,
/// then POSTs `{"user_id": "<uuid>"}` to `{API_SERVICE_URL}/internal/webauthn/reset`
/// with the shared secret in the `X-Internal-Service-Secret` header.
pub async fn reset_webauthn(user_id: Uuid) -> Result<(), ResetWebauthnError> {
    use ResetWebauthnErrorCtx as Ctx;

    let api_service_url = std::env::var("API_SERVICE_URL").with_context(Ctx::missing_api_url())?;

    let secret = std::env::var("INTERNAL_SERVICE_SECRET").with_context(Ctx::missing_secret())?;

    let url = format!(
        "{}/internal/webauthn/reset",
        api_service_url.trim_end_matches('/')
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .with_context(Ctx::request())?;

    let response = client
        .post(&url)
        .header("X-Internal-Service-Secret", &secret)
        .json(&serde_json::json!({ "user_id": user_id }))
        .send()
        .await
        .with_context(Ctx::Request)?;

    if !response.status().is_success() {
        return Err(ResetWebauthnError::NonSuccessStatus {
            status: response.status(),
            user_id,
            location: std::panic::Location::caller(),
        });
    }

    Ok(())
}

/// Errors from [`reset_webauthn`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum ResetWebauthnError {
    #[error("API_SERVICE_URL environment variable is not set [{location:?}]")]
    MissingApiUrl {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("INTERNAL_SERVICE_SECRET environment variable is not set [{location:?}]")]
    MissingSecret {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("HTTP request to the API failed [{location:?}]")]
    Request {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("API returned a non-success status [{location:?}]")]
    NonSuccessStatus {
        status: reqwest::StatusCode,
        user_id: Uuid,
        #[location]
        location: Location,
    },
}
