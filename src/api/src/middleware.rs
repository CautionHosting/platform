// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    extract::{Extension, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use sqlx::PgPool;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{AppState, AuthContext};

pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    // Check which auth method is being used
    let internal_secret = headers
        .get("x-internal-service-secret")
        .and_then(|h| h.to_str().ok());
    let session_id = headers.get("x-session-id").and_then(|h| h.to_str().ok());

    // Internal service authentication (takes precedence if secret header is present)
    if let Some(provided_secret) = internal_secret {
        let Some(ref configured_secret) = state.internal_service_secret else {
            tracing::warn!(
                "Auth middleware: internal service auth rejected - no secret configured on server"
            );
            return Err((
                StatusCode::UNAUTHORIZED,
                "Internal service authentication not configured".to_string(),
            ));
        };

        if !bool::from(
            provided_secret
                .as_bytes()
                .ct_eq(configured_secret.as_bytes()),
        ) {
            tracing::warn!("Auth middleware: internal service auth rejected - invalid secret");
            return Err((
                StatusCode::UNAUTHORIZED,
                "Invalid internal service secret".to_string(),
            ));
        }

        let Some(user_id_str) = headers
            .get("x-authenticated-user-id")
            .and_then(|h| h.to_str().ok())
        else {
            tracing::warn!("Auth middleware: internal service auth rejected - missing user ID");
            return Err((
                StatusCode::UNAUTHORIZED,
                "Missing user ID for internal service auth".to_string(),
            ));
        };

        let Ok(user_id) = Uuid::parse_str(user_id_str) else {
            tracing::warn!(
                "Auth middleware: internal service auth rejected - invalid user ID format"
            );
            return Err((
                StatusCode::UNAUTHORIZED,
                "Invalid user ID format".to_string(),
            ));
        };

        tracing::debug!(
            "Auth middleware: internal service auth for user_id={}",
            user_id
        );
        request.extensions_mut().insert(AuthContext { user_id });
        return Ok(next.run(request).await);
    }

    // Session-based authentication
    if let Some(session_id) = session_id {
        tracing::debug!("Auth middleware: validating session");
        let user_id = validate_session(&state.db, session_id)
            .await
            .map_err(|status| {
                let msg = match status {
                    StatusCode::UNAUTHORIZED => "Invalid or expired session".to_string(),
                    _ => "Authentication failed".to_string(),
                };
                (status, msg)
            })?;
        tracing::debug!("Session validated: user_id={}", user_id);
        request.extensions_mut().insert(AuthContext { user_id });
        return Ok(next.run(request).await);
    }

    // No valid authentication method provided
    tracing::debug!("Auth middleware: no authentication provided");
    Err((
        StatusCode::UNAUTHORIZED,
        "No authentication provided".to_string(),
    ))
}

/// Internal-only auth middleware — rejects session-based auth, requires service secret + user_id.
pub async fn internal_auth_middleware(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    let internal_secret = headers
        .get("x-internal-service-secret")
        .and_then(|h| h.to_str().ok());

    let Some(provided_secret) = internal_secret else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Internal service secret required".to_string(),
        ));
    };

    let Some(ref configured_secret) = state.internal_service_secret else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Internal service authentication not configured".to_string(),
        ));
    };

    if !bool::from(
        provided_secret
            .as_bytes()
            .ct_eq(configured_secret.as_bytes()),
    ) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Invalid internal service secret".to_string(),
        ));
    }

    // User ID is optional for internal routes — most operate on org_id from path
    if let Some(user_id_str) = headers
        .get("x-authenticated-user-id")
        .and_then(|h| h.to_str().ok())
    {
        if let Ok(user_id) = Uuid::parse_str(user_id_str) {
            request.extensions_mut().insert(AuthContext { user_id });
        }
    }

    Ok(next.run(request).await)
}

pub async fn onboarding_middleware(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    ensure_user_has_org(&state.db, auth.user_id).await?;

    request.extensions_mut().insert(auth);
    Ok(next.run(request).await)
}

#[derive(Serialize)]
struct LegalAcceptanceRequiredBody {
    code: &'static str,
    document_type: String,
    message: &'static str,
}

pub async fn legal_middleware(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    mut request: Request,
    next: Next,
) -> Result<Response, Response> {
    let blocking_document =
        crate::legal::get_blocking_document_requiring_acceptance(&state.db, auth.user_id)
            .await
            .map_err(|e| {
                tracing::error!(
                    "Failed to evaluate legal enforcement for user {}: {:?}",
                    auth.user_id,
                    e
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to evaluate legal acceptance requirements".to_string(),
                )
                    .into_response()
            })?;

    if let Some(document_type) = blocking_document {
        return Err((
            StatusCode::FORBIDDEN,
            Json(LegalAcceptanceRequiredBody {
                code: "legal_acceptance_required",
                document_type,
                message: "You must accept the current legal document before continuing.",
            }),
        )
            .into_response());
    }

    request.extensions_mut().insert(auth);
    Ok(next.run(request).await)
}

pub async fn validate_session(db: &PgPool, session_id: &str) -> Result<Uuid, StatusCode> {
    let result: Option<(Uuid,)> = sqlx::query_as(
        "SELECT u.id
         FROM auth_sessions s
         INNER JOIN fido2_credentials c ON s.credential_id = c.credential_id
         INNER JOIN users u ON c.user_id = u.id
         WHERE s.session_id = $1 AND s.expires_at > NOW()",
    )
    .bind(session_id)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        tracing::error!("Session validation query failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    result.map(|(user_id,)| user_id).ok_or_else(|| {
        tracing::warn!("Invalid or expired session");
        StatusCode::UNAUTHORIZED
    })
}

pub async fn ensure_user_has_org(db: &PgPool, user_id: Uuid) -> Result<(), StatusCode> {
    tracing::debug!("ensure_user_has_org: checking user {}", user_id);

    let is_onboarded = crate::onboarding::check_onboarding_status(db, user_id).await?;

    if !is_onboarded {
        tracing::warn!("User {} has not completed onboarding", user_id);
        return Err(StatusCode::PAYMENT_REQUIRED);
    }

    let has_org: Option<(uuid::Uuid,)> = sqlx::query_as(
        "SELECT organization_id FROM organization_members WHERE user_id = $1 LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to check user org membership: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if has_org.is_some() {
        tracing::debug!("User {} already has organization", user_id);
        return Ok(());
    }

    tracing::info!(
        "User {} has no organization, initializing new account",
        user_id
    );

    crate::provisioning::initialize_user_account(db, user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to initialize user account: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::info!("Successfully initialized account for user {}", user_id);
    Ok(())
}
