// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    Json,
    extract::{Extension, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use dterror::{BoxError, CtxError, Location, ResultExt};
use serde::Serialize;
use sqlx::PgPool;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{AppState, AuthContext};

/// Failure modes for [`auth_middleware`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum AuthMiddlewareError {
    #[error("internal service authentication not configured [{location}]")]
    NoSecretConfigured { location: Location },

    #[error("invalid internal service secret [{location}]")]
    InvalidSecret { location: Location },

    #[error("missing user ID for internal service auth [{location}]")]
    MissingUserId { location: Location },

    #[error("invalid user ID format [{location}]")]
    InvalidUserIdFormat { location: Location },

    #[error("invalid or expired session [{location}]")]
    SessionInvalid { location: Location },

    #[error("authentication failed [{location}]")]
    SessionFailed {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("no authentication provided [{location}]")]
    NoAuth { location: Location },
}

impl IntoResponse for AuthMiddlewareError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            AuthMiddlewareError::NoSecretConfigured { .. } => (
                StatusCode::UNAUTHORIZED,
                "Internal service authentication not configured",
            ),
            AuthMiddlewareError::InvalidSecret { .. } => {
                (StatusCode::UNAUTHORIZED, "Invalid internal service secret")
            }
            AuthMiddlewareError::MissingUserId { .. } => (
                StatusCode::UNAUTHORIZED,
                "Missing user ID for internal service auth",
            ),
            AuthMiddlewareError::InvalidUserIdFormat { .. } => {
                (StatusCode::UNAUTHORIZED, "Invalid user ID format")
            }
            AuthMiddlewareError::SessionInvalid { .. } => {
                (StatusCode::UNAUTHORIZED, "Invalid or expired session")
            }
            AuthMiddlewareError::SessionFailed { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Authentication failed")
            }
            AuthMiddlewareError::NoAuth { .. } => {
                (StatusCode::UNAUTHORIZED, "No authentication provided")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err)]
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, AuthMiddlewareError> {
    use AuthMiddlewareErrorCtx as Ctx;

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
            return Err(AuthMiddlewareError::NoSecretConfigured {
                location: std::panic::Location::caller(),
            });
        };

        if !bool::from(
            provided_secret
                .as_bytes()
                .ct_eq(configured_secret.as_bytes()),
        ) {
            tracing::warn!("Auth middleware: internal service auth rejected - invalid secret");
            return Err(AuthMiddlewareError::InvalidSecret {
                location: std::panic::Location::caller(),
            });
        }

        let Some(user_id_str) = headers
            .get("x-authenticated-user-id")
            .and_then(|h| h.to_str().ok())
        else {
            tracing::warn!("Auth middleware: internal service auth rejected - missing user ID");
            return Err(AuthMiddlewareError::MissingUserId {
                location: std::panic::Location::caller(),
            });
        };

        let Ok(user_id) = Uuid::parse_str(user_id_str) else {
            tracing::warn!(
                "Auth middleware: internal service auth rejected - invalid user ID format"
            );
            return Err(AuthMiddlewareError::InvalidUserIdFormat {
                location: std::panic::Location::caller(),
            });
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
        let session = validate_session(&state.db, session_id).await;
        if let Err(ref error) = session
            && matches!(error, ValidateSessionError::Invalid { .. })
        {
            return Err(AuthMiddlewareError::SessionInvalid {
                location: std::panic::Location::caller(),
            });
        }
        let user_id = session.with_context(Ctx::session_failed())?;
        tracing::debug!("Session validated: user_id={}", user_id);
        request.extensions_mut().insert(AuthContext { user_id });
        return Ok(next.run(request).await);
    }

    // No valid authentication method provided
    tracing::debug!("Auth middleware: no authentication provided");
    Err(AuthMiddlewareError::NoAuth {
        location: std::panic::Location::caller(),
    })
}

/// Failure modes for [`validate_session`] (leaf error; callers map into their own type).
#[derive(Debug, thiserror::Error, CtxError)]
pub enum ValidateSessionError {
    #[error("session validation query failed [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("invalid or expired session [{location}]")]
    Invalid { location: Location },
}

#[tracing::instrument(skip_all, err)]
pub async fn validate_session(db: &PgPool, session_id: &str) -> Result<Uuid, ValidateSessionError> {
    use ValidateSessionErrorCtx as Ctx;

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
    .inspect_err(|e| tracing::error!("Session validation query failed: {}", e))
    .with_context(Ctx::query())?;

    result.map(|(user_id,)| user_id).ok_or_else(|| {
        tracing::warn!("Invalid or expired session");
        ValidateSessionError::Invalid {
            location: std::panic::Location::caller(),
        }
    })
}

/// Failure modes for [`ensure_user_has_org`] (leaf error; callers map into their own type).
#[derive(Debug, thiserror::Error, CtxError)]
pub enum EnsureUserHasOrgError {
    #[error("could not check onboarding status [{location}]")]
    CheckStatus {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("user has not completed onboarding [{location}]")]
    NotOnboarded { location: Location },

    #[error("failed to check organization membership [{location}]")]
    Membership {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to initialize user account [{location}]")]
    Initialize {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
pub async fn ensure_user_has_org(db: &PgPool, user_id: Uuid) -> Result<(), EnsureUserHasOrgError> {
    use EnsureUserHasOrgErrorCtx as Ctx;

    tracing::debug!("ensure_user_has_org: checking user {}", user_id);

    let is_onboarded = crate::onboarding::check_onboarding_status(db, user_id)
        .await
        .inspect_err(|e| tracing::error!("Failed to check onboarding status: {:?}", e))
        .with_context(Ctx::check_status())?;

    if !is_onboarded {
        tracing::warn!("User {} has not completed onboarding", user_id);
        return Err(EnsureUserHasOrgError::NotOnboarded {
            location: std::panic::Location::caller(),
        });
    }

    let has_org: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM organization_members WHERE user_id = $1)")
            .bind(user_id)
            .fetch_one(db)
            .await
            .inspect_err(|e| tracing::error!("Failed to check user org membership: {:?}", e))
            .with_context(Ctx::membership())?;

    if has_org {
        tracing::debug!("User {} already has organization", user_id);
        return Ok(());
    }

    tracing::info!(
        "User {} has no organization, initializing new account",
        user_id
    );

    crate::provisioning::initialize_user_account(db, user_id)
        .await
        .inspect_err(|e| tracing::error!("Failed to initialize user account: {:?}", e))
        .with_context(Ctx::initialize())?;

    tracing::info!("Successfully initialized account for user {}", user_id);
    Ok(())
}

/// Failure modes for [`onboarding_middleware`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum OnboardingMiddlewareError {
    #[error("onboarding required [{location}]")]
    NotOnboarded { location: Location },

    #[error("internal error [{location}]")]
    Internal {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for OnboardingMiddlewareError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            OnboardingMiddlewareError::NotOnboarded { .. } => {
                (StatusCode::PAYMENT_REQUIRED, "payment required")
            }
            OnboardingMiddlewareError::Internal { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(user_id = %auth.user_id))]
pub async fn onboarding_middleware(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    mut request: Request,
    next: Next,
) -> Result<Response, OnboardingMiddlewareError> {
    use OnboardingMiddlewareErrorCtx as Ctx;

    let org = ensure_user_has_org(&state.db, auth.user_id).await;
    if let Err(ref error) = org
        && matches!(error, EnsureUserHasOrgError::NotOnboarded { .. })
    {
        return Err(OnboardingMiddlewareError::NotOnboarded {
            location: std::panic::Location::caller(),
        });
    }
    org.with_context(Ctx::internal())?;

    request.extensions_mut().insert(auth);
    Ok(next.run(request).await)
}

/// Failure modes for [`legal_middleware`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum LegalMiddlewareError {
    #[error("failed to evaluate legal acceptance requirements [{location}]")]
    Evaluate {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("legal document '{document_type}' requires acceptance [{location}]")]
    AcceptanceRequired {
        document_type: String,
        location: Location,
    },
}

impl IntoResponse for LegalMiddlewareError {
    fn into_response(self) -> Response {
        match self {
            LegalMiddlewareError::Evaluate { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to evaluate legal acceptance requirements",
            )
                .into_response(),
            LegalMiddlewareError::AcceptanceRequired { document_type, .. } => (
                StatusCode::FORBIDDEN,
                Json(LegalAcceptanceRequiredBody {
                    code: "legal_acceptance_required",
                    document_type,
                    message: "You must accept the current legal document before continuing.",
                }),
            )
                .into_response(),
        }
    }
}

#[derive(Serialize)]
struct LegalAcceptanceRequiredBody {
    code: &'static str,
    document_type: String,
    message: &'static str,
}

#[tracing::instrument(skip_all, err, fields(user_id = %auth.user_id))]
pub async fn legal_middleware(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    mut request: Request,
    next: Next,
) -> Result<Response, LegalMiddlewareError> {
    use LegalMiddlewareErrorCtx as Ctx;

    let blocking_document =
        crate::legal::get_blocking_document_requiring_acceptance(&state.db, auth.user_id)
            .await
            .inspect_err(|e| {
                tracing::error!(
                    "Failed to evaluate legal enforcement for user {}: {:?}",
                    auth.user_id,
                    e
                );
            })
            .with_context(Ctx::evaluate())?;

    if let Some(document_type) = blocking_document {
        return Err(LegalMiddlewareError::AcceptanceRequired {
            document_type,
            location: std::panic::Location::caller(),
        });
    }

    request.extensions_mut().insert(auth);
    Ok(next.run(request).await)
}

/// Failure modes for [`internal_auth_middleware`] (source-less leaf error).
#[derive(Debug, thiserror::Error)]
pub enum InternalAuthMiddlewareError {
    #[error("internal service secret required [{location}]")]
    MissingSecret { location: Location },

    #[error("internal service authentication not configured [{location}]")]
    NoSecretConfigured { location: Location },

    #[error("invalid internal service secret [{location}]")]
    InvalidSecret { location: Location },
}

impl IntoResponse for InternalAuthMiddlewareError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            InternalAuthMiddlewareError::MissingSecret { .. } => {
                (StatusCode::UNAUTHORIZED, "Internal service secret required")
            }
            InternalAuthMiddlewareError::NoSecretConfigured { .. } => (
                StatusCode::UNAUTHORIZED,
                "Internal service authentication not configured",
            ),
            InternalAuthMiddlewareError::InvalidSecret { .. } => {
                (StatusCode::UNAUTHORIZED, "Invalid internal service secret")
            }
        };
        (status, body).into_response()
    }
}

/// Internal-only auth middleware — rejects session-based auth, requires service secret + user_id.
#[tracing::instrument(skip_all, err)]
pub async fn internal_auth_middleware(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, InternalAuthMiddlewareError> {
    let internal_secret = headers
        .get("x-internal-service-secret")
        .and_then(|h| h.to_str().ok());

    let Some(provided_secret) = internal_secret else {
        return Err(InternalAuthMiddlewareError::MissingSecret {
            location: std::panic::Location::caller(),
        });
    };

    let Some(ref configured_secret) = state.internal_service_secret else {
        return Err(InternalAuthMiddlewareError::NoSecretConfigured {
            location: std::panic::Location::caller(),
        });
    };

    if !bool::from(
        provided_secret
            .as_bytes()
            .ct_eq(configured_secret.as_bytes()),
    ) {
        return Err(InternalAuthMiddlewareError::InvalidSecret {
            location: std::panic::Location::caller(),
        });
    }

    // User ID is optional for internal routes — most operate on org_id from path
    if let Some(user_id_str) = headers
        .get("x-authenticated-user-id")
        .and_then(|h| h.to_str().ok())
        && let Ok(user_id) = Uuid::parse_str(user_id_str)
    {
        request.extensions_mut().insert(AuthContext { user_id });
    }

    Ok(next.run(request).await)
}
