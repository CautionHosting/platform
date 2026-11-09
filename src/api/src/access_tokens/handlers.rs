// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Organization access tokens: mint, list, inspect, and revoke.
//!
//! Owner-only (docs/access-tokens-bible.md D8). Every handler verifies the
//! caller is an owner of the organization in the path, so no RBAC rule can
//! delegate token minting (minting attaches arbitrary roles, D2b). The plaintext
//! is returned exactly once, at mint; only its SHA-256 hash is stored (D4).

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use dterror::{BoxError, CtxError, Location, ResultExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

use crate::{AppState, AuthContext};

const MAX_NAME_LEN: usize = 100;
const MAX_DESCRIPTION_LEN: usize = 500;
const MIN_EXPIRY_DAYS: i64 = 1;
const MAX_EXPIRY_DAYS: i64 = 3650;
const TOKEN_PREFIX: &str = "caut_oat_";

/// Generates a new opaque token: `caut_oat_` + base64url(32 random bytes).
fn generate_access_token() -> String {
    let bytes: [u8; 32] = rand::random();
    format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// SHA-256 (lowercase hex) of the token string, matching the gateway.
fn hash_access_token(plaintext: &str) -> String {
    hex::encode(Sha256::digest(plaintext.as_bytes()))
}

/// Builds an [`IntoResponse`] impl from `pattern => (status, body)` arms.
macro_rules! impl_error_response {
    ($ty:ty { $($pattern:pat => ($status:expr, $body:expr)),+ $(,)? }) => {
        impl IntoResponse for $ty {
            fn into_response(self) -> Response {
                let (status, body) = match &self {
                    $($pattern => ($status, $body)),+
                };
                sentry_middleware::error_response(status, body, self)
            }
        }
    };
}

/// Requires the caller to be an owner of `org_id`, mapping access failures into
/// the calling handler's own variants.
macro_rules! ensure_owner {
    ($state:expr, $user:expr, $org:expr, $error:ident) => {{
        let role = crate::check_org_access(&$state.db, $user, $org)
            .await
            .map_err(|error| {
                let location = std::panic::Location::caller();
                match error {
                    crate::CheckOrgAccessError::Forbidden { .. } => $error::Forbidden { location },
                    crate::CheckOrgAccessError::Query { source, .. } => {
                        $error::AccessQuery { location, source }
                    }
                }
            })?;
        if !crate::is_owner(&role) {
            return Err($error::Forbidden {
                location: std::panic::Location::caller(),
            });
        }
        role
    }};
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub(crate) struct AccessTokenRow {
    pub(crate) id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) created_by: Option<Uuid>,
    pub(crate) expires_at: Option<DateTime<Utc>>,
    pub(crate) last_used_at: Option<DateTime<Utc>>,
    pub(crate) created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub(crate) struct AccessTokenRoleRow {
    pub(crate) token_id: Uuid,
    pub(crate) role_id: Uuid,
    pub(crate) role_name: String,
}

/// A token as returned to the UI, with its (immutable) role set. Never includes
/// the secret.
#[derive(Debug, Serialize)]
pub(crate) struct AccessTokenView {
    #[serde(flatten)]
    pub(crate) token: AccessTokenRow,
    pub(crate) roles: Vec<AccessTokenRoleRef>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AccessTokenRoleRef {
    pub(crate) id: Uuid,
    pub(crate) name: String,
}

async fn load_roles_for_tokens(
    db: &sqlx::PgPool,
    org_id: Uuid,
) -> Result<std::collections::HashMap<Uuid, Vec<AccessTokenRoleRef>>, sqlx::Error> {
    let rows = sqlx::query_as::<_, AccessTokenRoleRow>(
        "SELECT tr.token_id, r.id AS role_id, r.name AS role_name
         FROM organization_access_token_roles tr
         JOIN rbac_roles r ON r.id = tr.role_id
         WHERE tr.organization_id = $1
         ORDER BY r.name, r.id",
    )
    .bind(org_id)
    .fetch_all(db)
    .await?;

    let mut grouped: std::collections::HashMap<Uuid, Vec<AccessTokenRoleRef>> =
        std::collections::HashMap::new();
    for row in rows {
        grouped
            .entry(row.token_id)
            .or_default()
            .push(AccessTokenRoleRef {
                id: row.role_id,
                name: row.role_name,
            });
    }
    Ok(grouped)
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ListAccessTokensError {
    #[error("failed to check organization access [{location}]")]
    AccessQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("organization access denied [{location}]")]
    Forbidden { location: Location },

    #[error("failed to list access tokens [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl_error_response!(ListAccessTokensError {
    ListAccessTokensError::AccessQuery { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    ListAccessTokensError::Forbidden { .. } => (StatusCode::FORBIDDEN, "forbidden".to_string()),
    ListAccessTokensError::Query { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
});

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id))]
pub(crate) async fn list_access_tokens(
    State(state): State<Arc<AppState>>,
    auth: crate::UserPrincipal,
    Path(org_id): Path<Uuid>,
) -> Result<Json<Vec<AccessTokenView>>, ListAccessTokensError> {
    use ListAccessTokensErrorCtx as Ctx;
    ensure_owner!(state, &auth, org_id, ListAccessTokensError);

    let tokens = sqlx::query_as::<_, AccessTokenRow>(
        "SELECT id, organization_id, name, description, created_by,
                expires_at, last_used_at, created_at
         FROM organization_access_tokens
         WHERE organization_id = $1
         ORDER BY created_at DESC, id",
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .with_context(Ctx::query())?;

    let mut roles = load_roles_for_tokens(&state.db, org_id)
        .await
        .with_context(Ctx::query())?;

    let views = tokens
        .into_iter()
        .map(|token| AccessTokenView {
            roles: roles.remove(&token.id).unwrap_or_default(),
            token,
        })
        .collect();

    Ok(Json(views))
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct CreateAccessTokenRequest {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) description: Option<String>,
    /// Days until expiry. Omitted/null means no expiry (allowed but discouraged;
    /// the UI warns). Defaults to 90 in the UI, not here.
    #[serde(default)]
    pub(crate) expires_in_days: Option<i64>,
    /// RBAC roles to attach. Chosen here and immutable thereafter (D2).
    #[serde(default)]
    pub(crate) role_ids: Vec<Uuid>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CreatedAccessToken {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) expires_at: Option<DateTime<Utc>>,
    pub(crate) role_ids: Vec<Uuid>,
    /// The plaintext token. Returned exactly once and never stored.
    pub(crate) token: String,
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum CreateAccessTokenError {
    #[error("failed to check organization access [{location}]")]
    AccessQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("organization access denied [{location}]")]
    Forbidden { location: Location },

    #[error("invalid token name [{location}]")]
    InvalidName { location: Location },

    #[error("invalid description [{location}]")]
    InvalidDescription { location: Location },

    #[error("expiry must be between {MIN_EXPIRY_DAYS} and {MAX_EXPIRY_DAYS} days [{location}]")]
    InvalidExpiry { location: Location },

    #[error("unknown role {role_id} [{location}]")]
    UnknownRole { role_id: Uuid, location: Location },

    #[error("failed to create the access token [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl_error_response!(CreateAccessTokenError {
    CreateAccessTokenError::AccessQuery { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    CreateAccessTokenError::Forbidden { .. } => (StatusCode::FORBIDDEN, "forbidden".to_string()),
    CreateAccessTokenError::InvalidName { .. } => (StatusCode::BAD_REQUEST, "invalid token name".to_string()),
    CreateAccessTokenError::InvalidDescription { .. } => (StatusCode::BAD_REQUEST, "invalid description".to_string()),
    CreateAccessTokenError::InvalidExpiry { .. } => (StatusCode::BAD_REQUEST, "invalid expiry".to_string()),
    CreateAccessTokenError::UnknownRole { .. } => (StatusCode::BAD_REQUEST, "unknown role".to_string()),
    CreateAccessTokenError::Query { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
});

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id))]
pub(crate) async fn create_access_token(
    State(state): State<Arc<AppState>>,
    auth: crate::UserPrincipal,
    Path(org_id): Path<Uuid>,
    Json(payload): Json<CreateAccessTokenRequest>,
) -> Result<Json<CreatedAccessToken>, CreateAccessTokenError> {
    use CreateAccessTokenError as E;
    use CreateAccessTokenErrorCtx as Ctx;
    ensure_owner!(state, &auth, org_id, CreateAccessTokenError);

    let name = payload.name.trim();
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(E::InvalidName {
            location: std::panic::Location::caller(),
        });
    }
    let description = payload
        .description
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if description.is_some_and(|value| value.len() > MAX_DESCRIPTION_LEN) {
        return Err(E::InvalidDescription {
            location: std::panic::Location::caller(),
        });
    }
    if let Some(days) = payload.expires_in_days
        && !(MIN_EXPIRY_DAYS..=MAX_EXPIRY_DAYS).contains(&days)
    {
        return Err(E::InvalidExpiry {
            location: std::panic::Location::caller(),
        });
    }

    // Every requested role must belong to this organization (D2). Roles are
    // per-organization, so a foreign role id is rejected, not silently dropped.
    let mut role_ids = payload.role_ids.clone();
    role_ids.sort_unstable();
    role_ids.dedup();
    if !role_ids.is_empty() {
        let found: Vec<(Uuid,)> =
            sqlx::query_as("SELECT id FROM rbac_roles WHERE organization_id = $1 AND id = ANY($2)")
                .bind(org_id)
                .bind(&role_ids)
                .fetch_all(&state.db)
                .await
                .with_context(Ctx::query())?;
        let found: std::collections::HashSet<Uuid> = found.into_iter().map(|(id,)| id).collect();
        if let Some(missing) = role_ids.iter().find(|id| !found.contains(id)) {
            return Err(E::UnknownRole {
                role_id: *missing,
                location: std::panic::Location::caller(),
            });
        }
    }

    let expires_at = payload
        .expires_in_days
        .map(|days| Utc::now() + Duration::days(days));

    let plaintext = generate_access_token();
    let token_hash = hash_access_token(&plaintext);

    let mut tx = state.db.begin().await.with_context(Ctx::query())?;

    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO organization_access_tokens
             (organization_id, token_hash, name, description, created_by, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id",
    )
    .bind(org_id)
    .bind(&token_hash)
    .bind(name)
    .bind(description)
    .bind(auth.user_id())
    .bind(expires_at)
    .fetch_one(&mut *tx)
    .await
    .with_context(Ctx::query())?;
    let token_id = row.0;

    for role_id in &role_ids {
        sqlx::query(
            "INSERT INTO organization_access_token_roles (organization_id, token_id, role_id)
             VALUES ($1, $2, $3)",
        )
        .bind(org_id)
        .bind(token_id)
        .bind(role_id)
        .execute(&mut *tx)
        .await
        .with_context(Ctx::query())?;
    }

    tx.commit().await.with_context(Ctx::query())?;

    Ok(Json(CreatedAccessToken {
        id: token_id,
        name: name.to_string(),
        expires_at,
        role_ids,
        token: plaintext,
    }))
}

// ---------------------------------------------------------------------------
// Get
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetAccessTokenError {
    #[error("failed to check organization access [{location}]")]
    AccessQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("organization access denied [{location}]")]
    Forbidden { location: Location },

    #[error("access token not found [{location}]")]
    NotFound { location: Location },

    #[error("failed to load the access token [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl_error_response!(GetAccessTokenError {
    GetAccessTokenError::AccessQuery { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    GetAccessTokenError::Forbidden { .. } => (StatusCode::FORBIDDEN, "forbidden".to_string()),
    GetAccessTokenError::NotFound { .. } => (StatusCode::NOT_FOUND, "not found".to_string()),
    GetAccessTokenError::Query { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
});

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id))]
pub(crate) async fn get_access_token(
    State(state): State<Arc<AppState>>,
    auth: crate::UserPrincipal,
    Path((org_id, token_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<AccessTokenView>, GetAccessTokenError> {
    use GetAccessTokenError as E;
    use GetAccessTokenErrorCtx as Ctx;
    ensure_owner!(state, &auth, org_id, GetAccessTokenError);

    let token = sqlx::query_as::<_, AccessTokenRow>(
        "SELECT id, organization_id, name, description, created_by,
                expires_at, last_used_at, created_at
         FROM organization_access_tokens
         WHERE id = $1 AND organization_id = $2",
    )
    .bind(token_id)
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .with_context(Ctx::query())?
    .ok_or_else(|| E::NotFound {
        location: std::panic::Location::caller(),
    })?;

    let roles = sqlx::query_as::<_, AccessTokenRoleRow>(
        "SELECT tr.token_id, r.id AS role_id, r.name AS role_name
         FROM organization_access_token_roles tr
         JOIN rbac_roles r ON r.id = tr.role_id
         WHERE tr.token_id = $1 AND tr.organization_id = $2
         ORDER BY r.name, r.id",
    )
    .bind(token_id)
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .with_context(Ctx::query())?;

    Ok(Json(AccessTokenView {
        token,
        roles: roles
            .into_iter()
            .map(|row| AccessTokenRoleRef {
                id: row.role_id,
                name: row.role_name,
            })
            .collect(),
    }))
}

// ---------------------------------------------------------------------------
// Delete (revoke)
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum DeleteAccessTokenError {
    #[error("failed to check organization access [{location}]")]
    AccessQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("organization access denied [{location}]")]
    Forbidden { location: Location },

    #[error("access token not found [{location}]")]
    NotFound { location: Location },

    #[error("failed to delete the access token [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl_error_response!(DeleteAccessTokenError {
    DeleteAccessTokenError::AccessQuery { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    DeleteAccessTokenError::Forbidden { .. } => (StatusCode::FORBIDDEN, "forbidden".to_string()),
    DeleteAccessTokenError::NotFound { .. } => (StatusCode::NOT_FOUND, "not found".to_string()),
    DeleteAccessTokenError::Query { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
});

/// Revokes a token by hard delete (D7). The next request presenting it fails.
#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id))]
pub(crate) async fn delete_access_token(
    State(state): State<Arc<AppState>>,
    auth: crate::UserPrincipal,
    Path((org_id, token_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, DeleteAccessTokenError> {
    use DeleteAccessTokenError as E;
    use DeleteAccessTokenErrorCtx as Ctx;
    ensure_owner!(state, &auth, org_id, DeleteAccessTokenError);

    let result = sqlx::query(
        "DELETE FROM organization_access_tokens WHERE id = $1 AND organization_id = $2",
    )
    .bind(token_id)
    .bind(org_id)
    .execute(&state.db)
    .await
    .with_context(Ctx::query())?;

    if result.rows_affected() == 0 {
        return Err(E::NotFound {
            location: std::panic::Location::caller(),
        });
    }

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Token identity (GET /access-tokens/me)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub(crate) struct TokenIdentity {
    pub(crate) token_id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) name: String,
    pub(crate) expires_at: Option<DateTime<Utc>>,
    pub(crate) roles: Vec<AccessTokenRoleRef>,
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum TokenIdentityError {
    #[error("this endpoint requires an access token [{location}]")]
    NotAToken { location: Location },

    #[error("access token no longer exists [{location}]")]
    NotFound { location: Location },

    #[error("failed to load the access token [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl_error_response!(TokenIdentityError {
    TokenIdentityError::NotAToken { .. } => (StatusCode::UNAUTHORIZED, "an access token is required".to_string()),
    TokenIdentityError::NotFound { .. } => (StatusCode::UNAUTHORIZED, "invalid access token".to_string()),
    TokenIdentityError::Query { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
});

/// Reports the principal behind an access token: its org, name, expiry, and
/// (immutable) roles. The token equivalent of `/users/me`, reachable by tokens.
pub(crate) async fn token_identity(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<TokenIdentity>, TokenIdentityError> {
    use TokenIdentityError as E;
    use TokenIdentityErrorCtx as Ctx;

    let Some(token_id) = auth.token_id() else {
        return Err(E::NotAToken {
            location: std::panic::Location::caller(),
        });
    };
    let Some(organization_id) = auth.token_organization_id() else {
        return Err(E::NotAToken {
            location: std::panic::Location::caller(),
        });
    };

    let row: Option<(String, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT name, expires_at FROM organization_access_tokens
         WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL",
    )
    .bind(token_id)
    .bind(organization_id)
    .fetch_optional(&state.db)
    .await
    .with_context(Ctx::query())?;

    let Some((name, expires_at)) = row else {
        return Err(E::NotFound {
            location: std::panic::Location::caller(),
        });
    };

    let roles = sqlx::query_as::<_, AccessTokenRoleRow>(
        "SELECT tr.token_id, r.id AS role_id, r.name AS role_name
         FROM organization_access_token_roles tr
         JOIN rbac_roles r ON r.id = tr.role_id
         WHERE tr.token_id = $1 AND tr.organization_id = $2
         ORDER BY r.name, r.id",
    )
    .bind(token_id)
    .bind(organization_id)
    .fetch_all(&state.db)
    .await
    .with_context(Ctx::query())?;

    Ok(Json(TokenIdentity {
        token_id,
        organization_id,
        name,
        expires_at,
        roles: roles
            .into_iter()
            .map(|row| AccessTokenRoleRef {
                id: row.role_id,
                name: row.role_name,
            })
            .collect(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_token_has_prefix_and_32_random_bytes() {
        let token = generate_access_token();
        let encoded = token.strip_prefix(TOKEN_PREFIX).expect("token prefix");
        let bytes = URL_SAFE_NO_PAD.decode(encoded).expect("base64url payload");
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn two_tokens_differ() {
        assert_ne!(generate_access_token(), generate_access_token());
    }

    #[test]
    fn hash_is_sha256_hex() {
        // Fixed known-answer vector: sha256("abc").
        assert_eq!(
            hash_access_token("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
