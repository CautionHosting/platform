// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! CRUD for per-organization roles and their rules, plus attaching/removing
//! roles from members.
//!
//! These routes run behind [`super::rbac_middleware`], so a non-owner reaches
//! them only with a matching rule; owners bypass. Every handler still verifies
//! the caller is a member of the organization in the path, so a rule scoped to
//! `["*"]` cannot be used against another tenant.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use dterror::{BoxError, CtxError, Location, ResultExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

use crate::{AppState, AuthContext, CheckOrgAccessError, check_org_access};

const MAX_ROLE_NAME_LEN: usize = 100;
const METHODS: [&str; 8] = [
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "*",
];

#[derive(Debug, Serialize, sqlx::FromRow)]
pub(crate) struct RbacRole {
    pub(crate) id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub(crate) struct RbacRule {
    pub(crate) id: Uuid,
    pub(crate) role_id: Uuid,
    pub(crate) effect: String,
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) objects: Option<Value>,
    pub(crate) priority: i32,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub(crate) struct RbacMemberRole {
    pub(crate) organization_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) role_id: Uuid,
    pub(crate) granted_by: Option<Uuid>,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateRoleRequest {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct UpdateRoleRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateRuleRequest {
    pub(crate) effect: String,
    pub(crate) method: String,
    pub(crate) path: String,
    #[serde(default)]
    pub(crate) objects: Option<Value>,
    #[serde(default)]
    pub(crate) priority: i32,
}

#[derive(Debug, Deserialize)]
pub(crate) struct UpdateRuleRequest {
    #[serde(default)]
    pub(crate) effect: Option<String>,
    #[serde(default)]
    pub(crate) method: Option<String>,
    #[serde(default)]
    pub(crate) path: Option<String>,
    #[serde(default)]
    pub(crate) objects: Option<Value>,
    #[serde(default)]
    pub(crate) priority: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AttachRoleRequest {
    pub(crate) role_id: Uuid,
}

/// Failure modes shared by the RBAC CRUD handlers.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum RbacApiError {
    #[error("database error [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("organization access denied [{location}]")]
    Forbidden { location: Location },

    #[error("not found [{location}]")]
    NotFound { location: Location },

    #[error("conflict [{location}]")]
    Conflict { location: Location },

    #[error("{message} [{location}]")]
    Validation { message: String, location: Location },
}

impl RbacApiError {
    fn validation(message: impl Into<String>) -> Self {
        RbacApiError::Validation {
            message: message.into(),
            location: std::panic::Location::caller(),
        }
    }
}

impl IntoResponse for RbacApiError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            RbacApiError::Database { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error".to_string(),
            ),
            RbacApiError::Forbidden { .. } => (StatusCode::FORBIDDEN, "forbidden".to_string()),
            RbacApiError::NotFound { .. } => (StatusCode::NOT_FOUND, "not found".to_string()),
            RbacApiError::Conflict { .. } => (StatusCode::CONFLICT, "conflict".to_string()),
            RbacApiError::Validation { message, .. } => (StatusCode::BAD_REQUEST, message.clone()),
        };
        sentry_middleware::error_response(status, body, self)
    }
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .map(|database_error| database_error.is_unique_violation())
        .unwrap_or(false)
}

/// Verifies the caller belongs to `org_id`. A rule scoped broadly (e.g.
/// `["*"]`) must not be usable against another organization.
async fn require_member(state: &AppState, user_id: Uuid, org_id: Uuid) -> Result<(), RbacApiError> {
    check_org_access(&state.db, user_id, org_id)
        .await
        .map_err(|error| {
            let location = std::panic::Location::caller();
            match error {
                CheckOrgAccessError::Forbidden { .. } => RbacApiError::Forbidden { location },
                CheckOrgAccessError::Query { source, .. } => {
                    RbacApiError::Database { location, source }
                }
            }
        })?;
    Ok(())
}

async fn role_in_org(state: &AppState, org_id: Uuid, role_id: Uuid) -> Result<bool, RbacApiError> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM rbac_roles WHERE id = $1 AND organization_id = $2)",
    )
    .bind(role_id)
    .bind(org_id)
    .fetch_one(&state.db)
    .await
    .with_context(RbacApiErrorCtx::database())
}

/// Names of the `{param}` placeholders in an axum route template.
fn path_parameter_names(path: &str) -> Vec<&str> {
    let mut names = Vec::new();
    let mut rest = path;
    while let Some(start) = rest.find('{') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('}') else {
            break;
        };
        names.push(&after[..end]);
        rest = &after[end + 1..];
    }
    names
}

/// Validates a rule's shape, including that `objects` covers every path
/// parameter, exactly, with array values.
fn validate_rule(
    effect: &str,
    method: &str,
    path: &str,
    objects: Option<&Value>,
    priority: i32,
) -> Result<(), String> {
    if effect != "allow" && effect != "deny" {
        return Err("effect must be 'allow' or 'deny'".to_string());
    }
    if !METHODS.contains(&method) {
        return Err("invalid method".to_string());
    }
    if !path.starts_with('/') || path.len() < 2 {
        return Err("path must be an absolute route template".to_string());
    }
    if priority < 0 {
        return Err("priority must be >= 0".to_string());
    }

    let params = path_parameter_names(path);
    match (params.is_empty(), objects) {
        (true, None) => Ok(()),
        (true, Some(_)) => Err("objects must be omitted for a path without parameters".to_string()),
        (false, None) => Err("objects is required for a path with parameters".to_string()),
        (false, Some(Value::Object(map))) => {
            if map.len() != params.len() {
                return Err("objects must cover exactly the path's parameters".to_string());
            }
            for param in params {
                let Some(allowed) = map.get(param) else {
                    return Err(format!("objects is missing parameter '{param}'"));
                };
                let Some(entries) = allowed.as_array() else {
                    return Err(format!("objects['{param}'] must be an array"));
                };
                if entries.iter().any(|entry| !entry.is_string()) {
                    return Err(format!("objects['{param}'] must contain only strings"));
                }
            }
            Ok(())
        }
        (false, Some(_)) => Err("objects must be a JSON object".to_string()),
    }
}

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id))]
pub(crate) async fn list_roles(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(auth): axum::extract::Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
) -> Result<Json<Vec<RbacRole>>, RbacApiError> {
    require_member(&state, auth.user_id, org_id).await?;
    let roles = sqlx::query_as::<_, RbacRole>(
        "SELECT id, organization_id, name, description, created_at, updated_at
         FROM rbac_roles WHERE organization_id = $1 ORDER BY name, id",
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .with_context(RbacApiErrorCtx::database())?;
    Ok(Json(roles))
}

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id))]
pub(crate) async fn create_role(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(auth): axum::extract::Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
    Json(payload): Json<CreateRoleRequest>,
) -> Result<(StatusCode, Json<RbacRole>), RbacApiError> {
    require_member(&state, auth.user_id, org_id).await?;

    let name = payload.name.trim();
    if name.is_empty() || name.len() > MAX_ROLE_NAME_LEN {
        return Err(RbacApiError::validation(format!(
            "role name must be 1-{MAX_ROLE_NAME_LEN} characters"
        )));
    }

    let role = sqlx::query_as::<_, RbacRole>(
        "INSERT INTO rbac_roles (organization_id, name, description)
         VALUES ($1, $2, $3)
         RETURNING id, organization_id, name, description, created_at, updated_at",
    )
    .bind(org_id)
    .bind(name)
    .bind(payload.description.as_deref().map(str::trim))
    .fetch_one(&state.db)
    .await
    .map_err(|error| {
        if is_unique_violation(&error) {
            RbacApiError::Conflict {
                location: std::panic::Location::caller(),
            }
        } else {
            RbacApiError::Database {
                location: std::panic::Location::caller(),
                source: Box::new(error),
            }
        }
    })?;

    Ok((StatusCode::CREATED, Json(role)))
}

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id, role_id = %role_id))]
pub(crate) async fn get_role(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(auth): axum::extract::Extension<AuthContext>,
    Path((org_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<RbacRole>, RbacApiError> {
    require_member(&state, auth.user_id, org_id).await?;
    let role = sqlx::query_as::<_, RbacRole>(
        "SELECT id, organization_id, name, description, created_at, updated_at
         FROM rbac_roles WHERE id = $1 AND organization_id = $2",
    )
    .bind(role_id)
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .with_context(RbacApiErrorCtx::database())?
    .ok_or_else(|| RbacApiError::NotFound {
        location: std::panic::Location::caller(),
    })?;
    Ok(Json(role))
}

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id, role_id = %role_id))]
pub(crate) async fn update_role(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(auth): axum::extract::Extension<AuthContext>,
    Path((org_id, role_id)): Path<(Uuid, Uuid)>,
    Json(payload): Json<UpdateRoleRequest>,
) -> Result<Json<RbacRole>, RbacApiError> {
    require_member(&state, auth.user_id, org_id).await?;

    if payload.name.is_none() && payload.description.is_none() {
        return Err(RbacApiError::validation("no fields to update"));
    }
    if let Some(name) = payload.name.as_deref() {
        let name = name.trim();
        if name.is_empty() || name.len() > MAX_ROLE_NAME_LEN {
            return Err(RbacApiError::validation(format!(
                "role name must be 1-{MAX_ROLE_NAME_LEN} characters"
            )));
        }
    }

    let role = sqlx::query_as::<_, RbacRole>(
        "UPDATE rbac_roles
         SET name = COALESCE($3, name),
             description = COALESCE($4, description),
             updated_at = NOW()
         WHERE id = $2 AND organization_id = $1
         RETURNING id, organization_id, name, description, created_at, updated_at",
    )
    .bind(org_id)
    .bind(role_id)
    .bind(payload.name.as_deref().map(str::trim))
    .bind(payload.description.as_deref().map(str::trim))
    .fetch_optional(&state.db)
    .await
    .map_err(|error| {
        if is_unique_violation(&error) {
            RbacApiError::Conflict {
                location: std::panic::Location::caller(),
            }
        } else {
            RbacApiError::Database {
                location: std::panic::Location::caller(),
                source: Box::new(error),
            }
        }
    })?
    .ok_or_else(|| RbacApiError::NotFound {
        location: std::panic::Location::caller(),
    })?;

    Ok(Json(role))
}

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id, role_id = %role_id))]
pub(crate) async fn delete_role(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(auth): axum::extract::Extension<AuthContext>,
    Path((org_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, RbacApiError> {
    require_member(&state, auth.user_id, org_id).await?;
    let deleted = sqlx::query("DELETE FROM rbac_roles WHERE id = $1 AND organization_id = $2")
        .bind(role_id)
        .bind(org_id)
        .execute(&state.db)
        .await
        .with_context(RbacApiErrorCtx::database())?
        .rows_affected();
    if deleted == 0 {
        return Err(RbacApiError::NotFound {
            location: std::panic::Location::caller(),
        });
    }
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id, role_id = %role_id))]
pub(crate) async fn list_rules(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(auth): axum::extract::Extension<AuthContext>,
    Path((org_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Vec<RbacRule>>, RbacApiError> {
    require_member(&state, auth.user_id, org_id).await?;
    if !role_in_org(&state, org_id, role_id).await? {
        return Err(RbacApiError::NotFound {
            location: std::panic::Location::caller(),
        });
    }
    let rules = sqlx::query_as::<_, RbacRule>(
        "SELECT id, role_id, effect, method, path, objects, priority, created_at, updated_at
         FROM rbac_role_rules WHERE role_id = $1 ORDER BY priority, id",
    )
    .bind(role_id)
    .fetch_all(&state.db)
    .await
    .with_context(RbacApiErrorCtx::database())?;
    Ok(Json(rules))
}

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id, role_id = %role_id))]
pub(crate) async fn create_rule(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(auth): axum::extract::Extension<AuthContext>,
    Path((org_id, role_id)): Path<(Uuid, Uuid)>,
    Json(payload): Json<CreateRuleRequest>,
) -> Result<(StatusCode, Json<RbacRule>), RbacApiError> {
    require_member(&state, auth.user_id, org_id).await?;
    if !role_in_org(&state, org_id, role_id).await? {
        return Err(RbacApiError::NotFound {
            location: std::panic::Location::caller(),
        });
    }
    validate_rule(
        &payload.effect,
        &payload.method,
        &payload.path,
        payload.objects.as_ref(),
        payload.priority,
    )
    .map_err(RbacApiError::validation)?;

    let rule = sqlx::query_as::<_, RbacRule>(
        "INSERT INTO rbac_role_rules (role_id, effect, method, path, objects, priority)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, role_id, effect, method, path, objects, priority, created_at, updated_at",
    )
    .bind(role_id)
    .bind(&payload.effect)
    .bind(&payload.method)
    .bind(&payload.path)
    .bind(&payload.objects)
    .bind(payload.priority)
    .fetch_one(&state.db)
    .await
    .map_err(|error| {
        if is_unique_violation(&error) {
            RbacApiError::Conflict {
                location: std::panic::Location::caller(),
            }
        } else {
            RbacApiError::Database {
                location: std::panic::Location::caller(),
                source: Box::new(error),
            }
        }
    })?;

    Ok((StatusCode::CREATED, Json(rule)))
}

async fn load_rule(
    state: &AppState,
    org_id: Uuid,
    role_id: Uuid,
    rule_id: Uuid,
) -> Result<RbacRule, RbacApiError> {
    sqlx::query_as::<_, RbacRule>(
        "SELECT r.id, r.role_id, r.effect, r.method, r.path, r.objects, r.priority,
                r.created_at, r.updated_at
         FROM rbac_role_rules r
         JOIN rbac_roles ro ON ro.id = r.role_id
         WHERE r.id = $1 AND r.role_id = $2 AND ro.organization_id = $3",
    )
    .bind(rule_id)
    .bind(role_id)
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .with_context(RbacApiErrorCtx::database())?
    .ok_or_else(|| RbacApiError::NotFound {
        location: std::panic::Location::caller(),
    })
}

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id, role_id = %role_id, rule_id = %rule_id))]
pub(crate) async fn get_rule(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(auth): axum::extract::Extension<AuthContext>,
    Path((org_id, role_id, rule_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<Json<RbacRule>, RbacApiError> {
    require_member(&state, auth.user_id, org_id).await?;
    Ok(Json(load_rule(&state, org_id, role_id, rule_id).await?))
}

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id, role_id = %role_id, rule_id = %rule_id))]
pub(crate) async fn update_rule(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(auth): axum::extract::Extension<AuthContext>,
    Path((org_id, role_id, rule_id)): Path<(Uuid, Uuid, Uuid)>,
    Json(payload): Json<UpdateRuleRequest>,
) -> Result<Json<RbacRule>, RbacApiError> {
    require_member(&state, auth.user_id, org_id).await?;
    let existing = load_rule(&state, org_id, role_id, rule_id).await?;

    let effect = payload.effect.unwrap_or(existing.effect);
    let method = payload.method.unwrap_or(existing.method);
    let path = payload.path.unwrap_or(existing.path);
    let priority = payload.priority.unwrap_or(existing.priority);
    // `objects` has no "absent vs null" distinction in JSON; the request value
    // (if any) replaces the existing one.
    let objects = payload.objects.or(existing.objects);

    validate_rule(&effect, &method, &path, objects.as_ref(), priority)
        .map_err(RbacApiError::validation)?;

    let rule = sqlx::query_as::<_, RbacRule>(
        "UPDATE rbac_role_rules
         SET effect = $3, method = $4, path = $5, objects = $6, priority = $7,
             updated_at = NOW()
         WHERE id = $1 AND role_id = $2
         RETURNING id, role_id, effect, method, path, objects, priority, created_at, updated_at",
    )
    .bind(rule_id)
    .bind(role_id)
    .bind(&effect)
    .bind(&method)
    .bind(&path)
    .bind(&objects)
    .bind(priority)
    .fetch_one(&state.db)
    .await
    .map_err(|error| {
        if is_unique_violation(&error) {
            RbacApiError::Conflict {
                location: std::panic::Location::caller(),
            }
        } else {
            RbacApiError::Database {
                location: std::panic::Location::caller(),
                source: Box::new(error),
            }
        }
    })?;

    Ok(Json(rule))
}

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id, role_id = %role_id, rule_id = %rule_id))]
pub(crate) async fn delete_rule(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(auth): axum::extract::Extension<AuthContext>,
    Path((org_id, role_id, rule_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<StatusCode, RbacApiError> {
    require_member(&state, auth.user_id, org_id).await?;
    if !role_in_org(&state, org_id, role_id).await? {
        return Err(RbacApiError::NotFound {
            location: std::panic::Location::caller(),
        });
    }
    let deleted = sqlx::query("DELETE FROM rbac_role_rules WHERE id = $1 AND role_id = $2")
        .bind(rule_id)
        .bind(role_id)
        .execute(&state.db)
        .await
        .with_context(RbacApiErrorCtx::database())?
        .rows_affected();
    if deleted == 0 {
        return Err(RbacApiError::NotFound {
            location: std::panic::Location::caller(),
        });
    }
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Member role assignments
// ---------------------------------------------------------------------------

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id, member_id = %member_id))]
pub(crate) async fn list_member_roles(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(auth): axum::extract::Extension<AuthContext>,
    Path((org_id, member_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Vec<RbacMemberRole>>, RbacApiError> {
    require_member(&state, auth.user_id, org_id).await?;
    let roles = sqlx::query_as::<_, RbacMemberRole>(
        "SELECT organization_id, user_id, role_id, granted_by, created_at, updated_at
         FROM rbac_member_roles WHERE organization_id = $1 AND user_id = $2
         ORDER BY role_id",
    )
    .bind(org_id)
    .bind(member_id)
    .fetch_all(&state.db)
    .await
    .with_context(RbacApiErrorCtx::database())?;
    Ok(Json(roles))
}

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id, member_id = %member_id))]
pub(crate) async fn attach_role(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(auth): axum::extract::Extension<AuthContext>,
    Path((org_id, member_id)): Path<(Uuid, Uuid)>,
    Json(payload): Json<AttachRoleRequest>,
) -> Result<(StatusCode, Json<RbacMemberRole>), RbacApiError> {
    require_member(&state, auth.user_id, org_id).await?;

    if !role_in_org(&state, org_id, payload.role_id).await? {
        return Err(RbacApiError::NotFound {
            location: std::panic::Location::caller(),
        });
    }

    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM organization_members
                        WHERE organization_id = $1 AND user_id = $2)",
    )
    .bind(org_id)
    .bind(member_id)
    .fetch_one(&state.db)
    .await
    .with_context(RbacApiErrorCtx::database())?;
    if !is_member {
        return Err(RbacApiError::NotFound {
            location: std::panic::Location::caller(),
        });
    }

    let assignment = sqlx::query_as::<_, RbacMemberRole>(
        "INSERT INTO rbac_member_roles (organization_id, user_id, role_id, granted_by)
         VALUES ($1, $2, $3, $4)
         RETURNING organization_id, user_id, role_id, granted_by, created_at, updated_at",
    )
    .bind(org_id)
    .bind(member_id)
    .bind(payload.role_id)
    .bind(auth.user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|error| {
        if is_unique_violation(&error) {
            RbacApiError::Conflict {
                location: std::panic::Location::caller(),
            }
        } else {
            RbacApiError::Database {
                location: std::panic::Location::caller(),
                source: Box::new(error),
            }
        }
    })?;

    Ok((StatusCode::CREATED, Json(assignment)))
}

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id, member_id = %member_id, role_id = %role_id))]
pub(crate) async fn detach_role(
    State(state): State<Arc<AppState>>,
    axum::extract::Extension(auth): axum::extract::Extension<AuthContext>,
    Path((org_id, member_id, role_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<StatusCode, RbacApiError> {
    require_member(&state, auth.user_id, org_id).await?;
    let deleted = sqlx::query(
        "DELETE FROM rbac_member_roles
         WHERE organization_id = $1 AND user_id = $2 AND role_id = $3",
    )
    .bind(org_id)
    .bind(member_id)
    .bind(role_id)
    .execute(&state.db)
    .await
    .with_context(RbacApiErrorCtx::database())?
    .rows_affected();
    if deleted == 0 {
        return Err(RbacApiError::NotFound {
            location: std::panic::Location::caller(),
        });
    }
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn path_parameters_are_extracted() {
        assert_eq!(path_parameter_names("/users/me"), Vec::<&str>::new());
        assert_eq!(path_parameter_names("/resources/{id}"), vec!["id"]);
        assert_eq!(
            path_parameter_names("/organizations/{id}/members/{user_id}"),
            vec!["id", "user_id"]
        );
    }

    #[test]
    fn parameterless_paths_accept_no_objects() {
        assert!(validate_rule("allow", "GET", "/users/me", None, 0).is_ok());
        assert!(validate_rule("allow", "GET", "/users/me", Some(&json!({})), 0).is_err());
    }

    #[test]
    fn parameterized_paths_require_covering_objects() {
        assert!(validate_rule("allow", "PATCH", "/resources/{id}", None, 0).is_err());
        assert!(
            validate_rule(
                "allow",
                "PATCH",
                "/resources/{id}",
                Some(&json!({"id": ["*"]})),
                0
            )
            .is_ok()
        );
        // Missing param.
        assert!(
            validate_rule(
                "allow",
                "PATCH",
                "/resources/{id}",
                Some(&json!({"other": ["*"]})),
                0
            )
            .is_err()
        );
        // Non-array value.
        assert!(
            validate_rule(
                "allow",
                "PATCH",
                "/resources/{id}",
                Some(&json!({"id": "*"})),
                0
            )
            .is_err()
        );
    }

    #[test]
    fn invalid_rule_fields_are_rejected() {
        assert!(validate_rule("maybe", "GET", "/x", None, 0).is_err());
        assert!(validate_rule("allow", "FETCH", "/x", None, 0).is_err());
        assert!(validate_rule("allow", "GET", "x", None, 0).is_err());
        assert!(validate_rule("allow", "GET", "/x", None, -1).is_err());
    }
}
