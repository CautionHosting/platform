// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! CRUD for per-organization roles and their rules, plus attaching/removing
//! roles from members.
//!
//! These routes run behind [`super::rbac_middleware`], so a non-owner reaches
//! them only with a matching rule; owners bypass. Every handler still verifies
//! the caller is a member of the organization in the path, so a rule scoped to
//! `["*"]` cannot be used against another tenant.
//!
//! Each handler owns its error type, with one variant per distinct failure
//! branch.

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use dterror::{BoxError, CtxError, Location, ResultExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

use crate::{AppState, AuthContext, CheckOrgAccessError};

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
    #[serde(default)]
    pub(crate) rules: Vec<RuleSpec>,
}

/// Full replacement of a role (PUT): name, description, and the complete rule
/// set.
#[derive(Debug, Deserialize)]
pub(crate) struct UpdateRoleRequest {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) description: Option<String>,
    #[serde(default)]
    pub(crate) rules: Vec<RuleSpec>,
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

/// Verifies the caller belongs to `org_id`, mapping the two access failures
/// into the calling handler's own variants. A rule scoped broadly (e.g. `["*"]`)
/// must not be usable against another organization.
macro_rules! ensure_member {
    ($state:expr, $user:expr, $org:expr, $error:ident) => {{
        crate::check_org_access(&$state.db, $user, $org)
            .await
            .map_err(|error| {
                let location = std::panic::Location::caller();
                match error {
                    CheckOrgAccessError::Forbidden { .. } => $error::Forbidden { location },
                    CheckOrgAccessError::Query { source, .. } => {
                        $error::AccessQuery { location, source }
                    }
                }
            })?
    }};
}

async fn role_in_org(db: &sqlx::PgPool, org_id: Uuid, role_id: Uuid) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM rbac_roles WHERE id = $1 AND organization_id = $2)",
    )
    .bind(role_id)
    .bind(org_id)
    .fetch_one(db)
    .await
}

async fn load_rule(
    db: &sqlx::PgPool,
    org_id: Uuid,
    role_id: Uuid,
    rule_id: Uuid,
) -> Result<Option<RbacRule>, sqlx::Error> {
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
    .fetch_optional(db)
    .await
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

/// Why a proposed rule was rejected. Each variant is one validation failure.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RuleValidationError {
    #[error("effect must be 'allow' or 'deny' (got '{effect}')")]
    InvalidEffect { effect: String },

    #[error("unknown method '{method}'")]
    InvalidMethod { method: String },

    #[error("path must be an absolute route template (got '{path}')")]
    InvalidPath { path: String },

    #[error("priority must be >= 0 (got {priority})")]
    NegativePriority { priority: i32 },

    #[error("objects must be omitted for a path without parameters")]
    ObjectsNotAllowed,

    #[error("objects is required for a path with parameters")]
    ObjectsRequired,

    #[error("objects must be a JSON object")]
    ObjectsNotAnObject,

    #[error("objects must cover exactly the path's parameters")]
    ObjectsParameterMismatch,

    #[error("objects is missing parameter '{parameter}'")]
    MissingParameter { parameter: String },

    #[error("objects['{parameter}'] must be an array")]
    ParameterNotArray { parameter: String },

    #[error("objects['{parameter}'] must contain only strings")]
    ParameterNotStrings { parameter: String },
}

/// Validates a rule's shape, including that `objects` covers every path
/// parameter, exactly, with array values.
fn validate_rule(
    effect: &str,
    method: &str,
    path: &str,
    objects: Option<&Value>,
    priority: i32,
) -> Result<(), RuleValidationError> {
    if effect != "allow" && effect != "deny" {
        return Err(RuleValidationError::InvalidEffect {
            effect: effect.to_string(),
        });
    }
    if !METHODS.contains(&method) {
        return Err(RuleValidationError::InvalidMethod {
            method: method.to_string(),
        });
    }
    if !path.starts_with('/') || path.len() < 2 {
        return Err(RuleValidationError::InvalidPath {
            path: path.to_string(),
        });
    }
    if priority < 0 {
        return Err(RuleValidationError::NegativePriority { priority });
    }

    let params = path_parameter_names(path);
    match (params.is_empty(), objects) {
        (true, None) => Ok(()),
        (true, Some(_)) => Err(RuleValidationError::ObjectsNotAllowed),
        (false, None) => Err(RuleValidationError::ObjectsRequired),
        (false, Some(Value::Object(map))) => {
            if map.len() != params.len() {
                return Err(RuleValidationError::ObjectsParameterMismatch);
            }
            for param in params {
                let Some(allowed) = map.get(param) else {
                    return Err(RuleValidationError::MissingParameter {
                        parameter: param.to_string(),
                    });
                };
                let Some(entries) = allowed.as_array() else {
                    return Err(RuleValidationError::ParameterNotArray {
                        parameter: param.to_string(),
                    });
                };
                if entries.iter().any(|entry| !entry.is_string()) {
                    return Err(RuleValidationError::ParameterNotStrings {
                        parameter: param.to_string(),
                    });
                }
            }
            Ok(())
        }
        (false, Some(_)) => Err(RuleValidationError::ObjectsNotAnObject),
    }
}

/// One rule inside a role create/replace payload.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RuleSpec {
    pub(crate) effect: String,
    pub(crate) method: String,
    pub(crate) path: String,
    #[serde(default)]
    pub(crate) objects: Option<Value>,
    #[serde(default)]
    pub(crate) priority: i32,
}

/// Why a set of rules was rejected.
enum RuleSetError {
    Invalid {
        index: usize,
        source: RuleValidationError,
    },
    Duplicate {
        index: usize,
    },
}

/// Validates every rule and rejects duplicates within the set (the same
/// `(effect, method, path)` the table's unique constraint covers).
fn validate_rules(rules: &[RuleSpec]) -> Result<(), RuleSetError> {
    let mut seen = std::collections::HashSet::new();
    for (index, rule) in rules.iter().enumerate() {
        validate_rule(
            &rule.effect,
            &rule.method,
            &rule.path,
            rule.objects.as_ref(),
            rule.priority,
        )
        .map_err(|source| RuleSetError::Invalid { index, source })?;
        if !seen.insert((rule.effect.clone(), rule.method.clone(), rule.path.clone())) {
            return Err(RuleSetError::Duplicate { index });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ListRolesError {
    #[error("failed to check organization access [{location}]")]
    AccessQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("organization access denied [{location}]")]
    Forbidden { location: Location },

    #[error("failed to list roles [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl_error_response!(ListRolesError {
    ListRolesError::AccessQuery { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    ListRolesError::Forbidden { .. } => (StatusCode::FORBIDDEN, "forbidden".to_string()),
    ListRolesError::Query { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
});

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id))]
pub(crate) async fn list_roles(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
) -> Result<Json<Vec<RbacRole>>, ListRolesError> {
    use ListRolesErrorCtx as Ctx;
    ensure_member!(state, auth.user_id, org_id, ListRolesError);
    let roles = sqlx::query_as::<_, RbacRole>(
        "SELECT id, organization_id, name, description, created_at, updated_at
         FROM rbac_roles WHERE organization_id = $1 ORDER BY name, id",
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .with_context(Ctx::query())?;
    Ok(Json(roles))
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum CreateRoleError {
    #[error("failed to check organization access [{location}]")]
    AccessQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("organization access denied [{location}]")]
    Forbidden { location: Location },

    #[error("invalid role name [{location}]")]
    InvalidName { location: Location },

    #[error("rule {index} is invalid: {source} [{location}]")]
    InvalidRule {
        index: usize,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("rule {index} duplicates an earlier rule [{location}]")]
    DuplicateRule { index: usize, location: Location },

    #[error("a role with that name already exists [{location}]")]
    NameConflict { location: Location },

    #[error("failed to begin transaction [{location}]")]
    Begin {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to create role [{location}]")]
    Insert {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to create rule {index} [{location}]")]
    InsertRule {
        index: usize,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to commit transaction [{location}]")]
    Commit {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl_error_response!(CreateRoleError {
    CreateRoleError::AccessQuery { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    CreateRoleError::Forbidden { .. } => (StatusCode::FORBIDDEN, "forbidden".to_string()),
    CreateRoleError::InvalidName { .. } => (
        StatusCode::BAD_REQUEST,
        format!("role name must be 1-{MAX_ROLE_NAME_LEN} characters")
    ),
    CreateRoleError::InvalidRule { index, source, .. } => (
        StatusCode::BAD_REQUEST,
        format!("rule {index}: {source}")
    ),
    CreateRoleError::DuplicateRule { index, .. } => (
        StatusCode::BAD_REQUEST,
        format!("rule {index} duplicates an earlier rule")
    ),
    CreateRoleError::NameConflict { .. } => (StatusCode::CONFLICT, "role name already exists".to_string()),
    CreateRoleError::Begin { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    CreateRoleError::Insert { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    CreateRoleError::InsertRule { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    CreateRoleError::Commit { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
});

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id))]
pub(crate) async fn create_role(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
    Json(payload): Json<CreateRoleRequest>,
) -> Result<(StatusCode, Json<RbacRole>), CreateRoleError> {
    use CreateRoleErrorCtx as Ctx;
    ensure_member!(state, auth.user_id, org_id, CreateRoleError);

    let name = payload.name.trim();
    if name.is_empty() || name.len() > MAX_ROLE_NAME_LEN {
        return Err(CreateRoleError::InvalidName {
            location: std::panic::Location::caller(),
        });
    }

    validate_rules(&payload.rules).map_err(|error| match error {
        RuleSetError::Invalid { index, source } => CreateRoleError::InvalidRule {
            index,
            location: std::panic::Location::caller(),
            source: Box::new(source),
        },
        RuleSetError::Duplicate { index } => CreateRoleError::DuplicateRule {
            index,
            location: std::panic::Location::caller(),
        },
    })?;

    let mut tx = state.db.begin().await.with_context(Ctx::begin())?;

    let role = sqlx::query_as::<_, RbacRole>(
        "INSERT INTO rbac_roles (organization_id, name, description)
         VALUES ($1, $2, $3)
         ON CONFLICT (organization_id, name) DO NOTHING
         RETURNING id, organization_id, name, description, created_at, updated_at",
    )
    .bind(org_id)
    .bind(name)
    .bind(payload.description.as_deref().map(str::trim))
    .fetch_optional(&mut *tx)
    .await
    .with_context(Ctx::insert())?
    .ok_or_else(|| CreateRoleError::NameConflict {
        location: std::panic::Location::caller(),
    })?;

    for (index, rule) in payload.rules.iter().enumerate() {
        sqlx::query(
            "INSERT INTO rbac_role_rules (role_id, effect, method, path, objects, priority)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(role.id)
        .bind(&rule.effect)
        .bind(&rule.method)
        .bind(&rule.path)
        .bind(&rule.objects)
        .bind(rule.priority)
        .execute(&mut *tx)
        .await
        .with_context(Ctx::insert_rule(index))?;
    }

    tx.commit().await.with_context(Ctx::commit())?;

    Ok((StatusCode::CREATED, Json(role)))
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetRoleError {
    #[error("failed to check organization access [{location}]")]
    AccessQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("organization access denied [{location}]")]
    Forbidden { location: Location },

    #[error("role not found [{location}]")]
    NotFound { location: Location },

    #[error("failed to load role [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl_error_response!(GetRoleError {
    GetRoleError::AccessQuery { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    GetRoleError::Forbidden { .. } => (StatusCode::FORBIDDEN, "forbidden".to_string()),
    GetRoleError::NotFound { .. } => (StatusCode::NOT_FOUND, "not found".to_string()),
    GetRoleError::Query { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
});

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id, role_id = %role_id))]
pub(crate) async fn get_role(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((org_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<RbacRole>, GetRoleError> {
    use GetRoleErrorCtx as Ctx;
    ensure_member!(state, auth.user_id, org_id, GetRoleError);
    let role = sqlx::query_as::<_, RbacRole>(
        "SELECT id, organization_id, name, description, created_at, updated_at
         FROM rbac_roles WHERE id = $1 AND organization_id = $2",
    )
    .bind(role_id)
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .with_context(Ctx::query())?
    .ok_or_else(|| GetRoleError::NotFound {
        location: std::panic::Location::caller(),
    })?;
    Ok(Json(role))
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum UpdateRoleError {
    #[error("failed to check organization access [{location}]")]
    AccessQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("organization access denied [{location}]")]
    Forbidden { location: Location },

    #[error("invalid role name [{location}]")]
    InvalidName { location: Location },

    #[error("rule {index} is invalid: {source} [{location}]")]
    InvalidRule {
        index: usize,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("rule {index} duplicates an earlier rule [{location}]")]
    DuplicateRule { index: usize, location: Location },

    #[error("a role with that name already exists [{location}]")]
    NameConflict { location: Location },

    #[error("failed to check role name [{location}]")]
    NameQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("role not found [{location}]")]
    NotFound { location: Location },

    #[error("failed to begin transaction [{location}]")]
    Begin {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to update role [{location}]")]
    Update {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to replace role rules [{location}]")]
    DeleteRules {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to create rule {index} [{location}]")]
    InsertRule {
        index: usize,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to commit transaction [{location}]")]
    Commit {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl_error_response!(UpdateRoleError {
    UpdateRoleError::AccessQuery { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    UpdateRoleError::Forbidden { .. } => (StatusCode::FORBIDDEN, "forbidden".to_string()),
    UpdateRoleError::InvalidName { .. } => (
        StatusCode::BAD_REQUEST,
        format!("role name must be 1-{MAX_ROLE_NAME_LEN} characters")
    ),
    UpdateRoleError::InvalidRule { index, source, .. } => (
        StatusCode::BAD_REQUEST,
        format!("rule {index}: {source}")
    ),
    UpdateRoleError::DuplicateRule { index, .. } => (
        StatusCode::BAD_REQUEST,
        format!("rule {index} duplicates an earlier rule")
    ),
    UpdateRoleError::NameConflict { .. } => (StatusCode::CONFLICT, "role name already exists".to_string()),
    UpdateRoleError::NameQuery { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    UpdateRoleError::NotFound { .. } => (StatusCode::NOT_FOUND, "not found".to_string()),
    UpdateRoleError::Begin { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    UpdateRoleError::Update { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    UpdateRoleError::DeleteRules { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    UpdateRoleError::InsertRule { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    UpdateRoleError::Commit { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
});

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id, role_id = %role_id))]
pub(crate) async fn update_role(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((org_id, role_id)): Path<(Uuid, Uuid)>,
    Json(payload): Json<UpdateRoleRequest>,
) -> Result<Json<RbacRole>, UpdateRoleError> {
    use UpdateRoleErrorCtx as Ctx;
    ensure_member!(state, auth.user_id, org_id, UpdateRoleError);

    let name = payload.name.trim();
    if name.is_empty() || name.len() > MAX_ROLE_NAME_LEN {
        return Err(UpdateRoleError::InvalidName {
            location: std::panic::Location::caller(),
        });
    }

    validate_rules(&payload.rules).map_err(|error| match error {
        RuleSetError::Invalid { index, source } => UpdateRoleError::InvalidRule {
            index,
            location: std::panic::Location::caller(),
            source: Box::new(source),
        },
        RuleSetError::Duplicate { index } => UpdateRoleError::DuplicateRule {
            index,
            location: std::panic::Location::caller(),
        },
    })?;

    // A rename must not collide with another role's name. Checking first keeps
    // the update itself context-only (PostgreSQL UPDATE has no ON CONFLICT).
    let taken: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM rbac_roles
                        WHERE organization_id = $1 AND name = $2 AND id <> $3)",
    )
    .bind(org_id)
    .bind(name)
    .bind(role_id)
    .fetch_one(&state.db)
    .await
    .with_context(Ctx::name_query())?;
    if taken {
        return Err(UpdateRoleError::NameConflict {
            location: std::panic::Location::caller(),
        });
    }

    let mut tx = state.db.begin().await.with_context(Ctx::begin())?;

    let role = sqlx::query_as::<_, RbacRole>(
        "UPDATE rbac_roles
         SET name = $3, description = $4, updated_at = NOW()
         WHERE id = $2 AND organization_id = $1
         RETURNING id, organization_id, name, description, created_at, updated_at",
    )
    .bind(org_id)
    .bind(role_id)
    .bind(name)
    .bind(payload.description.as_deref().map(str::trim))
    .fetch_optional(&mut *tx)
    .await
    .with_context(Ctx::update())?
    .ok_or_else(|| UpdateRoleError::NotFound {
        location: std::panic::Location::caller(),
    })?;

    sqlx::query("DELETE FROM rbac_role_rules WHERE role_id = $1")
        .bind(role_id)
        .execute(&mut *tx)
        .await
        .with_context(Ctx::delete_rules())?;

    for (index, rule) in payload.rules.iter().enumerate() {
        sqlx::query(
            "INSERT INTO rbac_role_rules (role_id, effect, method, path, objects, priority)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(role_id)
        .bind(&rule.effect)
        .bind(&rule.method)
        .bind(&rule.path)
        .bind(&rule.objects)
        .bind(rule.priority)
        .execute(&mut *tx)
        .await
        .with_context(Ctx::insert_rule(index))?;
    }

    tx.commit().await.with_context(Ctx::commit())?;

    Ok(Json(role))
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum DeleteRoleError {
    #[error("failed to check organization access [{location}]")]
    AccessQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("organization access denied [{location}]")]
    Forbidden { location: Location },

    #[error("role not found [{location}]")]
    NotFound { location: Location },

    #[error("failed to delete role [{location}]")]
    Delete {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl_error_response!(DeleteRoleError {
    DeleteRoleError::AccessQuery { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    DeleteRoleError::Forbidden { .. } => (StatusCode::FORBIDDEN, "forbidden".to_string()),
    DeleteRoleError::NotFound { .. } => (StatusCode::NOT_FOUND, "not found".to_string()),
    DeleteRoleError::Delete { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
});

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id, role_id = %role_id))]
pub(crate) async fn delete_role(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((org_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, DeleteRoleError> {
    use DeleteRoleErrorCtx as Ctx;
    ensure_member!(state, auth.user_id, org_id, DeleteRoleError);
    let deleted = sqlx::query("DELETE FROM rbac_roles WHERE id = $1 AND organization_id = $2")
        .bind(role_id)
        .bind(org_id)
        .execute(&state.db)
        .await
        .with_context(Ctx::delete())?
        .rows_affected();
    if deleted == 0 {
        return Err(DeleteRoleError::NotFound {
            location: std::panic::Location::caller(),
        });
    }
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ListRulesError {
    #[error("failed to check organization access [{location}]")]
    AccessQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("organization access denied [{location}]")]
    Forbidden { location: Location },

    #[error("role not found [{location}]")]
    RoleNotFound { location: Location },

    #[error("failed to check role [{location}]")]
    RoleQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to list rules [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl_error_response!(ListRulesError {
    ListRulesError::AccessQuery { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    ListRulesError::Forbidden { .. } => (StatusCode::FORBIDDEN, "forbidden".to_string()),
    ListRulesError::RoleNotFound { .. } => (StatusCode::NOT_FOUND, "not found".to_string()),
    ListRulesError::RoleQuery { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    ListRulesError::Query { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
});

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id, role_id = %role_id))]
pub(crate) async fn list_rules(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((org_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Vec<RbacRule>>, ListRulesError> {
    use ListRulesErrorCtx as Ctx;
    ensure_member!(state, auth.user_id, org_id, ListRulesError);
    if !role_in_org(&state.db, org_id, role_id)
        .await
        .with_context(Ctx::role_query())?
    {
        return Err(ListRulesError::RoleNotFound {
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
    .with_context(Ctx::query())?;
    Ok(Json(rules))
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum CreateRuleError {
    #[error("failed to check organization access [{location}]")]
    AccessQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("organization access denied [{location}]")]
    Forbidden { location: Location },

    #[error("role not found [{location}]")]
    RoleNotFound { location: Location },

    #[error("failed to check role [{location}]")]
    RoleQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("invalid rule: {source} [{location}]")]
    InvalidRule {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("an identical rule already exists [{location}]")]
    RuleConflict { location: Location },

    #[error("failed to create rule [{location}]")]
    Insert {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl_error_response!(CreateRuleError {
    CreateRuleError::AccessQuery { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    CreateRuleError::Forbidden { .. } => (StatusCode::FORBIDDEN, "forbidden".to_string()),
    CreateRuleError::RoleNotFound { .. } => (StatusCode::NOT_FOUND, "not found".to_string()),
    CreateRuleError::RoleQuery { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    CreateRuleError::InvalidRule { source, .. } => (StatusCode::BAD_REQUEST, source.to_string()),
    CreateRuleError::RuleConflict { .. } => (StatusCode::CONFLICT, "identical rule already exists".to_string()),
    CreateRuleError::Insert { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
});

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id, role_id = %role_id))]
pub(crate) async fn create_rule(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((org_id, role_id)): Path<(Uuid, Uuid)>,
    Json(payload): Json<CreateRuleRequest>,
) -> Result<(StatusCode, Json<RbacRule>), CreateRuleError> {
    use CreateRuleErrorCtx as Ctx;
    ensure_member!(state, auth.user_id, org_id, CreateRuleError);
    if !role_in_org(&state.db, org_id, role_id)
        .await
        .with_context(Ctx::role_query())?
    {
        return Err(CreateRuleError::RoleNotFound {
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
    .map_err(|source| CreateRuleError::InvalidRule {
        location: std::panic::Location::caller(),
        source: Box::new(source),
    })?;

    let rule = sqlx::query_as::<_, RbacRule>(
        "INSERT INTO rbac_role_rules (role_id, effect, method, path, objects, priority)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (role_id, effect, method, path) DO NOTHING
         RETURNING id, role_id, effect, method, path, objects, priority, created_at, updated_at",
    )
    .bind(role_id)
    .bind(&payload.effect)
    .bind(&payload.method)
    .bind(&payload.path)
    .bind(&payload.objects)
    .bind(payload.priority)
    .fetch_optional(&state.db)
    .await
    .with_context(Ctx::insert())?
    .ok_or_else(|| CreateRuleError::RuleConflict {
        location: std::panic::Location::caller(),
    })?;

    Ok((StatusCode::CREATED, Json(rule)))
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetRuleError {
    #[error("failed to check organization access [{location}]")]
    AccessQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("organization access denied [{location}]")]
    Forbidden { location: Location },

    #[error("rule not found [{location}]")]
    NotFound { location: Location },

    #[error("failed to load rule [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl_error_response!(GetRuleError {
    GetRuleError::AccessQuery { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    GetRuleError::Forbidden { .. } => (StatusCode::FORBIDDEN, "forbidden".to_string()),
    GetRuleError::NotFound { .. } => (StatusCode::NOT_FOUND, "not found".to_string()),
    GetRuleError::Query { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
});

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id, role_id = %role_id, rule_id = %rule_id))]
pub(crate) async fn get_rule(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((org_id, role_id, rule_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<Json<RbacRule>, GetRuleError> {
    use GetRuleErrorCtx as Ctx;
    ensure_member!(state, auth.user_id, org_id, GetRuleError);
    let rule = load_rule(&state.db, org_id, role_id, rule_id)
        .await
        .with_context(Ctx::query())?
        .ok_or_else(|| GetRuleError::NotFound {
            location: std::panic::Location::caller(),
        })?;
    Ok(Json(rule))
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum UpdateRuleError {
    #[error("failed to check organization access [{location}]")]
    AccessQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("organization access denied [{location}]")]
    Forbidden { location: Location },

    #[error("rule not found [{location}]")]
    NotFound { location: Location },

    #[error("failed to load rule [{location}]")]
    Load {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("invalid rule: {source} [{location}]")]
    InvalidRule {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("an identical rule already exists [{location}]")]
    RuleConflict { location: Location },

    #[error("failed to update rule [{location}]")]
    Update {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl_error_response!(UpdateRuleError {
    UpdateRuleError::AccessQuery { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    UpdateRuleError::Forbidden { .. } => (StatusCode::FORBIDDEN, "forbidden".to_string()),
    UpdateRuleError::NotFound { .. } => (StatusCode::NOT_FOUND, "not found".to_string()),
    UpdateRuleError::Load { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    UpdateRuleError::InvalidRule { source, .. } => (StatusCode::BAD_REQUEST, source.to_string()),
    UpdateRuleError::RuleConflict { .. } => (StatusCode::CONFLICT, "identical rule already exists".to_string()),
    UpdateRuleError::Update { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
});

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id, role_id = %role_id, rule_id = %rule_id))]
pub(crate) async fn update_rule(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((org_id, role_id, rule_id)): Path<(Uuid, Uuid, Uuid)>,
    Json(payload): Json<UpdateRuleRequest>,
) -> Result<Json<RbacRule>, UpdateRuleError> {
    use UpdateRuleErrorCtx as Ctx;
    ensure_member!(state, auth.user_id, org_id, UpdateRuleError);
    let existing = load_rule(&state.db, org_id, role_id, rule_id)
        .await
        .with_context(Ctx::load())?
        .ok_or_else(|| UpdateRuleError::NotFound {
            location: std::panic::Location::caller(),
        })?;

    let effect = payload.effect.unwrap_or(existing.effect);
    let method = payload.method.unwrap_or(existing.method);
    let path = payload.path.unwrap_or(existing.path);
    let priority = payload.priority.unwrap_or(existing.priority);
    // `objects` has no "absent vs null" distinction in JSON; the request value
    // (if any) replaces the existing one.
    let objects = payload.objects.or(existing.objects);

    validate_rule(&effect, &method, &path, objects.as_ref(), priority).map_err(|source| {
        UpdateRuleError::InvalidRule {
            location: std::panic::Location::caller(),
            source: Box::new(source),
        }
    })?;

    let rule = sqlx::query_as::<_, RbacRule>(
        "UPDATE rbac_role_rules
         SET effect = $3, method = $4, path = $5, objects = $6, priority = $7,
             updated_at = NOW()
         WHERE id = $1 AND role_id = $2
           AND NOT EXISTS (
               SELECT 1 FROM rbac_role_rules other
               WHERE other.role_id = $2
                 AND other.effect = $3
                 AND other.method = $4
                 AND other.path = $5
                 AND other.id <> $1
           )
         RETURNING id, role_id, effect, method, path, objects, priority, created_at, updated_at",
    )
    .bind(rule_id)
    .bind(role_id)
    .bind(&effect)
    .bind(&method)
    .bind(&path)
    .bind(&objects)
    .bind(priority)
    .fetch_optional(&state.db)
    .await
    .with_context(Ctx::update())?
    .ok_or_else(|| UpdateRuleError::RuleConflict {
        location: std::panic::Location::caller(),
    })?;

    Ok(Json(rule))
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum DeleteRuleError {
    #[error("failed to check organization access [{location}]")]
    AccessQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("organization access denied [{location}]")]
    Forbidden { location: Location },

    #[error("role not found [{location}]")]
    RoleNotFound { location: Location },

    #[error("failed to check role [{location}]")]
    RoleQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("rule not found [{location}]")]
    NotFound { location: Location },

    #[error("failed to delete rule [{location}]")]
    Delete {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl_error_response!(DeleteRuleError {
    DeleteRuleError::AccessQuery { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    DeleteRuleError::Forbidden { .. } => (StatusCode::FORBIDDEN, "forbidden".to_string()),
    DeleteRuleError::RoleNotFound { .. } => (StatusCode::NOT_FOUND, "not found".to_string()),
    DeleteRuleError::RoleQuery { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    DeleteRuleError::NotFound { .. } => (StatusCode::NOT_FOUND, "not found".to_string()),
    DeleteRuleError::Delete { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
});

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id, role_id = %role_id, rule_id = %rule_id))]
pub(crate) async fn delete_rule(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((org_id, role_id, rule_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<StatusCode, DeleteRuleError> {
    use DeleteRuleErrorCtx as Ctx;
    ensure_member!(state, auth.user_id, org_id, DeleteRuleError);
    if !role_in_org(&state.db, org_id, role_id)
        .await
        .with_context(Ctx::role_query())?
    {
        return Err(DeleteRuleError::RoleNotFound {
            location: std::panic::Location::caller(),
        });
    }
    let deleted = sqlx::query("DELETE FROM rbac_role_rules WHERE id = $1 AND role_id = $2")
        .bind(rule_id)
        .bind(role_id)
        .execute(&state.db)
        .await
        .with_context(Ctx::delete())?
        .rows_affected();
    if deleted == 0 {
        return Err(DeleteRuleError::NotFound {
            location: std::panic::Location::caller(),
        });
    }
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Member role assignments
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ListMemberRolesError {
    #[error("failed to check organization access [{location}]")]
    AccessQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("organization access denied [{location}]")]
    Forbidden { location: Location },

    #[error("failed to list member roles [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl_error_response!(ListMemberRolesError {
    ListMemberRolesError::AccessQuery { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    ListMemberRolesError::Forbidden { .. } => (StatusCode::FORBIDDEN, "forbidden".to_string()),
    ListMemberRolesError::Query { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
});

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id, member_id = %member_id))]
pub(crate) async fn list_member_roles(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((org_id, member_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Vec<RbacMemberRole>>, ListMemberRolesError> {
    use ListMemberRolesErrorCtx as Ctx;
    ensure_member!(state, auth.user_id, org_id, ListMemberRolesError);
    let roles = sqlx::query_as::<_, RbacMemberRole>(
        "SELECT organization_id, user_id, role_id, granted_by, created_at, updated_at
         FROM rbac_member_roles WHERE organization_id = $1 AND user_id = $2
         ORDER BY role_id",
    )
    .bind(org_id)
    .bind(member_id)
    .fetch_all(&state.db)
    .await
    .with_context(Ctx::query())?;
    Ok(Json(roles))
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum AttachRoleError {
    #[error("failed to check organization access [{location}]")]
    AccessQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("organization access denied [{location}]")]
    Forbidden { location: Location },

    #[error("role not found [{location}]")]
    RoleNotFound { location: Location },

    #[error("failed to check role [{location}]")]
    RoleQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("user not found [{location}]")]
    MemberNotFound { location: Location },

    #[error("failed to check membership [{location}]")]
    MemberQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("role already attached [{location}]")]
    AlreadyAttached { location: Location },

    #[error("failed to attach role [{location}]")]
    Insert {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl_error_response!(AttachRoleError {
    AttachRoleError::AccessQuery { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    AttachRoleError::Forbidden { .. } => (StatusCode::FORBIDDEN, "forbidden".to_string()),
    AttachRoleError::RoleNotFound { .. } => (StatusCode::NOT_FOUND, "not found".to_string()),
    AttachRoleError::RoleQuery { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    AttachRoleError::MemberNotFound { .. } => (StatusCode::NOT_FOUND, "not found".to_string()),
    AttachRoleError::MemberQuery { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    AttachRoleError::AlreadyAttached { .. } => (StatusCode::CONFLICT, "role already attached".to_string()),
    AttachRoleError::Insert { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
});

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id, member_id = %member_id))]
pub(crate) async fn attach_role(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((org_id, member_id)): Path<(Uuid, Uuid)>,
    Json(payload): Json<AttachRoleRequest>,
) -> Result<(StatusCode, Json<RbacMemberRole>), AttachRoleError> {
    use AttachRoleErrorCtx as Ctx;
    ensure_member!(state, auth.user_id, org_id, AttachRoleError);

    if !role_in_org(&state.db, org_id, payload.role_id)
        .await
        .with_context(Ctx::role_query())?
    {
        return Err(AttachRoleError::RoleNotFound {
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
    .with_context(Ctx::member_query())?;
    if !is_member {
        return Err(AttachRoleError::MemberNotFound {
            location: std::panic::Location::caller(),
        });
    }

    let assignment = sqlx::query_as::<_, RbacMemberRole>(
        "INSERT INTO rbac_member_roles (organization_id, user_id, role_id, granted_by)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (organization_id, user_id, role_id) DO NOTHING
         RETURNING organization_id, user_id, role_id, granted_by, created_at, updated_at",
    )
    .bind(org_id)
    .bind(member_id)
    .bind(payload.role_id)
    .bind(auth.user_id)
    .fetch_optional(&state.db)
    .await
    .with_context(Ctx::insert())?
    .ok_or_else(|| AttachRoleError::AlreadyAttached {
        location: std::panic::Location::caller(),
    })?;

    Ok((StatusCode::CREATED, Json(assignment)))
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum DetachRoleError {
    #[error("failed to check organization access [{location}]")]
    AccessQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("organization access denied [{location}]")]
    Forbidden { location: Location },

    #[error("assignment not found [{location}]")]
    NotFound { location: Location },

    #[error("failed to detach role [{location}]")]
    Delete {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl_error_response!(DetachRoleError {
    DetachRoleError::AccessQuery { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
    DetachRoleError::Forbidden { .. } => (StatusCode::FORBIDDEN, "forbidden".to_string()),
    DetachRoleError::NotFound { .. } => (StatusCode::NOT_FOUND, "not found".to_string()),
    DetachRoleError::Delete { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string()),
});

#[tracing::instrument(skip_all, err(Debug), fields(org_id = %org_id, member_id = %member_id, role_id = %role_id))]
pub(crate) async fn detach_role(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((org_id, member_id, role_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Result<StatusCode, DetachRoleError> {
    use DetachRoleErrorCtx as Ctx;
    ensure_member!(state, auth.user_id, org_id, DetachRoleError);
    let deleted = sqlx::query(
        "DELETE FROM rbac_member_roles
         WHERE organization_id = $1 AND user_id = $2 AND role_id = $3",
    )
    .bind(org_id)
    .bind(member_id)
    .bind(role_id)
    .execute(&state.db)
    .await
    .with_context(Ctx::delete())?
    .rows_affected();
    if deleted == 0 {
        return Err(DetachRoleError::NotFound {
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
        assert!(matches!(
            validate_rule("allow", "GET", "/users/me", Some(&json!({})), 0),
            Err(RuleValidationError::ObjectsNotAllowed)
        ));
    }

    #[test]
    fn parameterized_paths_require_covering_objects() {
        assert!(matches!(
            validate_rule("allow", "PATCH", "/resources/{id}", None, 0),
            Err(RuleValidationError::ObjectsRequired)
        ));
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
        assert!(matches!(
            validate_rule("allow", "PATCH", "/resources/{id}", Some(&json!({"other": ["*"]})), 0),
            Err(RuleValidationError::MissingParameter { parameter }) if parameter == "id"
        ));
        assert!(matches!(
            validate_rule("allow", "PATCH", "/resources/{id}", Some(&json!({"id": "*"})), 0),
            Err(RuleValidationError::ParameterNotArray { parameter }) if parameter == "id"
        ));
        assert!(matches!(
            validate_rule("allow", "PATCH", "/resources/{id}", Some(&json!({"id": [1]})), 0),
            Err(RuleValidationError::ParameterNotStrings { parameter }) if parameter == "id"
        ));
    }

    fn spec(effect: &str, method: &str, path: &str) -> RuleSpec {
        RuleSpec {
            effect: effect.to_string(),
            method: method.to_string(),
            path: path.to_string(),
            objects: None,
            priority: 0,
        }
    }

    #[test]
    fn rule_set_rejects_duplicates_by_index() {
        let rules = vec![
            spec("allow", "GET", "/users/me"),
            spec("allow", "GET", "/users/me"),
        ];
        assert!(matches!(
            validate_rules(&rules),
            Err(RuleSetError::Duplicate { index }) if index == 1
        ));
    }

    #[test]
    fn rule_set_reports_the_first_invalid_rule() {
        let rules = vec![
            spec("allow", "GET", "/users/me"),
            spec("maybe", "GET", "/x"),
        ];
        assert!(matches!(
            validate_rules(&rules),
            Err(RuleSetError::Invalid { index, .. }) if index == 1
        ));
    }

    #[test]
    fn invalid_rule_fields_are_rejected() {
        assert!(matches!(
            validate_rule("maybe", "GET", "/x", None, 0),
            Err(RuleValidationError::InvalidEffect { effect }) if effect == "maybe"
        ));
        assert!(matches!(
            validate_rule("allow", "FETCH", "/x", None, 0),
            Err(RuleValidationError::InvalidMethod { method }) if method == "FETCH"
        ));
        assert!(matches!(
            validate_rule("allow", "GET", "x", None, 0),
            Err(RuleValidationError::InvalidPath { path }) if path == "x"
        ));
        assert!(matches!(
            validate_rule("allow", "GET", "/x", None, -1),
            Err(RuleValidationError::NegativePriority { priority }) if priority == -1
        ));
    }
}
