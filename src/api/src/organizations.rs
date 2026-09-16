// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use dterror::{BoxError, CtxError, Location, ResultExt};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool};
use std::sync::Arc;
use uuid::Uuid;

use crate::types;
use crate::validated_types;
use crate::validated_types::{
    AddMemberRequest, CreateOrganizationRequest, InviteMemberRequest, UpdateMemberRequest,
    UpdateOrgSettingsRequest, UpdateOrganizationRequest,
};
use crate::{AppState, AuthContext, can_manage_org, check_org_access, is_owner};

const INVITATION_EXPIRY_HOURS: i64 = 72;
const LEGACY_DEFAULT_ORG_PREFIX: &str = "Organization for user ";

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct Organization {
    pub id: Uuid,
    pub name: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, FromRow)]
pub struct OrganizationMember {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub user_id: Uuid,
    pub username: Option<String>,
    pub email: Option<String>,
    pub role: String,
    pub joined_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, FromRow)]
pub struct OrganizationInvitation {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub email: String,
    pub role: String,
    pub invited_by: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct InviteMemberResponse {
    pub invitation: OrganizationInvitation,
    pub email_sent: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OrgSettings {
    pub require_pin: bool,
}

/// Failure modes for [`user_has_organization`] (leaf error: no underlying source
/// surfaces to a client; callers box it into their own error).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum UserHasOrganizationError {
    #[error("failed to check user organization membership [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn user_has_organization(
    db: &PgPool,
    user_id: Uuid,
) -> Result<bool, UserHasOrganizationError> {
    use UserHasOrganizationErrorCtx as Ctx;

    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM organization_members WHERE user_id = $1)")
        .bind(user_id)
        .fetch_one(db)
        .await
        .with_context(Ctx::query())
}

fn generate_invitation_token() -> (String, String) {
    let mut token_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut token_bytes);

    let token = URL_SAFE_NO_PAD.encode(token_bytes);
    let token_hash = hex::encode(Sha256::digest(token_bytes));

    (token, token_hash)
}

fn public_organization_name(name: &str) -> String {
    let trimmed = name.trim();
    if let Some(user_id) = trimmed.strip_prefix(LEGACY_DEFAULT_ORG_PREFIX)
        && Uuid::parse_str(user_id).is_ok()
    {
        return "your organization".to_string();
    }
    trimmed.to_string()
}

/// Failure modes for [`list_organizations`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum ListOrganizationsError {
    #[error("failed to list organizations [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for ListOrganizationsError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            ListOrganizationsError::Query { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(user_id = %auth.user_id))]
pub async fn list_organizations(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<Organization>>, ListOrganizationsError> {
    use ListOrganizationsErrorCtx as Ctx;

    tracing::debug!("list_organizations called for user {}", auth.user_id);
    let orgs = sqlx::query_as::<_, Organization>(
        "SELECT o.id, o.name, o.is_active, o.created_at, o.updated_at
         FROM organizations o
         INNER JOIN organization_members om ON o.id = om.organization_id
         WHERE om.user_id = $1
         ORDER BY om.created_at ASC, om.id ASC",
    )
    .bind(auth.user_id)
    .fetch_all(&state.db)
    .await
    .with_context(Ctx::query())?;

    tracing::debug!("list_organizations returning {} orgs", orgs.len());
    Ok(Json(orgs))
}

/// Failure modes for [`create_organization`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum CreateOrganizationError {
    #[error("failed to check existing organization membership [{location}]")]
    HasOrgCheck {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("user {user_id} already belongs to an organization [{location}]")]
    AlreadyMember { user_id: Uuid, location: Location },

    #[error("failed to begin transaction [{location}]")]
    Begin {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to create organization [{location}]")]
    InsertOrg {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("user already belongs to an organization [{location}]")]
    MemberConflict {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to add organization member [{location}]")]
    MemberInsert {
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

impl IntoResponse for CreateOrganizationError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            CreateOrganizationError::HasOrgCheck { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            CreateOrganizationError::AlreadyMember { .. } => (StatusCode::CONFLICT, "conflict"),
            CreateOrganizationError::Begin { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            CreateOrganizationError::InsertOrg { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            CreateOrganizationError::MemberConflict { .. } => (StatusCode::CONFLICT, "conflict"),
            CreateOrganizationError::MemberInsert { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            CreateOrganizationError::Commit { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(user_id = %auth.user_id))]
pub async fn create_organization(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    validated_types::Validated(payload): validated_types::Validated<CreateOrganizationRequest>,
) -> Result<Json<Organization>, CreateOrganizationError> {
    use CreateOrganizationErrorCtx as Ctx;

    if user_has_organization(&state.db, auth.user_id)
        .await
        .with_context(Ctx::has_org_check())?
    {
        return Err(CreateOrganizationError::AlreadyMember {
            user_id: auth.user_id,
            location: std::panic::Location::caller(),
        });
    }

    let mut tx = state.db.begin().await.with_context(Ctx::begin())?;

    let org = sqlx::query_as::<_, Organization>(
        "INSERT INTO organizations (name)
         VALUES ($1)
         RETURNING id, name, is_active, created_at, updated_at",
    )
    .bind(&payload.name)
    .fetch_one(&mut *tx)
    .await
    .with_context(Ctx::insert_org())?;

    sqlx::query(
        "INSERT INTO organization_members (organization_id, user_id, role)
         VALUES ($1, $2, $3)",
    )
    .bind(org.id)
    .bind(auth.user_id)
    .bind(types::UserRole::Owner)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        if e.as_database_error()
            .map(|database_error| database_error.is_unique_violation())
            .unwrap_or(false)
        {
            CreateOrganizationError::MemberConflict {
                location: std::panic::Location::caller(),
                source: Box::new(e),
            }
        } else {
            CreateOrganizationError::MemberInsert {
                location: std::panic::Location::caller(),
                source: Box::new(e),
            }
        }
    })?;

    tx.commit().await.with_context(Ctx::commit())?;

    Ok(Json(org))
}

/// Failure modes for [`get_organization`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum GetOrganizationError {
    #[error("failed to check organization access [{location}]")]
    AccessQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("organization {org_id} not found [{location}]")]
    NotFound {
        org_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for GetOrganizationError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            GetOrganizationError::AccessQuery { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            GetOrganizationError::NotFound { .. } => (StatusCode::NOT_FOUND, "not found"),
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(org_id = %org_id))]
pub async fn get_organization(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
) -> Result<Json<Organization>, GetOrganizationError> {
    use GetOrganizationErrorCtx as Ctx;

    check_org_access(&state.db, auth.user_id, org_id)
        .await
        .with_context(Ctx::access_query())?;

    let org = sqlx::query_as::<_, Organization>(
        "SELECT id, name, is_active, created_at, updated_at
         FROM organizations WHERE id = $1",
    )
    .bind(org_id)
    .fetch_one(&state.db)
    .await
    .with_context(Ctx::not_found(org_id))?;

    Ok(Json(org))
}

/// Failure modes for [`update_organization`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum UpdateOrganizationError {
    #[error("failed to check organization access [{location}]")]
    AccessQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("you do not have permission to manage this organization [{location}]")]
    NotManager { location: Location },

    #[error("no organization name provided [{location}]")]
    BadRequest { location: Location },

    #[error("failed to update organization {org_id} [{location}]")]
    Update {
        org_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for UpdateOrganizationError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            UpdateOrganizationError::AccessQuery { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            UpdateOrganizationError::NotManager { .. } => (StatusCode::FORBIDDEN, "forbidden"),
            UpdateOrganizationError::BadRequest { .. } => (StatusCode::BAD_REQUEST, "bad request"),
            UpdateOrganizationError::Update { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(org_id = %org_id))]
pub async fn update_organization(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
    validated_types::Validated(payload): validated_types::Validated<UpdateOrganizationRequest>,
) -> Result<Json<Organization>, UpdateOrganizationError> {
    use UpdateOrganizationErrorCtx as Ctx;

    let role = check_org_access(&state.db, auth.user_id, org_id)
        .await
        .with_context(Ctx::access_query())?;

    if !can_manage_org(&role) {
        return Err(UpdateOrganizationError::NotManager {
            location: std::panic::Location::caller(),
        });
    }

    if payload.name.is_none() {
        return Err(UpdateOrganizationError::BadRequest {
            location: std::panic::Location::caller(),
        });
    }

    let mut query_builder = sqlx::QueryBuilder::new("UPDATE organizations SET ");

    if let Some(name) = &payload.name {
        query_builder.push("name = ");
        query_builder.push_bind(name);
    }

    query_builder.push(" WHERE id = ");
    query_builder.push_bind(org_id);
    query_builder.push(" RETURNING id, name, is_active, created_at, updated_at");

    let org = query_builder
        .build_query_as::<Organization>()
        .fetch_one(&state.db)
        .await
        .with_context(Ctx::update(org_id))?;

    Ok(Json(org))
}

/// Failure modes for [`delete_organization`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum DeleteOrganizationError {
    #[error("failed to check organization access [{location}]")]
    AccessQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("you do not have permission to manage this organization [{location}]")]
    NotOwner { location: Location },

    #[error("failed to delete organization {org_id} [{location}]")]
    Update {
        org_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for DeleteOrganizationError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            DeleteOrganizationError::AccessQuery { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            DeleteOrganizationError::NotOwner { .. } => (StatusCode::FORBIDDEN, "forbidden"),
            DeleteOrganizationError::Update { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(org_id = %org_id))]
pub async fn delete_organization(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
) -> Result<StatusCode, DeleteOrganizationError> {
    use DeleteOrganizationErrorCtx as Ctx;

    let role = check_org_access(&state.db, auth.user_id, org_id)
        .await
        .with_context(Ctx::access_query())?;

    if !is_owner(&role) {
        return Err(DeleteOrganizationError::NotOwner {
            location: std::panic::Location::caller(),
        });
    }

    sqlx::query("UPDATE organizations SET is_active = false WHERE id = $1")
        .bind(org_id)
        .execute(&state.db)
        .await
        .with_context(Ctx::update(org_id))?;

    Ok(StatusCode::NO_CONTENT)
}

/// Failure modes for [`get_org_settings`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum GetOrgSettingsError {
    #[error("failed to check organization access [{location}]")]
    AccessQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to load organization settings [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for GetOrgSettingsError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            GetOrgSettingsError::AccessQuery { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            GetOrgSettingsError::Query { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(org_id = %org_id))]
pub async fn get_org_settings(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
) -> Result<Json<OrgSettings>, GetOrgSettingsError> {
    use GetOrgSettingsErrorCtx as Ctx;

    tracing::debug!("get_org_settings called for org {}", org_id);
    check_org_access(&state.db, auth.user_id, org_id)
        .await
        .with_context(Ctx::access_query())?;

    let settings: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT settings FROM organizations WHERE id = $1")
            .bind(org_id)
            .fetch_optional(&state.db)
            .await
            .with_context(Ctx::query())?
            .flatten();

    let org_settings = settings
        .and_then(|s| serde_json::from_value(s).ok())
        .unwrap_or(OrgSettings { require_pin: false });

    tracing::debug!("get_org_settings returning: {:?}", org_settings);
    Ok(Json(org_settings))
}

/// Failure modes for [`update_org_settings`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum UpdateOrgSettingsError {
    #[error("failed to check organization access [{location}]")]
    AccessQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("you do not have permission to manage this organization [{location}]")]
    NotManager { location: Location },

    #[error("failed to update organization settings [{location}]")]
    Update {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to parse updated organization settings [{location}]")]
    Parse {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for UpdateOrgSettingsError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            UpdateOrgSettingsError::AccessQuery { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            UpdateOrgSettingsError::NotManager { .. } => (StatusCode::FORBIDDEN, "forbidden"),
            UpdateOrgSettingsError::Update { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            UpdateOrgSettingsError::Parse { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(org_id = %org_id))]
pub async fn update_org_settings(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
    validated_types::Validated(payload): validated_types::Validated<UpdateOrgSettingsRequest>,
) -> Result<Json<OrgSettings>, UpdateOrgSettingsError> {
    use UpdateOrgSettingsErrorCtx as Ctx;

    let role = check_org_access(&state.db, auth.user_id, org_id)
        .await
        .with_context(Ctx::access_query())?;

    if !can_manage_org(&role) {
        return Err(UpdateOrgSettingsError::NotManager {
            location: std::panic::Location::caller(),
        });
    }

    // Build the settings JSON update
    let mut settings = serde_json::json!({});
    if let Some(require_pin) = payload.require_pin {
        settings["require_pin"] = serde_json::json!(require_pin);
    }

    let updated_settings: serde_json::Value = sqlx::query_scalar(
        "UPDATE organizations
         SET settings = COALESCE(settings, '{}'::jsonb) || $1::jsonb,
             updated_at = NOW()
         WHERE id = $2
         RETURNING settings",
    )
    .bind(&settings)
    .bind(org_id)
    .fetch_one(&state.db)
    .await
    .with_context(Ctx::update())?;

    let org_settings: OrgSettings =
        serde_json::from_value(updated_settings.clone()).with_context(Ctx::parse())?;

    Ok(Json(org_settings))
}

/// Failure modes for [`list_members`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum ListMembersError {
    #[error("failed to check organization access [{location}]")]
    AccessQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to list organization members [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for ListMembersError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            ListMembersError::AccessQuery { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            ListMembersError::Query { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(org_id = %org_id))]
pub async fn list_members(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
) -> Result<Json<Vec<OrganizationMember>>, ListMembersError> {
    use ListMembersErrorCtx as Ctx;

    check_org_access(&state.db, auth.user_id, org_id)
        .await
        .with_context(Ctx::access_query())?;

    let members = sqlx::query_as::<_, OrganizationMember>(
        "SELECT om.id,
                om.organization_id,
                om.user_id,
                u.username,
                u.email,
                om.role::text as role,
                om.accepted_at as joined_at,
                om.created_at,
                om.updated_at
         FROM organization_members om
         INNER JOIN users u ON u.id = om.user_id
         WHERE om.organization_id = $1
         ORDER BY om.accepted_at ASC",
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .with_context(Ctx::query())?;

    Ok(Json(members))
}

/// Failure modes for [`invite_member`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum InviteMemberError {
    #[error("you do not have permission to manage this organization [{location}]")]
    Forbidden { location: Location },

    #[error("a user with this email is already a member of this organization [{location}]")]
    AlreadyMember { location: Location },

    #[error("an active invitation already exists for this email [{location}]")]
    AlreadyInvited { location: Location },

    #[error("a platform user with this email already exists [{location}]")]
    UserAlreadyExists { location: Location },

    #[error("organization invitation not found [{location}]")]
    NotFound { org_id: Uuid, location: Location },

    #[error("failed to create invitation [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for InviteMemberError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            InviteMemberError::Forbidden { .. } => (StatusCode::FORBIDDEN, "forbidden"),
            InviteMemberError::AlreadyMember { .. } => (StatusCode::CONFLICT, "conflict"),
            InviteMemberError::AlreadyInvited { .. } => (StatusCode::CONFLICT, "conflict"),
            InviteMemberError::UserAlreadyExists { .. } => (StatusCode::CONFLICT, "conflict"),
            InviteMemberError::NotFound { .. } => (StatusCode::NOT_FOUND, "not found"),
            InviteMemberError::Database { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(org_id = %org_id))]
pub async fn invite_member(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
    validated_types::Validated(payload): validated_types::Validated<InviteMemberRequest>,
) -> Result<Json<InviteMemberResponse>, InviteMemberError> {
    use InviteMemberErrorCtx as Ctx;

    let role = check_org_access(&state.db, auth.user_id, org_id)
        .await
        .with_context(Ctx::database())?;

    if !can_manage_org(&role) {
        return Err(InviteMemberError::Forbidden {
            location: std::panic::Location::caller(),
        });
    }

    let email = payload.email.trim().to_lowercase();

    let already_member: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1
             FROM users u
             INNER JOIN organization_members om ON om.user_id = u.id
             WHERE om.organization_id = $1 AND lower(u.email) = $2
         )",
    )
    .bind(org_id)
    .bind(&email)
    .fetch_one(&state.db)
    .await
    .with_context(Ctx::database())?;

    if already_member {
        return Err(InviteMemberError::AlreadyMember {
            location: std::panic::Location::caller(),
        });
    }

    let already_invited: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1
             FROM organization_invitations
             WHERE organization_id = $1
               AND lower(email) = $2
               AND accepted_at IS NULL
               AND revoked_at IS NULL
               AND expires_at > NOW()
         )",
    )
    .bind(org_id)
    .bind(&email)
    .fetch_one(&state.db)
    .await
    .with_context(Ctx::database())?;

    if already_invited {
        return Err(InviteMemberError::AlreadyInvited {
            location: std::panic::Location::caller(),
        });
    }

    sqlx::query(
        "UPDATE organization_invitations
         SET revoked_at = NOW()
         WHERE organization_id = $1
           AND lower(email) = $2
           AND accepted_at IS NULL
           AND revoked_at IS NULL
           AND expires_at <= NOW()",
    )
    .bind(org_id)
    .bind(&email)
    .execute(&state.db)
    .await
    .with_context(Ctx::database())?;

    let existing_user: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE lower(email) = $1)")
            .bind(&email)
            .fetch_one(&state.db)
            .await
            .with_context(Ctx::database())?;

    if existing_user {
        return Err(InviteMemberError::UserAlreadyExists {
            location: std::panic::Location::caller(),
        });
    }

    let org_name: String = sqlx::query_scalar("SELECT name FROM organizations WHERE id = $1")
        .bind(org_id)
        .fetch_optional(&state.db)
        .await
        .with_context(Ctx::database())?
        .ok_or_else(|| InviteMemberError::NotFound {
            org_id,
            location: std::panic::Location::caller(),
        })?;

    let inviter_email: Option<String> = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(auth.user_id)
        .fetch_optional(&state.db)
        .await
        .with_context(Ctx::database())?
        .flatten();

    let (token, token_hash) = generate_invitation_token();
    let expires_at = Utc::now() + Duration::hours(INVITATION_EXPIRY_HOURS);

    let invitation = sqlx::query_as::<_, OrganizationInvitation>(
        "INSERT INTO organization_invitations
             (organization_id, email, role, token_hash, invited_by, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id,
                   organization_id,
                   email,
                   role::text as role,
                   invited_by,
                   expires_at,
                   accepted_at,
                   revoked_at,
                   created_at,
                   updated_at",
    )
    .bind(org_id)
    .bind(&email)
    .bind(types::UserRole::Owner)
    .bind(&token_hash)
    .bind(auth.user_id)
    .bind(expires_at)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        if e.as_database_error()
            .map(|database_error| database_error.is_unique_violation())
            .unwrap_or(false)
        {
            return InviteMemberError::AlreadyInvited {
                location: std::panic::Location::caller(),
            };
        }
        InviteMemberError::Database {
            location: std::panic::Location::caller(),
            source: Box::new(e),
        }
    })?;

    let email_sent = send_organization_invite_email(
        &email,
        &public_organization_name(&org_name),
        inviter_email.as_deref(),
        &token,
        expires_at,
    )
    .await;

    Ok(Json(InviteMemberResponse {
        invitation,
        email_sent,
    }))
}

/// Failure modes for [`list_active_invitations`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum ListActiveInvitationsError {
    #[error("you do not have permission to manage this organization [{location}]")]
    Forbidden { location: Location },

    #[error("failed to list organization invitations [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for ListActiveInvitationsError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            ListActiveInvitationsError::Forbidden { .. } => (StatusCode::FORBIDDEN, "forbidden"),
            ListActiveInvitationsError::Query { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(org_id = %org_id))]
pub async fn list_active_invitations(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
) -> Result<Json<Vec<OrganizationInvitation>>, ListActiveInvitationsError> {
    use ListActiveInvitationsErrorCtx as Ctx;

    let role = check_org_access(&state.db, auth.user_id, org_id)
        .await
        .with_context(Ctx::query())?;

    if !can_manage_org(&role) {
        return Err(ListActiveInvitationsError::Forbidden {
            location: std::panic::Location::caller(),
        });
    }

    let invitations = sqlx::query_as::<_, OrganizationInvitation>(
        "SELECT id,
                organization_id,
                email,
                role::text as role,
                invited_by,
                expires_at,
                accepted_at,
                revoked_at,
                created_at,
                updated_at
         FROM organization_invitations
         WHERE organization_id = $1
           AND accepted_at IS NULL
           AND revoked_at IS NULL
           AND expires_at > NOW()
         ORDER BY created_at DESC",
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .with_context(Ctx::query())?;

    Ok(Json(invitations))
}

/// Failure modes for [`cancel_invitation`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum CancelInvitationError {
    #[error("you do not have permission to manage this organization [{location}]")]
    Forbidden { location: Location },

    #[error("organization invitation not found [{location}]")]
    NotFound { location: Location },

    #[error("failed to cancel organization invitation [{location}]")]
    Database {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for CancelInvitationError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            CancelInvitationError::Forbidden { .. } => (StatusCode::FORBIDDEN, "forbidden"),
            CancelInvitationError::NotFound { .. } => (StatusCode::NOT_FOUND, "not found"),
            CancelInvitationError::Database { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(org_id = %org_id))]
pub async fn cancel_invitation(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((org_id, invitation_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, CancelInvitationError> {
    use CancelInvitationErrorCtx as Ctx;

    let role = check_org_access(&state.db, auth.user_id, org_id)
        .await
        .with_context(Ctx::database())?;

    if !can_manage_org(&role) {
        return Err(CancelInvitationError::Forbidden {
            location: std::panic::Location::caller(),
        });
    }

    let result = sqlx::query(
        "UPDATE organization_invitations
         SET revoked_at = NOW()
         WHERE id = $1
           AND organization_id = $2
           AND accepted_at IS NULL
           AND revoked_at IS NULL",
    )
    .bind(invitation_id)
    .bind(org_id)
    .execute(&state.db)
    .await
    .with_context(Ctx::database())?;

    if result.rows_affected() == 0 {
        return Err(CancelInvitationError::NotFound {
            location: std::panic::Location::caller(),
        });
    }

    Ok(StatusCode::NO_CONTENT)
}

#[tracing::instrument(skip_all)]
async fn send_organization_invite_email(
    email: &str,
    org_name: &str,
    inviter_email: Option<&str>,
    token: &str,
    expires_at: DateTime<Utc>,
) -> bool {
    let email_service_url =
        std::env::var("EMAIL_SERVICE_URL").unwrap_or_else(|_| "http://email:8082".to_string());
    let frontend_url =
        std::env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:8000".to_string());
    let invite_url = format!(
        "{}/invite?token={}",
        frontend_url.trim_end_matches('/'),
        token
    );

    let email_request = serde_json::json!({
        "to": email,
        "template": "organization_invite",
        "data": {
            "organization_name": org_name,
            "inviter_email": inviter_email,
            "invite_url": invite_url,
            "expires_at": expires_at.to_rfc3339(),
        }
    });

    match reqwest::Client::new()
        .post(format!("{}/send", email_service_url))
        .json(&email_request)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => true,
        Ok(response) => {
            tracing::error!(
                "Email service returned {} while sending organization invite",
                response.status()
            );
            false
        }
        Err(e) => {
            tracing::error!(
                "Failed to call email service for organization invite: {:?}",
                e
            );
            false
        }
    }
}

/// Failure modes for [`add_member`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum AddMemberError {
    #[error("failed to check organization access [{location}]")]
    AccessQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("you do not have permission to manage this organization [{location}]")]
    NotManager { location: Location },

    #[error("failed to check existing organization membership [{location}]")]
    HasOrgCheck {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("user already belongs to an organization [{location}]")]
    AlreadyMember { location: Location },

    #[error("failed to add organization member [{location}]")]
    Insert {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for AddMemberError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            AddMemberError::AccessQuery { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            AddMemberError::NotManager { .. } => (StatusCode::FORBIDDEN, "forbidden"),
            AddMemberError::HasOrgCheck { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            AddMemberError::AlreadyMember { .. } => (StatusCode::CONFLICT, "conflict"),
            AddMemberError::Insert { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(org_id = %org_id))]
pub async fn add_member(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
    validated_types::Validated(payload): validated_types::Validated<AddMemberRequest>,
) -> Result<Json<OrganizationMember>, AddMemberError> {
    use AddMemberErrorCtx as Ctx;

    let role = check_org_access(&state.db, auth.user_id, org_id)
        .await
        .with_context(Ctx::access_query())?;

    if !can_manage_org(&role) {
        return Err(AddMemberError::NotManager {
            location: std::panic::Location::caller(),
        });
    }

    if user_has_organization(&state.db, payload.user_id)
        .await
        .with_context(Ctx::has_org_check())?
    {
        return Err(AddMemberError::AlreadyMember {
            location: std::panic::Location::caller(),
        });
    }

    let member = sqlx::query_as::<_, OrganizationMember>(
        "INSERT INTO organization_members (organization_id, user_id, role, invited_by)
         VALUES ($1, $2, $3::user_role, $4)
         RETURNING id,
                   organization_id,
                   user_id,
                   NULL::text as username,
                   NULL::text as email,
                   role::text as role,
                   accepted_at as joined_at,
                   created_at,
                   updated_at",
    )
    .bind(org_id)
    .bind(payload.user_id)
    .bind(&payload.role)
    .bind(auth.user_id)
    .fetch_one(&state.db)
    .await
    .with_context(Ctx::insert())?;

    Ok(Json(member))
}

/// Failure modes for [`update_member`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum UpdateMemberError {
    #[error("failed to check organization access [{location}]")]
    AccessQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("you do not have permission to manage this organization [{location}]")]
    NotManager { location: Location },

    #[error("failed to update organization member [{location}]")]
    Update {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for UpdateMemberError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            UpdateMemberError::AccessQuery { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            UpdateMemberError::NotManager { .. } => (StatusCode::FORBIDDEN, "forbidden"),
            UpdateMemberError::Update { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(org_id = %org_id))]
pub async fn update_member(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((org_id, member_user_id)): Path<(Uuid, Uuid)>,
    validated_types::Validated(payload): validated_types::Validated<UpdateMemberRequest>,
) -> Result<Json<OrganizationMember>, UpdateMemberError> {
    use UpdateMemberErrorCtx as Ctx;

    let role = check_org_access(&state.db, auth.user_id, org_id)
        .await
        .with_context(Ctx::access_query())?;

    if !can_manage_org(&role) {
        return Err(UpdateMemberError::NotManager {
            location: std::panic::Location::caller(),
        });
    }

    let member = sqlx::query_as::<_, OrganizationMember>(
        "UPDATE organization_members
         SET role = $1::user_role
         WHERE organization_id = $2 AND user_id = $3
         RETURNING id,
                   organization_id,
                   user_id,
                   NULL::text as username,
                   NULL::text as email,
                   role::text as role,
                   accepted_at as joined_at,
                   created_at,
                   updated_at",
    )
    .bind(&payload.role)
    .bind(org_id)
    .bind(member_user_id)
    .fetch_one(&state.db)
    .await
    .with_context(Ctx::update())?;

    Ok(Json(member))
}

/// Failure modes for [`remove_member`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum RemoveMemberError {
    #[error("failed to check organization access [{location}]")]
    AccessQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("you do not have permission to manage this organization [{location}]")]
    NotManager { location: Location },

    #[error("failed to remove organization member [{location}]")]
    Delete {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for RemoveMemberError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            RemoveMemberError::AccessQuery { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            RemoveMemberError::NotManager { .. } => (StatusCode::FORBIDDEN, "forbidden"),
            RemoveMemberError::Delete { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(org_id = %org_id))]
pub async fn remove_member(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((org_id, member_user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, RemoveMemberError> {
    use RemoveMemberErrorCtx as Ctx;

    let role = check_org_access(&state.db, auth.user_id, org_id)
        .await
        .with_context(Ctx::access_query())?;

    if !can_manage_org(&role) {
        return Err(RemoveMemberError::NotManager {
            location: std::panic::Location::caller(),
        });
    }

    sqlx::query(
        "DELETE FROM organization_members
         WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(org_id)
    .bind(member_user_id)
    .execute(&state.db)
    .await
    .with_context(Ctx::delete())?;

    Ok(StatusCode::NO_CONTENT)
}
