// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use rand::{rngs::OsRng, RngCore};
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
use crate::{can_manage_org, check_org_access, is_owner, AppState, AuthContext};

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

#[derive(Debug, thiserror::Error)]
pub enum InvitationError {
    #[error("organization invitation not found")]
    NotFound,
    #[error("you do not have permission to manage this organization")]
    Forbidden,
    #[error("a user with this email is already a member of this organization")]
    AlreadyMember,
    #[error("an active invitation already exists for this email")]
    AlreadyInvited,
    #[error("a platform user with this email already exists")]
    UserAlreadyExists,
    #[error("failed to create invitation")]
    Database,
}

impl IntoResponse for InvitationError {
    fn into_response(self) -> Response {
        #[derive(Serialize)]
        struct ErrorBody {
            error: String,
        }

        let status = match self {
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::AlreadyMember | Self::AlreadyInvited | Self::UserAlreadyExists => {
                StatusCode::CONFLICT
            }
            Self::Database => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (
            status,
            Json(ErrorBody {
                error: self.to_string(),
            }),
        )
            .into_response()
    }
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
    if let Some(user_id) = trimmed.strip_prefix(LEGACY_DEFAULT_ORG_PREFIX) {
        if Uuid::parse_str(user_id).is_ok() {
            return "your organization".to_string();
        }
    }
    trimmed.to_string()
}

async fn user_has_organization(db: &PgPool, user_id: Uuid) -> Result<bool, StatusCode> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM organization_members WHERE user_id = $1)")
        .bind(user_id)
        .fetch_one(db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to check user organization membership: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

pub async fn list_organizations(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<Organization>>, StatusCode> {
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
    .map_err(|e| {
        tracing::error!("list_organizations failed: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::debug!("list_organizations returning {} orgs", orgs.len());
    Ok(Json(orgs))
}

pub async fn create_organization(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    validated_types::Validated(payload): validated_types::Validated<CreateOrganizationRequest>,
) -> Result<Json<Organization>, StatusCode> {
    if user_has_organization(&state.db, auth.user_id).await? {
        return Err(StatusCode::CONFLICT);
    }

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let org = sqlx::query_as::<_, Organization>(
        "INSERT INTO organizations (name)
         VALUES ($1)
         RETURNING id, name, is_active, created_at, updated_at",
    )
    .bind(&payload.name)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

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
            return StatusCode::CONFLICT;
        }
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tx.commit()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(org))
}

pub async fn get_organization(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
) -> Result<Json<Organization>, StatusCode> {
    check_org_access(&state.db, auth.user_id, org_id).await?;

    let org = sqlx::query_as::<_, Organization>(
        "SELECT id, name, is_active, created_at, updated_at
         FROM organizations WHERE id = $1",
    )
    .bind(org_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(Json(org))
}

pub async fn update_organization(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
    validated_types::Validated(payload): validated_types::Validated<UpdateOrganizationRequest>,
) -> Result<Json<Organization>, StatusCode> {
    let role = check_org_access(&state.db, auth.user_id, org_id).await?;

    if !can_manage_org(&role) {
        return Err(StatusCode::FORBIDDEN);
    }

    if payload.name.is_none() {
        return Err(StatusCode::BAD_REQUEST);
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
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(org))
}

pub async fn delete_organization(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let role = check_org_access(&state.db, auth.user_id, org_id).await?;

    if !is_owner(&role) {
        return Err(StatusCode::FORBIDDEN);
    }

    sqlx::query("UPDATE organizations SET is_active = false WHERE id = $1")
        .bind(org_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}

#[tracing::instrument(skip(state, auth))]
pub async fn get_org_settings(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
) -> Result<Json<OrgSettings>, StatusCode> {
    tracing::debug!("get_org_settings called for org {}", org_id);
    check_org_access(&state.db, auth.user_id, org_id).await?;

    let settings: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT settings FROM organizations WHERE id = $1")
            .bind(org_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("get_org_settings failed: {:?}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .flatten();

    let org_settings = settings
        .and_then(|s| serde_json::from_value(s).ok())
        .unwrap_or(OrgSettings { require_pin: false });

    tracing::debug!("get_org_settings returning: {:?}", org_settings);
    Ok(Json(org_settings))
}

#[tracing::instrument(skip(state, auth, payload))]
pub async fn update_org_settings(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
    validated_types::Validated(payload): validated_types::Validated<UpdateOrgSettingsRequest>,
) -> Result<Json<OrgSettings>, StatusCode> {
    let role = check_org_access(&state.db, auth.user_id, org_id).await?;

    if !can_manage_org(&role) {
        return Err(StatusCode::FORBIDDEN);
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
    .map_err(|e| {
        tracing::error!("Failed to update org settings: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let org_settings: OrgSettings =
        serde_json::from_value(updated_settings.clone()).map_err(|e| {
            tracing::error!(
                "Failed to parse updated org settings: {:?}, raw value: {:?}",
                e,
                updated_settings
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(org_settings))
}

pub async fn list_members(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
) -> Result<Json<Vec<OrganizationMember>>, StatusCode> {
    check_org_access(&state.db, auth.user_id, org_id).await?;

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
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(members))
}

pub async fn invite_member(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
    validated_types::Validated(payload): validated_types::Validated<InviteMemberRequest>,
) -> Result<Json<InviteMemberResponse>, InvitationError> {
    let role = check_org_access(&state.db, auth.user_id, org_id)
        .await
        .map_err(|status| match status {
            StatusCode::FORBIDDEN => InvitationError::Forbidden,
            _ => InvitationError::Database,
        })?;

    if !can_manage_org(&role) {
        return Err(InvitationError::Forbidden);
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
    .map_err(|e| {
        tracing::error!("Failed to check existing member email: {:?}", e);
        InvitationError::Database
    })?;

    if already_member {
        return Err(InvitationError::AlreadyMember);
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
    .map_err(|e| {
        tracing::error!("Failed to check existing invitation email: {:?}", e);
        InvitationError::Database
    })?;

    if already_invited {
        return Err(InvitationError::AlreadyInvited);
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
    .map_err(|e| {
        tracing::error!("Failed to revoke expired invitation email: {:?}", e);
        InvitationError::Database
    })?;

    let existing_user: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE lower(email) = $1)")
            .bind(&email)
            .fetch_one(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("Failed to check existing user email: {:?}", e);
                InvitationError::Database
            })?;

    if existing_user {
        return Err(InvitationError::UserAlreadyExists);
    }

    let org_name: String = sqlx::query_scalar("SELECT name FROM organizations WHERE id = $1")
        .bind(org_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to load organization for invitation: {:?}", e);
            InvitationError::Database
        })?
        .ok_or(InvitationError::NotFound)?;

    let inviter_email: Option<String> = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(auth.user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to load inviter email: {:?}", e);
            InvitationError::Database
        })?
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
            return InvitationError::AlreadyInvited;
        }
        tracing::error!("Failed to create organization invitation: {:?}", e);
        InvitationError::Database
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

pub async fn list_active_invitations(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
) -> Result<Json<Vec<OrganizationInvitation>>, InvitationError> {
    let role = check_org_access(&state.db, auth.user_id, org_id)
        .await
        .map_err(|status| match status {
            StatusCode::FORBIDDEN => InvitationError::Forbidden,
            _ => InvitationError::Database,
        })?;

    if !can_manage_org(&role) {
        return Err(InvitationError::Forbidden);
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
    .map_err(|e| {
        tracing::error!("Failed to list organization invitations: {:?}", e);
        InvitationError::Database
    })?;

    Ok(Json(invitations))
}

pub async fn cancel_invitation(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((org_id, invitation_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, InvitationError> {
    let role = check_org_access(&state.db, auth.user_id, org_id)
        .await
        .map_err(|status| match status {
            StatusCode::FORBIDDEN => InvitationError::Forbidden,
            _ => InvitationError::Database,
        })?;

    if !can_manage_org(&role) {
        return Err(InvitationError::Forbidden);
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
    .map_err(|e| {
        tracing::error!("Failed to cancel organization invitation: {:?}", e);
        InvitationError::Database
    })?;

    if result.rows_affected() == 0 {
        return Err(InvitationError::NotFound);
    }

    Ok(StatusCode::NO_CONTENT)
}

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

pub async fn add_member(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
    validated_types::Validated(payload): validated_types::Validated<AddMemberRequest>,
) -> Result<Json<OrganizationMember>, StatusCode> {
    let role = check_org_access(&state.db, auth.user_id, org_id).await?;

    if !can_manage_org(&role) {
        return Err(StatusCode::FORBIDDEN);
    }

    if user_has_organization(&state.db, payload.user_id).await? {
        return Err(StatusCode::CONFLICT);
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
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(member))
}

pub async fn update_member(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((org_id, member_user_id)): Path<(Uuid, Uuid)>,
    validated_types::Validated(payload): validated_types::Validated<UpdateMemberRequest>,
) -> Result<Json<OrganizationMember>, StatusCode> {
    let role = check_org_access(&state.db, auth.user_id, org_id).await?;

    if !can_manage_org(&role) {
        return Err(StatusCode::FORBIDDEN);
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
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(member))
}

pub async fn remove_member(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path((org_id, member_user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, StatusCode> {
    let role = check_org_access(&state.db, auth.user_id, org_id).await?;

    if !can_manage_org(&role) {
        return Err(StatusCode::FORBIDDEN);
    }

    sqlx::query(
        "DELETE FROM organization_members
         WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(org_id)
    .bind(member_user_id)
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}
