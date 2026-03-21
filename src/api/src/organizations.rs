// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::sync::Arc;
use uuid::Uuid;

use crate::{AppState, AuthContext, check_org_access, can_manage_org, is_owner};
use crate::validated_types;
use crate::validated_types::{CreateOrganizationRequest, UpdateOrganizationRequest, AddMemberRequest, UpdateMemberRequest, UpdateOrgSettingsRequest};
use crate::types;

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
    pub role: String,
    pub joined_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OrgSettings {
    pub require_pin: bool,
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
         WHERE om.user_id = $1"
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
    let org = sqlx::query_as::<_, Organization>(
        "INSERT INTO organizations (name)
         VALUES ($1)
         RETURNING id, name, is_active, created_at, updated_at"
    )
    .bind(&payload.name)
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    sqlx::query(
        "INSERT INTO organization_members (organization_id, user_id, role)
         VALUES ($1, $2, $3)"
    )
    .bind(org.id)
    .bind(auth.user_id)
    .bind(types::UserRole::Owner)
    .execute(&state.db)
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
         FROM organizations WHERE id = $1"
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

    let settings: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT settings FROM organizations WHERE id = $1"
    )
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
         RETURNING settings"
    )
    .bind(&settings)
    .bind(org_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to update org settings: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let org_settings: OrgSettings = serde_json::from_value(updated_settings.clone())
        .map_err(|e| {
            tracing::error!("Failed to parse updated org settings: {:?}, raw value: {:?}", e, updated_settings);
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
        "SELECT id, organization_id, user_id, role::text as role, joined_at, created_at, updated_at
         FROM organization_members
         WHERE organization_id = $1"
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(members))
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

    let member = sqlx::query_as::<_, OrganizationMember>(
        "INSERT INTO organization_members (organization_id, user_id, role, invited_by)
         VALUES ($1, $2, $3::user_role, $4)
         RETURNING id, organization_id, user_id, role::text as role, joined_at, created_at, updated_at"
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
         RETURNING id, organization_id, user_id, role::text as role, joined_at, created_at, updated_at"
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
         WHERE organization_id = $1 AND user_id = $2"
    )
    .bind(org_id)
    .bind(member_user_id)
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}
