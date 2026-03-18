// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(Debug, Serialize, FromRow)]
pub struct QuorumBundle {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub data: serde_json::Value,
    pub name: Option<String>,
    pub labels: serde_json::Value,
    pub created_by: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, FromRow)]
pub struct SecretsBundle {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub data: serde_json::Value,
    pub created_by: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateBundleRequest {
    pub data: serde_json::Value,
    pub name: Option<String>,
    pub labels: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateBundleRequest {
    pub data: Option<serde_json::Value>,
    pub name: Option<String>,
    pub labels: Option<serde_json::Value>,
}

// -- Quorum Bundles --

pub async fn list_quorum_bundles(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<QuorumBundle>, (StatusCode, String)> {
    let rows = sqlx::query_as::<_, QuorumBundle>(
        "SELECT id, organization_id, data, name, labels, created_by, created_at, updated_at
         FROM quorum_bundles
         WHERE organization_id = $1
         ORDER BY created_at"
    )
    .bind(org_id)
    .fetch_all(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(rows)
}

pub async fn get_quorum_bundle(
    pool: &PgPool,
    org_id: Uuid,
    bundle_id: Uuid,
) -> Result<Option<QuorumBundle>, (StatusCode, String)> {
    let row = sqlx::query_as::<_, QuorumBundle>(
        "SELECT id, organization_id, data, name, labels, created_by, created_at, updated_at
         FROM quorum_bundles
         WHERE organization_id = $1 AND id = $2"
    )
    .bind(org_id)
    .bind(bundle_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(row)
}

pub async fn create_quorum_bundle(
    pool: &PgPool,
    org_id: Uuid,
    user_id: Uuid,
    req: CreateBundleRequest,
) -> Result<QuorumBundle, (StatusCode, String)> {
    let labels = req.labels.unwrap_or(serde_json::json!({}));
    let row = sqlx::query_as::<_, QuorumBundle>(
        "INSERT INTO quorum_bundles (organization_id, data, name, labels, created_by)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, organization_id, data, name, labels, created_by, created_at, updated_at"
    )
    .bind(org_id)
    .bind(&req.data)
    .bind(&req.name)
    .bind(&labels)
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(row)
}

pub async fn update_quorum_bundle(
    pool: &PgPool,
    org_id: Uuid,
    bundle_id: Uuid,
    req: UpdateBundleRequest,
) -> Result<Option<QuorumBundle>, (StatusCode, String)> {
    let row = sqlx::query_as::<_, QuorumBundle>(
        "UPDATE quorum_bundles
         SET data = COALESCE($1, data),
             name = COALESCE($2, name),
             labels = COALESCE($3, labels),
             updated_at = NOW()
         WHERE organization_id = $4 AND id = $5
         RETURNING id, organization_id, data, name, labels, created_by, created_at, updated_at"
    )
    .bind(&req.data)
    .bind(&req.name)
    .bind(&req.labels)
    .bind(org_id)
    .bind(bundle_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(row)
}

pub async fn delete_quorum_bundle(
    pool: &PgPool,
    org_id: Uuid,
    bundle_id: Uuid,
) -> Result<bool, (StatusCode, String)> {
    let result = sqlx::query(
        "DELETE FROM quorum_bundles WHERE organization_id = $1 AND id = $2"
    )
    .bind(org_id)
    .bind(bundle_id)
    .execute(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(result.rows_affected() > 0)
}

// -- Secrets Bundles --

pub async fn list_secrets_bundles(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<SecretsBundle>, (StatusCode, String)> {
    let rows = sqlx::query_as::<_, SecretsBundle>(
        "SELECT id, organization_id, data, created_by, created_at, updated_at
         FROM secrets_bundles
         WHERE organization_id = $1
         ORDER BY created_at"
    )
    .bind(org_id)
    .fetch_all(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(rows)
}

pub async fn get_secrets_bundle(
    pool: &PgPool,
    org_id: Uuid,
    bundle_id: Uuid,
) -> Result<Option<SecretsBundle>, (StatusCode, String)> {
    let row = sqlx::query_as::<_, SecretsBundle>(
        "SELECT id, organization_id, data, created_by, created_at, updated_at
         FROM secrets_bundles
         WHERE organization_id = $1 AND id = $2"
    )
    .bind(org_id)
    .bind(bundle_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(row)
}

pub async fn create_secrets_bundle(
    pool: &PgPool,
    org_id: Uuid,
    user_id: Uuid,
    req: CreateBundleRequest,
) -> Result<SecretsBundle, (StatusCode, String)> {
    let row = sqlx::query_as::<_, SecretsBundle>(
        "INSERT INTO secrets_bundles (organization_id, data, created_by)
         VALUES ($1, $2, $3)
         RETURNING id, organization_id, data, created_by, created_at, updated_at"
    )
    .bind(org_id)
    .bind(&req.data)
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(row)
}

pub async fn update_secrets_bundle(
    pool: &PgPool,
    org_id: Uuid,
    bundle_id: Uuid,
    req: UpdateBundleRequest,
) -> Result<Option<SecretsBundle>, (StatusCode, String)> {
    let row = sqlx::query_as::<_, SecretsBundle>(
        "UPDATE secrets_bundles SET data = COALESCE($1, data), updated_at = NOW()
         WHERE organization_id = $2 AND id = $3
         RETURNING id, organization_id, data, created_by, created_at, updated_at"
    )
    .bind(&req.data)
    .bind(org_id)
    .bind(bundle_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(row)
}

pub async fn delete_secrets_bundle(
    pool: &PgPool,
    org_id: Uuid,
    bundle_id: Uuid,
) -> Result<bool, (StatusCode, String)> {
    let result = sqlx::query(
        "DELETE FROM secrets_bundles WHERE organization_id = $1 AND id = $2"
    )
    .bind(org_id)
    .bind(bundle_id)
    .execute(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(result.rows_affected() > 0)
}
