// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use dterror::{BoxError, CtxError, Location, ResultExt};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

mod holders;

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
    #[sqlx(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holders: Option<Vec<holders::HolderMetadata>>,
    #[sqlx(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_hash: Option<String>,
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
    #[serde(default)]
    pub allow_legacy: bool,
    pub data: serde_json::Value,
    pub name: Option<String>,
    pub labels: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateBundleRequest {
    #[serde(default)]
    pub allow_legacy: bool,
    pub data: Option<serde_json::Value>,
    pub name: Option<String>,
    pub labels: Option<serde_json::Value>,
}

// Derived display metadata only: computing this hash does not verify the proof.
fn canonical_hash(data: &serde_json::Value) -> Option<String> {
    use keymaker_models::generate_quorum::{GenerateQuorumResponse, deterministic_bundle_hash};
    if data.get("format").is_some() {
        let bundle: locksmith::legacy::ImportedV0 = serde_json::from_value(data.clone()).ok()?;
        return bundle.content_hash().ok();
    }
    let response: GenerateQuorumResponse = serde_json::from_value(data.clone()).ok()?;
    deterministic_bundle_hash(&response.data).ok().map(hex::encode)
}

// -- Quorum Bundles --

/// Failure modes for [`list_quorum_bundles`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum ListQuorumBundlesError {
    #[error("failed to list quorum bundles for organization {org_id} [{location}]")]
    Database {
        org_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err, fields(org_id = %org_id))]
pub async fn list_quorum_bundles(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<QuorumBundle>, ListQuorumBundlesError> {
    use ListQuorumBundlesErrorCtx as Ctx;

    let mut rows = sqlx::query_as::<_, QuorumBundle>(
        "SELECT id, organization_id, data, name, labels, created_by, created_at, updated_at
         FROM quorum_bundles
         WHERE organization_id = $1
         ORDER BY created_at",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await
    .with_context(Ctx::database(org_id))?;

    for bundle in &mut rows { bundle.bundle_hash = canonical_hash(&bundle.data); }
    holders::enrich(pool, org_id, &mut rows).await;
    Ok(rows)
}

/// Failure modes for [`get_quorum_bundle`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum GetQuorumBundleError {
    #[error("failed to get quorum bundle {bundle_id} for organization {org_id} [{location}]")]
    Database {
        org_id: Uuid,
        bundle_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err, fields(org_id = %org_id, bundle_id = %bundle_id))]
pub async fn get_quorum_bundle(
    pool: &PgPool,
    org_id: Uuid,
    bundle_id: Uuid,
) -> Result<Option<QuorumBundle>, GetQuorumBundleError> {
    use GetQuorumBundleErrorCtx as Ctx;

    let mut row = sqlx::query_as::<_, QuorumBundle>(
        "SELECT id, organization_id, data, name, labels, created_by, created_at, updated_at
         FROM quorum_bundles
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(org_id)
    .bind(bundle_id)
    .fetch_optional(pool)
    .await
    .with_context(Ctx::database(org_id, bundle_id))?;

    if let Some(bundle) = &mut row {
        bundle.bundle_hash = canonical_hash(&bundle.data);
        holders::enrich(pool, org_id, std::slice::from_mut(bundle)).await;
    }
    Ok(row)
}

/// Failure modes for [`create_quorum_bundle`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum CreateQuorumBundleError {
    #[error("failed to create quorum bundle for organization {org_id} [{location}]")]
    Database {
        org_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err, fields(org_id = %org_id))]
pub async fn create_quorum_bundle(
    pool: &PgPool,
    org_id: Uuid,
    user_id: Uuid,
    req: CreateBundleRequest,
) -> Result<QuorumBundle, CreateQuorumBundleError> {
    use CreateQuorumBundleErrorCtx as Ctx;

    let labels = req.labels.unwrap_or(serde_json::json!({}));
    let row = sqlx::query_as::<_, QuorumBundle>(
        "INSERT INTO quorum_bundles (organization_id, data, name, labels, created_by)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, organization_id, data, name, labels, created_by, created_at, updated_at",
    )
    .bind(org_id)
    .bind(&req.data)
    .bind(&req.name)
    .bind(&labels)
    .bind(user_id)
    .fetch_one(pool)
    .await
    .with_context(Ctx::database(org_id))?;

    Ok(row)
}

/// Failure modes for [`update_quorum_bundle`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum UpdateQuorumBundleError {
    #[error("failed to update quorum bundle {bundle_id} for organization {org_id} [{location}]")]
    Database {
        org_id: Uuid,
        bundle_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err, fields(org_id = %org_id, bundle_id = %bundle_id))]
pub async fn update_quorum_bundle(
    pool: &PgPool,
    org_id: Uuid,
    bundle_id: Uuid,
    req: UpdateBundleRequest,
) -> Result<Option<QuorumBundle>, UpdateQuorumBundleError> {
    use UpdateQuorumBundleErrorCtx as Ctx;

    let row = sqlx::query_as::<_, QuorumBundle>(
        "UPDATE quorum_bundles
         SET data = COALESCE($1, data),
             name = COALESCE($2, name),
             labels = COALESCE($3, labels),
             updated_at = NOW()
         WHERE organization_id = $4 AND id = $5
         RETURNING id, organization_id, data, name, labels, created_by, created_at, updated_at",
    )
    .bind(&req.data)
    .bind(&req.name)
    .bind(&req.labels)
    .bind(org_id)
    .bind(bundle_id)
    .fetch_optional(pool)
    .await
    .with_context(Ctx::database(org_id, bundle_id))?;

    Ok(row)
}

/// Failure modes for [`delete_quorum_bundle`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum DeleteQuorumBundleError {
    #[error("failed to delete quorum bundle {bundle_id} for organization {org_id} [{location}]")]
    Database {
        org_id: Uuid,
        bundle_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err, fields(org_id = %org_id, bundle_id = %bundle_id))]
pub async fn delete_quorum_bundle(
    pool: &PgPool,
    org_id: Uuid,
    bundle_id: Uuid,
) -> Result<bool, DeleteQuorumBundleError> {
    use DeleteQuorumBundleErrorCtx as Ctx;

    let result = sqlx::query("DELETE FROM quorum_bundles WHERE organization_id = $1 AND id = $2")
        .bind(org_id)
        .bind(bundle_id)
        .execute(pool)
        .await
        .with_context(Ctx::database(org_id, bundle_id))?;

    Ok(result.rows_affected() > 0)
}

// -- Secrets Bundles --

/// Failure modes for [`list_secrets_bundles`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum ListSecretsBundlesError {
    #[error("failed to list secrets bundles for organization {org_id} [{location}]")]
    Database {
        org_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err, fields(org_id = %org_id))]
pub async fn list_secrets_bundles(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<SecretsBundle>, ListSecretsBundlesError> {
    use ListSecretsBundlesErrorCtx as Ctx;

    let rows = sqlx::query_as::<_, SecretsBundle>(
        "SELECT id, organization_id, data, created_by, created_at, updated_at
         FROM secrets_bundles
         WHERE organization_id = $1
         ORDER BY created_at",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await
    .with_context(Ctx::database(org_id))?;

    Ok(rows)
}

/// Failure modes for [`get_secrets_bundle`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum GetSecretsBundleError {
    #[error("failed to get secrets bundle {bundle_id} for organization {org_id} [{location}]")]
    Database {
        org_id: Uuid,
        bundle_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err, fields(org_id = %org_id, bundle_id = %bundle_id))]
pub async fn get_secrets_bundle(
    pool: &PgPool,
    org_id: Uuid,
    bundle_id: Uuid,
) -> Result<Option<SecretsBundle>, GetSecretsBundleError> {
    use GetSecretsBundleErrorCtx as Ctx;

    let row = sqlx::query_as::<_, SecretsBundle>(
        "SELECT id, organization_id, data, created_by, created_at, updated_at
         FROM secrets_bundles
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(org_id)
    .bind(bundle_id)
    .fetch_optional(pool)
    .await
    .with_context(Ctx::database(org_id, bundle_id))?;

    Ok(row)
}

/// Failure modes for [`create_secrets_bundle`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum CreateSecretsBundleError {
    #[error("failed to create secrets bundle for organization {org_id} [{location}]")]
    Database {
        org_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err, fields(org_id = %org_id))]
pub async fn create_secrets_bundle(
    pool: &PgPool,
    org_id: Uuid,
    user_id: Uuid,
    req: CreateBundleRequest,
) -> Result<SecretsBundle, CreateSecretsBundleError> {
    use CreateSecretsBundleErrorCtx as Ctx;

    let row = sqlx::query_as::<_, SecretsBundle>(
        "INSERT INTO secrets_bundles (organization_id, data, created_by)
         VALUES ($1, $2, $3)
         RETURNING id, organization_id, data, created_by, created_at, updated_at",
    )
    .bind(org_id)
    .bind(&req.data)
    .bind(user_id)
    .fetch_one(pool)
    .await
    .with_context(Ctx::database(org_id))?;

    Ok(row)
}

/// Failure modes for [`update_secrets_bundle`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum UpdateSecretsBundleError {
    #[error("failed to update secrets bundle {bundle_id} for organization {org_id} [{location}]")]
    Database {
        org_id: Uuid,
        bundle_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err, fields(org_id = %org_id, bundle_id = %bundle_id))]
pub async fn update_secrets_bundle(
    pool: &PgPool,
    org_id: Uuid,
    bundle_id: Uuid,
    req: UpdateBundleRequest,
) -> Result<Option<SecretsBundle>, UpdateSecretsBundleError> {
    use UpdateSecretsBundleErrorCtx as Ctx;

    let row = sqlx::query_as::<_, SecretsBundle>(
        "UPDATE secrets_bundles SET data = COALESCE($1, data), updated_at = NOW()
         WHERE organization_id = $2 AND id = $3
         RETURNING id, organization_id, data, created_by, created_at, updated_at",
    )
    .bind(&req.data)
    .bind(org_id)
    .bind(bundle_id)
    .fetch_optional(pool)
    .await
    .with_context(Ctx::database(org_id, bundle_id))?;

    Ok(row)
}

/// Failure modes for [`delete_secrets_bundle`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum DeleteSecretsBundleError {
    #[error("failed to delete secrets bundle {bundle_id} for organization {org_id} [{location}]")]
    Database {
        org_id: Uuid,
        bundle_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err, fields(org_id = %org_id, bundle_id = %bundle_id))]
pub async fn delete_secrets_bundle(
    pool: &PgPool,
    org_id: Uuid,
    bundle_id: Uuid,
) -> Result<bool, DeleteSecretsBundleError> {
    use DeleteSecretsBundleErrorCtx as Ctx;

    let result = sqlx::query("DELETE FROM secrets_bundles WHERE organization_id = $1 AND id = $2")
        .bind(org_id)
        .bind(bundle_id)
        .execute(pool)
        .await
        .with_context(Ctx::database(org_id, bundle_id))?;

    Ok(result.rows_affected() > 0)
}

#[cfg(test)]
mod identity_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_hash_matches_shared_hash_and_ignores_json_order() {
        use keymaker_models::generate_quorum::{GenerateQuorumResponse, deterministic_bundle_hash};
        let data = json!({"data":{"version":"V1","bundle_id":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],"label":{"a":"1","b":"2"},"keyring":[],"threshold":1,"max":1,"shardfile":"shares","public_key":"key"},"necroproof":[]});
        let response: GenerateQuorumResponse = serde_json::from_value(data.clone()).unwrap();
        assert_eq!(canonical_hash(&data), Some(hex::encode(deterministic_bundle_hash(&response.data).unwrap())));
        let mut reordered = data.clone();
        reordered["data"]["label"] = serde_json::from_str(r#"{"b":"2","a":"1"}"#).unwrap();
        assert_eq!(canonical_hash(&data), canonical_hash(&reordered));
        reordered["data"]["public_key"] = json!("different");
        assert_ne!(canonical_hash(&data), canonical_hash(&reordered));
        assert_eq!(canonical_hash(&json!({})), None);
        assert_eq!(canonical_hash(&json!({"version":"V0"})), None);
    }
}
