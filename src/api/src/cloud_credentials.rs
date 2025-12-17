// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::encryption::Encryptor;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "cloud_provider", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum CloudPlatform {
    Aws,
}

impl std::fmt::Display for CloudPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CloudPlatform::Aws => write!(f, "aws"),
        }
    }
}

#[derive(Debug, Serialize, FromRow)]
pub struct CloudCredential {
    pub id: i64,
    pub organization_id: Uuid,
    pub platform: CloudPlatform,
    pub name: String,
    pub identifier: String,
    pub config: serde_json::Value,
    pub is_default: bool,
    pub is_active: bool,
    pub last_validated_at: Option<chrono::NaiveDateTime>,
    pub validation_error: Option<String>,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

#[derive(Debug, Deserialize)]
pub struct CreateAwsCredential {
    pub name: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub is_default: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "platform", rename_all = "lowercase")]
pub enum CreateCredentialRequest {
    Aws(CreateAwsCredential),
}

impl CreateCredentialRequest {
    pub fn name(&self) -> &str {
        match self {
            Self::Aws(c) => &c.name,
        }
    }

    pub fn platform(&self) -> CloudPlatform {
        match self {
            Self::Aws(_) => CloudPlatform::Aws,
        }
    }

    pub fn identifier(&self) -> String {
        match self {
            Self::Aws(c) => c.access_key_id.clone(),
        }
    }

    pub fn secrets(&self) -> serde_json::Value {
        match self {
            Self::Aws(c) => serde_json::json!({
                "secret_access_key": c.secret_access_key
            }),
        }
    }

    pub fn config(&self) -> serde_json::Value {
        match self {
            Self::Aws(_) => serde_json::json!({}),
        }
    }

    pub fn is_default(&self) -> bool {
        match self {
            Self::Aws(c) => c.is_default.unwrap_or(false),
        }
    }
}

pub async fn create_credential(
    pool: &PgPool,
    encryptor: &Encryptor,
    org_id: Uuid,
    user_id: i64,
    req: CreateCredentialRequest,
) -> Result<CloudCredential, (StatusCode, String)> {
    let secrets_encrypted = encryptor
        .encrypt_json(&req.secrets())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Encryption failed: {}", e)))?;

    if req.is_default() {
        sqlx::query(
            "UPDATE cloud_credentials SET is_default = false
             WHERE organization_id = $1 AND platform = $2 AND is_default = true"
        )
        .bind(org_id)
        .bind(req.platform())
        .execute(pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    let row = sqlx::query_as::<_, CloudCredential>(
        "INSERT INTO cloud_credentials
         (organization_id, platform, name, identifier, secrets_encrypted, config, is_default, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING id, organization_id, platform, name, identifier,
                   config, is_default, is_active, last_validated_at, validation_error,
                   created_at, updated_at"
    )
    .bind(org_id)
    .bind(req.platform())
    .bind(req.name())
    .bind(req.identifier())
    .bind(&secrets_encrypted)
    .bind(req.config())
    .bind(req.is_default())
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        if e.to_string().contains("cloud_credentials_unique_name") {
            (StatusCode::CONFLICT, format!("Credential with name '{}' already exists", req.name()))
        } else {
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        }
    })?;

    Ok(row)
}

pub async fn list_credentials(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<CloudCredential>, (StatusCode, String)> {
    let rows = sqlx::query_as::<_, CloudCredential>(
        "SELECT id, organization_id, platform, name, identifier,
                config, is_default, is_active, last_validated_at, validation_error,
                created_at, updated_at
         FROM cloud_credentials
         WHERE organization_id = $1
         ORDER BY platform, name"
    )
    .bind(org_id)
    .fetch_all(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(rows)
}

pub async fn get_credential(
    pool: &PgPool,
    org_id: Uuid,
    credential_id: i64,
) -> Result<Option<CloudCredential>, (StatusCode, String)> {
    let row = sqlx::query_as::<_, CloudCredential>(
        "SELECT id, organization_id, platform, name, identifier,
                config, is_default, is_active, last_validated_at, validation_error,
                created_at, updated_at
         FROM cloud_credentials
         WHERE organization_id = $1 AND id = $2"
    )
    .bind(org_id)
    .bind(credential_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(row)
}

pub async fn get_credential_secrets(
    pool: &PgPool,
    encryptor: &Encryptor,
    org_id: Uuid,
    credential_id: i64,
) -> Result<Option<serde_json::Value>, (StatusCode, String)> {
    let row: Option<(Vec<u8>,)> = sqlx::query_as(
        "SELECT secrets_encrypted FROM cloud_credentials
         WHERE organization_id = $1 AND id = $2"
    )
    .bind(org_id)
    .bind(credential_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match row {
        Some((secrets_encrypted,)) => {
            let secrets: serde_json::Value = encryptor
                .decrypt_json(&secrets_encrypted)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Decryption failed: {}", e)))?;
            Ok(Some(secrets))
        }
        None => Ok(None),
    }
}

pub async fn delete_credential(
    pool: &PgPool,
    org_id: Uuid,
    credential_id: i64,
) -> Result<bool, (StatusCode, String)> {
    let result = sqlx::query(
        "DELETE FROM cloud_credentials WHERE organization_id = $1 AND id = $2"
    )
    .bind(org_id)
    .bind(credential_id)
    .execute(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(result.rows_affected() > 0)
}

pub async fn set_default_credential(
    pool: &PgPool,
    org_id: Uuid,
    credential_id: i64,
) -> Result<bool, (StatusCode, String)> {
    let cred = get_credential(pool, org_id, credential_id).await?;
    let cred = match cred {
        Some(c) => c,
        None => return Ok(false),
    };

    sqlx::query(
        "UPDATE cloud_credentials SET is_default = false
         WHERE organization_id = $1 AND platform = $2 AND is_default = true"
    )
    .bind(org_id)
    .bind(cred.platform)
    .execute(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let result = sqlx::query(
        "UPDATE cloud_credentials SET is_default = true
         WHERE organization_id = $1 AND id = $2"
    )
    .bind(org_id)
    .bind(credential_id)
    .execute(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(result.rows_affected() > 0)
}

pub async fn get_default_credential_for_platform(
    pool: &PgPool,
    org_id: Uuid,
    platform: CloudPlatform,
) -> Result<Option<CloudCredential>, (StatusCode, String)> {
    let row = sqlx::query_as::<_, CloudCredential>(
        "SELECT id, organization_id, platform, name, identifier,
                config, is_default, is_active, last_validated_at, validation_error,
                created_at, updated_at
         FROM cloud_credentials
         WHERE organization_id = $1 AND platform = $2 AND is_default = true AND is_active = true"
    )
    .bind(org_id)
    .bind(platform)
    .fetch_optional(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(row)
}
