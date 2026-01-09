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
    pub id: Uuid,
    pub organization_id: Uuid,
    pub resource_id: Option<Uuid>,
    pub platform: CloudPlatform,
    pub managed_on_prem: bool,
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
pub struct CreateCredentialRequest {
    pub platform: CloudPlatform,
    pub resource_id: Option<Uuid>,
    #[serde(default)]
    pub managed_on_prem: bool,
    #[serde(default)]
    pub is_default: bool,

    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,

    pub deployment_id: Option<String>,
    pub asg_name: Option<String>,
    pub launch_template_name: Option<String>,
    pub launch_template_id: Option<String>,
    pub vpc_id: Option<String>,
    pub subnet_ids: Option<Vec<String>>,
    pub eif_bucket: Option<String>,
    pub instance_profile_name: Option<String>,
    pub iam_user: Option<String>,
    pub aws_access_key_id: Option<String>,
    pub aws_secret_access_key: Option<String>,
    pub aws_region: Option<String>,
    pub aws_account_id: Option<String>,
    pub scope_tag: Option<String>,
}

impl CreateCredentialRequest {
    pub fn validate(&self) -> Result<(), String> {
        match self.platform {
            CloudPlatform::Aws => {
                if self.managed_on_prem {
                    let required = [
                        ("deployment_id", self.deployment_id.as_ref()),
                        ("asg_name", self.asg_name.as_ref()),
                        ("launch_template_name", self.launch_template_name.as_ref()),
                        ("launch_template_id", self.launch_template_id.as_ref()),
                        ("vpc_id", self.vpc_id.as_ref()),
                        ("eif_bucket", self.eif_bucket.as_ref()),
                        ("instance_profile_name", self.instance_profile_name.as_ref()),
                        ("iam_user", self.iam_user.as_ref()),
                        ("aws_access_key_id", self.aws_access_key_id.as_ref()),
                        ("aws_secret_access_key", self.aws_secret_access_key.as_ref()),
                        ("aws_region", self.aws_region.as_ref()),
                        ("aws_account_id", self.aws_account_id.as_ref()),
                        ("scope_tag", self.scope_tag.as_ref()),
                    ];
                    for (field, value) in required {
                        if value.is_none() || value.map(|s| s.is_empty()).unwrap_or(true) {
                            return Err(format!("Missing required field for managed on-prem: {}", field));
                        }
                    }
                    if self.subnet_ids.as_ref().map(|v| v.is_empty()).unwrap_or(true) {
                        return Err("Missing required field for managed on-prem: subnet_ids".to_string());
                    }
                } else {
                    if self.access_key_id.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                        return Err("Missing required field: access_key_id".to_string());
                    }
                    if self.secret_access_key.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                        return Err("Missing required field: secret_access_key".to_string());
                    }
                }
                Ok(())
            }
        }
    }

    pub fn identifier(&self) -> String {
        if self.managed_on_prem {
            self.deployment_id.clone().unwrap_or_default()
        } else {
            self.access_key_id.clone().unwrap_or_default()
        }
    }

    pub fn secrets(&self) -> serde_json::Value {
        if self.managed_on_prem {
            serde_json::json!({
                "aws_access_key_id": self.aws_access_key_id,
                "aws_secret_access_key": self.aws_secret_access_key
            })
        } else {
            serde_json::json!({
                "secret_access_key": self.secret_access_key
            })
        }
    }

    pub fn config(&self) -> serde_json::Value {
        if self.managed_on_prem {
            serde_json::json!({
                "deployment_id": self.deployment_id,
                "asg_name": self.asg_name,
                "launch_template_name": self.launch_template_name,
                "launch_template_id": self.launch_template_id,
                "vpc_id": self.vpc_id,
                "subnet_ids": self.subnet_ids,
                "eif_bucket": self.eif_bucket,
                "instance_profile_name": self.instance_profile_name,
                "iam_user": self.iam_user,
                "aws_region": self.aws_region,
                "aws_account_id": self.aws_account_id,
                "scope_tag": self.scope_tag
            })
        } else {
            serde_json::json!({})
        }
    }
}

pub async fn create_credential(
    pool: &PgPool,
    encryptor: &Encryptor,
    org_id: Uuid,
    user_id: Uuid,
    req: CreateCredentialRequest,
) -> Result<CloudCredential, (StatusCode, String)> {
    req.validate().map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let secrets_encrypted = encryptor
        .encrypt_json(&req.secrets())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Encryption failed: {}", e)))?;

    if req.is_default {
        sqlx::query(
            "UPDATE cloud_credentials SET is_default = false
             WHERE organization_id = $1 AND platform = $2 AND is_default = true"
        )
        .bind(org_id)
        .bind(req.platform)
        .execute(pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    let existing_cred = if let Some(resource_id) = req.resource_id {
        get_credential_by_resource(pool, org_id, resource_id).await?
    } else if req.managed_on_prem {
        get_credential_by_identifier(pool, org_id, &req.identifier()).await?
    } else {
        None
    };

    if let Some(existing_cred) = existing_cred {
        let row = sqlx::query_as::<_, CloudCredential>(
            "UPDATE cloud_credentials
             SET platform = $1, managed_on_prem = $2, identifier = $3,
                 secrets_encrypted = $4, config = $5, is_default = $6,
                 resource_id = COALESCE($7, resource_id), updated_at = NOW()
             WHERE id = $8 AND organization_id = $9
             RETURNING id, organization_id, resource_id, platform, managed_on_prem, identifier,
                       config, is_default, is_active, last_validated_at, validation_error,
                       created_at, updated_at"
        )
        .bind(req.platform)
        .bind(req.managed_on_prem)
        .bind(req.identifier())
        .bind(&secrets_encrypted)
        .bind(req.config())
        .bind(req.is_default)
        .bind(req.resource_id)
        .bind(existing_cred.id)
        .bind(org_id)
        .fetch_one(pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        return Ok(row);
    }

    let row = sqlx::query_as::<_, CloudCredential>(
        "INSERT INTO cloud_credentials
         (organization_id, resource_id, platform, managed_on_prem, identifier, secrets_encrypted, config, is_default, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING id, organization_id, resource_id, platform, managed_on_prem, identifier,
                   config, is_default, is_active, last_validated_at, validation_error,
                   created_at, updated_at"
    )
    .bind(org_id)
    .bind(req.resource_id)
    .bind(req.platform)
    .bind(req.managed_on_prem)
    .bind(req.identifier())
    .bind(&secrets_encrypted)
    .bind(req.config())
    .bind(req.is_default)
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(row)
}

pub async fn list_credentials(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<CloudCredential>, (StatusCode, String)> {
    let rows = sqlx::query_as::<_, CloudCredential>(
        "SELECT id, organization_id, resource_id, platform, managed_on_prem, identifier,
                config, is_default, is_active, last_validated_at, validation_error,
                created_at, updated_at
         FROM cloud_credentials
         WHERE organization_id = $1
         ORDER BY platform, created_at"
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
    credential_id: Uuid,
) -> Result<Option<CloudCredential>, (StatusCode, String)> {
    let row = sqlx::query_as::<_, CloudCredential>(
        "SELECT id, organization_id, resource_id, platform, managed_on_prem, identifier,
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
    credential_id: Uuid,
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
    credential_id: Uuid,
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
    credential_id: Uuid,
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
        "SELECT id, organization_id, resource_id, platform, managed_on_prem, identifier,
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

#[derive(Debug, Clone, Serialize)]
pub struct ManagedOnPremCredentialData {
    pub deployment_id: String,
    pub asg_name: String,
    pub launch_template_name: String,
    pub launch_template_id: String,
    pub vpc_id: String,
    pub subnet_ids: Vec<String>,
    pub eif_bucket: String,
    pub instance_profile_name: String,
    pub aws_access_key_id: String,
    pub aws_secret_access_key: String,
    pub aws_region: String,
}

pub async fn get_managed_onprem_credential(
    pool: &PgPool,
    encryptor: &Encryptor,
    org_id: Uuid,
    credential_id: Uuid,
) -> Result<Option<ManagedOnPremCredentialData>, (StatusCode, String)> {
    let cred = get_credential(pool, org_id, credential_id).await?;
    let cred = match cred {
        Some(c) => c,
        None => return Ok(None),
    };

    if !cred.managed_on_prem {
        return Err((StatusCode::BAD_REQUEST, "Credential is not a managed on-prem type".to_string()));
    }

    let secrets = get_credential_secrets(pool, encryptor, org_id, credential_id).await?
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Failed to get secrets".to_string()))?;

    let data = ManagedOnPremCredentialData {
        deployment_id: cred.config["deployment_id"].as_str().unwrap_or("").to_string(),
        asg_name: cred.config["asg_name"].as_str().unwrap_or("").to_string(),
        launch_template_name: cred.config["launch_template_name"].as_str().unwrap_or("").to_string(),
        launch_template_id: cred.config["launch_template_id"].as_str().unwrap_or("").to_string(),
        vpc_id: cred.config["vpc_id"].as_str().unwrap_or("").to_string(),
        subnet_ids: cred.config["subnet_ids"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default(),
        eif_bucket: cred.config["eif_bucket"].as_str().unwrap_or("").to_string(),
        instance_profile_name: cred.config["instance_profile_name"].as_str().unwrap_or("").to_string(),
        aws_access_key_id: secrets["aws_access_key_id"].as_str().unwrap_or("").to_string(),
        aws_secret_access_key: secrets["aws_secret_access_key"].as_str().unwrap_or("").to_string(),
        aws_region: cred.config["aws_region"].as_str().unwrap_or("").to_string(),
    };

    Ok(Some(data))
}

pub async fn list_managed_onprem_credentials(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<CloudCredential>, (StatusCode, String)> {
    let rows = sqlx::query_as::<_, CloudCredential>(
        "SELECT id, organization_id, resource_id, platform, managed_on_prem, identifier,
                config, is_default, is_active, last_validated_at, validation_error,
                created_at, updated_at
         FROM cloud_credentials
         WHERE organization_id = $1 AND managed_on_prem = true
         ORDER BY created_at"
    )
    .bind(org_id)
    .fetch_all(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(rows)
}

pub async fn get_credential_by_resource(
    pool: &PgPool,
    org_id: Uuid,
    resource_id: Uuid,
) -> Result<Option<CloudCredential>, (StatusCode, String)> {
    let row = sqlx::query_as::<_, CloudCredential>(
        "SELECT id, organization_id, resource_id, platform, managed_on_prem, identifier,
                config, is_default, is_active, last_validated_at, validation_error,
                created_at, updated_at
         FROM cloud_credentials
         WHERE organization_id = $1 AND resource_id = $2"
    )
    .bind(org_id)
    .bind(resource_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(row)
}

pub async fn get_credential_by_identifier(
    pool: &PgPool,
    org_id: Uuid,
    identifier: &str,
) -> Result<Option<CloudCredential>, (StatusCode, String)> {
    let row = sqlx::query_as::<_, CloudCredential>(
        "SELECT id, organization_id, resource_id, platform, managed_on_prem, identifier,
                config, is_default, is_active, last_validated_at, validation_error,
                created_at, updated_at
         FROM cloud_credentials
         WHERE organization_id = $1 AND identifier = $2"
    )
    .bind(org_id)
    .bind(identifier)
    .fetch_optional(pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(row)
}
