// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use dterror::{BoxError, CtxError, Location, ResultExt};
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
    pub last_validated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub validation_error: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize)]
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
    pub builder_instance_profile_name: Option<String>,
    pub iam_user: Option<String>,
    pub aws_access_key_id: Option<String>,
    pub aws_secret_access_key: Option<String>,
    pub aws_region: Option<String>,
    pub aws_account_id: Option<String>,
    pub scope_tag: Option<String>,
}

impl std::fmt::Debug for CreateCredentialRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateCredentialRequest")
            .field("platform", &self.platform)
            .field("resource_id", &self.resource_id)
            .field("managed_on_prem", &self.managed_on_prem)
            .field("is_default", &self.is_default)
            .field("access_key_id", &"[REDACTED]")
            .field("secret_access_key", &"[REDACTED]")
            .field("deployment_id", &self.deployment_id)
            .field("asg_name", &self.asg_name)
            .field("launch_template_name", &self.launch_template_name)
            .field("launch_template_id", &self.launch_template_id)
            .field("vpc_id", &self.vpc_id)
            .field("subnet_ids", &self.subnet_ids)
            .field("eif_bucket", &self.eif_bucket)
            .field("instance_profile_name", &self.instance_profile_name)
            .field(
                "builder_instance_profile_name",
                &self.builder_instance_profile_name,
            )
            .field("iam_user", &self.iam_user)
            .field("aws_access_key_id", &"[REDACTED]")
            .field("aws_secret_access_key", &"[REDACTED]")
            .field("aws_region", &self.aws_region)
            .field("aws_account_id", &self.aws_account_id)
            .field("scope_tag", &self.scope_tag)
            .finish()
    }
}

/// Failure modes for [`CreateCredentialRequest::validate`] (leaf error: no underlying source).
#[derive(Debug, thiserror::Error)]
pub enum ValidateCredentialError {
    #[error("missing required field '{field}' [{location}]")]
    MissingField { field: String, location: Location },
}

impl CreateCredentialRequest {
    pub fn validate(&self) -> Result<(), ValidateCredentialError> {
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
                            return Err(ValidateCredentialError::MissingField {
                                field: format!("managed on-prem: {}", field),
                                location: std::panic::Location::caller(),
                            });
                        }
                    }
                    if self
                        .subnet_ids
                        .as_ref()
                        .map(|v| v.is_empty())
                        .unwrap_or(true)
                    {
                        return Err(ValidateCredentialError::MissingField {
                            field: "managed on-prem: subnet_ids".to_string(),
                            location: std::panic::Location::caller(),
                        });
                    }
                } else {
                    if self
                        .access_key_id
                        .as_ref()
                        .map(|s| s.is_empty())
                        .unwrap_or(true)
                    {
                        return Err(ValidateCredentialError::MissingField {
                            field: "access_key_id".to_string(),
                            location: std::panic::Location::caller(),
                        });
                    }
                    if self
                        .secret_access_key
                        .as_ref()
                        .map(|s| s.is_empty())
                        .unwrap_or(true)
                    {
                        return Err(ValidateCredentialError::MissingField {
                            field: "secret_access_key".to_string(),
                            location: std::panic::Location::caller(),
                        });
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
                "builder_instance_profile_name": self.builder_instance_profile_name,
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

/// Failure modes for [`create_credential`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum CreateCredentialError {
    #[error("invalid credential request [{location}]")]
    InvalidRequest {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("encryption failed [{location}]")]
    Encrypt {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to update default flag [{location}]")]
    UpdateDefault {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to check resource ownership [{location}]")]
    ResourceLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("resource not found [{location}]")]
    ResourceNotFound { location: Location },

    #[error("failed to look up existing credential [{location}]")]
    LookupExisting {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to update credential [{location}]")]
    Update {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to insert credential [{location}]")]
    Insert {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`list_credentials`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum ListCredentialsError {
    #[error("failed to list cloud credentials [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`get_credential`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum GetCredentialError {
    #[error("failed to get cloud credential [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`get_credential_secrets`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum GetCredentialSecretsError {
    #[error("failed to query secrets [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("decryption failed [{location}]")]
    Decrypt {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`delete_credential`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum DeleteCredentialError {
    #[error("failed to delete cloud credential [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`set_default_credential`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum SetDefaultCredentialError {
    #[error("failed to look up credential [{location}]")]
    Lookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to clear previous default [{location}]")]
    ClearDefault {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to set new default [{location}]")]
    SetDefault {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`get_managed_onprem_credential`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum GetManagedOnpremCredentialError {
    #[error("failed to look up credential [{location}]")]
    Lookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("credential is not a managed on-prem type [{location}]")]
    NotManagedOnPrem { location: Location },

    #[error("failed to get secrets [{location}]")]
    Secrets {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("secrets not found [{location}]")]
    SecretsMissing { location: Location },
}

/// Failure modes for [`get_credential_by_resource`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum GetCredentialByResourceError {
    #[error("failed to query credential by resource [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`get_credential_by_identifier`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum GetCredentialByIdentifierError {
    #[error("failed to query credential by identifier [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
pub async fn create_credential(
    pool: &PgPool,
    encryptor: &Encryptor,
    org_id: Uuid,
    user_id: Uuid,
    req: CreateCredentialRequest,
) -> Result<CloudCredential, CreateCredentialError> {
    use CreateCredentialErrorCtx as Ctx;

    req.validate()
        .inspect_err(|e| tracing::error!("Invalid credential request: {e}"))
        .with_context(Ctx::invalid_request())?;

    let secrets_encrypted = encryptor
        .encrypt_json(&req.secrets())
        .with_context(Ctx::encrypt())?;

    if req.is_default {
        sqlx::query(
            "UPDATE cloud_credentials SET is_default = false
             WHERE organization_id = $1 AND platform = $2 AND is_default = true",
        )
        .bind(org_id)
        .bind(req.platform)
        .execute(pool)
        .await
        .inspect_err(|source| {
            tracing::error!("Database error: {:?}", source);
        })
        .with_context(Ctx::update_default())?;
    }

    // Verify resource_id belongs to this org to prevent IDOR
    if let Some(resource_id) = req.resource_id {
        let owns_resource: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM compute_resources WHERE id = $1 AND organization_id = $2",
        )
        .bind(resource_id)
        .bind(org_id)
        .fetch_optional(pool)
        .await
        .inspect_err(|source| {
            tracing::error!("Database error: {:?}", source);
        })
        .with_context(Ctx::resource_lookup())?;

        if owns_resource.is_none() {
            return Err(CreateCredentialError::ResourceNotFound {
                location: std::panic::Location::caller(),
            });
        }
    }

    let existing_cred = if let Some(resource_id) = req.resource_id {
        get_credential_by_resource(pool, org_id, resource_id)
            .await
            .with_context(Ctx::lookup_existing())?
    } else if req.managed_on_prem {
        get_credential_by_identifier(pool, org_id, &req.identifier())
            .await
            .with_context(Ctx::lookup_existing())?
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
                       created_at, updated_at",
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
        .inspect_err(|source| {
            tracing::error!("Database error: {:?}", source);
        })
        .with_context(Ctx::update())?;

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
    .inspect_err(|source| {
        tracing::error!("Database error: {:?}", source);
    })
    .with_context(Ctx::insert())?;

    Ok(row)
}

#[tracing::instrument(skip_all, err)]
pub async fn list_credentials(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<CloudCredential>, ListCredentialsError> {
    use ListCredentialsErrorCtx as Ctx;

    let rows = sqlx::query_as::<_, CloudCredential>(
        "SELECT id, organization_id, resource_id, platform, managed_on_prem, identifier,
                config, is_default, is_active, last_validated_at, validation_error,
                created_at, updated_at
         FROM cloud_credentials
         WHERE organization_id = $1
         ORDER BY platform, created_at",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await
    .inspect_err(|source| {
        tracing::error!("Database error: {:?}", source);
    })
    .with_context(Ctx::query())?;

    Ok(rows)
}

#[tracing::instrument(skip_all, err)]
pub async fn get_credential(
    pool: &PgPool,
    org_id: Uuid,
    credential_id: Uuid,
) -> Result<Option<CloudCredential>, GetCredentialError> {
    use GetCredentialErrorCtx as Ctx;

    let row = sqlx::query_as::<_, CloudCredential>(
        "SELECT id, organization_id, resource_id, platform, managed_on_prem, identifier,
                config, is_default, is_active, last_validated_at, validation_error,
                created_at, updated_at
         FROM cloud_credentials
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(org_id)
    .bind(credential_id)
    .fetch_optional(pool)
    .await
    .inspect_err(|source| {
        tracing::error!("Database error: {:?}", source);
    })
    .with_context(Ctx::query())?;

    Ok(row)
}

#[tracing::instrument(skip_all, err)]
pub async fn get_credential_secrets(
    pool: &PgPool,
    encryptor: &Encryptor,
    org_id: Uuid,
    credential_id: Uuid,
) -> Result<Option<serde_json::Value>, GetCredentialSecretsError> {
    use GetCredentialSecretsErrorCtx as Ctx;

    let row: Option<(Vec<u8>,)> = sqlx::query_as(
        "SELECT secrets_encrypted FROM cloud_credentials
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(org_id)
    .bind(credential_id)
    .fetch_optional(pool)
    .await
    .inspect_err(|source| {
        tracing::error!("Database error: {:?}", source);
    })
    .with_context(Ctx::query())?;

    match row {
        Some((secrets_encrypted,)) => {
            let secrets: serde_json::Value = encryptor
                .decrypt_json(&secrets_encrypted)
                .with_context(Ctx::decrypt())?;
            Ok(Some(secrets))
        }
        None => Ok(None),
    }
}

#[tracing::instrument(skip_all, err)]
pub async fn delete_credential(
    pool: &PgPool,
    org_id: Uuid,
    credential_id: Uuid,
) -> Result<bool, DeleteCredentialError> {
    use DeleteCredentialErrorCtx as Ctx;

    let result =
        sqlx::query("DELETE FROM cloud_credentials WHERE organization_id = $1 AND id = $2")
            .bind(org_id)
            .bind(credential_id)
            .execute(pool)
            .await
            .inspect_err(|source| {
                tracing::error!("Database error: {:?}", source);
            })
            .with_context(Ctx::query())?;

    Ok(result.rows_affected() > 0)
}

#[tracing::instrument(skip_all, err)]
pub async fn set_default_credential(
    pool: &PgPool,
    org_id: Uuid,
    credential_id: Uuid,
) -> Result<bool, SetDefaultCredentialError> {
    use SetDefaultCredentialErrorCtx as Ctx;

    let cred = get_credential(pool, org_id, credential_id)
        .await
        .with_context(Ctx::lookup())?;
    let cred = match cred {
        Some(c) => c,
        None => return Ok(false),
    };

    sqlx::query(
        "UPDATE cloud_credentials SET is_default = false
         WHERE organization_id = $1 AND platform = $2 AND is_default = true",
    )
    .bind(org_id)
    .bind(cred.platform)
    .execute(pool)
    .await
    .inspect_err(|source| {
        tracing::error!("Database error: {:?}", source);
    })
    .with_context(Ctx::clear_default())?;

    let result = sqlx::query(
        "UPDATE cloud_credentials SET is_default = true
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(org_id)
    .bind(credential_id)
    .execute(pool)
    .await
    .inspect_err(|source| {
        tracing::error!("Database error: {:?}", source);
    })
    .with_context(Ctx::set_default())?;

    Ok(result.rows_affected() > 0)
}

#[derive(Clone, Serialize)]
pub struct ManagedOnPremCredentialData {
    pub deployment_id: String,
    pub asg_name: String,
    pub launch_template_name: String,
    pub launch_template_id: String,
    pub vpc_id: String,
    pub subnet_ids: Vec<String>,
    pub eif_bucket: String,
    pub instance_profile_name: String,
    pub builder_instance_profile_name: Option<String>,
    pub aws_access_key_id: String,
    pub aws_secret_access_key: String,
    pub aws_region: String,
}

impl std::fmt::Debug for ManagedOnPremCredentialData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedOnPremCredentialData")
            .field("deployment_id", &self.deployment_id)
            .field("asg_name", &self.asg_name)
            .field("launch_template_name", &self.launch_template_name)
            .field("launch_template_id", &self.launch_template_id)
            .field("vpc_id", &self.vpc_id)
            .field("subnet_ids", &self.subnet_ids)
            .field("eif_bucket", &self.eif_bucket)
            .field("instance_profile_name", &self.instance_profile_name)
            .field(
                "builder_instance_profile_name",
                &self.builder_instance_profile_name,
            )
            .field("aws_access_key_id", &"[REDACTED]")
            .field("aws_secret_access_key", &"[REDACTED]")
            .field("aws_region", &self.aws_region)
            .finish()
    }
}

fn managed_onprem_credential_data(
    cred: &CloudCredential,
    secrets: &serde_json::Value,
) -> ManagedOnPremCredentialData {
    ManagedOnPremCredentialData {
        deployment_id: cred.config["deployment_id"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        asg_name: cred.config["asg_name"].as_str().unwrap_or("").to_string(),
        launch_template_name: cred.config["launch_template_name"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        launch_template_id: cred.config["launch_template_id"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        vpc_id: cred.config["vpc_id"].as_str().unwrap_or("").to_string(),
        subnet_ids: cred.config["subnet_ids"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default(),
        eif_bucket: cred.config["eif_bucket"].as_str().unwrap_or("").to_string(),
        instance_profile_name: cred.config["instance_profile_name"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        builder_instance_profile_name: cred.config["builder_instance_profile_name"]
            .as_str()
            .map(|value| value.to_string()),
        aws_access_key_id: secrets["aws_access_key_id"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        aws_secret_access_key: secrets["aws_secret_access_key"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        aws_region: cred.config["aws_region"].as_str().unwrap_or("").to_string(),
    }
}

#[tracing::instrument(skip_all, err)]
pub async fn get_managed_onprem_credential(
    pool: &PgPool,
    encryptor: &Encryptor,
    org_id: Uuid,
    credential_id: Uuid,
) -> Result<Option<ManagedOnPremCredentialData>, GetManagedOnpremCredentialError> {
    use GetManagedOnpremCredentialErrorCtx as Ctx;

    let cred = get_credential(pool, org_id, credential_id)
        .await
        .with_context(Ctx::lookup())?;
    let cred = match cred {
        Some(c) => c,
        None => return Ok(None),
    };

    if !cred.managed_on_prem {
        return Err(GetManagedOnpremCredentialError::NotManagedOnPrem {
            location: std::panic::Location::caller(),
        });
    }

    let secrets = get_credential_secrets(pool, encryptor, org_id, credential_id)
        .await
        .with_context(Ctx::secrets())?
        .ok_or(GetManagedOnpremCredentialError::SecretsMissing {
            location: std::panic::Location::caller(),
        })?;

    Ok(Some(managed_onprem_credential_data(&cred, &secrets)))
}

#[tracing::instrument(skip_all, err)]
pub async fn get_credential_by_resource(
    pool: &PgPool,
    org_id: Uuid,
    resource_id: Uuid,
) -> Result<Option<CloudCredential>, GetCredentialByResourceError> {
    use GetCredentialByResourceErrorCtx as Ctx;

    let row = sqlx::query_as::<_, CloudCredential>(
        "SELECT id, organization_id, resource_id, platform, managed_on_prem, identifier,
                config, is_default, is_active, last_validated_at, validation_error,
                created_at, updated_at
         FROM cloud_credentials
         WHERE organization_id = $1 AND resource_id = $2",
    )
    .bind(org_id)
    .bind(resource_id)
    .fetch_optional(pool)
    .await
    .inspect_err(|source| {
        tracing::error!("Database error: {:?}", source);
    })
    .with_context(Ctx::query())?;

    Ok(row)
}

#[tracing::instrument(skip_all, err)]
pub async fn get_credential_by_identifier(
    pool: &PgPool,
    org_id: Uuid,
    identifier: &str,
) -> Result<Option<CloudCredential>, GetCredentialByIdentifierError> {
    use GetCredentialByIdentifierErrorCtx as Ctx;

    let row = sqlx::query_as::<_, CloudCredential>(
        "SELECT id, organization_id, resource_id, platform, managed_on_prem, identifier,
                config, is_default, is_active, last_validated_at, validation_error,
                created_at, updated_at
         FROM cloud_credentials
         WHERE organization_id = $1 AND identifier = $2",
    )
    .bind(org_id)
    .bind(identifier)
    .fetch_optional(pool)
    .await
    .inspect_err(|source| {
        tracing::error!("Database error: {:?}", source);
    })
    .with_context(Ctx::query())?;

    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn managed_onprem_request() -> CreateCredentialRequest {
        CreateCredentialRequest {
            platform: CloudPlatform::Aws,
            resource_id: None,
            managed_on_prem: true,
            is_default: false,
            access_key_id: None,
            secret_access_key: None,
            deployment_id: Some("dep-123".to_string()),
            asg_name: Some("caution-asg".to_string()),
            launch_template_name: Some("caution-lt".to_string()),
            launch_template_id: Some("lt-123".to_string()),
            vpc_id: Some("vpc-123".to_string()),
            subnet_ids: Some(vec!["subnet-a".to_string(), "subnet-b".to_string()]),
            eif_bucket: Some("customer-bucket".to_string()),
            instance_profile_name: Some("caution-ec2-profile-dep-123".to_string()),
            builder_instance_profile_name: None,
            iam_user: Some("caution-provisioner-dep-123".to_string()),
            aws_access_key_id: Some("AKIA_TEST".to_string()),
            aws_secret_access_key: Some("secret".to_string()),
            aws_region: Some("us-east-1".to_string()),
            aws_account_id: Some("123456789012".to_string()),
            scope_tag: Some("caution:deployment-id=dep-123".to_string()),
        }
    }

    #[test]
    fn test_managed_onprem_validation_allows_missing_builder_instance_profile() {
        let req = managed_onprem_request();
        assert!(req.validate().is_ok());
    }

    #[test]
    fn test_managed_onprem_config_preserves_builder_instance_profile() {
        let mut req = managed_onprem_request();
        req.builder_instance_profile_name = Some("caution-builder-profile-dep-123".to_string());

        let config = req.config();
        assert_eq!(
            config["builder_instance_profile_name"].as_str(),
            Some("caution-builder-profile-dep-123")
        );
        assert_eq!(
            config["instance_profile_name"].as_str(),
            Some("caution-ec2-profile-dep-123")
        );
    }
}
