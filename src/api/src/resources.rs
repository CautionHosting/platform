use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use dterror::{BoxError, CtxError, Location, ResultExt};
use serde::{Deserialize, Serialize};
use sqlx::{Connection, FromRow, PgConnection};
use std::sync::Arc;
use uuid::Uuid;

use crate::validated_types;
use crate::validated_types::{
    CreateResourceRequest, CreateResourceResponse, RenameResourceRequest,
};
use crate::{
    AppState, AuthContext, get_or_create_provider_account, get_or_create_resource_type,
    get_user_primary_org,
};
use crate::{cloud_credentials, deployment, types, validation};

#[derive(Debug, Serialize, FromRow)]
pub struct ComputeResource {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub provider_account_id: Uuid,
    pub resource_type_id: Uuid,
    pub provider_resource_id: String,
    pub resource_name: Option<String>,
    pub state: String,
    pub region: Option<String>,
    pub public_ip: Option<String>,
    pub domain: Option<String>,
    pub dns_status: String,
    pub dns_error: Option<String>,
    pub billing_tag: Option<String>,
    pub configuration: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Failure modes for [`create_resource`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum CreateResourceError {
    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not obtain a provider account for organization {org_id} [{location}]")]
    ProviderAccount { org_id: Uuid, location: Location },

    #[error("could not obtain the compute resource type [{location}]")]
    ResourceType { location: Location },

    #[error("failed to check for an existing resource name '{resource_name}' [{location}]")]
    CheckName {
        resource_name: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to create compute resource '{provider_resource_id}' [{location}]")]
    Insert {
        provider_resource_id: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for CreateResourceError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            CreateResourceError::PrimaryOrgLookup { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            CreateResourceError::ProviderAccount { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            CreateResourceError::ResourceType { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            CreateResourceError::CheckName { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            CreateResourceError::Insert { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(user_id = %auth.user_id))]
pub async fn create_resource(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    validated_types::Validated(payload): validated_types::Validated<CreateResourceRequest>,
) -> Result<Json<CreateResourceResponse>, CreateResourceError> {
    use CreateResourceErrorCtx as Ctx;

    tracing::info!("Creating resource for user_id: {}", auth.user_id);
    tracing::debug!("Resource payload: {:?}", payload);

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    let provider_account_id = match get_or_create_provider_account(&state.db, org_id).await {
        Ok(id) => {
            tracing::debug!("Provider account: {}", id);
            id
        }
        Err(status) => {
            tracing::error!("Failed to get/create provider account: {:?}", status);
            return Err(CreateResourceError::ProviderAccount {
                org_id,
                location: std::panic::Location::caller(),
            });
        }
    };

    let resource_type_id = match get_or_create_resource_type(&state.db).await {
        Ok(id) => {
            tracing::debug!("Resource type: {}", id);
            id
        }
        Err(status) => {
            tracing::error!("Failed to get/create resource type: {:?}", status);
            return Err(CreateResourceError::ResourceType {
                location: std::panic::Location::caller(),
            });
        }
    };

    let provider_resource_id = Uuid::new_v4().to_string();

    // Use provided name (typically from directory name) or generate one
    let resource_slug = if let Some(ref name) = payload.name {
        // Validate the app name
        if let Err(e) = validation::validate_app_name(name) {
            tracing::warn!(
                "Invalid app name '{}': {}, falling back to auto-generated",
                name,
                e
            );
            format!("app-{}", &provider_resource_id[..8])
        } else {
            // Check if name is already taken in this organization
            let existing: Option<(Uuid,)> = sqlx::query_as(
                "SELECT id FROM compute_resources
                 WHERE organization_id = $1 AND resource_name = $2 AND destroyed_at IS NULL",
            )
            .bind(org_id)
            .bind(name)
            .fetch_optional(&state.db)
            .await
            .with_context(Ctx::check_name(name.as_str()))?;

            if existing.is_some() {
                tracing::warn!(
                    "App name '{}' already exists, falling back to auto-generated",
                    name
                );
                format!("app-{}", &provider_resource_id[..8])
            } else {
                name.clone()
            }
        }
    } else {
        format!("app-{}", &provider_resource_id[..8])
    };

    // `cmd` is still accepted at the API boundary for backward compatibility, but
    // deploys now derive build commands from the current repository state rather
    // than persisted resource configuration.
    let configuration = initial_resource_configuration();

    tracing::debug!("Creating resource with slug: {}", resource_slug);

    let resource: (Uuid, types::ResourceState, DateTime<Utc>) = sqlx::query_as(
        "INSERT INTO compute_resources
         (organization_id, provider_account_id, resource_type_id, provider_resource_id,
          resource_name, state, configuration, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING id, state, created_at",
    )
    .bind(org_id)
    .bind(provider_account_id)
    .bind(resource_type_id)
    .bind(&provider_resource_id)
    .bind(&resource_slug)
    .bind(types::ResourceState::Initialized)
    .bind(&configuration)
    .bind(auth.user_id)
    .fetch_one(&state.db)
    .await
    .with_context(Ctx::insert(provider_resource_id.as_str()))?;

    let (resource_id, resource_state, created_at) = resource;

    let git_url = match state.git_ssh_port {
        Some(port) => format!(
            "ssh://git@{}:{}/{}.git",
            state.git_hostname, port, resource_id
        ),
        None => format!("git@{}:{}.git", state.git_hostname, resource_id),
    };

    tracing::info!(
        "Resource created successfully: id={}, name={}",
        resource_id,
        resource_slug
    );

    Ok(Json(CreateResourceResponse {
        id: resource_id,
        resource_name: resource_slug,
        git_url,
        state: resource_state.as_str().to_string(),
        created_at,
        managed_hostname: crate::managed_dns::managed_hostname(resource_id),
        dns_status: "reserved".to_string(),
        dns_error: None,
    }))
}

fn initial_resource_configuration() -> serde_json::Value {
    serde_json::json!({})
}

/// Failure modes for [`list_resources`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum ListResourcesError {
    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to list resources for organization {org_id} [{location}]")]
    Query {
        org_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for ListResourcesError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            ListResourcesError::PrimaryOrgLookup { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            ListResourcesError::Query { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(user_id = %auth.user_id))]
pub async fn list_resources(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<serde_json::Value>>, ListResourcesError> {
    use ListResourcesErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    tracing::info!(
        "Listing resources for user {} in org {}",
        auth.user_id,
        org_id
    );

    let resources = sqlx::query_as::<_, ComputeResource>(
        "SELECT id, organization_id, provider_account_id, resource_type_id,
                provider_resource_id, resource_name, state::text as state,
                region, public_ip, configuration->>'domain' as domain,
                dns_status, dns_error, billing_tag, configuration, created_at, updated_at
         FROM compute_resources
         WHERE organization_id = $1",
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .with_context(Ctx::query(org_id))?;

    tracing::info!("Found {} resources", resources.len());

    let resources_with_git_url: Vec<serde_json::Value> = resources
        .into_iter()
        .map(|resource| {
            let git_url = match state.git_ssh_port {
                Some(port) => format!(
                    "ssh://git@{}:{}/{}.git",
                    state.git_hostname, port, resource.id
                ),
                None => format!("git@{}:{}.git", state.git_hostname, resource.id),
            };
            let mut value = serde_json::to_value(&resource).unwrap_or_default();
            if let Some(obj) = value.as_object_mut() {
                obj.insert("git_url".to_string(), serde_json::json!(git_url));
                obj.insert(
                    "managed_hostname".to_string(),
                    serde_json::json!(crate::managed_dns::managed_hostname(resource.id)),
                );
            }
            value
        })
        .collect();

    Ok(Json(resources_with_git_url))
}

#[cfg(test)]
mod tests {
    use super::initial_resource_configuration;

    #[test]
    fn initial_resource_configuration_does_not_store_legacy_cmd() {
        let configuration = initial_resource_configuration();

        assert_eq!(configuration, serde_json::json!({}));
        assert!(configuration.get("cmd").is_none());
    }
}

/// Failure modes for [`get_resource`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum GetResourceError {
    #[error("resource {resource_id} not found [{location}]")]
    NotFound {
        resource_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for GetResourceError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            GetResourceError::NotFound { .. } => (StatusCode::NOT_FOUND, "not found"),
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(resource_id = %resource_id))]
pub async fn get_resource(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(resource_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, GetResourceError> {
    use GetResourceErrorCtx as Ctx;

    let resource = sqlx::query_as::<_, ComputeResource>(
        "SELECT cr.id, cr.organization_id, cr.provider_account_id, cr.resource_type_id,
                cr.provider_resource_id, cr.resource_name, cr.state::text as state,
                cr.region, cr.public_ip, cr.configuration->>'domain' as domain,
                cr.dns_status, cr.dns_error, cr.billing_tag, cr.configuration,
                cr.created_at, cr.updated_at
         FROM compute_resources cr
         INNER JOIN organization_members om ON cr.organization_id = om.organization_id
         WHERE cr.id = $1 AND om.user_id = $2 AND cr.destroyed_at IS NULL",
    )
    .bind(resource_id)
    .bind(auth.user_id)
    .fetch_one(&state.db)
    .await
    .with_context(Ctx::not_found(resource_id))?;

    let git_url = match state.git_ssh_port {
        Some(port) => format!(
            "ssh://git@{}:{}/{}.git",
            state.git_hostname, port, resource_id
        ),
        None => format!("git@{}:{}.git", state.git_hostname, resource_id),
    };

    let mut response = serde_json::to_value(&resource).unwrap_or_default();
    if let Some(obj) = response.as_object_mut() {
        obj.insert("git_url".to_string(), serde_json::json!(git_url));
        obj.insert(
            "managed_hostname".to_string(),
            serde_json::json!(crate::managed_dns::managed_hostname(resource_id)),
        );
    }

    Ok(Json(response))
}

/// Failure modes for [`proxy_attestation`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum ProxyAttestationError {
    #[error("resource not found [{location}]")]
    ResourceNotFound {
        resource_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("resource has no public IP [{location}]")]
    NoPublicIp {
        resource_id: Uuid,
        location: Location,
    },

    #[error("failed to create HTTP client [{location}]")]
    ClientBuild {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to reach attestation endpoint [{location}]")]
    SendRequest {
        resource_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("attestation endpoint returned an error status [{location}]")]
    EndpointStatus {
        resource_id: Uuid,
        location: Location,
    },

    #[error("invalid JSON from attestation endpoint [{location}]")]
    JsonParse {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for ProxyAttestationError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            ProxyAttestationError::ResourceNotFound { .. } => {
                (StatusCode::NOT_FOUND, "resource not found")
            }
            ProxyAttestationError::NoPublicIp { .. } => {
                (StatusCode::BAD_REQUEST, "resource has no public IP")
            }
            ProxyAttestationError::ClientBuild { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            ProxyAttestationError::SendRequest { .. } => {
                (StatusCode::BAD_GATEWAY, "attestation endpoint unreachable")
            }
            ProxyAttestationError::EndpointStatus { .. } => {
                (StatusCode::BAD_GATEWAY, "attestation endpoint error")
            }
            ProxyAttestationError::JsonParse { .. } => {
                (StatusCode::BAD_GATEWAY, "invalid attestation response")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(resource_id = %resource_id))]
pub async fn proxy_attestation(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(resource_id): Path<Uuid>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, ProxyAttestationError> {
    use ProxyAttestationErrorCtx as Ctx;

    // Get the resource to verify ownership and get the public IP
    let public_ip: Option<String> = sqlx::query_scalar(
        "SELECT cr.public_ip
         FROM compute_resources cr
         INNER JOIN organization_members om ON cr.organization_id = om.organization_id
         WHERE cr.id = $1 AND om.user_id = $2 AND cr.destroyed_at IS NULL",
    )
    .bind(resource_id)
    .bind(auth.user_id)
    .fetch_one(&state.db)
    .await
    .with_context(Ctx::resource_not_found(resource_id))?;

    let public_ip = public_ip.ok_or_else(|| ProxyAttestationError::NoPublicIp {
        resource_id,
        location: std::panic::Location::caller(),
    })?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .with_context(Ctx::client_build())?;

    // Fetch over plain HTTP by IP: the attestation document is a COSE_Sign1 verified
    // client-side (certificate chain + signature + nonce), so transport TLS is not
    // load-bearing here. Using HTTP avoids the enclave's on-demand Let's Encrypt TLS,
    // whose inline cert issuance intermittently fails the handshake (502s in the UI).
    let attestation_url = format!("http://{}/attestation", public_ip);
    tracing::info!("Proxying attestation request to {}", attestation_url);

    let response = client
        .post(&attestation_url)
        .header("Content-Type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .with_context(Ctx::send_request(resource_id))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        tracing::error!("Attestation endpoint returned error: {} - {}", status, body);
        return Err(ProxyAttestationError::EndpointStatus {
            resource_id,
            location: std::panic::Location::caller(),
        });
    }

    let json: serde_json::Value = response.json().await.with_context(Ctx::json_parse())?;

    Ok(Json(json))
}

/// Failure modes for [`rename_resource`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum RenameResourceError {
    #[error("resource not found [{location}]")]
    NotFound {
        resource_id: Uuid,
        location: Location,
    },

    #[error("failed to look up resource [{location}]")]
    Lookup {
        resource_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to check name uniqueness [{location}]")]
    CheckName {
        org_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("an app with that name already exists in this organization [{location}]")]
    NameTaken {
        resource_id: Uuid,
        location: Location,
    },

    #[error("failed to update resource name [{location}]")]
    Update {
        resource_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for RenameResourceError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            RenameResourceError::NotFound { .. } => (StatusCode::NOT_FOUND, "not found"),
            RenameResourceError::Lookup { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            RenameResourceError::CheckName { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            RenameResourceError::NameTaken { .. } => (StatusCode::CONFLICT, "name already taken"),
            RenameResourceError::Update { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(resource_id = %resource_id))]
pub async fn rename_resource(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(resource_id): Path<Uuid>,
    validated_types::Validated(payload): validated_types::Validated<RenameResourceRequest>,
) -> Result<Json<ComputeResource>, RenameResourceError> {
    use RenameResourceErrorCtx as Ctx;

    tracing::info!(
        "rename_resource: resource_id={}, user_id={}, new_name={}",
        resource_id,
        auth.user_id,
        payload.name
    );

    // Verify user has access to this resource via organization membership
    let resource: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT cr.organization_id, cr.resource_name
         FROM compute_resources cr
         INNER JOIN organization_members om ON cr.organization_id = om.organization_id
         WHERE cr.id = $1 AND om.user_id = $2 AND cr.destroyed_at IS NULL",
    )
    .bind(resource_id)
    .bind(auth.user_id)
    .fetch_optional(&state.db)
    .await
    .with_context(Ctx::lookup(resource_id))?;

    let Some((org_id, old_name)) = resource else {
        return Err(RenameResourceError::NotFound {
            resource_id,
            location: std::panic::Location::caller(),
        });
    };

    // Check if the new name is already taken within this organization (for active resources)
    let name_exists: Option<bool> = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM compute_resources
            WHERE organization_id = $1 AND resource_name = $2 AND destroyed_at IS NULL AND id != $3
        )",
    )
    .bind(org_id)
    .bind(&payload.name)
    .bind(resource_id)
    .fetch_one(&state.db)
    .await
    .with_context(Ctx::check_name(org_id))?;

    if name_exists == Some(true) {
        return Err(RenameResourceError::NameTaken {
            resource_id,
            location: std::panic::Location::caller(),
        });
    }

    // Update the resource name
    let updated_resource = sqlx::query_as::<_, ComputeResource>(
        "UPDATE compute_resources
         SET resource_name = $1
         WHERE id = $2 AND organization_id = $3
         RETURNING id, organization_id, provider_account_id, resource_type_id,
                   provider_resource_id, resource_name, state::text as state,
                   region, public_ip, configuration->>'domain' as domain,
                   dns_status, dns_error, billing_tag, configuration, created_at, updated_at",
    )
    .bind(&payload.name)
    .bind(resource_id)
    .bind(org_id)
    .fetch_one(&state.db)
    .await
    .with_context(Ctx::update(resource_id))?;

    // Rename the git repository if it exists
    let old_repo_path = format!("{}/git-repos/{}.git", state.data_dir, old_name);
    let new_repo_path = format!("{}/git-repos/{}.git", state.data_dir, payload.name);

    if tokio::fs::metadata(&old_repo_path).await.is_ok() {
        if let Err(e) = tokio::fs::rename(&old_repo_path, &new_repo_path).await {
            tracing::warn!(
                "Failed to rename git repo from {} to {}: {} (resource renamed in DB)",
                old_repo_path,
                new_repo_path,
                e
            );
        } else {
            tracing::info!(
                "Renamed git repo from {} to {}",
                old_repo_path,
                new_repo_path
            );
        }
    }

    tracing::info!(
        "Resource {} renamed from '{}' to '{}' by user {}",
        resource_id,
        old_name,
        payload.name,
        auth.user_id
    );

    Ok(Json(updated_resource))
}

#[derive(Debug, Deserialize)]
pub struct DeleteResourceQuery {
    #[serde(default)]
    pub force: bool,
}

/// Failure modes for [`delete_resource`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum DeleteResourceError {
    #[error("failed to read app state [{location}]")]
    AccessQuery {
        resource_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("app not found [{location}]")]
    NotFound {
        resource_id: Uuid,
        location: Location,
    },

    #[error("failed to update app deletion state [{location}]")]
    ClaimUpdate {
        resource_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("resource is deploying [{location}]")]
    Deploying {
        resource_id: Uuid,
        location: Location,
    },

    #[error("app no longer exists [{location}]")]
    AlreadyGone {
        resource_id: Uuid,
        location: Location,
    },

    #[error("app destroy failed [{location}]")]
    DestroyFailed {
        resource_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for DeleteResourceError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            DeleteResourceError::AccessQuery { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            DeleteResourceError::NotFound { .. } => (StatusCode::NOT_FOUND, "app not found"),
            DeleteResourceError::ClaimUpdate { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            DeleteResourceError::Deploying { .. } => {
                (StatusCode::CONFLICT, "resource is deploying")
            }
            DeleteResourceError::AlreadyGone { .. } => (StatusCode::NOT_FOUND, "app not found"),
            DeleteResourceError::DestroyFailed { .. } => {
                (StatusCode::SERVICE_UNAVAILABLE, "app destroy failed")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(resource_id = %resource_id))]
pub async fn delete_resource(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(resource_id): Path<Uuid>,
    query: axum::extract::Query<DeleteResourceQuery>,
) -> Result<StatusCode, DeleteResourceError> {
    use DeleteResourceErrorCtx as Ctx;

    tracing::info!(
        "delete_resource called: resource_id={}, user_id={}, force={}",
        resource_id,
        auth.user_id,
        query.force
    );

    tracing::debug!(
        "Querying resource access for user {} on resource {}",
        auth.user_id,
        resource_id
    );
    let resource: Option<(Uuid, bool)> = sqlx::query_as(
        "SELECT cr.id, cr.destroyed_at IS NOT NULL
         FROM compute_resources cr
         INNER JOIN organization_members om ON cr.organization_id = om.organization_id
         WHERE cr.id = $1 AND om.user_id = $2",
    )
    .bind(resource_id)
    .bind(auth.user_id)
    .fetch_optional(&state.db)
    .await
    .with_context(Ctx::access_query(resource_id))?;

    let Some((resource_id, destroyed)) = resource else {
        tracing::warn!(
            "Resource {} not found or user {} has no access",
            resource_id,
            auth.user_id
        );
        return Err(DeleteResourceError::NotFound {
            resource_id,
            location: std::panic::Location::caller(),
        });
    };
    if destroyed {
        return Ok(StatusCode::NO_CONTENT);
    }

    // An explicit user delete takes precedence over a crash-safe deploy rollback
    // which is already terminating under its retained attempt marker.
    sqlx::query(
        "UPDATE compute_resources SET deploy_attempt_id = NULL
         WHERE id = $1 AND state = 'terminating' AND deploy_attempt_id IS NOT NULL",
    )
    .bind(resource_id)
    .execute(&state.db)
    .await
    .with_context(Ctx::claim_update(resource_id))?;

    let destroy_result = destroy_resource_by_id(&state, resource_id, query.force).await;
    if let Err(ref error) = destroy_result {
        let destroyed: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1 FROM compute_resources cr
                 INNER JOIN organization_members om ON cr.organization_id = om.organization_id
                 WHERE cr.id = $1 AND om.user_id = $2 AND cr.destroyed_at IS NOT NULL
             )",
        )
        .bind(resource_id)
        .bind(auth.user_id)
        .fetch_one(&state.db)
        .await
        .unwrap_or(false);
        if destroyed {
            return Ok(StatusCode::NO_CONTENT);
        }

        tracing::error!(resource_id = %resource_id, error = %error, "app destroy failed");
        match error.kind {
            DestroyResourceByIdErrorKind::Deploying => {
                return Err(DeleteResourceError::Deploying {
                    resource_id,
                    location: std::panic::Location::caller(),
                });
            }
            DestroyResourceByIdErrorKind::Gone => {
                return Err(DeleteResourceError::AlreadyGone {
                    resource_id,
                    location: std::panic::Location::caller(),
                });
            }
            _ => {}
        }
    }

    if destroy_result.is_err() {
        return destroy_result
            .map(|()| StatusCode::NO_CONTENT)
            .with_context(Ctx::destroy_failed(resource_id));
    }

    tracing::info!(
        "Resource {} terminated by user {} (git repo preserved for redeployment)",
        resource_id,
        auth.user_id
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Categories of failure surfaced by [`destroy_resource_by_id`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum DestroyResourceByIdErrorKind {
    BeginTermination,
    Deploying,
    Gone,
    TeardownLimiterClosed,
    EnsureSafeToRelease,
    DnsDisabled,
    DnsSnapshot,
    LoadResource,
    ConnectLock,
    AdvisoryLock,
    StillTerminating,
    TofuDestroyFailed,
    MarkDestroyed,
}

/// Failure modes for [`destroy_resource_by_id`]. The shared `resource_id` context
/// rides along on every failure; source-less kinds carry `source: None`.
#[derive(Debug, thiserror::Error, CtxError)]
#[error("could not destroy resource {resource_id} ({kind:?}) [{location}]")]
pub(crate) struct DestroyResourceByIdError {
    kind: DestroyResourceByIdErrorKind,
    resource_id: Uuid,
    #[location]
    location: Location,
    #[source]
    #[context(option)]
    source: Option<BoxError>,
}

impl DestroyResourceByIdError {
    /// Client-facing message for the e2e-testing teardown surface: fixed literals,
    /// never the underlying source or the internal location segment.
    #[cfg(feature = "e2e-testing-unsafe")]
    pub(crate) fn client_message(&self) -> &'static str {
        match self.kind {
            DestroyResourceByIdErrorKind::Deploying => "resource is deploying",
            DestroyResourceByIdErrorKind::Gone => "resource no longer exists",
            _ => "internal error",
        }
    }
}

#[tracing::instrument(skip_all, err)]
pub(crate) async fn destroy_resource_by_id(
    state: &Arc<AppState>,
    resource_id: Uuid,
    force: bool,
) -> Result<(), DestroyResourceByIdError> {
    use DestroyResourceByIdErrorCtx as Ctx;
    use DestroyResourceByIdErrorKind as Kind;

    let begin_error = crate::managed_dns::begin_termination(&state.db, resource_id).await;
    if let Err(ref error) = begin_error {
        let message = error.to_string();
        if message == "resource is deploying" {
            return Err(DestroyResourceByIdError {
                kind: Kind::Deploying,
                resource_id,
                location: std::panic::Location::caller(),
                source: None,
            });
        } else if message == "resource no longer exists" {
            return Err(DestroyResourceByIdError {
                kind: Kind::Gone,
                resource_id,
                location: std::panic::Location::caller(),
                source: None,
            });
        }
    }
    begin_error.with_context(Ctx::new(Kind::BeginTermination, resource_id))?;

    let _teardown_slot = state
        .teardown_slots
        .acquire()
        .await
        .with_context(Ctx::new(Kind::TeardownLimiterClosed, resource_id))?;

    if let Some(managed_dns) = state.managed_dns.as_ref() {
        managed_dns
            .ensure_safe_to_release(&state.db, resource_id)
            .await
            .with_context(Ctx::new(Kind::EnsureSafeToRelease, resource_id))?;
    } else {
        let dns = crate::managed_dns::dns_snapshot(&state.db, resource_id)
            .await
            .with_context(Ctx::new(Kind::DnsSnapshot, resource_id))?;
        if dns.status != "reserved" {
            return Err(DestroyResourceByIdError {
                kind: Kind::DnsDisabled,
                resource_id,
                location: std::panic::Location::caller(),
                source: None,
            });
        }
    }

    let resource: Option<(Uuid, String, String, Option<String>)> = sqlx::query_as(
        "SELECT organization_id, resource_name, provider_resource_id, region
         FROM compute_resources
         WHERE id = $1 AND destroyed_at IS NULL AND state = 'terminating'",
    )
    .bind(resource_id)
    .fetch_optional(&state.db)
    .await
    .with_context(Ctx::new(Kind::LoadResource, resource_id))?;
    let Some((org_id, resource_name, tracked_resource_id, resource_region)) = resource else {
        return Ok(());
    };

    let resource_region = resource_region
        .or_else(|| std::env::var("AWS_REGION").ok())
        .unwrap_or_else(|| "us-west-2".to_string());
    let destroy_credentials =
        destroy_credentials(state, org_id, resource_id, &resource_region).await;

    // Use a dedicated session lock so OpenTofu cannot consume the API pool or
    // hold a database transaction open. Closing the connection releases it.
    let mut lock_connection = PgConnection::connect(&state.database_url)
        .await
        .with_context(Ctx::new(Kind::ConnectLock, resource_id))?;
    sqlx::query("SELECT pg_advisory_lock(hashtextextended($1, 1))")
        .bind(resource_id.to_string())
        .execute(&mut lock_connection)
        .await
        .with_context(Ctx::new(Kind::AdvisoryLock, resource_id))?;

    let still_terminating: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM compute_resources
             WHERE id = $1 AND destroyed_at IS NULL AND state = 'terminating'
         )",
    )
    .bind(resource_id)
    .fetch_one(&mut lock_connection)
    .await
    .with_context(Ctx::new(Kind::StillTerminating, resource_id))?;
    if !still_terminating {
        release_teardown_lock(&mut lock_connection, resource_id).await;
        return Ok(());
    }

    let terraform_result = match destroy_credentials {
        Ok((aws_credentials, asg_name)) => deployment::destroy_app_with_credentials(
            org_id,
            resource_id,
            resource_name,
            aws_credentials,
            asg_name,
        )
        .await
        .map_err(|error| -> BoxError { error.into() }),
        Err(error) => Err(Box::new(error) as BoxError),
    };
    if let Err(source) = terraform_result {
        tracing::error!(resource_id = %resource_id, error = %source, "OpenTofu destroy failed");
        if !force {
            return Err(DestroyResourceByIdError {
                kind: Kind::TofuDestroyFailed,
                resource_id,
                location: std::panic::Location::caller(),
                source: Some(source),
            });
        }
        tracing::warn!(resource_id = %resource_id, "force enabled after DNS withdrawal; marking app destroyed despite OpenTofu failure");
    }

    sqlx::query(
        "UPDATE compute_resources
         SET destroyed_at = CASE WHEN deploy_attempt_id IS NULL THEN NOW() ELSE NULL END,
             state = CASE
                 WHEN deploy_attempt_id IS NULL THEN 'terminated'::resource_state
                 ELSE 'failed'::resource_state
             END,
             public_ip = NULL, region = NULL, deploy_attempt_id = NULL,
             dns_status = 'reserved', dns_error = NULL, dns_change_id = NULL,
             dns_release_not_before = NULL, updated_at = NOW()
         WHERE id = $1 AND organization_id = $2 AND state = 'terminating'",
    )
    .bind(resource_id)
    .bind(org_id)
    .execute(&mut lock_connection)
    .await
    .with_context(Ctx::new(Kind::MarkDestroyed, resource_id))?;
    release_teardown_lock(&mut lock_connection, resource_id).await;
    drop(lock_connection);

    if let Err(error) = crate::metering::stop_tracked_resource(
        state.internal_service_secret.as_deref(),
        &tracked_resource_id,
    )
    .await
    {
        tracing::error!(resource_id = %resource_id, error = %error, "failed to stop metering after app destroy");
        let _ = sqlx::query(
            "UPDATE tracked_resources SET status = 'stopped', stopped_at = NOW()
             WHERE resource_id = $1 AND status = 'running'",
        )
        .bind(&tracked_resource_id)
        .execute(&state.db)
        .await;
    }

    Ok(())
}

#[tracing::instrument(skip_all)]
async fn release_teardown_lock(connection: &mut PgConnection, resource_id: Uuid) {
    if let Err(error) = sqlx::query("SELECT pg_advisory_unlock(hashtextextended($1, 1))")
        .bind(resource_id.to_string())
        .execute(connection)
        .await
    {
        tracing::warn!(resource_id = %resource_id, error = %error, "failed to explicitly release teardown advisory lock; closing its connection");
    }
}

/// Failure modes for [`destroy_credentials`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum DestroyCredentialsError {
    #[error("could not load cloud credential for resource {resource_id} [{location}]")]
    LoadCredential {
        resource_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("BYOC teardown requires the configured credential encryptor [{location}]")]
    MissingEncryptor { location: Location },

    #[error("BYOC credentials are unavailable; infrastructure was preserved [{location}]")]
    SecretsUnavailable {
        #[location]
        location: Location,
        #[source]
        #[context(option)]
        source: Option<BoxError>,
    },

    #[error("BYOC access key is unavailable [{location}]")]
    AccessKeyUnavailable { location: Location },

    #[error("BYOC secret key is unavailable [{location}]")]
    SecretKeyUnavailable { location: Location },
}

#[tracing::instrument(skip_all, err)]
async fn destroy_credentials(
    state: &Arc<AppState>,
    org_id: Uuid,
    resource_id: Uuid,
    resource_region: &str,
) -> Result<(Option<deployment::AwsCredentials>, Option<String>), DestroyCredentialsError> {
    use DestroyCredentialsErrorCtx as Ctx;

    let credential = cloud_credentials::get_credential_by_resource(&state.db, org_id, resource_id)
        .await
        .with_context(Ctx::load_credential(resource_id))?;

    if let Some(credential) = credential
        && credential.managed_on_prem
    {
        let encryptor =
            state
                .encryptor
                .as_ref()
                .ok_or_else(|| DestroyCredentialsError::MissingEncryptor {
                    location: std::panic::Location::caller(),
                })?;
        let secrets =
            cloud_credentials::get_credential_secrets(&state.db, encryptor, org_id, credential.id)
                .await
                .with_context(Ctx::secrets_unavailable())?
                .ok_or_else(|| DestroyCredentialsError::SecretsUnavailable {
                    location: std::panic::Location::caller(),
                    source: None,
                })?;
        let access_key_id = secrets["aws_access_key_id"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| DestroyCredentialsError::AccessKeyUnavailable {
                location: std::panic::Location::caller(),
            })?
            .to_string();
        let secret_access_key = secrets["aws_secret_access_key"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| DestroyCredentialsError::SecretKeyUnavailable {
                location: std::panic::Location::caller(),
            })?
            .to_string();
        let region = credential.config["aws_region"]
            .as_str()
            .map(str::to_string)
            .or_else(|| std::env::var("AWS_REGION").ok())
            .unwrap_or_else(|| "us-west-2".to_string());
        let asg_name = credential.config["asg_name"].as_str().map(str::to_string);
        return Ok((
            Some(deployment::AwsCredentials {
                access_key_id,
                secret_access_key,
                region,
            }),
            asg_name,
        ));
    }

    Ok((
        Some(crate::fully_managed_capacity::platform_credentials_for_region(resource_region)),
        None,
    ))
}
