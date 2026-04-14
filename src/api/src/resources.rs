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

use crate::{AppState, AuthContext, get_user_primary_org, get_or_create_provider_account, get_or_create_resource_type};
use crate::validated_types;
use crate::validated_types::{CreateResourceRequest, CreateResourceResponse, RenameResourceRequest};
use crate::{types, validation, deployment, cloud_credentials};

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
    pub billing_tag: Option<String>,
    pub configuration: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub async fn create_resource(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    validated_types::Validated(payload): validated_types::Validated<CreateResourceRequest>,
) -> Result<Json<CreateResourceResponse>, StatusCode> {
    tracing::info!("Creating resource for user_id: {}", auth.user_id);
    tracing::debug!("Resource payload: {:?}", payload);

    let org_id = match get_user_primary_org(&state.db, auth.user_id).await {
        Ok(id) => {
            tracing::debug!("Found primary org: {}", id);
            id
        }
        Err(e) => {
            tracing::error!("Failed to get primary org for user {}: {:?}", auth.user_id, e);
            return Err(e);
        }
    };

    let provider_account_id = match get_or_create_provider_account(&state.db, org_id).await {
        Ok(id) => {
            tracing::debug!("Provider account: {}", id);
            id
        }
        Err(e) => {
            tracing::error!("Failed to get/create provider account: {:?}", e);
            return Err(e);
        }
    };

    let resource_type_id = match get_or_create_resource_type(&state.db).await {
        Ok(id) => {
            tracing::debug!("Resource type: {}", id);
            id
        }
        Err(e) => {
            tracing::error!("Failed to get/create resource type: {:?}", e);
            return Err(e);
        }
    };

    let provider_resource_id = Uuid::new_v4().to_string();

    // Use provided name (typically from directory name) or generate one
    let resource_slug = if let Some(ref name) = payload.name {
        // Validate the app name
        if let Err(e) = validation::validate_app_name(name) {
            tracing::warn!("Invalid app name '{}': {}, falling back to auto-generated", name, e);
            format!("app-{}", &provider_resource_id[..8])
        } else {
            // Check if name is already taken in this organization
            let existing: Option<(Uuid,)> = sqlx::query_as(
                "SELECT id FROM compute_resources
                 WHERE organization_id = $1 AND resource_name = $2 AND destroyed_at IS NULL"
            )
            .bind(org_id)
            .bind(name)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                tracing::error!("Failed to check for existing resource name: {:?}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            if existing.is_some() {
                tracing::warn!("App name '{}' already exists, falling back to auto-generated", name);
                format!("app-{}", &provider_resource_id[..8])
            } else {
                name.clone()
            }
        }
    } else {
        format!("app-{}", &provider_resource_id[..8])
    };

    let configuration = serde_json::json!({
        "cmd": payload.cmd
    });

    tracing::debug!("Creating resource with slug: {}", resource_slug);

    let resource: (Uuid, types::ResourceState, DateTime<Utc>) = match sqlx::query_as(
        "INSERT INTO compute_resources
         (organization_id, provider_account_id, resource_type_id, provider_resource_id,
          resource_name, state, configuration, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING id, state, created_at"
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
    .await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Database error creating resource: {:?}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let (resource_id, resource_state, created_at) = resource;

    let git_url = match state.git_ssh_port {
        Some(port) => format!("ssh://git@{}:{}/{}.git", state.git_hostname, port, resource_id),
        None => format!("git@{}:{}.git", state.git_hostname, resource_id),
    };

    tracing::info!("Resource created successfully: id={}, name={}", resource_id, resource_slug);

    Ok(Json(CreateResourceResponse {
        id: resource_id,
        resource_name: resource_slug,
        git_url,
        state: resource_state.as_str().to_string(),
        created_at,
    }))
}

pub async fn list_resources(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
    let org_id = get_user_primary_org(&state.db, auth.user_id).await?;

    tracing::info!("Listing resources for user {} in org {}", auth.user_id, org_id);

    let resources = sqlx::query_as::<_, ComputeResource>(
        "SELECT id, organization_id, provider_account_id, resource_type_id,
                provider_resource_id, resource_name, state::text as state,
                region, public_ip, configuration->>'domain' as domain,
                billing_tag, configuration, created_at, updated_at
         FROM compute_resources
         WHERE organization_id = $1"
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to list resources: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::info!("Found {} resources", resources.len());

    let resources_with_git_url: Vec<serde_json::Value> = resources
        .into_iter()
        .map(|resource| {
            let git_url = match state.git_ssh_port {
                Some(port) => format!("ssh://git@{}:{}/{}.git", state.git_hostname, port, resource.id),
                None => format!("git@{}:{}.git", state.git_hostname, resource.id),
            };
            let mut value = serde_json::to_value(&resource).unwrap_or_default();
            if let Some(obj) = value.as_object_mut() {
                obj.insert("git_url".to_string(), serde_json::json!(git_url));
            }
            value
        })
        .collect();

    Ok(Json(resources_with_git_url))
}

pub async fn get_resource(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(resource_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let resource = sqlx::query_as::<_, ComputeResource>(
        "SELECT cr.id, cr.organization_id, cr.provider_account_id, cr.resource_type_id,
                cr.provider_resource_id, cr.resource_name, cr.state::text as state,
                cr.region, cr.public_ip, cr.configuration->>'domain' as domain,
                cr.billing_tag, cr.configuration, cr.created_at, cr.updated_at
         FROM compute_resources cr
         INNER JOIN organization_members om ON cr.organization_id = om.organization_id
         WHERE cr.id = $1 AND om.user_id = $2 AND cr.destroyed_at IS NULL"
    )
    .bind(resource_id)
    .bind(auth.user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::NOT_FOUND)?;

    let git_url = match state.git_ssh_port {
        Some(port) => format!("ssh://git@{}:{}/{}.git", state.git_hostname, port, resource_id),
        None => format!("git@{}:{}.git", state.git_hostname, resource_id),
    };

    let mut response = serde_json::to_value(&resource).unwrap_or_default();
    if let Some(obj) = response.as_object_mut() {
        obj.insert("git_url".to_string(), serde_json::json!(git_url));
    }

    Ok(Json(response))
}

pub async fn proxy_attestation(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(resource_id): Path<Uuid>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Get the resource to verify ownership and get the public IP + domain
    let resource: (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT cr.public_ip, cr.configuration->>'domain' as domain
         FROM compute_resources cr
         INNER JOIN organization_members om ON cr.organization_id = om.organization_id
         WHERE cr.id = $1 AND om.user_id = $2 AND cr.destroyed_at IS NULL"
    )
    .bind(resource_id)
    .bind(auth.user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| (StatusCode::NOT_FOUND, "Resource not found".to_string()))?;

    let public_ip = resource.0.ok_or_else(|| {
        (StatusCode::BAD_REQUEST, "Resource has no public IP".to_string())
    })?;

    // Create HTTP client that accepts self-signed certs (for IP fallback)
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create HTTP client: {}", e)))?;

    // Always use HTTPS — domain gets Let's Encrypt, IP gets self-signed cert
    // (danger_accept_invalid_certs handles the self-signed case)
    let attestation_url = if let Some(ref domain) = resource.1 {
        format!("https://{}/attestation", domain)
    } else {
        format!("https://{}/attestation", public_ip)
    };
    tracing::info!("Proxying attestation request to {}", attestation_url);

    let response = client
        .post(&attestation_url)
        .header("Content-Type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Attestation proxy request failed: {:?}", e);
            (StatusCode::BAD_GATEWAY, format!("Failed to reach attestation endpoint: {}", e))
        })?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        tracing::error!("Attestation endpoint returned error: {} - {}", status, body);
        return Err((StatusCode::BAD_GATEWAY, format!("Attestation endpoint error: {}", status)));
    }

    let json: serde_json::Value = response
        .json()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Invalid JSON from attestation endpoint: {}", e)))?;

    Ok(Json(json))
}

pub async fn rename_resource(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(resource_id): Path<Uuid>,
    validated_types::Validated(payload): validated_types::Validated<RenameResourceRequest>,
) -> Result<Json<ComputeResource>, (StatusCode, String)> {
    tracing::info!(
        "rename_resource: resource_id={}, user_id={}, new_name={}",
        resource_id, auth.user_id, payload.name
    );

    // Verify user has access to this resource via organization membership
    let resource: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT cr.organization_id, cr.resource_name
         FROM compute_resources cr
         INNER JOIN organization_members om ON cr.organization_id = om.organization_id
         WHERE cr.id = $1 AND om.user_id = $2 AND cr.destroyed_at IS NULL"
    )
    .bind(resource_id)
    .bind(auth.user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error in rename_resource: {:?}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string())
    })?;

    let Some((org_id, old_name)) = resource else {
        return Err((StatusCode::NOT_FOUND, "Resource not found".to_string()));
    };

    // Check if the new name is already taken within this organization (for active resources)
    let name_exists: Option<bool> = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM compute_resources
            WHERE organization_id = $1 AND resource_name = $2 AND destroyed_at IS NULL AND id != $3
        )"
    )
    .bind(org_id)
    .bind(&payload.name)
    .bind(resource_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error checking name uniqueness: {:?}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string())
    })?;

    if name_exists == Some(true) {
        return Err((
            StatusCode::CONFLICT,
            format!("An app with the name '{}' already exists in this organization", payload.name),
        ));
    }

    // Update the resource name
    let updated_resource = sqlx::query_as::<_, ComputeResource>(
        "UPDATE compute_resources
         SET resource_name = $1
         WHERE id = $2 AND organization_id = $3
         RETURNING id, organization_id, provider_account_id, resource_type_id,
                   provider_resource_id, resource_name, state::text as state,
                   region, public_ip, configuration->>'domain' as domain,
                   billing_tag, configuration, created_at, updated_at"
    )
    .bind(&payload.name)
    .bind(resource_id)
    .bind(org_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to update resource name: {:?}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Failed to rename resource".to_string())
    })?;

    // Rename the git repository if it exists
    let old_repo_path = format!("{}/git-repos/{}.git", state.data_dir, old_name);
    let new_repo_path = format!("{}/git-repos/{}.git", state.data_dir, payload.name);

    if tokio::fs::metadata(&old_repo_path).await.is_ok() {
        if let Err(e) = tokio::fs::rename(&old_repo_path, &new_repo_path).await {
            tracing::warn!(
                "Failed to rename git repo from {} to {}: {} (resource renamed in DB)",
                old_repo_path, new_repo_path, e
            );
        } else {
            tracing::info!("Renamed git repo from {} to {}", old_repo_path, new_repo_path);
        }
    }

    tracing::info!(
        "Resource {} renamed from '{}' to '{}' by user {}",
        resource_id, old_name, payload.name, auth.user_id
    );

    Ok(Json(updated_resource))
}

#[derive(Debug, Deserialize)]
pub struct DeleteResourceQuery {
    #[serde(default)]
    pub force: bool,
}

pub async fn delete_resource(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(resource_id): Path<Uuid>,
    query: axum::extract::Query<DeleteResourceQuery>,
) -> Result<StatusCode, StatusCode> {
    tracing::info!("delete_resource called: resource_id={}, user_id={}, force={}", resource_id, auth.user_id, query.force);

    tracing::debug!("Querying resource access for user {} on resource {}", auth.user_id, resource_id);
    let resource: Option<(Uuid, Uuid, String, Option<String>, String)> = sqlx::query_as(
        "SELECT cr.id, cr.organization_id, cr.resource_name, pa.role_arn, cr.provider_resource_id
         FROM compute_resources cr
         INNER JOIN organization_members om ON cr.organization_id = om.organization_id
         INNER JOIN provider_accounts pa ON cr.provider_account_id = pa.id
         WHERE cr.id = $1 AND om.user_id = $2 AND cr.destroyed_at IS NULL"
    )
    .bind(resource_id)
    .bind(auth.user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database query failed in delete_resource: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let Some((_, org_id, resource_name, _role_arn_opt, tracked_resource_id)) = resource else {
        tracing::warn!("Resource {} not found or user {} has no access", resource_id, auth.user_id);
        return Err(StatusCode::NOT_FOUND);
    };

    tracing::info!("Destroying resource {} (id: {})", resource_name, resource_id);

    let (aws_credentials, asg_name) = if let Some(encryptor) = state.encryptor.as_ref() {
        if let Ok(Some(credential)) = cloud_credentials::get_credential_by_resource(&state.db, org_id, resource_id).await {
            if credential.managed_on_prem {
                if let Ok(Some(secrets)) = cloud_credentials::get_credential_secrets(&state.db, encryptor, org_id, credential.id).await {
                    let region = credential.config["aws_region"].as_str()
                        .map(|s| s.to_string())
                        .or_else(|| std::env::var("AWS_REGION").ok())
                        .unwrap_or_else(|| "us-west-2".to_string());
                    let asg = credential.config["asg_name"].as_str()
                        .map(|s| s.to_string());
                    (Some(deployment::AwsCredentials {
                        access_key_id: secrets["aws_access_key_id"].as_str().unwrap_or("").to_string(),
                        secret_access_key: secrets["aws_secret_access_key"].as_str().unwrap_or("").to_string(),
                        region,
                    }), asg)
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            }
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    let terraform_result = deployment::destroy_app_with_credentials(org_id, resource_id, resource_name.clone(), aws_credentials, asg_name).await;

    if let Err(ref e) = terraform_result {
        tracing::error!("Terraform destroy failed for resource {}: {}", resource_id, e);
        if !query.force {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        tracing::warn!("Force flag set - marking resource as destroyed despite Terraform failure. AWS resources may still exist!");
    }

    sqlx::query(
        "UPDATE compute_resources
         SET destroyed_at = NOW(), state = $1
         WHERE id = $2 AND organization_id = $3"
    )
    .bind(types::ResourceState::Terminated)
    .bind(resource_id)
    .bind(org_id)
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Stop metering for the destroyed resource
    match crate::metering::stop_tracked_resource(
        state.internal_service_secret.as_deref(),
        &tracked_resource_id,
    )
    .await {
        Ok(()) => {
            tracing::info!("Stopped metering for resource {}", resource_id);
        }
        Err(e) => {
            tracing::error!(
                "Failed to stop metering for resource {} via metering service: {}",
                resource_id,
                e
            );
            let _ = sqlx::query(
                "UPDATE tracked_resources SET status = 'stopped', stopped_at = NOW() WHERE resource_id = $1 AND status = 'running'"
            )
            .bind(&tracked_resource_id)
            .execute(&state.db)
            .await;
        }
    }

    tracing::info!("Resource {} terminated by user {} (git repo preserved for redeployment)", resource_id, auth.user_id);

    Ok(StatusCode::NO_CONTENT)
}
