// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    extract::{Extension, Path, State, Request},
    http::{StatusCode, HeaderMap},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, patch, delete},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool, FromRow};
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::info;
use chrono::{DateTime, Utc, NaiveDateTime};
use uuid::Uuid;
use enclave_builder::{BuildConfig as DockerBuildConfig, build_user_image};

mod provisioning;
mod deployment;
mod validation;
mod validated_types;
mod onboarding;
mod types;
mod errors;
mod encryption;
mod cloud_credentials;

#[derive(Clone)]
struct AppState {
    db: PgPool,
    git_hostname: String,
    git_ssh_port: Option<u16>,
    data_dir: String,
    encryptor: Option<Arc<encryption::Encryptor>>,
    internal_service_secret: Option<String>,
}

#[derive(Clone)]
struct AuthContext {
    user_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
struct User {
    id: Uuid,
    username: String,
    email: Option<String>,
    is_active: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

use validated_types::UpdateUserRequest;

#[derive(Debug, Serialize, Deserialize, FromRow)]
struct Organization {
    id: Uuid,
    name: String,
    is_active: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

use validated_types::{CreateOrganizationRequest, UpdateOrganizationRequest};

#[derive(Debug, Serialize, FromRow)]
struct OrganizationMember {
    id: Uuid,
    organization_id: Uuid,
    user_id: Uuid,
    role: String,
    joined_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

use validated_types::{AddMemberRequest, UpdateMemberRequest};

#[derive(Debug, Serialize, FromRow)]
struct ComputeResource {
    id: Uuid,
    organization_id: Uuid,
    provider_account_id: Uuid,
    resource_type_id: Uuid,
    provider_resource_id: String,
    resource_name: Option<String>,
    state: String,
    region: Option<String>,
    public_ip: Option<String>,
    domain: Option<String>,
    billing_tag: Option<String>,
    configuration: Option<serde_json::Value>,
    created_at: chrono::NaiveDateTime,
    updated_at: chrono::NaiveDateTime,
}

use validated_types::{CreateResourceRequest, CreateResourceResponse, RenameResourceRequest};
use validated_types::{DeployRequest, DeployResponse};

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    // Internal service authentication requires BOTH the user ID AND a valid secret
    // This prevents external callers from bypassing authentication by providing the header
    if let Some(user_id_str) = headers.get("x-authenticated-user-id").and_then(|h| h.to_str().ok()) {
        let provided_secret = headers.get("x-internal-service-secret").and_then(|h| h.to_str().ok());

        // Only accept internal service auth if a secret is configured AND it matches
        if let Some(ref configured_secret) = state.internal_service_secret {
            if provided_secret == Some(configured_secret.as_str()) {
                if let Ok(user_id) = Uuid::parse_str(user_id_str) {
                    tracing::debug!("Auth middleware: internal service auth for user_id={}", user_id);
                    request.extensions_mut().insert(AuthContext { user_id });
                    return Ok(next.run(request).await);
                }
            } else {
                tracing::warn!("Auth middleware: internal service auth attempted with invalid or missing secret");
            }
        } else {
            tracing::warn!("Auth middleware: internal service auth attempted but no secret configured");
        }
    }

    let Some(session_id) = headers.get("x-session-id").and_then(|h| h.to_str().ok()) else {
        tracing::debug!("Auth middleware: no authentication header provided");
        return Err((StatusCode::UNAUTHORIZED, "No authentication provided".to_string()));
    };

    tracing::debug!("Auth middleware: validating session {}", session_id);
    let user_id = validate_session(&state.db, session_id).await.map_err(|status| {
        let msg = match status {
            StatusCode::UNAUTHORIZED => "Invalid or expired session".to_string(),
            _ => "Authentication failed".to_string(),
        };
        (status, msg)
    })?;
    tracing::debug!("Session validated: user_id={}", user_id);

    request.extensions_mut().insert(AuthContext { user_id });
    Ok(next.run(request).await)
}

async fn onboarding_middleware(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    ensure_user_has_org(&state.db, auth.user_id).await?;

    request.extensions_mut().insert(auth);
    Ok(next.run(request).await)
}

async fn validate_session(db: &PgPool, session_id: &str) -> Result<Uuid, StatusCode> {
    let result: Option<(Uuid,)> = sqlx::query_as(
        "SELECT u.id
         FROM auth_sessions s
         INNER JOIN fido2_credentials c ON s.credential_id = c.credential_id
         INNER JOIN users u ON c.user_id = u.id
         WHERE s.session_id = $1 AND s.expires_at > NOW()"
    )
    .bind(session_id)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        tracing::error!("Session validation query failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    result.map(|(user_id,)| user_id).ok_or_else(|| {
        tracing::warn!("Invalid or expired session: {}", session_id);
        StatusCode::UNAUTHORIZED
    })
}

async fn ensure_user_has_org(db: &PgPool, user_id: Uuid) -> Result<(), StatusCode> {
    tracing::debug!("ensure_user_has_org: checking user {}", user_id);

    let is_onboarded = onboarding::check_onboarding_status(db, user_id).await?;

    if !is_onboarded {
        tracing::warn!("User {} has not completed onboarding", user_id);
        return Err(StatusCode::PAYMENT_REQUIRED);
    }

    let has_org: Option<(uuid::Uuid,)> = sqlx::query_as(
        "SELECT organization_id FROM organization_members WHERE user_id = $1 LIMIT 1"
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to check user org membership: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if has_org.is_some() {
        tracing::debug!("User {} already has organization", user_id);
        return Ok(());
    }

    tracing::info!("User {} has no organization, initializing new account", user_id);

    provisioning::initialize_user_account(db, user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to initialize user account: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::info!("Successfully initialized account for user {}", user_id);
    Ok(())
}

async fn check_org_access(
    db: &PgPool,
    user_id: Uuid,
    org_id: Uuid,
) -> Result<types::UserRole, StatusCode> {
    let member: Option<(types::UserRole,)> = sqlx::query_as(
        "SELECT role FROM organization_members
         WHERE organization_id = $1 AND user_id = $2"
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    member.map(|m| m.0).ok_or(StatusCode::FORBIDDEN)
}

fn can_manage_org(role: &types::UserRole) -> bool {
    role.can_manage_org()
}

fn is_owner(role: &types::UserRole) -> bool {
    role.is_owner()
}

async fn get_user_primary_org(db: &PgPool, user_id: Uuid) -> Result<Uuid, StatusCode> {
    let org_id: Option<(Uuid,)> = sqlx::query_as(
        "SELECT organization_id FROM organization_members
         WHERE user_id = $1
         ORDER BY created_at ASC
         LIMIT 1"
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    org_id.map(|o| o.0).ok_or(StatusCode::NOT_FOUND)
}

async fn get_or_create_provider_account(
    db: &PgPool,
    org_id: Uuid,
) -> Result<Uuid, StatusCode> {
    let aws_account_id = std::env::var("AWS_ACCOUNT_ID")
        .map_err(|_| {
            tracing::error!("AWS_ACCOUNT_ID environment variable not set");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let existing: Option<(Uuid, Option<String>, Option<bool>)> = sqlx::query_as(
        "SELECT pa.id, pa.role_arn, pa.is_active FROM provider_accounts pa
         JOIN providers p ON pa.provider_id = p.id
         WHERE pa.organization_id = $1 AND p.provider_type = 'aws'
         LIMIT 1"
    )
    .bind(org_id)
    .fetch_optional(db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Some((id, role_arn, is_active)) = existing {
        if role_arn.is_none() || is_active != Some(true) {
            let role_arn = format!("arn:aws:iam::{}:role/OrganizationAccountAccessRole", aws_account_id);

            sqlx::query(
                "UPDATE provider_accounts
                 SET role_arn = $1, is_active = true, external_account_id = $2
                 WHERE id = $3"
            )
            .bind(&role_arn)
            .bind(&aws_account_id)
            .bind(id)
            .execute(db)
            .await
            .map_err(|e| {
                tracing::error!("Failed to update provider account: {:?}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            tracing::info!("Updated provider account {} for org {}", id, org_id);
        }
        return Ok(id);
    }

    let role_arn = format!("arn:aws:iam::{}:role/OrganizationAccountAccessRole", aws_account_id);

    let account_id: (Uuid,) = sqlx::query_as(
        "INSERT INTO provider_accounts
         (organization_id, provider_id, external_account_id, account_name, role_arn, is_active)
         VALUES ($1, (SELECT id FROM providers WHERE provider_type = 'aws'), $2, $3, $4, true)
         RETURNING id"
    )
    .bind(org_id)
    .bind(&aws_account_id)
    .bind(format!("AWS Account {}", aws_account_id))
    .bind(&role_arn)
    .fetch_one(db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to create provider account: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::info!("Created provider account {} for org {} using AWS account {}", account_id.0, org_id, aws_account_id);

    Ok(account_id.0)
}

async fn get_or_create_resource_type(db: &PgPool) -> Result<Uuid, StatusCode> {
    let existing: Option<(Uuid,)> = sqlx::query_as(
        "SELECT rt.id FROM resource_types rt
         JOIN providers p ON rt.provider_id = p.id
         WHERE p.provider_type = 'aws' AND rt.type_code = $1
         LIMIT 1"
    )
    .bind(types::AWSResourceType::EC2Instance.as_str())
    .fetch_optional(db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Some((id,)) = existing {
        return Ok(id);
    }

    let type_id: (Uuid,) = sqlx::query_as(
        "INSERT INTO resource_types
         (provider_id, type_code, display_name, category)
         VALUES ((SELECT id FROM providers WHERE provider_type = 'aws'), $1, 'EC2 Instance', 'compute')
         RETURNING id"
    )
    .bind(types::AWSResourceType::EC2Instance.as_str())
    .fetch_one(db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(type_id.0)
}

async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn wait_for_attestation_health(public_ip: &str, timeout_secs: u64) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let url = format!("http://{}/attestation", public_ip);
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_secs);
    let mut attempt = 0u32;

    loop {
        attempt += 1;
        tracing::info!("Polling attestation endpoint (attempt {}): {}", attempt, url);

        let nonce: [u8; 32] = [0; 32];
        let result = client
            .post(&url)
            .json(&serde_json::json!({"nonce": nonce}))
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!("Attestation endpoint is healthy after {} attempts", attempt);
                return Ok(());
            }
            Ok(resp) => {
                tracing::debug!("Attestation endpoint returned {}, retrying...", resp.status());
            }
            Err(e) => {
                tracing::debug!("Attestation endpoint not ready: {}", e);
            }
        }

        if start.elapsed() >= timeout {
            return Err(format!(
                "Attestation endpoint did not become healthy within {} seconds",
                timeout_secs
            ));
        }

        let delay = std::cmp::min(2u64.pow(attempt.min(4)), 30);
        tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
    }
}

async fn get_current_user(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<User>, StatusCode> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, username, email, is_active, created_at, updated_at 
         FROM users WHERE id = $1"
    )
    .bind(auth.user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(Json(user))
}

async fn update_current_user(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    validated_types::Validated(payload): validated_types::Validated<UpdateUserRequest>,
) -> Result<Json<User>, StatusCode> {
    if payload.username.is_none() && payload.email.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut query_builder = sqlx::QueryBuilder::new("UPDATE users SET ");
    let mut has_updates = false;

    if let Some(username) = &payload.username {
        if has_updates {
            query_builder.push(", ");
        }
        query_builder.push("username = ");
        query_builder.push_bind(username);
        has_updates = true;
    }

    if let Some(email) = &payload.email {
        if has_updates {
            query_builder.push(", ");
        }
        query_builder.push("email = ");
        query_builder.push_bind(email);
        has_updates = true;
    }

    query_builder.push(" WHERE id = ");
    query_builder.push_bind(auth.user_id);
    query_builder.push(" RETURNING id, username, email, is_active, created_at, updated_at");

    let user = query_builder
        .build_query_as::<User>()
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(user))
}

async fn delete_current_user(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<StatusCode, StatusCode> {
    sqlx::query("UPDATE users SET is_active = false WHERE id = $1")
        .bind(auth.user_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}

async fn list_organizations(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<Organization>>, StatusCode> {
    let orgs = sqlx::query_as::<_, Organization>(
        "SELECT o.id, o.name, o.slug, o.is_active, o.created_at, o.updated_at 
         FROM organizations o
         INNER JOIN organization_members om ON o.id = om.organization_id
         WHERE om.user_id = $1"
    )
    .bind(auth.user_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(orgs))
}

async fn create_organization(
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

async fn get_organization(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(org_id): Path<Uuid>,
) -> Result<Json<Organization>, StatusCode> {
    check_org_access(&state.db, auth.user_id, org_id).await?;

    let org = sqlx::query_as::<_, Organization>(
        "SELECT id, name, slug, is_active, created_at, updated_at 
         FROM organizations WHERE id = $1"
    )
    .bind(org_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(Json(org))
}

async fn update_organization(
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

async fn delete_organization(
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

async fn list_members(
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

async fn add_member(
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

async fn update_member(
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

async fn remove_member(
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

async fn get_commit_sha(app_name: &str, branch: &str, data_dir: &str) -> Result<String, Box<dyn std::error::Error>> {
    use tokio::process::Command;

    let repo_path = format!("{}/git-repos/{}.git", data_dir, app_name);
    let ref_spec = format!("refs/heads/{}", branch);

    let output = Command::new("git")
        .args(&["--git-dir", &repo_path, "rev-parse", &ref_spec])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to get commit SHA for branch '{}': {}", branch, stderr).into());
    }

    let commit_sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(commit_sha)
}

async fn build_image_from_repo(
    app_name: &str,
    build_config: &types::BuildConfig,
    image_name: &str,
    branch: &str,
    data_dir: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use tokio::fs;
    use tokio::process::Command;

    let repo_path = format!("{}/git-repos/{}.git", data_dir, app_name);
    let work_dir = format!("{}/build/{}-build", data_dir, app_name);

    tracing::info!("Cloning repository from {} to {} (branch: {})", repo_path, work_dir, branch);

    fs::create_dir_all(format!("{}/build", data_dir)).await?;

    let _ = fs::remove_dir_all(&work_dir).await;

    let _ = Command::new("git")
        .args(&["config", "--global", "--add", "safe.directory", &repo_path])
        .output()
        .await;

    let output = Command::new("git")
        .args(&["clone", "--branch", branch, &repo_path, &work_dir])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Git clone failed: {}", stderr).into());
    }

    tracing::info!("Successfully cloned repository (branch: {})", branch);

    let commit_output = Command::new("git")
        .args(&["rev-parse", "HEAD"])
        .current_dir(&work_dir)
        .output()
        .await?;

    let commit_sha = if commit_output.status.success() {
        String::from_utf8_lossy(&commit_output.stdout).trim().to_string()
    } else {
        "unknown".to_string()
    };

    tracing::info!("Building commit: {}", commit_sha);

    // Use shared build logic from enclave-builder
    let docker_config = DockerBuildConfig {
        build_command: build_config.build.clone(),
        containerfile: build_config.containerfile.clone(),
        oci_tarball: build_config.oci_tarball.clone(),
        no_cache: build_config.no_cache,
    };

    let work_dir_path = std::path::PathBuf::from(&work_dir);

    // Build the Docker image (now async)
    build_user_image(&work_dir_path, image_name, &docker_config)
        .await
        .map_err(|e| format!("Build failed: {}", e))?;

    tracing::info!("Image built and tagged as {}", image_name);

    Ok(commit_sha)
}

async fn export_image_to_tarball(
    image_name: &str,
    tarball_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use tokio::process::Command;
    use tokio::fs;

    tracing::info!("Exporting image {} to {}", image_name, tarball_path);

    if let Some(parent) = std::path::Path::new(tarball_path).parent() {
        fs::create_dir_all(parent).await?;
    }

    let output = Command::new("docker")
        .args(&["save", "-o", tarball_path, image_name])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Docker save failed: {}", stderr).into());
    }

    Ok(())
}

async fn create_ami_from_image(
    app_name: &str,
    image_tarball: &str,
    aws_region: &str,
    _role_arn: Option<&str>,
    data_dir: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use tokio::fs;
    use tokio::process::Command;

    let packer_dir = format!("{}/build/{}-packer", data_dir, app_name);
    let _ = fs::remove_dir_all(&packer_dir).await;
    fs::create_dir_all(&packer_dir).await?;

    let packer_template = format!(
        r#"{{
  "variables": {{
    "aws_region": "{}",
    "app_name": "{}",
    "image_tarball": "{}"
  }},
  "builders": [
    {{
      "type": "amazon-ebs",
      "region": "{{{{ user `aws_region` }}}}",
      "source_ami_filter": {{
        "filters": {{
          "name": "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*",
          "root-device-type": "ebs",
          "virtualization-type": "hvm"
        }},
        "owners": ["099720109477"],
        "most_recent": true
      }},
      "instance_type": "t3.small",
      "ssh_username": "ubuntu",
      "ami_name": "caution-{{{{ user `app_name` }}}}-{{{{timestamp}}}}",
      "ami_description": "Caution app: {{{{ user `app_name` }}}}",
      "tags": {{
        "Name": "caution-{{{{ user `app_name` }}}}",
        "ManagedBy": "Caution",
        "AppName": "{{{{ user `app_name` }}}}"
      }}
    }}
  ],
  "provisioners": [
    {{
      "type": "shell",
      "inline": [
        "sleep 5",
        "sudo rm -rf /var/lib/apt/lists/*",
        "sudo apt-get clean",
        "sudo apt-get update -y || (sleep 5 && sudo apt-get update -y)",
        "sudo apt-get install -y containerd",
        "sudo systemctl enable containerd",
        "sudo systemctl start containerd"
      ]
    }},
    {{
      "type": "file",
      "source": "{{{{ user `image_tarball` }}}}",
      "destination": "/tmp/app.tar"
    }},
    {{
      "type": "shell",
      "inline": [
        "sudo ctr -n default images import /tmp/app.tar",
        "sudo ctr -n default images list",
        "sudo rm /tmp/app.tar"
      ]
    }},
    {{
      "type": "shell",
      "inline": [
        "cat <<'EOF' | sudo tee /etc/systemd/system/caution-app.service",
        "[Unit]",
        "Description=Caution Application Container",
        "After=containerd.service",
        "Requires=containerd.service",
        "",
        "[Service]",
        "Type=simple",
        "ExecStartPre=/usr/bin/ctr -n default images list",
        "ExecStart=/bin/sh -c '/usr/bin/ctr -n default run --rm --net-host $(/usr/bin/ctr -n default images list -q | head -1) caution-app'",
        "Restart=always",
        "RestartSec=10",
        "",
        "[Install]",
        "WantedBy=multi-user.target",
        "EOF",
        "sudo systemctl enable caution-app.service"
      ]
    }}
  ]
}}"#,
        aws_region, app_name, image_tarball
    );

    let template_path = format!("{}/template.json", packer_dir);
    fs::write(&template_path, packer_template.clone()).await?;

    tracing::info!("Running Packer to create AMI for {}", app_name);
    tracing::debug!("Packer template:\n{}", packer_template);
    tracing::debug!("Packer template path: {}", template_path);
    tracing::debug!("Packer working directory: {}", packer_dir);

    match Command::new("packer").arg("version").output().await {
        Ok(version_output) => {
            let version = String::from_utf8_lossy(&version_output.stdout);
            tracing::info!("Packer version: {}", version.trim());
        }
        Err(e) => {
            tracing::warn!("Failed to get Packer version: {}", e);
        }
    }

    match Command::new("packer").args(&["plugins", "installed"]).output().await {
        Ok(plugins_output) => {
            let plugins_stdout = String::from_utf8_lossy(&plugins_output.stdout);
            let plugins_stderr = String::from_utf8_lossy(&plugins_output.stderr);
            tracing::info!("Packer plugins installed:\nstdout: {}\nstderr: {}", plugins_stdout.trim(), plugins_stderr.trim());
        }
        Err(e) => {
            tracing::warn!("Failed to list Packer plugins: {}", e);
        }
    }

    tracing::info!("Installing Packer Amazon plugin");
    match Command::new("packer")
        .args(&["plugins", "install", "github.com/hashicorp/amazon"])
        .output()
        .await
    {
        Ok(install_output) => {
            let install_stdout = String::from_utf8_lossy(&install_output.stdout);
            let install_stderr = String::from_utf8_lossy(&install_output.stderr);
            tracing::info!("Packer plugin install output:\nstdout: {}\nstderr: {}", install_stdout.trim(), install_stderr.trim());
            if !install_output.status.success() && !install_stderr.contains("already installed") {
                tracing::warn!("Plugin installation returned non-zero exit, but continuing: {}", install_stderr);
            }
        }
        Err(e) => {
            tracing::warn!("Failed to install packer plugin (may already be installed): {}", e);
        }
    }

    let mut cmd = Command::new("packer");
    cmd.args(&["build", "-force", &template_path])
        .env("AWS_REGION", aws_region)
        .current_dir(&packer_dir);

    let has_access_key = std::env::var("AWS_ACCESS_KEY_ID").is_ok();
    let has_secret_key = std::env::var("AWS_SECRET_ACCESS_KEY").is_ok();

    tracing::info!("AWS credentials available: access_key={}, secret_key={}", has_access_key, has_secret_key);

    if let Ok(access_key) = std::env::var("AWS_ACCESS_KEY_ID") {
        cmd.env("AWS_ACCESS_KEY_ID", access_key);
        tracing::debug!("Set AWS_ACCESS_KEY_ID environment variable");
    }
    if let Ok(secret_key) = std::env::var("AWS_SECRET_ACCESS_KEY") {
        cmd.env("AWS_SECRET_ACCESS_KEY", secret_key);
        tracing::debug!("Set AWS_SECRET_ACCESS_KEY environment variable");
    }

    tracing::info!("Executing packer command: packer build -force {}", template_path);

    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn()?;
    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let stderr = child.stderr.take().expect("Failed to capture stderr");

    let stdout_task = tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();
        let mut all_output = String::new();

        while let Ok(Some(line)) = lines.next_line().await {
            tracing::info!("Packer stdout: {}", line);
            all_output.push_str(&line);
            all_output.push('\n');
        }
        all_output
    });

    let stderr_task = tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let reader = BufReader::new(stderr);
        let mut lines = reader.lines();
        let mut all_output = String::new();

        while let Ok(Some(line)) = lines.next_line().await {
            tracing::warn!("Packer stderr: {}", line);
            all_output.push_str(&line);
            all_output.push('\n');
        }
        all_output
    });

    let status = child.wait().await?;
    let stdout_output = stdout_task.await.unwrap_or_default();
    let stderr_output = stderr_task.await.unwrap_or_default();

    if !status.success() {
        tracing::error!("Packer build failed with exit code: {:?}", status.code());
        tracing::error!("Full stdout:\n{}", stdout_output);
        tracing::error!("Full stderr:\n{}", stderr_output);
        return Err(format!("Packer build failed: {}", stderr_output).into());
    }

    tracing::info!("Packer build completed successfully");
    tracing::debug!("Packer full output: {}", stdout_output);

    fn strip_ansi_codes(s: &str) -> String {
        let re = regex::Regex::new(r"\x1b\[[0-9;]*m").unwrap();
        re.replace_all(s, "").to_string()
    }

    let clean_output = strip_ansi_codes(&stdout_output);
    tracing::debug!("Clean Packer output (first 500 chars): {}", &clean_output.chars().take(500).collect::<String>());

    let ami_id = clean_output
        .lines()
        .rev()
        .find(|line| {
            (line.contains("us-west-2:") || line.contains("AMI:")) && line.contains("ami-")
        })
        .and_then(|line| {
            tracing::debug!("Found AMI line: {}", line);
            line.split_whitespace()
                .find(|s| s.starts_with("ami-"))
        })
        .ok_or_else(|| {
            tracing::error!("Could not find created AMI ID in Packer output. Full output:\n{}", clean_output);
            "Could not find created AMI ID in Packer output"
        })?
        .to_string();

    tracing::info!("Created AMI: {}", ami_id);

    Ok(ami_id)
}

async fn create_resource(
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

    let resource_slug = payload.name.unwrap_or_else(|| format!("app-{}", &provider_resource_id[..8]));

    let configuration = serde_json::json!({
        "cmd": payload.cmd
    });

    tracing::debug!("Creating resource with slug: {}", resource_slug);

    let resource: (Uuid, types::ResourceState, NaiveDateTime) = match sqlx::query_as(
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
    .bind(types::ResourceState::Pending)
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

async fn list_resources(
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
         WHERE organization_id = $1 AND destroyed_at IS NULL"
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

async fn get_resource(
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

async fn rename_resource(
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
         WHERE id = $2
         RETURNING id, organization_id, provider_account_id, resource_type_id,
                   provider_resource_id, resource_name, state::text as state,
                   region, public_ip, configuration->>'domain' as domain,
                   billing_tag, configuration, created_at, updated_at"
    )
    .bind(&payload.name)
    .bind(resource_id)
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
struct DeleteResourceQuery {
    #[serde(default)]
    force: bool,
}

async fn delete_resource(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(resource_id): Path<Uuid>,
    query: axum::extract::Query<DeleteResourceQuery>,
) -> Result<StatusCode, StatusCode> {
    tracing::info!("delete_resource called: resource_id={}, user_id={}, force={}", resource_id, auth.user_id, query.force);

    tracing::debug!("Querying resource access for user {} on resource {}", auth.user_id, resource_id);
    let resource: Option<(Uuid, Uuid, String, Option<String>)> = sqlx::query_as(
        "SELECT cr.id, cr.organization_id, cr.resource_name, pa.role_arn
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

    let Some((_, org_id, resource_name, _role_arn_opt)) = resource else {
        tracing::warn!("Resource {} not found or user {} has no access", resource_id, auth.user_id);
        return Err(StatusCode::NOT_FOUND);
    };

    tracing::info!("Destroying resource {} (id: {})", resource_name, resource_id);

    let terraform_result = deployment::destroy_app(org_id, resource_id, resource_name.clone()).await;

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
         WHERE id = $2"
    )
    .bind(types::ResourceState::Terminated)
    .bind(resource_id)
    .execute(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tracing::info!("Resource {} terminated by user {} (git repo preserved for redeployment)", resource_id, auth.user_id);

    Ok(StatusCode::NO_CONTENT)
}

async fn list_cloud_credentials(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<cloud_credentials::CloudCredential>>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let credentials = cloud_credentials::list_credentials(&state.db, org_id).await?;
    Ok(Json(credentials))
}

async fn create_cloud_credential(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<cloud_credentials::CreateCredentialRequest>,
) -> Result<Json<cloud_credentials::CloudCredential>, (StatusCode, String)> {
    let encryptor = state.encryptor.as_ref()
        .ok_or((StatusCode::SERVICE_UNAVAILABLE, "Cloud credentials feature not configured. Set CAUTION_ENCRYPTION_KEY.".to_string()))?;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let credential = cloud_credentials::create_credential(&state.db, encryptor, org_id, auth.user_id, req).await?;
    Ok(Json(credential))
}

async fn get_cloud_credential(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(credential_id): Path<Uuid>,
) -> Result<Json<cloud_credentials::CloudCredential>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let credential = cloud_credentials::get_credential(&state.db, org_id, credential_id)
        .await?
        .ok_or((StatusCode::NOT_FOUND, "Credential not found".to_string()))?;

    Ok(Json(credential))
}

async fn delete_cloud_credential(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(credential_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let deleted = cloud_credentials::delete_credential(&state.db, org_id, credential_id).await?;

    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((StatusCode::NOT_FOUND, "Credential not found".to_string()))
    }
}

async fn set_default_cloud_credential(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(credential_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let updated = cloud_credentials::set_default_credential(&state.db, org_id, credential_id).await?;

    if updated {
        Ok(StatusCode::OK)
    } else {
        Err((StatusCode::NOT_FOUND, "Credential not found".to_string()))
    }
}

async fn deploy_handler(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    validated_types::Validated(req): validated_types::Validated<DeployRequest>,
) -> Result<Json<DeployResponse>, (StatusCode, String)> {
    use tokio::process::Command;

    tracing::info!(
        "Deployment request: user_id={}, org_id={}, app_id={}",
        auth.user_id,
        req.org_id,
        req.app_id
    );

    let app_id_str = req.app_id.to_string();

    let user_in_org: Option<bool> = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM organization_members 
            WHERE user_id = $1 AND organization_id = $2
        )"
    )
    .bind(auth.user_id)
    .bind(req.org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;
    
    if user_in_org != Some(true) {
        return Err((
            StatusCode::FORBIDDEN,
            "User does not belong to this organization".to_string(),
        ));
    }

    tracing::info!("Fetching provider account for org {}", req.org_id);
    let provider_account: Option<(Uuid, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT id, external_account_id, role_arn
         FROM provider_accounts
         WHERE organization_id = $1 AND is_active = true
         LIMIT 1"
    )
    .bind(req.org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to fetch provider account: {:?}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error fetching provider account: {}", e))
    })?;

    tracing::info!("Provider account query result: {:?}", provider_account);

    let (provider_account_id, aws_account_id_opt, role_arn_opt) = provider_account
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "No active provider account found".to_string()))?;

    tracing::info!("Provider account details: id={}, aws_account_id={:?}, role_arn={:?}",
                   provider_account_id, aws_account_id_opt, role_arn_opt);

    let aws_account_id = aws_account_id_opt
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Provider account has no AWS account ID configured".to_string()))?;

    if let Some(ref role_arn) = role_arn_opt {
        tracing::info!("Deploying to AWS account {} via role {}", aws_account_id, role_arn);
    } else {
        tracing::info!("Deploying to root AWS account {} (no role assumption)", aws_account_id);
    }

    tracing::info!("Fetching resource type for EC2Instance");
    let resource_type_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM resource_types WHERE type_code = $1 LIMIT 1"
    )
    .bind(types::AWSResourceType::EC2Instance.as_str())
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get resource type: {}", e)))?;

    tracing::info!("Looking up resource by id={}", req.app_id);
    let existing_resource: Option<(Uuid, Option<String>, Option<serde_json::Value>, Option<chrono::NaiveDateTime>)> = sqlx::query_as(
        "SELECT id, resource_name, configuration, destroyed_at FROM compute_resources
         WHERE id = $1 AND organization_id = $2"
    )
    .bind(req.app_id)
    .bind(req.org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to check existing resource: {:?}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error checking existing resource: {}", e))
    })?;

    let (resource_id, app_name, configuration, was_destroyed) = match &existing_resource {
        Some((id, name_opt, config_opt, destroyed_at)) => {
            let name = name_opt.clone().unwrap_or_else(|| "unnamed".to_string());
            let config = config_opt.clone().unwrap_or_else(|| serde_json::json!({}));
            (*id, name, config, destroyed_at.is_some())
        }
        None => return Err((StatusCode::NOT_FOUND, format!("App with id {} not found", req.app_id))),
    };

    if was_destroyed {
        tracing::info!("Reactivating previously destroyed resource {}", resource_id);
        sqlx::query("UPDATE compute_resources SET destroyed_at = NULL, state = $1 WHERE id = $2")
            .bind(types::ResourceState::Pending)
            .bind(resource_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to reactivate resource: {}", e)))?;
    }

    tracing::info!("Found resource: id={}, name={}", resource_id, app_name);
    tracing::info!("Deploying branch: {}", req.branch);

    let commit_sha = match get_commit_sha(&app_id_str, &req.branch, &state.data_dir).await {
        Ok(sha) => {
            tracing::info!("Latest commit on branch '{}': {}", req.branch, sha);
            sha
        }
        Err(e) => {
            tracing::error!("Failed to get commit SHA for branch '{}': {:?}", req.branch, e);
            return Err((StatusCode::BAD_REQUEST, format!("Failed to get commit SHA for branch '{}': {}", req.branch, e)));
        }
    };

    let git_dir = format!("{}/git-repos/{}.git", state.data_dir, app_id_str);
    let procfile_output = Command::new("git")
        .args(&["--git-dir", &git_dir, "show", &format!("{}:Procfile", commit_sha)])
        .output()
        .await
        .map_err(|e| {
            tracing::error!("Failed to run git show for Procfile: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Git command failed: {}", e))
        })?;

    let build_config = if procfile_output.status.success() {
        let content = String::from_utf8_lossy(&procfile_output.stdout);
        match types::BuildConfig::from_procfile(&content) {
            Ok(config) => {
                tracing::info!("Loaded build config from Procfile: containerfile={:?}, binary={:?}, build={:?}, oci_tarball={:?}",
                               config.containerfile, config.binary, config.build, config.oci_tarball);
                config
            }
            Err(e) => {
                tracing::error!("Failed to parse Procfile: {}", e);
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("Invalid Procfile: {}", e),
                ));
            }
        }
    } else {
        tracing::error!("Procfile not found in repository at commit {}", commit_sha);
        return Err((
            StatusCode::BAD_REQUEST,
            "No Procfile found in repository root. Please add a Procfile with 'containerfile', 'binary', and 'run' fields.".to_string(),
        ));
    };

    // Get build command from the resource configuration
    let build_command = configuration.get("cmd")
        .and_then(|v| v.as_str())
        .unwrap_or("docker build -t app .")
        .to_string();
    tracing::info!("Using resource {} with build command: {}", resource_id, build_command);

    tracing::info!("Build command for {}: {}", app_name, build_command);

    let cache_dir = format!("{}/build/{}", state.data_dir, req.org_id);
    let cache_dir_str = cache_dir.clone();
    tokio::fs::create_dir_all(&cache_dir).await.map_err(|e| {
        tracing::error!("Failed to create cache directory: {:?}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create cache directory: {}", e))
    })?;

    let image_tarball = format!("{}/{}-{}.tar", cache_dir_str, app_id_str, commit_sha);
    let tarball_exists = tokio::fs::metadata(&image_tarball).await.is_ok() && !build_config.no_cache;

    let image_name = format!("caution-{}:{}", app_id_str, &commit_sha[..12]);

    if build_config.no_cache {
        tracing::info!("Cache disabled (no_cache=true), forcing rebuild");
    }

    if tarball_exists {
        tracing::info!("Cache HIT: Using cached tarball for commit {}", commit_sha);

        tracing::info!("Loading cached image into Docker: {}", image_name);
        let load_output = Command::new("docker")
            .args(&["load", "-i", &image_tarball])
            .output()
            .await
            .map_err(|e| {
                tracing::error!("Failed to load cached image: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load cached image: {}", e))
            })?;

        if !load_output.status.success() {
            let stderr = String::from_utf8_lossy(&load_output.stderr);
            tracing::error!("Docker load failed: {}", stderr);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load cached image: {}", stderr)));
        }

        let load_stdout = String::from_utf8_lossy(&load_output.stdout);
        tracing::info!("Cached image loaded successfully. Docker load output: {}", load_stdout);

        let inspect_output = Command::new("docker")
            .args(&["inspect", "--type=image", &image_name])
            .output()
            .await
            .map_err(|e| {
                tracing::error!("Failed to inspect image: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to inspect image: {}", e))
            })?;

        if !inspect_output.status.success() {
            tracing::warn!("Loaded cached image doesn't have expected tag {}, attempting to parse and tag", image_name);

            if let Some(loaded_line) = load_stdout.lines().find(|l| l.contains("Loaded image")) {
                let loaded_image = if loaded_line.contains("Loaded image ID:") {
                    loaded_line.split("Loaded image ID:").nth(1).map(|s| s.trim().to_string())
                } else if loaded_line.contains("Loaded image:") {
                    loaded_line.split("Loaded image:").nth(1).map(|s| s.trim().to_string())
                } else {
                    None
                };

                if let Some(loaded_img) = loaded_image {
                    tracing::info!("Tagging loaded image {} as {}", loaded_img, image_name);

                    let tag_output = Command::new("docker")
                        .args(&["tag", &loaded_img, &image_name])
                        .output()
                        .await
                        .map_err(|e| {
                            tracing::error!("Failed to tag cached image: {:?}", e);
                            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to tag cached image: {}", e))
                        })?;

                    if !tag_output.status.success() {
                        let stderr = String::from_utf8_lossy(&tag_output.stderr);
                        tracing::error!("Failed to tag cached image: {}", stderr);
                        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to tag cached image: {}", stderr)));
                    }

                    tracing::info!("Successfully tagged cached image as {}", image_name);
                } else {
                    tracing::error!("Could not parse loaded image name from: {}", loaded_line);
                    return Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to parse loaded image name".to_string()));
                }
            } else {
                tracing::error!("Docker load output didn't contain 'Loaded image' line");
                return Err((StatusCode::INTERNAL_SERVER_ERROR, "Invalid docker load output".to_string()));
            }
        } else {
            tracing::info!("Cached image already has correct tag: {}", image_name);
        }
    } else {
        tracing::info!("Cache MISS: Building Docker image for commit {}", commit_sha);

        let build_commit_sha = match build_image_from_repo(&app_id_str, &build_config, &image_name, &req.branch, &state.data_dir).await {
            Ok(sha) => {
                tracing::info!("Successfully built image: {} (commit: {})", image_name, sha);
                sha
            }
            Err(e) => {
                tracing::error!("Failed to build image: {:?}", e);
                return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Image build failed: {}", e)));
            }
        };

        if build_commit_sha != commit_sha {
            tracing::warn!("Commit SHA mismatch: expected {}, got {}", commit_sha, build_commit_sha);
        }

        tracing::info!("Exporting image to tarball: {}", image_tarball);
        match export_image_to_tarball(&image_name, &image_tarball).await {
            Ok(()) => {
                tracing::info!("Exported image to: {}", image_tarball);
            }
            Err(e) => {
                tracing::error!("Failed to export image: {:?}", e);
                return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Image export failed: {}", e)));
            }
        }
    }

    tracing::info!("Building Nitro Enclave EIF for commit {}", commit_sha);

    let containerfile = if let Some(cf) = build_config.containerfile.clone() {
        cf
    } else if build_config.build.is_none() {
        let containerfile_check = Command::new("git")
            .args(&["--git-dir", &git_dir, "show", &format!("{}:Containerfile", commit_sha)])
            .output()
            .await
            .map_err(|e| {
                tracing::error!("Failed to check for Containerfile: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Git command failed: {}", e))
            })?;

        if containerfile_check.status.success() {
            "Containerfile".to_string()
        } else {
            let dockerfile_check = Command::new("git")
                .args(&["--git-dir", &git_dir, "show", &format!("{}:Dockerfile", commit_sha)])
                .output()
                .await
                .map_err(|e| {
                    tracing::error!("Failed to check for Dockerfile: {}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, format!("Git command failed: {}", e))
                })?;

            if dockerfile_check.status.success() {
                "Dockerfile".to_string()
            } else {
                tracing::error!("No Containerfile or Dockerfile found at commit {}", commit_sha);
                return Err((
                    StatusCode::BAD_REQUEST,
                    "No Containerfile or Dockerfile found in repository root".to_string(),
                ));
            }
        }
    } else {
        "Dockerfile".to_string()
    };

    let work_dir = format!("{}/build/work-{}-{}", state.data_dir, app_id_str, commit_sha);
    if build_config.no_cache {
        if let Err(e) = tokio::fs::remove_dir_all(&work_dir).await {
            tracing::debug!("Could not remove work_dir (may not exist): {}", e);
        }
    }
    tokio::fs::create_dir_all(&work_dir).await.map_err(|e| {
        tracing::error!("Failed to create work directory: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create work directory: {}", e))
    })?;

    let extract_cmd = format!(
        "git --git-dir={} archive {} | tar -xC {}",
        git_dir, commit_sha, work_dir
    );
    let extract_output = Command::new("bash")
        .args(&["-c", &extract_cmd])
        .output()
        .await
        .map_err(|e| {
            tracing::error!("Failed to extract repository: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Repository extraction failed: {}", e))
        })?;

    if !extract_output.status.success() {
        let stderr = String::from_utf8_lossy(&extract_output.stderr);
        tracing::error!("Failed to extract repository archive: {}", stderr);
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to extract repository".to_string()));
    }

    let containerfile_path = format!("{}/{}", work_dir, containerfile);

    let enclave_config = types::EnclaveConfig {
        binary_path: build_config.binary.clone().unwrap_or_else(|| "/app".to_string()),
        args: vec![],
        memory_mb: build_config.memory_mb,
        cpus: build_config.cpus,
        debug: build_config.debug,
        ports: build_config.ports.clone(),
    };

    let prebuilt_eif_path = format!("{}/nitro.eif", work_dir);
    let prebuilt_pcrs_path = format!("{}/nitro.pcrs", work_dir);

    let cached_eif_path = format!("{}/{}-{}.eif", cache_dir_str, app_id_str, commit_sha);
    let cached_pcrs_path = format!("{}/{}-{}.pcrs", cache_dir_str, app_id_str, commit_sha);
    let eif_cache_exists = tokio::fs::metadata(&cached_eif_path).await.is_ok() && !build_config.no_cache;

    let eif_result = if eif_cache_exists {
        tracing::info!("EIF Cache HIT: Using cached EIF for commit {}", commit_sha);

        let eif_data = tokio::fs::read(&cached_eif_path).await.map_err(|e| {
            tracing::error!("Failed to read cached EIF: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to read cached EIF: {}", e))
        })?;

        let eif_size_bytes = eif_data.len() as u64;

        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&eif_data);
        let eif_hash = format!("{:x}", hasher.finalize());

        tracing::info!("Cached EIF loaded: {} bytes, hash: {}", eif_size_bytes, eif_hash);

        types::EIFBuildResult {
            eif_path: cached_eif_path.clone(),
            pcrs_path: cached_pcrs_path.clone(),
            eif_hash,
            eif_size_bytes,
        }
    } else {
        tracing::info!("Building EIF using enclave-builder from Docker image: caution-{}:latest", app_id_str);

        let enclave_source = if !build_config.enclave_sources.is_empty() {
            build_config.enclave_sources[0].clone()
        } else {
            enclave_builder::ENCLAVE_SOURCE.to_string()
        };
        tracing::info!("Using enclave source: {}", enclave_source);

        let builder = enclave_builder::EnclaveBuilder::new(
            "unused-template",
            "local",
            &enclave_source,
            "unused",
            enclave_builder::FRAMEWORK_SOURCE,
        )
            .map_err(|e| {
                tracing::error!("Failed to create enclave builder: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to initialize enclave builder: {}", e))
            })?
            .with_work_dir(std::path::PathBuf::from(&work_dir))
            .with_no_cache(build_config.no_cache);

        let user_image = enclave_builder::UserImage {
            reference: format!("caution-{}:{}", app_id_str, &commit_sha[..12]),
        };
        tracing::info!("Using Docker image for enclave build: {}", user_image.reference);

        let run_command = build_config.run.clone();
        if let Some(ref cmd) = run_command {
            tracing::info!("Using run command from Procfile: {}", cmd);
        } else {
            tracing::info!("No run command specified, using auto-detection");
        }

        let app_source_urls: Vec<String> = build_config.app_sources.clone();
        tracing::info!("Using {} app source URL(s): {:?}", app_source_urls.len(), app_source_urls);

        let deployment = if let Some(ref binary_path) = build_config.binary {
            tracing::info!("Using static binary extraction mode: {}", binary_path);
            builder
                .build_enclave_auto(
                    &user_image,
                    binary_path,
                    run_command,
                    Some(app_source_urls),
                    Some(req.branch.clone()),
                    Some(commit_sha.clone()),
                    build_config.metadata.clone(),
                    None,
                    &enclave_config.ports,
                )
                .await
                .map_err(|e| {
                    tracing::error!("Failed to build enclave: {:?}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, format!("Enclave build failed: {}", e))
                })?
        } else {
            tracing::info!("Using full filesystem extraction mode (no binary specified)");
            builder
                .build_enclave(
                    &user_image,
                    None,
                    run_command,
                    Some(build_config.app_sources.clone()),
                    Some(req.branch.clone()),
                    Some(commit_sha.clone()),
                    build_config.metadata.clone(),
                    None,
                    &enclave_config.ports,
                )
                .await
                .map_err(|e| {
                    tracing::error!("Failed to build enclave: {:?}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, format!("Enclave build failed: {}", e))
                })?
        };

        tracing::info!(
            "EIF built successfully: path={}, size={} bytes, hash={}",
            deployment.eif.path.display(),
            deployment.eif.size,
            deployment.eif.sha256
        );
        tracing::info!(
            "PCR values: PCR0={}, PCR1={}, PCR2={}",
            deployment.pcrs.pcr0,
            deployment.pcrs.pcr1,
            deployment.pcrs.pcr2
        );

        let built_eif_path = deployment.eif.path.to_string_lossy().to_string();
        let built_pcrs_path = deployment.eif.path.with_extension("pcrs").to_string_lossy().to_string();

        tracing::info!("Caching EIF to: {}", cached_eif_path);
        if let Err(e) = tokio::fs::copy(&built_eif_path, &cached_eif_path).await {
            tracing::warn!("Failed to cache EIF (non-fatal): {:?}", e);
        }
        if let Err(e) = tokio::fs::copy(&built_pcrs_path, &cached_pcrs_path).await {
            tracing::warn!("Failed to cache PCRs (non-fatal): {:?}", e);
        }

        types::EIFBuildResult {
            eif_path: cached_eif_path.clone(),
            pcrs_path: cached_pcrs_path.clone(),
            eif_hash: deployment.eif.sha256,
            eif_size_bytes: deployment.eif.size,
        }
    };

    let eif_path = eif_result.eif_path.clone();
    let eif_hash = eif_result.eif_hash.clone();

    tracing::info!("Storing EIF metadata: path={}, hash={}", eif_path, eif_hash);

    let eif_config = serde_json::json!({
        "eif_path": eif_path,
        "eif_hash": eif_hash,
        "pcrs_path": eif_result.pcrs_path,
        "eif_size_bytes": eif_result.eif_size_bytes,
        "commit_sha": commit_sha,
        "enclave_config": enclave_config,
        "run_command": build_config.run,
        "domain": build_config.domain,
    });

    let memory_bytes = (enclave_config.memory_mb as u64) * 1024 * 1024;
    if eif_result.eif_size_bytes > memory_bytes {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "EIF size ({} MB) exceeds allocated enclave memory ({} MB). Increase memory_mb in Procfile.",
                eif_result.eif_size_bytes / (1024 * 1024),
                enclave_config.memory_mb
            ),
        ));
    }
    if eif_result.eif_size_bytes > memory_bytes * 80 / 100 {
        tracing::warn!(
            "EIF size ({} MB) is more than 80% of allocated memory ({} MB). Consider increasing memory_mb.",
            eif_result.eif_size_bytes / (1024 * 1024),
            enclave_config.memory_mb
        );
    }

    tracing::info!("Deploying Nitro Enclave for resource {} with memory_mb={}, cpu_count={}, debug={}",
                   resource_id, enclave_config.memory_mb, enclave_config.cpus, enclave_config.debug);

    let credentials = if let Some(ref managed_config) = build_config.managed_on_prem {
        match managed_config {
            types::ManagedOnPremConfig::Aws(aws_config) => {
                tracing::info!("Managed on-prem deployment detected, fetching AWS credentials for region {}", aws_config.region);

                let encryptor = state.encryptor.as_ref().ok_or_else(|| {
                    (StatusCode::INTERNAL_SERVER_ERROR, "Encryptor not configured".to_string())
                })?;

                let cred = cloud_credentials::get_default_credential_for_platform(
                    &state.db,
                    req.org_id,
                    cloud_credentials::CloudPlatform::Aws,
                ).await?;

                match cred {
                    Some(credential) => {
                        let secrets = cloud_credentials::get_credential_secrets(
                            &state.db,
                            encryptor,
                            req.org_id,
                            credential.id,
                        ).await?;

                        match secrets {
                            Some(secrets_json) => {
                                let secret_access_key = secrets_json["secret_access_key"]
                                    .as_str()
                                    .ok_or_else(|| {
                                        (StatusCode::INTERNAL_SERVER_ERROR, "Missing secret_access_key in credentials".to_string())
                                    })?;

                                Some(deployment::AwsCredentials {
                                    access_key_id: credential.identifier.clone(),
                                    secret_access_key: secret_access_key.to_string(),
                                    region: aws_config.region.clone(),
                                })
                            }
                            None => {
                                return Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to decrypt credentials".to_string()));
                            }
                        }
                    }
                    None => {
                        return Err((
                            StatusCode::BAD_REQUEST,
                            "managed_on_prem requires a default AWS credential to be configured".to_string(),
                        ));
                    }
                }
            }
        }
    } else {
        None
    };

    let nitro_request = deployment::NitroDeploymentRequest {
        org_id: req.org_id,
        resource_id,
        resource_name: app_name.clone(),
        aws_account_id: aws_account_id.clone(),
        role_arn: role_arn_opt.clone(),
        eif_path: eif_path.clone(),
        memory_mb: enclave_config.memory_mb,
        cpu_count: enclave_config.cpus,
        debug_mode: enclave_config.debug,
        ports: enclave_config.ports.clone(),
        ssh_keys: build_config.ssh_keys.clone(),
        domain: build_config.domain.clone(),
        credentials,
    };

    let deployment_result = match deployment::deploy_nitro_enclave(nitro_request).await {
        Ok(result) => {
            tracing::info!(
                "Nitro Enclave deployed: instance_id={}, public_ip={}",
                result.instance_id,
                result.public_ip
            );
            result
        }
        Err(e) => {
            tracing::error!("Failed to deploy Nitro Enclave: {:?}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Nitro deployment failed: {}", e),
            ));
        }
    };

    let mut final_config = eif_config.clone();
    if let Some(instance_type) = &deployment_result.instance_type {
        final_config["instance_type"] = serde_json::json!(instance_type);
    }

    sqlx::query(
        "UPDATE compute_resources
         SET provider_resource_id = $1, state = $2, public_ip = $3, configuration = configuration || $4::jsonb
         WHERE id = $5"
    )
    .bind(&deployment_result.instance_id)
    .bind(types::ResourceState::Running)
    .bind(&deployment_result.public_ip)
    .bind(&final_config)
    .bind(resource_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update resource: {}", e)))?;

    tracing::info!(
        "EIF deployment complete: resource_id={}, instance_id={}, public_ip={}, instance_type={:?}",
        resource_id,
        deployment_result.instance_id,
        deployment_result.public_ip,
        deployment_result.instance_type
    );

    let app_url = if let Some(ref domain) = build_config.domain {
        format!("https://{}", domain)
    } else {
        format!("http://{}", deployment_result.public_ip)
    };
    let attestation_url = format!("{}/attestation", app_url);

    tracing::info!("Waiting for attestation endpoint to become healthy...");
    if let Err(e) = wait_for_attestation_health(&deployment_result.public_ip, 600).await {
        tracing::error!("Attestation health check failed: {}", e);
        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Enclave failed to become healthy: {}", e)));
    }

    tracing::info!(
        "Deployment URLs - App: {}, Attestation: {}",
        app_url,
        attestation_url
    );

    Ok(Json(DeployResponse {
        url: app_url,
        attestation_url,
        resource_id,
        public_ip: deployment_result.public_ip.clone(),
        domain: build_config.domain.clone(),
    }))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    if let Err(e) = provisioning::validate_setup() {
        tracing::warn!("Provisioning validation failed: {:?}", e);
        tracing::warn!("AWS child account provisioning will not be available");
    }
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");

    let git_hostname = std::env::var("GIT_HOSTNAME")
        .unwrap_or_else(|_| "alpha.caution.co".to_string());

    let git_ssh_port: Option<u16> = std::env::var("SSH_PORT")
        .ok()
        .and_then(|p| p.parse().ok());

    let data_dir = std::env::var("CAUTION_DATA_DIR")
        .unwrap_or_else(|_| "/var/cache/caution".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    info!("Connected to database");

    let encryptor = match encryption::Encryptor::from_env() {
        Ok(e) => {
            info!("Encryption enabled for cloud credentials");
            Some(Arc::new(e))
        }
        Err(e) => {
            tracing::warn!("Encryption not configured: {}. Cloud credentials feature disabled.", e);
            None
        }
    };

    let internal_service_secret = std::env::var("INTERNAL_SERVICE_SECRET").ok();
    if internal_service_secret.is_some() {
        info!("Internal service authentication enabled");
    } else {
        tracing::warn!("INTERNAL_SERVICE_SECRET not set - internal service authentication disabled");
    }

    let state = Arc::new(AppState {
        db: pool,
        git_hostname,
        git_ssh_port,
        data_dir,
        encryptor,
        internal_service_secret,
    });

    let onboarding_routes = Router::new()
        .route("/user/status", get(onboarding::get_user_status))
        .route("/onboarding/send-verification", post(onboarding::send_verification_email))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    let resource_routes = Router::new()
        .route("/users/me", get(get_current_user))
        .route("/users/me", patch(update_current_user))
        .route("/users/me", delete(delete_current_user))
        .route("/organizations", get(list_organizations))
        .route("/organizations", post(create_organization))
        .route("/organizations/{id}", get(get_organization))
        .route("/organizations/{id}", patch(update_organization))
        .route("/organizations/{id}", delete(delete_organization))
        .route("/organizations/{id}/members", get(list_members))
        .route("/organizations/{id}/members", post(add_member))
        .route("/organizations/{id}/members/{user_id}", patch(update_member))
        .route("/organizations/{id}/members/{user_id}", delete(remove_member))
        .route("/resources", post(create_resource))
        .route("/resources", get(list_resources))
        .route("/resources/{id}", get(get_resource))
        .route("/resources/{id}", patch(rename_resource))
        .route("/resources/{id}", delete(delete_resource))
        .route("/deploy", post(deploy_handler))
        .route("/credentials", get(list_cloud_credentials))
        .route("/credentials", post(create_cloud_credential))
        .route("/credentials/{id}", get(get_cloud_credential))
        .route("/credentials/{id}", delete(delete_cloud_credential))
        .route("/credentials/{id}/default", post(set_default_cloud_credential))
        .layer(middleware::from_fn_with_state(state.clone(), onboarding_middleware))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    let public_routes = Router::new()
        .route("/health", get(health_check))
        .route("/onboarding/verify", get(onboarding::verify_email));

    let app = Router::new()
        .merge(onboarding_routes)
        .merge(resource_routes)
        .merge(public_routes)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
        .await?;
    
    info!("API server listening on 0.0.0.0:8080");

    axum::serve(listener, app).await?;

    Ok(())
}
