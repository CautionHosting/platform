// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::Context;
use axum::{
    body::Body,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post, put},
    Json, Router,
};
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::sync::Arc;
use tokio_stream::wrappers::ReceiverStream;
use tower_http::trace::TraceLayer;
use tracing::info;
use uuid::Uuid;

mod billing;
mod builder;
mod cloud_credentials;
mod cryptographic_bundles;
mod deployment;
mod ec2;
mod encryption;
mod errors;
mod gpg;
mod legal;
mod metering;
mod middleware;
mod onboarding;
mod organizations;
mod provisioning;
mod resources;
mod subscriptions;
mod suspension;
mod types;
mod users;
mod validated_types;
mod validation;

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct PricingConfig {
    pub(crate) compute_margin_percent: f64,
    #[serde(default)]
    pub(crate) subscription_tiers: std::collections::HashMap<String, TierPricing>,
    #[serde(default)]
    pub(crate) credit_packages: std::collections::HashMap<String, CreditPackagePricing>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct TierPricing {
    #[serde(default)]
    pub(crate) annual_cents: i64,
    #[serde(default)]
    pub(crate) enclaves: i32,
    #[serde(default)]
    pub(crate) vcpu: i32,
    #[serde(default)]
    pub(crate) ram_gb: i32,
    #[serde(default)]
    pub(crate) storage_gb: i32,
}

impl TierPricing {
    pub(crate) fn monthly_price_cents(&self) -> i64 {
        self.annual_cents / 12
    }
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct CreditPackagePricing {
    pub(crate) bonus_percent: f64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct AppliedPricing {
    pub(crate) base_unit_cost_usd: f64,
    pub(crate) margin_percent: f64,
}

impl AppliedPricing {
    pub(crate) fn unit_cost_usd(self) -> f64 {
        self.base_unit_cost_usd * (1.0 + self.margin_percent / 100.0)
    }

    pub(crate) fn total_cost_usd(self, quantity: f64) -> f64 {
        quantity * self.unit_cost_usd()
    }
}

impl PricingConfig {
    pub(crate) fn instance_pricing(&self, instance_type: &str) -> Option<AppliedPricing> {
        Some(AppliedPricing {
            base_unit_cost_usd: billing::base_instance_rate(instance_type)?,
            margin_percent: self.compute_margin_percent,
        })
    }

    pub(crate) fn subscription_cost_hourly_usd(&self, tier_id: &str) -> Option<f64> {
        const HOURS_PER_YEAR: f64 = 365.0 * 24.0;
        let annual_tier_cents = self.subscription_tiers.get(tier_id)?.annual_cents;
        Some(annual_tier_cents as f64 / 100.0 / HOURS_PER_YEAR)
    }

    pub(crate) fn load() -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string("prices.json").context(
            "prices.json not found. Configure explicit pricing before starting the API.",
        )?;
        let config = serde_json::from_str(&contents).context(
            "Failed to parse prices.json. Ensure compute_margin_percent is explicitly set.",
        )?;
        tracing::info!("Loaded pricing config from prices.json");
        Ok(config)
    }

    pub(crate) fn credit_bonus_percent(&self, package_key: &str) -> f64 {
        self.credit_packages
            .get(package_key)
            .map(|p| p.bonus_percent)
            .unwrap_or(0.0)
    }
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) db: PgPool,
    pub(crate) git_hostname: String,
    pub(crate) git_ssh_port: Option<u16>,
    pub(crate) data_dir: String,
    pub(crate) encryptor: Option<Arc<encryption::Encryptor>>,
    pub(crate) internal_service_secret: Option<String>,
    pub(crate) paddle_client_token: Option<String>,
    pub(crate) paddle_setup_price_id: Option<String>,
    pub(crate) paddle_credits_price_ids: [Option<String>; 3],
    pub(crate) paddle_api_url: String,
    pub(crate) paddle_api_key: Option<String>,
    pub(crate) pricing: PricingConfig,
    pub(crate) builder_config: builder::BuilderConfig,
    pub(crate) builder_sizes: builder::BuilderSizesConfig,
}

#[derive(Clone)]
pub(crate) struct AuthContext {
    pub(crate) user_id: Uuid,
}

use validated_types::{DeployRequest, DeployResponse};

pub(crate) async fn check_org_access(
    db: &PgPool,
    user_id: Uuid,
    org_id: Uuid,
) -> Result<types::UserRole, StatusCode> {
    let member: Option<(types::UserRole,)> = sqlx::query_as(
        "SELECT role FROM organization_members
         WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        tracing::error!("check_org_access failed: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    member.map(|m| m.0).ok_or(StatusCode::FORBIDDEN)
}

pub(crate) fn can_manage_org(role: &types::UserRole) -> bool {
    role.can_manage_org()
}

pub(crate) fn is_owner(role: &types::UserRole) -> bool {
    role.is_owner()
}

pub(crate) async fn get_user_primary_org(db: &PgPool, user_id: Uuid) -> Result<Uuid, StatusCode> {
    let org_id: Option<(Uuid,)> = sqlx::query_as(
        "SELECT organization_id FROM organization_members
         WHERE user_id = $1
         ORDER BY created_at ASC
         LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    org_id.map(|o| o.0).ok_or(StatusCode::NOT_FOUND)
}

pub(crate) async fn get_or_create_provider_account(
    db: &PgPool,
    org_id: Uuid,
) -> Result<Uuid, StatusCode> {
    let aws_account_id = std::env::var("AWS_ACCOUNT_ID").map_err(|_| {
        tracing::error!("AWS_ACCOUNT_ID environment variable not set");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let existing: Option<(Uuid, Option<String>, Option<bool>)> = sqlx::query_as(
        "SELECT pa.id, pa.role_arn, pa.is_active FROM provider_accounts pa
         JOIN providers p ON pa.provider_id = p.id
         WHERE pa.organization_id = $1 AND p.provider_type = 'aws'
         LIMIT 1",
    )
    .bind(org_id)
    .fetch_optional(db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Some((id, role_arn, is_active)) = existing {
        if role_arn.is_none() || is_active != Some(true) {
            let role_arn = format!(
                "arn:aws:iam::{}:role/OrganizationAccountAccessRole",
                aws_account_id
            );

            sqlx::query(
                "UPDATE provider_accounts
                 SET role_arn = $1, is_active = true, external_account_id = $2
                 WHERE id = $3 AND organization_id = $4",
            )
            .bind(&role_arn)
            .bind(&aws_account_id)
            .bind(id)
            .bind(org_id)
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

    let role_arn = format!(
        "arn:aws:iam::{}:role/OrganizationAccountAccessRole",
        aws_account_id
    );

    let account_id: (Uuid,) = sqlx::query_as(
        "INSERT INTO provider_accounts
         (organization_id, provider_id, external_account_id, account_name, role_arn, is_active)
         VALUES ($1, (SELECT id FROM providers WHERE provider_type = 'aws'), $2, $3, $4, true)
         RETURNING id",
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

    tracing::info!(
        "Created provider account {} for org {} using AWS account {}",
        account_id.0,
        org_id,
        aws_account_id
    );

    Ok(account_id.0)
}

pub(crate) async fn get_or_create_resource_type(db: &PgPool) -> Result<Uuid, StatusCode> {
    let existing: Option<(Uuid,)> = sqlx::query_as(
        "SELECT rt.id FROM resource_types rt
         JOIN providers p ON rt.provider_id = p.id
         WHERE p.provider_type = 'aws' AND rt.type_code = $1
         LIMIT 1",
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
        tracing::info!(
            "Polling attestation endpoint (attempt {}): {}",
            attempt,
            url
        );

        let nonce_b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        let result = client
            .post(&url)
            .json(&serde_json::json!({"nonce": nonce_b64}))
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!("Attestation endpoint is healthy after {} attempts", attempt);
                return Ok(());
            }
            Ok(resp) => {
                tracing::debug!(
                    "Attestation endpoint returned {}, retrying...",
                    resp.status()
                );
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

async fn get_commit_sha(
    app_name: &str,
    branch: &str,
    data_dir: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use tokio::process::Command;

    let repo_path = format!("{}/git-repos/{}.git", data_dir, app_name);
    let ref_spec = format!("refs/heads/{}", branch);

    let output = Command::new("git")
        .args(&["--git-dir", &repo_path, "rev-parse", &ref_spec])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "Failed to get commit SHA for branch '{}': {}",
            branch, stderr
        )
        .into());
    }

    let commit_sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(commit_sha)
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
    let encryptor = state.encryptor.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Cloud credentials feature not configured. Set CAUTION_ENCRYPTION_KEY.".to_string(),
    ))?;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let credential =
        cloud_credentials::create_credential(&state.db, encryptor, org_id, auth.user_id, req)
            .await?;
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

    let updated =
        cloud_credentials::set_default_credential(&state.db, org_id, credential_id).await?;

    if updated {
        Ok(StatusCode::OK)
    } else {
        Err((StatusCode::NOT_FOUND, "Credential not found".to_string()))
    }
}

async fn list_quorum_bundles(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<cryptographic_bundles::QuorumBundle>>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let items = cryptographic_bundles::list_quorum_bundles(&state.db, org_id).await?;
    Ok(Json(items))
}

async fn create_quorum_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<cryptographic_bundles::CreateBundleRequest>,
) -> Result<Json<cryptographic_bundles::QuorumBundle>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let bundle =
        cryptographic_bundles::create_quorum_bundle(&state.db, org_id, auth.user_id, req).await?;
    Ok(Json(bundle))
}

async fn get_quorum_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<cryptographic_bundles::QuorumBundle>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let bundle = cryptographic_bundles::get_quorum_bundle(&state.db, org_id, id)
        .await?
        .ok_or((StatusCode::NOT_FOUND, "Quorum bundle not found".to_string()))?;

    Ok(Json(bundle))
}

async fn update_quorum_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(req): Json<cryptographic_bundles::UpdateBundleRequest>,
) -> Result<Json<cryptographic_bundles::QuorumBundle>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let bundle = cryptographic_bundles::update_quorum_bundle(&state.db, org_id, id, req)
        .await?
        .ok_or((StatusCode::NOT_FOUND, "Quorum bundle not found".to_string()))?;

    Ok(Json(bundle))
}

async fn delete_quorum_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let deleted = cryptographic_bundles::delete_quorum_bundle(&state.db, org_id, id).await?;

    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((StatusCode::NOT_FOUND, "Quorum bundle not found".to_string()))
    }
}

async fn list_secrets_bundles(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<cryptographic_bundles::SecretsBundle>>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let items = cryptographic_bundles::list_secrets_bundles(&state.db, org_id).await?;
    Ok(Json(items))
}

async fn create_secrets_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<cryptographic_bundles::CreateBundleRequest>,
) -> Result<Json<cryptographic_bundles::SecretsBundle>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let bundle =
        cryptographic_bundles::create_secrets_bundle(&state.db, org_id, auth.user_id, req).await?;
    Ok(Json(bundle))
}

async fn get_secrets_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<cryptographic_bundles::SecretsBundle>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let bundle = cryptographic_bundles::get_secrets_bundle(&state.db, org_id, id)
        .await?
        .ok_or((
            StatusCode::NOT_FOUND,
            "Secrets bundle not found".to_string(),
        ))?;

    Ok(Json(bundle))
}

async fn update_secrets_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(req): Json<cryptographic_bundles::UpdateBundleRequest>,
) -> Result<Json<cryptographic_bundles::SecretsBundle>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let bundle = cryptographic_bundles::update_secrets_bundle(&state.db, org_id, id, req)
        .await?
        .ok_or((
            StatusCode::NOT_FOUND,
            "Secrets bundle not found".to_string(),
        ))?;

    Ok(Json(bundle))
}

async fn delete_secrets_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let deleted = cryptographic_bundles::delete_secrets_bundle(&state.db, org_id, id).await?;

    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((
            StatusCode::NOT_FOUND,
            "Secrets bundle not found".to_string(),
        ))
    }
}

/// Create or update a managed on-prem resource.
/// Accepts either plain JSON or GPG-encrypted config from the setup script.
/// If resource_id is provided, updates the existing resource; otherwise creates a new one.
async fn create_managed_onprem_resource(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    body: String,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let json_content = if gpg::is_gpg_encrypted(&body) {
        tracing::info!("Received GPG-encrypted managed on-prem config, decrypting...");
        let decrypted = gpg::decrypt_gpg_message(&body).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("GPG decryption failed: {}", e),
            )
        })?;
        tracing::info!("GPG decryption successful");
        decrypted
    } else {
        body
    };

    let mut req: cloud_credentials::CreateCredentialRequest =
        serde_json::from_str(&json_content)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid JSON: {}", e)))?;

    if !req.managed_on_prem {
        return Err((
            StatusCode::BAD_REQUEST,
            "This endpoint requires managed_on_prem: true".to_string(),
        ));
    }

    let deployment_id = req.deployment_id.clone().ok_or((
        StatusCode::BAD_REQUEST,
        "deployment_id is required".to_string(),
    ))?;

    let encryptor = state.encryptor.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Encryption not configured. Set CAUTION_ENCRYPTION_KEY.".to_string(),
    ))?;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let managed_onprem_config = serde_json::json!({
        "deployment_id": req.deployment_id,
        "asg_name": req.asg_name,
        "launch_template_name": req.launch_template_name,
        "launch_template_id": req.launch_template_id,
        "vpc_id": req.vpc_id,
        "subnet_ids": req.subnet_ids,
        "eif_bucket": req.eif_bucket,
        "instance_profile_name": req.instance_profile_name,
        "aws_region": req.aws_region,
        "aws_account_id": req.aws_account_id,
    });

    let configuration = serde_json::json!({
        "managed_onprem": managed_onprem_config,
    });

    if let Some(existing_resource_id) = req.resource_id {
        tracing::info!(
            "Updating managed on-prem resource {}: deployment_id={}",
            existing_resource_id,
            deployment_id
        );

        let existing: Option<(String, types::ResourceState)> = sqlx::query_as(
            "SELECT resource_name, state FROM compute_resources
             WHERE id = $1 AND organization_id = $2",
        )
        .bind(existing_resource_id)
        .bind(org_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
        })?;

        let (resource_name, resource_state) = existing.ok_or((
            StatusCode::NOT_FOUND,
            format!("Resource {} not found", existing_resource_id),
        ))?;

        sqlx::query(
            "UPDATE compute_resources
             SET configuration = COALESCE(configuration, '{}'::jsonb) || $1::jsonb, updated_at = NOW()
             WHERE id = $2 AND organization_id = $3"
        )
        .bind(&configuration)
        .bind(existing_resource_id)
        .bind(org_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update resource: {}", e)))?;

        sqlx::query(
            "DELETE FROM cloud_credentials WHERE resource_id = $1 AND organization_id = $2",
        )
        .bind(existing_resource_id)
        .bind(org_id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to delete old credential: {}", e),
            )
        })?;

        let credential =
            cloud_credentials::create_credential(&state.db, encryptor, org_id, auth.user_id, req)
                .await?;

        let git_url = match state.git_ssh_port {
            Some(port) => format!(
                "ssh://git@{}:{}/{}.git",
                state.git_hostname, port, existing_resource_id
            ),
            None => format!("git@{}:{}.git", state.git_hostname, existing_resource_id),
        };

        tracing::info!(
            "Updated managed on-prem resource {}: credential_id={}, deployment_id={}",
            existing_resource_id,
            credential.id,
            deployment_id
        );

        Ok(Json(serde_json::json!({
            "id": existing_resource_id,
            "resource_name": resource_name,
            "git_url": git_url,
            "state": resource_state.as_str(),
            "credential_id": credential.id,
            "managed_onprem": managed_onprem_config,
            "updated": true,
        })))
    } else {
        tracing::info!(
            "Creating managed on-prem resource: deployment_id={}",
            deployment_id
        );

        let provider_account_id = get_or_create_provider_account(&state.db, org_id)
            .await
            .map_err(|e| (e, "Failed to get provider account".to_string()))?;

        let resource_type_id = get_or_create_resource_type(&state.db)
            .await
            .map_err(|e| (e, "Failed to get resource type".to_string()))?;

        let provider_resource_id = Uuid::new_v4().to_string();
        let resource_slug = format!("app-{}", &provider_resource_id[..8]);

        // Create the resource first (so we have a resource_id for the credential)
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
        .map_err(|e| {
            tracing::error!("Database error creating resource: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to create resource: {}", e),
            )
        })?;

        let (resource_id, resource_state, created_at) = resource;

        req.resource_id = Some(resource_id);

        let credential =
            cloud_credentials::create_credential(&state.db, encryptor, org_id, auth.user_id, req)
                .await?;

        let git_url = match state.git_ssh_port {
            Some(port) => format!(
                "ssh://git@{}:{}/{}.git",
                state.git_hostname, port, resource_id
            ),
            None => format!("git@{}:{}.git", state.git_hostname, resource_id),
        };

        tracing::info!(
            "Created managed on-prem resource {}: credential_id={}, deployment_id={}",
            resource_id,
            credential.id,
            deployment_id
        );

        Ok(Json(serde_json::json!({
            "id": resource_id,
            "resource_name": resource_slug,
            "git_url": git_url,
            "state": resource_state.as_str(),
            "created_at": created_at,
            "credential_id": credential.id,
            "managed_onprem": managed_onprem_config,
        })))
    }
}

fn milestone(msg: &str) -> bytes::Bytes {
    bytes::Bytes::from(format!("STEP:{}\n", msg))
}

fn milestone_done(msg: &str) -> bytes::Bytes {
    bytes::Bytes::from(format!("{}\n", msg))
}

fn milestone_error(msg: &str) -> bytes::Bytes {
    bytes::Bytes::from(format!("error: {}\n", msg))
}

async fn get_builder_config(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(resource_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let config: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT configuration FROM compute_resources WHERE id = $1 AND organization_id = $2",
    )
    .bind(resource_id)
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    let config = config.ok_or((StatusCode::NOT_FOUND, "Resource not found".to_string()))?;
    let builder_size = config
        .get("builder_size")
        .and_then(|v| v.as_str())
        .unwrap_or("small");

    Ok(Json(serde_json::json!({
        "builder_size": builder_size,
        "options": state.builder_sizes.builder_sizes,
    })))
}

async fn set_builder_config(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(resource_id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let builder_size = body
        .get("builder_size")
        .and_then(|v| v.as_str())
        .unwrap_or("small");

    if !state.builder_sizes.is_valid(builder_size) {
        let valid: Vec<&str> = state
            .builder_sizes
            .builder_sizes
            .iter()
            .map(|s| s.id.as_str())
            .collect();
        return Err((
            StatusCode::BAD_REQUEST,
            format!("builder_size must be one of: {}", valid.join(", ")),
        ));
    }

    let result = sqlx::query(
        "UPDATE compute_resources
         SET configuration = COALESCE(configuration, '{}'::jsonb) || jsonb_build_object('builder_size', $1::text)::jsonb,
             updated_at = NOW()
         WHERE id = $2 AND organization_id = $3"
    )
    .bind(builder_size)
    .bind(resource_id)
    .bind(org_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Resource not found".to_string()));
    }

    Ok(Json(serde_json::json!({ "builder_size": builder_size })))
}

async fn deploy_handler(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    validated_types::Validated(req): validated_types::Validated<DeployRequest>,
) -> Response {
    use tokio::process::Command;

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(32);

    // Spawn the deploy logic in a separate task
    let db_for_recovery = state.db.clone();
    let app_id_for_recovery = req.app_id;
    let org_id_for_recovery = req.org_id;
    tokio::spawn(async move {
        let result = deploy_logic(state, auth, req, tx.clone()).await;

        // Send final result as JSON
        match result {
            Ok(response) => {
                let json = serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
                let _ = tx.send(Ok(bytes::Bytes::from(format!("{}\n", json)))).await;
            }
            Err((status, msg)) => {
                // Reset state from Pending to Failed so the resource isn't stuck
                if let Err(e) = sqlx::query(
                    "UPDATE compute_resources SET state = $1 WHERE id = $2 AND organization_id = $3 AND state = $4"
                )
                .bind(types::ResourceState::Failed)
                .bind(app_id_for_recovery)
                .bind(org_id_for_recovery)
                .bind(types::ResourceState::Pending)
                .execute(&db_for_recovery)
                .await {
                    tracing::error!("Failed to reset resource state after deploy error: {}", e);
                }

                let _ = tx.send(Ok(milestone_error(&msg))).await;
                let error_json = serde_json::json!({"error": msg, "status": status.as_u16()});
                let _ = tx
                    .send(Ok(bytes::Bytes::from(format!("{}\n", error_json))))
                    .await;
            }
        }
    });

    let stream = ReceiverStream::new(rx);
    let body = Body::from_stream(stream);

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain; charset=utf-8")
        .header("X-Content-Type-Options", "nosniff")
        .body(body)
        .unwrap()
}

async fn deploy_logic(
    state: Arc<AppState>,
    auth: AuthContext,
    req: DeployRequest,
    tx: tokio::sync::mpsc::Sender<Result<bytes::Bytes, std::io::Error>>,
) -> Result<DeployResponse, (StatusCode, String)> {
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
        )",
    )
    .bind(auth.user_id)
    .bind(req.org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    if user_in_org != Some(true) {
        return Err((
            StatusCode::FORBIDDEN,
            "User does not belong to this organization".to_string(),
        ));
    }

    let _ = tx.send(Ok(milestone("Preparing deployment..."))).await;

    tracing::info!("Fetching provider account for org {}", req.org_id);
    let provider_account: Option<(Uuid, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT id, external_account_id, role_arn
         FROM provider_accounts
         WHERE organization_id = $1 AND is_active = true
         LIMIT 1",
    )
    .bind(req.org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to fetch provider account: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error fetching provider account: {}", e),
        )
    })?;

    tracing::info!("Provider account query result: {:?}", provider_account);

    let (provider_account_id, aws_account_id_opt, role_arn_opt) =
        provider_account.ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "No active provider account found".to_string(),
            )
        })?;

    tracing::info!(
        "Provider account details: id={}, aws_account_id={:?}, role_arn={:?}",
        provider_account_id,
        aws_account_id_opt,
        role_arn_opt
    );

    let aws_account_id = aws_account_id_opt.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "Provider account has no AWS account ID configured".to_string(),
        )
    })?;

    if let Some(ref role_arn) = role_arn_opt {
        tracing::info!(
            "Deploying to AWS account {} via role {}",
            aws_account_id,
            role_arn
        );
    } else {
        tracing::info!(
            "Deploying to root AWS account {} (no role assumption)",
            aws_account_id
        );
    }

    tracing::info!("Fetching resource type for EC2Instance");
    let resource_type_id: Uuid =
        sqlx::query_scalar("SELECT id FROM resource_types WHERE type_code = $1 LIMIT 1")
            .bind(types::AWSResourceType::EC2Instance.as_str())
            .fetch_one(&state.db)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to get resource type: {}", e),
                )
            })?;

    tracing::info!("Looking up resource by id={}", req.app_id);
    let existing_resource: Option<(
        Uuid,
        Option<String>,
        Option<serde_json::Value>,
        Option<DateTime<Utc>>,
        types::ResourceState,
    )> = sqlx::query_as(
        "SELECT id, resource_name, configuration, destroyed_at, state FROM compute_resources
         WHERE id = $1 AND organization_id = $2",
    )
    .bind(req.app_id)
    .bind(req.org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to check existing resource: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error checking existing resource: {}", e),
        )
    })?;

    let (resource_id, app_name, configuration, was_destroyed) = match &existing_resource {
        Some((id, name_opt, config_opt, destroyed_at, state)) => {
            // Reject if a deploy is already in progress
            if *state == types::ResourceState::Pending {
                return Err((StatusCode::CONFLICT, "A deployment is already in progress for this app. Please wait for it to complete.".to_string()));
            }
            let name = name_opt.clone().unwrap_or_else(|| "unnamed".to_string());
            let config = config_opt.clone().unwrap_or_else(|| serde_json::json!({}));
            (*id, name, config, destroyed_at.is_some())
        }
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                format!("App with id {} not found", req.app_id),
            ))
        }
    };

    tracing::info!("Found resource: id={}, name={}", resource_id, app_name);

    // --- Billing gate (pre-deploy) --- must run before reactivation to avoid side effects on failure
    let cred =
        cloud_credentials::get_credential_by_resource(&state.db, req.org_id, resource_id).await?;
    let is_managed_onprem = cred.as_ref().map(|c| c.managed_on_prem).unwrap_or(false);

    if is_managed_onprem {
        // Managed on-prem: require active subscription with capacity
        let sub: Option<(Uuid, String, i32)> = sqlx::query_as(
            "SELECT id, tier, max_apps FROM subscriptions
             WHERE organization_id = $1 AND status IN ('active', 'past_due') LIMIT 1",
        )
        .bind(req.org_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
        })?;

        let Some((sub_id, tier_id, stored_max_apps)) = sub else {
            return Err((StatusCode::PAYMENT_REQUIRED,
                "Managed on-premises deployment requires an active subscription. Choose a plan in Settings at https://caution.dev".to_string()));
        };

        let max_apps = state
            .pricing
            .subscription_tiers
            .get(&tier_id)
            .map(|tier| tier.enclaves)
            .unwrap_or(stored_max_apps);

        // Count current managed on-prem apps (exclude this resource if redeploying)
        let current_apps: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM compute_resources cr
             JOIN cloud_credentials cc ON cc.resource_id = cr.id
             WHERE cr.organization_id = $1 AND cc.managed_on_prem = true
               AND cr.state != 'terminated' AND cr.id != $2",
        )
        .bind(req.org_id)
        .bind(resource_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
        })?;

        // +1 for the app being deployed
        if current_apps + 1 > max_apps as i64 {
            return Err((StatusCode::PAYMENT_REQUIRED,
                format!("App limit reached ({}/{}). Upgrade your plan in Settings at https://caution.dev",
                    current_apps + 1, max_apps)));
        }

        tracing::info!(
            "Billing gate passed: managed on-prem app {}/{}, sub={}",
            current_apps + 1,
            max_apps,
            sub_id
        );
    } else {
        // Fully managed: require >= $25 in wallet credits (org-level)
        let balance = crate::billing::get_ledger_balance_cents(&state.db, req.org_id)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Database error: {}", e),
                )
            })?;

        if balance < 2500 {
            return Err((
                StatusCode::PAYMENT_REQUIRED,
                format!(
                    "Minimum $25.00 in credits required to deploy (current balance: ${:.2}). \
                         Purchase credits at https://caution.dev/settings/billing",
                    balance as f64 / 100.0
                ),
            ));
        }

        // Block deploy if org is credit-suspended (awaiting credit deposit)
        let credit_suspended: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT credit_suspended_at FROM organizations WHERE id = $1")
                .bind(req.org_id)
                .fetch_optional(&state.db)
                .await
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Database error: {}", e),
                    )
                })?
                .flatten();

        if credit_suspended.is_some() {
            return Err((
                StatusCode::PAYMENT_REQUIRED,
                "Your organization is suspended due to credit exhaustion. \
                 Add credits at https://caution.dev/settings/billing to resume."
                    .to_string(),
            ));
        }

        tracing::info!(
            "Billing gate passed: fully managed, balance_cents={}",
            balance
        );
    }

    // --- Resource limit check (both paths) ---
    let active_resources: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM compute_resources
         WHERE organization_id = $1 AND state NOT IN ('terminated', 'failed')
           AND destroyed_at IS NULL AND id != $2",
    )
    .bind(req.org_id)
    .bind(resource_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
    })?;

    let max_resources = state.builder_sizes.max_resources_per_org as i64;
    if active_resources + 1 > max_resources {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            format!(
                "Resource limit reached ({}/{}). Destroy unused resources or contact support.",
                active_resources + 1,
                max_resources
            ),
        ));
    }

    // Atomically transition to Pending — rejects concurrent deploys via the check above
    if was_destroyed {
        tracing::info!("Reactivating previously destroyed resource {}", resource_id);
        sqlx::query("UPDATE compute_resources SET destroyed_at = NULL, state = $1 WHERE id = $2 AND organization_id = $3")
            .bind(types::ResourceState::Pending)
            .bind(resource_id)
            .bind(req.org_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to reactivate resource: {}", e)))?;
    } else {
        // Mark as Pending so concurrent pushes are rejected
        let updated = sqlx::query(
            "UPDATE compute_resources SET state = $1 WHERE id = $2 AND organization_id = $3 AND state != $1"
        )
        .bind(types::ResourceState::Pending)
        .bind(resource_id)
        .bind(req.org_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update resource state: {}", e)))?;

        if updated.rows_affected() == 0 {
            return Err((
                StatusCode::CONFLICT,
                "A deployment is already in progress for this app. Please wait for it to complete."
                    .to_string(),
            ));
        }
    }

    tracing::info!("Deploying branch: {}", req.branch);

    let commit_sha = match get_commit_sha(&app_id_str, &req.branch, &state.data_dir).await {
        Ok(sha) => {
            tracing::info!("Latest commit on branch '{}': {}", req.branch, sha);
            sha
        }
        Err(e) => {
            tracing::error!(
                "Failed to get commit SHA for branch '{}': {:?}",
                req.branch,
                e
            );
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "Failed to get commit SHA for branch '{}': {}",
                    req.branch, e
                ),
            ));
        }
    };

    let git_dir = format!("{}/git-repos/{}.git", state.data_dir, app_id_str);
    let procfile_output = Command::new("git")
        .args(&[
            "--git-dir",
            &git_dir,
            "show",
            &format!("{}:Procfile", commit_sha),
        ])
        .output()
        .await
        .map_err(|e| {
            tracing::error!("Failed to run git show for Procfile: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Git command failed: {}", e),
            )
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
                return Err((StatusCode::BAD_REQUEST, format!("Invalid Procfile: {}", e)));
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
    let build_command = configuration
        .get("cmd")
        .and_then(|v| v.as_str())
        .unwrap_or("docker build -t app .")
        .to_string();
    tracing::info!(
        "Using resource {} with build command: {}",
        resource_id,
        build_command
    );

    tracing::info!("Build command for {}: {}", app_name, build_command);

    let enclave_config = types::EnclaveConfig {
        binary_path: build_config
            .binary
            .clone()
            .unwrap_or_else(|| "/app".to_string()),
        args: vec![],
        memory_mb: build_config.memory_mb,
        cpus: build_config.cpus,
        debug: build_config.debug,
        ports: build_config.ports.clone(),
        http_port: build_config.http_port,
    };

    // --- Dedicated builder path ---
    // Builds are always offloaded to an ephemeral EC2 builder instance.
    let builder_cfg = &state.builder_config;
    let builder_eif_s3_key = {
        let procfile_content = String::from_utf8_lossy(&procfile_output.stdout).to_string();
        let enclaveos_commit = enclave_builder::build::resolve_enclaveos_commit();
        let cache_key = builder::compute_cache_key(
            &commit_sha,
            &enclaveos_commit,
            &procfile_content,
            build_config.e2e,
            build_config.locksmith,
        );

        // Check cache first
        let cached_result = if !build_config.no_cache {
            builder::check_build_cache(&state.db, req.org_id, &cache_key)
                .await
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Cache lookup failed: {}", e),
                    )
                })?
        } else {
            None
        };

        if let Some(cached) = cached_result {
            let _ = tx.send(Ok(milestone("Using cached build..."))).await;
            tracing::info!(
                "Builder cache HIT: cache_key={}, s3_key={}",
                cache_key,
                cached.eif_s3_key
            );
            cached.eif_s3_key
        } else {
            let _ = tx
                .send(Ok(milestone("Starting build on dedicated instance...")))
                .await;

            // Archive source and upload to S3
            let git_dir = format!("{}/git-repos/{}.git", state.data_dir, app_id_str);
            let s3_config = aws_config::from_env()
                .region(aws_sdk_s3::config::Region::new(
                    std::env::var("AWS_REGION").unwrap_or_else(|_| "us-west-2".to_string()),
                ))
                .load()
                .await;
            let s3_client = aws_sdk_s3::Client::new(&s3_config);

            // Pre-build balance check: refuse if org can't cover minimum build cost (~$0.30 for 1 min)
            let min_build_cost_cents: i64 = 50; // $0.50 minimum balance required
            let balance = crate::billing::get_ledger_balance_cents(&state.db, req.org_id)
                .await
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("DB error: {}", e),
                    )
                })?;

            if balance < min_build_cost_cents {
                return Err((
                    StatusCode::PAYMENT_REQUIRED,
                    format!(
                        "Insufficient credits for builder (balance: {}c, minimum: {}c)",
                        balance, min_build_cost_cents
                    ),
                ));
            }

            let build_id = uuid::Uuid::new_v4();
            let source_s3_key = builder::upload_source_archive(
                &s3_client,
                &builder_cfg.eif_s3_bucket,
                &git_dir,
                &commit_sha,
                build_id,
                req.org_id,
            )
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to upload source archive: {}", e),
                )
            })?;

            let platform_creds = crate::deployment::AwsCredentials {
                access_key_id: std::env::var("AWS_ACCESS_KEY_ID").unwrap_or_default(),
                secret_access_key: std::env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_default(),
                region: std::env::var("AWS_REGION").unwrap_or_else(|_| "us-west-2".to_string()),
            };
            let ec2_client = crate::ec2::Ec2Client::new(&platform_creds);

            let size_id = req
                .builder_size
                .as_deref()
                .or_else(|| configuration.get("builder_size").and_then(|v| v.as_str()));
            let resolved_size = state.builder_sizes.resolve(size_id);

            let build_request = builder::BuildRequest {
                org_id: req.org_id,
                app_id: resource_id,
                app_name: app_name.clone(),
                commit_sha: commit_sha.clone(),
                branch: req.branch.clone(),
                source_s3_key,
                procfile_content,
                run_command: build_config.run.clone(),
                build_command: Some(build_command.clone()),
                binary_path: build_config.binary.clone(),
                ports: enclave_config.ports.clone(),
                e2e: build_config.e2e,
                locksmith: build_config.locksmith,
                enclaveos_commit,
                builder_size: resolved_size.id.clone(),
                builder_instance_type: resolved_size.instance_type.clone(),
                app_sources: build_config.app_sources.clone(),
            };

            let build_result = builder::execute_remote_build(
                &state.db,
                &ec2_client,
                &s3_client,
                builder_cfg,
                &build_request,
                &cache_key,
                &tx,
                auth.user_id,
            )
            .await
            .map_err(|e| {
                tracing::error!("Dedicated builder failed: {:?}", e);
                if e.to_string() == builder::ACTIVE_BUILD_CONFLICT_MSG {
                    (
                        StatusCode::CONFLICT,
                        builder::ACTIVE_BUILD_CONFLICT_MSG.to_string(),
                    )
                } else {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Build failed: {}", e),
                    )
                }
            })?;

            build_result.eif_s3_key
        }
    };

    let eif_path = format!("s3://{}/{}", builder_cfg.eif_s3_bucket, builder_eif_s3_key);
    let (eif_hash, eif_size_bytes_db) = sqlx::query_as::<_, (String, i64)>(
        "SELECT eif_sha256, eif_size_bytes FROM eif_builds WHERE eif_s3_key = $1 AND status = 'completed' LIMIT 1"
    )
    .bind(&builder_eif_s3_key)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {}", e)))?
    .unwrap_or_else(|| {
        tracing::warn!("Could not find eif_builds metadata for s3_key={}, using defaults", builder_eif_s3_key);
        ("unknown".to_string(), 0)
    });

    tracing::info!(
        "Using builder EIF: s3_key={}, hash={}",
        builder_eif_s3_key,
        eif_hash
    );

    let eif_config = serde_json::json!({
        "eif_path": eif_path,
        "eif_hash": eif_hash,
        "eif_s3_key": builder_eif_s3_key,
        "eif_size_bytes": eif_size_bytes_db,
        "commit_sha": commit_sha,
        "run_command": build_config.run,
        "domain": build_config.domain,
        "memory_mb": enclave_config.memory_mb,
        "cpus": enclave_config.cpus,
        "debug": enclave_config.debug,
        "ports": enclave_config.ports,
        "http_port": enclave_config.http_port,
    });
    let eif_size_bytes = eif_size_bytes_db as u64;

    let memory_bytes = (enclave_config.memory_mb as u64) * 1024 * 1024;
    if eif_size_bytes > memory_bytes {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "EIF size ({} MB) exceeds allocated enclave memory ({} MB). Increase memory_mb in Procfile.",
                eif_size_bytes / (1024 * 1024),
                enclave_config.memory_mb
            ),
        ));
    }
    if eif_size_bytes > memory_bytes * 80 / 100 {
        tracing::warn!(
            "EIF size ({} MB) is more than 80% of allocated memory ({} MB). Consider increasing memory_mb.",
            eif_size_bytes / (1024 * 1024),
            enclave_config.memory_mb
        );
    }

    tracing::info!(
        "Deploying Nitro Enclave for resource {} with memory_mb={}, cpu_count={}, debug={}",
        resource_id,
        enclave_config.memory_mb,
        enclave_config.cpus,
        enclave_config.debug
    );

    // Check if there's a managed-on-prem credential linked to this resource
    // This takes precedence over the Procfile - if init was called with --config,
    // the credential is already linked to the resource
    let (credentials, managed_onprem_config) = {
        let cred =
            cloud_credentials::get_credential_by_resource(&state.db, req.org_id, resource_id)
                .await?;

        if let Some(credential) = cred {
            if credential.managed_on_prem {
                tracing::info!(
                    "Managed on-prem credential found for resource {}, using linked credential",
                    resource_id
                );

                let encryptor = state.encryptor.as_ref().ok_or_else(|| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Encryptor not configured".to_string(),
                    )
                })?;

                let secrets = cloud_credentials::get_credential_secrets(
                    &state.db,
                    encryptor,
                    req.org_id,
                    credential.id,
                )
                .await?;

                match secrets {
                    Some(secrets_json) => {
                        let aws_access_key_id =
                            secrets_json["aws_access_key_id"].as_str().ok_or_else(|| {
                                (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "Missing aws_access_key_id in managed on-prem credentials"
                                        .to_string(),
                                )
                            })?;
                        let aws_secret_access_key = secrets_json["aws_secret_access_key"]
                            .as_str()
                            .ok_or_else(|| {
                                (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "Missing aws_secret_access_key in managed on-prem credentials"
                                        .to_string(),
                                )
                            })?;

                        // Extract infrastructure config from credential
                        let config = &credential.config;
                        let region = config["aws_region"]
                            .as_str()
                            .unwrap_or("us-west-2")
                            .to_string();

                        let onprem_config = deployment::ManagedOnPremConfig {
                            deployment_id: config["deployment_id"]
                                .as_str()
                                .unwrap_or("")
                                .to_string(),
                            asg_name: config["asg_name"].as_str().unwrap_or("").to_string(),
                            launch_template_name: config["launch_template_name"]
                                .as_str()
                                .unwrap_or("")
                                .to_string(),
                            launch_template_id: config["launch_template_id"]
                                .as_str()
                                .unwrap_or("")
                                .to_string(),
                            vpc_id: config["vpc_id"].as_str().unwrap_or("").to_string(),
                            subnet_ids: config["subnet_ids"]
                                .as_array()
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                        .collect()
                                })
                                .unwrap_or_default(),
                            eif_bucket: config["eif_bucket"].as_str().unwrap_or("").to_string(),
                            instance_profile_name: config["instance_profile_name"]
                                .as_str()
                                .unwrap_or("")
                                .to_string(),
                        };

                        tracing::info!(
                            "Using managed on-prem config: deployment_id={}, region={}",
                            onprem_config.deployment_id,
                            region
                        );

                        (
                            Some(deployment::AwsCredentials {
                                access_key_id: aws_access_key_id.to_string(),
                                secret_access_key: aws_secret_access_key.to_string(),
                                region,
                            }),
                            Some(onprem_config),
                        )
                    }
                    None => {
                        return Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Failed to decrypt managed on-prem credentials".to_string(),
                        ));
                    }
                }
            } else {
                // Credential linked but not managed on-prem - fully managed deployment
                tracing::info!(
                    "Non-managed-on-prem credential found, using fully managed deployment"
                );
                (None, None)
            }
        } else {
            // No credential linked - fully managed deployment
            tracing::info!(
                "No credential linked to resource {}, using fully managed deployment",
                resource_id
            );
            (None, None)
        }
    };

    // Extract region from credentials before moving into nitro_request
    let deployed_region = credentials
        .as_ref()
        .map(|c| c.region.clone())
        .unwrap_or_else(|| "us-west-2".to_string());

    let nitro_request = deployment::NitroDeploymentRequest {
        org_id: req.org_id,
        resource_id,
        resource_name: app_name.clone(),
        aws_account_id: aws_account_id.clone(),
        role_arn: role_arn_opt.clone(),
        eif_path: eif_path.clone(),
        eif_s3_key: Some(builder_eif_s3_key.clone()),
        memory_mb: enclave_config.memory_mb,
        cpu_count: enclave_config.cpus,
        disk_gb: build_config.disk_gb,
        debug_mode: enclave_config.debug,
        ports: enclave_config.ports.clone(),
        http_port: enclave_config.http_port,
        ssh_keys: build_config.ssh_keys.clone(),
        domain: build_config.domain.clone(),
        credentials,
        managed_onprem: managed_onprem_config,
    };

    let _ = tx.send(Ok(milestone("Uploading and launching..."))).await;

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
         SET provider_resource_id = $1, state = $2, public_ip = $3, region = $4, configuration = COALESCE(configuration, '{}'::jsonb) || $5::jsonb
         WHERE id = $6 AND organization_id = $7"
    )
    .bind(&deployment_result.instance_id)
    .bind(types::ResourceState::Running)
    .bind(&deployment_result.public_ip)
    .bind(&deployed_region)
    .bind(&final_config)
    .bind(resource_id)
    .bind(req.org_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update resource: {}", e)))?;

    crate::metering::upsert_tracked_resource(
        &state,
        &deployment_result.instance_id,
        req.org_id,
        Some(auth.user_id),
        resource_id,
        "aws",
        deployment_result.instance_type.as_deref(),
        Some(&deployed_region),
        &serde_json::json!({
            "resource_kind": "compute_resource",
            "compute_resource_id": resource_id.to_string(),
            "instance_id": deployment_result.instance_id,
            "resource_name": app_name,
        }),
    )
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "Deployment succeeded but metering registration failed: {:#}",
                e
            ),
        )
    })?;

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

    let _ = tx.send(Ok(milestone("Waiting for health check..."))).await;

    tracing::info!("Waiting for attestation endpoint to become healthy...");
    if let Err(e) = wait_for_attestation_health(&deployment_result.public_ip, 120).await {
        tracing::error!("Attestation health check failed: {}", e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Enclave failed to become healthy: {}", e),
        ));
    }

    tracing::info!(
        "Deployment URLs - App: {}, Attestation: {}",
        app_url,
        attestation_url
    );

    let _ = tx.send(Ok(milestone_done("Deployment successful!"))).await;

    Ok(DeployResponse {
        url: app_url,
        attestation_url,
        resource_id,
        public_ip: deployment_result.public_ip.clone(),
        domain: build_config.domain.clone(),
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    if let Err(e) = provisioning::validate_setup() {
        tracing::warn!("Provisioning validation failed: {:?}", e);
        tracing::warn!("AWS child account provisioning will not be available");
    }
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let git_hostname =
        std::env::var("GIT_HOSTNAME").unwrap_or_else(|_| "alpha.caution.co".to_string());

    let git_ssh_port: Option<u16> = std::env::var("SSH_PORT").ok().and_then(|p| p.parse().ok());

    let data_dir =
        std::env::var("CAUTION_DATA_DIR").unwrap_or_else(|_| "/var/cache/caution".to_string());

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
            tracing::warn!(
                "Encryption not configured: {}. Cloud credentials feature disabled.",
                e
            );
            None
        }
    };

    let internal_service_secret = std::env::var("INTERNAL_SERVICE_SECRET").ok();
    if internal_service_secret.is_some() {
        info!("Internal service authentication enabled");
    } else {
        tracing::warn!(
            "INTERNAL_SERVICE_SECRET not set - internal service authentication disabled"
        );
    }

    // Paddle configuration
    let paddle_client_token = std::env::var("PADDLE_CLIENT_TOKEN").ok();
    let paddle_setup_price_id = std::env::var("PADDLE_SETUP_PRICE_ID").ok();
    if paddle_client_token.is_some() {
        info!("Paddle billing integration enabled");
    }
    if paddle_setup_price_id.is_none() {
        tracing::warn!("PADDLE_SETUP_PRICE_ID not set - checkout will not have items");
    }

    let paddle_credits_price_ids = [
        std::env::var("PADDLE_CREDITS_PRICE_ID_1000").ok(),
        std::env::var("PADDLE_CREDITS_PRICE_ID_5000").ok(),
        std::env::var("PADDLE_CREDITS_PRICE_ID_25000").ok(),
    ];

    let paddle_api_url = std::env::var("PADDLE_API_URL").unwrap_or_default();
    let paddle_api_key = std::env::var("PADDLE_API_KEY").ok();

    if paddle_api_key.is_some() && paddle_api_url.is_empty() {
        return Err("PADDLE_API_KEY is set but PADDLE_API_URL is not — set PADDLE_API_URL to the Paddle API base URL (e.g. https://sandbox-api.paddle.com or https://api.paddle.com)".into());
    }

    let pricing = PricingConfig::load()?;
    let builder_sizes = builder::BuilderSizesConfig::load()?;

    let builder_config = builder::BuilderConfig::from_env()?;
    info!("Dedicated builder enabled");

    let state = Arc::new(AppState {
        db: pool,
        git_hostname,
        git_ssh_port,
        data_dir,
        encryptor,
        internal_service_secret,
        paddle_client_token,
        paddle_setup_price_id,
        paddle_credits_price_ids,
        paddle_api_url,
        paddle_api_key,
        pricing,
        builder_config,
        builder_sizes,
    });

    let onboarding_routes = Router::new()
        .route("/user/status", get(onboarding::get_user_status))
        .route(
            "/onboarding/send-verification",
            post(onboarding::send_verification_email),
        )
        .route("/legal/accept", post(legal::accept_legal_document))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth_middleware,
        ));

    let resource_routes = Router::new()
        .route("/users/me", get(users::get_current_user))
        .route("/users/me", patch(users::update_current_user))
        .route("/users/me", delete(users::delete_current_user))
        .route("/organizations", get(organizations::list_organizations))
        .route("/organizations", post(organizations::create_organization))
        .route("/organizations/{id}", get(organizations::get_organization))
        .route(
            "/organizations/{id}",
            patch(organizations::update_organization),
        )
        .route(
            "/organizations/{id}",
            delete(organizations::delete_organization),
        )
        .route(
            "/organizations/{id}/settings",
            get(organizations::get_org_settings),
        )
        .route(
            "/organizations/{id}/settings",
            patch(organizations::update_org_settings),
        )
        .route(
            "/organizations/{id}/members",
            get(organizations::list_members),
        )
        .route(
            "/organizations/{id}/members",
            post(organizations::add_member),
        )
        .route(
            "/organizations/{id}/members/{user_id}",
            patch(organizations::update_member),
        )
        .route(
            "/organizations/{id}/members/{user_id}",
            delete(organizations::remove_member),
        )
        .route("/resources", post(resources::create_resource))
        .route("/resources", get(resources::list_resources))
        .route("/resources/{id}", get(resources::get_resource))
        .route("/resources/{id}", patch(resources::rename_resource))
        .route("/resources/{id}", delete(resources::delete_resource))
        .route(
            "/resources/{id}/attestation",
            post(resources::proxy_attestation),
        )
        .route("/resources/{id}/builder-config", get(get_builder_config))
        .route("/resources/{id}/builder-config", put(set_builder_config))
        .route(
            "/resources/managed-onprem",
            post(create_managed_onprem_resource),
        )
        .route("/deploy", post(deploy_handler))
        .route("/credentials", get(list_cloud_credentials))
        .route("/credentials", post(create_cloud_credential))
        .route("/credentials/{id}", get(get_cloud_credential))
        .route("/credentials/{id}", delete(delete_cloud_credential))
        .route(
            "/credentials/{id}/default",
            post(set_default_cloud_credential),
        )
        .route("/quorum-bundles", get(list_quorum_bundles))
        .route("/quorum-bundles", post(create_quorum_bundle))
        .route("/quorum-bundles/{id}", get(get_quorum_bundle))
        .route("/quorum-bundles/{id}", patch(update_quorum_bundle))
        .route("/quorum-bundles/{id}", delete(delete_quorum_bundle))
        .route("/secrets-bundles", get(list_secrets_bundles))
        .route("/secrets-bundles", post(create_secrets_bundle))
        .route("/secrets-bundles/{id}", get(get_secrets_bundle))
        .route("/secrets-bundles/{id}", patch(update_secrets_bundle))
        .route("/secrets-bundles/{id}", delete(delete_secrets_bundle))
        .route("/billing/usage", get(billing::get_billing_usage))
        .route("/billing/invoices", get(billing::get_billing_invoices))
        .route(
            "/billing/payment-methods",
            get(billing::get_payment_methods),
        )
        .route(
            "/billing/payment-methods/{id}",
            delete(billing::delete_payment_method),
        )
        .route(
            "/billing/payment-methods/{id}/set-primary",
            post(billing::set_primary_payment_method),
        )
        .route(
            "/billing/paddle/client-token",
            get(billing::get_paddle_client_token),
        )
        .route(
            "/billing/paddle/transaction-completed",
            post(billing::paddle_transaction_completed),
        )
        .route("/billing/credits/balance", get(billing::get_credit_balance))
        .route(
            "/billing/credits/packages",
            get(billing::get_credit_packages),
        )
        .route("/billing/credits/purchase", post(billing::purchase_credits))
        .route("/billing/credits/ledger", get(billing::get_credit_ledger))
        .route("/billing/credits/redeem", post(billing::redeem_credit_code))
        .route("/billing/auto-topup", get(billing::get_auto_topup))
        .route("/billing/auto-topup", put(billing::put_auto_topup))
        .route(
            "/billing/subscription/tiers",
            get(subscriptions::get_subscription_tiers),
        )
        .route(
            "/billing/subscription",
            get(subscriptions::get_subscription),
        )
        .route(
            "/billing/subscription/subscribe",
            post(subscriptions::subscribe),
        )
        .route(
            "/billing/subscription/change-tier",
            post(subscriptions::change_subscription_tier),
        )
        .route(
            "/billing/subscription/cancel",
            post(subscriptions::cancel_subscription),
        )
        .route(
            "/billing/subscription/reactivate",
            post(subscriptions::reactivate_subscription),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::onboarding_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::legal_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth_middleware,
        ));

    let internal_routes = Router::new()
        .route(
            "/internal/org/{org_id}/suspend",
            post(suspension::suspend_org_resources),
        )
        .route(
            "/internal/org/{org_id}/suspend-managed",
            post(suspension::suspend_managed_resources),
        )
        .route(
            "/internal/org/{org_id}/unsuspend",
            post(suspension::unsuspend_org_resources),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::internal_auth_middleware,
        ));

    let public_routes = Router::new()
        .route("/health", get(health_check))
        .route("/onboarding/verify", get(onboarding::verify_email));

    // Background task: reap orphaned builder instances
    let reaper_state = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(300)).await;
            let platform_creds = crate::deployment::AwsCredentials {
                access_key_id: std::env::var("AWS_ACCESS_KEY_ID").unwrap_or_default(),
                secret_access_key: std::env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_default(),
                region: std::env::var("AWS_REGION").unwrap_or_else(|_| "us-west-2".to_string()),
            };
            let ec2 = crate::ec2::Ec2Client::new(&platform_creds);
            builder::reap_orphaned_builders(&reaper_state.db, &ec2, |itype| {
                reaper_state.pricing.instance_pricing(itype)
            })
            .await;
        }
    });
    info!("Builder orphan reaper started (runs every 5 minutes)");

    let app = Router::new()
        .merge(onboarding_routes)
        .merge(resource_routes)
        .merge(internal_routes)
        .merge(public_routes)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;

    info!("API server listening on 0.0.0.0:8080");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to register SIGTERM handler");
    tokio::select! {
        _ = ctrl_c => tracing::info!("Received SIGINT, shutting down"),
        _ = sigterm.recv() => tracing::info!("Received SIGTERM, shutting down"),
    }
}
