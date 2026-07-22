// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    Json, Router,
    body::Body,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post, put},
};
use base64::Engine;
use chrono::{DateTime, Utc};
use dterror::{BoxError, CtxError, Location, ResultExt};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::Arc;
use tokio_stream::wrappers::ReceiverStream;
use tower_http::trace::TraceLayer;
use tracing::info;
use uuid::Uuid;

mod billing;
mod builder;
#[cfg(feature = "e2e-testing-unsafe")]
mod cleanup;
mod cloud_credentials;
mod config;
mod cryptographic_bundles;
mod deployment;
mod ec2;
mod eif_download;
mod encryption;
mod errors;
mod fully_managed_capacity;
mod gpg;
mod legal;
mod managed_dns;
mod metering;
mod middleware;
mod onboarding;
mod org_quorum;
mod organizations;
mod provisioning;
mod resources;
mod subscriptions;
mod suspension;
mod types;
mod users;
mod validated_types;
mod validation;
mod webauthn_reset;

const DEFAULT_DEPLOYMENT_HEALTH_TIMEOUT_SECS: u64 = 600;
const LIFECYCLE_RECONCILE_INTERVAL_SECS: u64 = 30;
const TEARDOWN_CONCURRENCY: usize = 2;

/// A `compute_resources` row as returned by the deploy lookup query.
type ExistingResourceRow = (
    Uuid,
    Option<String>,
    Option<serde_json::Value>,
    Option<DateTime<Utc>>,
    types::ResourceState,
);

/// A `subscriptions` entitlement row used to gate managed on-prem deploys.
type SubscriptionEntitlementRow = (
    Uuid,
    i32,
    Option<i32>,
    String,
    String,
    bool,
    Option<DateTime<Utc>>,
);

use caution_config::pricing::{
    CreditPackagePricing, PaddleCatalog, PricingConfig as SharedPricingConfig, TierPricing,
};

#[derive(Clone, Debug)]
pub(crate) struct PricingConfig {
    pub(crate) compute_margin_percent: f64,
    pub(crate) subscription_tiers: caution_config::pricing::DuplicateCheckedTiers,
    pub(crate) credit_packages: std::collections::HashMap<String, CreditPackagePricing>,
    pub(crate) paddle_catalog: Option<PaddleCatalog>,
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

/// Failure modes for [`PricingConfig::load`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum LoadPricingConfigError {
    #[error(
        "prices.json not found. Configure explicit pricing before starting the API. [{location}]"
    )]
    ReadFile {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error(
        "Failed to parse prices.json. Ensure compute_margin_percent is explicitly set. [{location}]"
    )]
    Parse {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
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
        let annual_tier_cents = self.subscription_tiers.get(tier_id)?.annual_cents();
        Some(annual_tier_cents as f64 / 100.0 / HOURS_PER_YEAR)
    }

    pub(crate) fn load() -> Result<Self, LoadPricingConfigError> {
        use LoadPricingConfigErrorCtx as Ctx;

        let contents = std::fs::read_to_string("prices.json").with_context(Ctx::read_file())?;
        let paddle_enabled = std::env::var("BYOC_PADDLE_SUBSCRIPTIONS_ENABLED")
            .is_ok_and(|value| value.eq_ignore_ascii_case("true"));
        let shared =
            SharedPricingConfig::parse(&contents, paddle_enabled).with_context(Ctx::parse())?;
        let config = Self {
            compute_margin_percent: shared.compute_margin_percent,
            subscription_tiers: shared.subscription_tiers,
            credit_packages: shared.credit_packages,
            paddle_catalog: shared.paddle_catalog,
        };
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
    pub(crate) database_url: String,
    pub(crate) teardown_slots: Arc<tokio::sync::Semaphore>,
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
    pub(crate) eif_download_cache: eif_download::EifDownloadCache,
    pub(crate) managed_dns: Option<managed_dns::ManagedDns>,
}

#[derive(Clone)]
pub(crate) struct AuthContext {
    pub(crate) user_id: Uuid,
}

use validated_types::{DeployRequest, DeployResponse};

/// Failure modes for [`check_org_access`] (leaf error: no underlying source).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum CheckOrgAccessError {
    #[error("Failed to check organization access [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Organization access denied [{location}]")]
    Forbidden { location: Location },
}

#[tracing::instrument(skip_all, err)]
pub(crate) async fn check_org_access(
    db: &PgPool,
    user_id: Uuid,
    org_id: Uuid,
) -> Result<types::UserRole, CheckOrgAccessError> {
    use CheckOrgAccessErrorCtx as Ctx;

    let member: Option<(types::UserRole,)> = sqlx::query_as(
        "SELECT role FROM organization_members
         WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_optional(db)
    .await
    .with_context(Ctx::query())?;

    member
        .map(|m| m.0)
        .ok_or_else(|| CheckOrgAccessError::Forbidden {
            location: std::panic::Location::caller(),
        })
}

pub(crate) fn can_manage_org(role: &types::UserRole) -> bool {
    role.can_manage_org()
}

pub(crate) fn is_owner(role: &types::UserRole) -> bool {
    role.is_owner()
}

/// Failure modes for [`get_user_primary_org`] (leaf error: no underlying source).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetUserPrimaryOrgError {
    #[error("Failed to get primary organization [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("User has no primary organization [{location}]")]
    NotFound { location: Location },
}

#[tracing::instrument(skip_all, err)]
pub(crate) async fn get_user_primary_org(
    db: &PgPool,
    user_id: Uuid,
) -> Result<Uuid, GetUserPrimaryOrgError> {
    use GetUserPrimaryOrgErrorCtx as Ctx;

    let org_id: Option<(Uuid,)> = sqlx::query_as(
        "SELECT organization_id FROM organization_members
         WHERE user_id = $1
         ORDER BY created_at ASC, id ASC
         LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .with_context(Ctx::query())?;

    org_id
        .map(|o| o.0)
        .ok_or_else(|| GetUserPrimaryOrgError::NotFound {
            location: std::panic::Location::caller(),
        })
}

/// Failure modes for [`get_or_create_provider_account`] (leaf error: no underlying source).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetOrCreateProviderAccountError {
    #[error("AWS_ACCOUNT_ID environment variable not set [{location}]")]
    MissingEnvVar {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Failed to look up provider account [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Failed to update provider account [{location}]")]
    Update {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Failed to create provider account [{location}]")]
    Insert {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
pub(crate) async fn get_or_create_provider_account(
    db: &PgPool,
    org_id: Uuid,
) -> Result<Uuid, GetOrCreateProviderAccountError> {
    use GetOrCreateProviderAccountErrorCtx as Ctx;

    let aws_account_id = std::env::var("AWS_ACCOUNT_ID").with_context(Ctx::missing_env_var())?;

    let existing: Option<(Uuid, Option<String>, Option<bool>)> = sqlx::query_as(
        "SELECT pa.id, pa.role_arn, pa.is_active FROM provider_accounts pa
         JOIN providers p ON pa.provider_id = p.id
         WHERE pa.organization_id = $1 AND p.provider_type = 'aws'
         LIMIT 1",
    )
    .bind(org_id)
    .fetch_optional(db)
    .await
    .with_context(Ctx::query())?;

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
            .with_context(Ctx::update())?;

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
    .with_context(Ctx::insert())?;

    tracing::info!(
        "Created provider account {} for org {} using AWS account {}",
        account_id.0,
        org_id,
        aws_account_id
    );

    Ok(account_id.0)
}

/// Failure modes for [`get_or_create_resource_type`] (leaf error: no underlying source).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetOrCreateResourceTypeError {
    #[error("Failed to look up resource type [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Failed to create resource type [{location}]")]
    Insert {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
pub(crate) async fn get_or_create_resource_type(
    db: &PgPool,
) -> Result<Uuid, GetOrCreateResourceTypeError> {
    use GetOrCreateResourceTypeErrorCtx as Ctx;

    let existing: Option<(Uuid,)> = sqlx::query_as(
        "SELECT rt.id FROM resource_types rt
         JOIN providers p ON rt.provider_id = p.id
         WHERE p.provider_type = 'aws' AND rt.type_code = $1
         LIMIT 1",
    )
    .bind(types::AWSResourceType::EC2Instance.as_str())
    .fetch_optional(db)
    .await
    .with_context(Ctx::query())?;

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
    .with_context(Ctx::insert())?;

    Ok(type_id.0)
}

async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

const PLATFORM_REPO: &str = "https://codeberg.org/caution/platform.git";

async fn build_inputs() -> impl IntoResponse {
    #[derive(serde::Serialize)]
    struct BuildInputs {
        #[serde(skip_serializing_if = "Option::is_none")]
        platform: Option<PlatformSource>,
        enclaveos: enclave_builder::build::ToolSource,
        bootproof: enclave_builder::build::ToolSource,
        steve: enclave_builder::build::ToolSource,
        locksmith: enclave_builder::build::ToolSource,
    }
    #[derive(serde::Serialize)]
    struct PlatformSource {
        commit: String,
        repo: &'static str,
    }

    let tools = enclave_builder::build::resolve_tool_commits();
    let platform = std::env::var("PLATFORM_GIT_SHA")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(|commit| PlatformSource {
            commit,
            repo: PLATFORM_REPO,
        });

    Json(BuildInputs {
        platform,
        enclaveos: tools.enclaveos,
        bootproof: tools.bootproof,
        steve: tools.steve,
        locksmith: tools.locksmith,
    })
}

#[tracing::instrument(skip_all)]
pub(crate) fn deployment_health_timeout_secs() -> u64 {
    std::env::var("DEPLOYMENT_HEALTH_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|timeout| *timeout > 0)
        .unwrap_or(DEFAULT_DEPLOYMENT_HEALTH_TIMEOUT_SECS)
}

/// Failure modes shared by [`wait_for_health`] and [`wait_for_attestation_health`]
/// (sibling helpers whose callers unify on one return type).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum WaitForHealthError {
    #[error("Failed to create HTTP client [{location}]")]
    ClientBuild {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Health endpoint did not become healthy within {timeout_secs} seconds [{location}]")]
    HealthTimeout {
        timeout_secs: u64,
        location: Location,
    },

    #[error(
        "Attestation endpoint did not become healthy within {timeout_secs} seconds [{location}]"
    )]
    AttestationTimeout {
        timeout_secs: u64,
        location: Location,
    },
}

impl WaitForHealthError {
    pub(crate) fn client_message(&self) -> String {
        match self {
            Self::ClientBuild { .. } => "Failed to create HTTP client".to_string(),
            Self::HealthTimeout { timeout_secs, .. } => {
                format!(
                    "Health endpoint did not become healthy within {} seconds",
                    timeout_secs
                )
            }
            Self::AttestationTimeout { timeout_secs, .. } => {
                format!(
                    "Attestation endpoint did not become healthy within {} seconds",
                    timeout_secs
                )
            }
        }
    }
}

#[tracing::instrument(skip_all, err)]
pub(crate) async fn wait_for_health(
    public_ip: &str,
    timeout_secs: u64,
) -> Result<(), WaitForHealthError> {
    use WaitForHealthErrorCtx as Ctx;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .with_context(Ctx::client_build())?;

    let url = format!("http://{public_ip}/.well-known/caution/health");
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_secs);
    let mut attempt = 0u32;

    loop {
        attempt += 1;
        tracing::info!("Polling endpoint (attempt {}): {}", attempt, url);

        let result = client.get(&url).send().await;

        match result {
            Ok(resp) if resp.status().is_success() => {
                return Ok(());
            }
            Ok(resp) => {
                tracing::debug!("Health endpoint returned status {}", resp.status());
            }
            Err(e) => {
                tracing::debug!("Health endpoint not ready: {}", e);
            }
        }

        if start.elapsed() >= timeout {
            return Err(WaitForHealthError::HealthTimeout {
                timeout_secs,
                location: std::panic::Location::caller(),
            });
        }

        let delay = std::cmp::min(2u64.pow(attempt.min(4)), 30);
        tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
    }
}

#[cfg(test)]
mod deployment_health_tests {
    use super::wait_for_health;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn health_check_rejects_error_responses() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            let bytes_read = socket.read(&mut request).await.unwrap();
            assert!(bytes_read > 0);
            socket
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });

        let error = wait_for_health(&address.to_string(), 0).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Health endpoint did not become healthy within 0 seconds")
        );
        server.await.unwrap();
    }
}

#[tracing::instrument(skip_all, err)]
pub(crate) async fn wait_for_attestation_health(
    public_ip: &str,
    timeout_secs: u64,
) -> Result<(), WaitForHealthError> {
    use WaitForHealthErrorCtx as Ctx;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .with_context(Ctx::client_build())?;

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
            return Err(WaitForHealthError::AttestationTimeout {
                timeout_secs,
                location: std::panic::Location::caller(),
            });
        }

        let delay = std::cmp::min(2u64.pow(attempt.min(4)), 30);
        tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
    }
}

/// Failure modes for [`get_commit_sha`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetCommitShaError {
    #[error("Failed to run git rev-parse [{location}]")]
    Spawn {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Failed to get commit SHA for branch '{branch}': {stderr} [{location}]")]
    CommandFailed {
        branch: String,
        stderr: String,
        location: Location,
    },
}

#[tracing::instrument(skip_all, err)]
async fn get_commit_sha(
    app_name: &str,
    branch: &str,
    data_dir: &str,
) -> Result<String, GetCommitShaError> {
    use GetCommitShaErrorCtx as Ctx;
    use tokio::process::Command;

    let repo_path = format!("{}/git-repos/{}.git", data_dir, app_name);
    let ref_spec = format!("refs/heads/{}", branch);

    let output = Command::new("git")
        .args(["--git-dir", &repo_path, "rev-parse", &ref_spec])
        .output()
        .await
        .with_context(Ctx::spawn())?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GetCommitShaError::CommandFailed {
            branch: branch.to_string(),
            stderr: stderr.trim().to_string(),
            location: std::panic::Location::caller(),
        });
    }

    let commit_sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(commit_sha)
}

/// Failure modes for [`select_deploy_commit_sha`] (leaf error: no underlying source).
#[derive(Debug, thiserror::Error)]
pub(crate) enum SelectDeployCommitShaError {
    #[error(
        "commit_sha does not match refs/heads/{branch} (expected {resolved_commit_sha}, got {requested_commit_sha}) [{location}]"
    )]
    Mismatch {
        branch: String,
        resolved_commit_sha: String,
        requested_commit_sha: String,
        location: Location,
    },
}

#[tracing::instrument(skip_all, err)]
fn select_deploy_commit_sha(
    branch: &str,
    resolved_commit_sha: &str,
    requested_commit_sha: Option<&str>,
) -> Result<String, SelectDeployCommitShaError> {
    let resolved_commit_sha = resolved_commit_sha.to_ascii_lowercase();

    if let Some(requested_commit_sha) = requested_commit_sha
        && !requested_commit_sha.eq_ignore_ascii_case(&resolved_commit_sha)
    {
        return Err(SelectDeployCommitShaError::Mismatch {
            branch: branch.to_string(),
            resolved_commit_sha,
            requested_commit_sha: requested_commit_sha.to_string(),
            location: std::panic::Location::caller(),
        });
    }

    Ok(resolved_commit_sha)
}

/// Failure modes for [`list_cloud_credentials`] (leaf error: no underlying source).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ListCloudCredentialsError {
    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to list cloud credentials [{location}]")]
    List {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for ListCloudCredentialsError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            ListCloudCredentialsError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            ListCloudCredentialsError::List { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(user_id = %auth.user_id))]
async fn list_cloud_credentials(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<cloud_credentials::CloudCredential>>, ListCloudCredentialsError> {
    use ListCloudCredentialsErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    let credentials = cloud_credentials::list_credentials(&state.db, org_id)
        .await
        .with_context(Ctx::list())?;
    Ok(Json(credentials))
}

/// Failure modes for [`create_cloud_credential`] (leaf error: no underlying source).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum CreateCloudCredentialError {
    #[error("cloud credentials feature not configured [{location}]")]
    EncryptorMissing { location: Location },

    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to create cloud credential [{location}]")]
    Internal {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for CreateCloudCredentialError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            CreateCloudCredentialError::EncryptorMissing { .. } => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Cloud credentials feature not configured. Set CAUTION_ENCRYPTION_KEY.",
            ),
            CreateCloudCredentialError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            CreateCloudCredentialError::Internal { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(user_id = %auth.user_id))]
async fn create_cloud_credential(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<cloud_credentials::CreateCredentialRequest>,
) -> Result<Json<cloud_credentials::CloudCredential>, CreateCloudCredentialError> {
    use CreateCloudCredentialErrorCtx as Ctx;

    let encryptor = state.encryptor.as_ref().ok_or_else(|| {
        tracing::error!("Cloud credentials feature not configured");
        CreateCloudCredentialError::EncryptorMissing {
            location: std::panic::Location::caller(),
        }
    })?;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    let credential =
        cloud_credentials::create_credential(&state.db, encryptor, org_id, auth.user_id, req)
            .await
            .with_context(Ctx::internal())?;
    Ok(Json(credential))
}

/// Failure modes for [`get_cloud_credential`] (leaf error: no underlying source).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetCloudCredentialError {
    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("credential {credential_id} not found [{location}]")]
    NotFound {
        credential_id: Uuid,
        location: Location,
    },

    #[error("failed to get cloud credential [{location}]")]
    Get {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for GetCloudCredentialError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            GetCloudCredentialError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            GetCloudCredentialError::NotFound { .. } => {
                (StatusCode::NOT_FOUND, "Credential not found")
            }
            GetCloudCredentialError::Get { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(credential_id = %credential_id))]
async fn get_cloud_credential(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(credential_id): Path<Uuid>,
) -> Result<Json<cloud_credentials::CloudCredential>, GetCloudCredentialError> {
    use GetCloudCredentialErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    let credential = cloud_credentials::get_credential(&state.db, org_id, credential_id)
        .await
        .with_context(Ctx::get())?
        .ok_or_else(|| GetCloudCredentialError::NotFound {
            credential_id,
            location: std::panic::Location::caller(),
        })?;

    Ok(Json(credential))
}

/// Failure modes for [`delete_cloud_credential`] (leaf error: no underlying source).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum DeleteCloudCredentialError {
    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("credential {credential_id} not found [{location}]")]
    NotFound {
        credential_id: Uuid,
        location: Location,
    },

    #[error("failed to delete cloud credential [{location}]")]
    Delete {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for DeleteCloudCredentialError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            DeleteCloudCredentialError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            DeleteCloudCredentialError::NotFound { .. } => {
                (StatusCode::NOT_FOUND, "Credential not found")
            }
            DeleteCloudCredentialError::Delete { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(credential_id = %credential_id))]
async fn delete_cloud_credential(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(credential_id): Path<Uuid>,
) -> Result<StatusCode, DeleteCloudCredentialError> {
    use DeleteCloudCredentialErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    let deleted = cloud_credentials::delete_credential(&state.db, org_id, credential_id)
        .await
        .with_context(Ctx::delete())?;

    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(DeleteCloudCredentialError::NotFound {
            credential_id,
            location: std::panic::Location::caller(),
        })
    }
}

/// Failure modes for [`set_default_cloud_credential`] (leaf error: no underlying source).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SetDefaultCloudCredentialError {
    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("credential {credential_id} not found [{location}]")]
    NotFound {
        credential_id: Uuid,
        location: Location,
    },

    #[error("failed to set default cloud credential [{location}]")]
    Update {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for SetDefaultCloudCredentialError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            SetDefaultCloudCredentialError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            SetDefaultCloudCredentialError::NotFound { .. } => {
                (StatusCode::NOT_FOUND, "Credential not found")
            }
            SetDefaultCloudCredentialError::Update { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(credential_id = %credential_id))]
async fn set_default_cloud_credential(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(credential_id): Path<Uuid>,
) -> Result<StatusCode, SetDefaultCloudCredentialError> {
    use SetDefaultCloudCredentialErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    let updated = cloud_credentials::set_default_credential(&state.db, org_id, credential_id)
        .await
        .with_context(Ctx::update())?;

    if updated {
        Ok(StatusCode::OK)
    } else {
        Err(SetDefaultCloudCredentialError::NotFound {
            credential_id,
            location: std::panic::Location::caller(),
        })
    }
}

/// Failure modes for [`list_quorum_bundles`] (leaf error: no underlying source).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ListQuorumBundlesError {
    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to list quorum bundles [{location}]")]
    List {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for ListQuorumBundlesError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            ListQuorumBundlesError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            ListQuorumBundlesError::List { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(user_id = %auth.user_id))]
async fn list_quorum_bundles(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<cryptographic_bundles::QuorumBundle>>, ListQuorumBundlesError> {
    use ListQuorumBundlesErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    let items = cryptographic_bundles::list_quorum_bundles(&state.db, org_id)
        .await
        .with_context(Ctx::list())?;
    Ok(Json(items))
}

/// Failure modes for [`create_quorum_bundle`] (leaf error: no underlying source).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum CreateQuorumBundleError {
    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to create quorum bundle [{location}]")]
    Create {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for CreateQuorumBundleError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            CreateQuorumBundleError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            CreateQuorumBundleError::Create { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(user_id = %auth.user_id))]
async fn create_quorum_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<cryptographic_bundles::CreateBundleRequest>,
) -> Result<Json<cryptographic_bundles::QuorumBundle>, CreateQuorumBundleError> {
    use CreateQuorumBundleErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    let bundle = cryptographic_bundles::create_quorum_bundle(&state.db, org_id, auth.user_id, req)
        .await
        .with_context(Ctx::create())?;
    Ok(Json(bundle))
}

async fn create_org_user_quorum_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<org_quorum::GenerateOrgQuorumBundleRequest>,
) -> Result<Json<cryptographic_bundles::QuorumBundle>, (StatusCode, String)> {
    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .map_err(|e| (e, "Failed to get organization".to_string()))?;

    let bundle =
        org_quorum::generate_org_quorum_bundle(&state.db, org_id, auth.user_id, req).await?;
    Ok(Json(bundle))
}

/// Failure modes for [`get_quorum_bundle`] (leaf error: no underlying source).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetQuorumBundleError {
    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("quorum bundle {bundle_id} not found [{location}]")]
    NotFound { bundle_id: Uuid, location: Location },

    #[error("failed to get quorum bundle [{location}]")]
    Get {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for GetQuorumBundleError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            GetQuorumBundleError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            GetQuorumBundleError::NotFound { .. } => {
                (StatusCode::NOT_FOUND, "Quorum bundle not found")
            }
            GetQuorumBundleError::Get { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(bundle_id = %id))]
async fn get_quorum_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<cryptographic_bundles::QuorumBundle>, GetQuorumBundleError> {
    use GetQuorumBundleErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    let bundle = cryptographic_bundles::get_quorum_bundle(&state.db, org_id, id)
        .await
        .with_context(Ctx::get())?
        .ok_or_else(|| GetQuorumBundleError::NotFound {
            bundle_id: id,
            location: std::panic::Location::caller(),
        })?;

    Ok(Json(bundle))
}

/// Failure modes for [`update_quorum_bundle`] (leaf error: no underlying source).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum UpdateQuorumBundleError {
    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("quorum bundle {bundle_id} not found [{location}]")]
    NotFound { bundle_id: Uuid, location: Location },

    #[error("failed to update quorum bundle [{location}]")]
    Update {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for UpdateQuorumBundleError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            UpdateQuorumBundleError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            UpdateQuorumBundleError::NotFound { .. } => {
                (StatusCode::NOT_FOUND, "Quorum bundle not found")
            }
            UpdateQuorumBundleError::Update { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(bundle_id = %id))]
async fn update_quorum_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(req): Json<cryptographic_bundles::UpdateBundleRequest>,
) -> Result<Json<cryptographic_bundles::QuorumBundle>, UpdateQuorumBundleError> {
    use UpdateQuorumBundleErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    let bundle = cryptographic_bundles::update_quorum_bundle(&state.db, org_id, id, req)
        .await
        .with_context(Ctx::update())?
        .ok_or_else(|| UpdateQuorumBundleError::NotFound {
            bundle_id: id,
            location: std::panic::Location::caller(),
        })?;

    Ok(Json(bundle))
}

/// Failure modes for [`delete_quorum_bundle`] (leaf error: no underlying source).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum DeleteQuorumBundleError {
    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("quorum bundle {bundle_id} not found [{location}]")]
    NotFound { bundle_id: Uuid, location: Location },

    #[error("failed to delete quorum bundle [{location}]")]
    Delete {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for DeleteQuorumBundleError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            DeleteQuorumBundleError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            DeleteQuorumBundleError::NotFound { .. } => {
                (StatusCode::NOT_FOUND, "Quorum bundle not found")
            }
            DeleteQuorumBundleError::Delete { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(bundle_id = %id))]
async fn delete_quorum_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, DeleteQuorumBundleError> {
    use DeleteQuorumBundleErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    let deleted = cryptographic_bundles::delete_quorum_bundle(&state.db, org_id, id)
        .await
        .with_context(Ctx::delete())?;

    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(DeleteQuorumBundleError::NotFound {
            bundle_id: id,
            location: std::panic::Location::caller(),
        })
    }
}

/// Failure modes for [`list_secrets_bundles`] (leaf error: no underlying source).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ListSecretsBundlesError {
    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to list secrets bundles [{location}]")]
    List {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for ListSecretsBundlesError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            ListSecretsBundlesError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            ListSecretsBundlesError::List { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(user_id = %auth.user_id))]
async fn list_secrets_bundles(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<cryptographic_bundles::SecretsBundle>>, ListSecretsBundlesError> {
    use ListSecretsBundlesErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    let items = cryptographic_bundles::list_secrets_bundles(&state.db, org_id)
        .await
        .with_context(Ctx::list())?;
    Ok(Json(items))
}

/// Failure modes for [`create_secrets_bundle`] (leaf error: no underlying source).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum CreateSecretsBundleError {
    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to create secrets bundle [{location}]")]
    Create {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for CreateSecretsBundleError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            CreateSecretsBundleError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            CreateSecretsBundleError::Create { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(user_id = %auth.user_id))]
async fn create_secrets_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<cryptographic_bundles::CreateBundleRequest>,
) -> Result<Json<cryptographic_bundles::SecretsBundle>, CreateSecretsBundleError> {
    use CreateSecretsBundleErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    let bundle = cryptographic_bundles::create_secrets_bundle(&state.db, org_id, auth.user_id, req)
        .await
        .with_context(Ctx::create())?;
    Ok(Json(bundle))
}

/// Failure modes for [`get_secrets_bundle`] (leaf error: no underlying source).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetSecretsBundleError {
    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("secrets bundle {bundle_id} not found [{location}]")]
    NotFound { bundle_id: Uuid, location: Location },

    #[error("failed to get secrets bundle [{location}]")]
    Get {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for GetSecretsBundleError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            GetSecretsBundleError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            GetSecretsBundleError::NotFound { .. } => {
                (StatusCode::NOT_FOUND, "Secrets bundle not found")
            }
            GetSecretsBundleError::Get { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(bundle_id = %id))]
async fn get_secrets_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<cryptographic_bundles::SecretsBundle>, GetSecretsBundleError> {
    use GetSecretsBundleErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    let bundle = cryptographic_bundles::get_secrets_bundle(&state.db, org_id, id)
        .await
        .with_context(Ctx::get())?
        .ok_or_else(|| GetSecretsBundleError::NotFound {
            bundle_id: id,
            location: std::panic::Location::caller(),
        })?;

    Ok(Json(bundle))
}

/// Failure modes for [`update_secrets_bundle`] (leaf error: no underlying source).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum UpdateSecretsBundleError {
    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("secrets bundle {bundle_id} not found [{location}]")]
    NotFound { bundle_id: Uuid, location: Location },

    #[error("failed to update secrets bundle [{location}]")]
    Update {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for UpdateSecretsBundleError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            UpdateSecretsBundleError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            UpdateSecretsBundleError::NotFound { .. } => {
                (StatusCode::NOT_FOUND, "Secrets bundle not found")
            }
            UpdateSecretsBundleError::Update { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(bundle_id = %id))]
async fn update_secrets_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(req): Json<cryptographic_bundles::UpdateBundleRequest>,
) -> Result<Json<cryptographic_bundles::SecretsBundle>, UpdateSecretsBundleError> {
    use UpdateSecretsBundleErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    let bundle = cryptographic_bundles::update_secrets_bundle(&state.db, org_id, id, req)
        .await
        .with_context(Ctx::update())?
        .ok_or_else(|| UpdateSecretsBundleError::NotFound {
            bundle_id: id,
            location: std::panic::Location::caller(),
        })?;

    Ok(Json(bundle))
}

/// Failure modes for [`delete_secrets_bundle`] (leaf error: no underlying source).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum DeleteSecretsBundleError {
    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("secrets bundle {bundle_id} not found [{location}]")]
    NotFound { bundle_id: Uuid, location: Location },

    #[error("failed to delete secrets bundle [{location}]")]
    Delete {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for DeleteSecretsBundleError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            DeleteSecretsBundleError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            DeleteSecretsBundleError::NotFound { .. } => {
                (StatusCode::NOT_FOUND, "Secrets bundle not found")
            }
            DeleteSecretsBundleError::Delete { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(bundle_id = %id))]
async fn delete_secrets_bundle(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, DeleteSecretsBundleError> {
    use DeleteSecretsBundleErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    let deleted = cryptographic_bundles::delete_secrets_bundle(&state.db, org_id, id)
        .await
        .with_context(Ctx::delete())?;

    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(DeleteSecretsBundleError::NotFound {
            bundle_id: id,
            location: std::panic::Location::caller(),
        })
    }
}

/// Failure modes for [`create_managed_onprem_resource`] (leaf error: no underlying source).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum CreateManagedOnpremResourceError {
    #[error("GPG decryption failed [{location}]")]
    DecryptFailed {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("invalid JSON body [{location}]")]
    InvalidJson {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("this endpoint requires managed_on_prem: true [{location}]")]
    NotManagedOnPrem { location: Location },

    #[error("deployment_id is required [{location}]")]
    MissingDeploymentId { location: Location },

    #[error("encryption not configured [{location}]")]
    EncryptorMissing { location: Location },

    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to look up existing resource [{location}]")]
    ExistingQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("resource not found [{location}]")]
    ResourceNotFound { location: Location },

    #[error("failed to update resource [{location}]")]
    UpdateResource {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to delete old credential [{location}]")]
    DeleteOldCredential {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to create cloud credential [{location}]")]
    CredentialInternal {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not obtain a provider account [{location}]")]
    ProviderAccount {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not obtain the compute resource type [{location}]")]
    ResourceType {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to create compute resource [{location}]")]
    InsertResource {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for CreateManagedOnpremResourceError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            CreateManagedOnpremResourceError::DecryptFailed { .. } => {
                (StatusCode::BAD_REQUEST, "GPG decryption failed")
            }
            CreateManagedOnpremResourceError::InvalidJson { .. } => {
                (StatusCode::BAD_REQUEST, "Invalid JSON")
            }
            CreateManagedOnpremResourceError::NotManagedOnPrem { .. } => (
                StatusCode::BAD_REQUEST,
                "This endpoint requires managed_on_prem: true",
            ),
            CreateManagedOnpremResourceError::MissingDeploymentId { .. } => {
                (StatusCode::BAD_REQUEST, "deployment_id is required")
            }
            CreateManagedOnpremResourceError::EncryptorMissing { .. } => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Encryption not configured. Set CAUTION_ENCRYPTION_KEY.",
            ),
            CreateManagedOnpremResourceError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            CreateManagedOnpremResourceError::ExistingQuery { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            CreateManagedOnpremResourceError::ResourceNotFound { .. } => {
                (StatusCode::NOT_FOUND, "Resource not found")
            }
            CreateManagedOnpremResourceError::UpdateResource { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            CreateManagedOnpremResourceError::DeleteOldCredential { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            CreateManagedOnpremResourceError::CredentialInternal { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            CreateManagedOnpremResourceError::ProviderAccount { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get provider account",
            ),
            CreateManagedOnpremResourceError::ResourceType { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get resource type",
            ),
            CreateManagedOnpremResourceError::InsertResource { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

/// Create or update a managed on-prem resource.
/// Accepts either plain JSON or GPG-encrypted config from the setup script.
/// If resource_id is provided, updates the existing resource; otherwise creates a new one.
#[tracing::instrument(skip_all, err)]
async fn create_managed_onprem_resource(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    body: String,
) -> Result<Json<serde_json::Value>, CreateManagedOnpremResourceError> {
    use CreateManagedOnpremResourceErrorCtx as Ctx;

    let json_content = if gpg::is_gpg_encrypted(&body) {
        tracing::info!("Received GPG-encrypted managed on-prem config, decrypting...");
        let decrypted = gpg::decrypt_gpg_message(&body).with_context(Ctx::decrypt_failed())?;
        tracing::info!("GPG decryption successful");
        decrypted
    } else {
        body
    };

    let mut req: cloud_credentials::CreateCredentialRequest =
        serde_json::from_str(&json_content).with_context(Ctx::invalid_json())?;

    if !req.managed_on_prem {
        return Err(CreateManagedOnpremResourceError::NotManagedOnPrem {
            location: std::panic::Location::caller(),
        });
    }

    let deployment_id = req.deployment_id.clone().ok_or_else(|| {
        CreateManagedOnpremResourceError::MissingDeploymentId {
            location: std::panic::Location::caller(),
        }
    })?;

    let encryptor = state.encryptor.as_ref().ok_or_else(|| {
        CreateManagedOnpremResourceError::EncryptorMissing {
            location: std::panic::Location::caller(),
        }
    })?;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    let managed_onprem_config = serde_json::json!({
        "deployment_id": req.deployment_id,
        "asg_name": req.asg_name,
        "launch_template_name": req.launch_template_name,
        "launch_template_id": req.launch_template_id,
        "vpc_id": req.vpc_id,
        "subnet_ids": req.subnet_ids,
        "eif_bucket": req.eif_bucket,
        "instance_profile_name": req.instance_profile_name,
        "builder_instance_profile_name": req.builder_instance_profile_name,
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

        let existing: Option<(String, types::ResourceState, String, Option<String>)> =
            sqlx::query_as(
                "SELECT resource_name, state, dns_status, dns_error FROM compute_resources
             WHERE id = $1 AND organization_id = $2",
            )
            .bind(existing_resource_id)
            .bind(org_id)
            .fetch_optional(&state.db)
            .await
            .with_context(Ctx::existing_query())?;

        let (resource_name, resource_state, dns_status, dns_error) = existing.ok_or_else(|| {
            tracing::warn!("Resource {} not found", existing_resource_id);
            CreateManagedOnpremResourceError::ResourceNotFound {
                location: std::panic::Location::caller(),
            }
        })?;

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
        .with_context(Ctx::update_resource())?;

        sqlx::query(
            "DELETE FROM cloud_credentials WHERE resource_id = $1 AND organization_id = $2",
        )
        .bind(existing_resource_id)
        .bind(org_id)
        .execute(&state.db)
        .await
        .with_context(Ctx::delete_old_credential())?;

        let credential =
            cloud_credentials::create_credential(&state.db, encryptor, org_id, auth.user_id, req)
                .await
                .with_context(Ctx::credential_internal())?;

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
            "managed_hostname": managed_dns::managed_hostname(existing_resource_id),
            "dns_status": dns_status,
            "dns_error": dns_error,
            "updated": true,
        })))
    } else {
        tracing::info!(
            "Creating managed on-prem resource: deployment_id={}",
            deployment_id
        );

        let provider_account_id = get_or_create_provider_account(&state.db, org_id)
            .await
            .with_context(Ctx::provider_account())?;

        let resource_type_id = get_or_create_resource_type(&state.db)
            .await
            .with_context(Ctx::resource_type())?;

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
        .with_context(Ctx::insert_resource())?;

        let (resource_id, resource_state, created_at) = resource;

        req.resource_id = Some(resource_id);

        let credential =
            cloud_credentials::create_credential(&state.db, encryptor, org_id, auth.user_id, req)
                .await
                .with_context(Ctx::credential_internal())?;

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
            "managed_hostname": managed_dns::managed_hostname(resource_id),
            "dns_status": "reserved",
            "dns_error": null,
        })))
    }
}

#[tracing::instrument(skip_all)]
fn milestone(msg: &str) -> bytes::Bytes {
    bytes::Bytes::from(format!("STEP:{}\n", msg))
}

#[tracing::instrument(skip_all)]
fn milestone_done(msg: &str) -> bytes::Bytes {
    bytes::Bytes::from(format!("{}\n", msg))
}

fn milestone_error(msg: &str) -> bytes::Bytes {
    bytes::Bytes::from(format!("error: {}\n", msg))
}

/// Failure modes for [`recover_deploy_failure`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum RecoverDeployFailureError {
    #[error("failed to hand deploy attempt to guarded rollback [{location}]")]
    Handoff {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("rollback retained infrastructure and will be retried [{location}]")]
    RollbackDestroy {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to restore resource state after deploy error [{location}]")]
    RestoreState {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip_all, err)]
async fn recover_deploy_failure(
    state: &Arc<AppState>,
    org_id: Uuid,
    resource_id: Uuid,
    deploy_attempt_id: Uuid,
    resource_name: &str,
    previous_state: types::ResourceState,
    should_cleanup: bool,
    deployed_region: &str,
) -> Result<(), RecoverDeployFailureError> {
    use RecoverDeployFailureErrorCtx as Ctx;

    if should_cleanup {
        tracing::warn!(
            "Best-effort rollback for failed deploy of resource {} ({})",
            resource_id,
            resource_name
        );
        let rolled_back = managed_dns::begin_owned_deploy_rollback(
            &state.db,
            resource_id,
            org_id,
            deploy_attempt_id,
            deployed_region,
        )
        .await
        .with_context(Ctx::handoff())?;
        if !rolled_back {
            tracing::warn!(resource_id = %resource_id, deploy_attempt_id = %deploy_attempt_id, "rollback skipped because deploy ownership changed");
            return Ok(());
        }
        resources::destroy_resource_by_id(state, resource_id, false)
            .await
            .with_context(Ctx::rollback_destroy())?;
    } else {
        sqlx::query(
            "UPDATE compute_resources
             SET state = $1, deploy_attempt_id = NULL
             WHERE id = $2 AND organization_id = $3
               AND state = 'pending' AND deploy_attempt_id = $4",
        )
        .bind(previous_state)
        .bind(resource_id)
        .bind(org_id)
        .bind(deploy_attempt_id)
        .execute(&state.db)
        .await
        .with_context(Ctx::restore_state())?;
    }

    Ok(())
}

/// Failure modes for [`restore_pending_deploy_rejection`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum RestorePendingDeployRejectionError {
    #[error("failed to restore resource after deploy rejection [{location}]")]
    Update {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn restore_pending_deploy_rejection(
    state: &Arc<AppState>,
    org_id: Uuid,
    resource_id: Uuid,
    deploy_attempt_id: Uuid,
    previous_state: types::ResourceState,
    was_destroyed: bool,
) -> Result<(), RestorePendingDeployRejectionError> {
    use RestorePendingDeployRejectionErrorCtx as Ctx;

    let result = if was_destroyed {
        sqlx::query(
            "UPDATE compute_resources
             SET state = $1, destroyed_at = COALESCE(destroyed_at, NOW()),
                 deploy_attempt_id = NULL
             WHERE id = $2 AND organization_id = $3
               AND state = 'pending' AND deploy_attempt_id = $4",
        )
        .bind(previous_state)
        .bind(resource_id)
        .bind(org_id)
        .bind(deploy_attempt_id)
        .execute(&state.db)
        .await
    } else {
        sqlx::query(
            "UPDATE compute_resources
             SET state = $1, deploy_attempt_id = NULL
             WHERE id = $2 AND organization_id = $3
               AND state = 'pending' AND deploy_attempt_id = $4",
        )
        .bind(previous_state)
        .bind(resource_id)
        .bind(org_id)
        .bind(deploy_attempt_id)
        .execute(&state.db)
        .await
    };

    result.map(|_| ()).with_context(Ctx::update())
}

#[derive(Clone)]
struct ResolvedBuilderTarget {
    config: builder::BuilderConfig,
    aws_credentials: deployment::AwsCredentials,
    cache_app_id: Option<Uuid>,
}

#[tracing::instrument(skip_all)]
fn aws_credentials_from_managed_onprem(
    credential: &cloud_credentials::ManagedOnPremCredentialData,
) -> deployment::AwsCredentials {
    deployment::AwsCredentials {
        access_key_id: credential.aws_access_key_id.clone(),
        secret_access_key: credential.aws_secret_access_key.clone(),
        region: credential.aws_region.clone(),
    }
}

#[tracing::instrument(skip_all)]
fn managed_onprem_config_from_credential(
    credential: &cloud_credentials::ManagedOnPremCredentialData,
) -> deployment::ManagedOnPremConfig {
    deployment::ManagedOnPremConfig {
        deployment_id: credential.deployment_id.clone(),
        asg_name: credential.asg_name.clone(),
        launch_template_name: credential.launch_template_name.clone(),
        launch_template_id: credential.launch_template_id.clone(),
        vpc_id: credential.vpc_id.clone(),
        subnet_ids: credential.subnet_ids.clone(),
        eif_bucket: credential.eif_bucket.clone(),
        instance_profile_name: credential.instance_profile_name.clone(),
        builder_instance_profile_name: credential.builder_instance_profile_name.clone(),
    }
}

/// Overlay fields from the HCL `provider {}` block onto a managed on-prem
/// deployment config. Inline fields take precedence over credential defaults.
#[tracing::instrument(skip_all)]
fn merge_provider_into_onprem(
    provider: &config::Provider,
    onprem: &mut deployment::ManagedOnPremConfig,
) {
    let config::Provider::Aws(aws) = provider;
    if let Some(vpc_id) = &aws.vpc_id {
        onprem.vpc_id = vpc_id.clone();
    }
    if let Some(subnet_ids) = &aws.subnet_ids {
        onprem.subnet_ids = subnet_ids.clone();
    }
}

fn provider_requires_linked_byoc(
    config_file: &config::ConfigurationFile,
    has_linked_byoc: bool,
) -> bool {
    config_file
        .caution
        .as_ref()
        .and_then(|caution| caution.provider.as_ref())
        .is_some()
        && !has_linked_byoc
}

fn deployment_target_milestone(capacity: &str, aws_account: &str, region: &str) -> String {
    [
        "Deployment target: capacity=",
        capacity,
        ", aws_account=",
        aws_account,
        ", region=",
        region,
    ]
    .concat()
}

fn platform_builder_credentials() -> deployment::AwsCredentials {
    deployment::AwsCredentials {
        access_key_id: std::env::var("AWS_ACCESS_KEY_ID").unwrap_or_default(),
        secret_access_key: std::env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_default(),
        region: std::env::var("AWS_REGION").unwrap_or_else(|_| "us-west-2".to_string()),
    }
}

#[tracing::instrument(skip_all)]
async fn s3_client_for_credentials(credentials: &deployment::AwsCredentials) -> aws_sdk_s3::Client {
    let creds = aws_sdk_s3::config::Credentials::new(
        &credentials.access_key_id,
        &credentials.secret_access_key,
        None,
        None,
        "caution-builder",
    );

    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(credentials.region.clone()))
        .credentials_provider(creds)
        .load()
        .await;

    aws_sdk_s3::Client::new(&config)
}

#[tracing::instrument(skip_all)]
async fn cached_object_exists(s3: &aws_sdk_s3::Client, bucket: &str, key: &str) -> bool {
    match s3.head_object().bucket(bucket).key(key).send().await {
        Ok(_) => true,
        Err(error) => {
            tracing::warn!(
                "Skipping cached build because s3://{}/{} was not readable: {:?}",
                bucket,
                key,
                error
            );
            false
        }
    }
}

/// Failure modes for [`resolve_builder_target`] (source-less domain failures plus a
/// boxed inner failure).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ResolveBuilderTargetError {
    #[error("Managed on-prem builder path selected without managed_onprem config [{location}]")]
    MissingOnpremConfig { location: Location },

    #[error("Managed on-prem builder path selected without customer credentials [{location}]")]
    MissingCredentials { location: Location },

    #[error("Failed to resolve managed on-prem builder target [{location}]")]
    Resolve {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn resolve_builder_target(
    default_config: &builder::BuilderConfig,
    managed_onprem: Option<&deployment::ManagedOnPremConfig>,
    managed_onprem_credentials: Option<&deployment::AwsCredentials>,
    resource_id: Uuid,
) -> Result<ResolvedBuilderTarget, ResolveBuilderTargetError> {
    use ResolveBuilderTargetErrorCtx as Ctx;

    if builder::should_use_customer_builder_path(managed_onprem) {
        let managed_onprem =
            managed_onprem.ok_or_else(|| ResolveBuilderTargetError::MissingOnpremConfig {
                location: std::panic::Location::caller(),
            })?;
        let managed_onprem_credentials = managed_onprem_credentials.ok_or_else(|| {
            ResolveBuilderTargetError::MissingCredentials {
                location: std::panic::Location::caller(),
            }
        })?;

        let config = builder::resolve_managed_onprem_builder_config(
            default_config,
            managed_onprem_credentials,
            managed_onprem,
        )
        .await
        .with_context(Ctx::resolve())?;

        tracing::info!(
            "Using managed on-prem builder target: bucket={}, subnet_id={}, instance_profile={}",
            config.eif_s3_bucket,
            config.subnet_id,
            config.instance_profile
        );

        Ok(ResolvedBuilderTarget {
            config,
            aws_credentials: managed_onprem_credentials.clone(),
            cache_app_id: Some(resource_id),
        })
    } else {
        if let Some(managed_onprem) = managed_onprem {
            tracing::info!(
                "Managed on-prem credential has no builder profile; falling back to platform builder path for deployment {}",
                managed_onprem.deployment_id
            );
        }

        Ok(ResolvedBuilderTarget {
            config: default_config.clone(),
            aws_credentials: platform_builder_credentials(),
            cache_app_id: None,
        })
    }
}

/// Failure modes for [`get_builder_config`] (leaf error: no underlying source).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetBuilderConfigError {
    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("resource {resource_id} not found [{location}]")]
    NotFound {
        resource_id: Uuid,
        location: Location,
    },

    #[error("failed to read builder configuration [{location}]")]
    Query {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for GetBuilderConfigError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            GetBuilderConfigError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            GetBuilderConfigError::NotFound { .. } => (StatusCode::NOT_FOUND, "Resource not found"),
            GetBuilderConfigError::Query { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(resource_id = %resource_id))]
async fn get_builder_config(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(resource_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, GetBuilderConfigError> {
    use GetBuilderConfigErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

    let config: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT configuration FROM compute_resources WHERE id = $1 AND organization_id = $2",
    )
    .bind(resource_id)
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .with_context(Ctx::query())?;

    let config = config.ok_or_else(|| GetBuilderConfigError::NotFound {
        resource_id,
        location: std::panic::Location::caller(),
    })?;
    let builder_size = config
        .get("builder_size")
        .and_then(|v| v.as_str())
        .unwrap_or("small");

    Ok(Json(serde_json::json!({
        "builder_size": builder_size,
        "options": state.builder_sizes.builder_sizes,
    })))
}

/// Failure modes for [`set_builder_config`] (leaf error: no underlying source).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SetBuilderConfigError {
    #[error("could not look up the primary organization [{location}]")]
    PrimaryOrgLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("invalid builder_size [{location}]")]
    InvalidSize { location: Location },

    #[error("resource not found [{location}]")]
    NotFound { location: Location },

    #[error("failed to update builder configuration [{location}]")]
    Update {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl IntoResponse for SetBuilderConfigError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            SetBuilderConfigError::PrimaryOrgLookup { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get organization",
            ),
            SetBuilderConfigError::InvalidSize { .. } => {
                (StatusCode::BAD_REQUEST, "invalid builder_size")
            }
            SetBuilderConfigError::NotFound { .. } => (StatusCode::NOT_FOUND, "Resource not found"),
            SetBuilderConfigError::Update { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };
        (status, body).into_response()
    }
}

#[tracing::instrument(skip_all, err, fields(resource_id = %resource_id))]
async fn set_builder_config(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(resource_id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, SetBuilderConfigError> {
    use SetBuilderConfigErrorCtx as Ctx;

    let org_id = get_user_primary_org(&state.db, auth.user_id)
        .await
        .with_context(Ctx::primary_org_lookup())?;

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
        tracing::warn!("builder_size must be one of: {}", valid.join(", "));
        return Err(SetBuilderConfigError::InvalidSize {
            location: std::panic::Location::caller(),
        });
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
    .with_context(Ctx::update())?;

    if result.rows_affected() == 0 {
        return Err(SetBuilderConfigError::NotFound {
            location: std::panic::Location::caller(),
        });
    }

    Ok(Json(serde_json::json!({ "builder_size": builder_size })))
}

/// Failure modes for [`deploy_logic`]. Client-visible bodies are fixed literals;
/// the underlying sources stay chained on the error and never reach the client.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum DeployLogicError {
    #[error("invalid platform framework commit [{location}]")]
    FrameworkCommit {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to check organization membership [{location}]")]
    OrgMembership {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("user does not belong to this organization [{location}]")]
    NotOrgMember { location: Location },

    #[error("failed to fetch provider account [{location}]")]
    ProviderAccountQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("no active provider account found [{location}]")]
    NoProviderAccount { location: Location },

    #[error("provider account has no AWS account ID configured [{location}]")]
    NoAwsAccountId { location: Location },

    #[error("failed to get resource type [{location}]")]
    ResourceTypeQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to check existing resource [{location}]")]
    ResourceLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("deployment already in progress [{location}]")]
    DeployInProgress { location: Location },

    #[error("app is being destroyed [{location}]")]
    Terminating { location: Location },

    #[error("app with id {resource_id} not found [{location}]")]
    AppNotFound {
        resource_id: Uuid,
        location: Location,
    },

    #[error("failed to load cloud credential [{location}]")]
    CredentialLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("unable to check deployment entitlement [{location}]")]
    EntitlementQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("managed on-premises deployment requires an active subscription [{location}]")]
    NoSubscription { location: Location },

    #[error("managed on-premises subscription is not active [{location}]")]
    SubscriptionInactive { location: Location },

    #[error("managed on-premises subscription has no deployment capacity [{location}]")]
    SubscriptionNoCapacity { location: Location },

    #[error("unable to check deployment capacity [{location}]")]
    AppCountQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("app limit reached [{location}]")]
    AppLimitReached { location: Location },

    #[error("unable to finish deployment entitlement check [{location}]")]
    EntitlementCommit {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to read ledger balance [{location}]")]
    BalanceQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("minimum $25.00 in credits required to deploy [{location}]")]
    InsufficientCredits { location: Location },

    #[error("failed to read suspension status [{location}]")]
    SuspensionQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("organization is suspended due to credit exhaustion [{location}]")]
    CreditSuspended { location: Location },

    #[error("failed to count active resources [{location}]")]
    ActiveResourcesQuery {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("resource limit reached [{location}]")]
    ResourceLimitReached { location: Location },

    #[error("failed to reactivate resource [{location}]")]
    ReactivateUpdate {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to update resource state [{location}]")]
    PendingUpdate {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to get commit SHA for branch [{location}]")]
    CommitSha {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("commit_sha does not match branch head [{location}]")]
    CommitMismatch {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to load build config from git [{location}]")]
    BuildConfigGit {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to inspect repository contents [{location}]")]
    RepoInspect {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("invalid enclave unit configuration [{location}]")]
    UnitConfig {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("encryptor not configured [{location}]")]
    EncryptorMissing { location: Location },

    #[error("failed to load managed on-prem credential [{location}]")]
    OnpremSecrets {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("BYOC provider configuration requires linked credentials [{location}]")]
    ByocRequired { location: Location },

    #[error("vCPU request exceeds fully managed limit [{location}]")]
    VcpuLimit { location: Location },

    #[error("invalid enclave resource request [{location}]")]
    SizingInvalid {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to read EIF build metadata [{location}]")]
    EifMetadata {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("EIF size exceeds allocated enclave memory [{location}]")]
    EifTooLarge { location: Location },

    #[error("builder target resolution failed [{location}]")]
    BuilderTarget {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("cache lookup failed [{location}]")]
    CacheLookup {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("insufficient credits for builder [{location}]")]
    BuilderCredits { location: Location },

    #[error("failed to upload source archive [{location}]")]
    UploadSource {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("dedicated builder failed [{location}]")]
    BuilderFailed {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("database error while reserving fully managed capacity [{location}]")]
    CapacityDatabase {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("no deployment region resolved [{location}]")]
    NoRegion { location: Location },

    #[error("Nitro deployment failed [{location}]")]
    NitroDeploy {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("enclave failed to become healthy [{location}]")]
    EnclaveUnhealthy {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to update resource [{location}]")]
    ResourceUpdate {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error(
        "Deployment completed after the app lifecycle changed; refusing to publish it [{location}]"
    )]
    PublishConflict { location: Location },

    #[error("deployment succeeded but metering registration failed [{location}]")]
    Metering {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl DeployLogicError {
    /// Frozen status code and fixed client body for each failure path.
    fn client_response(&self) -> (StatusCode, &'static str) {
        match self {
            DeployLogicError::FrameworkCommit { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            DeployLogicError::OrgMembership { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            DeployLogicError::NotOrgMember { .. } => (
                StatusCode::FORBIDDEN,
                "User does not belong to this organization",
            ),
            DeployLogicError::ProviderAccountQuery { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            DeployLogicError::NoProviderAccount { .. } => {
                (StatusCode::BAD_REQUEST, "No active provider account found")
            }
            DeployLogicError::NoAwsAccountId { .. } => (
                StatusCode::BAD_REQUEST,
                "Provider account has no AWS account ID configured",
            ),
            DeployLogicError::ResourceTypeQuery { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            DeployLogicError::ResourceLookup { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            DeployLogicError::DeployInProgress { .. } => (
                StatusCode::CONFLICT,
                "A deployment is already in progress for this app. Please wait for it to complete.",
            ),
            DeployLogicError::Terminating { .. } => (
                StatusCode::CONFLICT,
                "This app is being destroyed. Wait for teardown to complete before deploying it again.",
            ),
            DeployLogicError::AppNotFound { .. } => (StatusCode::NOT_FOUND, "App not found"),
            DeployLogicError::CredentialLookup { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            DeployLogicError::EntitlementQuery { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to check deployment entitlement",
            ),
            DeployLogicError::NoSubscription { .. } => (
                StatusCode::PAYMENT_REQUIRED,
                "Managed on-premises deployment requires an active subscription. Choose a plan in Settings at https://dashboard.caution.co",
            ),
            DeployLogicError::SubscriptionInactive { .. } => (
                StatusCode::PAYMENT_REQUIRED,
                "Managed on-premises subscription is not active",
            ),
            DeployLogicError::SubscriptionNoCapacity { .. } => (
                StatusCode::PAYMENT_REQUIRED,
                "Managed on-premises subscription has no deployment capacity",
            ),
            DeployLogicError::AppCountQuery { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to check deployment capacity",
            ),
            DeployLogicError::AppLimitReached { .. } => (
                StatusCode::PAYMENT_REQUIRED,
                "App limit reached. Upgrade your plan in Settings at https://dashboard.caution.co",
            ),
            DeployLogicError::EntitlementCommit { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to finish deployment entitlement check",
            ),
            DeployLogicError::BalanceQuery { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            DeployLogicError::InsufficientCredits { .. } => (
                StatusCode::PAYMENT_REQUIRED,
                "Minimum $25.00 in credits required to deploy. Purchase credits in Settings.",
            ),
            DeployLogicError::SuspensionQuery { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            DeployLogicError::CreditSuspended { .. } => (
                StatusCode::PAYMENT_REQUIRED,
                "Your organization is suspended due to credit exhaustion. Add credits in Settings to resume.",
            ),
            DeployLogicError::ActiveResourcesQuery { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            DeployLogicError::ResourceLimitReached { .. } => (
                StatusCode::TOO_MANY_REQUESTS,
                "Resource limit reached. Destroy unused resources or contact support.",
            ),
            DeployLogicError::ReactivateUpdate { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            DeployLogicError::PendingUpdate { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            DeployLogicError::CommitSha { .. } => (
                StatusCode::BAD_REQUEST,
                "Failed to get commit SHA for branch",
            ),
            DeployLogicError::CommitMismatch { .. } => (
                StatusCode::BAD_REQUEST,
                "Requested commit_sha does not match the branch head",
            ),
            DeployLogicError::BuildConfigGit { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            DeployLogicError::RepoInspect { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            DeployLogicError::UnitConfig { .. } => (
                StatusCode::BAD_REQUEST,
                "Invalid enclave unit configuration",
            ),
            DeployLogicError::EncryptorMissing { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Encryptor not configured",
            ),
            DeployLogicError::OnpremSecrets { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            DeployLogicError::ByocRequired { .. } => (
                StatusCode::BAD_REQUEST,
                "caution.hcl declares AWS BYOC, but this app has no linked BYOC credentials. Refusing Caution-managed deployment. Reuse the original BYOC app and remote. To attach BYOC credentials to this linked app, run `caution init --byoc --config <decrypted-json>`. For a new BYOC app, use a fresh unlinked checkout and run `caution init --byoc`; `caution apps create` is managed capacity.",
            ),
            DeployLogicError::VcpuLimit { .. } => (
                StatusCode::BAD_REQUEST,
                "Fully managed deployments support up to 46 enclave vCPUs. Contact support for larger requests.",
            ),
            DeployLogicError::SizingInvalid { .. } => {
                (StatusCode::BAD_REQUEST, "Invalid enclave resource request")
            }
            DeployLogicError::EifMetadata { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            DeployLogicError::EifTooLarge { .. } => (
                StatusCode::BAD_REQUEST,
                "EIF size exceeds allocated enclave memory. Increase memory_mb in configuration file.",
            ),
            DeployLogicError::BuilderTarget { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            DeployLogicError::CacheLookup { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            DeployLogicError::BuilderCredits { .. } => (
                StatusCode::PAYMENT_REQUIRED,
                "Insufficient credits for builder",
            ),
            DeployLogicError::UploadSource { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            DeployLogicError::BuilderFailed { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            DeployLogicError::CapacityDatabase { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error while reserving fully managed capacity.",
            ),
            DeployLogicError::NoRegion { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "No deployment region resolved",
            ),
            DeployLogicError::NitroDeploy { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Nitro deployment failed")
            }
            DeployLogicError::EnclaveUnhealthy { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Enclave failed to become healthy",
            ),
            DeployLogicError::ResourceUpdate { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            DeployLogicError::PublishConflict { .. } => (
                StatusCode::CONFLICT,
                "Deployment completed after the app lifecycle changed; refusing to publish it",
            ),
            DeployLogicError::Metering { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Deployment succeeded but metering registration failed",
            ),
        }
    }
}

#[tracing::instrument(skip_all, fields(org_id = %req.org_id, app_id = %req.app_id))]
async fn deploy_handler(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    validated_types::Validated(req): validated_types::Validated<DeployRequest>,
) -> Response {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(32);
    let deploy_attempt_id = Uuid::new_v4();

    // Spawn the deploy logic in a separate task
    let db_for_recovery = state.db.clone();
    let app_id_for_recovery = req.app_id;
    let org_id_for_recovery = req.org_id;
    tokio::spawn(async move {
        let result = deploy_logic(state, auth, req, deploy_attempt_id, tx.clone()).await;

        // Send final result as JSON
        match result {
            Ok(response) => {
                let json = serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
                let _ = tx.send(Ok(bytes::Bytes::from(format!("{}\n", json)))).await;
            }
            Err(error) => {
                // Reset only the pending state owned by this deploy attempt.
                if let Err(e) = sqlx::query(
                    "UPDATE compute_resources
                     SET state = $1, deploy_attempt_id = NULL
                     WHERE id = $2 AND organization_id = $3 AND state = $4
                       AND deploy_attempt_id = $5",
                )
                .bind(types::ResourceState::Failed)
                .bind(app_id_for_recovery)
                .bind(org_id_for_recovery)
                .bind(types::ResourceState::Pending)
                .bind(deploy_attempt_id)
                .execute(&db_for_recovery)
                .await
                {
                    tracing::error!("Failed to reset resource state after deploy error: {}", e);
                }

                let (status, msg) = error.client_response();
                let _ = tx.send(Ok(milestone_error(msg))).await;
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

/// Failure modes for [`repo_has_file_at_commit`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum RepoHasFileAtCommitError {
    #[error("Git command failed while inspecting {path} [{location}]")]
    Spawn {
        #[context(borrow = str)]
        path: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("git ls-tree failed while inspecting {path} at {commit_sha}: {stderr} [{location}]")]
    GitFailed {
        path: String,
        commit_sha: String,
        stderr: String,
        location: Location,
    },
}

#[tracing::instrument(skip_all, err)]
async fn repo_has_file_at_commit(
    git_dir: &str,
    commit_sha: &str,
    path: &str,
) -> Result<bool, RepoHasFileAtCommitError> {
    use tokio::process::Command;

    use RepoHasFileAtCommitErrorCtx as Ctx;

    let output = Command::new("git")
        .args(["--git-dir", git_dir, "ls-tree", commit_sha, "--", path])
        .output()
        .await
        .with_context(Ctx::spawn(path))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!(
            "git ls-tree failed while inspecting {} at {}: {}",
            path,
            commit_sha,
            stderr
        );
        return Err(RepoHasFileAtCommitError::GitFailed {
            path: path.to_string(),
            commit_sha: commit_sha.to_string(),
            stderr: stderr.trim().to_string(),
            location: std::panic::Location::caller(),
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).lines().any(|line| {
        let Some((metadata, output_path)) = line.split_once('\t') else {
            return false;
        };
        let mut parts = metadata.split_whitespace();
        let _mode = parts.next();
        let file_type = parts.next();

        output_path.trim() == path && file_type == Some("blob")
    }))
}

/// Failure modes shared by [`validate_explicit_containerfile_for_deploy`] and
/// [`resolve_containerfile_for_deploy`] (sibling helpers whose caller unifies on one type).
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ResolveContainerfileForDeployError {
    #[error("Invalid containerfile path [{location}]")]
    InvalidPath {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Procfile field `containerfile:` points to missing file: {containerfile} [{location}]")]
    MissingFile {
        containerfile: String,
        location: Location,
    },

    #[error("Failed to inspect repository contents [{location}]")]
    Inspect {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn validate_explicit_containerfile_for_deploy(
    git_dir: &str,
    commit_sha: &str,
    containerfile: Option<&str>,
) -> Result<Option<String>, ResolveContainerfileForDeployError> {
    use ResolveContainerfileForDeployErrorCtx as Ctx;

    let Some(containerfile) = containerfile else {
        return Ok(None);
    };

    let containerfile = builder::validate_remote_containerfile_path(containerfile)
        .with_context(Ctx::invalid_path())?;

    if !repo_has_file_at_commit(git_dir, commit_sha, &containerfile)
        .await
        .with_context(Ctx::inspect())?
    {
        return Err(ResolveContainerfileForDeployError::MissingFile {
            containerfile,
            location: std::panic::Location::caller(),
        });
    }

    Ok(Some(containerfile))
}

/// Failure modes for [`load_build_config_for_deploy`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum LoadBuildConfigForDeployError {
    #[error("Git command failed while reading caution.hcl [{location}]")]
    HclGit {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Invalid caution.hcl [{location}]")]
    HclParse {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Git command failed while reading Procfile [{location}]")]
    ProcfileGit {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error(
        "No configuration file found in repository root. Add a `caution.hcl` file or a `Procfile` with a required `run:` field. [{location}]"
    )]
    NoConfigFile { location: Location },

    #[error("Invalid Procfile [{location}]")]
    ProcfileParse {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn load_build_config_for_deploy(
    git_dir: &str,
    commit_sha: &str,
) -> Result<(String, config::ConfigurationFile), LoadBuildConfigForDeployError> {
    use tokio::process::Command;

    use LoadBuildConfigForDeployErrorCtx as Ctx;

    // Try caution.hcl first
    let hcl_output = Command::new("git")
        .args([
            "--git-dir",
            git_dir,
            "show",
            &format!("{}:caution.hcl", commit_sha),
        ])
        .output()
        .await
        .with_context(Ctx::hcl_git())?;

    if hcl_output.status.success() {
        let raw_content = String::from_utf8_lossy(&hcl_output.stdout).to_string();
        let config_file =
            config::ConfigurationFile::from_str(&raw_content).with_context(Ctx::hcl_parse())?;

        tracing::info!("Loaded build config from caution.hcl");
        return Ok((raw_content, config_file));
    }

    // Fall back to Procfile
    let procfile_output = Command::new("git")
        .args([
            "--git-dir",
            git_dir,
            "show",
            &format!("{}:Procfile", commit_sha),
        ])
        .output()
        .await
        .with_context(Ctx::procfile_git())?;

    if !procfile_output.status.success() {
        tracing::error!(
            "Neither caution.hcl nor Procfile found in repository at commit {}",
            commit_sha
        );
        return Err(LoadBuildConfigForDeployError::NoConfigFile {
            location: std::panic::Location::caller(),
        });
    }

    let procfile_content = String::from_utf8_lossy(&procfile_output.stdout).to_string();
    let config_file = config::ConfigurationFile::from_procfile(&procfile_content)
        .with_context(Ctx::procfile_parse())?;

    tracing::info!("Loaded build config from Procfile (fallback)");
    Ok((procfile_content, config_file))
}

#[tracing::instrument(skip_all, err)]
async fn resolve_containerfile_for_deploy(
    git_dir: &str,
    commit_sha: &str,
    config_file: &config::ConfigurationFile,
) -> Result<String, ResolveContainerfileForDeployError> {
    use ResolveContainerfileForDeployErrorCtx as Ctx;

    let containerfile = config_file
        .enclave
        .as_ref()
        .and_then(|e| e.iter().next())
        .and_then(|(_name, ec)| ec.build.as_ref())
        .and_then(|b| b.containerfile.as_deref());

    let containerfile =
        validate_explicit_containerfile_for_deploy(git_dir, commit_sha, containerfile).await?;
    let containerfile = if containerfile.is_none()
        && repo_has_file_at_commit(git_dir, commit_sha, "Containerfile")
            .await
            .with_context(Ctx::inspect())?
    {
        Some("Containerfile".to_string())
    } else {
        containerfile
    };

    Ok(containerfile.unwrap_or_else(|| "Dockerfile".to_string()))
}

#[cfg(test)]
mod build_inputs_tests {
    use super::build_inputs;
    use crate::PLATFORM_REPO;
    use axum::body::to_bytes;
    use axum::response::IntoResponse;

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(key);
            // SAFETY: This test owns PLATFORM_GIT_SHA for the duration of the call;
            // the API test module has no other environment-mutating tests.
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            // SAFETY: Restores the process environment value captured by this guard.
            unsafe {
                match &self.previous {
                    Some(value) => std::env::set_var(self.key, value),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }

    #[tokio::test]
    async fn build_inputs_returns_commits_and_repos() {
        let platform_sha = EnvVarGuard::set("PLATFORM_GIT_SHA", "test-sha");

        let resp = build_inputs().await.into_response();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(json["platform"]["commit"].as_str(), Some("test-sha"));
        assert_eq!(json["platform"]["repo"].as_str(), Some(PLATFORM_REPO));

        // Each tool carries its commit paired with the repo the footer builds
        // its commit URLs from.
        for tool in ["enclaveos", "bootproof", "steve", "locksmith"] {
            assert!(
                json[tool]["commit"].as_str().is_some_and(|s| !s.is_empty()),
                "missing/empty {tool}.commit"
            );
            assert!(
                json[tool]["repo"]
                    .as_str()
                    .is_some_and(|s| s.contains(tool)),
                "missing {tool}.repo"
            );
        }
        drop(platform_sha);
    }
}

#[cfg(test)]
mod deployment_target_tests {
    use super::{deployment_target_milestone, provider_requires_linked_byoc};
    use crate::config;

    #[test]
    fn provider_requires_linked_credentials() {
        let with_provider = config::ConfigurationFile::from_str(
            "caution {\n provider {\n type = \"aws\"\n region = \"us-east-1\"\n }\n }\n\
             enclave \"main\" {\n unit \"default\" {\n command = \"/app\"\n }\n }",
        )
        .unwrap();
        let managed = config::ConfigurationFile::from_str(
            "enclave \"main\" {\n unit \"default\" {\n command = \"/app\"\n }\n }",
        )
        .unwrap();
        assert!(provider_requires_linked_byoc(&with_provider, false));
        assert!(!provider_requires_linked_byoc(&with_provider, true));
        assert!(!provider_requires_linked_byoc(&managed, false));
    }

    #[test]
    fn target_milestone_is_exact() {
        assert_eq!(
            deployment_target_milestone("BYOC", "123456789012", "us-east-1"),
            "Deployment target: capacity=BYOC, aws_account=123456789012, region=us-east-1"
        );
    }
}

#[cfg(test)]
mod deploy_containerfile_tests {
    use super::{load_build_config_for_deploy, resolve_containerfile_for_deploy};
    use std::{path::Path, process::Command};
    use tempfile::TempDir;

    fn run_git(repo_dir: &Path, args: &[&str]) -> std::process::Output {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo_dir)
            .args(args)
            .output()
            .unwrap_or_else(|err| panic!("git {:?} failed to start: {}", args, err));

        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );

        output
    }

    fn commit_test_repo(files: &[(&str, &str)]) -> (TempDir, String) {
        let repo_dir = tempfile::tempdir().unwrap();
        run_git(repo_dir.path(), &["init"]);

        for (path, contents) in files {
            let full_path = repo_dir.path().join(path);
            if let Some(parent) = full_path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(full_path, contents).unwrap();
        }

        run_git(repo_dir.path(), &["add", "."]);
        run_git(
            repo_dir.path(),
            &[
                "-c",
                "user.name=Test User",
                "-c",
                "user.email=test@example.com",
                "commit",
                "--no-gpg-sign",
                "-m",
                "initial commit",
            ],
        );
        let output = run_git(repo_dir.path(), &["rev-parse", "HEAD"]);
        let commit_sha = String::from_utf8(output.stdout).unwrap().trim().to_string();

        (repo_dir, commit_sha)
    }

    #[tokio::test]
    async fn deploy_path_auto_detects_committed_containerfile() {
        let (repo_dir, commit_sha) = commit_test_repo(&[
            ("Procfile", "run: /app\n"),
            ("Containerfile", "FROM alpine:3.20\n"),
        ]);
        let git_dir = repo_dir.path().join(".git");
        let (procfile_content, config_file) =
            load_build_config_for_deploy(git_dir.to_str().unwrap(), &commit_sha)
                .await
                .unwrap();
        assert_eq!(procfile_content, "run: /app\n");
        assert!(
            config_file
                .enclave
                .as_ref()
                .unwrap()
                .get("default")
                .unwrap()
                .build
                .is_none()
        );

        let containerfile =
            resolve_containerfile_for_deploy(git_dir.to_str().unwrap(), &commit_sha, &config_file)
                .await
                .unwrap();

        assert_eq!(containerfile, "Containerfile");
    }

    #[tokio::test]
    async fn deploy_path_honors_explicit_custom_containerfile() {
        let (repo_dir, commit_sha) = commit_test_repo(&[
            (
                "Procfile",
                "containerfile: Custom.Containerfile\nrun: /app\n",
            ),
            ("Containerfile", "FROM alpine:3.20\n"),
            ("Custom.Containerfile", "FROM debian:bookworm-slim\n"),
        ]);
        let git_dir = repo_dir.path().join(".git");
        let (procfile_content, config_file) =
            load_build_config_for_deploy(git_dir.to_str().unwrap(), &commit_sha)
                .await
                .unwrap();
        assert_eq!(
            procfile_content,
            "containerfile: Custom.Containerfile\nrun: /app\n"
        );
        let enclave = config_file
            .enclave
            .as_ref()
            .unwrap()
            .get("default")
            .unwrap();
        assert_eq!(
            enclave.build.as_ref().unwrap().containerfile.as_deref(),
            Some("Custom.Containerfile")
        );

        let containerfile =
            resolve_containerfile_for_deploy(git_dir.to_str().unwrap(), &commit_sha, &config_file)
                .await
                .unwrap();

        assert_eq!(containerfile, "Custom.Containerfile");
    }

    #[tokio::test]
    async fn deploy_path_falls_back_to_dockerfile() {
        let (repo_dir, commit_sha) = commit_test_repo(&[
            ("Procfile", "run: /app\n"),
            ("Dockerfile", "FROM alpine:3.20\n"),
        ]);
        let git_dir = repo_dir.path().join(".git");
        let (_, config_file) = load_build_config_for_deploy(git_dir.to_str().unwrap(), &commit_sha)
            .await
            .unwrap();

        let containerfile =
            resolve_containerfile_for_deploy(git_dir.to_str().unwrap(), &commit_sha, &config_file)
                .await
                .unwrap();

        assert_eq!(containerfile, "Dockerfile");
    }

    #[tokio::test]
    async fn deploy_path_ignores_procfile_build_command() {
        let (repo_dir, commit_sha) = commit_test_repo(&[
            (
                "Procfile",
                "build: docker build -f Dockerfile .\nrun: /app\n",
            ),
            ("Dockerfile", "FROM alpine:3.20\n"),
        ]);
        let git_dir = repo_dir.path().join(".git");
        let (_, config_file) = load_build_config_for_deploy(git_dir.to_str().unwrap(), &commit_sha)
            .await
            .unwrap();

        let containerfile =
            resolve_containerfile_for_deploy(git_dir.to_str().unwrap(), &commit_sha, &config_file)
                .await
                .unwrap();

        assert_eq!(containerfile, "Dockerfile");
    }
}

#[cfg(test)]
mod deploy_commit_tests {
    use super::select_deploy_commit_sha;

    const COMMIT_SHA: &str = "abcdef123456abcdef123456abcdef123456abcd";

    #[test]
    fn uses_resolved_commit_when_request_does_not_pin_sha() {
        let selected = select_deploy_commit_sha("main", COMMIT_SHA, None).unwrap();

        assert_eq!(selected, COMMIT_SHA);
    }

    #[test]
    fn accepts_matching_requested_commit_sha() {
        let uppercase = COMMIT_SHA.to_uppercase();
        let selected = select_deploy_commit_sha("feature", COMMIT_SHA, Some(&uppercase)).unwrap();

        assert_eq!(selected, COMMIT_SHA);
    }

    #[test]
    fn rejects_mismatched_requested_commit_sha() {
        let err = select_deploy_commit_sha(
            "feature",
            COMMIT_SHA,
            Some("1111111111111111111111111111111111111111"),
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("commit_sha does not match refs/heads/feature")
        );
    }
}

#[tracing::instrument(skip_all, fields(org_id = %req.org_id, app_id = %req.app_id, deploy_attempt_id = %deploy_attempt_id))]
async fn deploy_logic(
    state: Arc<AppState>,
    auth: AuthContext,
    req: DeployRequest,
    deploy_attempt_id: Uuid,
    tx: tokio::sync::mpsc::Sender<Result<bytes::Bytes, std::io::Error>>,
) -> Result<DeployResponse, DeployLogicError> {
    use DeployLogicErrorCtx as Ctx;

    tracing::info!(
        "Deployment request: user_id={}, org_id={}, app_id={}",
        auth.user_id,
        req.org_id,
        req.app_id
    );

    let platform_git_sha = std::env::var("PLATFORM_GIT_SHA").ok();
    let framework_commit = builder::require_platform_framework_commit(platform_git_sha.as_deref())
        .with_context(Ctx::framework_commit())?;

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
    .with_context(Ctx::org_membership())?;

    if user_in_org != Some(true) {
        return Err(DeployLogicError::NotOrgMember {
            location: std::panic::Location::caller(),
        });
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
    .with_context(Ctx::provider_account_query())?;

    tracing::info!("Provider account query result: {:?}", provider_account);

    let (provider_account_id, aws_account_id_opt, role_arn_opt) =
        provider_account.ok_or_else(|| DeployLogicError::NoProviderAccount {
            location: std::panic::Location::caller(),
        })?;

    tracing::info!(
        "Provider account details: id={}, aws_account_id={:?}, role_arn={:?}",
        provider_account_id,
        aws_account_id_opt,
        role_arn_opt
    );

    let aws_account_id = aws_account_id_opt.ok_or_else(|| DeployLogicError::NoAwsAccountId {
        location: std::panic::Location::caller(),
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
    let _resource_type_id: Uuid =
        sqlx::query_scalar("SELECT id FROM resource_types WHERE type_code = $1 LIMIT 1")
            .bind(types::AWSResourceType::EC2Instance.as_str())
            .fetch_one(&state.db)
            .await
            .with_context(Ctx::resource_type_query())?;

    tracing::info!("Looking up resource by id={}", req.app_id);
    let existing_resource: Option<ExistingResourceRow> = sqlx::query_as(
        "SELECT id, resource_name, configuration, destroyed_at, state FROM compute_resources
         WHERE id = $1 AND organization_id = $2",
    )
    .bind(req.app_id)
    .bind(req.org_id)
    .fetch_optional(&state.db)
    .await
    .with_context(Ctx::resource_lookup())?;

    let (resource_id, app_name, configuration, was_destroyed, previous_state) =
        match &existing_resource {
            Some((id, name_opt, config_opt, destroyed_at, state)) => {
                // Reject if a deploy is already in progress
                if *state == types::ResourceState::Pending {
                    return Err(DeployLogicError::DeployInProgress {
                        location: std::panic::Location::caller(),
                    });
                }
                if *state == types::ResourceState::Terminating {
                    return Err(DeployLogicError::Terminating {
                        location: std::panic::Location::caller(),
                    });
                }
                let name = name_opt.clone().unwrap_or_else(|| "unnamed".to_string());
                let config = config_opt.clone().unwrap_or_else(|| serde_json::json!({}));
                (*id, name, config, destroyed_at.is_some(), *state)
            }
            None => {
                return Err(DeployLogicError::AppNotFound {
                    resource_id: req.app_id,
                    location: std::panic::Location::caller(),
                });
            }
        };

    tracing::info!("Found resource: id={}, name={}", resource_id, app_name);

    // --- Billing gate (pre-deploy) --- must run before reactivation to avoid side effects on failure
    let cred = cloud_credentials::get_credential_by_resource(&state.db, req.org_id, resource_id)
        .await
        .with_context(Ctx::credential_lookup())?;
    let is_managed_onprem = cred.as_ref().map(|c| c.managed_on_prem).unwrap_or(false);

    if is_managed_onprem {
        // Managed on-prem: resolve the stored entitlement under an organization lock.
        let mut entitlement_tx = state
            .db
            .begin()
            .await
            .with_context(Ctx::entitlement_query())?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(req.org_id.to_string())
            .execute(&mut *entitlement_tx)
            .await
            .with_context(Ctx::entitlement_query())?;

        let sub: Option<SubscriptionEntitlementRow> = sqlx::query_as(
            "SELECT id, max_apps, pending_max_apps, billing_source, status,
                    catalog_valid, enterprise_expires_at
             FROM subscriptions
             WHERE organization_id = $1 AND status <> 'canceled'
             LIMIT 1
             FOR UPDATE",
        )
        .bind(req.org_id)
        .fetch_optional(&mut *entitlement_tx)
        .await
        .with_context(Ctx::entitlement_query())?;

        let Some((
            sub_id,
            stored_max_apps,
            pending_max_apps,
            billing_source,
            subscription_status,
            catalog_valid,
            enterprise_expires_at,
        )) = sub
        else {
            return Err(DeployLogicError::NoSubscription {
                location: std::panic::Location::caller(),
            });
        };

        let status_permits_deploy = match billing_source.as_str() {
            "legacy_credits" => matches!(subscription_status.as_str(), "active" | "past_due"),
            "paddle" => subscription_status == "active" && catalog_valid,
            "enterprise" => {
                subscription_status == "active"
                    && enterprise_expires_at.is_none_or(|expires_at| expires_at > Utc::now())
            }
            _ => false,
        };
        if !status_permits_deploy {
            return Err(DeployLogicError::SubscriptionInactive {
                location: std::panic::Location::caller(),
            });
        }

        let max_apps = pending_max_apps
            .map(|pending| pending.min(stored_max_apps))
            .unwrap_or(stored_max_apps);
        if max_apps <= 0 {
            return Err(DeployLogicError::SubscriptionNoCapacity {
                location: std::panic::Location::caller(),
            });
        }

        // Pending, provisioning, running, and stopped BYOC resources all consume capacity.
        let current_apps: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM compute_resources cr
             JOIN cloud_credentials cc ON cc.resource_id = cr.id
             WHERE cr.organization_id = $1 AND cc.managed_on_prem = true
               AND cr.destroyed_at IS NULL
               AND cr.state NOT IN ('terminated', 'failed')
               AND cr.id != $2",
        )
        .bind(req.org_id)
        .bind(resource_id)
        .fetch_one(&mut *entitlement_tx)
        .await
        .with_context(Ctx::app_count_query())?;

        if current_apps + 1 > max_apps as i64 {
            return Err(DeployLogicError::AppLimitReached {
                location: std::panic::Location::caller(),
            });
        }
        entitlement_tx
            .commit()
            .await
            .with_context(Ctx::entitlement_commit())?;

        tracing::info!(
            "Billing gate passed: managed on-prem app {}/{}, sub={}",
            current_apps + 1,
            max_apps,
            sub_id
        );
    } else {
        // Fully managed: require >= $25 in derived org credits
        let balance = crate::billing::get_ledger_balance_cents(&state.db, req.org_id)
            .await
            .with_context(Ctx::balance_query())?;

        if balance < 2500 {
            return Err(DeployLogicError::InsufficientCredits {
                location: std::panic::Location::caller(),
            });
        }

        // Block deploy if org is credit-suspended (awaiting credit deposit)
        let credit_suspended: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT credit_suspended_at FROM organizations WHERE id = $1")
                .bind(req.org_id)
                .fetch_optional(&state.db)
                .await
                .with_context(Ctx::suspension_query())?
                .flatten();

        if credit_suspended.is_some() {
            return Err(DeployLogicError::CreditSuspended {
                location: std::panic::Location::caller(),
            });
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
    .with_context(Ctx::active_resources_query())?;

    let max_resources = state.builder_sizes.max_resources_per_org as i64;
    if active_resources + 1 > max_resources {
        return Err(DeployLogicError::ResourceLimitReached {
            location: std::panic::Location::caller(),
        });
    }

    // Atomically transition to Pending — rejects concurrent deploys via the check above
    if was_destroyed {
        tracing::info!("Reactivating previously destroyed resource {}", resource_id);
        let updated = sqlx::query("UPDATE compute_resources SET destroyed_at = NULL, state = $1, deploy_attempt_id = $2 WHERE id = $3 AND organization_id = $4 AND state != $1 AND state <> 'terminating'")
            .bind(types::ResourceState::Pending)
            .bind(deploy_attempt_id)
            .bind(resource_id)
            .bind(req.org_id)
            .execute(&state.db)
            .await
            .with_context(Ctx::reactivate_update())?;

        if updated.rows_affected() == 0 {
            return Err(DeployLogicError::DeployInProgress {
                location: std::panic::Location::caller(),
            });
        }
    } else {
        // Mark as Pending so concurrent pushes are rejected
        let updated = sqlx::query(
            "UPDATE compute_resources SET state = $1, deploy_attempt_id = $2
             WHERE id = $3 AND organization_id = $4 AND state != $1 AND state <> 'terminating'",
        )
        .bind(types::ResourceState::Pending)
        .bind(deploy_attempt_id)
        .bind(resource_id)
        .bind(req.org_id)
        .execute(&state.db)
        .await
        .with_context(Ctx::pending_update())?;

        if updated.rows_affected() == 0 {
            return Err(DeployLogicError::DeployInProgress {
                location: std::panic::Location::caller(),
            });
        }
    }

    tracing::info!("Deploying branch: {}", req.branch);

    let resolved_commit_sha = get_commit_sha(&app_id_str, &req.branch, &state.data_dir)
        .await
        .inspect(|sha| {
            tracing::info!("Latest commit on branch '{}': {}", req.branch, sha);
        })
        .with_context(Ctx::commit_sha())?;

    let commit_sha =
        select_deploy_commit_sha(&req.branch, &resolved_commit_sha, req.commit_sha.as_deref())
            .with_context(Ctx::commit_mismatch())?;

    let git_dir = format!("{}/git-repos/{}.git", state.data_dir, app_id_str);
    let (config_content, config_file) = load_build_config_for_deploy(&git_dir, &commit_sha)
        .await
        .with_context(Ctx::build_config_git())?;

    let containerfile = resolve_containerfile_for_deploy(&git_dir, &commit_sha, &config_file)
        .await
        .with_context(Ctx::repo_inspect())?;
    tracing::info!(
        "Resolved containerfile for resource {} at commit {}: {}",
        resource_id,
        commit_sha,
        containerfile
    );

    tracing::info!("Docker build file for {}: {}", app_name, containerfile);

    // Extract single enclave config fields from ConfigurationFile
    let enclave_opt = config_file
        .enclave
        .as_ref()
        .and_then(|e| e.iter().next())
        .map(|(_name, ec)| ec);

    let ec_build = enclave_opt.and_then(|e| e.build.as_ref());
    let ec_debug = enclave_opt.and_then(|e| e.debug.as_ref());
    let ec_network = enclave_opt.and_then(|e| e.network.as_ref());
    let ec_resources = enclave_opt.and_then(|e| e.resources.as_ref());
    let ec_units = enclave_opt.and_then(|e| e.unit.as_ref());

    let run_command = ec_units
        .and_then(|u| u.values().next())
        .map(|u| u.run_command_string())
        .transpose()
        .with_context(Ctx::unit_config())?;
    let memory_mb = ec_resources.map(|r| r.memory_mb).unwrap_or(512);
    let cpu_count = ec_resources.map(|r| r.cpu).unwrap_or(2);
    let debug_enabled = ec_debug.and_then(|d| d.enabled).unwrap_or(false);
    let ssh_keys = ec_debug.map(|d| d.ssh_keys.clone()).unwrap_or_default();
    let http_port = ec_network.and_then(|n| n.http.as_ref()).map(|h| h.port);
    let domain = ec_network
        .and_then(|n| n.http.as_ref())
        .and_then(|h| h.domain.clone());
    let http_upstream_protocol = ec_network
        .and_then(|n| n.http.as_ref())
        .and_then(|h| h.upstream_protocol)
        .map(|protocol| protocol.as_str())
        .unwrap_or("http");
    let e2e_config = ec_network
        .and_then(|n| n.http.as_ref())
        .and_then(|h| h.e2e_encryption.as_ref());
    let e2e_mode = e2e_config.and_then(|e| e.effective_mode());
    let e2e = e2e_mode == Some(config::E2eMode::Steve);
    let e2e_mode_value = e2e_mode.map(|mode| mode.as_str()).unwrap_or("disabled");
    let e2e_key_exchange = e2e_config
        .map(|e| e.key_exchange().steve_env_value())
        .unwrap_or(caution_config::KeyExchange::X25519.steve_env_value());
    let allow_plaintext_fallback = e2e_config
        .map(|e| e.allow_plaintext_fallback())
        .unwrap_or(false);

    let no_cache = ec_build.and_then(|b| b.cache).map(|c| !c).unwrap_or(false);
    let app_sources = ec_build.map(|b| b.app_sources.clone()).unwrap_or_default();
    let egress = ec_network.map(|n| n.egress_enabled()).unwrap_or(false);

    let ingress_ports: Vec<u16> = ec_network
        .map(|n| {
            let mut ports: Vec<u16> = n
                .ingress
                .iter()
                .flat_map(|rule| match &rule.port_spec {
                    Some(config::PortSpec::Exact { port }) => vec![*port],
                    Some(config::PortSpec::FromTo {
                        start_port,
                        end_port,
                    }) => (*start_port..=*end_port).collect::<Vec<u16>>(),
                    _ => Vec::new(),
                })
                .collect();
            ports.sort();
            ports.dedup();
            ports
        })
        .unwrap_or_default();

    let managed_onprem_credential = if let Some(credential) = cred
        .as_ref()
        .filter(|credential| credential.managed_on_prem)
    {
        let encryptor =
            state
                .encryptor
                .as_ref()
                .ok_or_else(|| DeployLogicError::EncryptorMissing {
                    location: std::panic::Location::caller(),
                })?;

        cloud_credentials::get_managed_onprem_credential(
            &state.db,
            encryptor,
            req.org_id,
            credential.id,
        )
        .await
        .with_context(Ctx::onprem_secrets())?
    } else {
        None
    };

    let deployment_credentials = managed_onprem_credential
        .as_ref()
        .map(aws_credentials_from_managed_onprem);
    let mut managed_onprem_config = managed_onprem_credential
        .as_ref()
        .map(managed_onprem_config_from_credential);

    if provider_requires_linked_byoc(&config_file, managed_onprem_config.is_some()) {
        if let Err(error) = restore_pending_deploy_rejection(
            &state,
            req.org_id,
            resource_id,
            deploy_attempt_id,
            previous_state,
            was_destroyed,
        )
        .await
        {
            tracing::error!(?error, "failed to restore pending deploy rejection");
        }
        return Err(DeployLogicError::ByocRequired {
            location: std::panic::Location::caller(),
        });
    }

    if !is_managed_onprem && cpu_count > fully_managed_capacity::MAX_FULLY_MANAGED_ENCLAVE_VCPUS {
        if let Err(error) = restore_pending_deploy_rejection(
            &state,
            req.org_id,
            resource_id,
            deploy_attempt_id,
            previous_state,
            was_destroyed,
        )
        .await
        {
            tracing::error!(?error, "failed to restore pending deploy rejection");
        }
        return Err(DeployLogicError::VcpuLimit {
            location: std::panic::Location::caller(),
        });
    }

    let deployment_requirements_result =
        fully_managed_capacity::DeploymentRequirements::for_enclave(cpu_count, memory_mb);
    if deployment_requirements_result.is_err()
        && let Err(error) = restore_pending_deploy_rejection(
            &state,
            req.org_id,
            resource_id,
            deploy_attempt_id,
            previous_state,
            was_destroyed,
        )
        .await
    {
        tracing::error!(?error, "failed to restore pending deploy rejection");
    }
    let deployment_requirements =
        deployment_requirements_result.with_context(Ctx::sizing_invalid())?;

    // Overlay inline provider config from caution.hcl onto DB credential defaults.
    // Fields specified in the provider block take precedence.
    if let Some(provider) = config_file
        .caution
        .as_ref()
        .and_then(|c| c.provider.as_ref())
        && let Some(ref mut onprem) = managed_onprem_config
    {
        merge_provider_into_onprem(provider, onprem);
    }

    let should_cleanup_on_failure = was_destroyed
        || !matches!(
            previous_state,
            types::ResourceState::Running | types::ResourceState::Stopped
        );

    // --- Dedicated builder path ---
    // Builds are always offloaded to an ephemeral EC2 builder instance.
    let builder_cfg = &state.builder_config;
    let builder_target = resolve_builder_target(
        builder_cfg,
        managed_onprem_config.as_ref(),
        deployment_credentials.as_ref(),
        resource_id,
    )
    .await
    .with_context(Ctx::builder_target())?;
    let builder_eif_s3_key = {
        let enclaveos_commit = enclave_builder::build::resolve_enclaveos_commit();
        let steve_commit = enclave_builder::build::resolve_steve_commit();
        let cache_key = builder::compute_cache_key(
            &commit_sha,
            &enclaveos_commit,
            &steve_commit,
            &config_content,
            e2e,
            e2e_key_exchange,
            allow_plaintext_fallback,
            config_file.has_vault_env(), // auto-enable locksmith when env::vault is used
            e2e_config
                .as_ref()
                .and_then(|e2e| e2e.cors_origins.as_ref())
                .unwrap_or(&vec![]),
            &framework_commit,
        );
        let s3_client = s3_client_for_credentials(&builder_target.aws_credentials).await;

        // Check cache first
        let cached_result = if !no_cache {
            builder::check_build_cache(
                &state.db,
                req.org_id,
                &cache_key,
                builder_target.cache_app_id,
            )
            .await
            .with_context(Ctx::cache_lookup())?
        } else {
            None
        };
        let cached_result = if let Some(cached) = cached_result {
            if builder_target.cache_app_id.is_some()
                && !cached_object_exists(
                    &s3_client,
                    &builder_target.config.eif_s3_bucket,
                    &cached.eif_s3_key,
                )
                .await
            {
                None
            } else {
                Some(cached)
            }
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
                .send(Ok(milestone("Provisioning dedicated builder...")))
                .await;

            // Archive source and upload to S3
            let git_dir = format!("{}/git-repos/{}.git", state.data_dir, app_id_str);

            // Pre-build balance check: refuse if org can't cover minimum build cost (~$0.30 for 1 min)
            let min_build_cost_cents: i64 = 50; // $0.50 minimum balance required
            let balance = crate::billing::get_ledger_balance_cents(&state.db, req.org_id)
                .await
                .with_context(Ctx::balance_query())?;

            if balance < min_build_cost_cents {
                return Err(DeployLogicError::BuilderCredits {
                    location: std::panic::Location::caller(),
                });
            }

            let build_id = uuid::Uuid::new_v4();
            let source_artifact = builder::upload_source_archive(
                &s3_client,
                &builder_target.config.eif_s3_bucket,
                &git_dir,
                &commit_sha,
                build_id,
                req.org_id,
            )
            .await
            .with_context(Ctx::upload_source())?;

            let ec2_client = crate::ec2::Ec2Client::new(&builder_target.aws_credentials);

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
                source_s3_key: source_artifact.s3_key,
                source_sha256: source_artifact.sha256,
                procfile_content: config_content,
                run_command: run_command.clone(),
                containerfile: containerfile.clone(),
                ports: ingress_ports.clone(),
                http_port: ec_network.and_then(|n| n.http.as_ref()).map(|h| h.port),
                e2e,
                e2e_mode: e2e_mode_value.to_string(),
                e2e_key_exchange: e2e_key_exchange.to_string(),
                allow_plaintext_fallback,
                domain: ec_network
                    .and_then(|n| n.http.as_ref())
                    .and_then(|h| h.domain.clone()),
                http_upstream_protocol: http_upstream_protocol.to_string(),
                framework_commit: framework_commit.clone(),
                locksmith: config_file.has_vault_env(),
                egress,
                e2e_cors_origins: e2e_config
                    .as_ref()
                    .and_then(|e2e| e2e.cors_origins.as_ref())
                    .map(|origins| origins.join(",")),
                no_cache,
                enclaveos_commit,
                steve_commit,
                builder_instance_type: resolved_size.instance_type.clone(),
                app_sources,
            };

            let build_result = builder::execute_remote_build(
                &state.db,
                &ec2_client,
                &s3_client,
                &builder_target.config,
                &build_request,
                &cache_key,
                &tx,
                auth.user_id,
            )
            .await
            .with_context(Ctx::builder_failed())?;

            build_result.eif_s3_key
        }
    };

    let eif_path = format!(
        "s3://{}/{}",
        builder_target.config.eif_s3_bucket, builder_eif_s3_key
    );
    let (eif_hash, eif_size_bytes_db) = sqlx::query_as::<_, (String, i64)>(
        "SELECT eif_sha256, eif_size_bytes FROM eif_builds WHERE eif_s3_key = $1 AND status = 'completed' LIMIT 1"
    )
    .bind(&builder_eif_s3_key)
    .fetch_optional(&state.db)
    .await
    .with_context(Ctx::eif_metadata())?
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
        "run_command": run_command,
        "domain": domain,
        "memory_mb": memory_mb,
        "cpus": cpu_count,
        "debug": debug_enabled,
        "ports": ingress_ports,
        "http_port": http_port,
    });
    let eif_size_bytes = eif_size_bytes_db as u64;

    let memory_bytes = (memory_mb as u64) * 1024 * 1024;
    if eif_size_bytes > memory_bytes {
        return Err(DeployLogicError::EifTooLarge {
            location: std::panic::Location::caller(),
        });
    }
    if eif_size_bytes > memory_bytes * 80 / 100 {
        tracing::warn!(
            "EIF size ({} MB) is more than 80% of allocated memory ({} MB). Consider increasing memory_mb.",
            eif_size_bytes / (1024 * 1024),
            memory_mb
        );
    }

    let capacity_reservation = if managed_onprem_config.is_none() {
        let _ = tx
            .send(Ok(milestone("Checking fully managed capacity...")))
            .await;
        let reservation = fully_managed_capacity::reserve_capacity(
            &state.db,
            req.org_id,
            auth.user_id,
            resource_id,
            &deployment_requirements,
        )
        .await;
        if reservation.is_err()
            && let Err(rejection_error) = restore_pending_deploy_rejection(
                &state,
                req.org_id,
                resource_id,
                deploy_attempt_id,
                previous_state,
                was_destroyed,
            )
            .await
        {
            tracing::error!(
                ?rejection_error,
                "failed to restore pending deploy rejection"
            );
        }
        Some(reservation.with_context(Ctx::capacity_database())?)
    } else {
        None
    };
    let fully_managed_region = capacity_reservation
        .as_ref()
        .map(|reservation| reservation.region.clone());

    tracing::info!(
        "Deploying Nitro Enclave for resource {} with memory_mb={}, cpu_count={}, debug={}",
        resource_id,
        memory_mb,
        cpu_count,
        debug_enabled
    );

    if let Some(managed_onprem) = managed_onprem_config.as_ref() {
        tracing::info!(
            "Using managed on-prem config: deployment_id={}, region={}",
            managed_onprem.deployment_id,
            deployment_credentials
                .as_ref()
                .map(|credentials| credentials.region.as_str())
                .unwrap_or("us-west-2")
        );
    } else {
        tracing::info!(
            "No managed on-prem credential linked to resource {}, using fully managed deployment",
            resource_id
        );
    }

    let deployed_region = deployment_credentials
        .as_ref()
        .map(|c| c.region.clone())
        .or_else(|| fully_managed_region.clone())
        .ok_or_else(|| DeployLogicError::NoRegion {
            location: std::panic::Location::caller(),
        })?;

    let (capacity, target_account) = if managed_onprem_config.is_some() {
        let account = cred
            .as_ref()
            .and_then(|credential| credential.config.get("aws_account_id"))
            .and_then(|account| account.as_str())
            .unwrap_or("unknown");
        ("BYOC", account)
    } else {
        ("Caution-managed", aws_account_id.as_str())
    };
    let target = deployment_target_milestone(capacity, target_account, &deployed_region);
    let _ = tx.send(Ok(milestone(&target))).await;

    let nitro_request = deployment::NitroDeploymentRequest {
        org_id: req.org_id,
        resource_id,
        resource_name: app_name.clone(),
        aws_account_id: aws_account_id.clone(),
        role_arn: role_arn_opt.clone(),
        eif_path: eif_path.clone(),
        eif_s3_key: Some(builder_eif_s3_key.clone()),
        memory_mb,
        cpu_count,
        disk_gb: 30, // no HCL equivalent
        debug_mode: debug_enabled,
        ports: ingress_ports.clone(),
        http_port,
        e2e,
        e2e_mode: e2e_mode_value.to_string(),
        locksmith: config_file.has_vault_env(),
        egress,
        ssh_keys,
        domain: domain.clone(),
        region: fully_managed_region.clone(),
        credentials: deployment_credentials,
        managed_onprem: managed_onprem_config,
    };

    let _ = tx.send(Ok(milestone("Uploading and launching..."))).await;

    let deployment_result = deployment::deploy_nitro_enclave(nitro_request).await;
    match &deployment_result {
        Ok(result) => {
            tracing::info!(
                "Nitro Enclave deployed: instance_id={}, public_ip={}",
                result.instance_id,
                result.public_ip
            );
        }
        Err(source) => {
            tracing::error!("Failed to deploy Nitro Enclave: {:?}", source);
            if let Some(reservation) = capacity_reservation.as_ref() {
                fully_managed_capacity::release_reservation(&state.db, reservation).await;
            }
            if let Err(recover_error) = recover_deploy_failure(
                &state,
                req.org_id,
                resource_id,
                deploy_attempt_id,
                &app_name,
                previous_state,
                should_cleanup_on_failure,
                &deployed_region,
            )
            .await
            {
                tracing::error!(?recover_error, "failed to recover from deploy failure");
            }
        }
    }
    let deployment_result = deployment_result.with_context(Ctx::nitro_deploy())?;

    let mut final_config = eif_config.clone();
    if let Some(instance_type) = &deployment_result.instance_type {
        final_config["instance_type"] = serde_json::json!(instance_type);
    }
    final_config["region"] = serde_json::json!(deployed_region.clone());

    let app_url = if let Some(ref d) = domain {
        format!("https://{}", d)
    } else {
        format!("http://{}", deployment_result.public_ip)
    };
    let attestation_url = format!("{}/attestation", app_url);

    let _ = tx.send(Ok(milestone("Waiting for health check..."))).await;

    let health_timeout_secs = deployment_health_timeout_secs();

    tracing::info!("Waiting for health endpoint to become healthy...");
    let health_result = wait_for_health(&deployment_result.public_ip, health_timeout_secs).await;
    if let Err(ref source) = health_result {
        tracing::error!("Health check failed: {}", source);
        if let Some(reservation) = capacity_reservation.as_ref() {
            fully_managed_capacity::release_reservation(&state.db, reservation).await;
        }
        if let Err(recover_error) = recover_deploy_failure(
            &state,
            req.org_id,
            resource_id,
            deploy_attempt_id,
            &app_name,
            previous_state,
            should_cleanup_on_failure,
            &deployed_region,
        )
        .await
        {
            tracing::error!(?recover_error, "failed to recover from deploy failure");
        }
    }
    health_result.with_context(Ctx::enclave_unhealthy())?;

    if debug_enabled {
        tracing::info!("Skipping attestation check: enclave is in debug mode");
    } else {
        tracing::info!("Waiting for attestation endpoint to become healthy...");
        let attestation_result =
            wait_for_attestation_health(&deployment_result.public_ip, health_timeout_secs).await;
        if let Err(ref source) = attestation_result {
            tracing::error!("Attestation health check failed: {}", source);
            if let Some(reservation) = capacity_reservation.as_ref() {
                fully_managed_capacity::release_reservation(&state.db, reservation).await;
            }
            if let Err(recover_error) = recover_deploy_failure(
                &state,
                req.org_id,
                resource_id,
                deploy_attempt_id,
                &app_name,
                previous_state,
                should_cleanup_on_failure,
                &deployed_region,
            )
            .await
            {
                tracing::error!(?recover_error, "failed to recover from deploy failure");
            }
        }
        attestation_result.with_context(Ctx::enclave_unhealthy())?;
    }

    let managed_dns_enabled = state.managed_dns.is_some();
    let resource_update = sqlx::query_as::<_, (String, Option<String>)>(
        "UPDATE compute_resources
         SET provider_resource_id = $1, state = $2, public_ip = $3, region = $4,
             configuration = COALESCE(configuration, '{}'::jsonb) || $5::jsonb,
             dns_status = CASE
                 WHEN NOT $6::boolean THEN dns_status
                 WHEN dns_status = 'ready' AND public_ip = $3 THEN 'ready'
                 ELSE 'publishing'
             END,
             dns_error = CASE WHEN $6::boolean THEN NULL ELSE dns_error END,
             dns_change_id = CASE
                 WHEN $6::boolean AND NOT (dns_status = 'ready' AND public_ip = $3) THEN NULL
                 ELSE dns_change_id
             END,
             dns_release_not_before = CASE WHEN $6::boolean THEN NULL ELSE dns_release_not_before END,
             deploy_attempt_id = NULL
         WHERE id = $7 AND organization_id = $8 AND state = 'pending'
           AND deploy_attempt_id = $9
         RETURNING dns_status, dns_error"
    )
    .bind(&deployment_result.instance_id)
    .bind(types::ResourceState::Running)
    .bind(&deployment_result.public_ip)
    .bind(&deployed_region)
    .bind(&final_config)
    .bind(managed_dns_enabled)
    .bind(resource_id)
    .bind(req.org_id)
    .bind(deploy_attempt_id)
    .fetch_optional(&state.db)
    .await;
    if resource_update.is_err() {
        if let Some(reservation) = capacity_reservation.as_ref() {
            fully_managed_capacity::release_reservation(&state.db, reservation).await;
        }
        if let Err(recover_error) = recover_deploy_failure(
            &state,
            req.org_id,
            resource_id,
            deploy_attempt_id,
            &app_name,
            previous_state,
            should_cleanup_on_failure,
            &deployed_region,
        )
        .await
        {
            tracing::error!(?recover_error, "failed to recover from deploy failure");
        }
    }
    let resource_update = resource_update.with_context(Ctx::resource_update())?;
    let Some((initial_dns_status, initial_dns_error)) = resource_update else {
        if let Some(reservation) = capacity_reservation.as_ref() {
            fully_managed_capacity::release_reservation(&state.db, reservation).await;
        }
        if let Err(recover_error) = recover_deploy_failure(
            &state,
            req.org_id,
            resource_id,
            deploy_attempt_id,
            &app_name,
            previous_state,
            should_cleanup_on_failure,
            &deployed_region,
        )
        .await
        {
            tracing::error!(?recover_error, "failed to recover from deploy failure");
        }
        return Err(DeployLogicError::PublishConflict {
            location: std::panic::Location::caller(),
        });
    };

    let metering_result = crate::metering::upsert_tracked_resource(
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
    .await;
    if metering_result.is_err()
        && let Some(reservation) = capacity_reservation.as_ref()
    {
        fully_managed_capacity::release_reservation(&state.db, reservation).await;
    }
    metering_result.with_context(Ctx::metering())?;

    if let Some(reservation) = capacity_reservation.as_ref() {
        fully_managed_capacity::release_reservation(&state.db, reservation).await;
    }

    let initial_dns = managed_dns::DnsSnapshot {
        status: initial_dns_status,
        error: initial_dns_error,
    };
    let dns = if initial_dns.status == "publishing" {
        let _ = tx.send(Ok(milestone("Publishing managed DNS..."))).await;
        if let Some(managed_dns) = state.managed_dns.as_ref() {
            match managed_dns.publish_resource(&state.db, resource_id).await {
                Ok(dns) => dns,
                Err(error) => {
                    tracing::error!(resource_id = %resource_id, error = %error, "managed DNS publication will be retried");
                    managed_dns::DnsSnapshot {
                        status: initial_dns.status,
                        error: Some(managed_dns::sanitize_error(&error)),
                    }
                }
            }
        } else {
            initial_dns
        }
    } else {
        initial_dns
    };

    tracing::info!(
        "EIF deployment complete: resource_id={}, instance_id={}, public_ip={}, instance_type={:?}",
        resource_id,
        deployment_result.instance_id,
        deployment_result.public_ip,
        deployment_result.instance_type
    );

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
        domain,
        managed_hostname: managed_dns::managed_hostname(resource_id),
        dns_status: dns.status,
        dns_error: dns.error,
    })
}

async fn reconcile_terminating_resources(state: Arc<AppState>) {
    use futures::{StreamExt, stream};

    let terminating: Vec<Uuid> = match sqlx::query_scalar(
        "SELECT id FROM compute_resources
         WHERE destroyed_at IS NULL AND state = 'terminating'
         ORDER BY updated_at ASC LIMIT 20",
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(ids) => ids,
        Err(error) => {
            tracing::error!(error = %error, "failed to list interrupted app teardowns");
            return;
        }
    };
    stream::iter(terminating)
        .for_each_concurrent(TEARDOWN_CONCURRENCY, |resource_id| {
            let state = state.clone();
            async move {
                if let Err(error) = resources::destroy_resource_by_id(&state, resource_id, false).await {
                    tracing::warn!(resource_id = %resource_id, error = %error, "app teardown reconciliation will retry");
                }
            }
        })
        .await;
}

async fn reconcile_managed_dns(state: Arc<AppState>, managed_dns: managed_dns::ManagedDns) {
    use futures::{StreamExt, stream};

    let publishing: Vec<Uuid> = match sqlx::query_scalar(
        "SELECT id FROM compute_resources
         WHERE destroyed_at IS NULL AND dns_status = 'publishing' AND state <> 'terminating'
         ORDER BY updated_at ASC LIMIT 20",
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(ids) => ids,
        Err(error) => {
            tracing::error!(error = %error, "failed to list managed DNS publications");
            return;
        }
    };
    stream::iter(publishing)
        .for_each_concurrent(4, |resource_id| {
            let managed_dns = managed_dns.clone();
            let db = state.db.clone();
            async move {
                if let Err(error) = managed_dns.publish_resource(&db, resource_id).await {
                    tracing::warn!(resource_id = %resource_id, error = %error, "managed DNS publication will retry");
                }
            }
        })
        .await;
}

/// Failure modes for the process entry point [`main`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum MainError {
    #[error("could not connect to the database [{location}]")]
    DatabaseConnect {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error(
        "PADDLE_API_KEY is set but PADDLE_API_URL is not — set PADDLE_API_URL to the Paddle API base URL (e.g. https://sandbox-api.paddle.com or https://api.paddle.com) [{location}]"
    )]
    PaddleApiUrlMissing { location: Location },

    #[error("could not load pricing config [{location}]")]
    PricingLoad {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not load builder sizes config [{location}]")]
    BuilderSizesLoad {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not load builder config from environment [{location}]")]
    BuilderConfigFromEnv {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not configure managed DNS [{location}]")]
    ManagedDnsConfig {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not bind the API listener [{location}]")]
    Bind {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("the API server exited with an error [{location}]")]
    Serve {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tokio::main]
async fn main() -> Result<(), MainError> {
    use MainErrorCtx as Ctx;
    tracing_subscriber::fmt::init();

    #[cfg(feature = "e2e-testing-unsafe")]
    {
        let env = std::env::var("ENVIRONMENT").unwrap_or_default();
        if env == "production" {
            eprintln!(
                "FATAL: e2e-testing-unsafe feature is enabled in a production build. Refusing to start."
            );
            std::process::exit(1);
        }
        tracing::warn!(
            "e2e-testing-unsafe feature is enabled — /internal/cleanup/destroy-next-app endpoint is active. Do NOT use in production."
        );
    }

    if let Err(e) = provisioning::validate_setup() {
        tracing::warn!("Provisioning validation failed: {:?}", e);
        tracing::warn!("AWS child account provisioning will not be available");
    }
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let git_hostname =
        std::env::var("GIT_HOSTNAME").unwrap_or_else(|_| "dashboard.caution.co".to_string());

    let git_ssh_port: Option<u16> = std::env::var("SSH_PORT").ok().and_then(|p| p.parse().ok());

    let data_dir =
        std::env::var("CAUTION_DATA_DIR").unwrap_or_else(|_| "/var/cache/caution".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .with_context(Ctx::database_connect())?;

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
        std::env::var("PADDLE_CREDITS_PRICE_ID_10000").ok(),
    ];

    let paddle_api_url = std::env::var("PADDLE_API_URL").unwrap_or_default();
    let paddle_api_key = std::env::var("PADDLE_API_KEY").ok();

    if paddle_api_key.is_some() && paddle_api_url.is_empty() {
        return Err(MainError::PaddleApiUrlMissing {
            location: std::panic::Location::caller(),
        });
    }

    let pricing = PricingConfig::load().with_context(Ctx::pricing_load())?;
    let builder_sizes =
        builder::BuilderSizesConfig::load().with_context(Ctx::builder_sizes_load())?;

    let builder_config =
        builder::BuilderConfig::from_env().with_context(Ctx::builder_config_from_env())?;
    info!("Dedicated builder enabled");

    let eif_cache_size_gb: u64 = std::env::var("EIF_CACHE_SIZE_GB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);
    let eif_download_cache = eif_download::EifDownloadCache::new(&data_dir, eif_cache_size_gb);
    let managed_dns = managed_dns::ManagedDns::from_env()
        .await
        .with_context(Ctx::managed_dns_config())?;

    let state = Arc::new(AppState {
        db: pool,
        database_url,
        teardown_slots: Arc::new(tokio::sync::Semaphore::new(TEARDOWN_CONCURRENCY)),
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
        eif_download_cache,
        managed_dns,
    });

    let teardown_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(
            LIFECYCLE_RECONCILE_INTERVAL_SECS,
        ));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            reconcile_terminating_resources(teardown_state.clone()).await;
        }
    });
    info!("App teardown reconciler started (runs every 30 seconds)");

    if let Some(managed_dns) = state.managed_dns.clone() {
        let dns_state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(
                LIFECYCLE_RECONCILE_INTERVAL_SECS,
            ));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                reconcile_managed_dns(dns_state.clone(), managed_dns.clone()).await;
            }
        });
        info!("Managed app DNS reconciler started (runs every 30 seconds)");
    }

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
            "/organizations/{id}/invitations",
            get(organizations::list_active_invitations).post(organizations::invite_member),
        )
        .route(
            "/organizations/{id}/invitations/{invitation_id}",
            delete(organizations::cancel_invitation),
        )
        .route(
            "/organizations/{id}/members/{user_id}",
            patch(organizations::update_member),
        )
        .route(
            "/organizations/{id}/members/{user_id}",
            delete(organizations::remove_member),
        )
        .route(
            "/organizations/{id}/fully-managed/waitlist",
            post(fully_managed_capacity::join_waitlist),
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
            "/resources/{id}/eif/download",
            get(eif_download::download_eif),
        )
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
        .route(
            "/quorum-bundles/from-org-users",
            post(create_org_user_quorum_bundle),
        )
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
        .route(
            "/billing/subscription/tiers",
            get(subscriptions::get_subscription_tiers),
        )
        .route(
            "/billing/subscription",
            get(subscriptions::get_subscription),
        )
        .route(
            "/billing/subscription/checkout",
            post(subscriptions::checkout_subscription),
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

    #[cfg_attr(not(feature = "e2e-testing-unsafe"), allow(unused_mut))]
    let mut internal_routes = Router::new()
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
        .route(
            "/internal/legal-notices/send",
            post(legal::send_legal_notices),
        )
        .route(
            "/internal/webauthn/reset",
            post(webauthn_reset::reset_webauthn_credentials),
        );

    #[cfg(feature = "e2e-testing-unsafe")]
    {
        internal_routes = internal_routes.route(
            "/internal/cleanup/destroy-next-app",
            post(cleanup::destroy_next_app),
        );
    }

    let internal_routes = internal_routes.layer(axum::middleware::from_fn_with_state(
        state.clone(),
        middleware::internal_auth_middleware,
    ));

    let public_routes = Router::new()
        .route("/health", get(health_check))
        .route("/.well-known/caution/build-inputs", get(build_inputs))
        .route("/onboarding/verify", get(onboarding::verify_email))
        .route(
            "/legal/active-documents",
            get(legal::list_active_legal_documents),
        );

    // Background task: reap orphaned builder instances
    let reaper_state = state.clone();
    tokio::spawn(async move {
        loop {
            info!("Builder orphan reaper starting scan");
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
            builder::reap_unattributed_builders(&reaper_state.db, &ec2).await;
            tokio::time::sleep(std::time::Duration::from_secs(300)).await;
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

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
        .await
        .with_context(Ctx::bind())?;

    info!("API server listening on 0.0.0.0:8080");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .with_context(Ctx::serve())?;

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
