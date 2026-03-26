// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    body::Body,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post, put, patch, delete},
    Json, Router,
};
use tokio_stream::wrappers::ReceiverStream;
use serde::Deserialize;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::info;
use base64::Engine;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use enclave_builder::{BuildConfig as DockerBuildConfig, build_user_image};

mod provisioning;
mod deployment;
mod ec2;
mod validation;
mod validated_types;
mod onboarding;
mod types;
mod errors;
mod encryption;
mod cloud_credentials;
mod cryptographic_bundles;
mod gpg;
mod middleware;
mod users;
mod organizations;
mod resources;
mod billing;
mod subscriptions;
mod suspension;

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct PricingConfig {
    #[serde(default)]
    pub(crate) compute_margin_percent: f64,
    #[serde(default)]
    pub(crate) subscription_tiers: std::collections::HashMap<String, TierPricing>,
    #[serde(default)]
    pub(crate) extra_block: ExtraBlock,
    #[serde(default)]
    pub(crate) billing_discounts: BillingDiscounts,
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
    pub(crate) fn cycle_price(&self, billing_period: &str, discounts: &BillingDiscounts) -> i64 {
        match billing_period {
            "yearly" => (self.annual_cents as f64 * (1.0 - discounts.yearly_percent_off / 100.0)) as i64,
            "2year" => (self.annual_cents as f64 * 2.0 * (1.0 - discounts.two_year_percent_off / 100.0)) as i64,
            _ => self.annual_cents / 12,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct ExtraBlock {
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

#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct BillingDiscounts {
    #[serde(default)]
    pub(crate) yearly_percent_off: f64,
    #[serde(default)]
    pub(crate) two_year_percent_off: f64,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct CreditPackagePricing {
    pub(crate) bonus_percent: f64,
}

impl Default for PricingConfig {
    fn default() -> Self {
        Self {
            compute_margin_percent: 0.0,
            subscription_tiers: std::collections::HashMap::new(),
            extra_block: ExtraBlock::default(),
            billing_discounts: BillingDiscounts::default(),
            credit_packages: std::collections::HashMap::new(),
        }
    }
}

impl PricingConfig {
    pub(crate) fn load() -> Self {
        match std::fs::read_to_string("prices.json") {
            Ok(contents) => match serde_json::from_str(&contents) {
                Ok(config) => {
                    tracing::info!("Loaded pricing config from prices.json");
                    config
                }
                Err(e) => {
                    tracing::error!("Failed to parse prices.json: {}. Using defaults (all zeros).", e);
                    Self::default()
                }
            },
            Err(_) => {
                tracing::warn!("prices.json not found. Using defaults (all zeros). Copy prices.json.example to prices.json to configure pricing.");
                Self::default()
            }
        }
    }

    pub(crate) fn credit_bonus_percent(&self, package_key: &str) -> f64 {
        self.credit_packages.get(package_key).map(|p| p.bonus_percent).unwrap_or(0.0)
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
         WHERE organization_id = $1 AND user_id = $2"
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
         LIMIT 1"
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
                 WHERE id = $3 AND organization_id = $4"
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

pub(crate) async fn get_or_create_resource_type(db: &PgPool) -> Result<Uuid, StatusCode> {
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
    resource_id: &str,
    image_tarball: &str,
    aws_region: &str,
    _role_arn: Option<&str>,
    data_dir: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use tokio::fs;
    use tokio::process::Command;

    let packer_dir = format!("{}/build/{}-packer", data_dir, resource_id);
    let _ = fs::remove_dir_all(&packer_dir).await;
    fs::create_dir_all(&packer_dir).await?;

    let packer_template = format!(
        r#"{{
  "variables": {{
    "aws_region": "{}",
    "resource_id": "{}",
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
      "ami_name": "caution-{{{{ user `resource_id` }}}}-{{{{timestamp}}}}",
      "ami_description": "Caution resource: {{{{ user `resource_id` }}}}",
      "tags": {{
        "Name": "caution-{{{{ user `resource_id` }}}}",
        "ManagedBy": "Caution",
        "ResourceId": "{{{{ user `resource_id` }}}}"
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
        aws_region, resource_id, image_tarball
    );

    let template_path = format!("{}/template.json", packer_dir);
    fs::write(&template_path, packer_template.clone()).await?;

    tracing::info!("Running Packer to create AMI for {}", resource_id);
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

    let bundle = cryptographic_bundles::create_quorum_bundle(&state.db, org_id, auth.user_id, req).await?;
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

    let bundle = cryptographic_bundles::create_secrets_bundle(&state.db, org_id, auth.user_id, req).await?;
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
        .ok_or((StatusCode::NOT_FOUND, "Secrets bundle not found".to_string()))?;

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
        .ok_or((StatusCode::NOT_FOUND, "Secrets bundle not found".to_string()))?;

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
        Err((StatusCode::NOT_FOUND, "Secrets bundle not found".to_string()))
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
        let decrypted = gpg::decrypt_gpg_message(&body)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("GPG decryption failed: {}", e)))?;
        tracing::info!("GPG decryption successful");
        decrypted
    } else {
        body
    };

    let mut req: cloud_credentials::CreateCredentialRequest = serde_json::from_str(&json_content)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid JSON: {}", e)))?;

    if !req.managed_on_prem {
        return Err((StatusCode::BAD_REQUEST, "This endpoint requires managed_on_prem: true".to_string()));
    }

    let deployment_id = req.deployment_id.clone()
        .ok_or((StatusCode::BAD_REQUEST, "deployment_id is required".to_string()))?;

    let encryptor = state.encryptor.as_ref()
        .ok_or((StatusCode::SERVICE_UNAVAILABLE, "Encryption not configured. Set CAUTION_ENCRYPTION_KEY.".to_string()))?;

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
            existing_resource_id, deployment_id
        );

        let existing: Option<(String, types::ResourceState)> = sqlx::query_as(
            "SELECT resource_name, state FROM compute_resources
             WHERE id = $1 AND organization_id = $2"
        )
        .bind(existing_resource_id)
        .bind(org_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

        let (resource_name, resource_state) = existing
            .ok_or((StatusCode::NOT_FOUND, format!("Resource {} not found", existing_resource_id)))?;

        sqlx::query(
            "UPDATE compute_resources SET configuration = $1, updated_at = NOW()
             WHERE id = $2 AND organization_id = $3"
        )
        .bind(&configuration)
        .bind(existing_resource_id)
        .bind(org_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update resource: {}", e)))?;

        sqlx::query("DELETE FROM cloud_credentials WHERE resource_id = $1 AND organization_id = $2")
            .bind(existing_resource_id)
            .bind(org_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete old credential: {}", e)))?;

        let credential = cloud_credentials::create_credential(
            &state.db, encryptor, org_id, auth.user_id, req
        ).await?;

        let git_url = match state.git_ssh_port {
            Some(port) => format!("ssh://git@{}:{}/{}.git", state.git_hostname, port, existing_resource_id),
            None => format!("git@{}:{}.git", state.git_hostname, existing_resource_id),
        };

        tracing::info!(
            "Updated managed on-prem resource {}: credential_id={}, deployment_id={}",
            existing_resource_id, credential.id, deployment_id
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
        .await
        .map_err(|e| {
            tracing::error!("Database error creating resource: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create resource: {}", e))
        })?;

        let (resource_id, resource_state, created_at) = resource;

        req.resource_id = Some(resource_id);

        let credential = cloud_credentials::create_credential(
            &state.db, encryptor, org_id, auth.user_id, req
        ).await?;

        let git_url = match state.git_ssh_port {
            Some(port) => format!("ssh://git@{}:{}/{}.git", state.git_hostname, port, resource_id),
            None => format!("git@{}:{}.git", state.git_hostname, resource_id),
        };

        tracing::info!(
            "Created managed on-prem resource {}: credential_id={}, deployment_id={}",
            resource_id, credential.id, deployment_id
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

async fn deploy_handler(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    validated_types::Validated(req): validated_types::Validated<DeployRequest>,
) -> Response {
    use tokio::process::Command;

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(32);

    // Spawn the deploy logic in a separate task
    tokio::spawn(async move {
        let result = deploy_logic(state, auth, req, tx.clone()).await;

        // Send final result as JSON
        match result {
            Ok(response) => {
                let json = serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
                let _ = tx.send(Ok(bytes::Bytes::from(format!("{}\n", json)))).await;
            }
            Err((status, msg)) => {
                let _ = tx.send(Ok(milestone_error(&msg))).await;
                let error_json = serde_json::json!({"error": msg, "status": status.as_u16()});
                let _ = tx.send(Ok(bytes::Bytes::from(format!("{}\n", error_json)))).await;
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

    let _ = tx.send(Ok(milestone("Preparing deployment..."))).await;

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
    let existing_resource: Option<(Uuid, Option<String>, Option<serde_json::Value>, Option<DateTime<Utc>>)> = sqlx::query_as(
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

    tracing::info!("Found resource: id={}, name={}", resource_id, app_name);

    // --- Billing gate (pre-deploy) --- must run before reactivation to avoid side effects on failure
    let cred = cloud_credentials::get_credential_by_resource(&state.db, req.org_id, resource_id).await?;
    let is_managed_onprem = cred.as_ref().map(|c| c.managed_on_prem).unwrap_or(false);

    if is_managed_onprem {
        // Managed on-prem: require active subscription with capacity
        let sub: Option<(Uuid, i32)> = sqlx::query_as(
            "SELECT id, max_apps FROM subscriptions
             WHERE organization_id = $1 AND status IN ('active', 'past_due') LIMIT 1"
        )
        .bind(req.org_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

        let Some((sub_id, max_apps)) = sub else {
            return Err((StatusCode::PAYMENT_REQUIRED,
                "Managed on-premises deployment requires an active subscription. Choose a plan in Settings at https://caution.dev".to_string()));
        };

        // Count current managed on-prem apps (exclude this resource if redeploying)
        let current_apps: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM compute_resources cr
             JOIN cloud_credentials cc ON cc.resource_id = cr.id
             WHERE cr.organization_id = $1 AND cc.managed_on_prem = true
               AND cr.state != 'terminated' AND cr.id != $2"
        )
        .bind(req.org_id)
        .bind(resource_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

        // +1 for the app being deployed
        if current_apps + 1 > max_apps as i64 {
            return Err((StatusCode::PAYMENT_REQUIRED,
                format!("App limit reached ({}/{}). Upgrade your plan or add capacity in Settings at https://caution.dev",
                    current_apps + 1, max_apps)));
        }

        tracing::info!("Billing gate passed: managed on-prem app {}/{}, sub={}", current_apps + 1, max_apps, sub_id);
    } else {
        // Fully managed: require >= $5 (500 cents) in wallet credits
        let balance: i64 = sqlx::query_scalar(
            "SELECT COALESCE(balance_cents, 0) FROM wallet_balance WHERE user_id = $1"
        )
        .bind(auth.user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?
        .unwrap_or(0);

        if balance < 500 {
            return Err((StatusCode::PAYMENT_REQUIRED,
                format!("Minimum $5.00 in credits required to deploy (current balance: ${:.2}). \
                         Purchase credits at https://caution.dev/settings/billing",
                         balance as f64 / 100.0)));
        }

        // Block deploy if org is credit-suspended (awaiting credit deposit)
        let credit_suspended: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
            "SELECT credit_suspended_at FROM organizations WHERE id = $1"
        )
        .bind(req.org_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?
        .flatten();

        if credit_suspended.is_some() {
            return Err((StatusCode::PAYMENT_REQUIRED,
                "Your organization is suspended due to credit exhaustion. \
                 Add credits at https://caution.dev/settings/billing to resume.".to_string()));
        }

        tracing::info!("Billing gate passed: fully managed, balance_cents={}", balance);
    }

    if was_destroyed {
        tracing::info!("Reactivating previously destroyed resource {}", resource_id);
        sqlx::query("UPDATE compute_resources SET destroyed_at = NULL, state = $1 WHERE id = $2 AND organization_id = $3")
            .bind(types::ResourceState::Pending)
            .bind(resource_id)
            .bind(req.org_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to reactivate resource: {}", e)))?;
    }

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

    let _ = tx.send(Ok(milestone("Building Docker image..."))).await;

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

    let _ = tx.send(Ok(milestone("Building enclave image..."))).await;

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

    let mut git_archive = Command::new("git")
        .args(["--git-dir", &git_dir, "archive", &commit_sha])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| {
            tracing::error!("Failed to spawn git archive: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Repository extraction failed".to_string())
        })?;

    let git_stdout = git_archive.stdout.take().expect("piped stdout")
        .into_owned_fd().map_err(|e| {
            tracing::error!("Failed to get git stdout fd: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Repository extraction failed".to_string())
        })?;

    let tar_output = Command::new("tar")
        .args(["-xC", &work_dir])
        .stdin(git_stdout)
        .stderr(std::process::Stdio::piped())
        .output()
        .await
        .map_err(|e| {
            tracing::error!("Failed to run tar extract: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Repository extraction failed".to_string())
        })?;

    let git_status = git_archive.wait().await.map_err(|e| {
        tracing::error!("Failed to wait for git archive: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Repository extraction failed".to_string())
    })?;

    if !git_status.success() {
        tracing::error!("git archive failed with status {}", git_status);
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to extract repository".to_string()));
    }

    if !tar_output.status.success() {
        let stderr = String::from_utf8_lossy(&tar_output.stderr);
        tracing::error!("tar extract failed: {}", stderr);
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to extract repository".to_string()));
    }

    let _containerfile_path = format!("{}/{}", work_dir, containerfile);

    let enclave_config = types::EnclaveConfig {
        binary_path: build_config.binary.clone().unwrap_or_else(|| "/app".to_string()),
        args: vec![],
        memory_mb: build_config.memory_mb,
        cpus: build_config.cpus,
        debug: build_config.debug,
        ports: build_config.ports.clone(),
        http_port: build_config.http_port,
    };

    // --- Billing gate: vCPU check (post-Procfile parse, managed on-prem only) ---
    if is_managed_onprem {
        let sub_vcpus: Option<(i32,)> = sqlx::query_as(
            "SELECT max_vcpus FROM subscriptions
             WHERE organization_id = $1 AND status IN ('active', 'past_due') LIMIT 1"
        )
        .bind(req.org_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

        if let Some((max_vcpus,)) = sub_vcpus {
            let used_vcpus: i64 = sqlx::query_scalar(
                "SELECT COALESCE(SUM((cr.configuration->>'vcpus')::int), 0)
                 FROM compute_resources cr
                 JOIN cloud_credentials cc ON cc.resource_id = cr.id
                 WHERE cr.organization_id = $1 AND cc.managed_on_prem = true
                   AND cr.state = 'running' AND cr.id != $2"
            )
            .bind(req.org_id)
            .bind(resource_id)
            .fetch_one(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", e)))?;

            let requested_vcpus = enclave_config.cpus as i64;
            if used_vcpus + requested_vcpus > max_vcpus as i64 {
                return Err((StatusCode::PAYMENT_REQUIRED,
                    format!("vCPU limit would be exceeded ({}+{}/{}). Upgrade your plan or add capacity in Settings at https://caution.dev",
                        used_vcpus, requested_vcpus, max_vcpus)));
            }
            tracing::info!("vCPU gate passed: {}+{}/{}", used_vcpus, requested_vcpus, max_vcpus);
        }
    }

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
            enclave_builder::enclave_source_url(&enclave_builder::build::resolve_enclaveos_commit())
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
                    build_config.e2e,
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
                    build_config.e2e,
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
        "run_command": build_config.run,
        "domain": build_config.domain,
        "memory_mb": enclave_config.memory_mb,
        "cpus": enclave_config.cpus,
        "debug": enclave_config.debug,
        "ports": enclave_config.ports,
        "http_port": enclave_config.http_port,
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

    // Check if there's a managed-on-prem credential linked to this resource
    // This takes precedence over the Procfile - if init was called with --config,
    // the credential is already linked to the resource
    let (credentials, managed_onprem_config) = {
        let cred = cloud_credentials::get_credential_by_resource(
            &state.db,
            req.org_id,
            resource_id,
        ).await?;

        if let Some(credential) = cred {
            if credential.managed_on_prem {
                tracing::info!("Managed on-prem credential found for resource {}, using linked credential", resource_id);

                let encryptor = state.encryptor.as_ref().ok_or_else(|| {
                    (StatusCode::INTERNAL_SERVER_ERROR, "Encryptor not configured".to_string())
                })?;

                let secrets = cloud_credentials::get_credential_secrets(
                    &state.db,
                    encryptor,
                    req.org_id,
                    credential.id,
                ).await?;

                match secrets {
                    Some(secrets_json) => {
                        let aws_access_key_id = secrets_json["aws_access_key_id"]
                            .as_str()
                            .ok_or_else(|| {
                                (StatusCode::INTERNAL_SERVER_ERROR, "Missing aws_access_key_id in managed on-prem credentials".to_string())
                            })?;
                        let aws_secret_access_key = secrets_json["aws_secret_access_key"]
                            .as_str()
                            .ok_or_else(|| {
                                (StatusCode::INTERNAL_SERVER_ERROR, "Missing aws_secret_access_key in managed on-prem credentials".to_string())
                            })?;

                        // Extract infrastructure config from credential
                        let config = &credential.config;
                        let region = config["aws_region"].as_str().unwrap_or("us-west-2").to_string();

                        let onprem_config = deployment::ManagedOnPremConfig {
                            deployment_id: config["deployment_id"].as_str().unwrap_or("").to_string(),
                            asg_name: config["asg_name"].as_str().unwrap_or("").to_string(),
                            launch_template_name: config["launch_template_name"].as_str().unwrap_or("").to_string(),
                            launch_template_id: config["launch_template_id"].as_str().unwrap_or("").to_string(),
                            vpc_id: config["vpc_id"].as_str().unwrap_or("").to_string(),
                            subnet_ids: config["subnet_ids"]
                                .as_array()
                                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                                .unwrap_or_default(),
                            eif_bucket: config["eif_bucket"].as_str().unwrap_or("").to_string(),
                            instance_profile_name: config["instance_profile_name"].as_str().unwrap_or("").to_string(),
                        };

                        tracing::info!("Using managed on-prem config: deployment_id={}, region={}", onprem_config.deployment_id, region);

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
                        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to decrypt managed on-prem credentials".to_string()));
                    }
                }
            } else {
                // Credential linked but not managed on-prem - fully managed deployment
                tracing::info!("Non-managed-on-prem credential found, using fully managed deployment");
                (None, None)
            }
        } else {
            // No credential linked - fully managed deployment
            tracing::info!("No credential linked to resource {}, using fully managed deployment", resource_id);
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
        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Enclave failed to become healthy: {}", e)));
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

    let pricing = PricingConfig::load();

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
    });

    let onboarding_routes = Router::new()
        .route("/user/status", get(onboarding::get_user_status))
        .route("/onboarding/send-verification", post(onboarding::send_verification_email))
        .layer(axum::middleware::from_fn_with_state(state.clone(), middleware::auth_middleware));

    let resource_routes = Router::new()
        .route("/users/me", get(users::get_current_user))
        .route("/users/me", patch(users::update_current_user))
        .route("/users/me", delete(users::delete_current_user))
        .route("/organizations", get(organizations::list_organizations))
        .route("/organizations", post(organizations::create_organization))
        .route("/organizations/{id}", get(organizations::get_organization))
        .route("/organizations/{id}", patch(organizations::update_organization))
        .route("/organizations/{id}", delete(organizations::delete_organization))
        .route("/organizations/{id}/settings", get(organizations::get_org_settings))
        .route("/organizations/{id}/settings", patch(organizations::update_org_settings))
        .route("/organizations/{id}/members", get(organizations::list_members))
        .route("/organizations/{id}/members", post(organizations::add_member))
        .route("/organizations/{id}/members/{user_id}", patch(organizations::update_member))
        .route("/organizations/{id}/members/{user_id}", delete(organizations::remove_member))
        .route("/resources", post(resources::create_resource))
        .route("/resources", get(resources::list_resources))
        .route("/resources/{id}", get(resources::get_resource))
        .route("/resources/{id}", patch(resources::rename_resource))
        .route("/resources/{id}", delete(resources::delete_resource))
        .route("/resources/{id}/attestation", post(resources::proxy_attestation))
        .route("/resources/managed-onprem", post(create_managed_onprem_resource))
        .route("/deploy", post(deploy_handler))
        .route("/credentials", get(list_cloud_credentials))
        .route("/credentials", post(create_cloud_credential))
        .route("/credentials/{id}", get(get_cloud_credential))
        .route("/credentials/{id}", delete(delete_cloud_credential))
        .route("/credentials/{id}/default", post(set_default_cloud_credential))
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
        .route("/billing/payment-methods", get(billing::get_payment_methods))
        .route("/billing/payment-methods/{id}", delete(billing::delete_payment_method))
        .route("/billing/payment-methods/{id}/set-primary", post(billing::set_primary_payment_method))
        .route("/billing/paddle/client-token", get(billing::get_paddle_client_token))
        .route("/billing/paddle/transaction-completed", post(billing::paddle_transaction_completed))
        .route("/billing/credits/balance", get(billing::get_credit_balance))
        .route("/billing/credits/packages", get(billing::get_credit_packages))
        .route("/billing/credits/purchase", post(billing::purchase_credits))
        .route("/billing/credits/ledger", get(billing::get_credit_ledger))
        .route("/billing/credits/redeem", post(billing::redeem_credit_code))
        .route("/billing/auto-topup", get(billing::get_auto_topup))
        .route("/billing/auto-topup", put(billing::put_auto_topup))
        .route("/billing/subscription/tiers", get(subscriptions::get_subscription_tiers))
        .route("/billing/subscription", get(subscriptions::get_subscription))
        .route("/billing/subscription/subscribe", post(subscriptions::subscribe))
        .route("/billing/subscription/change-tier", post(subscriptions::change_subscription_tier))
        .route("/billing/subscription/add-capacity", post(subscriptions::add_subscription_capacity))
        .route("/billing/subscription/cancel", post(subscriptions::cancel_subscription))
        .route("/billing/subscription/reactivate", post(subscriptions::reactivate_subscription))
        .layer(axum::middleware::from_fn_with_state(state.clone(), middleware::onboarding_middleware))
        .layer(axum::middleware::from_fn_with_state(state.clone(), middleware::auth_middleware));

    let internal_routes = Router::new()
        .route("/internal/org/{org_id}/suspend", post(suspension::suspend_org_resources))
        .route("/internal/org/{org_id}/suspend-managed", post(suspension::suspend_managed_resources))
        .route("/internal/org/{org_id}/unsuspend", post(suspension::unsuspend_org_resources))
        .layer(axum::middleware::from_fn_with_state(state.clone(), middleware::internal_auth_middleware));

    let public_routes = Router::new()
        .route("/health", get(health_check))
        .route("/onboarding/verify", get(onboarding::verify_email));

    let app = Router::new()
        .merge(onboarding_routes)
        .merge(resource_routes)
        .merge(internal_routes)
        .merge(public_routes)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
        .await?;
    
    info!("API server listening on 0.0.0.0:8080");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut sigterm = tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::terminate(),
    )
    .expect("failed to register SIGTERM handler");
    tokio::select! {
        _ = ctrl_c => tracing::info!("Received SIGINT, shutting down"),
        _ = sigterm.recv() => tracing::info!("Received SIGTERM, shutting down"),
    }
}
