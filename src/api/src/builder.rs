// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Dedicated EC2 builder instances for EIF builds.
//!
//! Instead of building EIFs inline on the API server, this module launches
//! ephemeral EC2 instances that perform the build, upload the EIF to S3,
//! and signal completion via an S3 status file.

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc, TimeDelta};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use uuid::Uuid;

use crate::{
    AppliedPricing,
    deployment::{AwsCredentials, ManagedOnPremConfig},
    ec2::{Ec2Client, Filter, RunInstancesParams},
};

const REMOTE_BUILDER_HELPER: &str = "remote-build-helper";
const MANAGED_ONPREM_DEPLOYMENT_TAG_KEY: &str = "caution:deployment-id";

/// Tag key on EC2 instances holding the UUID of the owning organization.
/// Build runners are tagged with their owning organization at launch.
const ORG_ID_TAG: &str = "org_id";
/// Tag key marking the entity that created an EC2 instance.
const MANAGED_BY_TAG: &str = "ManagedBy";
/// Value of [`MANAGED_BY_TAG`] on build runner instances.
const MANAGED_BY_BUILDER: &str = "caution-builder";
/// Tag key on build runner instances holding the build UUID.
const BUILD_ID_TAG: &str = "BuildId";
/// Tag key used by AWS for the instance display name.
const NAME_TAG: &str = "Name";
/// Prefix of the `Name` tag on build runner instances.
const BUILDER_NAME_PREFIX: &str = "caution-builder-";

/// Specification for a builder instance size, loaded from config.json.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct BuilderSizeSpec {
    pub id: String,
    pub label: String,
    pub instance_type: String,
    pub vcpus: u32,
    pub ram_gb: u32,
}

fn default_max_resources() -> u32 {
    10
}

/// Platform configuration loaded from config.json.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct BuilderSizesConfig {
    pub builder_sizes: Vec<BuilderSizeSpec>,
    #[serde(default = "default_max_resources")]
    pub max_resources_per_org: u32,
}

impl BuilderSizesConfig {
    pub fn load() -> Result<Self> {
        let contents = std::fs::read_to_string("config.json").context(
            "config.json not found. Copy config.json.example to config.json to configure.",
        )?;
        let config: Self =
            serde_json::from_str(&contents).context("Failed to parse config.json")?;
        if config.builder_sizes.is_empty() {
            bail!("config.json: builder_sizes must not be empty");
        }
        Ok(config)
    }

    /// Find a builder size spec by id (case-insensitive). Returns the first entry if not found.
    pub fn resolve(&self, size_id: Option<&str>) -> &BuilderSizeSpec {
        let first = &self.builder_sizes[0];
        match size_id {
            Some(id) => {
                let lower = id.to_lowercase();
                self.builder_sizes
                    .iter()
                    .find(|s| s.id == lower)
                    .unwrap_or(first)
            }
            None => first,
        }
    }

    /// Check if a size id is valid.
    pub fn is_valid(&self, size_id: &str) -> bool {
        self.builder_sizes.iter().any(|s| s.id == size_id)
    }
}

/// Configuration for the builder infrastructure.
#[derive(Clone, Debug)]
pub struct BuilderConfig {
    pub ami_id: String,
    pub security_group_id: String,
    pub subnet_id: String,
    pub instance_profile: String,
    pub region: String,
    pub timeout_secs: u64,
    pub eif_s3_bucket: String,
    pub git_hostname: String,
    pub additional_instance_tags: Vec<(String, String)>,
}

impl BuilderConfig {
    pub fn from_env() -> Result<Self> {
        let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-west-2".to_string());
        Ok(Self {
            ami_id: std::env::var("BUILDER_AMI_ID").context("BUILDER_AMI_ID required")?,
            security_group_id: std::env::var("BUILDER_SECURITY_GROUP_ID")
                .context("BUILDER_SECURITY_GROUP_ID required")?,
            subnet_id: std::env::var("BUILDER_SUBNET_ID").context("BUILDER_SUBNET_ID required")?,
            instance_profile: std::env::var("BUILDER_INSTANCE_PROFILE")
                .context("BUILDER_INSTANCE_PROFILE required")?,
            region,
            timeout_secs: std::env::var("BUILDER_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(7200),
            eif_s3_bucket: std::env::var("EIF_S3_BUCKET").unwrap_or_else(|_| {
                let account = std::env::var("AWS_ACCOUNT_ID").unwrap_or_default();
                format!("caution-eif-storage-{}", account)
            }),
            git_hostname: std::env::var("GIT_HOSTNAME").unwrap_or_default(),
            additional_instance_tags: Vec::new(),
        })
    }
}

/// Result of a completed build.
#[derive(Debug, Clone)]
pub struct BuildResult {
    pub eif_s3_key: String,
    pub eif_sha256: String,
    pub eif_size_bytes: i64,
    pub pcrs: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct StagedArtifact {
    pub s3_key: String,
    pub sha256: String,
}

/// Input parameters for a build.
pub struct BuildRequest {
    pub org_id: Uuid,
    pub app_id: Uuid,
    pub app_name: String,
    pub commit_sha: String,
    pub branch: String,
    /// S3 key where the source archive was uploaded (e.g., builds/{build_id}/source.tar.gz)
    pub source_s3_key: String,
    /// SHA-256 of the uploaded source archive bytes.
    pub source_sha256: String,
    pub procfile_content: String,
    pub run_command: Option<String>,
    pub containerfile: String,
    pub ports: Vec<u16>,
    pub http_port: Option<u16>,
    pub e2e: bool,
    pub e2e_mode: String,
    pub e2e_key_exchange: String,
    pub allow_plaintext_fallback: bool,
    pub domain: Option<String>,
    pub http_upstream_protocol: String,
    pub framework_commit: String,
    pub locksmith: bool,
    pub egress: bool,
    pub e2e_cors_origins: Option<String>,
    pub no_cache: bool,
    pub enclaveos_commit: String,
    pub steve_commit: String,
    pub builder_size: String,
    pub builder_instance_type: String,
    pub app_sources: Vec<String>,
}

pub const ACTIVE_BUILD_CONFLICT_MSG: &str =
    "A build is already in progress for this app. Please wait for it to complete.";

pub fn validate_remote_containerfile_path(containerfile: &str) -> Result<String> {
    let containerfile = enclave_builder::validate_explicit_containerfile_path(containerfile)?;
    if let Some(ch) = containerfile
        .chars()
        .find(|ch| !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/')))
    {
        bail!(
            "Remote builder containerfile path contains unsupported character {:?}",
            ch
        );
    }

    Ok(containerfile)
}

pub fn should_use_customer_builder_path(managed_onprem: Option<&ManagedOnPremConfig>) -> bool {
    managed_onprem
        .and_then(|config| config.builder_instance_profile_name.as_deref())
        .map(|value| !value.is_empty())
        .unwrap_or(false)
}

pub fn build_managed_onprem_builder_config(
    default_config: &BuilderConfig,
    managed_onprem: &ManagedOnPremConfig,
    ami_id: String,
    security_group_id: String,
    subnet_id: String,
    region: String,
    instance_profile: String,
) -> BuilderConfig {
    BuilderConfig {
        ami_id,
        security_group_id,
        subnet_id,
        instance_profile,
        region,
        timeout_secs: default_config.timeout_secs,
        eif_s3_bucket: managed_onprem.eif_bucket.clone(),
        git_hostname: default_config.git_hostname.clone(),
        additional_instance_tags: vec![(
            MANAGED_ONPREM_DEPLOYMENT_TAG_KEY.to_string(),
            managed_onprem.deployment_id.clone(),
        )],
    }
}

pub async fn resolve_managed_onprem_builder_config(
    default_config: &BuilderConfig,
    credentials: &AwsCredentials,
    managed_onprem: &ManagedOnPremConfig,
) -> Result<BuilderConfig> {
    let instance_profile = managed_onprem
        .builder_instance_profile_name
        .as_deref()
        .filter(|value| !value.is_empty())
        .context("Managed on-prem credential missing builder_instance_profile_name")?
        .to_string();
    let subnet_id = managed_onprem
        .subnet_ids
        .iter()
        .find(|value| !value.is_empty())
        .cloned()
        .context("Managed on-prem credential missing subnet_ids")?;

    let ec2 = Ec2Client::new(credentials);
    let security_group_id = ensure_managed_onprem_builder_security_group(
        &ec2,
        &managed_onprem.deployment_id,
        &managed_onprem.vpc_id,
    )
    .await?;
    let ami_id = ec2
        .latest_amazon_linux_2023_ami_id()
        .await
        .context("Failed to resolve Amazon Linux 2023 AMI for managed on-prem builder")?;

    Ok(build_managed_onprem_builder_config(
        default_config,
        managed_onprem,
        ami_id,
        security_group_id,
        subnet_id,
        credentials.region.clone(),
        instance_profile,
    ))
}

/// Compute a cache key from all inputs that affect the EIF output.
pub fn compute_cache_key(
    commit_sha: &str,
    enclaveos_commit: &str,
    steve_commit: &str,
    procfile_content: &str,
    e2e: bool,
    e2e_key_exchange: &str,
    allow_plaintext_fallback: bool,
    locksmith: bool,
    e2e_cors_origins: &[String],
    framework_commit: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(commit_sha.as_bytes());
    hasher.update(b"|");
    hasher.update(enclaveos_commit.as_bytes());
    hasher.update(b"|");
    hasher.update(procfile_content.as_bytes());
    hasher.update(b"|");
    hasher.update(if e2e { "e2e" } else { "no-e2e" }.as_bytes());
    hasher.update(b"|");
    if e2e {
        hasher.update(steve_commit.as_bytes());
        hasher.update(b"|");
    }
    // Only a non-default key exchange reaches run.sh, so hashing it otherwise
    // would invalidate cached builds whose output is byte-identical.
    if e2e && e2e_key_exchange != enclave_builder::build::DEFAULT_KEY_EXCHANGE {
        hasher.update(e2e_key_exchange.as_bytes());
    }
    hasher.update(b"|");
    if e2e && allow_plaintext_fallback {
        hasher.update(b"allow-plaintext-fallback|");
    }
    hasher.update(
        if locksmith {
            "locksmith"
        } else {
            "no-locksmith"
        }
        .as_bytes(),
    );
    hasher.update(b"|");
    for origin in e2e_cors_origins {
        hasher.update(origin.as_bytes());
    }
    hasher.update(b"|framework|");
    hasher.update(framework_commit.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn require_platform_framework_commit(platform_git_sha: Option<&str>) -> Result<String> {
    let commit = platform_git_sha
        .filter(|value| !value.is_empty())
        .context("PLATFORM_GIT_SHA is required for EIF builds")?;
    if commit.len() != 40 || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("PLATFORM_GIT_SHA must be a 40-character Git commit SHA");
    }

    Ok(commit.to_ascii_lowercase())
}

/// Check if a completed build exists in the cache for this org + cache_key.
pub async fn check_build_cache(
    db: &PgPool,
    org_id: Uuid,
    cache_key: &str,
    app_id_scope: Option<Uuid>,
) -> Result<Option<BuildResult>> {
    let row = if let Some(app_id) = app_id_scope {
        sqlx::query_as::<_, (String, String, i64, serde_json::Value)>(
            "SELECT eif_s3_key, eif_sha256, eif_size_bytes, pcrs
             FROM eif_builds
             WHERE organization_id = $1 AND app_id = $2 AND cache_key = $3 AND status = 'completed'
             LIMIT 1",
        )
        .bind(org_id)
        .bind(app_id)
        .bind(cache_key)
        .fetch_optional(db)
        .await
        .context("Failed to query resource-scoped eif_builds cache")?
    } else {
        sqlx::query_as::<_, (String, String, i64, serde_json::Value)>(
            "SELECT eif_s3_key, eif_sha256, eif_size_bytes, pcrs
             FROM eif_builds
             WHERE organization_id = $1 AND cache_key = $2 AND status = 'completed'
             LIMIT 1",
        )
        .bind(org_id)
        .bind(cache_key)
        .fetch_optional(db)
        .await
        .context("Failed to query eif_builds cache")?
    };

    Ok(row.map(
        |(eif_s3_key, eif_sha256, eif_size_bytes, pcrs)| BuildResult {
            eif_s3_key,
            eif_sha256,
            eif_size_bytes,
            pcrs,
        },
    ))
}

/// Archive the source at a given commit and upload to S3 for the builder.
/// Returns the uploaded artifact metadata.
pub async fn upload_source_archive(
    s3: &aws_sdk_s3::Client,
    bucket: &str,
    git_dir: &str,
    commit_sha: &str,
    build_id: Uuid,
    org_id: Uuid,
) -> Result<StagedArtifact> {
    let s3_key = format!("builds/{}/source.tar.gz", build_id);

    // git archive produces a tar.gz of the repo at the given commit
    let output = tokio::process::Command::new("git")
        .args(&[
            "--git-dir",
            git_dir,
            "archive",
            "--format=tar.gz",
            commit_sha,
        ])
        .output()
        .await
        .context("Failed to run git archive")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git archive failed: {}", stderr);
    }

    let archive_bytes = output.stdout;
    let sha256 = format!("{:x}", Sha256::digest(&archive_bytes));

    s3.put_object()
        .bucket(bucket)
        .key(&s3_key)
        .tagging(format!("org_id={}&build_id={}", org_id, build_id))
        .body(aws_sdk_s3::primitives::ByteStream::from(archive_bytes))
        .send()
        .await
        .context("Failed to upload source archive to S3")?;

    tracing::info!("Source archive uploaded to s3://{}/{}", bucket, s3_key);
    Ok(StagedArtifact { s3_key, sha256 })
}

fn resolve_remote_builder_helper_path() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("REMOTE_BUILDER_HELPER_PATH") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Ok(path);
        }
        bail!(
            "REMOTE_BUILDER_HELPER_PATH does not exist: {}",
            path.display()
        );
    }

    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            let sibling = parent.join(REMOTE_BUILDER_HELPER);
            if sibling.exists() {
                return Ok(sibling);
            }
        }
    }

    let default_path = PathBuf::from(format!("/usr/local/bin/{}", REMOTE_BUILDER_HELPER));
    if default_path.exists() {
        return Ok(default_path);
    }

    bail!("Could not locate {}", REMOTE_BUILDER_HELPER)
}

async fn upload_remote_builder_helper(
    s3: &aws_sdk_s3::Client,
    bucket: &str,
    build_id: Uuid,
    org_id: Uuid,
) -> Result<StagedArtifact> {
    let helper_path = resolve_remote_builder_helper_path()?;
    let helper_bytes = std::fs::read(&helper_path)
        .with_context(|| format!("Failed to read {}", helper_path.display()))?;
    let s3_key = format!("builds/{}/{}", build_id, REMOTE_BUILDER_HELPER);
    let sha256 = format!("{:x}", Sha256::digest(&helper_bytes));

    s3.put_object()
        .bucket(bucket)
        .key(&s3_key)
        .tagging(format!("org_id={}&build_id={}", org_id, build_id))
        .body(aws_sdk_s3::primitives::ByteStream::from(helper_bytes))
        .send()
        .await
        .context("Failed to upload remote builder helper to S3")?;

    tracing::info!(
        "Remote builder helper uploaded to s3://{}/{}",
        bucket,
        s3_key
    );
    Ok(StagedArtifact { s3_key, sha256 })
}

async fn ensure_managed_onprem_builder_security_group(
    ec2: &Ec2Client,
    deployment_id: &str,
    vpc_id: &str,
) -> Result<String> {
    let group_name = format!("caution-builder-{}", deployment_id);
    if let Some(group_id) = ec2.find_security_group_id(vpc_id, &group_name).await? {
        return Ok(group_id);
    }

    ec2.create_security_group(
        &group_name,
        &format!(
            "Security group for Caution builder deployment {}",
            deployment_id
        ),
        vpc_id,
        &[
            ("Name".to_string(), group_name.clone()),
            ("ManagedBy".to_string(), "caution-builder".to_string()),
            (
                MANAGED_ONPREM_DEPLOYMENT_TAG_KEY.to_string(),
                deployment_id.to_string(),
            ),
        ],
    )
    .await
}

/// Execute a build on a dedicated EC2 instance.
///
/// 1. Insert a pending build row
/// 2. Launch EC2 instance with user-data build script
/// 3. Poll S3 for status updates until completion or timeout
/// 4. Record results in DB
/// 5. Terminate builder instance
pub async fn execute_remote_build(
    db: &PgPool,
    ec2: &Ec2Client,
    s3: &aws_sdk_s3::Client,
    config: &BuilderConfig,
    request: &BuildRequest,
    cache_key: &str,
    tx: &tokio::sync::mpsc::Sender<Result<bytes::Bytes, std::io::Error>>,
    user_id: Uuid,
) -> Result<BuildResult> {
    let build_id = Uuid::new_v4();
    let instance_type = request.builder_instance_type.as_str();
    let eif_s3_key = format!("eifs/{}/{}.eif", request.org_id, cache_key);
    let procfile_hash = format!("{:x}", Sha256::digest(request.procfile_content.as_bytes()));

    // 1. Atomically reserve the single active-build slot for this app.
    // A per-app transaction-scoped advisory lock serializes concurrent deploys so the
    // check-then-insert below cannot race (two `git push` both passing the COUNT check).
    // The lock is released automatically when the transaction commits or rolls back.
    let mut db_tx = db
        .begin()
        .await
        .context("Failed to begin build reservation transaction")?;

    let app_lock_key = request.app_id.as_u128() as i64;
    let is_locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(app_lock_key)
        .fetch_one(&mut *db_tx)
        .await
        .context("Failed to acquire per-app build lock")?;

    if !is_locked {
        bail!("Deployment already locked for app: {}", request.app_name);
    }

    // NOTE: The above advisory lock should ensure we don't have an existing build.
    let existing = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM eif_builds WHERE app_id = $1 AND status IN ('pending', 'building')"
    )
    .bind(request.app_id)
    .fetch_one(&mut *db_tx)
    .await
    .context("Failed to check for existing builds")?;

    if existing > 0 {
        bail!(ACTIVE_BUILD_CONFLICT_MSG);
    }

    // 2. Insert pending build row and commit, releasing the lock.
    sqlx::query(
        "INSERT INTO eif_builds (id, organization_id, app_id, user_id, commit_sha, procfile_hash, cache_key, builder_instance_type, status, started_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', NOW())"
    )
    .bind(build_id)
    .bind(request.org_id)
    .bind(request.app_id)
    .bind(user_id)
    .bind(&request.commit_sha)
    .bind(&procfile_hash)
    .bind(cache_key)
    .bind(instance_type)
    .execute(&mut *db_tx)
    .await
    .context("Failed to insert eif_builds row")?;

    db_tx
        .commit()
        .await
        .context("Failed to commit build reservation")?;

    // 2. Generate user-data and launch EC2 instance
    let helper_artifact =
        upload_remote_builder_helper(s3, &config.eif_s3_bucket, build_id, request.org_id)
            .await
            .context("Failed to stage remote builder helper")?;
    let user_data = generate_builder_userdata(
        build_id,
        config,
        request,
        &eif_s3_key,
        &helper_artifact.s3_key,
        &helper_artifact.sha256,
    )?;
    let mut instance_tags = vec![
        (
            "Name".to_string(),
            format!("caution-builder-{}", &build_id.to_string()[..8]),
        ),
        ("org_id".to_string(), request.org_id.to_string()),
        ("ManagedBy".to_string(), "caution-builder".to_string()),
        ("BuildId".to_string(), build_id.to_string()),
    ];
    instance_tags.extend(config.additional_instance_tags.clone());
    let instance_id = match ec2
        .run_instances(&RunInstancesParams {
            image_id: config.ami_id.clone(),
            instance_type: instance_type.to_string(),
            user_data,
            iam_instance_profile: config.instance_profile.clone(),
            security_group_ids: vec![config.security_group_id.clone()],
            subnet_id: config.subnet_id.clone(),
            tags: instance_tags,
        })
        .await
    {
        Ok(id) => id,
        Err(e) => {
            mark_build_failed(db, build_id, &format!("Failed to launch builder: {}", e)).await;
            bail!("Failed to launch builder instance: {}", e);
        }
    };

    tracing::info!(
        "Builder instance {} launched for build {}",
        instance_id,
        build_id
    );

    // Update build row with instance ID
    let _ = sqlx::query(
        "UPDATE eif_builds SET builder_instance_id = $1, status = 'building' WHERE id = $2",
    )
    .bind(&instance_id)
    .bind(build_id)
    .execute(db)
    .await;

    // Register builder with metering so the collection loop deducts credits in real-time
    if let Err(e) = sqlx::query(
        "INSERT INTO tracked_resources (resource_id, organization_id, application_id, provider, instance_type, region, metadata, status, started_at, last_billed_at)
         VALUES ($1, $2, $3, 'aws', $4, $5, $6, 'running', NOW(), NOW())
         ON CONFLICT (resource_id) DO UPDATE SET application_id = EXCLUDED.application_id, status = 'running', started_at = NOW(), last_billed_at = NOW()"
    )
    .bind(&instance_id)
    .bind(request.org_id)
    .bind(request.app_id)
    .bind(instance_type)
    .bind(&config.region)
    .bind(serde_json::json!({"build_id": build_id.to_string(), "resource_type": "builder"}))
    .execute(db)
    .await {
        tracing::error!("Failed to register builder {} with metering: {}", instance_id, e);
    }

    // 3. Poll S3 for status updates
    let status_key = format!("builds/{}/status.json", build_id);
    let result = poll_build_status(
        s3,
        &config.eif_s3_bucket,
        &status_key,
        config.timeout_secs,
        tx,
    )
    .await;

    // 4. Stop metering for the builder instance and force a final usage slice.
    let internal_service_secret = std::env::var("INTERNAL_SERVICE_SECRET").ok();
    if let Err(e) =
        crate::metering::stop_tracked_resource(internal_service_secret.as_deref(), &instance_id)
            .await
    {
        tracing::error!("Failed to stop metering for builder {}: {}", instance_id, e);
        let _ = sqlx::query(
            "UPDATE tracked_resources SET status = 'stopped', stopped_at = NOW() WHERE resource_id = $1 AND status = 'running'"
        )
        .bind(&instance_id)
        .execute(db)
        .await;
    }

    // 5. Terminate builder (always do this, retry on failure)
    tracing::info!("Terminating builder instance {}", instance_id);
    let mut terminate_attempts = 0;
    loop {
        terminate_attempts += 1;
        match ec2.terminate_instances(&[instance_id.clone()]).await {
            Ok(_) => break,
            Err(e) => {
                if terminate_attempts >= 3 {
                    tracing::error!("Failed to terminate builder {} after {} attempts: {}. INSTANCE MAY BE LEAKED.", instance_id, terminate_attempts, e);
                    break;
                }
                tracing::warn!(
                    "Failed to terminate builder {} (attempt {}): {}, retrying...",
                    instance_id,
                    terminate_attempts,
                    e
                );
                tokio::time::sleep(std::time::Duration::from_secs(
                    2_u64.pow(terminate_attempts),
                ))
                .await;
            }
        }
    }

    // 5. Handle result
    match result {
        Ok(status) => {
            let build_result = BuildResult {
                eif_s3_key: eif_s3_key.clone(),
                eif_sha256: status.eif_sha256.clone(),
                eif_size_bytes: status.eif_size_bytes,
                pcrs: status.pcrs.clone(),
            };

            if let Err(e) = sqlx::query(
                "UPDATE eif_builds SET status = 'completed', eif_s3_key = $1, eif_sha256 = $2, eif_size_bytes = $3, pcrs = $4, completed_at = NOW()
                 WHERE id = $5"
            )
            .bind(&eif_s3_key)
            .bind(&status.eif_sha256)
            .bind(status.eif_size_bytes)
            .bind(&status.pcrs)
            .bind(build_id)
            .execute(db)
            .await {
                if let Some(database_error) = e.as_database_error() &&
                database_error.is_unique_violation() {
                    // We matched an existing EIF
                    tracing::warn!(
                        eif_s3_key = eif_s3_key,
                        ?database_error,
                        "Duplicate EIF, ignoring error..."
                    );
                } else {
                    bail!("Unable to insert EIF: {e}");
                }
            }

            // Billing is handled by the metering collection loop via tracked_resources.

            Ok(build_result)
        }
        Err(e) => {
            mark_build_failed(db, build_id, &e.to_string()).await;
            Err(e)
        }
    }
}

async fn mark_build_failed(db: &PgPool, build_id: Uuid, error: &str) {
    let _ = sqlx::query(
        "UPDATE eif_builds SET status = 'failed', error_message = $1, completed_at = NOW() WHERE id = $2"
    )
    .bind(error)
    .bind(build_id)
    .execute(db)
    .await;
}

/// Status reported by the builder via S3.
#[derive(Debug, Clone, serde::Deserialize)]
struct BuildStatus {
    phase: String,
    #[serde(with = "chrono::serde::ts_seconds")]
    timestamp: DateTime<Utc>,
    #[serde(default)]
    eif_sha256: String,
    #[serde(default)]
    eif_size_bytes: i64,
    #[serde(default)]
    pcrs: serde_json::Value,
    #[serde(default)]
    error: Option<String>,
}

fn build_phase_milestone(phase: &str) -> Option<&str> {
    match phase {
        "starting" => Some("Builder ready, downloading source..."),
        "docker_built" => Some("Docker image built, building EIF..."),
        "eif_built" => Some("EIF built, uploading to S3..."),
        "completed" => Some("Cleaning up builder..."),
        "failed" => None,
        _ => Some(phase),
    }
}

/// Poll S3 for status.json until the build completes or times out.
async fn poll_build_status(
    s3: &aws_sdk_s3::Client,
    bucket: &str,
    status_key: &str,
    timeout_secs: u64,
    tx: &tokio::sync::mpsc::Sender<Result<bytes::Bytes, std::io::Error>>,
) -> Result<BuildStatus> {
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_secs);
    let stalled_timeout = TimeDelta::new(120, 0).expect("const timedelta is always valid");
    let poll_interval = std::time::Duration::from_secs(10);
    let mut last_phase = String::new();

    loop {
        if start.elapsed() > timeout {
            bail!("Build timed out after {} seconds", timeout_secs);
        }

        tokio::time::sleep(poll_interval).await;

        match s3.get_object().bucket(bucket).key(status_key).send().await {
            Ok(output) => {
                let body = output
                    .body
                    .collect()
                    .await
                    .context("Failed to read status body")?
                    .to_vec();
                let status: BuildStatus = match serde_json::from_slice(&body) {
                    Ok(o) => {
                        tracing::info!("Received status: {o:?} ({:?})", String::from_utf8(body));
                        o
                    },
                    Err(e) => {
                        tracing::error!("Could not parse status.json: {e}");
                        tracing::error!("Received body: {:?}", String::from_utf8(body));
                        return Err(e).context("Failed to parse status.json");
                    }
                };

                // If the build status hasn't been updated in a while (machine stalled?), bail
                let elapsed = Utc::now().signed_duration_since(status.timestamp);
                if elapsed > stalled_timeout {
                    bail!("Build timed out after {elapsed}: {status:?}");
                }

                // Send milestone if phase changed
                if status.phase != last_phase {
                    if let Some(msg) = build_phase_milestone(&status.phase) {
                        let _ = tx
                            .send(Ok(bytes::Bytes::from(format!("STEP:{}\n", msg))))
                            .await;
                    }
                    last_phase = status.phase.clone();
                }

                match status.phase.as_str() {
                    "completed" => return Ok(status),
                    "failed" => {
                        let err = status
                            .error
                            .unwrap_or_else(|| "Unknown build error".to_string());
                        bail!("{}", err);
                    }
                    _ => continue,
                }
            }
            Err(e) => {
                // NoSuchKey is expected while builder is starting — status.json not yet written
                let is_not_found = format!("{}", e).contains("NoSuchKey")
                    || format!("{:?}", e).contains("NoSuchKey");
                if !is_not_found {
                    tracing::warn!("S3 status poll error (non-NoSuchKey): {}", e);
                }
                continue;
            }
        }
    }
}

/// Generate the user-data shell script for the builder instance.
fn generate_builder_userdata(
    build_id: Uuid,
    config: &BuilderConfig,
    request: &BuildRequest,
    eif_s3_key: &str,
    helper_s3_key: &str,
    helper_sha256: &str,
) -> anyhow::Result<String> {
    let status_key = format!("builds/{}/status.json", build_id);
    let bucket = &config.eif_s3_bucket;
    let source_s3_key = &request.source_s3_key;
    let source_sha256 = &request.source_sha256;
    let ports_csv = request
        .ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let http_port = request
        .http_port
        .map(|port| port.to_string())
        .unwrap_or_default();

    let containerfile = validate_remote_containerfile_path(&request.containerfile)?;

    // STEVE and Platform are resolved before the cache lookup and carried on
    // BuildRequest, so the cache key, manifest, and EIF build use the same commits.
    let bootproof_commit = enclave_builder::build::resolve_bootproof_commit();
    let locksmith_commit = enclave_builder::build::resolve_locksmith_commit();

    let e2e_flag = if request.e2e { "true" } else { "false" };
    let key_exchange = &request.e2e_key_exchange;
    let plaintext_fallback_flag = if request.allow_plaintext_fallback {
        "true"
    } else {
        "false"
    };
    let locksmith_flag = if request.locksmith { "true" } else { "false" };
    let egress_flag = if request.egress { "true" } else { "false" };
    let cors_origins_value = request.e2e_cors_origins.as_deref().unwrap_or("");
    let cors_origins_escaped = cors_origins_value.replace('\'', "'\\''");
    let no_cache_flag = if request.no_cache { "true" } else { "false" };

    // Build manifest using the same EnclaveManifest struct as the inline build path
    let app_source = if request.app_sources.is_empty() {
        None
    } else {
        Some(enclave_builder::AppSource {
            urls: request.app_sources.clone(),
            commit: request.commit_sha.clone(),
            branch: Some(request.branch.clone()),
        })
    };
    let framework_url = enclave_builder::pin_archive_url_to_commit(
        enclave_builder::FRAMEWORK_SOURCE,
        &request.framework_commit,
    );
    let mut manifest = enclave_builder::EnclaveManifest::new(
        app_source,
        enclave_builder::EnclaveSource::GitArchive {
            urls: vec![format!(
                "https://git.distrust.co/public/enclaveos/archive/{}.tar.gz",
                request.enclaveos_commit
            )],
            commit: Some(request.enclaveos_commit.clone()),
        },
        enclave_builder::FrameworkSource::GitArchive {
            url: framework_url,
            commit: Some(request.framework_commit.clone()),
        },
        None,
        request.run_command.clone(),
        None,
    );
    manifest.enclaveos_commit = Some(request.enclaveos_commit.clone());
    manifest.bootproof_commit = Some(bootproof_commit);
    if request.e2e {
        manifest.steve_commit = Some(request.steve_commit.clone());
        manifest.steve_allow_plaintext_fallback = request.allow_plaintext_fallback;
        if request.e2e_key_exchange != enclave_builder::build::DEFAULT_KEY_EXCHANGE {
            manifest.steve_key_exchange = Some(request.e2e_key_exchange.clone());
        }
    }
    if request.locksmith {
        manifest.locksmith = true;
        manifest.locksmith_commit = Some(locksmith_commit);
    }
    let manifest_json =
        serde_json::to_string(&manifest).expect("manifest serialization cannot fail");

    Ok(format!(
        r##"#!/bin/bash
set -euo pipefail

# --- Caution Dedicated Builder ---
BUILD_ID="{build_id}"
S3_BUCKET="{bucket}"
STATUS_KEY="{status_key}"
EIF_S3_KEY="{eif_s3_key}"
SOURCE_S3_KEY="{source_s3_key}"
SOURCE_SHA256="{source_sha256}"
HELPER_S3_KEY="{helper_s3_key}"
HELPER_SHA256="{helper_sha256}"
HELPER_LOG="/build/remote-build-helper.log"
HELPER_LOG_KEY="builds/$BUILD_ID/remote-build-helper.log"
COMMIT_SHA="{commit_sha}"
ENCLAVEOS_COMMIT="{enclaveos_commit}"
CONTAINERFILE="{containerfile}"
PORTS="{ports_csv}"
HTTP_PORT="{http_port}"
E2E="{e2e_flag}"
E2E_MODE="{e2e_mode}"
KEY_EXCHANGE="{key_exchange}"
ALLOW_PLAINTEXT_FALLBACK="{plaintext_fallback_flag}"
DOMAIN="{domain}"
HTTP_UPSTREAM_PROTOCOL="{http_upstream_protocol}"
LOCKSMITH="{locksmith_flag}"
EGRESS="{egress_flag}"
CORS_ORIGINS='{cors_origins_escaped}'
NO_CACHE="{no_cache_flag}"

# Install script dependencies
# We won't have status tracking for these, but we also can't build status without these.

dnf install -y jq

# Global state tracking for heartbeat and metadata accumulation
# Phase must be persisted to a file to exist in a subshell
PHASEFILE="$(mktemp /tmp/build-status.XXXX)"
TEMPLATEFILE="$(mktemp /tmp/build-template.XXXX)"

heartbeat() {{
    # PHASEFILE contains a newline, but storing as a variable trims newlines
    phase="$(cat $PHASEFILE)"
    timestamp="$(date -u +%s)"
    s3_url="s3://$S3_BUCKET/$STATUS_KEY"
    cat "$TEMPLATEFILE" | \
        jq -c --arg phase "$phase" --argjson timestamp "$timestamp" '.phase = $phase | .timestamp = $timestamp' | \
        aws s3 cp - "$s3_url" --content-type application/json
}}

set_template() {{
    echo "$1" > $TEMPLATEFILE
}}

set_phase() {{
    echo "$1" > $PHASEFILE
    heartbeat
}}

set_template "{{}}"
set_phase "starting"

# Run heartbeat periodically to ensure timestamp is always fresh
(
    while true; do
        heartbeat
        sleep 30
    done
) &

fail() {{
    local msg="$1"
    if [ -f "$HELPER_LOG" ]; then
        timeout 30 aws s3 cp "$HELPER_LOG" "s3://$S3_BUCKET/$HELPER_LOG_KEY" >/dev/null 2>&1 || true
    fi
    set_template "$(jq -cn --arg error "$msg" '{{"error": $error}}')"
    set_phase "failed"
    exit 1
}}

trap 'rc=$?; line=$LINENO; trap - ERR; fail "Builder command failed at line $line (exit $rc)"' ERR

# Install dependencies
echo "Installing Docker..."
dnf install -y docker
systemctl start docker
systemctl enable docker

set_phase "starting"

# Download source archive from S3
echo "Downloading source archive..."
mkdir -p /build/repo
aws s3 cp "s3://$S3_BUCKET/$SOURCE_S3_KEY" /build/source.tar.gz
echo "$SOURCE_SHA256  /build/source.tar.gz" | sha256sum -c -
tar -xzf /build/source.tar.gz -C /build/repo

echo "Downloading remote build helper..."
aws s3 cp "s3://$S3_BUCKET/$HELPER_S3_KEY" /usr/local/bin/remote-build-helper
echo "$HELPER_SHA256  /usr/local/bin/remote-build-helper" | sha256sum -c -
chmod +x /usr/local/bin/remote-build-helper

# Build Docker image
echo "Building Docker image..."
cd /build/repo
docker build -f "$CONTAINERFILE" -t app-image .
set_phase "docker_built"

# Write manifest for remote-build-helper
cat > /build/manifest.json << 'MANIFEST_EOF'
{manifest_json}
MANIFEST_EOF

echo "Building EIF via remote-build-helper..."
mkdir -p /build/output
if CAUTION_IMAGE_REF="app-image" \
CAUTION_MANIFEST_PATH="/build/manifest.json" \
CAUTION_WORK_DIR="/build/remote-helper-work" \
CAUTION_OUTPUT_EIF="/build/output/enclave.eif" \
CAUTION_OUTPUT_PCRS="/build/output/enclave.pcrs" \
CAUTION_PORTS="$PORTS" \
CAUTION_HTTP_PORT="$HTTP_PORT" \
CAUTION_E2E="$E2E" \
CAUTION_E2E_MODE="$E2E_MODE" \
CAUTION_DOMAIN="$DOMAIN" \
CAUTION_HTTP_UPSTREAM_PROTOCOL="$HTTP_UPSTREAM_PROTOCOL" \
CAUTION_KEY_EXCHANGE="$KEY_EXCHANGE" \
CAUTION_ALLOW_PLAINTEXT_FALLBACK="$ALLOW_PLAINTEXT_FALLBACK" \
CAUTION_LOCKSMITH="$LOCKSMITH" \
CAUTION_EGRESS="$EGRESS" \
CAUTION_CORS_ORIGINS="$CORS_ORIGINS" \
CAUTION_NO_CACHE="$NO_CACHE" \
/usr/local/bin/remote-build-helper 2>&1 | tee "$HELPER_LOG"; then
    :
else
    fail "EIF build helper failed:
$(tail -12 "$HELPER_LOG" 2>/dev/null | tail -c 4096 | tr -d '\000-\010\013-\037\177' || echo "No helper output available")"
fi

EIF_PATH="/build/output/enclave.eif"
PCRS_PATH="/build/output/enclave.pcrs"

if [ ! -f "$EIF_PATH" ]; then
    fail "EIF file not found after build"
fi

set_phase "eif_built"

# Compute SHA256
EIF_SHA256=$(sha256sum "$EIF_PATH" | awk '{{print $1}}')
EIF_SIZE=$(stat -c%s "$EIF_PATH")

# Read PCRs
PCRS_JSON='{{}}'
if [ -f "$PCRS_PATH" ]; then
    # Convert "hash PCRn" lines to JSON object {{"PCR0":"hash",...}}
    PCRS_JSON=$(awk '{{printf "%s\"%s\":\"%s\"", (NR>1?",":""), $2, $1}}' "$PCRS_PATH")
    PCRS_JSON="{{"$PCRS_JSON"}}"
fi

# Upload EIF to S3
echo "Uploading EIF to S3..."
aws s3 cp "$EIF_PATH" "s3://$S3_BUCKET/$EIF_S3_KEY"

set_template "$(jq -cn \
    --arg eif_sha256 "$EIF_SHA256" \
    --argjson eif_size_bytes "$EIF_SIZE" \
    --argjson pcrs "$PCRS_JSON" \
    '{{"eif_sha256": $eif_sha256, "eif_size_bytes": $eif_size_bytes, "pcrs": $pcrs}}')"
set_phase "completed"

echo "Build complete: $EIF_SHA256 ($EIF_SIZE bytes)"
"##,
        build_id = build_id,
        bucket = bucket,
        status_key = status_key,
        eif_s3_key = eif_s3_key,
        source_s3_key = source_s3_key,
        source_sha256 = source_sha256,
        helper_s3_key = helper_s3_key,
        helper_sha256 = helper_sha256,
        commit_sha = request.commit_sha,
        enclaveos_commit = request.enclaveos_commit,
        containerfile = containerfile,
        ports_csv = ports_csv,
        http_port = http_port,
        e2e_flag = e2e_flag,
        e2e_mode = request.e2e_mode.as_str(),
        domain = request.domain.as_deref().unwrap_or(""),
        http_upstream_protocol = request.http_upstream_protocol.as_str(),
        locksmith_flag = locksmith_flag,
        egress_flag = egress_flag,
        cors_origins_escaped = cors_origins_escaped,
        no_cache_flag = no_cache_flag,
        manifest_json = manifest_json,
    ))
}

/// Reap builder instances that have been running for too long.
/// Called periodically from a background task.
/// Bill a user for builder instance time. Used as a fallback by the orphan reaper
/// when real-time metering via tracked_resources was not active for the build.
async fn bill_builder_usage(
    db: &PgPool,
    build_id: Uuid,
    instance_id: &str,
    org_id: Uuid,
    app_id: Option<Uuid>,
    instance_type: &str,
    started_at: chrono::DateTime<chrono::Utc>,
    pricing: AppliedPricing,
) {
    let duration_secs = (chrono::Utc::now() - started_at).num_seconds().max(0) as f64;
    let hours = duration_secs / 3600.0;
    let billable_hours = hours.max(1.0 / 60.0); // minimum 1 minute charge
    let cost_usd = pricing.total_cost_usd(billable_hours);
    let cost_cents = (cost_usd * 100.0).round() as i64;

    if cost_cents <= 0 {
        return;
    }

    if let Err(e) = async {
        let mut tx = db.begin().await?;

        sqlx::query(
            "INSERT INTO usage_ledger (
                organization_id, application_id, resource_id, provider, resource_type,
                quantity, unit, base_unit_cost_usd, margin_percent, recorded_at, metadata
             )
             VALUES ($1, $2, $3, 'aws', 'compute', $4, 'hours', $5, $6, NOW(), $7)",
        )
        .bind(org_id)
        .bind(app_id)
        .bind(instance_id)
        .bind(billable_hours)
        .bind(pricing.base_unit_cost_usd)
        .bind(pricing.margin_percent)
        .bind(serde_json::json!({
            "build_id": build_id.to_string(),
            "application_id": app_id.map(|id| id.to_string()),
            "instance_type": instance_type,
            "duration_secs": duration_secs as i64,
        }))
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok::<_, anyhow::Error>(())
    }
    .await
    {
        tracing::error!("Failed to bill for build {}: {}", build_id, e);
        return;
    }

    tracing::info!(
        "Builder billing: org={}, build={}, type={}, {:.1}min, ${:.4} ({}c debited)",
        org_id,
        build_id,
        instance_type,
        duration_secs / 60.0,
        cost_usd,
        cost_cents
    );
}

pub async fn reap_orphaned_builders(
    db: &PgPool,
    ec2: &Ec2Client,
    instance_pricing: impl Fn(&str) -> Option<AppliedPricing>,
) {
    let rows = match sqlx::query_as::<_, (Uuid, Option<String>, Uuid, Option<Uuid>, Option<String>, Option<chrono::DateTime<chrono::Utc>>, String)>(
        "SELECT id, builder_instance_id, organization_id, app_id, builder_instance_type, started_at, status FROM eif_builds
         WHERE created_at < NOW() - INTERVAL '30 minutes'"
    )
    .fetch_all(db)
    .await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("Failed to query orphaned builds: {}", e);
            return;
        }
    };

    let mut orphaned_per_org: HashMap<Uuid, usize> = HashMap::new();
    for (build_id, instance_id, org_id, app_id, instance_type, started_at, status) in rows {
        // Every build older than 30 minutes is a candidate regardless of build
        // status: a builder instance can be left behind by a timeout, a
        // failure, or even a successful build. Only builds still stuck in
        // pending/building get the metering/timeout treatment; anything else
        // just gets its still-existing instance terminated.
        let stuck = status == "pending" || status == "building";
        if stuck {
            tracing::warn!(
                "Reaping orphaned build {} (instance: {:?})",
                build_id,
                instance_id
            );

            if let Some(ref iid) = instance_id {
                // Check if this builder was tracked by the metering collection loop
                let was_tracked: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM tracked_resources WHERE resource_id = $1)",
                )
                .bind(iid)
                .fetch_one(db)
                .await
                .unwrap_or(false);

                if was_tracked {
                    // Stop metering — the collection loop already billed for runtime
                    let _ = sqlx::query(
                        "UPDATE tracked_resources SET status = 'stopped', stopped_at = NOW() WHERE resource_id = $1 AND status = 'running'"
                    )
                    .bind(iid)
                    .execute(db)
                    .await;
                } else if let (Some(itype), Some(started)) = (&instance_type, started_at) {
                    // Fallback: metering tracking failed, bill directly for the full duration
                    if let Some(pricing) = instance_pricing(itype) {
                        bill_builder_usage(db, build_id, iid, org_id, app_id, itype, started, pricing)
                            .await;
                    } else {
                        tracing::error!(
                            "Cannot bill orphaned builder {} for build {}: unknown instance type {}",
                            iid,
                            build_id,
                            itype
                        );
                    }
                }
            }

            let _ = sqlx::query(
                "UPDATE eif_builds SET status = 'timeout', error_message = 'Build timed out (reaped)', completed_at = NOW()
                 WHERE id = $1"
            )
            .bind(build_id)
            .execute(db)
            .await;
        }

        // Terminate the builder only if the instance still exists; a build in
        // a terminal state, or one reaped on an earlier pass, has no instance
        // left to clean up.
        let Some(iid) = instance_id else { continue };
        let still_exists = match ec2
            .describe_instances(&[Filter::new("instance-id", &[iid.as_str()])])
            .await
        {
            Ok(instances) => !instances.is_empty(),
            Err(e) => {
                tracing::error!(
                    "Failed to check instance {} existence for build {}: {}",
                    iid,
                    build_id,
                    e
                );
                continue;
            }
        };
        if !still_exists {
            tracing::debug!(
                "Skipping build {} (instance {} no longer exists)",
                build_id,
                iid
            );
            continue;
        }

        *orphaned_per_org.entry(org_id).or_default() += 1;
        if let Err(e) = ec2.terminate_instances(std::slice::from_ref(&iid)).await {
            tracing::error!("Failed to terminate orphaned builder {}: {}", iid, e);
        }
    }

    if !orphaned_per_org.is_empty() {
        tracing::info!(
            "Found {} orphaned builder(s) across {} organization(s)",
            orphaned_per_org.values().sum::<usize>(),
            orphaned_per_org.len()
        );
        let mut orgs: Vec<&Uuid> = orphaned_per_org.keys().collect();
        orgs.sort_unstable();
        for org_id in orgs {
            tracing::info!(
                "Found {} orphaned builder(s) in organization {}",
                orphaned_per_org[org_id],
                org_id
            );
        }
    }
}

/// Whether an EC2 instance's tags identify it as a Caution build machine.
///
/// Builders launched by [`execute_remote_build`] carry `ManagedBy:
/// caution-builder`, a `BuildId` tag, and a `Name` tag prefixed with
/// `caution-builder-`. Any of the three markers is sufficient, mirroring the
/// drift detector's builder classification.
fn is_caution_builder(tags: &HashMap<String, String>) -> bool {
    tags.get(MANAGED_BY_TAG)
        .is_some_and(|value| value == MANAGED_BY_BUILDER)
        || tags.contains_key(BUILD_ID_TAG)
        || tags
            .get(NAME_TAG)
            .is_some_and(|value| value.starts_with(BUILDER_NAME_PREFIX))
}

/// Whether an instance's `org_id` tag names one of the active organizations.
///
/// A missing, unparseable, or stale `org_id` tag means the instance has no
/// organization attached, matching how the drift detector attributes
/// instances to the active organizations it scans.
fn attached_to_active_org(tags: &HashMap<String, String>, active_orgs: &HashSet<Uuid>) -> bool {
    tags.get(ORG_ID_TAG)
        .and_then(|value| Uuid::parse_str(value).ok())
        .is_some_and(|org_id| active_orgs.contains(&org_id))
}

/// Terminate build machines running with no organization attached.
///
/// Build runners are tagged with their owning organization (`org_id`) at
/// launch, so a running instance recognized as a Caution builder whose
/// `org_id` tag is missing, unparseable, or names an organization that no
/// longer exists is a leak (typically a manually launched instance or one
/// stranded by a failed launch). This complements [`reap_orphaned_builders`]:
/// that reaper handles builds stuck in `pending`/`building` for over 30
/// minutes, while this one sweeps up instances that can never be attributed
/// to an organization at all.
///
/// Every enabled AWS region is swept (falling back to the client's configured
/// region when discovery fails), so a builder stranded in any region is found
/// and terminated from within that region.
///
/// Instances whose `BuildId` tag (or instance ID) matches an in-flight build
/// are left for [`reap_orphaned_builders`]: terminating them here would
/// strand the `eif_builds` row in `building` and wedge the app's build slot
/// until the timeout reaper runs.
pub async fn reap_unattributed_builders(db: &PgPool, ec2: &Ec2Client) {
    let active_orgs: HashSet<Uuid> =
        match sqlx::query_scalar("SELECT id FROM organizations WHERE is_active = true")
            .fetch_all(db)
            .await
        {
            Ok(ids) => ids.into_iter().collect(),
            Err(e) => {
                tracing::error!(
                    "Failed to load active organizations for unattributed builder reaping: {}",
                    e
                );
                return;
            }
        };

    // Builders backing an in-flight build are owned by that build; skip them
    // so a missing `org_id` tag can never abort a live build.
    let in_flight_build_ids: HashSet<Uuid> = match sqlx::query_scalar(
        "SELECT id FROM eif_builds WHERE status IN ('pending', 'building')",
    )
    .fetch_all(db)
    .await
    {
        Ok(ids) => ids.into_iter().collect(),
        Err(e) => {
            tracing::error!(
                "Failed to load in-flight builds for unattributed builder reaping: {}",
                e
            );
            return;
        }
    };
    let in_flight_instance_ids: HashSet<String> = match sqlx::query_scalar::<
        sqlx::Postgres,
        Option<String>,
    >(
        "SELECT builder_instance_id FROM eif_builds
             WHERE status IN ('pending', 'building') AND builder_instance_id IS NOT NULL",
    )
    .fetch_all(db)
    .await
    {
        Ok(ids) => ids.into_iter().flatten().collect(),
        Err(e) => {
            tracing::error!(
                "Failed to load in-flight builder instances for unattributed builder reaping: {}",
                e
            );
            return;
        }
    };

    // Sweep every enabled region: a builder stranded in a region other than
    // the API's configured region would otherwise leak forever.
    let regions = match ec2.describe_regions(false).await {
        Ok(regions) if !regions.is_empty() => regions
            .into_iter()
            .map(|region| region.name)
            .collect::<Vec<_>>(),
        Ok(_) => {
            tracing::warn!(
                "No enabled AWS regions discovered; falling back to configured region {}",
                ec2.region()
            );
            vec![ec2.region().to_string()]
        }
        Err(e) => {
            tracing::warn!(
                "Failed to discover AWS regions; falling back to configured region {}: {}",
                ec2.region(),
                e
            );
            vec![ec2.region().to_string()]
        }
    };

    let mut found_unattributed = 0usize;
    let mut terminated = 0usize;
    for region in regions {
        tracing::debug!(region, "Searching for instances");
        let region_ec2 = ec2.for_region(&region);
        let instances = match region_ec2.describe_instances(&[]).await {
            Ok(instances) => instances,
            Err(e) => {
                tracing::error!(
                    "Failed to describe instances in region {} for unattributed builder reaping: {:?}",
                    region,
                    e
                );
                continue;
            }
        };
        for instance in instances {
            tracing::debug!(
                "Found AWS instance {} (region: {}, org_id tag: {:?})",
                instance.instance_id,
                region,
                instance.tags.get(ORG_ID_TAG)
            );
            if !is_caution_builder(&instance.tags) {
                continue;
            }
            if attached_to_active_org(&instance.tags, &active_orgs) {
                continue;
            }
            found_unattributed += 1;

            let build_id = instance
                .tags
                .get(BUILD_ID_TAG)
                .and_then(|value| Uuid::parse_str(value).ok());
            if in_flight_instance_ids.contains(&instance.instance_id)
                || build_id.is_some_and(|id| in_flight_build_ids.contains(&id))
            {
                tracing::warn!(
                    "Skipping unattributed builder {} (build {:?} is in flight)",
                    instance.instance_id,
                    build_id.map(|id| id.to_string())
                );
                continue;
            }

            tracing::warn!(
                "Terminating build machine {} with no organization attached (region: {}, tags: {:?})",
                instance.instance_id,
                region,
                instance.tags
            );
            if let Err(e) = region_ec2
                .terminate_instances(std::slice::from_ref(&instance.instance_id))
                .await
            {
                tracing::error!(
                    "Failed to terminate unattributed build machine {}: {}",
                    instance.instance_id,
                    e
                );
                continue;
            }
            terminated += 1;
        }
    }

    tracing::info!(
        "Found {} unattributed Caution builder(s) with no organization attached",
        found_unattributed
    );
    if terminated > 0 {
        tracing::info!(
            "Terminated {} build machine(s) with no organization attached",
            terminated
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_build_phase_is_not_a_progress_milestone() {
        assert_eq!(build_phase_milestone("failed"), None);
        assert_eq!(
            build_phase_milestone("docker_built"),
            Some("Docker image built, building EIF...")
        );
    }

    // --- unattributed builder classification ---

    fn tags(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect()
    }

    #[test]
    fn test_is_caution_builder_recognizes_launch_tags() {
        let launch_tags = tags(&[
            ("Name", "caution-builder-12345678"),
            ("org_id", "550e8400-e29b-41d4-a716-446655440000"),
            ("ManagedBy", "caution-builder"),
            ("BuildId", "12345678-1234-1234-1234-123456789abc"),
        ]);

        assert!(is_caution_builder(&launch_tags));
    }

    #[test]
    fn test_is_caution_builder_requires_caution_marker() {
        let unrelated = tags(&[
            ("Name", "web-1"),
            ("ManagedBy", "CloudFormation"),
            ("org_id", "550e8400-e29b-41d4-a716-446655440000"),
        ]);

        assert!(!is_caution_builder(&unrelated));
        assert!(!is_caution_builder(&HashMap::new()));
    }

    #[test]
    fn test_is_caution_builder_accepts_each_marker_independently() {
        let by_managed_by = tags(&[("ManagedBy", "caution-builder")]);
        let by_build_id = tags(&[("BuildId", "b-123")]);
        let by_name_prefix = tags(&[("Name", "caution-builder-abc12345")]);
        let foreign_managed_by = tags(&[("ManagedBy", "CloudFormation")]);
        let non_prefixed_name = tags(&[("Name", "caution-builder")]);

        assert!(is_caution_builder(&by_managed_by));
        assert!(is_caution_builder(&by_build_id));
        assert!(is_caution_builder(&by_name_prefix));
        assert!(!is_caution_builder(&foreign_managed_by));
        assert!(!is_caution_builder(&non_prefixed_name));
    }

    #[test]
    fn test_attached_to_active_org_matches_org_id_tag() {
        let org_id = Uuid::new_v4();
        let active: HashSet<Uuid> = [org_id].into_iter().collect();

        let attached = tags(&[("org_id", &org_id.to_string())]);
        let missing = tags(&[]);
        let unparseable = tags(&[("org_id", "not-a-uuid")]);
        let stale = tags(&[("org_id", &Uuid::new_v4().to_string())]);

        assert!(attached_to_active_org(&attached, &active));
        assert!(!attached_to_active_org(&missing, &active));
        assert!(!attached_to_active_org(&unparseable, &active));
        assert!(!attached_to_active_org(&stale, &active));
    }

    // --- compute_cache_key ---

    const TEST_FRAMEWORK_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    fn cache_key(
        commit: &str,
        enclaveos: &str,
        procfile: &str,
        e2e: bool,
        e2e_key_exchange: &str,
        locksmith: bool,
        framework_commit: Option<&str>,
    ) -> String {
        compute_cache_key(
            commit,
            enclaveos,
            "steve-v1",
            procfile,
            e2e,
            e2e_key_exchange,
            false,
            locksmith,
            &[],
            framework_commit.unwrap_or(TEST_FRAMEWORK_COMMIT),
        )
    }

    #[test]
    fn test_cache_key_deterministic() {
        let key1 = cache_key("abc123", "enclave-v1", "run: /app", false, "X25519", false, None);
        let key2 = cache_key("abc123", "enclave-v1", "run: /app", false, "X25519", false, None);
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 64); // SHA256 hex
    }

    #[test]
    fn test_cache_key_changes_with_commit() {
        let key1 = cache_key("abc123", "enclave-v1", "run: /app", false, "X25519", false, None);
        let key2 = cache_key("def456", "enclave-v1", "run: /app", false, "X25519", false, None);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_cache_key_changes_with_enclaveos() {
        let key1 = cache_key("abc123", "enclave-v1", "run: /app", false, "X25519", false, None);
        let key2 = cache_key("abc123", "enclave-v2", "run: /app", false, "X25519", false, None);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_cache_key_changes_with_procfile() {
        let key1 = cache_key("abc123", "enclave-v1", "run: /app", false, "X25519", false, None);
        let key2 = cache_key("abc123", "enclave-v1", "run: /other", false, "X25519", false, None);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_cache_key_changes_with_e2e() {
        let key1 = cache_key("abc123", "enclave-v1", "run: /app", false, "X25519", false, None);
        let key2 = cache_key("abc123", "enclave-v1", "run: /app", true, "X25519", false, None);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_cache_key_changes_with_locksmith() {
        let key1 = cache_key("abc123", "enclave-v1", "run: /app", false, "X25519", false, None);
        let key2 = cache_key("abc123", "enclave-v1", "run: /app", false, "X25519", true, None);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_cache_key_changes_with_framework_commit() {
        for e2e in [false, true] {
            let key1 = cache_key(
                "abc123",
                "enclave-v1",
                "run: /app",
                e2e,
                "X25519",
                false,
                Some("1111111111111111111111111111111111111111"),
            );
            let key2 = cache_key(
                "abc123",
                "enclave-v1",
                "run: /app",
                e2e,
                "X25519",
                false,
                Some("2222222222222222222222222222222222222222"),
            );
            assert_ne!(key1, key2);
        }
    }

    #[test]
    fn test_cache_key_changes_with_steve_commit_only_for_e2e() {
        let e2e_v1 = compute_cache_key(
            "abc123",
            "enclave-v1",
            "steve-v1",
            "run: /app",
            true,
            "X25519",
            false,
            false,
            &[],
            TEST_FRAMEWORK_COMMIT,
        );
        let e2e_v2 = compute_cache_key(
            "abc123",
            "enclave-v1",
            "steve-v2",
            "run: /app",
            true,
            "X25519",
            false,
            false,
            &[],
            TEST_FRAMEWORK_COMMIT,
        );
        assert_ne!(e2e_v1, e2e_v2);

        let plain_v1 = compute_cache_key(
            "abc123",
            "enclave-v1",
            "steve-v1",
            "run: /app",
            false,
            "X25519",
            false,
            false,
            &[],
            TEST_FRAMEWORK_COMMIT,
        );
        let plain_v2 = compute_cache_key(
            "abc123",
            "enclave-v1",
            "steve-v2",
            "run: /app",
            false,
            "X25519",
            false,
            false,
            &[],
            TEST_FRAMEWORK_COMMIT,
        );
        assert_eq!(plain_v1, plain_v2);
    }

    #[test]
    fn test_cache_key_changes_with_key_exchange() {
        let x25519 = cache_key("abc123", "enclave-v1", "run: /app", true, "X25519", false, None);
        let xwing = cache_key(
            "abc123",
            "enclave-v1",
            "run: /app",
            true,
            "XWING-DRAFT10",
            false,
            None,
        );
        assert_ne!(x25519, xwing);
    }

    #[test]
    fn test_cache_key_changes_with_plaintext_fallback_only_for_e2e() {
        let fail_closed = compute_cache_key(
            "abc123",
            "enclave-v1",
            "steve-v1",
            "run: /app",
            true,
            "X25519",
            false,
            false,
            &[],
            TEST_FRAMEWORK_COMMIT,
        );
        let fallback = compute_cache_key(
            "abc123",
            "enclave-v1",
            "steve-v1",
            "run: /app",
            true,
            "X25519",
            true,
            false,
            &[],
            TEST_FRAMEWORK_COMMIT,
        );
        assert_ne!(fail_closed, fallback);
        assert_eq!(
            fail_closed,
            "36ed62e47d1cde90321166fa213b60a55da0dfebd45728bb0f8599b582f905aa"
        );

        let plain_default = compute_cache_key(
            "abc123",
            "enclave-v1",
            "steve-v1",
            "run: /app",
            false,
            "X25519",
            false,
            false,
            &[],
            TEST_FRAMEWORK_COMMIT,
        );
        let plain_ignored = compute_cache_key(
            "abc123",
            "enclave-v1",
            "steve-v1",
            "run: /app",
            false,
            "X25519",
            true,
            false,
            &[],
            TEST_FRAMEWORK_COMMIT,
        );
        assert_eq!(plain_default, plain_ignored);
        assert_eq!(
            plain_default,
            "f0b5c8c963ebbc0bba86733210780a95d0be45efbca04891ed08314b2bead71f"
        );
    }

    #[test]
    fn test_platform_framework_commit_is_required_and_normalized() {
        let commit = "ABCDEF0123456789ABCDEF0123456789ABCDEF01";
        assert_eq!(
            require_platform_framework_commit(Some(commit)).unwrap(),
            commit.to_ascii_lowercase()
        );
        assert!(require_platform_framework_commit(None).is_err());
        assert!(require_platform_framework_commit(Some("")).is_err());
        assert!(require_platform_framework_commit(Some("test-sha")).is_err());
        assert!(
            require_platform_framework_commit(Some("gggggggggggggggggggggggggggggggggggggggg"))
                .is_err()
        );
    }

    // --- BuilderSizesConfig ---

    fn test_config() -> BuilderSizesConfig {
        serde_json::from_str(r#"{
            "builder_sizes": [
                { "id": "small", "label": "Small", "instance_type": "c5.xlarge", "vcpus": 4, "ram_gb": 8 },
                { "id": "medium", "label": "Medium", "instance_type": "c5.2xlarge", "vcpus": 8, "ram_gb": 16 },
                { "id": "large", "label": "Large", "instance_type": "c5.4xlarge", "vcpus": 16, "ram_gb": 32 }
            ]
        }"#).unwrap()
    }

    #[test]
    fn test_builder_size_resolve_default() {
        let config = test_config();
        let spec = config.resolve(None);
        assert_eq!(spec.id, "small");
        assert_eq!(spec.instance_type, "c5.xlarge");
    }

    #[test]
    fn test_builder_size_resolve_by_id() {
        let config = test_config();
        assert_eq!(config.resolve(Some("small")).instance_type, "c5.xlarge");
        assert_eq!(config.resolve(Some("medium")).instance_type, "c5.2xlarge");
        assert_eq!(config.resolve(Some("large")).instance_type, "c5.4xlarge");
    }

    #[test]
    fn test_builder_size_resolve_case_insensitive() {
        let config = test_config();
        assert_eq!(config.resolve(Some("MEDIUM")).instance_type, "c5.2xlarge");
    }

    #[test]
    fn test_builder_size_resolve_unknown_defaults_to_first() {
        let config = test_config();
        assert_eq!(config.resolve(Some("xlarge")).instance_type, "c5.xlarge");
    }

    #[test]
    fn test_builder_size_is_valid() {
        let config = test_config();
        assert!(config.is_valid("small"));
        assert!(config.is_valid("medium"));
        assert!(config.is_valid("large"));
        assert!(!config.is_valid("xlarge"));
    }

    #[test]
    fn test_max_resources_per_org_default() {
        // Config without max_resources_per_org should default to 10
        let config: BuilderSizesConfig = serde_json::from_str(r#"{
            "builder_sizes": [
                { "id": "small", "label": "Small", "instance_type": "c5.xlarge", "vcpus": 4, "ram_gb": 8 }
            ]
        }"#).unwrap();
        assert_eq!(config.max_resources_per_org, 10);
    }

    #[test]
    fn test_max_resources_per_org_explicit() {
        let config: BuilderSizesConfig = serde_json::from_str(r#"{
            "builder_sizes": [
                { "id": "small", "label": "Small", "instance_type": "c5.xlarge", "vcpus": 4, "ram_gb": 8 }
            ],
            "max_resources_per_org": 5
        }"#).unwrap();
        assert_eq!(config.max_resources_per_org, 5);
    }

    #[test]
    fn test_should_use_customer_builder_path_requires_builder_profile() {
        let mut config = ManagedOnPremConfig {
            deployment_id: "dep-123".to_string(),
            asg_name: "asg-123".to_string(),
            launch_template_name: "lt-name".to_string(),
            launch_template_id: "lt-123".to_string(),
            vpc_id: "vpc-123".to_string(),
            subnet_ids: vec!["subnet-123".to_string()],
            eif_bucket: "customer-bucket".to_string(),
            instance_profile_name: "runtime-profile".to_string(),
            builder_instance_profile_name: None,
        };
        assert!(!should_use_customer_builder_path(Some(&config)));

        config.builder_instance_profile_name = Some("builder-profile".to_string());
        assert!(should_use_customer_builder_path(Some(&config)));
    }

    #[test]
    fn test_validate_remote_containerfile_path_accepts_relative_paths() {
        assert_eq!(
            validate_remote_containerfile_path("docker/Prod.Containerfile").unwrap(),
            "docker/Prod.Containerfile"
        );
    }

    #[test]
    fn test_validate_remote_containerfile_path_rejects_absolute_paths() {
        let err = validate_remote_containerfile_path("/etc/passwd").unwrap_err();
        assert!(
            err.to_string().contains("relative path"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_validate_remote_containerfile_path_rejects_parent_dirs() {
        let err = validate_remote_containerfile_path("../Dockerfile").unwrap_err();
        assert!(
            err.to_string().contains("within the repository"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_validate_remote_containerfile_path_rejects_shell_chars() {
        let err = validate_remote_containerfile_path("Dockerfile$(aws)").unwrap_err();
        assert!(
            err.to_string().contains("unsupported character"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_build_managed_onprem_builder_config_uses_customer_settings() {
        let default_config = BuilderConfig {
            ami_id: "ami-platform".to_string(),
            security_group_id: "sg-platform".to_string(),
            subnet_id: "subnet-platform".to_string(),
            instance_profile: "profile-platform".to_string(),
            region: "us-west-2".to_string(),
            timeout_secs: 1200,
            eif_s3_bucket: "platform-bucket".to_string(),
            git_hostname: "git.example.com".to_string(),
            additional_instance_tags: Vec::new(),
        };
        let managed_onprem = ManagedOnPremConfig {
            deployment_id: "dep-123".to_string(),
            asg_name: "asg-123".to_string(),
            launch_template_name: "lt-name".to_string(),
            launch_template_id: "lt-123".to_string(),
            vpc_id: "vpc-123".to_string(),
            subnet_ids: vec!["subnet-123".to_string()],
            eif_bucket: "customer-bucket".to_string(),
            instance_profile_name: "runtime-profile".to_string(),
            builder_instance_profile_name: Some("builder-profile".to_string()),
        };

        let resolved = build_managed_onprem_builder_config(
            &default_config,
            &managed_onprem,
            "ami-customer".to_string(),
            "sg-customer".to_string(),
            "subnet-customer".to_string(),
            "us-east-1".to_string(),
            "builder-profile".to_string(),
        );

        assert_eq!(resolved.ami_id, "ami-customer");
        assert_eq!(resolved.security_group_id, "sg-customer");
        assert_eq!(resolved.subnet_id, "subnet-customer");
        assert_eq!(resolved.instance_profile, "builder-profile");
        assert_eq!(resolved.region, "us-east-1");
        assert_eq!(resolved.eif_s3_bucket, "customer-bucket");
        assert_eq!(
            resolved.additional_instance_tags,
            vec![(
                MANAGED_ONPREM_DEPLOYMENT_TAG_KEY.to_string(),
                "dep-123".to_string(),
            )]
        );
    }

    // --- generate_builder_userdata ---

    #[test]
    fn test_userdata_contains_required_sections() {
        let config = BuilderConfig {
            ami_id: "ami-test".to_string(),
            security_group_id: "sg-test".to_string(),
            subnet_id: "subnet-test".to_string(),
            instance_profile: "profile-test".to_string(),
            region: "us-west-2".to_string(),
            timeout_secs: 1200,
            eif_s3_bucket: "test-bucket".to_string(),
            git_hostname: "git.example.com".to_string(),
            additional_instance_tags: Vec::new(),
        };

        let request = BuildRequest {
            org_id: Uuid::new_v4(),
            app_id: Uuid::new_v4(),
            app_name: "test-app".to_string(),
            commit_sha: "abc123def456".to_string(),
            branch: "main".to_string(),
            source_s3_key: "builds/test-id/source.tar.gz".to_string(),
            source_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            procfile_content: "run: /app\n".to_string(),
            run_command: Some("/app".to_string()),
            containerfile: "Dockerfile".to_string(),
            ports: vec![],
            http_port: None,
            e2e: true,
            e2e_mode: "steve".to_string(),
            e2e_key_exchange: "X25519".to_string(),
            allow_plaintext_fallback: true,
            domain: None,
            http_upstream_protocol: "http".to_string(),
            framework_commit: TEST_FRAMEWORK_COMMIT.to_string(),
            locksmith: false,
            egress: false,
            e2e_cors_origins: None,
            no_cache: true,
            enclaveos_commit: "enclave-abc".to_string(),
            steve_commit: "steve-from-cache-key".to_string(),
            builder_size: "small".to_string(),
            builder_instance_type: "c5.xlarge".to_string(),
            app_sources: vec![],
        };

        let build_id = Uuid::new_v4();
        let userdata = generate_builder_userdata(
            build_id,
            &config,
            &request,
            "eifs/org/key.eif",
            "builds/test-id/remote-build-helper",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();

        // Should be a valid bash script
        assert!(
            userdata.starts_with("#!/bin/bash"),
            "should start with shebang"
        );

        // Should contain S3 bucket reference
        assert!(
            userdata.contains("test-bucket"),
            "should reference S3 bucket"
        );

        // Should download source from S3, not git clone
        assert!(userdata.contains("aws s3 cp"), "should download from S3");
        assert!(
            userdata.contains("source.tar.gz"),
            "should reference source archive"
        );
        assert!(
            userdata.contains("SOURCE_SHA256=\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\""),
            "should include source archive digest"
        );
        assert!(
            userdata.contains("HELPER_SHA256=\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\""),
            "should include helper digest"
        );
        assert!(
            userdata.contains("sha256sum -c -"),
            "should verify downloaded artifacts before use"
        );
        // User source comes from S3, not git clone (Containerfile.eif still clones bootproof/steve deps)
        assert!(
            !userdata.contains("git clone \"$GIT_URL\""),
            "should not git clone user repo"
        );

        assert!(
            userdata.contains("CONTAINERFILE=\"Dockerfile\""),
            "should include the selected Dockerfile path"
        );
        assert!(
            userdata.contains("docker build -f \"$CONTAINERFILE\" -t app-image ."),
            "should build app-image with the platform-owned Docker command"
        );
        assert!(
            !userdata.contains("BUILD_CMD") && !userdata.contains("eval "),
            "should not embed or evaluate user-controlled build commands"
        );

        // Should invoke the shared remote-build-helper path
        assert!(
            userdata.contains("remote-build-helper"),
            "should use remote build helper"
        );
        assert!(
            userdata.contains("CAUTION_MANIFEST_PATH"),
            "should pass manifest to helper"
        );
        assert!(
            userdata.contains("E2E_MODE=\"steve\"")
                && userdata.contains("CAUTION_E2E_MODE=\"$E2E_MODE\""),
            "should pass e2e mode to helper"
        );
        assert!(
            userdata.contains("KEY_EXCHANGE=\"X25519\"")
                && userdata.contains("CAUTION_KEY_EXCHANGE=\"$KEY_EXCHANGE\""),
            "should pass the default key exchange to helper"
        );
        assert!(
            !userdata.contains("\"steve_key_exchange\""),
            "default key exchange should stay implicit in the manifest"
        );
        assert!(
            userdata.contains("DOMAIN=\"\"") && userdata.contains("CAUTION_DOMAIN=\"$DOMAIN\""),
            "should pass HTTP domain to helper"
        );
        assert!(
            userdata.contains("NO_CACHE=\"true\"")
                && userdata.contains("CAUTION_NO_CACHE=\"$NO_CACHE\""),
            "should pass no_cache to helper"
        );
        assert!(
            userdata.contains("\"steve_commit\":\"steve-from-cache-key\""),
            "manifest should use the STEVE commit resolved before cache lookup"
        );
        assert!(
            userdata.contains(&format!("\"commit\":\"{TEST_FRAMEWORK_COMMIT}\"")),
            "manifest should use the Platform commit resolved before cache lookup"
        );
        assert!(
            userdata.contains("ALLOW_PLAINTEXT_FALLBACK=\"true\"")
                && userdata.contains(
                    "CAUTION_ALLOW_PLAINTEXT_FALLBACK=\"$ALLOW_PLAINTEXT_FALLBACK\"",
                )
                && userdata.contains("\"steve_allow_plaintext_fallback\":true"),
            "explicit plaintext fallback should reach the helper and manifest"
        );

        // Should upload EIF to S3
        assert!(
            userdata.contains("eifs/org/key.eif"),
            "should upload to correct S3 key"
        );

        // Should write status updates
        assert!(
            userdata.contains("set_phase"),
            "should write status to S3"
        );
        assert!(
            userdata.contains("\"completed\""),
            "should write completed status"
        );

        // Should download the helper from S3
        assert!(
            userdata.contains("builds/test-id/remote-build-helper"),
            "should download helper binary"
        );
        assert!(
            userdata.contains("| tee \"$HELPER_LOG\""),
            "should retain the complete helper log"
        );
        assert!(
            userdata.contains(
                "timeout 30 aws s3 cp \"$HELPER_LOG\" \"s3://$S3_BUCKET/$HELPER_LOG_KEY\""
            ),
            "should upload the private helper log on failure"
        );
        assert!(
            userdata.contains("tail -12 \"$HELPER_LOG\"")
                && userdata.contains("tail -c 4096")
                && userdata.contains("tr -d"),
            "public failure detail should be bounded"
        );
        assert!(
            !userdata.contains("/var/log/cloud-init-output.log") && !userdata.contains("tail -80"),
            "cloud-init output must not be returned to the Git client"
        );

        let script = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(script.path(), &userdata).unwrap();
        let syntax = std::process::Command::new("bash")
            .arg("-n")
            .arg(script.path())
            .output()
            .unwrap();
        assert!(
            syntax.status.success(),
            "generated userdata must be valid Bash: {}",
            String::from_utf8_lossy(&syntax.stderr)
        );
    }

    #[test]
    fn test_userdata_uses_resolved_containerfile() {
        let config = BuilderConfig {
            ami_id: "ami-test".to_string(),
            security_group_id: "sg-test".to_string(),
            subnet_id: "subnet-test".to_string(),
            instance_profile: "profile-test".to_string(),
            region: "us-west-2".to_string(),
            timeout_secs: 1200,
            eif_s3_bucket: "test-bucket".to_string(),
            git_hostname: "git.example.com".to_string(),
            additional_instance_tags: Vec::new(),
        };

        let request = BuildRequest {
            org_id: Uuid::new_v4(),
            app_id: Uuid::new_v4(),
            app_name: "test-app".to_string(),
            commit_sha: "abc123".to_string(),
            branch: "main".to_string(),
            source_s3_key: "builds/test/source.tar.gz".to_string(),
            source_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            procfile_content: "run: /app\n".to_string(),
            run_command: Some("/app".to_string()),
            containerfile: "Containerfile".to_string(),
            ports: vec![],
            http_port: None,
            e2e: false,
            e2e_mode: "disabled".to_string(),
            e2e_key_exchange: "X25519".to_string(),
            allow_plaintext_fallback: false,
            domain: None,
            http_upstream_protocol: "http".to_string(),
            framework_commit: TEST_FRAMEWORK_COMMIT.to_string(),
            locksmith: false,
            egress: false,
            e2e_cors_origins: None,
            no_cache: false,
            enclaveos_commit: "abc".to_string(),
            steve_commit: "steve-test".to_string(),
            builder_size: "small".to_string(),
            builder_instance_type: "c5.xlarge".to_string(),
            app_sources: vec![],
        };

        let userdata = generate_builder_userdata(
            Uuid::new_v4(),
            &config,
            &request,
            "eifs/test.eif",
            "builds/test/remote-build-helper",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();

        assert!(userdata.contains("CONTAINERFILE=\"Containerfile\""));
        assert!(userdata.contains(&format!("\"commit\":\"{TEST_FRAMEWORK_COMMIT}\"")));
    }

    #[test]
    fn test_userdata_uses_explicit_custom_containerfile() {
        let config = BuilderConfig {
            ami_id: "ami-test".to_string(),
            security_group_id: "sg-test".to_string(),
            subnet_id: "subnet-test".to_string(),
            instance_profile: "profile-test".to_string(),
            region: "us-west-2".to_string(),
            timeout_secs: 1200,
            eif_s3_bucket: "test-bucket".to_string(),
            git_hostname: "git.example.com".to_string(),
            additional_instance_tags: Vec::new(),
        };

        let request = BuildRequest {
            org_id: Uuid::new_v4(),
            app_id: Uuid::new_v4(),
            app_name: "test-app".to_string(),
            commit_sha: "abc123".to_string(),
            branch: "main".to_string(),
            source_s3_key: "builds/test/source.tar.gz".to_string(),
            source_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            procfile_content: "containerfile: Custom.Containerfile\nrun: /app\n".to_string(),
            run_command: Some("/app".to_string()),
            containerfile: "Custom.Containerfile".to_string(),
            ports: vec![],
            http_port: None,
            e2e: false,
            e2e_mode: "disabled".to_string(),
            e2e_key_exchange: "X25519".to_string(),
            allow_plaintext_fallback: false,
            domain: None,
            http_upstream_protocol: "http".to_string(),
            framework_commit: TEST_FRAMEWORK_COMMIT.to_string(),
            locksmith: false,
            egress: false,
            e2e_cors_origins: None,
            no_cache: false,
            enclaveos_commit: "abc".to_string(),
            steve_commit: "steve-test".to_string(),
            builder_size: "small".to_string(),
            builder_instance_type: "c5.xlarge".to_string(),
            app_sources: vec![],
        };

        let userdata = generate_builder_userdata(
            Uuid::new_v4(),
            &config,
            &request,
            "eifs/test.eif",
            "builds/test/remote-build-helper",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();

        assert!(userdata.contains("CONTAINERFILE=\"Custom.Containerfile\""));
    }

    #[test]
    fn test_userdata_has_no_user_build_command() {
        let config = BuilderConfig {
            ami_id: "ami-test".to_string(),
            security_group_id: "sg-test".to_string(),
            subnet_id: "subnet-test".to_string(),
            instance_profile: "profile-test".to_string(),
            region: "us-west-2".to_string(),
            timeout_secs: 1200,
            eif_s3_bucket: "test-bucket".to_string(),
            git_hostname: "git.example.com".to_string(),
            additional_instance_tags: Vec::new(),
        };
        let request = BuildRequest {
            org_id: Uuid::new_v4(),
            app_id: Uuid::new_v4(),
            app_name: "test-app".to_string(),
            commit_sha: "abc123".to_string(),
            branch: "main".to_string(),
            source_s3_key: "builds/test/source.tar.gz".to_string(),
            source_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            procfile_content: "run: /app\n".to_string(),
            run_command: Some("/app".to_string()),
            containerfile: "Dockerfile".to_string(),
            ports: vec![],
            http_port: None,
            e2e: false,
            e2e_mode: "disabled".to_string(),
            e2e_key_exchange: "X25519".to_string(),
            allow_plaintext_fallback: false,
            domain: None,
            http_upstream_protocol: "http".to_string(),
            framework_commit: TEST_FRAMEWORK_COMMIT.to_string(),
            locksmith: false,
            egress: false,
            e2e_cors_origins: None,
            no_cache: false,
            enclaveos_commit: "abc".to_string(),
            steve_commit: "steve-test".to_string(),
            builder_size: "small".to_string(),
            builder_instance_type: "c5.xlarge".to_string(),
            app_sources: vec![],
        };

        let userdata = generate_builder_userdata(
            Uuid::new_v4(),
            &config,
            &request,
            "eifs/test.eif",
            "builds/test/remote-build-helper",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();

        assert!(
            !userdata.contains("eval \"$BUILD_CMD\""),
            "build command should not be evaluated through eval"
        );
        assert!(
            !userdata.contains("BUILD_CMD"),
            "userdata should not include a user-supplied build command"
        );
    }

    #[test]
    fn test_userdata_rejects_unsafe_containerfile_path() {
        let config = BuilderConfig {
            ami_id: "ami-test".to_string(),
            security_group_id: "sg-test".to_string(),
            subnet_id: "subnet-test".to_string(),
            instance_profile: "profile-test".to_string(),
            region: "us-west-2".to_string(),
            timeout_secs: 1200,
            eif_s3_bucket: "test-bucket".to_string(),
            git_hostname: "git.example.com".to_string(),
            additional_instance_tags: Vec::new(),
        };

        let request = BuildRequest {
            org_id: Uuid::new_v4(),
            app_id: Uuid::new_v4(),
            app_name: "test-app".to_string(),
            commit_sha: "abc123".to_string(),
            branch: "main".to_string(),
            source_s3_key: "builds/test/source.tar.gz".to_string(),
            source_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            procfile_content: "run: /app\n".to_string(),
            run_command: Some("/app".to_string()),
            containerfile: "Dockerfile$(aws)".to_string(),
            ports: vec![],
            http_port: None,
            e2e: false,
            e2e_mode: "disabled".to_string(),
            e2e_key_exchange: "X25519".to_string(),
            allow_plaintext_fallback: false,
            domain: None,
            http_upstream_protocol: "http".to_string(),
            framework_commit: TEST_FRAMEWORK_COMMIT.to_string(),
            locksmith: false,
            egress: false,
            e2e_cors_origins: None,
            no_cache: false,
            enclaveos_commit: "abc".to_string(),
            steve_commit: "steve-test".to_string(),
            builder_size: "small".to_string(),
            builder_instance_type: "c5.xlarge".to_string(),
            app_sources: vec![],
        };

        let err = generate_builder_userdata(
            Uuid::new_v4(),
            &config,
            &request,
            "eifs/test.eif",
            "builds/test/remote-build-helper",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("unsupported character"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_userdata_size_under_16kb_limit() {
        let config = BuilderConfig {
            ami_id: "ami-test".to_string(),
            security_group_id: "sg-test".to_string(),
            subnet_id: "subnet-test".to_string(),
            instance_profile: "profile-test".to_string(),
            region: "us-west-2".to_string(),
            timeout_secs: 1200,
            eif_s3_bucket: "test-bucket".to_string(),
            git_hostname: "git.example.com".to_string(),
            additional_instance_tags: Vec::new(),
        };

        let request = BuildRequest {
            org_id: Uuid::new_v4(),
            app_id: Uuid::new_v4(),
            app_name: "test-app".to_string(),
            commit_sha: "abc123".to_string(),
            branch: "main".to_string(),
            source_s3_key: "builds/test/source.tar.gz".to_string(),
            source_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            procfile_content: "run: /app\n".to_string(),
            run_command: Some("/app".to_string()),
            containerfile: "Dockerfile".to_string(),
            ports: vec![],
            http_port: None,
            e2e: false,
            e2e_mode: "disabled".to_string(),
            e2e_key_exchange: "X25519".to_string(),
            allow_plaintext_fallback: false,
            domain: None,
            http_upstream_protocol: "http".to_string(),
            framework_commit: TEST_FRAMEWORK_COMMIT.to_string(),
            locksmith: false,
            egress: false,
            e2e_cors_origins: None,
            no_cache: false,
            enclaveos_commit: "abc".to_string(),
            steve_commit: "steve-test".to_string(),
            builder_size: "small".to_string(),
            builder_instance_type: "c5.xlarge".to_string(),
            app_sources: vec![],
        };

        let userdata = generate_builder_userdata(
            Uuid::new_v4(),
            &config,
            &request,
            "eifs/test.eif",
            "builds/test/remote-build-helper",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();

        // AWS user-data limit is 16KB (before base64 encoding)
        // base64 expands by ~33%, so raw limit is effectively ~12KB to be safe
        let size = userdata.len();
        assert!(
            size < 16_384,
            "User-data is {} bytes, exceeds 16KB AWS limit. Consider moving templates to S3.",
            size
        );
        // Log the actual size for visibility
        eprintln!(
            "User-data size: {} bytes ({:.1}% of 16KB limit)",
            size,
            size as f64 / 16384.0 * 100.0
        );
    }

    fn make_test_build_request_with_egress(egress: bool) -> BuildRequest {
        BuildRequest {
            org_id: Uuid::new_v4(),
            app_id: Uuid::new_v4(),
            app_name: "test-app".to_string(),
            commit_sha: "abc123".to_string(),
            branch: "main".to_string(),
            source_s3_key: "builds/test/source.tar.gz".to_string(),
            source_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            procfile_content: "run: /app\n".to_string(),
            run_command: Some("/app".to_string()),
            containerfile: "Dockerfile".to_string(),
            ports: vec![],
            http_port: None,
            e2e: false,
            e2e_mode: "disabled".to_string(),
            e2e_key_exchange: "X25519".to_string(),
            allow_plaintext_fallback: false,
            domain: None,
            http_upstream_protocol: "http".to_string(),
            framework_commit: TEST_FRAMEWORK_COMMIT.to_string(),
            locksmith: false,
            egress,
            e2e_cors_origins: None,
            no_cache: false,
            enclaveos_commit: "abc".to_string(),
            steve_commit: "steve-test".to_string(),
            builder_size: "small".to_string(),
            builder_instance_type: "c5.xlarge".to_string(),
            app_sources: vec![],
        }
    }

    #[test]
    fn test_xwing_userdata_carries_suite_to_helper_and_manifest() {
        let config = BuilderConfig {
            ami_id: "ami-test".to_string(),
            security_group_id: "sg-test".to_string(),
            subnet_id: "subnet-test".to_string(),
            instance_profile: "profile-test".to_string(),
            region: "us-west-2".to_string(),
            timeout_secs: 1200,
            eif_s3_bucket: "test-bucket".to_string(),
            git_hostname: "git.example.com".to_string(),
            additional_instance_tags: Vec::new(),
        };
        let mut request = make_test_build_request_with_egress(false);
        request.e2e = true;
        request.e2e_mode = "steve".to_string();
        request.e2e_key_exchange = "XWING-DRAFT10".to_string();

        let userdata = generate_builder_userdata(
            Uuid::new_v4(),
            &config,
            &request,
            "eifs/test.eif",
            "builds/test/remote-build-helper",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();

        assert!(userdata.contains("E2E_MODE=\"steve\""));
        assert!(userdata.contains("KEY_EXCHANGE=\"XWING-DRAFT10\""));
        assert!(userdata.contains("CAUTION_KEY_EXCHANGE=\"$KEY_EXCHANGE\""));
        assert!(userdata.contains("\"steve_key_exchange\":\"XWING-DRAFT10\""));
        assert!(userdata.contains(&format!("\"commit\":\"{TEST_FRAMEWORK_COMMIT}\"")));
    }

    #[test]
    fn test_build_script_sets_caution_egress() {
        let config = BuilderConfig {
            ami_id: "ami-test".to_string(),
            security_group_id: "sg-test".to_string(),
            subnet_id: "subnet-test".to_string(),
            instance_profile: "profile-test".to_string(),
            region: "us-west-2".to_string(),
            timeout_secs: 1200,
            eif_s3_bucket: "test-bucket".to_string(),
            git_hostname: "git.example.com".to_string(),
            additional_instance_tags: Vec::new(),
        };
        let request = make_test_build_request_with_egress(true);
        let script = generate_builder_userdata(
            Uuid::new_v4(),
            &config,
            &request,
            "eifs/test.eif",
            "builds/test/remote-build-helper",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();
        assert!(script.contains("EGRESS=\"true\""));
        assert!(script.contains("CAUTION_EGRESS=\"$EGRESS\""));
    }

    #[test]
    fn test_tls_userdata_pins_platform_commit_in_manifest() {
        let config = BuilderConfig {
            ami_id: "ami-test".to_string(),
            security_group_id: "sg-test".to_string(),
            subnet_id: "subnet-test".to_string(),
            instance_profile: "profile-test".to_string(),
            region: "us-west-2".to_string(),
            timeout_secs: 1200,
            eif_s3_bucket: "test-bucket".to_string(),
            git_hostname: "git.example.com".to_string(),
            additional_instance_tags: Vec::new(),
        };
        let platform_commit = "0123456789abcdef0123456789abcdef01234567";
        let mut request = make_test_build_request_with_egress(true);
        request.e2e_mode = "tls".to_string();
        request.domain = Some("app.example.com".to_string());
        request.http_upstream_protocol = "h2c".to_string();
        request.ports = vec![8080];
        request.http_port = Some(8080);
        request.framework_commit = platform_commit.to_string();

        let userdata = generate_builder_userdata(
            Uuid::new_v4(),
            &config,
            &request,
            "eifs/test.eif",
            "builds/test/remote-build-helper",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();

        assert!(userdata.contains("E2E_MODE=\"tls\""));
        assert!(userdata.contains("DOMAIN=\"app.example.com\""));
        assert!(userdata.contains("HTTP_UPSTREAM_PROTOCOL=\"h2c\""));
        assert!(userdata.contains("CAUTION_HTTP_UPSTREAM_PROTOCOL=\"$HTTP_UPSTREAM_PROTOCOL\""));
        assert!(userdata.contains(&format!(
            "https://codeberg.org/caution/platform/archive/{platform_commit}.tar.gz"
        )));
        assert!(userdata.contains(&format!("\"commit\":\"{platform_commit}\"")));
    }
}
