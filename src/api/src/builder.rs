// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Dedicated EC2 builder instances for EIF builds.
//!
//! Instead of building EIFs inline on the API server, this module launches
//! ephemeral EC2 instances that perform the build, upload the EIF to S3,
//! and signal completion via an S3 status file.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::path::PathBuf;
use uuid::Uuid;

use crate::{
    deployment::{AwsCredentials, ManagedOnPremConfig},
    ec2::{Ec2Client, RunInstancesParams},
    AppliedPricing,
};

const REMOTE_BUILDER_HELPER: &str = "remote-build-helper";
const MANAGED_ONPREM_DEPLOYMENT_TAG_KEY: &str = "caution:deployment-id";

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
                .unwrap_or(1200),
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
    pub build_command: Option<String>,
    pub binary_path: Option<String>,
    pub ports: Vec<u16>,
    pub e2e: bool,
    pub locksmith: bool,
    pub enclaveos_commit: String,
    pub builder_size: String,
    pub builder_instance_type: String,
    pub app_sources: Vec<String>,
}

pub const ACTIVE_BUILD_CONFLICT_MSG: &str =
    "A build is already in progress for this app. Please wait for it to complete.";

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
    procfile_content: &str,
    e2e: bool,
    locksmith: bool,
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
    hasher.update(
        if locksmith {
            "locksmith"
        } else {
            "no-locksmith"
        }
        .as_bytes(),
    );
    format!("{:x}", hasher.finalize())
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

    // 1. Insert pending build row
    let insert_result = sqlx::query(
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
    .execute(db)
    .await;

    match insert_result {
        Ok(_) => {}
        Err(sqlx::Error::Database(db_err))
            if db_err.constraint() == Some("idx_eif_builds_active_app") =>
        {
            bail!(ACTIVE_BUILD_CONFLICT_MSG);
        }
        Err(e) => return Err(e).context("Failed to insert eif_builds row"),
    }

    // 2. Generate user-data and launch EC2 instance
    let helper_artifact =
        upload_remote_builder_helper(s3, &config.eif_s3_bucket, build_id, request.org_id)
            .await
            .context("Failed to stage remote builder helper")?;
    let framework_commit = resolve_framework_commit(enclave_builder::FRAMEWORK_SOURCE).await;
    let user_data = generate_builder_userdata(
        build_id,
        config,
        request,
        &eif_s3_key,
        &helper_artifact.s3_key,
        &helper_artifact.sha256,
        framework_commit,
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

            sqlx::query(
                "UPDATE eif_builds SET status = 'completed', eif_s3_key = $1, eif_sha256 = $2, eif_size_bytes = $3, pcrs = $4, completed_at = NOW()
                 WHERE id = $5"
            )
            .bind(&eif_s3_key)
            .bind(&status.eif_sha256)
            .bind(status.eif_size_bytes)
            .bind(&status.pcrs)
            .bind(build_id)
            .execute(db)
            .await
            .context("Failed to update eif_builds with result")?;

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
#[derive(Debug, serde::Deserialize)]
struct BuildStatus {
    phase: String,
    #[serde(default)]
    eif_sha256: String,
    #[serde(default)]
    eif_size_bytes: i64,
    #[serde(default)]
    pcrs: serde_json::Value,
    #[serde(default)]
    error: Option<String>,
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
                let status: BuildStatus = serde_json::from_slice(&body)
                    .context("Failed to parse status.json")?;

                // Send milestone if phase changed
                if status.phase != last_phase {
                    let msg = match status.phase.as_str() {
                        "starting" => "Builder ready, downloading source...",
                        "docker_built" => "Docker image built, building EIF...",
                        "eif_built" => "EIF built, uploading to S3...",
                        "completed" => "Build complete",
                        "failed" => "Build failed",
                        _ => &status.phase,
                    };
                    let _ = tx
                        .send(Ok(bytes::Bytes::from(format!("STEP:{}\n", msg))))
                        .await;
                    last_phase = status.phase.clone();
                }

                match status.phase.as_str() {
                    "completed" => return Ok(status),
                    "failed" => {
                        let err = status
                            .error
                            .unwrap_or_else(|| "Unknown build error".to_string());
                        bail!("Build failed: {}", err);
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
async fn resolve_framework_commit(framework_source: &str) -> Option<String> {
    let archive_pos = framework_source.find("/archive/")?;
    let base_url = &framework_source[..archive_pos];
    let git_url = format!("{}.git", base_url);
    let after_archive = &framework_source[archive_pos + 9..];
    let ref_name = after_archive
        .trim_end_matches(".tar.gz")
        .trim_end_matches(".tar");
    if ref_name.is_empty() {
        return None;
    }
    enclave_builder::resolve_ref_to_commit(&git_url, ref_name).await
}

fn generate_builder_userdata(
    build_id: Uuid,
    config: &BuilderConfig,
    request: &BuildRequest,
    eif_s3_key: &str,
    helper_s3_key: &str,
    helper_sha256: &str,
    framework_commit: Option<String>,
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

    let build_cmd_raw = request
        .build_command
        .as_deref()
        .unwrap_or("docker build -t app-image .");
    let build_cmd = build_cmd_raw.replace('\'', "'\\''");

    let bootproof_commit = std::env::var("BOOTPROOF_COMMIT")
        .unwrap_or_else(|_| "64dae0628e58b9f898b89f9b7a404b37e2f0ca9f".to_string());
    let steve_commit = std::env::var("STEVE_COMMIT")
        .unwrap_or_else(|_| "ed38a190cd5d7a8f452c854e41d00ec748e172bf".to_string());
    let locksmith_commit = std::env::var("LOCKSMITH_COMMIT")
        .unwrap_or_else(|_| "d16b74c6b3fd1d1006a5b00e4d9e21a4613947a9".to_string());

    let e2e_flag = if request.e2e { "true" } else { "false" };
    let locksmith_flag = if request.locksmith { "true" } else { "false" };

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
            url: enclave_builder::FRAMEWORK_SOURCE.to_string(),
            commit: framework_commit,
        },
        request.binary_path.clone(),
        request.run_command.clone(),
        None,
    );
    manifest.enclaveos_commit = Some(request.enclaveos_commit.clone());
    manifest.bootproof_commit = Some(bootproof_commit);
    if request.e2e {
        manifest.steve_commit = Some(steve_commit);
    }
    if request.locksmith {
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
COMMIT_SHA="{commit_sha}"
ENCLAVEOS_COMMIT="{enclaveos_commit}"
BUILD_CMD='{build_cmd}'
PORTS="{ports_csv}"
E2E="{e2e_flag}"
LOCKSMITH="{locksmith_flag}"

# Install script dependencies
# We won't have status tracking for these, but we also can't build status without these.

dnf install -y jq

# Global state tracking for heartbeat and metadata accumulation
# Phase must be persisted to a file to exist in a subshell
PHASEFILE="$(mktemp build-status.XXXX)"
echo "starting" > $PHASEFILE
TEMPLATEFILE="$(mktemp build-template.XXXX)"
echo "{{}}" > $TEMPLATEFILE

set_phase() {{
    echo "$1" > $PHASEFILE
    heartbeat
}}

set_template() {{
    echo "$1" > $TEMPLATEFILE
    heartbeat
}}

heartbeat() {{
    # PHASEFILE contains a newline, but storing as a variable trims newlines
    phase="$(cat $PHASEFILE)"
    timestamp="$(date -u +%s)"
    s3_url="s3://$S3_BUCKET/$STATUS_KEY"
    cat "$TEMPLATEFILE" | \
        jq -c --arg phase "$phase" --arg timestamp "$timestamp" '.phase = $phase | .timestamp = $timestamp' | \
        aws s3 cp - "$s3_url" --content-type application/json
}}

# Run heartbeat periodically to ensure timestamp is always fresh
(
    while true; do
        heartbeat
        sleep 30
    done
) &

fail() {{
    local msg="$1"
    set_phase "failed"
    set_template $(jq -cn --arg error "$msg" '{{"error": $error}}')
    heartbeat
    exit 1
}}

trap 'fail "Builder script crashed at line $LINENO: $(tail -1 /var/log/cloud-init-output.log 2>/dev/null || echo unknown)"' ERR

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
eval "$BUILD_CMD"
# Re-tag to a known name so we can reference it consistently
BUILT_IMAGE=$(docker images -q --no-trunc | head -1)
docker tag "$BUILT_IMAGE" app-image 2>/dev/null || true
set_phase "docker_built"

# Write manifest for remote-build-helper
cat > /build/manifest.json << 'MANIFEST_EOF'
{manifest_json}
MANIFEST_EOF

echo "Building EIF via remote-build-helper..."
mkdir -p /build/output
CAUTION_IMAGE_REF="app-image" \
CAUTION_MANIFEST_PATH="/build/manifest.json" \
CAUTION_WORK_DIR="/build/remote-helper-work" \
CAUTION_OUTPUT_EIF="/build/output/enclave.eif" \
CAUTION_OUTPUT_PCRS="/build/output/enclave.pcrs" \
CAUTION_PORTS="$PORTS" \
CAUTION_E2E="$E2E" \
CAUTION_LOCKSMITH="$LOCKSMITH" \
/usr/local/bin/remote-build-helper 2>&1

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
        build_cmd = build_cmd,
        ports_csv = ports_csv,
        e2e_flag = e2e_flag,
        locksmith_flag = locksmith_flag,
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
    let rows = match sqlx::query_as::<_, (Uuid, Option<String>, Uuid, Option<Uuid>, Option<String>, Option<chrono::DateTime<chrono::Utc>>)>(
        "SELECT id, builder_instance_id, organization_id, app_id, builder_instance_type, started_at FROM eif_builds
         WHERE status IN ('pending', 'building')
         AND created_at < NOW() - INTERVAL '30 minutes'"
    )
    .fetch_all(db)
    .await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("Failed to query orphaned builds: {}", e);
            return;
        }
    };

    for (build_id, instance_id, org_id, app_id, instance_type, started_at) in rows {
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
            } else if let (Some(ref itype), Some(started)) = (&instance_type, started_at) {
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

            if let Err(e) = ec2.terminate_instances(&[iid.clone()]).await {
                tracing::error!("Failed to terminate orphaned builder {}: {}", iid, e);
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
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- compute_cache_key ---

    #[test]
    fn test_cache_key_deterministic() {
        let key1 = compute_cache_key("abc123", "enclave-v1", "run: /app", false, false);
        let key2 = compute_cache_key("abc123", "enclave-v1", "run: /app", false, false);
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 64); // SHA256 hex
    }

    #[test]
    fn test_cache_key_changes_with_commit() {
        let key1 = compute_cache_key("abc123", "enclave-v1", "run: /app", false, false);
        let key2 = compute_cache_key("def456", "enclave-v1", "run: /app", false, false);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_cache_key_changes_with_enclaveos() {
        let key1 = compute_cache_key("abc123", "enclave-v1", "run: /app", false, false);
        let key2 = compute_cache_key("abc123", "enclave-v2", "run: /app", false, false);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_cache_key_changes_with_procfile() {
        let key1 = compute_cache_key("abc123", "enclave-v1", "run: /app", false, false);
        let key2 = compute_cache_key("abc123", "enclave-v1", "run: /other", false, false);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_cache_key_changes_with_e2e() {
        let key1 = compute_cache_key("abc123", "enclave-v1", "run: /app", false, false);
        let key2 = compute_cache_key("abc123", "enclave-v1", "run: /app", true, false);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_cache_key_changes_with_locksmith() {
        let key1 = compute_cache_key("abc123", "enclave-v1", "run: /app", false, false);
        let key2 = compute_cache_key("abc123", "enclave-v1", "run: /app", false, true);
        assert_ne!(key1, key2);
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
            build_command: Some("docker build -t app-image .".to_string()),
            binary_path: None,
            ports: vec![],
            e2e: false,
            locksmith: false,
            enclaveos_commit: "enclave-abc".to_string(),
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
            None,
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

        // Should contain docker build
        assert!(
            userdata.contains("docker build -t app-image"),
            "should build docker image"
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

        // Should upload EIF to S3
        assert!(
            userdata.contains("eifs/org/key.eif"),
            "should upload to correct S3 key"
        );

        // Should write status updates
        assert!(
            userdata.contains("write_status"),
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
    }

    #[test]
    fn test_userdata_preserves_resolved_containerfile_build_command() {
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
            build_command: Some("docker build -f Containerfile .".to_string()),
            binary_path: None,
            ports: vec![],
            e2e: false,
            locksmith: false,
            enclaveos_commit: "abc".to_string(),
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
            None,
        )
        .unwrap();

        assert!(
            userdata.contains("BUILD_CMD='docker build -f Containerfile .'"),
            "should preserve the resolved Containerfile build command verbatim"
        );
    }

    #[test]
    fn test_userdata_preserves_explicit_custom_containerfile_build_command() {
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
            build_command: Some("docker build -f Custom.Containerfile .".to_string()),
            binary_path: None,
            ports: vec![],
            e2e: false,
            locksmith: false,
            enclaveos_commit: "abc".to_string(),
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
            None,
        )
        .unwrap();

        assert!(
            userdata.contains("BUILD_CMD='docker build -f Custom.Containerfile .'"),
            "should preserve the explicit custom containerfile build command verbatim"
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
            build_command: None,
            binary_path: None,
            ports: vec![],
            e2e: false,
            locksmith: false,
            enclaveos_commit: "abc".to_string(),
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
            None,
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
}
