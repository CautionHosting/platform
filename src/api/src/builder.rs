// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Dedicated EC2 builder instances for EIF builds.
//!
//! Instead of building EIFs inline on the API server, this module launches
//! ephemeral EC2 instances that perform the build, upload the EIF to S3,
//! and signal completion via an S3 status file.

use anyhow::{Context, Result, bail};
use sha2::{Sha256, Digest};
use sqlx::PgPool;
use uuid::Uuid;

use crate::ec2::{Ec2Client, RunInstancesParams};

const CONTAINERFILE_EIF_TEMPLATE: &str = include_str!("../../enclave-builder/templates/Containerfile.eif");
const RUN_SH_TEMPLATE: &str = include_str!("../../enclave-builder/templates/run.sh.template");

/// Specification for a builder instance size, loaded from config.json.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct BuilderSizeSpec {
    pub id: String,
    pub label: String,
    pub instance_type: String,
    pub vcpus: u32,
    pub ram_gb: u32,
}

fn default_max_resources() -> u32 { 10 }

/// Platform configuration loaded from config.json.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct BuilderSizesConfig {
    pub builder_sizes: Vec<BuilderSizeSpec>,
    #[serde(default = "default_max_resources")]
    pub max_resources_per_org: u32,
}

impl BuilderSizesConfig {
    pub fn load() -> Result<Self> {
        let contents = std::fs::read_to_string("config.json")
            .context("config.json not found. Copy config.json.example to config.json to configure.")?;
        let config: Self = serde_json::from_str(&contents)
            .context("Failed to parse config.json")?;
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
                self.builder_sizes.iter()
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
    pub timeout_secs: u64,
    pub eif_s3_bucket: String,
    pub git_hostname: String,
}

impl BuilderConfig {
    /// Load from environment variables. Returns None if BUILDER_ENABLED is not set to "true".
    pub fn from_env() -> Option<Self> {
        let enabled = std::env::var("BUILDER_ENABLED")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        if !enabled {
            return None;
        }

        Some(Self {
            ami_id: std::env::var("BUILDER_AMI_ID")
                .expect("BUILDER_AMI_ID required when BUILDER_ENABLED=true"),
            security_group_id: std::env::var("BUILDER_SECURITY_GROUP_ID")
                .expect("BUILDER_SECURITY_GROUP_ID required when BUILDER_ENABLED=true"),
            subnet_id: std::env::var("BUILDER_SUBNET_ID")
                .expect("BUILDER_SUBNET_ID required when BUILDER_ENABLED=true"),
            instance_profile: std::env::var("BUILDER_INSTANCE_PROFILE")
                .expect("BUILDER_INSTANCE_PROFILE required when BUILDER_ENABLED=true"),
            timeout_secs: std::env::var("BUILDER_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1200),
            eif_s3_bucket: std::env::var("EIF_S3_BUCKET")
                .unwrap_or_else(|_| {
                    let account = std::env::var("AWS_ACCOUNT_ID").unwrap_or_default();
                    format!("caution-eif-storage-{}", account)
                }),
            git_hostname: std::env::var("GIT_HOSTNAME").unwrap_or_default(),
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

/// Input parameters for a build.
pub struct BuildRequest {
    pub org_id: Uuid,
    pub app_name: String,
    pub commit_sha: String,
    pub branch: String,
    /// S3 key where the source archive was uploaded (e.g., builds/{build_id}/source.tar.gz)
    pub source_s3_key: String,
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
    hasher.update(if locksmith { "locksmith" } else { "no-locksmith" }.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Check if a completed build exists in the cache for this org + cache_key.
pub async fn check_build_cache(
    db: &PgPool,
    org_id: Uuid,
    cache_key: &str,
) -> Result<Option<BuildResult>> {
    let row = sqlx::query_as::<_, (String, String, i64, serde_json::Value)>(
        "SELECT eif_s3_key, eif_sha256, eif_size_bytes, pcrs
         FROM eif_builds
         WHERE organization_id = $1 AND cache_key = $2 AND status = 'completed'
         LIMIT 1"
    )
    .bind(org_id)
    .bind(cache_key)
    .fetch_optional(db)
    .await
    .context("Failed to query eif_builds cache")?;

    Ok(row.map(|(eif_s3_key, eif_sha256, eif_size_bytes, pcrs)| BuildResult {
        eif_s3_key,
        eif_sha256,
        eif_size_bytes,
        pcrs,
    }))
}

/// Archive the source at a given commit and upload to S3 for the builder.
/// Returns the S3 key of the uploaded archive.
pub async fn upload_source_archive(
    s3: &aws_sdk_s3::Client,
    bucket: &str,
    git_dir: &str,
    commit_sha: &str,
    build_id: Uuid,
) -> Result<String> {
    let s3_key = format!("builds/{}/source.tar.gz", build_id);

    // git archive produces a tar.gz of the repo at the given commit
    let output = tokio::process::Command::new("git")
        .args(&["--git-dir", git_dir, "archive", "--format=tar.gz", commit_sha])
        .output()
        .await
        .context("Failed to run git archive")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git archive failed: {}", stderr);
    }

    s3.put_object()
        .bucket(bucket)
        .key(&s3_key)
        .body(aws_sdk_s3::primitives::ByteStream::from(output.stdout))
        .send()
        .await
        .context("Failed to upload source archive to S3")?;

    tracing::info!("Source archive uploaded to s3://{}/{}", bucket, s3_key);
    Ok(s3_key)
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
    sqlx::query(
        "INSERT INTO eif_builds (id, organization_id, user_id, commit_sha, procfile_hash, cache_key, builder_instance_type, status, started_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', NOW())"
    )
    .bind(build_id)
    .bind(request.org_id)
    .bind(user_id)
    .bind(&request.commit_sha)
    .bind(&procfile_hash)
    .bind(cache_key)
    .bind(instance_type)
    .execute(db)
    .await
    .context("Failed to insert eif_builds row")?;

    // 2. Generate user-data and launch EC2 instance
    let user_data = generate_builder_userdata(build_id, config, request, &eif_s3_key)?;
    let instance_id = match ec2.run_instances(&RunInstancesParams {
        image_id: config.ami_id.clone(),
        instance_type: instance_type.to_string(),
        user_data,
        iam_instance_profile: config.instance_profile.clone(),
        security_group_ids: vec![config.security_group_id.clone()],
        subnet_id: config.subnet_id.clone(),
        tags: vec![
            ("Name".to_string(), format!("caution-builder-{}", &build_id.to_string()[..8])),
            ("ManagedBy".to_string(), "caution-builder".to_string()),
            ("BuildId".to_string(), build_id.to_string()),
        ],
    }).await {
        Ok(id) => id,
        Err(e) => {
            mark_build_failed(db, build_id, &format!("Failed to launch builder: {}", e)).await;
            bail!("Failed to launch builder instance: {}", e);
        }
    };

    tracing::info!("Builder instance {} launched for build {}", instance_id, build_id);

    // Update build row with instance ID
    let _ = sqlx::query("UPDATE eif_builds SET builder_instance_id = $1, status = 'building' WHERE id = $2")
        .bind(&instance_id)
        .bind(build_id)
        .execute(db)
        .await;

    // Register builder with metering so the collection loop deducts credits in real-time
    if let Err(e) = sqlx::query(
        "INSERT INTO tracked_resources (resource_id, user_id, provider, instance_type, region, metadata, status, started_at, last_billed_at)
         VALUES ($1, $2, 'aws', $3, $4, $5, 'running', NOW(), NOW())
         ON CONFLICT (resource_id) DO UPDATE SET status = 'running', started_at = NOW(), last_billed_at = NOW()"
    )
    .bind(&instance_id)
    .bind(user_id)
    .bind(instance_type)
    .bind(std::env::var("AWS_REGION").unwrap_or_else(|_| "us-west-2".to_string()))
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
    ).await;

    // 4. Stop metering for the builder instance
    if let Err(e) = sqlx::query(
        "UPDATE tracked_resources SET status = 'stopped', stopped_at = NOW() WHERE resource_id = $1 AND status = 'running'"
    )
    .bind(&instance_id)
    .execute(db)
    .await {
        tracing::error!("Failed to stop metering for builder {}: {}", instance_id, e);
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
                tracing::warn!("Failed to terminate builder {} (attempt {}): {}, retrying...", instance_id, terminate_attempts, e);
                tokio::time::sleep(std::time::Duration::from_secs(2_u64.pow(terminate_attempts))).await;
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
            // The untrack call above triggers a final usage collection.

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

        match s3.get_object()
            .bucket(bucket)
            .key(status_key)
            .send()
            .await
        {
            Ok(output) => {
                let body = output.body.collect().await
                    .context("Failed to read status body")?;
                let status: BuildStatus = serde_json::from_slice(&body.into_bytes())
                    .context("Failed to parse status.json")?;

                // Send milestone if phase changed
                if status.phase != last_phase {
                    let msg = match status.phase.as_str() {
                        "starting" => "Builder instance starting...",
                        "docker_built" => "Docker image built, building EIF...",
                        "eif_built" => "EIF built, uploading to S3...",
                        "completed" => "Build complete",
                        "failed" => "Build failed",
                        _ => &status.phase,
                    };
                    let _ = tx.send(Ok(bytes::Bytes::from(format!("data: {}\n\n", msg)))).await;
                    last_phase = status.phase.clone();
                }

                match status.phase.as_str() {
                    "completed" => return Ok(status),
                    "failed" => {
                        let err = status.error.unwrap_or_else(|| "Unknown build error".to_string());
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

/// Process template blocks — strips `# {BLOCK` / `# }BLOCK` sections
/// unless the block name is in `enabled_blocks`.
/// Same logic as `enclave-builder/src/build.rs::process_template_blocks`.
fn process_template_blocks(content: &str, enabled_blocks: &[&str]) -> String {
    let mut result = Vec::new();
    let mut skip = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(block_name) = trimmed.strip_prefix("# {") {
            let block_name = block_name.trim();
            if !enabled_blocks.contains(&block_name) {
                skip = true;
            }
            continue;
        }
        if trimmed.starts_with("# }") {
            skip = false;
            continue;
        }
        if !skip {
            result.push(line);
        }
    }
    let mut output = result.join("\n");
    if content.ends_with('\n') {
        output.push('\n');
    }
    output
}

/// Render the Containerfile.eif and run.sh templates with the build parameters.
fn render_templates(request: &BuildRequest) -> anyhow::Result<(String, String)> {
    // Validate reserved ports
    let reserved: &[(u16, &str)] = &[
        (8080, "internal enclave services"),
        (8081, "internal enclave services"),
        (8082, "bootproofd"),
        (8084, "locksmith"),
    ];
    for &(port, service) in reserved {
        if request.ports.contains(&port) {
            anyhow::bail!("Port {} is reserved for {}", port, service);
        }
    }

    let mut enabled_blocks: Vec<&str> = vec![];
    if request.e2e { enabled_blocks.push("STEVE"); }
    if request.locksmith { enabled_blocks.push("LOCKSMITH"); }

    let bootproof_commit = std::env::var("BOOTPROOF_COMMIT")
        .unwrap_or_else(|_| "64dae0628e58b9f898b89f9b7a404b37e2f0ca9f".to_string());
    let steve_commit = std::env::var("STEVE_COMMIT")
        .unwrap_or_else(|_| "ed38a190cd5d7a8f452c854e41d00ec748e172bf".to_string());
    let locksmith_commit = std::env::var("LOCKSMITH_COMMIT")
        .unwrap_or_else(|_| "d16b74c6b3fd1d1006a5b00e4d9e21a4613947a9".to_string());

    // Render Containerfile.eif
    let containerfile = process_template_blocks(CONTAINERFILE_EIF_TEMPLATE, &enabled_blocks)
        .replace("{{BOOTPROOF_COMMIT}}", &bootproof_commit)
        .replace("{{STEVE_COMMIT}}", &steve_commit)
        .replace("{{LOCKSMITH_COMMIT}}", &locksmith_commit);

    // Render run.sh
    let run_cmd = request.run_command.as_deref().unwrap_or("");
    let user_cmd = if run_cmd.is_empty() {
        "echo \"ERROR: No run command specified\"\nexit 1".to_string()
    } else {
        let escaped = run_cmd.replace('\'', "'\\''");
        format!("exec sh -c '{}'", escaped)
    };

    let custom_port_proxies: String = request.ports.iter()
        .filter(|&&p| p != 8080 && p != 8081 && p != 8082 && !(request.locksmith && p == 8084))
        .map(|p| format!("/bin/socat VSOCK-LISTEN:{p},reuseaddr,fork TCP:localhost:{p} &"))
        .collect::<Vec<_>>()
        .join("\n");

    let custom_port_section = if custom_port_proxies.is_empty() {
        String::new()
    } else {
        format!("\necho \"Starting custom port proxies...\"\n{}\n", custom_port_proxies)
    };

    let run_sh = process_template_blocks(RUN_SH_TEMPLATE, &enabled_blocks)
        .replace("{{USER_CMD}}", &user_cmd)
        .replace("{{CUSTOM_PORT_SECTION}}", &custom_port_section);

    Ok((containerfile, run_sh))
}

/// Generate the user-data shell script for the builder instance.
fn generate_builder_userdata(
    build_id: Uuid,
    config: &BuilderConfig,
    request: &BuildRequest,
    eif_s3_key: &str,
) -> anyhow::Result<String> {
    let status_key = format!("builds/{}/status.json", build_id);
    let bucket = &config.eif_s3_bucket;
    let source_s3_key = &request.source_s3_key;

    let build_cmd_raw = request.build_command.as_deref().unwrap_or("docker build -t app-image .");
    let build_cmd = build_cmd_raw.replace('\'', "'\\''");
    let binary_flag = request.binary_path.as_deref().unwrap_or("");

    // Render the enclave templates at generation time
    let (containerfile_eif, run_sh) = render_templates(request)?;

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
    let manifest = enclave_builder::EnclaveManifest::new(
        app_source,
        enclave_builder::EnclaveSource::GitArchive {
            urls: vec![format!("https://git.distrust.co/public/enclaveos/archive/{}.tar.gz", request.enclaveos_commit)],
            commit: Some(request.enclaveos_commit.clone()),
        },
        enclave_builder::FrameworkSource::GitArchive {
            url: enclave_builder::FRAMEWORK_SOURCE.to_string(),
            commit: None,
        },
        request.binary_path.clone(),
        request.run_command.clone(),
        None,
    );
    let manifest_json = serde_json::to_string(&manifest).expect("manifest serialization cannot fail");

    Ok(format!(r##"#!/bin/bash
set -euo pipefail

# --- Caution Dedicated Builder ---
BUILD_ID="{build_id}"
S3_BUCKET="{bucket}"
STATUS_KEY="{status_key}"
EIF_S3_KEY="{eif_s3_key}"
SOURCE_S3_KEY="{source_s3_key}"
COMMIT_SHA="{commit_sha}"
ENCLAVEOS_COMMIT="{enclaveos_commit}"
BUILD_CMD='{build_cmd}'
BINARY_PATH="{binary_flag}"
E2E="{e2e_flag}"
LOCKSMITH="{locksmith_flag}"

write_status() {{
    local phase="$1"
    shift
    local extra=""
    if [ $# -gt 0 ]; then extra=",$@"; fi
    echo '{{"phase":"'"$phase"'"'"$extra"'}}' | aws s3 cp - "s3://$S3_BUCKET/$STATUS_KEY" --content-type application/json
}}

fail() {{
    local msg="$1"
    echo '{{"phase":"failed","error":"'"$(echo "$msg" | sed 's/"/\\"/g')"'"}}' | aws s3 cp - "s3://$S3_BUCKET/$STATUS_KEY" --content-type application/json
    exit 1
}}

trap 'fail "Builder script crashed at line $LINENO: $(tail -1 /var/log/cloud-init-output.log 2>/dev/null || echo unknown)"' ERR

# Install dependencies
echo "Installing Docker..."
dnf install -y docker
systemctl start docker
systemctl enable docker

write_status "starting"

# Download source archive from S3
echo "Downloading source archive..."
mkdir -p /build/repo
aws s3 cp "s3://$S3_BUCKET/$SOURCE_S3_KEY" /build/source.tar.gz
tar -xzf /build/source.tar.gz -C /build/repo

# Build Docker image
echo "Building Docker image..."
cd /build/repo
eval "$BUILD_CMD"
# Re-tag to a known name so we can reference it consistently
BUILT_IMAGE=$(docker images -q --no-trunc | head -1)
docker tag "$BUILT_IMAGE" app-image 2>/dev/null || true
write_status "docker_built"

# Extract user filesystem
echo "Extracting user filesystem..."
mkdir -p /build/user-fs
CONTAINER_ID=$(docker create app-image)
docker export "$CONTAINER_ID" | tar -xf - -C /build/user-fs
docker rm "$CONTAINER_ID"

if [ -n "$BINARY_PATH" ] && [ -f "/build/user-fs$BINARY_PATH" ]; then
    echo "Binary-only mode: extracting $BINARY_PATH"
    mkdir -p /build/binary-fs/$(dirname "$BINARY_PATH")
    cp "/build/user-fs$BINARY_PATH" "/build/binary-fs$BINARY_PATH"
    if [ -f /build/user-fs/etc/ssl/certs/ca-certificates.crt ]; then
        mkdir -p /build/binary-fs/etc/ssl/certs
        cp /build/user-fs/etc/ssl/certs/ca-certificates.crt /build/binary-fs/etc/ssl/certs/
    fi
    rm -rf /build/user-fs
    mv /build/binary-fs /build/user-fs
fi

# Download enclave OS source
echo "Downloading enclave OS source..."
mkdir -p /build/enclave-src
curl -fsSL "https://git.distrust.co/public/enclaveos/archive/$ENCLAVEOS_COMMIT.tar.gz" | tar -xzf - -C /build/enclave-src --strip-components=1

# Stage EIF build
echo "Staging EIF build..."
mkdir -p /build/eif-stage/app /build/eif-stage/enclave /build/eif-stage/output

cp -r /build/user-fs/* /build/eif-stage/app/ 2>/dev/null || true
cp -r /build/enclave-src/* /build/eif-stage/enclave/ 2>/dev/null || true

# Write run.sh (rendered from template)
cat > /build/eif-stage/run.sh << 'RUNSH_EOF'
{run_sh}
RUNSH_EOF
chmod +x /build/eif-stage/run.sh

# Write Containerfile.eif (rendered from template)
cat > /build/eif-stage/Containerfile.eif << 'CONTAINERFILE_EOF'
{containerfile_eif}
CONTAINERFILE_EOF

# Write manifest (must match EnclaveManifest struct for caution verify)
cat > /build/eif-stage/manifest.json << 'MANIFEST_EOF'
{manifest_json}
MANIFEST_EOF

# Build EIF
echo "Building EIF..."
cd /build/eif-stage
DOCKER_BUILDKIT=1 SOURCE_DATE_EPOCH=1 docker build \
    --progress=plain \
    --target output \
    --output type=local,rewrite-timestamp=true,dest=/build/eif-stage/output \
    -f Containerfile.eif \
    . 2>&1

EIF_PATH="/build/eif-stage/output/enclave.eif"
PCRS_PATH="/build/eif-stage/output/enclave.pcrs"

if [ ! -f "$EIF_PATH" ]; then
    fail "EIF file not found after build"
fi

write_status "eif_built"

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

write_status "completed" '"eif_sha256":"'"$EIF_SHA256"'","eif_size_bytes":'"$EIF_SIZE"',"pcrs":'"$PCRS_JSON"

echo "Build complete: $EIF_SHA256 ($EIF_SIZE bytes)"
"##,
        build_id = build_id,
        bucket = bucket,
        status_key = status_key,
        eif_s3_key = eif_s3_key,
        source_s3_key = source_s3_key,
        commit_sha = request.commit_sha,
        enclaveos_commit = request.enclaveos_commit,
        build_cmd = build_cmd,
        binary_flag = binary_flag,
        e2e_flag = e2e_flag,
        locksmith_flag = locksmith_flag,
        run_sh = run_sh,
        containerfile_eif = containerfile_eif,
    ))
}

/// Reap builder instances that have been running for too long.
/// Called periodically from a background task.
/// Bill a user for builder instance time. Used as a fallback by the orphan reaper
/// when real-time metering via tracked_resources was not active for the build.
async fn bill_builder_usage(
    db: &PgPool,
    build_id: Uuid,
    user_id: Uuid,
    instance_type: &str,
    started_at: chrono::DateTime<chrono::Utc>,
    hourly_rate_usd: f64,
) {
    let duration_secs = (chrono::Utc::now() - started_at).num_seconds().max(0) as f64;
    let hours = duration_secs / 3600.0;
    let billable_hours = hours.max(1.0 / 60.0); // minimum 1 minute charge
    let cost_usd = billable_hours * hourly_rate_usd;
    let cost_cents = (cost_usd * 100.0).round() as i64;

    if cost_cents <= 0 {
        return;
    }

    if let Err(e) = async {
        let mut tx = db.begin().await?;

        sqlx::query(
            "INSERT INTO usage_records (user_id, resource_id, provider, resource_type, quantity, unit, cost_usd, recorded_at, metadata)
             VALUES ($1, $2, 'aws', 'builder', $3, 'hours', $4, NOW(), $5)"
        )
        .bind(user_id)
        .bind(build_id)
        .bind(billable_hours)
        .bind(cost_usd)
        .bind(serde_json::json!({
            "instance_type": instance_type,
            "duration_secs": duration_secs as i64,
        }))
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE wallet_balance SET balance_cents = balance_cents - $1 WHERE user_id = $2"
        )
        .bind(cost_cents)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        let new_balance: i64 = sqlx::query_scalar(
            "SELECT COALESCE(balance_cents, 0) FROM wallet_balance WHERE user_id = $1"
        )
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO credit_ledger (user_id, delta_cents, balance_after, entry_type, description)
             VALUES ($1, $2, $3, 'realtime_usage', $4)"
        )
        .bind(user_id)
        .bind(-cost_cents)
        .bind(new_balance)
        .bind(format!("Builder: {} ({:.1} min)", instance_type, duration_secs / 60.0))
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok::<_, anyhow::Error>(())
    }.await {
        tracing::error!("Failed to bill for build {}: {}", build_id, e);
        return;
    }

    tracing::info!(
        "Builder billing: user={}, build={}, type={}, {:.1}min, ${:.4} ({}c deducted)",
        user_id, build_id, instance_type, duration_secs / 60.0, cost_usd, cost_cents
    );
}

pub async fn reap_orphaned_builders(db: &PgPool, ec2: &Ec2Client, instance_hourly_rate: impl Fn(&str) -> f64) {
    let rows = match sqlx::query_as::<_, (Uuid, Option<String>, Option<Uuid>, Option<String>, Option<chrono::DateTime<chrono::Utc>>)>(
        "SELECT id, builder_instance_id, user_id, builder_instance_type, started_at FROM eif_builds
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

    for (build_id, instance_id, user_id, instance_type, started_at) in rows {
        tracing::warn!("Reaping orphaned build {} (instance: {:?})", build_id, instance_id);

        if let Some(ref iid) = instance_id {
            // Check if this builder was tracked by the metering collection loop
            let was_tracked: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM tracked_resources WHERE resource_id = $1)"
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
            } else if let (Some(uid), Some(ref itype), Some(started)) = (user_id, &instance_type, started_at) {
                // Fallback: metering tracking failed, bill directly for the full duration
                let hourly_rate = instance_hourly_rate(itype);
                bill_builder_usage(db, build_id, uid, itype, started, hourly_rate).await;
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

    // --- process_template_blocks ---

    #[test]
    fn test_process_blocks_strips_disabled() {
        let input = "line1\n# {STEVE\nsteve line\n# }STEVE\nline2\n";
        let result = process_template_blocks(input, &[]);
        assert_eq!(result, "line1\nline2\n");
    }

    #[test]
    fn test_process_blocks_keeps_enabled() {
        let input = "line1\n# {STEVE\nsteve line\n# }STEVE\nline2\n";
        let result = process_template_blocks(input, &["STEVE"]);
        assert_eq!(result, "line1\nsteve line\nline2\n");
    }

    #[test]
    fn test_process_blocks_no_blocks() {
        let input = "line1\nline2\n";
        let result = process_template_blocks(input, &[]);
        assert_eq!(result, "line1\nline2\n");
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

    // --- render_templates ---

    #[test]
    fn test_render_templates_produces_run_sh_with_user_cmd() {
        let request = BuildRequest {
            org_id: Uuid::new_v4(),
            app_name: "test-app".to_string(),
            commit_sha: "abc123".to_string(),
            branch: "main".to_string(),
            source_s3_key: "builds/test/source.tar.gz".to_string(),
            procfile_content: "run: /app\n".to_string(),
            run_command: Some("/usr/bin/myapp --port 8080".to_string()),
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

        let (containerfile, run_sh) = render_templates(&request).unwrap();

        // run.sh should contain the user command
        assert!(run_sh.contains("/usr/bin/myapp --port 8080"), "run.sh should contain user command");
        // run.sh should NOT contain STEVE when e2e=false
        assert!(!run_sh.contains("steve"), "run.sh should not contain steve when e2e=false");
        // Containerfile should contain eif_build
        assert!(containerfile.contains("eif_build"), "Containerfile should contain eif_build command");
        // Containerfile should NOT contain STEVE blocks
        assert!(!containerfile.contains("steve-builder"), "Containerfile should not contain steve-builder when e2e=false");
    }

    #[test]
    fn test_render_templates_e2e_includes_steve() {
        let request = BuildRequest {
            org_id: Uuid::new_v4(),
            app_name: "test-app".to_string(),
            commit_sha: "abc123".to_string(),
            branch: "main".to_string(),
            source_s3_key: "builds/test/source.tar.gz".to_string(),
            procfile_content: "run: /app\n".to_string(),
            run_command: Some("/app".to_string()),
            build_command: None,
            binary_path: None,
            ports: vec![],
            e2e: true,
            locksmith: false,
            enclaveos_commit: "abc".to_string(),
            builder_size: "small".to_string(),
            builder_instance_type: "c5.xlarge".to_string(),
            app_sources: vec![],
        };

        let (containerfile, run_sh) = render_templates(&request).unwrap();

        assert!(containerfile.contains("steve-builder"), "Containerfile should contain steve-builder when e2e=true");
        assert!(run_sh.contains("steve"), "run.sh should contain steve when e2e=true");
    }

    #[test]
    fn test_render_templates_locksmith_includes_locksmith() {
        let request = BuildRequest {
            org_id: Uuid::new_v4(),
            app_name: "test-app".to_string(),
            commit_sha: "abc123".to_string(),
            branch: "main".to_string(),
            source_s3_key: "builds/test/source.tar.gz".to_string(),
            procfile_content: "run: /app\n".to_string(),
            run_command: Some("/app".to_string()),
            build_command: None,
            binary_path: None,
            ports: vec![],
            e2e: false,
            locksmith: true,
            enclaveos_commit: "abc".to_string(),
            builder_size: "small".to_string(),
            builder_instance_type: "c5.xlarge".to_string(),
            app_sources: vec![],
        };

        let (containerfile, run_sh) = render_templates(&request).unwrap();

        assert!(containerfile.contains("locksmith-builder"), "Containerfile should contain locksmith-builder when locksmith=true");
        assert!(run_sh.contains("locksmithd"), "run.sh should contain locksmithd when locksmith=true");
    }

    #[test]
    fn test_render_templates_no_locksmith_by_default() {
        let request = BuildRequest {
            org_id: Uuid::new_v4(),
            app_name: "test-app".to_string(),
            commit_sha: "abc123".to_string(),
            branch: "main".to_string(),
            source_s3_key: "builds/test/source.tar.gz".to_string(),
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

        let (containerfile, run_sh) = render_templates(&request).unwrap();

        assert!(!containerfile.contains("locksmith-builder"), "Containerfile should not contain locksmith-builder when locksmith=false");
        assert!(!run_sh.contains("locksmithd"), "run.sh should not contain locksmithd when locksmith=false");
    }

    #[test]
    fn test_render_templates_custom_ports() {
        let request = BuildRequest {
            org_id: Uuid::new_v4(),
            app_name: "test-app".to_string(),
            commit_sha: "abc123".to_string(),
            branch: "main".to_string(),
            source_s3_key: "builds/test/source.tar.gz".to_string(),
            procfile_content: "run: /app\n".to_string(),
            run_command: Some("/app".to_string()),
            build_command: None,
            binary_path: None,
            ports: vec![8083, 9090, 3000],
            e2e: false,
            locksmith: false,
            enclaveos_commit: "abc".to_string(),
            builder_size: "small".to_string(),
            builder_instance_type: "c5.xlarge".to_string(),
            app_sources: vec![],
        };

        let (_containerfile, run_sh) = render_templates(&request).unwrap();

        // 8083, 9090, and 3000 should appear as custom port proxies
        assert!(run_sh.contains("VSOCK-LISTEN:8083"), "should have proxy for port 8083");
        assert!(run_sh.contains("VSOCK-LISTEN:9090"), "should have proxy for port 9090");
        assert!(run_sh.contains("VSOCK-LISTEN:3000"), "should have proxy for port 3000");
    }

    // --- generate_builder_userdata ---

    #[test]
    fn test_userdata_contains_required_sections() {
        let config = BuilderConfig {
            ami_id: "ami-test".to_string(),
            security_group_id: "sg-test".to_string(),
            subnet_id: "subnet-test".to_string(),
            instance_profile: "profile-test".to_string(),
            timeout_secs: 1200,
            eif_s3_bucket: "test-bucket".to_string(),
            git_hostname: "git.example.com".to_string(),
        };

        let request = BuildRequest {
            org_id: Uuid::new_v4(),
            app_name: "test-app".to_string(),
            commit_sha: "abc123def456".to_string(),
            branch: "main".to_string(),
            source_s3_key: "builds/test-id/source.tar.gz".to_string(),
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
        let userdata = generate_builder_userdata(build_id, &config, &request, "eifs/org/key.eif").unwrap();

        // Should be a valid bash script
        assert!(userdata.starts_with("#!/bin/bash"), "should start with shebang");

        // Should contain S3 bucket reference
        assert!(userdata.contains("test-bucket"), "should reference S3 bucket");

        // Should download source from S3, not git clone
        assert!(userdata.contains("aws s3 cp"), "should download from S3");
        assert!(userdata.contains("source.tar.gz"), "should reference source archive");
        // User source comes from S3, not git clone (Containerfile.eif still clones bootproof/steve deps)
        assert!(!userdata.contains("git clone \"$GIT_URL\""), "should not git clone user repo");

        // Should contain docker build
        assert!(userdata.contains("docker build -t app-image"), "should build docker image");

        // Should contain EIF build
        assert!(userdata.contains("Containerfile.eif"), "should build EIF via Containerfile");
        assert!(userdata.contains("docker build"), "should use docker build for EIF");

        // Should upload EIF to S3
        assert!(userdata.contains("eifs/org/key.eif"), "should upload to correct S3 key");

        // Should write status updates
        assert!(userdata.contains("write_status"), "should write status to S3");
        assert!(userdata.contains("\"completed\""), "should write completed status");

        // Should contain the rendered Containerfile.eif template (embedded)
        assert!(userdata.contains("eif_build"), "should contain embedded Containerfile.eif with eif_build command");

        // Should contain rendered run.sh
        assert!(userdata.contains("Caution Enclave Startup"), "should contain embedded run.sh");
    }

    #[test]
    fn test_userdata_size_under_16kb_limit() {
        let config = BuilderConfig {
            ami_id: "ami-test".to_string(),
            security_group_id: "sg-test".to_string(),
            subnet_id: "subnet-test".to_string(),
            instance_profile: "profile-test".to_string(),
            timeout_secs: 1200,
            eif_s3_bucket: "test-bucket".to_string(),
            git_hostname: "git.example.com".to_string(),
        };

        let request = BuildRequest {
            org_id: Uuid::new_v4(),
            app_name: "test-app".to_string(),
            commit_sha: "abc123".to_string(),
            branch: "main".to_string(),
            source_s3_key: "builds/test/source.tar.gz".to_string(),
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

        let userdata = generate_builder_userdata(Uuid::new_v4(), &config, &request, "eifs/test.eif").unwrap();

        // AWS user-data limit is 16KB (before base64 encoding)
        // base64 expands by ~33%, so raw limit is effectively ~12KB to be safe
        let size = userdata.len();
        assert!(
            size < 16_384,
            "User-data is {} bytes, exceeds 16KB AWS limit. Consider moving templates to S3.",
            size
        );
        // Log the actual size for visibility
        eprintln!("User-data size: {} bytes ({:.1}% of 16KB limit)", size, size as f64 / 16384.0 * 100.0);
    }
}
