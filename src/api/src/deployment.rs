// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use dterror::{BoxError, CtxError, Location};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, LazyLock};
use tempfile::TempDir;
use tokio::fs;
use tokio::sync::Semaphore;
use uuid::Uuid;

// Module-level semaphore for lockfile generation coordination (LazyLock enables deref access)
static LOCKFILE_SEMAPHORE: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(1)));

/// Generate lockfile config using hcl-rs types instead of string template
fn generate_provider_lock_config() -> String {
    let structure = hcl::structure!(
        terraform {
            required_version = ">= 1.0"
            required_providers {
                aws = {
                    source = "hashicorp/aws"
                    version = "~> 5.0"
                }
            }
        }
    );

    hcl::to_string(&structure).expect("static terraform block body must serialize")
}

/// Default timeout for tofu init/apply/destroy operations (10 minutes).
const TOFU_TIMEOUT_SECS: u64 = 600;

/// Returns the path to the cached provider lockfile in the data directory.
pub fn cached_lockfile_path(data_dir: &str) -> PathBuf {
    Path::new(data_dir)
        .join("terraform")
        .join(".terraform.lock.hcl")
}

/// Attempts to get or generate the provider lockfile on-demand.
///
/// - Acquires module-level semaphore (only one generation at a time per container)
/// - Checks if lockfile exists; if yes, returns path immediately (~0.1 sec)
/// - If missing: writes temp .tf with hashicorp/aws ~> 5.0, runs tofu providers lock,
///   copies resulting lockfile to cache dir, returns path
/// - Always fail-open: logs warning on error, releases semaphore, returns None
#[tracing::instrument(skip_all)]
pub async fn get_or_generate_lockfile(data_dir: &str) -> Option<PathBuf> {
    let permit = LOCKFILE_SEMAPHORE
        .acquire()
        .await
        .expect("lockfile semaphore is never closed");

    let lockfile_path = cached_lockfile_path(data_dir);

    // Check if lockfile already exists (common case after first generation)
    if tokio::fs::try_exists(&lockfile_path).await.unwrap_or(false) {
        tracing::info!("Provider lockfile cache hit at {}", lockfile_path.display());
        drop(permit);
        return Some(lockfile_path);
    }

    // Lockfile doesn't exist - generate it
    tracing::info!("Generating provider lockfile in {}...", data_dir);

    let temp_dir = match TempDir::new() {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(
                "Failed to create temp dir for lockfile generation: {}; proceeding without cache",
                e
            );
            drop(permit);
            return None;
        }
    };

    // Write minimal .tf with our provider constraint using hcl-rs
    let minimal_tf = generate_provider_lock_config();

    let main_tf_path = temp_dir.path().join("main.tf");
    if let Err(e) = std::fs::write(&main_tf_path, minimal_tf) {
        tracing::warn!(
            "Failed to write temp .tf for lockfile generation: {}; proceeding without cache",
            e
        );
        drop(permit);
        return None;
    }

    // Run tofu providers lock
    let mut cmd = Command::new("tofu");
    cmd.args(["providers", "lock", "-platform=linux_amd64"])
        .current_dir(temp_dir.path());

    let output = match run_with_timeout(&mut cmd, 60) {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!(
                "tofu providers lock failed: {}; proceeding without cache",
                e
            );
            drop(permit);
            return None;
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        tracing::warn!(
            "tofu providers lock failed (exit code {:?}): stderr={}, stdout={}; proceeding without cache",
            output.status.code(),
            stderr,
            stdout
        );
        drop(permit);
        return None;
    }

    // Copy the generated lockfile to the cache directory
    let temp_lockfile = temp_dir.path().join(".terraform.lock.hcl");
    let cache_terraform_dir = Path::new(data_dir).join("terraform");

    if let Err(e) = tokio::fs::create_dir_all(&cache_terraform_dir).await {
        tracing::warn!(
            "Failed to create terraform cache dir {}: {}; proceeding without cache",
            cache_terraform_dir.display(),
            e
        );
        drop(permit);
        return None;
    }

    let result = match tokio::fs::copy(&temp_lockfile, &lockfile_path).await {
        Ok(_) => {
            tracing::info!("Provider lockfile cached at {}", lockfile_path.display());
            Some(lockfile_path)
        }
        Err(e) => {
            tracing::warn!(
                "Failed to copy lockfile to {}: {}; proceeding without cache",
                lockfile_path.display(),
                e
            );
            None
        }
    };
    drop(permit);
    result
}

/// Failure modes for [`run_with_timeout`].
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum RunCommandError {
    #[error("could not spawn command [{location}]")]
    Spawn {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not wait on command [{location}]")]
    Wait {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not read command output [{location}]")]
    ReadOutput {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("command timed out after {timeout_secs}s [{location}]")]
    TimedOut {
        timeout_secs: u64,
        location: Location,
    },
    #[error("command timed out after {timeout_secs}s; failed to read output [{location}]")]
    TimedOutReadOutput {
        timeout_secs: u64,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for `tofu init`.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum TofuInitError {
    #[error("could not run tofu init [{location}]")]
    RunCommand {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("tofu init failed (exit code {exit_code:?}) [{location}]")]
    NonZeroExit {
        exit_code: Option<i32>,
        location: Location,
    },
}

/// Failure modes for `tofu apply`.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum TofuApplyError {
    #[error("could not run tofu apply [{location}]")]
    RunCommand {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("tofu apply failed (exit code {exit_code:?}) [{location}]")]
    NonZeroExit {
        exit_code: Option<i32>,
        location: Location,
    },
}

/// Failure modes for `tofu destroy`.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum TofuDestroyError {
    #[error("could not run tofu destroy [{location}]")]
    RunCommand {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("tofu destroy failed (exit code {exit_code:?}) [{location}]")]
    NonZeroExit {
        exit_code: Option<i32>,
        location: Location,
    },
}

/// Run a command with a timeout. Kills the process if deadline expires.
#[tracing::instrument(skip_all, err)]
fn run_with_timeout(
    cmd: &mut Command,
    timeout_secs: u64,
) -> std::result::Result<std::process::Output, RunCommandError> {
    use RunCommandErrorCtx as Ctx;

    let mut child = dterror::ResultExt::with_context(
        cmd.stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn(),
        Ctx::spawn(),
    )?;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

    loop {
        let status = dterror::ResultExt::with_context(child.try_wait(), Ctx::wait())?;
        match status {
            Some(_) => {
                return dterror::ResultExt::with_context(
                    child.wait_with_output(),
                    Ctx::read_output(),
                );
            }
            None => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    match child.wait_with_output() {
                        Ok(output) => {
                            tracing::error!(
                                stdout = %String::from_utf8_lossy(&output.stdout),
                                stderr = %String::from_utf8_lossy(&output.stderr),
                                "command timed out"
                            );
                            return Err(RunCommandError::TimedOut {
                                timeout_secs,
                                location: std::panic::Location::caller(),
                            });
                        }
                        Err(e) => {
                            return dterror::ResultExt::with_context(
                                std::result::Result::<std::process::Output, _>::Err(e),
                                Ctx::timed_out_read_output(timeout_secs),
                            );
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
    }
}

#[derive(Clone)]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub region: String,
}

impl std::fmt::Debug for AwsCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsCredentials")
            .field("access_key_id", &"[REDACTED]")
            .field("secret_access_key", &"[REDACTED]")
            .field("region", &self.region)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentResult {
    pub instance_id: String,
    pub public_ip: String,
    pub url: String,
    pub instance_type: Option<String>,
}

pub const E2E_MODE_DISABLED: &str = "disabled";
pub const E2E_MODE_STEVE: &str = "steve";

fn default_e2e_mode() -> String {
    E2E_MODE_DISABLED.to_string()
}

fn effective_e2e_mode(e2e: bool, e2e_mode: &str) -> &str {
    match e2e_mode {
        "" | E2E_MODE_DISABLED if e2e => E2E_MODE_STEVE,
        "" => E2E_MODE_DISABLED,
        other => other,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NitroDeploymentRequest {
    pub org_id: Uuid,
    pub resource_id: Uuid,
    pub resource_name: String,
    pub aws_account_id: String,
    pub role_arn: Option<String>,
    pub eif_path: String,
    /// If set, EIF is already in S3 at this key — skip local upload.
    #[serde(default)]
    pub eif_s3_key: Option<String>,
    pub memory_mb: u32,
    pub cpu_count: u32,
    pub disk_gb: u32,
    pub debug_mode: bool,
    pub ports: Vec<u16>,
    pub http_port: Option<u16>,
    #[serde(default)]
    pub e2e: bool,
    #[serde(default = "default_e2e_mode")]
    pub e2e_mode: String,
    #[serde(default)]
    pub locksmith: bool,
    #[serde(default)]
    pub egress: bool,
    pub ssh_keys: Vec<String>,
    pub domain: Option<String>,
    pub region: Option<String>,
    #[serde(skip)]
    pub credentials: Option<AwsCredentials>,
    pub managed_onprem: Option<ManagedOnPremConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedOnPremConfig {
    pub deployment_id: String,
    pub asg_name: String,
    pub launch_template_name: String,
    pub launch_template_id: String,
    pub vpc_id: String,
    pub subnet_ids: Vec<String>,
    pub eif_bucket: String,
    pub instance_profile_name: String,
    #[serde(default)]
    pub builder_instance_profile_name: Option<String>,
}

fn managed_onprem_uses_direct_customer_bucket(
    request: &NitroDeploymentRequest,
    managed_onprem: &ManagedOnPremConfig,
) -> bool {
    request.eif_s3_key.is_some()
        && request
            .eif_path
            .starts_with(&format!("s3://{}/", managed_onprem.eif_bucket))
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum DeployNitroEnclaveError {
    #[error("deployment region is required [{location}]")]
    MissingRegion { location: Location },
    #[error("credentials required for managed on-prem [{location}]")]
    MissingCredentials { location: Location },
    #[error("failed to upload EIF to customer bucket [{location}]")]
    UploadEifCustomerBucket {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("failed to upload EIF to S3 [{location}]")]
    UploadEifS3 {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("managed on-prem provisioning failed [{location}]")]
    ProvisionManagedOnprem {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("nitro enclave provisioning failed [{location}]")]
    ProvisionNitroEnclave {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
pub async fn deploy_nitro_enclave(
    request: NitroDeploymentRequest,
) -> std::result::Result<DeploymentResult, DeployNitroEnclaveError> {
    use DeployNitroEnclaveErrorCtx as Ctx;

    tracing::info!(
        "Starting Nitro Enclave deployment for resource {} ({})",
        request.resource_id,
        request.resource_name
    );

    // A deployment region must be configured for this resource. The concrete
    // value is resolved downstream by the Terraform module.
    request
        .credentials
        .as_ref()
        .map(|c| c.region.clone())
        .or_else(|| request.region.clone())
        .ok_or(DeployNitroEnclaveError::MissingRegion {
            location: std::panic::Location::caller(),
        })?;

    let config = TerraformConfig {
        module_path: PathBuf::from("terraform/modules/aws/nitro-enclave"),
        s3_bucket: std::env::var("TERRAFORM_STATE_BUCKET")
            .unwrap_or_else(|_| "caution-terraform-state".to_string()),
    };

    if let Some(ref managed_onprem) = request.managed_onprem {
        tracing::info!("Using managed on-prem deployment flow");
        let customer_creds =
            request
                .credentials
                .as_ref()
                .ok_or(DeployNitroEnclaveError::MissingCredentials {
                    location: std::panic::Location::caller(),
                })?;
        let eif_s3_path = if managed_onprem_uses_direct_customer_bucket(&request, managed_onprem) {
            tracing::info!(
                "Managed on-prem builder output already in customer bucket: {}",
                request.eif_path
            );
            request.eif_path.clone()
        } else if let Some(ref s3_key) = request.eif_s3_key {
            dterror::ResultExt::with_context(
                upload_eif_from_platform_s3_to_customer_bucket(
                    s3_key,
                    &request.resource_id,
                    &managed_onprem.eif_bucket,
                    customer_creds,
                    &request.aws_account_id,
                )
                .await,
                Ctx::upload_eif_customer_bucket(),
            )?
        } else {
            dterror::ResultExt::with_context(
                upload_eif_to_customer_bucket(
                    &request.eif_path,
                    &request.resource_id,
                    &managed_onprem.eif_bucket,
                    customer_creds,
                )
                .await,
                Ctx::upload_eif_customer_bucket(),
            )?
        };
        dterror::ResultExt::with_context(
            provision_managed_onprem(&request, &eif_s3_path, &config).await,
            Ctx::provision_managed_onprem(),
        )
    } else if let Some(ref s3_key) = request.eif_s3_key {
        // EIF already in S3 (uploaded by dedicated builder)
        let bucket = std::env::var("EIF_S3_BUCKET").unwrap_or_else(|_| {
            let account = std::env::var("AWS_ACCOUNT_ID").unwrap_or_default();
            format!("caution-eif-storage-{}", account)
        });
        let eif_s3_path = format!("s3://{}/{}", bucket, s3_key);
        tracing::info!("Using pre-uploaded EIF: {}", eif_s3_path);
        dterror::ResultExt::with_context(
            provision_nitro_enclave(&request, &eif_s3_path, &config).await,
            Ctx::provision_nitro_enclave(),
        )
    } else {
        let eif_s3_path = dterror::ResultExt::with_context(
            upload_eif_to_s3(
                &request.eif_path,
                &request.org_id,
                &request.resource_id,
                &request.aws_account_id,
            )
            .await,
            Ctx::upload_eif_s3(),
        )?;
        dterror::ResultExt::with_context(
            provision_nitro_enclave(&request, &eif_s3_path, &config).await,
            Ctx::provision_nitro_enclave(),
        )
    }
}

#[tracing::instrument(skip_all, err)]
pub async fn destroy_app_with_credentials(
    org_id: Uuid,
    resource_id: Uuid,
    resource_name: String,
    credentials: Option<AwsCredentials>,
    asg_name: Option<String>,
) -> std::result::Result<(), DestroyEc2Error> {
    tracing::info!(
        "Starting Terraform destroy for resource {} ({})",
        resource_id,
        resource_name
    );

    let config = TerraformConfig::default();

    // For managed on-prem: scale ASG to 0 first so instance terminates cleanly
    // This ensures the EIP gets disassociated and security group can be deleted
    if let (Some(creds), Some(asg)) = (&credentials, &asg_name) {
        tracing::info!("Managed on-prem destroy - scaling ASG {} to 0", asg);
        if let Err(e) = scale_down_asg(asg, creds).await {
            tracing::warn!("Failed to scale down ASG: {} (continuing with destroy)", e);
        }
    }

    destroy_ec2_app(
        org_id,
        resource_id,
        &resource_name,
        &config,
        credentials.as_ref(),
    )
    .await?;

    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ScaleDownAsgError {
    #[error("could not set ASG desired capacity to 0 [{location}]")]
    SetDesiredCapacity {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Scale down ASG to 0 and wait for instances to terminate
#[tracing::instrument(skip_all, err)]
async fn scale_down_asg(
    asg_name: &str,
    credentials: &AwsCredentials,
) -> std::result::Result<(), ScaleDownAsgError> {
    use ScaleDownAsgErrorCtx as Ctx;
    use std::time::{Duration, Instant};

    let asg = crate::ec2::AsgClient::new(credentials);
    dterror::ResultExt::with_context(
        asg.set_desired_capacity(asg_name, 0).await,
        Ctx::set_desired_capacity(),
    )?;

    tracing::info!(
        "Set ASG {} desired capacity to 0, waiting for instance termination...",
        asg_name
    );

    let ec2 = crate::ec2::Ec2Client::new(credentials);

    let start = Instant::now();
    let timeout = Duration::from_secs(180);

    loop {
        if start.elapsed() > timeout {
            tracing::warn!("Timeout waiting for ASG instances to terminate");
            break;
        }

        let result = ec2
            .describe_instances(&[
                crate::ec2::Filter::new("tag:aws:autoscaling:groupName", &[asg_name]),
                crate::ec2::Filter::new("instance-state-name", &["pending", "running", "stopping"]),
            ])
            .await;

        match result {
            Ok(instances) => {
                if instances.is_empty() {
                    tracing::info!("All ASG instances terminated");
                    return Ok(());
                }
                tracing::debug!("ASG still has {} instance(s), waiting...", instances.len());
            }
            Err(e) => {
                tracing::warn!("Error checking instances: {}", e);
            }
        }

        tokio::time::sleep(Duration::from_secs(10)).await;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn assert_template_references_guarded_by_debug(user_data: &str, needle: &str) {
        const DEBUG_IF: &str = r#"%{ if debug_mode == "true" ~}"#;
        const ENDIF: &str = "%{ endif ~}";

        let mut debug_ranges = Vec::new();
        let mut search_start = 0;
        while let Some(offset) = user_data[search_start..].find(DEBUG_IF) {
            let start = search_start + offset;
            let body_start = start + DEBUG_IF.len();
            let end_offset = user_data[body_start..]
                .find(ENDIF)
                .unwrap_or_else(|| panic!("debug template block at byte {start} is not closed"));
            let end = body_start + end_offset + ENDIF.len();
            debug_ranges.push(start..end);
            search_start = end;
        }

        assert!(
            !debug_ranges.is_empty(),
            "expected at least one debug_mode template block"
        );

        let mut found = false;
        let mut needle_search_start = 0;
        while let Some(offset) = user_data[needle_search_start..].find(needle) {
            found = true;
            let position = needle_search_start + offset;
            assert!(
                debug_ranges.iter().any(|range| range.contains(&position)),
                "{needle} reference at byte {position} must be guarded by debug_mode"
            );
            needle_search_start = position + needle.len();
        }

        assert!(
            found,
            "expected user-data template to contain {needle} reference"
        );
    }

    fn managed_onprem_config() -> ManagedOnPremConfig {
        ManagedOnPremConfig {
            deployment_id: "dep-123".to_string(),
            asg_name: "asg-123".to_string(),
            launch_template_name: "lt-name".to_string(),
            launch_template_id: "lt-123".to_string(),
            vpc_id: "vpc-123".to_string(),
            subnet_ids: vec!["subnet-123".to_string()],
            eif_bucket: "customer-bucket".to_string(),
            instance_profile_name: "runtime-profile".to_string(),
            builder_instance_profile_name: Some("builder-profile".to_string()),
        }
    }

    fn deployment_request(eif_path: &str, eif_s3_key: Option<&str>) -> NitroDeploymentRequest {
        NitroDeploymentRequest {
            org_id: Uuid::nil(),
            resource_id: Uuid::nil(),
            resource_name: "app".to_string(),
            aws_account_id: "123456789012".to_string(),
            role_arn: None,
            eif_path: eif_path.to_string(),
            eif_s3_key: eif_s3_key.map(|key| key.to_string()),
            memory_mb: 512,
            cpu_count: 2,
            disk_gb: 30,
            debug_mode: false,
            ports: vec![],
            http_port: None,
            e2e: false,
            e2e_mode: E2E_MODE_DISABLED.to_string(),
            locksmith: false,
            egress: false,
            ssh_keys: vec![],
            domain: None,
            region: Some("us-west-2".to_string()),
            credentials: None,
            managed_onprem: Some(managed_onprem_config()),
        }
    }

    #[test]
    fn test_managed_onprem_uses_direct_customer_bucket_for_builder_output() {
        let request = deployment_request(
            "s3://customer-bucket/eifs/org/key.eif",
            Some("eifs/org/key.eif"),
        );
        assert!(managed_onprem_uses_direct_customer_bucket(
            &request,
            request.managed_onprem.as_ref().unwrap()
        ));
    }

    #[test]
    fn test_managed_onprem_does_not_use_direct_customer_bucket_for_platform_path() {
        let request = deployment_request(
            "s3://platform-bucket/eifs/org/key.eif",
            Some("eifs/org/key.eif"),
        );
        assert!(!managed_onprem_uses_direct_customer_bucket(
            &request,
            request.managed_onprem.as_ref().unwrap()
        ));
    }

    #[test]
    fn test_caddy_routes_encrypted_e2p_requests_before_default_upstream() {
        let user_data = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("terraform/modules/aws/nitro-enclave/user-data.sh"),
        )
        .unwrap();
        let e2p_header_matcher = r#"@e2p_encrypted {
        method POST
        header X-E2P-Key *
        header X-E2P-Original-Method *
        header Content-Type application/octet-stream
    }
    handle @e2p_encrypted {
        reverse_proxy localhost:49500
    }"#;

        assert_eq!(user_data.matches(e2p_header_matcher).count(), 4);

        for block in user_data.split("handle /e2p/* {").skip(1).take(4) {
            let encrypted_route = block.find("handle @e2p_encrypted").unwrap();
            let default_upstream = block.find("$CADDY_DEFAULT_UPSTREAM").unwrap();
            assert!(
                encrypted_route < default_upstream,
                "encrypted E2P requests must be routed before the app catch-all"
            );
        }
    }

    #[test]
    fn test_enclave_console_capture_is_debug_only() {
        let user_data = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("terraform/modules/aws/nitro-enclave/user-data.sh"),
        )
        .unwrap();

        for needle in [
            "/usr/local/bin/capture-enclave-console.sh",
            "nitro-enclave-console.service",
            "/var/log/nitro_enclaves/enclave-console.log",
            "nitro-cli console",
        ] {
            assert_template_references_guarded_by_debug(&user_data, needle);
        }
    }

    #[tokio::test]
    async fn test_fully_managed_tf_opens_steve_port_when_e2e_enabled() {
        let mut request = deployment_request("/tmp/enclave.eif", None);
        request.managed_onprem = None;
        request.e2e = true;

        let work_dir = TempDir::new().unwrap();
        generate_nitro_deployment_main_tf(work_dir.path(), &request, "s3://bucket/enclave.eif")
            .await
            .unwrap();

        let main_tf = std::fs::read_to_string(work_dir.path().join("main.tf")).unwrap();
        assert!(norm(&main_tf).contains("from_port = 49500"));
        assert!(norm(&main_tf).contains("to_port = 49500"));
        assert!(main_tf.contains("Allow STEVE encrypted transport"));
        assert!(norm(&main_tf).contains(r#"e2e = "true""#));
        assert!(!norm(&main_tf).contains("from_port = 49501"));
        assert!(!norm(&main_tf).contains("from_port = 49502"));
        assert!(!norm(&main_tf).contains("from_port = 49504"));
    }

    #[tokio::test]
    async fn test_fully_managed_tf_keeps_steve_port_closed_when_e2e_disabled() {
        let mut request = deployment_request("/tmp/enclave.eif", None);
        request.managed_onprem = None;

        let work_dir = TempDir::new().unwrap();
        generate_nitro_deployment_main_tf(work_dir.path(), &request, "s3://bucket/enclave.eif")
            .await
            .unwrap();

        let main_tf = std::fs::read_to_string(work_dir.path().join("main.tf")).unwrap();
        assert!(norm(&main_tf).contains(r#"e2e = "false""#));
        assert!(!norm(&main_tf).contains("from_port = 49500"));
        assert!(!norm(&main_tf).contains("from_port = 49501"));
        assert!(!norm(&main_tf).contains("from_port = 49502"));
        assert!(!norm(&main_tf).contains("from_port = 49504"));
    }

    #[tokio::test]
    async fn test_managed_onprem_tf_opens_locksmith_port_when_enabled() {
        let mut request = deployment_request(
            "s3://customer-bucket/eifs/org/key.eif",
            Some("eifs/org/key.eif"),
        );
        request.e2e = true;
        request.locksmith = true;

        let work_dir = TempDir::new().unwrap();
        generate_managed_onprem_deployment_tf(
            work_dir.path(),
            &request,
            "s3://customer-bucket/enclave.eif",
        )
        .await
        .unwrap();

        let main_tf = std::fs::read_to_string(work_dir.path().join("main.tf")).unwrap();
        assert!(norm(&main_tf).contains("from_port = 49500"));
        assert!(norm(&main_tf).contains("to_port = 49500"));
        assert!(norm(&main_tf).contains(r#"e2e = "true""#));
        assert!(norm(&main_tf).contains("from_port = 49504"));
        assert!(main_tf.contains("Allow Locksmith shard receiver"));
        assert!(norm(&main_tf).contains(r#"e2e_mode = "steve""#));
        assert!(norm(&main_tf).contains(r#"locksmith = "true""#));
        assert!(
            norm(&main_tf).contains("(local.scope_tag_key) = local.deployment_tag"),
            "scoped deployment tag key must be present in the rendered tags maps"
        );
        assert!(
            norm(&main_tf).contains(r#"name = "runtime-profile""#),
            "instance profile name from managed_onprem config must be wired into the launch template"
        );
        assert!(
            norm(&main_tf).contains(r#"value = "https://${aws_eip.enclave.public_ip}""#),
            "url output falls back to the EIP public IP when no domain is configured"
        );
    }

    #[tokio::test]
    async fn test_managed_onprem_tf_locksmith_port_absent_when_disabled() {
        let mut request = deployment_request(
            "s3://customer-bucket/eifs/org/key.eif",
            Some("eifs/org/key.eif"),
        );
        request.e2e = false;
        request.locksmith = false;

        let work_dir = TempDir::new().unwrap();
        generate_managed_onprem_deployment_tf(
            work_dir.path(),
            &request,
            "s3://customer-bucket/enclave.eif",
        )
        .await
        .unwrap();

        let main_tf = std::fs::read_to_string(work_dir.path().join("main.tf")).unwrap();
        assert!(norm(&main_tf).contains(r#"e2e = "false""#));
        assert!(!norm(&main_tf).contains("from_port = 49500"));
        assert!(!norm(&main_tf).contains("from_port = 49504"));
    }

    #[tokio::test]
    async fn test_managed_onprem_tf_url_output_uses_configured_domain() {
        let mut request = deployment_request(
            "s3://customer-bucket/eifs/org/key.eif",
            Some("eifs/org/key.eif"),
        );
        request.domain = Some("example.com".to_string());

        let work_dir = TempDir::new().unwrap();
        generate_managed_onprem_deployment_tf(
            work_dir.path(),
            &request,
            "s3://customer-bucket/enclave.eif",
        )
        .await
        .unwrap();

        let main_tf = std::fs::read_to_string(work_dir.path().join("main.tf")).unwrap();
        assert!(norm(&main_tf).contains(r#"value = "https://example.com""#));
    }

    #[tokio::test]
    async fn test_main_tf_passes_egress_var_to_user_data() {
        let mut request = deployment_request("/tmp/enclave.eif", None);
        request.managed_onprem = None;
        request.egress = true;

        let work_dir = TempDir::new().unwrap();
        generate_nitro_deployment_main_tf(work_dir.path(), &request, "s3://bucket/enclave.eif")
            .await
            .unwrap();

        let main_tf = std::fs::read_to_string(work_dir.path().join("main.tf")).unwrap();
        assert!(norm(&main_tf).contains(r#"egress = "true""#));
    }

    #[test]
    fn test_user_data_proxy_guarded_by_egress() {
        let user_data = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("terraform/modules/aws/nitro-enclave/user-data.sh"),
        )
        .unwrap();
        let needle = "Setting up vsock network proxy for enclave";
        let egress_if = r#"%{ if egress == "true" ~}"#;
        let if_pos = user_data.find(egress_if).expect("egress guard present");
        let needle_pos = user_data.find(needle).expect("proxy setup present");
        assert!(
            if_pos < needle_pos,
            "proxy setup must be guarded by egress conditional"
        );
    }

    #[test]
    fn test_user_data_routes_e2e_default_traffic_through_steve() {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let user_data = std::fs::read_to_string(
            manifest_dir.join("../../terraform/modules/aws/nitro-enclave/user-data.sh"),
        )
        .unwrap();

        assert!(user_data.contains(r#"%{ if e2e_mode == "steve" ~}"#));
        assert!(user_data.contains(r#"CADDY_DEFAULT_UPSTREAM="reverse_proxy localhost:49500""#));
    }

    #[test]
    fn test_user_data_tls_mode_forwards_tls_to_enclave() {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let user_data = std::fs::read_to_string(
            manifest_dir.join("../../terraform/modules/aws/nitro-enclave/user-data.sh"),
        )
        .unwrap();

        assert!(user_data.contains(r#"%{ if e2e_mode == "tls" ~}"#));
        assert!(user_data.contains(r#"standard_ports="$standard_ports 443""#));
        assert!(user_data.contains(r#"%{ if http_port != 0 && e2e_mode == "disabled" ~}"#));
        assert!(user_data.contains("TLS :443 is forwarded into the enclave"));
        assert!(user_data.contains("respond \"OK\" 200"));
        assert!(user_data.contains("redir https://${domain}{uri} 308"));
        let redir_pos = user_data.find("redir https://${domain}{uri} 308").unwrap();
        let http_site_pos = user_data[..redir_pos].rfind(":80 {").unwrap();
        let tls_mode_http_site = &user_data[http_site_pos..redir_pos];
        assert!(tls_mode_http_site.contains("handle /attestation"));
        assert!(tls_mode_http_site.contains("reverse_proxy localhost:49502"));
        assert!(!user_data.contains("reverse_proxy https://127.0.0.1:443"));
        assert!(!user_data.contains("header_up Host ${domain}"));
        assert!(!user_data.contains("tls_server_name ${domain}"));
        assert!(!user_data.contains("tls_insecure_skip_verify"));
        assert!(!user_data.contains("reverse_proxy http://localhost:443"));
    }

    #[test]
    fn test_http_port_proxy_is_loopback_only_and_omitted_for_e2e() {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let user_data = std::fs::read_to_string(
            manifest_dir.join("../../terraform/modules/aws/nitro-enclave/user-data.sh"),
        )
        .unwrap();

        assert_eq!(
            user_data
                .matches(r#"%{ if http_port != 0 && e2e_mode == "disabled" ~}"#)
                .count(),
            3
        );
        assert!(user_data.contains(
            "ExecStart=/usr/bin/socat TCP-LISTEN:${http_port},bind=127.0.0.1,reuseaddr,fork VSOCK-CONNECT:16:${http_port}"
        ));
    }

    #[tokio::test]
    async fn test_generate_backend_config_produces_correct_structure() {
        let org_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let resource_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let temp_dir = TempDir::new().unwrap();

        generate_backend_config(temp_dir.path(), org_id, resource_id, "my-bucket")
            .await
            .unwrap();

        let content = std::fs::read_to_string(temp_dir.path().join("backend.tf")).unwrap();
        let normalized: String = content.split_whitespace().collect::<Vec<_>>().join(" ");

        assert!(normalized.contains("terraform"), "missing terraform block");
        assert!(
            normalized.contains(r#"backend "s3""#),
            "missing backend s3 block"
        );
        assert!(
            normalized.contains(r#"bucket = "my-bucket""#),
            "missing bucket attribute"
        );
        assert!(
            normalized.contains(&format!(
                r#"key = "organizations/{}/resources/{}/terraform.tfstate""#,
                org_id, resource_id
            )),
            "missing or incorrect key attribute"
        );
        assert!(
            normalized.contains(r#"region = "us-west-2""#),
            "missing region attribute"
        );
        assert!(
            normalized.contains("encrypt = true"),
            "missing encrypt attribute"
        );
    }

    #[test]
    fn test_destroy_tf_body_without_credentials_uses_plain_provider() {
        let content = hcl::to_string(&build_destroy_tf_body(false, "us-east-1")).unwrap();
        let norm = content.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(norm.contains(r#"required_version = ">= 1.0""#));
        assert!(norm.contains(r#"source = "hashicorp/aws""#));
        assert!(norm.contains(r#"version = "~> 5.0""#));
        assert!(norm.contains(r#"region = "us-east-1""#));
        assert!(!norm.contains("provider_access_key"));
        assert!(!norm.contains("provider_secret_key"));
        assert!(!norm.contains("provider_region"));
    }

    #[test]
    fn test_destroy_tf_body_with_credentials_includes_variables_and_conditionals() {
        let content = hcl::to_string(&build_destroy_tf_body(true, "eu-west-1")).unwrap();
        let norm = content.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(norm.contains(r#"required_version = ">= 1.0""#));
        assert!(norm.contains(r#"variable "provider_access_key""#));
        assert!(norm.contains("sensitive = true"));
        assert!(norm.contains(r#"variable "provider_secret_key""#));
        assert!(norm.contains(r#"variable "provider_region""#));
        assert!(norm.contains("var.provider_region != \"\" ? var.provider_region : \"eu-west-1\""));
        assert!(norm.contains("var.provider_access_key != \"\" ? var.provider_access_key : null"));
        assert!(norm.contains("var.provider_secret_key != \"\" ? var.provider_secret_key : null"));
    }

    #[test]
    fn test_destroy_tf_body_has_no_default_tags() {
        let content = hcl::to_string(&build_destroy_tf_body(true, "us-west-2")).unwrap();
        assert!(!content.contains("default_tags"));
    }
}

struct TerraformConfig {
    module_path: PathBuf,
    s3_bucket: String,
}

impl Default for TerraformConfig {
    fn default() -> Self {
        Self {
            module_path: PathBuf::from("terraform/modules/aws/nitro-enclave"),
            s3_bucket: std::env::var("TERRAFORM_STATE_BUCKET")
                .unwrap_or_else(|_| "caution-terraform-state".to_string()),
        }
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum DestroyEc2Error {
    #[error("could not create temporary directory [{location}]")]
    TempDir {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not generate backend config [{location}]")]
    Backend {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not serialize main.tf [{location}]")]
    Serialize {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not write main.tf [{location}]")]
    WriteMainTf {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not run tofu init [{location}]")]
    Init {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not run tofu destroy [{location}]")]
    Destroy {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn destroy_ec2_app(
    org_id: Uuid,
    resource_id: Uuid,
    resource_name: &str,
    config: &TerraformConfig,
    credentials: Option<&AwsCredentials>,
) -> std::result::Result<(), DestroyEc2Error> {
    use DestroyEc2ErrorCtx as Ctx;

    tracing::info!("Starting Terraform destroy for resource: {}", resource_name);

    let temp_dir = dterror::ResultExt::with_context(TempDir::new(), Ctx::temp_dir())?;
    let work_dir = temp_dir.path();

    dterror::ResultExt::with_context(
        generate_backend_config(work_dir, org_id, resource_id, &config.s3_bucket).await,
        Ctx::backend(),
    )?;

    let aws_region = credentials
        .map(|c| c.region.clone())
        .unwrap_or_else(|| std::env::var("AWS_REGION").unwrap_or_else(|_| "us-west-2".to_string()));

    let body = build_destroy_tf_body(credentials.is_some(), &aws_region);
    let content = dterror::ResultExt::with_context(hcl::to_string(&body), Ctx::serialize())?;

    dterror::ResultExt::with_context(
        fs::write(work_dir.join("main.tf"), &content).await,
        Ctx::write_main_tf(),
    )?;

    let data_dir =
        std::env::var("CAUTION_DATA_DIR").unwrap_or_else(|_| "/var/cache/caution".to_string());
    let lockfile_path = get_or_generate_lockfile(&data_dir).await;

    dterror::ResultExt::with_context(
        run_tofu_init(work_dir, lockfile_path.as_deref(), None).await,
        Ctx::init(),
    )?;

    dterror::ResultExt::with_context(
        run_tofu_destroy(work_dir, resource_name, credentials),
        Ctx::destroy(),
    )?;

    tracing::info!("Successfully destroyed EC2 for resource {}", resource_name);

    Ok(())
}

fn build_destroy_tf_body(has_credentials: bool, aws_region: &str) -> hcl::Body {
    let mut body = hcl::Body::builder();

    body = body.add_block(
        hcl::Block::builder("terraform")
            .add_attribute(("required_version", ">= 1.0"))
            .add_block(
                hcl::Block::builder("required_providers")
                    .add_attribute((
                        "aws",
                        hcl::Expression::Object(
                            vec![
                                (
                                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                        "source",
                                    )),
                                    hcl::Expression::String("hashicorp/aws".into()),
                                ),
                                (
                                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                        "version",
                                    )),
                                    hcl::Expression::String("~> 5.0".into()),
                                ),
                            ]
                            .into_iter()
                            .collect(),
                        ),
                    ))
                    .build(),
            )
            .build(),
    );

    if has_credentials {
        body = body
            .add_block(provider_credential_variable("provider_access_key", true))
            .add_block(provider_credential_variable("provider_secret_key", true))
            .add_block(provider_credential_variable("provider_region", false));

        body = body.add_block(
            hcl::Block::builder("provider")
                .add_label("aws")
                .add_attribute(hcl::Attribute::new(
                    "region",
                    region_conditional(aws_region),
                ))
                .add_attribute(credential_conditional("access_key", "provider_access_key"))
                .add_attribute(credential_conditional("secret_key", "provider_secret_key"))
                .build(),
        );
    } else {
        body = body.add_block(
            hcl::Block::builder("provider")
                .add_label("aws")
                .add_attribute(("region", aws_region))
                .build(),
        );
    }

    body.build()
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GenerateBackendConfigError {
    #[error("could not serialize backend config [{location}]")]
    Serialize {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not write backend.tf [{location}]")]
    Write {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn generate_backend_config(
    work_dir: &Path,
    org_id: Uuid,
    resource_id: Uuid,
    s3_bucket: &str,
) -> std::result::Result<(), GenerateBackendConfigError> {
    use GenerateBackendConfigErrorCtx as Ctx;

    let key = format!(
        "organizations/{}/resources/{}/terraform.tfstate",
        org_id, resource_id
    );

    let body = hcl::Body::builder()
        .add_block(
            hcl::Block::builder("terraform")
                .add_block(
                    hcl::Block::builder("backend")
                        .add_label("s3")
                        .add_attribute(("bucket", s3_bucket))
                        .add_attribute(("key", key.as_str()))
                        .add_attribute(("region", "us-west-2"))
                        .add_attribute(("encrypt", true))
                        .build(),
                )
                .build(),
        )
        .build();

    let content = dterror::ResultExt::with_context(hcl::to_string(&body), Ctx::serialize())?;

    let backend_path = work_dir.join("backend.tf");
    dterror::ResultExt::with_context(fs::write(&backend_path, &content).await, Ctx::write())?;

    Ok(())
}

#[tracing::instrument(skip_all, err)]
async fn run_tofu_init(
    work_dir: &Path,
    lockfile_path: Option<&Path>,
    credentials: Option<&AwsCredentials>,
) -> std::result::Result<(), TofuInitError> {
    use TofuInitErrorCtx as Ctx;

    tracing::info!("Running tofu init in {}...", work_dir.display());

    // Copy lockfile into work dir if provided
    if let Some(src) = lockfile_path {
        let dst = work_dir.join(".terraform.lock.hcl");
        match tokio::fs::copy(src, &dst).await {
            Ok(_) => tracing::info!("Using cached provider lockfile from {}", src.display()),
            Err(e) => tracing::warn!(
                "Failed to copy lockfile from {} to {}: {}; proceeding without cache",
                src.display(),
                dst.display(),
                e
            ),
        }
    }

    let mut cmd = Command::new("tofu");
    cmd.args(["init", "-no-color", "-upgrade=false", "-reconfigure"])
        .current_dir(work_dir);

    if let Some(creds) = credentials {
        cmd.env("AWS_ACCESS_KEY_ID", &creds.access_key_id)
            .env("AWS_SECRET_ACCESS_KEY", &creds.secret_access_key)
            .env("AWS_REGION", &creds.region);
    }

    let output = dterror::ResultExt::with_context(
        run_with_timeout(&mut cmd, TOFU_TIMEOUT_SECS),
        Ctx::run_command(),
    )?;

    if !output.status.success() {
        tracing::error!(
            exit_code = ?output.status.code(),
            stdout = %String::from_utf8_lossy(&output.stdout),
            stderr = %String::from_utf8_lossy(&output.stderr),
            "tofu init failed"
        );
        return Err(TofuInitError::NonZeroExit {
            exit_code: output.status.code(),
            location: std::panic::Location::caller(),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    tracing::debug!("Tofu init output: {}", stdout);

    Ok(())
}

#[tracing::instrument(skip_all, err)]
fn run_tofu_apply_with_provider_creds(
    work_dir: &Path,
    resource_name: &str,
    ports: &[u16],
    http_port: Option<u16>,
    credentials: Option<&AwsCredentials>,
) -> std::result::Result<(), TofuApplyError> {
    use TofuApplyErrorCtx as Ctx;

    let public_ports = ports
        .iter()
        .copied()
        .filter(|port| Some(*port) != http_port)
        .collect::<Vec<_>>();
    tracing::info!(
        "Running tofu apply for {} in {} (ports={:?}, http_port={:?})...",
        resource_name,
        work_dir.display(),
        public_ports,
        http_port
    );

    let mut cmd = Command::new("tofu");
    cmd.arg("apply")
        .arg("-auto-approve")
        .arg("-no-color")
        .current_dir(work_dir);

    let ports_var = if !public_ports.is_empty() {
        let ports_str: Vec<String> = public_ports.iter().map(|p| p.to_string()).collect();
        format!("ports=[{}]", ports_str.join(","))
    } else {
        "ports=[]".to_string()
    };
    cmd.arg("-var").arg(&ports_var);
    cmd.arg("-var")
        .arg(format!("http_port={}", http_port.unwrap_or(0)));

    if let Some(creds) = credentials {
        tracing::info!("Passing user credentials to AWS provider via environment variables");
        cmd.env("TF_VAR_provider_access_key", &creds.access_key_id);
        cmd.env("TF_VAR_provider_secret_key", &creds.secret_access_key);
        cmd.env("TF_VAR_provider_region", &creds.region);
    }

    let output = dterror::ResultExt::with_context(
        run_with_timeout(&mut cmd, TOFU_TIMEOUT_SECS),
        Ctx::run_command(),
    )?;

    if !output.status.success() {
        tracing::error!(
            exit_code = ?output.status.code(),
            stdout = %String::from_utf8_lossy(&output.stdout),
            stderr = %String::from_utf8_lossy(&output.stderr),
            "tofu apply failed"
        );
        return Err(TofuApplyError::NonZeroExit {
            exit_code: output.status.code(),
            location: std::panic::Location::caller(),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    tracing::debug!("Tofu apply output: {}", stdout);

    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetTofuOutputsError {
    #[error("could not run tofu output command [{location}]")]
    RunCommand {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("tofu output exited with code {exit_code:?} [{location}]")]
    NonZeroExit {
        exit_code: Option<i32>,
        location: Location,
    },
    #[error("could not parse tofu output JSON [{location}]")]
    JsonParse {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("tofu output missing required field '{field}' [{location}]")]
    MissingField { field: String, location: Location },
}

#[tracing::instrument(skip_all, err)]
fn get_tofu_outputs(work_dir: &Path) -> std::result::Result<DeploymentResult, GetTofuOutputsError> {
    use GetTofuOutputsErrorCtx as Ctx;

    tracing::info!("Retrieving tofu outputs...");

    let output = dterror::ResultExt::with_context(
        run_with_timeout(
            Command::new("tofu")
                .args(["output", "-json", "-no-color"])
                .current_dir(work_dir),
            TOFU_TIMEOUT_SECS,
        ),
        Ctx::run_command(),
    )?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!("Tofu output failed: {}", stderr);
        return Err(GetTofuOutputsError::NonZeroExit {
            exit_code: output.status.code(),
            location: std::panic::Location::caller(),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let outputs: serde_json::Value =
        dterror::ResultExt::with_context(serde_json::from_str(&stdout), Ctx::json_parse())?;

    let instance_id = outputs["instance_id"]["value"]
        .as_str()
        .ok_or_else(|| GetTofuOutputsError::MissingField {
            field: "instance_id".to_string(),
            location: std::panic::Location::caller(),
        })?
        .to_string();

    let public_ip = outputs["public_ip"]["value"]
        .as_str()
        .ok_or_else(|| GetTofuOutputsError::MissingField {
            field: "public_ip".to_string(),
            location: std::panic::Location::caller(),
        })?
        .to_string();

    let url = outputs["url"]["value"]
        .as_str()
        .ok_or_else(|| GetTofuOutputsError::MissingField {
            field: "url".to_string(),
            location: std::panic::Location::caller(),
        })?
        .to_string();

    let instance_type = outputs["instance_type"]["value"]
        .as_str()
        .map(|s| s.to_string());

    Ok(DeploymentResult {
        instance_id,
        public_ip,
        url,
        instance_type,
    })
}

/// Terraform outputs for managed on-prem deployments (before ASG update)
#[derive(Debug)]
struct ManagedOnPremTerraformOutputs {
    launch_template_id: String,
    eip_allocation_id: String,
    public_ip: String,
    url: String,
    instance_type: String,
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetManagedOnpremOutputsError {
    #[error("could not run tofu output command [{location}]")]
    RunCommand {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("tofu output exited with code {exit_code:?} [{location}]")]
    NonZeroExit {
        exit_code: Option<i32>,
        location: Location,
    },
    #[error("could not parse tofu output JSON [{location}]")]
    JsonParse {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("tofu output missing required field '{field}' [{location}]")]
    MissingField { field: String, location: Location },
}

#[tracing::instrument(skip_all, err)]
fn get_managed_onprem_tofu_outputs(
    work_dir: &Path,
) -> std::result::Result<ManagedOnPremTerraformOutputs, GetManagedOnpremOutputsError> {
    use GetManagedOnpremOutputsErrorCtx as Ctx;

    tracing::info!("Retrieving managed on-prem tofu outputs...");

    let output = dterror::ResultExt::with_context(
        run_with_timeout(
            Command::new("tofu")
                .args(["output", "-json", "-no-color"])
                .current_dir(work_dir),
            TOFU_TIMEOUT_SECS,
        ),
        Ctx::run_command(),
    )?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!("Tofu output failed: {}", stderr);
        return Err(GetManagedOnpremOutputsError::NonZeroExit {
            exit_code: output.status.code(),
            location: std::panic::Location::caller(),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let outputs: serde_json::Value =
        dterror::ResultExt::with_context(serde_json::from_str(&stdout), Ctx::json_parse())?;

    Ok(ManagedOnPremTerraformOutputs {
        launch_template_id: outputs["launch_template_id"]["value"]
            .as_str()
            .ok_or_else(|| GetManagedOnpremOutputsError::MissingField {
                field: "launch_template_id".to_string(),
                location: std::panic::Location::caller(),
            })?
            .to_string(),
        eip_allocation_id: outputs["eip_allocation_id"]["value"]
            .as_str()
            .ok_or_else(|| GetManagedOnpremOutputsError::MissingField {
                field: "eip_allocation_id".to_string(),
                location: std::panic::Location::caller(),
            })?
            .to_string(),
        public_ip: outputs["public_ip"]["value"]
            .as_str()
            .ok_or_else(|| GetManagedOnpremOutputsError::MissingField {
                field: "public_ip".to_string(),
                location: std::panic::Location::caller(),
            })?
            .to_string(),
        url: outputs["url"]["value"]
            .as_str()
            .ok_or_else(|| GetManagedOnpremOutputsError::MissingField {
                field: "url".to_string(),
                location: std::panic::Location::caller(),
            })?
            .to_string(),
        instance_type: outputs["instance_type"]["value"]
            .as_str()
            .unwrap_or("unknown")
            .to_string(),
    })
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum UpdateAsgLaunchTemplateError {
    #[error("could not update ASG launch template after retries [{location}]")]
    UpdateAsg {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not set ASG desired capacity [{location}]")]
    SetDesiredCapacity {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Update an existing ASG to use a new launch template
#[tracing::instrument(skip_all, err)]
async fn update_asg_launch_template(
    asg_name: &str,
    launch_template_id: &str,
    credentials: &AwsCredentials,
) -> std::result::Result<(), UpdateAsgLaunchTemplateError> {
    use UpdateAsgLaunchTemplateErrorCtx as Ctx;

    tracing::info!(
        "Updating ASG {} with launch template {}",
        asg_name,
        launch_template_id
    );

    let asg = crate::ec2::AsgClient::new(credentials);

    // Retry with backoff for IAM eventual consistency
    let mut last_err = None;
    for attempt in 0..5u32 {
        if attempt > 0 {
            let delay = std::time::Duration::from_secs(2u64.pow(attempt));
            tracing::info!(
                "Retrying ASG update in {:?} (attempt {}/5)",
                delay,
                attempt + 1
            );
            tokio::time::sleep(delay).await;
        }
        // TODO(error-infra): update_auto_scaling_group can fail with:
        //   Retryable:
        //     - HTTP 500/503: transient AWS service errors
        //     - HTTP 429 (Throttling): rate limit exceeded
        //     - Network/connection errors (reqwest send failure)
        //     - HTTP 403 with "not yet propagated": IAM eventual consistency (already handled by this retry loop)
        //   Non-retryable:
        //     - HTTP 400 ValidationError: ASG or launch template doesn't exist, invalid params
        //     - HTTP 403 AccessDenied: IAM policy permanently forbids the action
        //     - HTTP 400 ScalingActivityInProgress: must wait for current scaling to finish (retryable with longer backoff)
        match asg
            .update_auto_scaling_group(asg_name, launch_template_id)
            .await
        {
            Ok(_) => {
                last_err = None;
                break;
            }
            Err(e) => {
                tracing::warn!("ASG update attempt {} failed: {:?}", attempt + 1, e);
                last_err = Some(e);
            }
        }
    }
    if let Some(e) = last_err {
        return Err(UpdateAsgLaunchTemplateError::UpdateAsg {
            location: std::panic::Location::caller(),
            source: e.into(),
        });
    }

    tracing::info!("Successfully updated ASG launch template");

    dterror::ResultExt::with_context(
        asg.set_desired_capacity(asg_name, 1).await,
        Ctx::set_desired_capacity(),
    )?;

    tracing::info!("Successfully set ASG desired capacity to 1");

    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum WaitForAsgInstanceError {
    #[error("timeout waiting for instance in ASG [{location}]")]
    Timeout { location: Location },
    #[error("could not describe instances [{location}]")]
    DescribeInstances {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Wait for an instance to be running in the ASG and return its instance ID
#[tracing::instrument(skip_all, err)]
async fn wait_for_asg_instance(
    asg_name: &str,
    credentials: &AwsCredentials,
    timeout_secs: u64,
) -> std::result::Result<String, WaitForAsgInstanceError> {
    use WaitForAsgInstanceErrorCtx as Ctx;
    use std::time::{Duration, Instant};

    tracing::info!("Waiting for instance to be running in ASG {}...", asg_name);

    let ec2 = crate::ec2::Ec2Client::new(credentials);

    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    loop {
        if start.elapsed() > timeout {
            return Err(WaitForAsgInstanceError::Timeout {
                location: std::panic::Location::caller(),
            });
        }

        let instances = dterror::ResultExt::with_context(
            ec2.describe_instances(&[
                crate::ec2::Filter::new("tag:aws:autoscaling:groupName", &[asg_name]),
                crate::ec2::Filter::new("instance-state-name", &["running"]),
            ])
            .await,
            Ctx::describe_instances(),
        )?;

        if let Some(instance) = instances.first() {
            tracing::info!("Found running instance: {}", instance.instance_id);
            return Ok(instance.instance_id.clone());
        }

        tracing::debug!("No running instance found yet, waiting 10 seconds...");
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum AssociateEipWithInstanceError {
    #[error("could not associate EIP with instance [{location}]")]
    AssociateAddress {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Associate an Elastic IP with an instance
#[tracing::instrument(skip_all, err)]
async fn associate_eip_with_instance(
    allocation_id: &str,
    instance_id: &str,
    credentials: &AwsCredentials,
) -> std::result::Result<(), AssociateEipWithInstanceError> {
    use AssociateEipWithInstanceErrorCtx as Ctx;

    tracing::info!(
        "Associating EIP {} with instance {}",
        allocation_id,
        instance_id
    );

    let ec2 = crate::ec2::Ec2Client::new(credentials);
    dterror::ResultExt::with_context(
        ec2.associate_address(allocation_id, instance_id).await,
        Ctx::associate_address(),
    )?;

    tracing::info!("Successfully associated EIP with instance");

    Ok(())
}

#[tracing::instrument(skip_all, err)]
fn run_tofu_destroy(
    work_dir: &Path,
    resource_name: &str,
    credentials: Option<&AwsCredentials>,
) -> std::result::Result<(), TofuDestroyError> {
    use TofuDestroyErrorCtx as Ctx;

    tracing::info!("Running tofu destroy for {}...", resource_name);

    let mut cmd = Command::new("tofu");
    cmd.args(["destroy", "-auto-approve", "-no-color"])
        .current_dir(work_dir);

    if let Some(creds) = credentials {
        tracing::info!("Passing user credentials to AWS provider via environment variables");
        cmd.env("TF_VAR_provider_access_key", &creds.access_key_id);
        cmd.env("TF_VAR_provider_secret_key", &creds.secret_access_key);
        cmd.env("TF_VAR_provider_region", &creds.region);
    }

    let output = dterror::ResultExt::with_context(
        run_with_timeout(&mut cmd, TOFU_TIMEOUT_SECS),
        Ctx::run_command(),
    )?;

    if !output.status.success() {
        tracing::error!(
            exit_code = ?output.status.code(),
            stdout = %String::from_utf8_lossy(&output.stdout),
            stderr = %String::from_utf8_lossy(&output.stderr),
            "tofu destroy failed"
        );
        return Err(TofuDestroyError::NonZeroExit {
            exit_code: output.status.code(),
            location: std::panic::Location::caller(),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    tracing::debug!("Tofu destroy output: {}", stdout);

    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum UploadEifToS3Error {
    #[error("could not read EIF file [{location}]")]
    ReadFile {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not upload EIF to S3 [{location}]")]
    PutObject {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn upload_eif_to_s3(
    eif_path: &str,
    org_id: &Uuid,
    resource_id: &Uuid,
    aws_account_id: &str,
) -> std::result::Result<String, UploadEifToS3Error> {
    use UploadEifToS3ErrorCtx as Ctx;
    use aws_sdk_s3::primitives::ByteStream;

    tracing::info!("Uploading EIF to S3: {}", eif_path);

    let bucket_name = std::env::var("EIF_S3_BUCKET")
        .unwrap_or_else(|_| format!("caution-eif-storage-{}", aws_account_id));

    let s3_key = format!("eifs/{}/{}.eif", org_id, resource_id);

    let config = aws_config::load_from_env().await;
    let client = aws_sdk_s3::Client::new(&config);

    // TODO(error-infra): ByteStream::from_path can fail with:
    //   Non-retryable:
    //     - File not found: EIF build produced no output or path is wrong
    //     - Permission denied: filesystem permissions on the EIF artifact
    let body = dterror::ResultExt::with_context(
        ByteStream::from_path(Path::new(eif_path)).await,
        Ctx::read_file(),
    )?;

    // TODO(error-infra): S3 PutObject can fail with:
    //   Retryable:
    //     - HTTP 500/503 (InternalError/SlowDown): transient S3 errors
    //     - Network/connection errors or timeouts (large EIF files)
    //   Non-retryable:
    //     - HTTP 404 NoSuchBucket: EIF_S3_BUCKET misconfigured or bucket deleted
    //     - HTTP 403 AccessDenied: IAM role lacks s3:PutObject on this bucket/key
    //     - HTTP 400 EntityTooLarge: EIF exceeds S3 single-PUT 5GB limit (should use multipart)
    dterror::ResultExt::with_context(
        client
            .put_object()
            .bucket(&bucket_name)
            .key(&s3_key)
            .tagging(format!("org_id={}&resource_id={}", org_id, resource_id))
            .body(body)
            .send()
            .await,
        Ctx::put_object(),
    )?;

    let s3_path = format!("s3://{}/{}", bucket_name, s3_key);

    tracing::info!("EIF uploaded successfully to: {}", s3_path);

    Ok(s3_path)
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum UploadEifToCustomerBucketError {
    #[error("could not read EIF file [{location}]")]
    ReadFile {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not upload EIF to customer bucket after retries [{location}]")]
    PutObject {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn upload_eif_to_customer_bucket(
    eif_path: &str,
    resource_id: &Uuid,
    bucket_name: &str,
    credentials: &AwsCredentials,
) -> std::result::Result<String, UploadEifToCustomerBucketError> {
    use UploadEifToCustomerBucketErrorCtx as Ctx;
    use aws_sdk_s3::primitives::ByteStream;

    tracing::info!("Uploading EIF to customer bucket: {}", bucket_name);

    let s3_key = format!("{}.eif", resource_id);

    let creds = aws_sdk_s3::config::Credentials::new(
        &credentials.access_key_id,
        &credentials.secret_access_key,
        None,
        None,
        "caution-managed-onprem",
    );

    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(credentials.region.clone()))
        .credentials_provider(creds)
        .load()
        .await;

    let client = aws_sdk_s3::Client::new(&config);

    // Retry with backoff for IAM eventual consistency — newly created
    // credentials may not be usable immediately across all AWS endpoints.
    let mut last_err = None;
    for attempt in 0..5u32 {
        if attempt > 0 {
            let delay = std::time::Duration::from_secs(2u64.pow(attempt));
            tracing::info!(
                "Retrying EIF upload in {:?} (attempt {}/5)",
                delay,
                attempt + 1
            );
            tokio::time::sleep(delay).await;
        }

        let body = dterror::ResultExt::with_context(
            ByteStream::from_path(Path::new(eif_path)).await,
            Ctx::read_file(),
        )?;

        // TODO(error-infra): S3 PutObject to customer bucket can fail with:
        //   Retryable:
        //     - HTTP 500/503 (InternalError/SlowDown): transient S3 errors
        //     - HTTP 403 with IAM eventual consistency: newly created credentials not yet propagated (handled by this retry loop)
        //     - Network/connection errors or timeouts (large EIF files)
        //   Non-retryable:
        //     - HTTP 404 NoSuchBucket: customer-provided bucket doesn't exist
        //     - HTTP 403 AccessDenied: customer IAM role/policy permanently forbids s3:PutObject
        //     - HTTP 400 EntityTooLarge: EIF exceeds S3 single-PUT 5GB limit (should use multipart)
        //     - HTTP 400 InvalidBucketName: customer provided an invalid bucket name
        match client
            .put_object()
            .bucket(bucket_name)
            .key(&s3_key)
            .body(body)
            .send()
            .await
        {
            Ok(_) => {
                let s3_path = format!("s3://{}/{}", bucket_name, s3_key);
                tracing::info!("EIF uploaded successfully to customer bucket: {}", s3_path);
                return Ok(s3_path);
            }
            Err(e) => {
                tracing::warn!("EIF upload attempt {} failed: {:?}", attempt + 1, e);
                last_err = Some(e);
            }
        }
    }

    Err(UploadEifToCustomerBucketError::PutObject {
        location: std::panic::Location::caller(),
        source: last_err
            .expect("retry loop always executes at least once, so last_err is always Some")
            .into(),
    })
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum UploadEifFromPlatformS3Error {
    #[error("could not download EIF from platform bucket [{location}]")]
    GetObject {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not read EIF body from platform bucket [{location}]")]
    ReadBody {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not upload EIF to customer bucket [{location}]")]
    PutObject {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn upload_eif_from_platform_s3_to_customer_bucket(
    source_s3_key: &str,
    resource_id: &Uuid,
    bucket_name: &str,
    credentials: &AwsCredentials,
    aws_account_id: &str,
) -> std::result::Result<String, UploadEifFromPlatformS3Error> {
    use UploadEifFromPlatformS3ErrorCtx as Ctx;

    tracing::info!(
        "Copying EIF from platform bucket to customer bucket: source_key={}, bucket={}",
        source_s3_key,
        bucket_name
    );

    let source_bucket = std::env::var("EIF_S3_BUCKET")
        .unwrap_or_else(|_| format!("caution-eif-storage-{}", aws_account_id));
    let platform_config = aws_config::load_from_env().await;
    let platform_client = aws_sdk_s3::Client::new(&platform_config);

    let source_obj = dterror::ResultExt::with_context(
        platform_client
            .get_object()
            .bucket(&source_bucket)
            .key(source_s3_key)
            .send()
            .await,
        Ctx::get_object(),
    )?;

    let data = dterror::ResultExt::with_context(source_obj.body.collect().await, Ctx::read_body())?;

    let s3_key = format!("{}.eif", resource_id);

    let creds = aws_sdk_s3::config::Credentials::new(
        &credentials.access_key_id,
        &credentials.secret_access_key,
        None,
        None,
        "caution-managed-onprem",
    );

    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(credentials.region.clone()))
        .credentials_provider(creds)
        .load()
        .await;

    let client = aws_sdk_s3::Client::new(&config);

    dterror::ResultExt::with_context(
        client
            .put_object()
            .bucket(bucket_name)
            .key(&s3_key)
            .body(data.into_bytes().into())
            .send()
            .await,
        Ctx::put_object(),
    )?;

    let s3_path = format!("s3://{}/{}", bucket_name, s3_key);
    tracing::info!("EIF copied successfully to customer bucket: {}", s3_path);
    Ok(s3_path)
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ProvisionNitroEnclaveError {
    #[error("could not create temporary directory [{location}]")]
    TempDir {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not generate backend config [{location}]")]
    BackendConfig {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not generate main.tf [{location}]")]
    GenerateMainTf {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not read user-data.sh template [{location}]")]
    ReadUserData {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not write user-data.sh [{location}]")]
    WriteUserData {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not run tofu init [{location}]")]
    TofuInit {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not run tofu apply [{location}]")]
    TofuApply {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not get tofu outputs [{location}]")]
    GetOutputs {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn provision_nitro_enclave(
    request: &NitroDeploymentRequest,
    eif_s3_path: &str,
    config: &TerraformConfig,
) -> std::result::Result<DeploymentResult, ProvisionNitroEnclaveError> {
    use ProvisionNitroEnclaveErrorCtx as Ctx;

    tracing::info!(
        "Starting Terraform Nitro Enclave provisioning for resource: {}",
        request.resource_name
    );
    tracing::info!(
        "Deployment config - domain: {:?}, memory: {}MB, cpus: {}, debug: {}, ports: {:?}",
        request.domain,
        request.memory_mb,
        request.cpu_count,
        request.debug_mode,
        request.ports
    );

    if request.credentials.is_some() {
        tracing::info!(
            "Using user-provided AWS credentials for provider (Caution credentials for state backend)"
        );
    }

    let temp_dir = dterror::ResultExt::with_context(TempDir::new(), Ctx::temp_dir())?;
    let work_dir = temp_dir.path();

    dterror::ResultExt::with_context(
        generate_backend_config(
            work_dir,
            request.org_id,
            request.resource_id,
            &config.s3_bucket,
        )
        .await,
        Ctx::backend_config(),
    )?;

    dterror::ResultExt::with_context(
        generate_nitro_deployment_main_tf(work_dir, request, eif_s3_path).await,
        Ctx::generate_main_tf(),
    )?;

    let user_data_template = dterror::ResultExt::with_context(
        std::fs::read_to_string(config.module_path.join("user-data.sh")),
        Ctx::read_user_data(),
    )?;
    dterror::ResultExt::with_context(
        std::fs::write(work_dir.join("user-data.sh"), user_data_template),
        Ctx::write_user_data(),
    )?;

    // Always use Caution's env credentials for init (S3 state backend access)
    let data_dir =
        std::env::var("CAUTION_DATA_DIR").unwrap_or_else(|_| "/var/cache/caution".to_string());
    let lockfile_path = get_or_generate_lockfile(&data_dir).await;
    dterror::ResultExt::with_context(
        run_tofu_init(work_dir, lockfile_path.as_deref(), None).await,
        Ctx::tofu_init(),
    )?;

    // Pass user credentials as Terraform variables, not env vars
    // This keeps Caution's creds for S3 state but uses user's creds for AWS provider
    dterror::ResultExt::with_context(
        run_tofu_apply_with_provider_creds(
            work_dir,
            &request.resource_name,
            &request.ports,
            request.http_port,
            request.credentials.as_ref(),
        ),
        Ctx::tofu_apply(),
    )?;

    let result = dterror::ResultExt::with_context(get_tofu_outputs(work_dir), Ctx::get_outputs())?;

    tracing::info!(
        "Successfully provisioned Nitro Enclave for resource {} at {}",
        request.resource_name,
        result.public_ip
    );

    Ok(result)
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ProvisionManagedOnpremError {
    #[error("missing managed_onprem config [{location}]")]
    MissingConfig { location: Location },
    #[error("could not create temporary directory [{location}]")]
    TempDir {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not generate backend config [{location}]")]
    BackendConfig {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not generate main.tf [{location}]")]
    GenerateMainTf {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not read user-data.sh template [{location}]")]
    ReadUserData {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not write user-data.sh [{location}]")]
    WriteUserData {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not run tofu init [{location}]")]
    TofuInit {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not run tofu apply [{location}]")]
    TofuApply {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not get tofu outputs [{location}]")]
    GetOutputs {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("missing AWS credentials for managed on-prem deployment [{location}]")]
    MissingCredentials { location: Location },
    #[error("could not update ASG [{location}]")]
    UpdateAsg {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not wait for instance [{location}]")]
    WaitForInstance {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not associate EIP [{location}]")]
    AssociateEip {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn provision_managed_onprem(
    request: &NitroDeploymentRequest,
    eif_s3_path: &str,
    config: &TerraformConfig,
) -> std::result::Result<DeploymentResult, ProvisionManagedOnpremError> {
    use ProvisionManagedOnpremErrorCtx as Ctx;

    let onprem =
        request
            .managed_onprem
            .as_ref()
            .ok_or(ProvisionManagedOnpremError::MissingConfig {
                location: std::panic::Location::caller(),
            })?;

    tracing::info!(
        "Starting managed on-prem deployment for resource: {} (deployment_id: {})",
        request.resource_name,
        onprem.deployment_id
    );

    let temp_dir = dterror::ResultExt::with_context(TempDir::new(), Ctx::temp_dir())?;
    let work_dir = temp_dir.path();

    dterror::ResultExt::with_context(
        generate_backend_config(
            work_dir,
            request.org_id,
            request.resource_id,
            &config.s3_bucket,
        )
        .await,
        Ctx::backend_config(),
    )?;

    dterror::ResultExt::with_context(
        generate_managed_onprem_deployment_tf(work_dir, request, eif_s3_path).await,
        Ctx::generate_main_tf(),
    )?;

    let user_data_template = dterror::ResultExt::with_context(
        std::fs::read_to_string(config.module_path.join("user-data.sh")),
        Ctx::read_user_data(),
    )?;
    dterror::ResultExt::with_context(
        std::fs::write(work_dir.join("user-data.sh"), user_data_template),
        Ctx::write_user_data(),
    )?;

    let data_dir =
        std::env::var("CAUTION_DATA_DIR").unwrap_or_else(|_| "/var/cache/caution".to_string());
    let lockfile_path = get_or_generate_lockfile(&data_dir).await;
    dterror::ResultExt::with_context(
        run_tofu_init(work_dir, lockfile_path.as_deref(), None).await,
        Ctx::tofu_init(),
    )?;

    dterror::ResultExt::with_context(
        run_tofu_apply_with_provider_creds(
            work_dir,
            &request.resource_name,
            &request.ports,
            request.http_port,
            request.credentials.as_ref(),
        ),
        Ctx::tofu_apply(),
    )?;

    let tf_outputs = dterror::ResultExt::with_context(
        get_managed_onprem_tofu_outputs(work_dir),
        Ctx::get_outputs(),
    )?;

    tracing::info!(
        "Terraform created launch template {} and EIP {}",
        tf_outputs.launch_template_id,
        tf_outputs.eip_allocation_id
    );

    let credentials =
        request
            .credentials
            .as_ref()
            .ok_or(ProvisionManagedOnpremError::MissingCredentials {
                location: std::panic::Location::caller(),
            })?;

    dterror::ResultExt::with_context(
        update_asg_launch_template(
            &onprem.asg_name,
            &tf_outputs.launch_template_id,
            credentials,
        )
        .await,
        Ctx::update_asg(),
    )?;

    let instance_id = dterror::ResultExt::with_context(
        wait_for_asg_instance(&onprem.asg_name, credentials, 300).await,
        Ctx::wait_for_instance(),
    )?;

    dterror::ResultExt::with_context(
        associate_eip_with_instance(&tf_outputs.eip_allocation_id, &instance_id, credentials).await,
        Ctx::associate_eip(),
    )?;

    let result = DeploymentResult {
        instance_id,
        public_ip: tf_outputs.public_ip,
        url: tf_outputs.url,
        instance_type: Some(tf_outputs.instance_type),
    };

    tracing::info!(
        "Successfully provisioned managed on-prem Nitro Enclave for resource {} at {}",
        request.resource_name,
        result.public_ip
    );

    Ok(result)
}

const PARENT_VCPU_RESERVE: u32 = 2;
const PARENT_MEMORY_RESERVE_MIB: u32 = 2 * 1024;

// AWS documents Nitro Enclaves support for these virtual M5 and R6i sizes.
// Entries are (instance type, vCPUs, memory MiB), ordered by capacity.
const NITRO_INSTANCE_SPECS: &[(&str, u32, u32)] = &[
    ("m5.xlarge", 4, 16 * 1024),
    ("r6i.xlarge", 4, 32 * 1024),
    ("m5.2xlarge", 8, 32 * 1024),
    ("r6i.2xlarge", 8, 64 * 1024),
    ("m5.4xlarge", 16, 64 * 1024),
    ("r6i.4xlarge", 16, 128 * 1024),
    ("m5.8xlarge", 32, 128 * 1024),
    ("r6i.8xlarge", 32, 256 * 1024),
    ("r6i.12xlarge", 48, 384 * 1024),
];

pub(crate) struct EnclaveSizing {
    pub(crate) cpu_count: u32,
    pub(crate) instance_type: &'static str,
    pub(crate) host_vcpus: u32,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum EnclaveSizingError {
    #[error("Enclave vCPU count must be at least 1 [{location}]")]
    ZeroCpu { location: dterror::Location },
    #[error("Enclave memory_mb must be at least 1 [{location}]")]
    ZeroMemory { location: dterror::Location },
    #[error("Enclave resource request is too large [{location}]")]
    Overflow { location: dterror::Location },
    #[error(
        "Requested enclave resources ({cpu_count} vCPUs, {memory_mb} MiB) exceed the supported r6i.12xlarge host capacity [{location}]"
    )]
    NoSupportedInstance {
        cpu_count: u32,
        memory_mb: u32,
        location: dterror::Location,
    },
}

#[tracing::instrument(skip_all, err)]
pub(crate) fn enclave_sizing(
    cpu_count: u32,
    memory_mb: u32,
) -> std::result::Result<EnclaveSizing, EnclaveSizingError> {
    if cpu_count == 0 {
        return Err(EnclaveSizingError::ZeroCpu {
            location: std::panic::Location::caller(),
        });
    }
    if memory_mb == 0 {
        return Err(EnclaveSizingError::ZeroMemory {
            location: std::panic::Location::caller(),
        });
    }

    let cpu_count_rounded =
        cpu_count
            .checked_add(cpu_count % 2)
            .ok_or(EnclaveSizingError::Overflow {
                location: std::panic::Location::caller(),
            })?;
    let total_vcpus_needed =
        cpu_count_rounded
            .checked_add(PARENT_VCPU_RESERVE)
            .ok_or(EnclaveSizingError::Overflow {
                location: std::panic::Location::caller(),
            })?;
    let total_memory_mib_needed =
        memory_mb
            .checked_add(PARENT_MEMORY_RESERVE_MIB)
            .ok_or(EnclaveSizingError::Overflow {
                location: std::panic::Location::caller(),
            })?;

    let (instance_type, host_vcpus, _) = *NITRO_INSTANCE_SPECS
        .iter()
        .find(|spec| spec.1 >= total_vcpus_needed && spec.2 >= total_memory_mib_needed)
        .ok_or(EnclaveSizingError::NoSupportedInstance {
            cpu_count,
            memory_mb,
            location: std::panic::Location::caller(),
        })?;

    Ok(EnclaveSizing {
        cpu_count: cpu_count_rounded,
        instance_type,
        host_vcpus,
    })
}

pub(crate) fn host_vcpus_for_instance_type(instance_type: &str) -> Option<u32> {
    let size = instance_type.split('.').next_back()?;

    match size {
        "nano" | "micro" | "small" | "medium" => Some(2),
        "large" => Some(2),
        "xlarge" => Some(4),
        "metal" => Some(96),
        size if size.ends_with("xlarge") => {
            let multiplier = size.trim_end_matches("xlarge").parse::<u32>().ok()?;
            Some(multiplier * 4)
        }
        _ => None,
    }
}

#[tracing::instrument(skip_all, err)]
fn compute_enclave_sizing(
    request: &NitroDeploymentRequest,
) -> std::result::Result<(u32, &'static str), EnclaveSizingError> {
    let sizing = enclave_sizing(request.cpu_count, request.memory_mb)?;

    if sizing.cpu_count != request.cpu_count {
        tracing::warn!(
            "Rounded CPU count from {} to {} (Nitro Enclaves requires even numbers)",
            request.cpu_count,
            sizing.cpu_count
        );
    }

    tracing::info!(
        "Selected instance type {} for {} CPUs and {} MB memory (total needed: {} vCPUs, {} GB)",
        sizing.instance_type,
        sizing.cpu_count,
        request.memory_mb,
        sizing.cpu_count + 2,
        (request.memory_mb / 1024) + 2
    );

    Ok((sizing.cpu_count, sizing.instance_type))
}

fn platform_internal_ingress(e2e: bool, locksmith: bool) -> Vec<hcl::Block> {
    let mut blocks = Vec::new();

    if e2e {
        blocks.push(
            hcl::Block::builder("ingress")
                .add_attribute(("from_port", 49500u64))
                .add_attribute(("to_port", 49500u64))
                .add_attribute(("protocol", "tcp"))
                .add_attribute((
                    "cidr_blocks",
                    hcl::Expression::Array(vec![hcl::Expression::String("0.0.0.0/0".into())]),
                ))
                .add_attribute(("description", "Allow STEVE encrypted transport"))
                .build(),
        );
    }

    if locksmith {
        blocks.push(
            hcl::Block::builder("ingress")
                .add_attribute(("from_port", 49504u64))
                .add_attribute(("to_port", 49504u64))
                .add_attribute(("protocol", "tcp"))
                .add_attribute((
                    "cidr_blocks",
                    hcl::Expression::Array(vec![hcl::Expression::String("0.0.0.0/0".into())]),
                ))
                .add_attribute(("description", "Allow Locksmith shard receiver"))
                .build(),
        );
    }

    blocks
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GenerateMainTfError {
    #[error("deployment region is required [{location}]")]
    MissingRegion { location: Location },
    #[error("could not compute enclave sizing [{location}]")]
    Sizing {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not serialize main.tf [{location}]")]
    Serialize {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not write main.tf [{location}]")]
    Write {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn generate_nitro_deployment_main_tf(
    work_dir: &Path,
    request: &NitroDeploymentRequest,
    eif_s3_path: &str,
) -> std::result::Result<(), GenerateMainTfError> {
    use GenerateMainTfErrorCtx as Ctx;

    let aws_region = request
        .credentials
        .as_ref()
        .map(|c| c.region.clone())
        .or_else(|| request.region.clone())
        .ok_or_else(|| GenerateMainTfError::MissingRegion {
            location: std::panic::Location::caller(),
        })?;
    let ssh_key_name = std::env::var("SSH_KEY_NAME").ok();

    let (cpu_count_rounded, instance_type) =
        dterror::ResultExt::with_context(compute_enclave_sizing(request), Ctx::sizing())?;

    let short_id: String = request.resource_id.to_string()[..8].to_owned();
    let resource_id_str = request.resource_id.to_string();
    let org_id_str = request.org_id.to_string();

    let eif_bucket = std::env::var("EIF_S3_BUCKET")
        .unwrap_or_else(|_| format!("caution-eif-storage-{}", request.aws_account_id));

    let mut body = hcl::Body::builder();

    // terraform block
    body = body.add_block(
        hcl::Block::builder("terraform")
            .add_attribute(("required_version", ">= 1.0"))
            .add_block(
                hcl::Block::builder("required_providers")
                    .add_attribute((
                        "aws",
                        hcl::Expression::Object(
                            vec![
                                (
                                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                        "source",
                                    )),
                                    hcl::Expression::String("hashicorp/aws".into()),
                                ),
                                (
                                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                        "version",
                                    )),
                                    hcl::Expression::String("~> 5.0".into()),
                                ),
                            ]
                            .into_iter()
                            .collect(),
                        ),
                    ))
                    .build(),
            )
            .build(),
    );

    // provider section
    if request.credentials.is_some() {
        body = body
            .add_block(
                hcl::Block::builder("variable")
                    .add_label("provider_access_key")
                    .add_attribute(("type", "string"))
                    .add_attribute(("sensitive", true))
                    .add_attribute(("default", ""))
                    .build(),
            )
            .add_block(
                hcl::Block::builder("variable")
                    .add_label("provider_secret_key")
                    .add_attribute(("type", "string"))
                    .add_attribute(("sensitive", true))
                    .add_attribute(("default", ""))
                    .build(),
            )
            .add_block(
                hcl::Block::builder("variable")
                    .add_label("provider_region")
                    .add_attribute(("type", "string"))
                    .add_attribute(("default", ""))
                    .build(),
            );

        let provider_block = hcl::Block::builder("provider")
            .add_label("aws")
            .add_attribute(hcl::Attribute::new(
                "region",
                hcl::expr::Conditional::new(
                    hcl::expr::BinaryOp::new(
                        hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("var"))
                            .attr("provider_region")
                            .build(),
                        hcl::expr::BinaryOperator::NotEq,
                        hcl::Expression::String(String::new()),
                    ),
                    hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("var"))
                        .attr("provider_region")
                        .build(),
                    hcl::Expression::String(aws_region.clone()),
                ),
            ))
            .add_attribute(hcl::Attribute::new(
                "access_key",
                hcl::expr::Conditional::new(
                    hcl::expr::BinaryOp::new(
                        hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("var"))
                            .attr("provider_access_key")
                            .build(),
                        hcl::expr::BinaryOperator::NotEq,
                        hcl::Expression::String(String::new()),
                    ),
                    hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("var"))
                        .attr("provider_access_key")
                        .build(),
                    hcl::Expression::Null,
                ),
            ))
            .add_attribute(hcl::Attribute::new(
                "secret_key",
                hcl::expr::Conditional::new(
                    hcl::expr::BinaryOp::new(
                        hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("var"))
                            .attr("provider_secret_key")
                            .build(),
                        hcl::expr::BinaryOperator::NotEq,
                        hcl::Expression::String(String::new()),
                    ),
                    hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("var"))
                        .attr("provider_secret_key")
                        .build(),
                    hcl::Expression::Null,
                ),
            ))
            .add_block(
                hcl::Block::builder("default_tags")
                    .add_attribute((
                        "tags",
                        hcl::Expression::Object(
                            vec![
                                (
                                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                        "org_id",
                                    )),
                                    hcl::Expression::String(org_id_str.clone()),
                                ),
                                (
                                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                        "ManagedBy",
                                    )),
                                    hcl::Expression::String("caution+tofu".into()),
                                ),
                            ]
                            .into_iter()
                            .collect(),
                        ),
                    ))
                    .build(),
            )
            .build();
        body = body.add_block(provider_block);
    } else {
        body = body.add_block(
            hcl::Block::builder("provider")
                .add_label("aws")
                .add_attribute(("region", aws_region.as_str()))
                .add_block(
                    hcl::Block::builder("default_tags")
                        .add_attribute((
                            "tags",
                            hcl::Expression::Object(
                                vec![
                                    (
                                        hcl::expr::ObjectKey::Identifier(
                                            hcl::Identifier::unchecked("org_id"),
                                        ),
                                        hcl::Expression::String(org_id_str.clone()),
                                    ),
                                    (
                                        hcl::expr::ObjectKey::Identifier(
                                            hcl::Identifier::unchecked("ManagedBy"),
                                        ),
                                        hcl::Expression::String("caution+tofu".into()),
                                    ),
                                ]
                                .into_iter()
                                .collect(),
                            ),
                        ))
                        .build(),
                )
                .build(),
        );
    }

    // data "aws_availability_zones" "available"
    body = body.add_block(
        hcl::Block::builder("data")
            .add_label("aws_availability_zones")
            .add_label("available")
            .add_attribute(("state", "available"))
            .build(),
    );

    // data "aws_ec2_instance_type_offerings" "enclave"
    body = body.add_block(
        hcl::Block::builder("data")
            .add_label("aws_ec2_instance_type_offerings")
            .add_label("enclave")
            .add_attribute(("location_type", "availability-zone"))
            .add_block(
                hcl::Block::builder("filter")
                    .add_attribute(("name", "instance-type"))
                    .add_attribute((
                        "values",
                        hcl::Expression::Array(vec![hcl::Expression::String(instance_type.into())]),
                    ))
                    .build(),
            )
            .add_block(
                hcl::Block::builder("filter")
                    .add_attribute(("name", "location"))
                    .add_attribute((
                        "values",
                        hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("data"))
                            .attr("aws_availability_zones")
                            .attr("available")
                            .attr("names")
                            .build(),
                    ))
                    .build(),
            )
            .build(),
    );

    // data "aws_ami" "amazon_linux_2023"
    body = body.add_block(
        hcl::Block::builder("data")
            .add_label("aws_ami")
            .add_label("amazon_linux_2023")
            .add_attribute(("most_recent", true))
            .add_attribute((
                "owners",
                hcl::Expression::Array(vec![hcl::Expression::String("amazon".into())]),
            ))
            .add_block(
                hcl::Block::builder("filter")
                    .add_attribute(("name", "name"))
                    .add_attribute((
                        "values",
                        hcl::Expression::Array(vec![hcl::Expression::String(
                            "al2023-ami-*-x86_64".into(),
                        )]),
                    ))
                    .build(),
            )
            .add_block(
                hcl::Block::builder("filter")
                    .add_attribute(("name", "virtualization-type"))
                    .add_attribute((
                        "values",
                        hcl::Expression::Array(vec![hcl::Expression::String("hvm".into())]),
                    ))
                    .build(),
            )
            .add_block(
                hcl::Block::builder("filter")
                    .add_attribute(("name", "root-device-type"))
                    .add_attribute((
                        "values",
                        hcl::Expression::Array(vec![hcl::Expression::String("ebs".into())]),
                    ))
                    .build(),
            )
            .build(),
    );

    // resource "aws_iam_role" "enclave"
    body = body.add_block(
        hcl::Block::builder("resource")
            .add_label("aws_iam_role")
            .add_label("enclave")
            .add_attribute(("name_prefix", format!("enclave-{short_id}-")))
            .add_attribute(hcl::Attribute::new(
                "assume_role_policy",
                hcl::expr::FuncCall::builder("jsonencode")
                    .arg(hcl::Expression::Object(
                        vec![
                            (
                                hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                    "Version",
                                )),
                                hcl::Expression::String("2012-10-17".into()),
                            ),
                            (
                                hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                    "Statement",
                                )),
                                hcl::Expression::Array(vec![hcl::Expression::Object(
                                    vec![
                                        (
                                            hcl::expr::ObjectKey::Identifier(
                                                hcl::Identifier::unchecked("Action"),
                                            ),
                                            hcl::Expression::String("sts:AssumeRole".into()),
                                        ),
                                        (
                                            hcl::expr::ObjectKey::Identifier(
                                                hcl::Identifier::unchecked("Effect"),
                                            ),
                                            hcl::Expression::String("Allow".into()),
                                        ),
                                        (
                                            hcl::expr::ObjectKey::Identifier(
                                                hcl::Identifier::unchecked("Principal"),
                                            ),
                                            hcl::Expression::Object(
                                                vec![(
                                                    hcl::expr::ObjectKey::Identifier(
                                                        hcl::Identifier::unchecked("Service"),
                                                    ),
                                                    hcl::Expression::String(
                                                        "ec2.amazonaws.com".into(),
                                                    ),
                                                )]
                                                .into_iter()
                                                .collect(),
                                            ),
                                        ),
                                    ]
                                    .into_iter()
                                    .collect(),
                                )]),
                            ),
                        ]
                        .into_iter()
                        .collect(),
                    ))
                    .build(),
            ))
            .add_attribute((
                "tags",
                hcl::Expression::Object(
                    vec![
                        (
                            hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked("Name")),
                            hcl::Expression::String(format!("enclave-role-{resource_id_str}")),
                        ),
                        (
                            hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                "ResourceId",
                            )),
                            hcl::Expression::String(resource_id_str.clone()),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ))
            .build(),
    );

    // resource "aws_iam_role_policy" "enclave_s3"
    body = body.add_block(
        hcl::Block::builder("resource")
            .add_label("aws_iam_role_policy")
            .add_label("enclave_s3")
            .add_attribute(("name_prefix", format!("enclave-s3-{short_id}-")))
            .add_attribute((
                "role",
                hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("aws_iam_role"))
                    .attr("enclave")
                    .attr("id")
                    .build(),
            ))
            .add_attribute(hcl::Attribute::new(
                "policy",
                hcl::expr::FuncCall::builder("jsonencode")
                    .arg(hcl::Expression::Object(
                        vec![
                            (
                                hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                    "Version",
                                )),
                                hcl::Expression::String("2012-10-17".into()),
                            ),
                            (
                                hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                    "Statement",
                                )),
                                hcl::Expression::Array(vec![hcl::Expression::Object(
                                    vec![
                                        (
                                            hcl::expr::ObjectKey::Identifier(
                                                hcl::Identifier::unchecked("Effect"),
                                            ),
                                            hcl::Expression::String("Allow".into()),
                                        ),
                                        (
                                            hcl::expr::ObjectKey::Identifier(
                                                hcl::Identifier::unchecked("Action"),
                                            ),
                                            hcl::Expression::Array(vec![hcl::Expression::String(
                                                "s3:GetObject".into(),
                                            )]),
                                        ),
                                        (
                                            hcl::expr::ObjectKey::Identifier(
                                                hcl::Identifier::unchecked("Resource"),
                                            ),
                                            hcl::Expression::Array(vec![hcl::Expression::String(
                                                format!(
                                                    "arn:aws:s3:::{eif_bucket}/eifs/{org_id_str}/*"
                                                ),
                                            )]),
                                        ),
                                    ]
                                    .into_iter()
                                    .collect(),
                                )]),
                            ),
                        ]
                        .into_iter()
                        .collect(),
                    ))
                    .build(),
            ))
            .build(),
    );

    // resource "aws_iam_instance_profile" "enclave"
    body = body.add_block(
        hcl::Block::builder("resource")
            .add_label("aws_iam_instance_profile")
            .add_label("enclave")
            .add_attribute(("name_prefix", format!("enclave-{short_id}-")))
            .add_attribute((
                "role",
                hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("aws_iam_role"))
                    .attr("enclave")
                    .attr("name")
                    .build(),
            ))
            .add_attribute((
                "tags",
                hcl::Expression::Object(
                    vec![
                        (
                            hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked("Name")),
                            hcl::Expression::String(format!("enclave-profile-{resource_id_str}")),
                        ),
                        (
                            hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                "ResourceId",
                            )),
                            hcl::Expression::String(resource_id_str.clone()),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ))
            .build(),
    );

    // resource "aws_vpc" "enclave"
    body = body.add_block(
        hcl::Block::builder("resource")
            .add_label("aws_vpc")
            .add_label("enclave")
            .add_attribute(("cidr_block", "10.0.0.0/16"))
            .add_attribute(("enable_dns_hostnames", true))
            .add_attribute(("enable_dns_support", true))
            .add_attribute((
                "tags",
                hcl::Expression::Object(
                    vec![
                        (
                            hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked("Name")),
                            hcl::Expression::String(format!("vpc-{resource_id_str}")),
                        ),
                        (
                            hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                "ResourceId",
                            )),
                            hcl::Expression::String(resource_id_str.clone()),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ))
            .build(),
    );

    // resource "aws_internet_gateway" "enclave"
    body = body.add_block(
        hcl::Block::builder("resource")
            .add_label("aws_internet_gateway")
            .add_label("enclave")
            .add_attribute((
                "vpc_id",
                hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("aws_vpc"))
                    .attr("enclave")
                    .attr("id")
                    .build(),
            ))
            .add_attribute((
                "tags",
                hcl::Expression::Object(
                    vec![
                        (
                            hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked("Name")),
                            hcl::Expression::String(format!("igw-{resource_id_str}")),
                        ),
                        (
                            hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                "ResourceId",
                            )),
                            hcl::Expression::String(resource_id_str.clone()),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ))
            .build(),
    );

    // resource "aws_subnet" "enclave"
    body = body.add_block(
        hcl::Block::builder("resource")
            .add_label("aws_subnet")
            .add_label("enclave")
            .add_attribute((
                "vpc_id",
                hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("aws_vpc"))
                    .attr("enclave")
                    .attr("id")
                    .build(),
            ))
            .add_attribute(("cidr_block", "10.0.1.0/24"))
            .add_attribute(("map_public_ip_on_launch", true))
            .add_attribute(hcl::Attribute::new(
                "availability_zone",
                hcl::expr::Traversal::builder(
                    hcl::expr::FuncCall::builder("sort")
                        .arg(
                            hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("data"))
                                .attr("aws_ec2_instance_type_offerings")
                                .attr("enclave")
                                .attr("locations")
                                .build(),
                        )
                        .build(),
                )
                .index(0u64)
                .build(),
            ))
            .add_attribute((
                "tags",
                hcl::Expression::Object(
                    vec![
                        (
                            hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked("Name")),
                            hcl::Expression::String(format!("subnet-{resource_id_str}")),
                        ),
                        (
                            hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                "ResourceId",
                            )),
                            hcl::Expression::String(resource_id_str.clone()),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ))
            .build(),
    );

    // resource "aws_route_table" "enclave"
    body = body.add_block(
        hcl::Block::builder("resource")
            .add_label("aws_route_table")
            .add_label("enclave")
            .add_attribute((
                "vpc_id",
                hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("aws_vpc"))
                    .attr("enclave")
                    .attr("id")
                    .build(),
            ))
            .add_block(
                hcl::Block::builder("route")
                    .add_attribute(("cidr_block", "0.0.0.0/0"))
                    .add_attribute((
                        "gateway_id",
                        hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked(
                            "aws_internet_gateway",
                        ))
                        .attr("enclave")
                        .attr("id")
                        .build(),
                    ))
                    .build(),
            )
            .add_attribute((
                "tags",
                hcl::Expression::Object(
                    vec![
                        (
                            hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked("Name")),
                            hcl::Expression::String(format!("rt-{resource_id_str}")),
                        ),
                        (
                            hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                "ResourceId",
                            )),
                            hcl::Expression::String(resource_id_str.clone()),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ))
            .build(),
    );

    // resource "aws_route_table_association" "enclave"
    body = body.add_block(
        hcl::Block::builder("resource")
            .add_label("aws_route_table_association")
            .add_label("enclave")
            .add_attribute((
                "subnet_id",
                hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("aws_subnet"))
                    .attr("enclave")
                    .attr("id")
                    .build(),
            ))
            .add_attribute((
                "route_table_id",
                hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("aws_route_table"))
                    .attr("enclave")
                    .attr("id")
                    .build(),
            ))
            .build(),
    );

    // variable "ports"
    body = body.add_block(
        hcl::Block::builder("variable")
            .add_label("ports")
            .add_attribute((
                "type",
                hcl::expr::FuncCall::builder("list")
                    .arg(hcl::Expression::from(hcl::expr::Variable::unchecked(
                        "number",
                    )))
                    .build(),
            ))
            .add_attribute(("default", hcl::Expression::Array(vec![])))
            .build(),
    );

    // variable "http_port"
    body = body.add_block(
        hcl::Block::builder("variable")
            .add_label("http_port")
            .add_attribute(("type", "number"))
            .add_attribute(("default", 0u64))
            .build(),
    );

    // resource "aws_security_group" "enclave"
    let mut sg_builder = hcl::Block::builder("resource")
        .add_label("aws_security_group")
        .add_label("enclave")
        .add_attribute(("name_prefix", format!("enclave-{short_id}-")))
        .add_attribute((
            "description",
            format!("Security group for {resource_id_str} Nitro Enclave"),
        ))
        .add_attribute((
            "vpc_id",
            hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("aws_vpc"))
                .attr("enclave")
                .attr("id")
                .build(),
        ));

    // SSH ingress (only when ssh_keys non-empty)
    if !request.ssh_keys.is_empty() {
        sg_builder = sg_builder.add_block(
            hcl::Block::builder("ingress")
                .add_attribute(("from_port", 22u64))
                .add_attribute(("to_port", 22u64))
                .add_attribute(("protocol", "tcp"))
                .add_attribute((
                    "cidr_blocks",
                    hcl::Expression::Array(vec![hcl::Expression::String("0.0.0.0/0".into())]),
                ))
                .add_attribute(("description", "Allow SSH"))
                .build(),
        );
    }

    // HTTP ingress
    sg_builder = sg_builder.add_block(
        hcl::Block::builder("ingress")
            .add_attribute(("from_port", 80u64))
            .add_attribute(("to_port", 80u64))
            .add_attribute(("protocol", "tcp"))
            .add_attribute((
                "cidr_blocks",
                hcl::Expression::Array(vec![hcl::Expression::String("0.0.0.0/0".into())]),
            ))
            .add_attribute(("description", "Allow HTTP"))
            .build(),
    );

    // HTTPS ingress
    sg_builder = sg_builder.add_block(
        hcl::Block::builder("ingress")
            .add_attribute(("from_port", 443u64))
            .add_attribute(("to_port", 443u64))
            .add_attribute(("protocol", "tcp"))
            .add_attribute((
                "cidr_blocks",
                hcl::Expression::Array(vec![hcl::Expression::String("0.0.0.0/0".into())]),
            ))
            .add_attribute(("description", "Allow HTTPS"))
            .build(),
    );

    // platform internal ingress blocks
    for block in platform_internal_ingress(request.e2e, request.locksmith) {
        sg_builder = sg_builder.add_block(block);
    }

    // dynamic "ingress" block
    sg_builder = sg_builder.add_block(
        hcl::Block::builder("dynamic")
            .add_label("ingress")
            .add_attribute((
                "for_each",
                hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("var"))
                    .attr("ports")
                    .build(),
            ))
            .add_block(
                hcl::Block::builder("content")
                    .add_attribute((
                        "from_port",
                        hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("ingress"))
                            .attr("value")
                            .build(),
                    ))
                    .add_attribute((
                        "to_port",
                        hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("ingress"))
                            .attr("value")
                            .build(),
                    ))
                    .add_attribute(("protocol", "tcp"))
                    .add_attribute((
                        "cidr_blocks",
                        hcl::Expression::Array(vec![hcl::Expression::String("0.0.0.0/0".into())]),
                    ))
                    .add_attribute(hcl::Attribute::new(
                        "description",
                        hcl::expr::TemplateExpr::from(
                            "Allow user port ${ingress.value}".to_string(),
                        ),
                    ))
                    .build(),
            )
            .build(),
    );

    // egress block
    sg_builder = sg_builder.add_block(
        hcl::Block::builder("egress")
            .add_attribute(("from_port", 0u64))
            .add_attribute(("to_port", 0u64))
            .add_attribute(("protocol", "-1"))
            .add_attribute((
                "cidr_blocks",
                hcl::Expression::Array(vec![hcl::Expression::String("0.0.0.0/0".into())]),
            ))
            .add_attribute(("description", "Allow all outbound"))
            .build(),
    );

    // security group tags
    sg_builder = sg_builder.add_attribute((
        "tags",
        hcl::Expression::Object(
            vec![
                (
                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked("Name")),
                    hcl::Expression::String(format!("enclave-{resource_id_str}")),
                ),
                (
                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked("ResourceId")),
                    hcl::Expression::String(resource_id_str.clone()),
                ),
            ]
            .into_iter()
            .collect(),
        ),
    ));

    body = body.add_block(sg_builder.build());

    // resource "aws_instance" "enclave"
    let mut instance_builder = hcl::Block::builder("resource")
        .add_label("aws_instance")
        .add_label("enclave")
        .add_attribute((
            "ami",
            hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("data"))
                .attr("aws_ami")
                .attr("amazon_linux_2023")
                .attr("id")
                .build(),
        ))
        .add_attribute(("instance_type", instance_type))
        .add_attribute((
            "iam_instance_profile",
            hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked(
                "aws_iam_instance_profile",
            ))
            .attr("enclave")
            .attr("name")
            .build(),
        ))
        .add_attribute((
            "vpc_security_group_ids",
            hcl::Expression::Array(vec![
                hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("aws_security_group"))
                    .attr("enclave")
                    .attr("id")
                    .build()
                    .into(),
            ]),
        ))
        .add_attribute((
            "subnet_id",
            hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("aws_subnet"))
                .attr("enclave")
                .attr("id")
                .build(),
        ));

    if let Some(ref key) = ssh_key_name {
        instance_builder = instance_builder.add_attribute(("key_name", key.as_str()));
    }

    instance_builder = instance_builder
        .add_block(
            hcl::Block::builder("enclave_options")
                .add_attribute(("enabled", true))
                .build(),
        )
        .add_block(
            hcl::Block::builder("metadata_options")
                .add_attribute(("http_endpoint", "enabled"))
                .add_attribute(("http_tokens", "required"))
                .build(),
        )
        .add_block(
            hcl::Block::builder("root_block_device")
                .add_attribute(("volume_size", request.disk_gb))
                .add_attribute(("volume_type", "gp3"))
                .add_attribute(("delete_on_termination", true))
                .add_attribute(("encrypted", true))
                .build(),
        )
        .add_attribute(("user_data_replace_on_change", true));

    // user_data = base64encode(templatefile("./user-data.sh", { ... }))
    let ssh_keys_json =
        serde_json::to_string(&request.ssh_keys).unwrap_or_else(|_| "[]".to_string());
    let domain_str = request.domain.as_deref().unwrap_or("");
    let url_output = if let Some(ref d) = request.domain {
        format!("https://{d}")
    } else {
        "https://${aws_eip.enclave.public_ip}".to_string()
    };

    instance_builder = instance_builder.add_attribute(hcl::Attribute::new(
        "user_data",
        hcl::expr::FuncCall::builder("base64encode")
            .arg(
                hcl::expr::FuncCall::builder("templatefile")
                    .arg(hcl::Expression::String("./user-data.sh".into()))
                    .arg(hcl::Expression::Object(
                        vec![
                            (
                                hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                    "eif_s3_path",
                                )),
                                hcl::Expression::String(eif_s3_path.into()),
                            ),
                            (
                                hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                    "memory_mb",
                                )),
                                hcl::Expression::Number(request.memory_mb.into()),
                            ),
                            (
                                hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                    "cpu_count",
                                )),
                                hcl::Expression::Number(cpu_count_rounded.into()),
                            ),
                            (
                                hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                    "debug_mode",
                                )),
                                hcl::Expression::String(
                                    if request.debug_mode { "true" } else { "false" }.into(),
                                ),
                            ),
                            (
                                hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                    "ports",
                                )),
                                hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked(
                                    "var",
                                ))
                                .attr("ports")
                                .build()
                                .into(),
                            ),
                            (
                                hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                    "http_port",
                                )),
                                hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked(
                                    "var",
                                ))
                                .attr("http_port")
                                .build()
                                .into(),
                            ),
                            (
                                hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked("e2e")),
                                hcl::Expression::String(
                                    if request.e2e { "true" } else { "false" }.into(),
                                ),
                            ),
                            (
                                hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                    "e2e_mode",
                                )),
                                hcl::Expression::String(
                                    effective_e2e_mode(request.e2e, &request.e2e_mode).into(),
                                ),
                            ),
                            (
                                hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                    "locksmith",
                                )),
                                hcl::Expression::String(
                                    if request.locksmith { "true" } else { "false" }.into(),
                                ),
                            ),
                            (
                                hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                    "egress",
                                )),
                                hcl::Expression::String(
                                    if request.egress { "true" } else { "false" }.into(),
                                ),
                            ),
                            (
                                hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                    "ssh_keys",
                                )),
                                hcl::Expression::from(
                                    serde_json::from_str::<Vec<String>>(&ssh_keys_json)
                                        .unwrap_or_default(),
                                ),
                            ),
                            (
                                hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                    "domain",
                                )),
                                hcl::Expression::String(domain_str.into()),
                            ),
                        ]
                        .into_iter()
                        .collect(),
                    ))
                    .build(),
            )
            .build(),
    ));

    // instance tags
    instance_builder = instance_builder.add_attribute((
        "tags",
        hcl::Expression::Object(
            vec![
                (
                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked("Name")),
                    hcl::Expression::String(resource_id_str.clone()),
                ),
                (
                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked("ResourceId")),
                    hcl::Expression::String(resource_id_str.clone()),
                ),
                (
                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked("ConfigDomain")),
                    hcl::Expression::String(domain_str.into()),
                ),
            ]
            .into_iter()
            .collect(),
        ),
    ));

    body = body.add_block(instance_builder.build());

    // resource "aws_eip" "enclave"
    body = body.add_block(
        hcl::Block::builder("resource")
            .add_label("aws_eip")
            .add_label("enclave")
            .add_attribute(("domain", "vpc"))
            .add_attribute((
                "instance",
                hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("aws_instance"))
                    .attr("enclave")
                    .attr("id")
                    .build(),
            ))
            .add_attribute((
                "tags",
                hcl::Expression::Object(
                    vec![
                        (
                            hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked("Name")),
                            hcl::Expression::String(format!("enclave-{resource_id_str}")),
                        ),
                        (
                            hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                "ResourceId",
                            )),
                            hcl::Expression::String(resource_id_str.clone()),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ))
            .build(),
    );

    // outputs
    body = body.add_block(
        hcl::Block::builder("output")
            .add_label("instance_id")
            .add_attribute((
                "value",
                hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("aws_instance"))
                    .attr("enclave")
                    .attr("id")
                    .build(),
            ))
            .build(),
    );

    body = body.add_block(
        hcl::Block::builder("output")
            .add_label("public_ip")
            .add_attribute((
                "value",
                hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("aws_eip"))
                    .attr("enclave")
                    .attr("public_ip")
                    .build(),
            ))
            .build(),
    );

    body = body.add_block(
        hcl::Block::builder("output")
            .add_label("url")
            .add_attribute(hcl::Attribute::new(
                "value",
                hcl::expr::TemplateExpr::from(url_output),
            ))
            .build(),
    );

    body = body.add_block(
        hcl::Block::builder("output")
            .add_label("instance_type")
            .add_attribute(("value", instance_type))
            .build(),
    );

    let content =
        dterror::ResultExt::with_context(hcl::to_string(&body.build()), Ctx::serialize())?;

    dterror::ResultExt::with_context(
        fs::write(work_dir.join("main.tf"), &content).await,
        Ctx::write(),
    )?;

    Ok(())
}

/// The scoped deployment tag key, rendered as the parenthesized object-key form
/// `(local.scope_tag_key)` via an `ObjectKey` wrapping a parenthesized traversal.
fn scoped_tag_key() -> hcl::expr::ObjectKey {
    hcl::expr::ObjectKey::Expression(hcl::Expression::Parenthesis(Box::new(
        hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("local"))
            .attr("scope_tag_key")
            .build()
            .into(),
    )))
}

/// A traversal to `local.deployment_tag`, the value paired with [`scoped_tag_key`].
fn deployment_tag_value() -> hcl::Expression {
    hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("local"))
        .attr("deployment_tag")
        .build()
        .into()
}

/// The provider/locals conditional `var.provider_region != "" ? var.provider_region : aws_region`.
fn region_conditional(aws_region: &str) -> hcl::expr::Conditional {
    hcl::expr::Conditional::new(
        hcl::expr::BinaryOp::new(
            hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("var"))
                .attr("provider_region")
                .build(),
            hcl::expr::BinaryOperator::NotEq,
            hcl::Expression::String(String::new()),
        ),
        hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("var"))
            .attr("provider_region")
            .build(),
        hcl::Expression::String(aws_region.to_string()),
    )
}

/// A conditional credential attribute named `attr_name`, referencing the variable
/// `var_name`: `var.<var_name> != "" ? var.<var_name> : null`.
fn credential_conditional(attr_name: &str, var_name: &str) -> hcl::Attribute {
    hcl::Attribute::new(
        attr_name,
        hcl::expr::Conditional::new(
            hcl::expr::BinaryOp::new(
                hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("var"))
                    .attr(var_name)
                    .build(),
                hcl::expr::BinaryOperator::NotEq,
                hcl::Expression::String(String::new()),
            ),
            hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("var"))
                .attr(var_name)
                .build(),
            hcl::Expression::Null,
        ),
    )
}

/// An ingress block opening `cidr_blocks = ["0.0.0.0/0"]` traffic on a single port.
fn cidr_ingress_block(port: u64, description: &str) -> hcl::Block {
    hcl::Block::builder("ingress")
        .add_attribute(("from_port", port))
        .add_attribute(("to_port", port))
        .add_attribute(("protocol", "tcp"))
        .add_attribute((
            "cidr_blocks",
            hcl::Expression::Array(vec![hcl::Expression::String("0.0.0.0/0".into())]),
        ))
        .add_attribute(("description", description))
        .build()
}

/// A `variable` block of type `string` (optionally sensitive) with an empty default.
fn provider_credential_variable(name: &str, sensitive: bool) -> hcl::Block {
    let mut builder = hcl::Block::builder("variable")
        .add_label(name)
        .add_attribute(("type", "string"));
    if sensitive {
        builder = builder.add_attribute(("sensitive", true));
    }
    builder.add_attribute(("default", "")).build()
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GenerateOnpremTfError {
    #[error("missing managed_onprem config [{location}]")]
    MissingConfig { location: Location },
    #[error("could not compute enclave sizing [{location}]")]
    Sizing {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not serialize main.tf [{location}]")]
    Serialize {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("could not write main.tf [{location}]")]
    Write {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
async fn generate_managed_onprem_deployment_tf(
    work_dir: &Path,
    request: &NitroDeploymentRequest,
    eif_s3_path: &str,
) -> std::result::Result<(), GenerateOnpremTfError> {
    use GenerateOnpremTfErrorCtx as Ctx;

    let onprem =
        request
            .managed_onprem
            .as_ref()
            .ok_or_else(|| GenerateOnpremTfError::MissingConfig {
                location: std::panic::Location::caller(),
            })?;

    let aws_region = request
        .credentials
        .as_ref()
        .map(|c| c.region.clone())
        .unwrap_or_else(|| std::env::var("AWS_REGION").unwrap_or_else(|_| "us-west-2".to_string()));

    let (cpu_count_rounded, instance_type) =
        dterror::ResultExt::with_context(compute_enclave_sizing(request), Ctx::sizing())?;

    let short_id: String = request.resource_id.to_string()[..8].to_owned();
    let resource_id_str = request.resource_id.to_string();
    let org_id_str = request.org_id.to_string();
    let domain_str = request.domain.as_deref().unwrap_or("");
    let url_output = if let Some(ref d) = request.domain {
        format!("https://{d}")
    } else {
        "https://${aws_eip.enclave.public_ip}".to_string()
    };

    let mut body = hcl::Body::builder();

    // terraform block
    body = body.add_block(
        hcl::Block::builder("terraform")
            .add_attribute(("required_version", ">= 1.0"))
            .add_block(
                hcl::Block::builder("required_providers")
                    .add_attribute((
                        "aws",
                        hcl::Expression::Object(
                            vec![
                                (
                                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                        "source",
                                    )),
                                    hcl::Expression::String("hashicorp/aws".into()),
                                ),
                                (
                                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                        "version",
                                    )),
                                    hcl::Expression::String("~> 5.0".into()),
                                ),
                            ]
                            .into_iter()
                            .collect(),
                        ),
                    ))
                    .build(),
            )
            .build(),
    );

    // provider credential variables
    body = body
        .add_block(provider_credential_variable("provider_access_key", true))
        .add_block(provider_credential_variable("provider_secret_key", true))
        .add_block(provider_credential_variable("provider_region", false));

    // variable "asg_name"
    body = body.add_block(
        hcl::Block::builder("variable")
            .add_label("asg_name")
            .add_attribute(("type", "string"))
            .add_attribute(("default", onprem.asg_name.clone()))
            .build(),
    );

    // provider "aws" block with conditional region/access_key/secret_key and default_tags
    body = body.add_block(
        hcl::Block::builder("provider")
            .add_label("aws")
            .add_attribute(hcl::Attribute::new(
                "region",
                region_conditional(&aws_region),
            ))
            .add_attribute(credential_conditional("access_key", "provider_access_key"))
            .add_attribute(credential_conditional("secret_key", "provider_secret_key"))
            .add_block(
                hcl::Block::builder("default_tags")
                    .add_attribute((
                        "tags",
                        hcl::Expression::Object(
                            vec![
                                (
                                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                        "org_id",
                                    )),
                                    hcl::Expression::String(org_id_str.clone()),
                                ),
                                (
                                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                        "ManagedBy",
                                    )),
                                    hcl::Expression::String("caution+tofu".into()),
                                ),
                            ]
                            .into_iter()
                            .collect(),
                        ),
                    ))
                    .build(),
            )
            .build(),
    );

    // variable "ports"
    body = body.add_block(
        hcl::Block::builder("variable")
            .add_label("ports")
            .add_attribute((
                "type",
                hcl::expr::FuncCall::builder("list")
                    .arg(hcl::Expression::from(hcl::expr::Variable::unchecked(
                        "number",
                    )))
                    .build(),
            ))
            .add_attribute(("default", hcl::Expression::Array(vec![])))
            .build(),
    );

    // variable "http_port"
    body = body.add_block(
        hcl::Block::builder("variable")
            .add_label("http_port")
            .add_attribute(("type", "number"))
            .add_attribute(("default", 0u64))
            .build(),
    );

    // locals block
    body = body.add_block(
        hcl::Block::builder("locals")
            .add_attribute((
                "deployment_tag",
                hcl::Expression::String(onprem.deployment_id.clone()),
            ))
            .add_attribute((
                "scope_tag_key",
                hcl::Expression::String("caution:deployment-id".into()),
            ))
            .add_attribute(hcl::Attribute::new(
                "aws_region",
                region_conditional(&aws_region),
            ))
            .build(),
    );

    // data "aws_ami" "amazon_linux_2023"
    body = body.add_block(
        hcl::Block::builder("data")
            .add_label("aws_ami")
            .add_label("amazon_linux_2023")
            .add_attribute(("most_recent", true))
            .add_attribute((
                "owners",
                hcl::Expression::Array(vec![hcl::Expression::String("amazon".into())]),
            ))
            .add_block(
                hcl::Block::builder("filter")
                    .add_attribute(("name", "name"))
                    .add_attribute((
                        "values",
                        hcl::Expression::Array(vec![hcl::Expression::String(
                            "al2023-ami-*-x86_64".into(),
                        )]),
                    ))
                    .build(),
            )
            .add_block(
                hcl::Block::builder("filter")
                    .add_attribute(("name", "virtualization-type"))
                    .add_attribute((
                        "values",
                        hcl::Expression::Array(vec![hcl::Expression::String("hvm".into())]),
                    ))
                    .build(),
            )
            .add_block(
                hcl::Block::builder("filter")
                    .add_attribute(("name", "root-device-type"))
                    .add_attribute((
                        "values",
                        hcl::Expression::Array(vec![hcl::Expression::String("ebs".into())]),
                    ))
                    .build(),
            )
            .build(),
    );

    // resource "aws_security_group" "enclave"
    let mut sg_builder = hcl::Block::builder("resource")
        .add_label("aws_security_group")
        .add_label("enclave")
        .add_attribute(("name_prefix", format!("enclave-{short_id}-")))
        .add_attribute((
            "description",
            format!("Security group for {resource_id_str} Nitro Enclave"),
        ))
        .add_attribute(("vpc_id", onprem.vpc_id.clone()));

    if !request.ssh_keys.is_empty() {
        sg_builder = sg_builder.add_block(cidr_ingress_block(22, "Allow SSH"));
    }

    sg_builder = sg_builder
        .add_block(cidr_ingress_block(80, "Allow HTTP"))
        .add_block(cidr_ingress_block(443, "Allow HTTPS"));

    for block in platform_internal_ingress(request.e2e, request.locksmith) {
        sg_builder = sg_builder.add_block(block);
    }

    // dynamic "ingress" over var.ports
    sg_builder = sg_builder.add_block(
        hcl::Block::builder("dynamic")
            .add_label("ingress")
            .add_attribute((
                "for_each",
                hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("var"))
                    .attr("ports")
                    .build(),
            ))
            .add_block(
                hcl::Block::builder("content")
                    .add_attribute((
                        "from_port",
                        hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("ingress"))
                            .attr("value")
                            .build(),
                    ))
                    .add_attribute((
                        "to_port",
                        hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("ingress"))
                            .attr("value")
                            .build(),
                    ))
                    .add_attribute(("protocol", "tcp"))
                    .add_attribute((
                        "cidr_blocks",
                        hcl::Expression::Array(vec![hcl::Expression::String("0.0.0.0/0".into())]),
                    ))
                    .add_attribute(hcl::Attribute::new(
                        "description",
                        hcl::expr::TemplateExpr::from(
                            "Allow user port ${ingress.value}".to_string(),
                        ),
                    ))
                    .build(),
            )
            .build(),
    );

    // egress block
    sg_builder = sg_builder.add_block(
        hcl::Block::builder("egress")
            .add_attribute(("from_port", 0u64))
            .add_attribute(("to_port", 0u64))
            .add_attribute(("protocol", "-1"))
            .add_attribute((
                "cidr_blocks",
                hcl::Expression::Array(vec![hcl::Expression::String("0.0.0.0/0".into())]),
            ))
            .add_attribute(("description", "Allow all outbound"))
            .build(),
    );

    // security group tags
    sg_builder = sg_builder.add_attribute((
        "tags",
        hcl::Expression::Object(
            vec![
                (
                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked("Name")),
                    hcl::Expression::String(format!("enclave-{resource_id_str}")),
                ),
                (
                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked("ResourceId")),
                    hcl::Expression::String(resource_id_str.clone()),
                ),
                (scoped_tag_key(), deployment_tag_value()),
            ]
            .into_iter()
            .collect(),
        ),
    ));

    body = body.add_block(sg_builder.build());

    // resource "aws_launch_template" "enclave"
    let ssh_keys_json =
        serde_json::to_string(&request.ssh_keys).unwrap_or_else(|_| "[]".to_string());

    let lt_builder = hcl::Block::builder("resource")
        .add_label("aws_launch_template")
        .add_label("enclave")
        .add_attribute(("name_prefix", format!("enclave-{resource_id_str}-")))
        .add_attribute((
            "image_id",
            hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("data"))
                .attr("aws_ami")
                .attr("amazon_linux_2023")
                .attr("id")
                .build(),
        ))
        .add_attribute(("instance_type", instance_type))
        .add_block(
            hcl::Block::builder("iam_instance_profile")
                .add_attribute(("name", onprem.instance_profile_name.clone()))
                .build(),
        )
        .add_attribute((
            "vpc_security_group_ids",
            hcl::Expression::Array(vec![
                hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("aws_security_group"))
                    .attr("enclave")
                    .attr("id")
                    .build()
                    .into(),
            ]),
        ))
        .add_block(
            hcl::Block::builder("enclave_options")
                .add_attribute(("enabled", true))
                .build(),
        )
        .add_block(
            hcl::Block::builder("metadata_options")
                .add_attribute(("http_endpoint", "enabled"))
                .add_attribute(("http_tokens", "required"))
                .build(),
        )
        .add_block(
            hcl::Block::builder("block_device_mappings")
                .add_attribute(("device_name", "/dev/xvda"))
                .add_block(
                    hcl::Block::builder("ebs")
                        .add_attribute(("volume_size", request.disk_gb))
                        .add_attribute(("volume_type", "gp3"))
                        .add_attribute(("delete_on_termination", true))
                        .add_attribute(("encrypted", true))
                        .build(),
                )
                .build(),
        )
        .add_attribute(hcl::Attribute::new(
            "user_data",
            hcl::expr::FuncCall::builder("base64encode")
                .arg(
                    hcl::expr::FuncCall::builder("templatefile")
                        .arg(hcl::Expression::String("./user-data.sh".into()))
                        .arg(hcl::Expression::Object(
                            vec![
                                (
                                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                        "eif_s3_path",
                                    )),
                                    hcl::Expression::String(eif_s3_path.into()),
                                ),
                                (
                                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                        "memory_mb",
                                    )),
                                    hcl::Expression::Number(request.memory_mb.into()),
                                ),
                                (
                                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                        "cpu_count",
                                    )),
                                    hcl::Expression::Number(cpu_count_rounded.into()),
                                ),
                                (
                                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                        "debug_mode",
                                    )),
                                    hcl::Expression::String(
                                        if request.debug_mode { "true" } else { "false" }.into(),
                                    ),
                                ),
                                (
                                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                        "ports",
                                    )),
                                    hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked(
                                        "var",
                                    ))
                                    .attr("ports")
                                    .build()
                                    .into(),
                                ),
                                (
                                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                        "http_port",
                                    )),
                                    hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked(
                                        "var",
                                    ))
                                    .attr("http_port")
                                    .build()
                                    .into(),
                                ),
                                (
                                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                        "e2e",
                                    )),
                                    hcl::Expression::String(
                                        if request.e2e { "true" } else { "false" }.into(),
                                    ),
                                ),
                                (
                                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                        "e2e_mode",
                                    )),
                                    hcl::Expression::String(
                                        effective_e2e_mode(request.e2e, &request.e2e_mode).into(),
                                    ),
                                ),
                                (
                                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                        "locksmith",
                                    )),
                                    hcl::Expression::String(
                                        if request.locksmith { "true" } else { "false" }.into(),
                                    ),
                                ),
                                (
                                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                        "egress",
                                    )),
                                    hcl::Expression::String(
                                        if request.egress { "true" } else { "false" }.into(),
                                    ),
                                ),
                                (
                                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                        "ssh_keys",
                                    )),
                                    hcl::Expression::from(
                                        serde_json::from_str::<Vec<String>>(&ssh_keys_json)
                                            .unwrap_or_default(),
                                    ),
                                ),
                                (
                                    hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                        "domain",
                                    )),
                                    hcl::Expression::String(domain_str.into()),
                                ),
                            ]
                            .into_iter()
                            .collect(),
                        ))
                        .build(),
                )
                .build(),
        ))
        .add_block(
            hcl::Block::builder("tag_specifications")
                .add_attribute(("resource_type", "instance"))
                .add_attribute((
                    "tags",
                    hcl::Expression::Object(
                        vec![
                            (
                                hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                    "Name",
                                )),
                                hcl::Expression::String(resource_id_str.clone()),
                            ),
                            (
                                hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                    "ResourceId",
                                )),
                                hcl::Expression::String(resource_id_str.clone()),
                            ),
                            (
                                hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                    "ConfigDomain",
                                )),
                                hcl::Expression::String(domain_str.into()),
                            ),
                            (scoped_tag_key(), deployment_tag_value()),
                        ]
                        .into_iter()
                        .collect(),
                    ),
                ))
                .build(),
        )
        .add_block(
            hcl::Block::builder("tag_specifications")
                .add_attribute(("resource_type", "volume"))
                .add_attribute((
                    "tags",
                    hcl::Expression::Object(
                        vec![
                            (
                                hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                    "Name",
                                )),
                                hcl::Expression::String(format!("enclave-{resource_id_str}")),
                            ),
                            (
                                hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                    "ResourceId",
                                )),
                                hcl::Expression::String(resource_id_str.clone()),
                            ),
                            (scoped_tag_key(), deployment_tag_value()),
                        ]
                        .into_iter()
                        .collect(),
                    ),
                ))
                .build(),
        )
        .add_attribute((
            "tags",
            hcl::Expression::Object(
                vec![
                    (
                        hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked("Name")),
                        hcl::Expression::String(format!("lt-{resource_id_str}")),
                    ),
                    (
                        hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked("ResourceId")),
                        hcl::Expression::String(resource_id_str.clone()),
                    ),
                    (scoped_tag_key(), deployment_tag_value()),
                ]
                .into_iter()
                .collect(),
            ),
        ));

    body = body.add_block(lt_builder.build());

    // resource "aws_eip" "enclave"
    body = body.add_block(
        hcl::Block::builder("resource")
            .add_label("aws_eip")
            .add_label("enclave")
            .add_attribute(("domain", "vpc"))
            .add_attribute((
                "tags",
                hcl::Expression::Object(
                    vec![
                        (
                            hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked("Name")),
                            hcl::Expression::String(format!("enclave-{resource_id_str}")),
                        ),
                        (
                            hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(
                                "ResourceId",
                            )),
                            hcl::Expression::String(resource_id_str.clone()),
                        ),
                        (scoped_tag_key(), deployment_tag_value()),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ))
            .build(),
    );

    // outputs
    body = body.add_block(
        hcl::Block::builder("output")
            .add_label("launch_template_id")
            .add_attribute((
                "value",
                hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked(
                    "aws_launch_template",
                ))
                .attr("enclave")
                .attr("id")
                .build(),
            ))
            .build(),
    );

    body = body.add_block(
        hcl::Block::builder("output")
            .add_label("launch_template_version")
            .add_attribute(hcl::Attribute::new(
                "value",
                hcl::expr::FuncCall::builder("tostring")
                    .arg(
                        hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked(
                            "aws_launch_template",
                        ))
                        .attr("enclave")
                        .attr("latest_version")
                        .build(),
                    )
                    .build(),
            ))
            .build(),
    );

    body = body.add_block(
        hcl::Block::builder("output")
            .add_label("eip_allocation_id")
            .add_attribute((
                "value",
                hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("aws_eip"))
                    .attr("enclave")
                    .attr("id")
                    .build(),
            ))
            .build(),
    );

    body = body.add_block(
        hcl::Block::builder("output")
            .add_label("public_ip")
            .add_attribute((
                "value",
                hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("aws_eip"))
                    .attr("enclave")
                    .attr("public_ip")
                    .build(),
            ))
            .build(),
    );

    body = body.add_block(
        hcl::Block::builder("output")
            .add_label("url")
            .add_attribute(hcl::Attribute::new(
                "value",
                hcl::expr::TemplateExpr::from(url_output),
            ))
            .build(),
    );

    body = body.add_block(
        hcl::Block::builder("output")
            .add_label("instance_type")
            .add_attribute(("value", instance_type))
            .build(),
    );

    let content =
        dterror::ResultExt::with_context(hcl::to_string(&body.build()), Ctx::serialize())?;

    dterror::ResultExt::with_context(
        fs::write(work_dir.join("main.tf"), &content).await,
        Ctx::write(),
    )?;

    Ok(())
}
