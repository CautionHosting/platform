// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

// The `CtxError` derive generates a `{Error}Ctx` mirror type per error enum;
// the generated struct initializations trip `redundant_field_names`, and the
// lint cannot be placed on the generated items themselves.
#![allow(
    clippy::redundant_field_names,
    reason = "generated {Error}Ctx mirrors trip redundant_field_names"
)]

pub use caution_deploy::DeploymentResult;
use dterror::{BoxError, CtxError, Location, ResultExt as _};
use serde::{Deserialize, Serialize};
use std::io::Read;
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
pub const TOFU_TIMEOUT_SECS: u64 = 600;

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
pub enum RunCommandError {
    #[error("Failed to spawn command [{location}]")]
    Spawn {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("Failed to start {stream} reader [{location}]")]
    StartReader {
        stream: &'static str,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("Failed to wait on command [{location}]")]
    Wait {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("Failed to read output [{location}]")]
    ReadOutput {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error(
        "Command timed out after {timeout_secs}s\nstdout: {stdout}\nstderr: {stderr} [{location}]"
    )]
    TimedOut {
        timeout_secs: u64,
        stdout: String,
        stderr: String,
        #[location]
        location: Location,
    },
    #[error("Command timed out after {timeout_secs}s; failed to read output [{location}]")]
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
pub enum TofuInitError {
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
pub enum TofuApplyError {
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
pub enum TofuDestroyError {
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

/// Drain both output pipes while waiting, so verbose commands cannot block on output.
/// Kill and reap the child when its deadline expires.
#[tracing::instrument(skip_all)]
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

    std::thread::scope(|scope| {
        let stdout = child.stdout.take();
        let stdout = std::thread::Builder::new().spawn_scoped(scope, move || {
            let mut bytes = Vec::new();
            stdout
                .ok_or_else(|| std::io::Error::other("Missing stdout pipe"))?
                .read_to_end(&mut bytes)?;
            Ok::<_, std::io::Error>(bytes)
        });
        let stdout = match stdout {
            Ok(reader) => reader,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return dterror::ResultExt::with_context(Err(error), Ctx::start_reader("stdout"));
            }
        };
        let stderr = child.stderr.take();
        let stderr = std::thread::Builder::new().spawn_scoped(scope, move || {
            let mut bytes = Vec::new();
            stderr
                .ok_or_else(|| std::io::Error::other("Missing stderr pipe"))?
                .read_to_end(&mut bytes)?;
            Ok::<_, std::io::Error>(bytes)
        });
        let stderr = match stderr {
            Ok(reader) => reader,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout.join();
                return dterror::ResultExt::with_context(Err(error), Ctx::start_reader("stderr"));
            }
        };

        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(Some(status)),
                Ok(None) if std::time::Instant::now() >= deadline => break Ok(None),
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(500)),
                Err(error) => break Err(error),
            }
        };
        if !matches!(status, Ok(Some(_))) {
            let _ = child.kill();
            let _ = child.wait();
        }
        // Join both readers even if waiting or one reader failed.
        let stdout = stdout
            .join()
            .unwrap_or_else(|_| Err(std::io::Error::other("Stdout reader panicked")));
        let stderr = stderr
            .join()
            .unwrap_or_else(|_| Err(std::io::Error::other("Stderr reader panicked")));
        let status = dterror::ResultExt::with_context(status, Ctx::wait())?;
        let output = stdout.and_then(|stdout| stderr.map(|stderr| (stdout, stderr)));
        if let Some(status) = status {
            let (stdout, stderr) = dterror::ResultExt::with_context(output, Ctx::read_output())?;
            Ok(std::process::Output {
                status,
                stdout,
                stderr,
            })
        } else {
            let (stdout, stderr) =
                dterror::ResultExt::with_context(output, Ctx::timed_out_read_output(timeout_secs))?;
            Err(RunCommandError::TimedOut {
                timeout_secs,
                stdout: String::from_utf8_lossy(&stdout).into_owned(),
                stderr: String::from_utf8_lossy(&stderr).into_owned(),
                location: std::panic::Location::caller(),
            })
        }
    })
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

/// Reviewed release digest, independent of builder-controlled EIF sidecars.
const SOURCE_TAP_FRAMER_SHA256: &str = include_str!("../../tap-framer/host.sha256");

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
    /// Exact deployment-paired host helper digest, retained across redeploy/rollback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tap_framer_sha256: Option<String>,
    pub memory_mb: u32,
    pub cpu_count: u32,
    pub disk_gb: u32,
    pub debug_mode: bool,
    #[serde(default)]
    pub restart: caution_config::RestartConfig,
    pub ports: Vec<u16>,
    pub network: caution_config::NetworkConfig,
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
    /// Deployments-lifecycle tls build: the instance publishes its public IPv4
    /// to the enclave, which starts Caddy once the app domain resolves to it.
    #[serde(default)]
    pub tls_await_app_address: bool,
    /// User-data template authored by the build mechanism. Required; a deploy
    /// request without it fails with `MissingUserData`.
    #[serde(default)]
    pub user_data: String,
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
pub enum DeployNitroEnclaveError {
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
    #[error("failed to upload paired TAP tunnel helper [{location}]")]
    UploadTapFramer {
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

#[tracing::instrument(skip_all)]
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
            upload_tap_framer(&request, &eif_s3_path).await,
            Ctx::upload_tap_framer(),
        )?;
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
            upload_tap_framer(&request, &eif_s3_path).await,
            Ctx::upload_tap_framer(),
        )?;
        dterror::ResultExt::with_context(
            provision_nitro_enclave(&request, &eif_s3_path, &config).await,
            Ctx::provision_nitro_enclave(),
        )
    }
}

#[tracing::instrument(skip_all)]
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
pub enum ScaleDownAsgError {
    #[error("could not set ASG desired capacity to 0 [{location}]")]
    SetDesiredCapacity {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Scale down ASG to 0 and wait for instances to terminate
#[tracing::instrument(skip_all)]
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
#[path = "deployment_component_tests.rs"]
mod component_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn test_run_with_timeout_large_output() {
        let output = run_with_timeout(
            Command::new("sh").args([
                "-c",
                "head -c 1048576 /dev/zero; head -c 1048576 /dev/zero >&2",
            ]),
            10,
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, vec![0; 1_048_576]);
        assert_eq!(output.stderr, vec![0; 1_048_576]);
    }

    #[test]
    #[cfg(unix)]
    fn test_run_with_timeout_nonzero_exit() {
        let output = run_with_timeout(
            Command::new("sh").args(["-c", "printf out; printf err >&2; exit 17"]),
            10,
        )
        .unwrap();
        assert_eq!(output.status.code(), Some(17));
        assert_eq!(output.stdout, b"out");
        assert_eq!(output.stderr, b"err");
    }

    #[test]
    #[cfg(unix)]
    fn test_run_with_timeout_kills_noisy_child() {
        let started = std::time::Instant::now();
        let error = run_with_timeout(
            Command::new("sh").args([
                "-c",
                "printf '%s\\n' \"$$\"; while :; do printf out; printf err >&2; done",
            ]),
            1,
        )
        .unwrap_err();
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        let RunCommandError::TimedOut {
            timeout_secs,
            stdout,
            stderr,
            ..
        } = error
        else {
            panic!("Expected a command timeout");
        };
        assert_eq!(timeout_secs, 1);
        assert!(stdout.contains("out"));
        assert!(stderr.starts_with("err"));
        let pid = stdout.lines().next().unwrap();
        assert!(pid.parse::<u32>().is_ok());
        assert!(
            !Command::new("kill")
                .args(["-0", pid])
                .output()
                .unwrap()
                .status
                .success()
        );
    }

    #[test]
    fn test_run_with_timeout_spawn_failure() {
        // Reject before execution: emulation can report missing executables as exit 127.
        let error = run_with_timeout(&mut Command::new("invalid\0command"), 1).unwrap_err();
        assert!(matches!(error, RunCommandError::Spawn { .. }));
    }

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

    pub(super) fn deployment_request(
        eif_path: &str,
        eif_s3_key: Option<&str>,
    ) -> NitroDeploymentRequest {
        NitroDeploymentRequest {
            tap_framer_sha256: None,
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
            restart: Default::default(),
            ports: vec![8080],
            network: serde_json::from_value(serde_json::json!({
                "ingress": [{"cidr_ipv4": "0.0.0.0/0", "port": 8080}],
                "http": {"port": 8080}
            }))
            .unwrap(),
            http_port: Some(8080),
            e2e: false,
            e2e_mode: E2E_MODE_DISABLED.to_string(),
            locksmith: false,
            egress: false,
            ssh_keys: vec![],
            domain: None,
            region: Some("us-west-2".to_string()),
            credentials: None,
            managed_onprem: Some(managed_onprem_config()),
            tls_await_app_address: false,
            user_data: String::new(),
        }
    }

    #[tokio::test]
    async fn generated_network_policy_preserves_sources_in_all_deployment_modes() {
        for (managed, candidate) in [(false, false), (true, false), (false, true), (true, true)] {
            let mut value =
                serde_json::to_value(deployment_request("/tmp/enclave.eif", None)).unwrap();
            value["ports"] = serde_json::json!([8080, 9000, 9001]);
            value["http_port"] = serde_json::json!(8080);
            value["e2e"] = serde_json::json!(true);
            value["e2e_mode"] = serde_json::json!("steve");
            value["locksmith"] = serde_json::json!(true);
            value["network"] = serde_json::json!({
                "ingress": [
                    {"cidr_ipv4": "198.51.100.0/24", "port": 8080},
                    {"cidr_ipv4": "203.0.113.4/32", "start_port": 9000, "end_port": 9001}
                ],
                "http": {"port": 8080, "e2e_encryption": {"mode": "steve"}}
            });
            let mut request: NitroDeploymentRequest = serde_json::from_value(value).unwrap();
            if !managed {
                request.managed_onprem = None;
            }
            let directory = TempDir::new().unwrap();
            if candidate {
                generate_deployment_main_tf(
                    directory.path(),
                    &request,
                    Uuid::nil(),
                    &sample_network(),
                    "s3://bucket/enclave.eif",
                )
                .await
                .unwrap();
            } else if managed {
                generate_managed_onprem_deployment_tf(
                    directory.path(),
                    &request,
                    "s3://bucket/enclave.eif",
                )
                .await
                .unwrap();
            } else {
                generate_nitro_deployment_main_tf(
                    directory.path(),
                    &request,
                    "s3://bucket/enclave.eif",
                )
                .await
                .unwrap();
            }
            let text = std::fs::read_to_string(directory.path().join("main.tf")).unwrap();
            let body: hcl::Body = hcl::from_str(&text).unwrap();
            let group = body
                .blocks()
                .find(|block| {
                    block.identifier() == "resource"
                        && block
                            .labels()
                            .first()
                            .is_some_and(|label| label.as_str() == "aws_security_group")
                })
                .unwrap();
            let ingress: Vec<_> = group
                .body
                .blocks()
                .filter(|block| block.identifier() == "ingress")
                .collect();
            let attributes = |block: &hcl::Block| -> serde_json::Value {
                hcl::from_str(&hcl::to_string(&block.body).unwrap()).unwrap()
            };
            for block in ingress {
                let rule = attributes(block);
                if rule["from_port"] == 80 {
                    continue;
                }
                assert_ne!(rule["from_port"], 8080, "HTTP upstream must be private");
                assert_ne!(
                    rule["cidr_blocks"],
                    serde_json::json!(["0.0.0.0/0"]),
                    "application source restrictions must survive rendering: {rule}"
                );
            }
            assert!(
                !group
                    .body
                    .blocks()
                    .any(|block| block.identifier() == "dynamic"),
                "lossy dynamic ingress must not remain"
            );
            assert!(text.contains("198.51.100.0/24"));
            assert!(text.contains("203.0.113.4/32"));
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
    fn test_caddy_management_routes_precede_source_scoped_application() {
        let request = deployment_request("/tmp/enclave.eif", None);
        let policy = request.network.policy().unwrap();
        let routes = crate::network_policy::http_routes(&policy, Some(8080), "steve", None);
        let app = routes.find("handle @caution_http_sources").unwrap();
        for management in ["handle /attestation", "handle /.well-known/caution/health"] {
            assert!(routes.find(management).unwrap() < app);
        }
        assert!(routes[app..].contains("reverse_proxy localhost:49500"));
        assert!(!routes.contains("header X-E2P"));
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
    async fn legacy_fully_managed_main_tf_is_unchanged() {
        // The generator reads these (`generate_nitro_deployment_main_tf` and
        // `enclave_instance_block`); a dev shell that exports them would produce a
        // different file.
        assert!(
            std::env::var_os("EIF_S3_BUCKET").is_none()
                && std::env::var_os("SSH_KEY_NAME").is_none(),
            "run with EIF_S3_BUCKET and SSH_KEY_NAME unset"
        );
        let mut request = deployment_request("/tmp/enclave.eif", None);
        request.managed_onprem = None;
        request.ports = vec![8080, 9000];
        request.http_port = Some(8080);
        request.domain = Some("app.example.com".to_string());
        request.locksmith = true;
        request.e2e = true;
        request.ssh_keys = vec!["ssh-ed25519 AAAA test".to_string()];

        let work_dir = TempDir::new().unwrap();
        generate_nitro_deployment_main_tf(work_dir.path(), &request, "s3://bucket/enclave.eif")
            .await
            .unwrap();
        let main_tf = std::fs::read_to_string(work_dir.path().join("main.tf")).unwrap();

        let golden =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("src/testdata/legacy_fully_managed_main.tf");
        if std::env::var_os("UPDATE_GOLDEN").is_some() {
            std::fs::create_dir_all(golden.parent().unwrap()).unwrap();
            std::fs::write(&golden, &main_tf).unwrap();
        }
        assert_eq!(main_tf, std::fs::read_to_string(&golden).unwrap());
    }

    /// The deployments lifecycle's fully managed states, pinned before BYOC shares
    /// their blocks.
    #[tokio::test]
    async fn managed_deployment_and_network_tf_are_unchanged() {
        assert!(
            std::env::var_os("EIF_S3_BUCKET").is_none()
                && std::env::var_os("SSH_KEY_NAME").is_none(),
            "run with EIF_S3_BUCKET and SSH_KEY_NAME unset"
        );
        let mut request = deployment_request("/tmp/enclave.eif", None);
        request.managed_onprem = None;
        request.ports = vec![8080, 9000];
        request.http_port = Some(8080);
        request.domain = Some("app.example.com".to_string());
        let deployment_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let deployment_dir = TempDir::new().unwrap();
        generate_deployment_main_tf(
            deployment_dir.path(),
            &request,
            deployment_id,
            &sample_network(),
            "s3://bucket/e.eif",
        )
        .await
        .unwrap();
        let network_dir = TempDir::new().unwrap();
        generate_app_network_main_tf(
            network_dir.path(),
            &AppNetworkRequest {
                org_id: Uuid::nil(),
                resource_id: Uuid::nil(),
                aws_account_id: "123456789012".to_string(),
                region: "us-west-2".to_string(),
                instance_type: "m5.xlarge".to_string(),
                linked: None,
            },
        )
        .await
        .unwrap();
        for (dir, name) in [
            (&deployment_dir, "deployment_main.tf"),
            (&network_dir, "app_network_main.tf"),
        ] {
            let main_tf = std::fs::read_to_string(dir.path().join("main.tf")).unwrap();
            let golden = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src/testdata")
                .join(name);
            if std::env::var_os("UPDATE_GOLDEN").is_some() {
                std::fs::write(&golden, &main_tf).unwrap();
            }
            assert_eq!(
                main_tf,
                std::fs::read_to_string(&golden).unwrap(),
                "{}",
                golden.display()
            );
        }
    }

    #[tokio::test]
    async fn linked_deployment_tf_uses_the_linked_account_and_scope_tag() {
        // `deployment_request` links `managed_onprem_config()` (deployment ID `dep-123`).
        let mut request = deployment_request("/tmp/enclave.eif", None);
        request.credentials = Some(AwsCredentials {
            access_key_id: "AKIALINKED".to_string(),
            secret_access_key: "secret".to_string(),
            region: "us-west-2".to_string(),
        });
        let deployment_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let work_dir = TempDir::new().unwrap();
        generate_deployment_main_tf(
            work_dir.path(),
            &request,
            deployment_id,
            &sample_network(),
            "s3://customer-bucket/e.eif",
        )
        .await
        .unwrap();
        let tf = norm(&std::fs::read_to_string(work_dir.path().join("main.tf")).unwrap());
        assert!(tf.contains(r#"variable "provider_access_key""#));
        assert!(tf.contains("access_key = var.provider_access_key"));
        assert!(
            !tf.contains("AKIALINKED"),
            "keys are variables, never written"
        );
        // The security group and the instance: the delegated policy only
        // terminates, edits and associates resources carrying the scope tag.
        assert_eq!(
            tf.matches(r#""caution:deployment-id" = "dep-123""#).count(),
            2
        );
        assert!(tf.contains(r#"DeploymentId = "11111111-1111-1111-1111-111111111111""#));
    }

    pub(super) fn sample_network() -> AppNetwork {
        AppNetwork {
            region: "us-west-2".to_string(),
            vpc_id: "vpc-0abc".to_string(),
            subnet_id: "subnet-0abc".to_string(),
            availability_zone: "us-west-2a".to_string(),
            instance_profile_name: "enclave-00000000-profile".to_string(),
            eip_allocation_id: "eipalloc-0abc".to_string(),
            eip_public_ip: "198.51.100.42".to_string(),
            scope_tag: None,
        }
    }

    fn sample_linked() -> LinkedNetwork {
        LinkedNetwork {
            credentials: AwsCredentials {
                access_key_id: "AKIALINKED".to_string(),
                secret_access_key: "secret".to_string(),
                region: "us-east-1".to_string(),
            },
            scope_tag: "dep-123".to_string(),
            vpc_id: "vpc-123".to_string(),
            subnet_id: "subnet-123".to_string(),
            availability_zone: "us-east-1a".to_string(),
            instance_profile_name: "runtime-profile".to_string(),
        }
    }

    #[tokio::test]
    async fn linked_app_network_tf_creates_only_a_scoped_eip() {
        let request = AppNetworkRequest {
            org_id: Uuid::nil(),
            resource_id: Uuid::nil(),
            aws_account_id: "123456789012".to_string(),
            region: "us-east-1".to_string(),
            instance_type: "m5.xlarge".to_string(),
            linked: Some(sample_linked()),
        };
        let work_dir = TempDir::new().unwrap();
        generate_app_network_main_tf(work_dir.path(), &request)
            .await
            .unwrap();
        let tf = norm(&std::fs::read_to_string(work_dir.path().join("main.tf")).unwrap());
        assert!(tf.contains(r#"resource "aws_eip" "enclave""#));
        // AllocateAddress requires the scope tag in the request itself.
        assert!(tf.contains(r#""caution:deployment-id" = "dep-123""#));
        assert!(tf.contains("var.provider_access_key"));
        assert!(!tf.contains("AKIALINKED"));
        assert!(tf.contains(r#"output "eip_allocation_id""#));
        for absent in [
            r#"resource "aws_vpc""#,
            r#"resource "aws_subnet""#,
            "aws_iam_role",
            r#"output "vpc_id""#,
            "aws_ec2_instance_type_offerings",
        ] {
            assert!(!tf.contains(absent), "unexpected {absent}");
        }
    }

    #[test]
    fn linked_network_outputs_keep_the_provisioner_network() {
        let outputs = serde_json::json!({
            "eip_allocation_id": {"value": "eipalloc-1"},
            "eip_public_ip": {"value": "198.51.100.7"},
        });
        let network =
            parse_linked_network_outputs(&outputs, "us-east-1", &sample_linked()).unwrap();
        assert_eq!(
            network,
            AppNetwork {
                region: "us-east-1".to_string(),
                vpc_id: "vpc-123".to_string(),
                subnet_id: "subnet-123".to_string(),
                availability_zone: "us-east-1a".to_string(),
                instance_profile_name: "runtime-profile".to_string(),
                eip_allocation_id: "eipalloc-1".to_string(),
                eip_public_ip: "198.51.100.7".to_string(),
                scope_tag: Some("dep-123".to_string()),
            }
        );
    }

    #[test]
    fn managed_app_network_json_is_unchanged() {
        let json = serde_json::to_value(sample_network()).unwrap();
        assert!(
            json.get("scope_tag").is_none(),
            "managed networks serialize as before"
        );
        // Rows written before M4 have no scope tag.
        let parsed: AppNetwork = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.scope_tag, None);
    }

    #[tokio::test]
    async fn app_network_tf_holds_network_iam_and_unassociated_eip_only() {
        let request = AppNetworkRequest {
            org_id: Uuid::nil(),
            resource_id: Uuid::nil(),
            aws_account_id: "123456789012".to_string(),
            region: "us-west-2".to_string(),
            instance_type: "m5.xlarge".to_string(),
            linked: None,
        };
        let work_dir = TempDir::new().unwrap();
        generate_app_network_main_tf(work_dir.path(), &request)
            .await
            .unwrap();
        let tf = norm(&std::fs::read_to_string(work_dir.path().join("main.tf")).unwrap());
        for present in [
            r#"resource "aws_vpc" "enclave""#,
            r#"resource "aws_subnet" "enclave""#,
            r#"resource "aws_iam_instance_profile" "enclave""#,
            r#"resource "aws_eip" "enclave""#,
            r#"output "eip_allocation_id""#,
            r#"output "availability_zone""#,
        ] {
            assert!(tf.contains(present), "missing {present}");
        }
        for absent in [
            r#"resource "aws_instance""#,
            r#"resource "aws_security_group""#,
            "instance = aws_instance",
        ] {
            assert!(!tf.contains(absent), "unexpected {absent}");
        }
    }

    #[tokio::test]
    async fn only_await_address_deployments_publish_the_public_ip() {
        let deployment_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        for (await_address, expected) in [(true, true), (false, false)] {
            let mut request = deployment_request("/tmp/enclave.eif", None);
            request.managed_onprem = None;
            request.tls_await_app_address = await_address;
            let work_dir = TempDir::new().unwrap();
            generate_deployment_main_tf(
                work_dir.path(),
                &request,
                deployment_id,
                &sample_network(),
                "s3://bucket/e.eif",
            )
            .await
            .unwrap();
            let tf = norm(&std::fs::read_to_string(work_dir.path().join("main.tf")).unwrap());
            assert_eq!(tf.contains(r#"file("./publish-public-ip.sh")"#), expected);
        }
    }

    #[test]
    fn public_ip_publisher_reads_imds_and_reloads_dnsmasq() {
        // `CARGO_MANIFEST_DIR` is `src/caution-deploy-aws`; the repo root is two
        // levels up.
        let script = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("terraform/modules/aws/nitro-enclave/publish-public-ip.sh"),
        )
        .unwrap();
        assert!(script.contains("public-ipv4.caution.internal"));
        assert!(script.contains("X-aws-ec2-metadata-token"));
        assert!(script.contains("pkill -HUP -x dnsmasq"));
        // A stalled IMDS request must not park the publisher: every curl is bounded.
        let curls: Vec<_> = script.lines().filter(|l| l.contains("curl ")).collect();
        assert_eq!(curls.len(), 2);
        assert!(curls.iter().all(|l| l.contains("--max-time 5")));
        // Read with `file()`, not `templatefile()`: no interpolation sequences.
        assert!(!script.contains("${"));
    }

    #[tokio::test]
    async fn deployment_tf_references_app_network_by_literal_ids() {
        let mut request = deployment_request("/tmp/enclave.eif", None);
        request.managed_onprem = None;
        let deployment_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let work_dir = TempDir::new().unwrap();
        generate_deployment_main_tf(
            work_dir.path(),
            &request,
            deployment_id,
            &sample_network(),
            "s3://bucket/e.eif",
        )
        .await
        .unwrap();
        let tf = norm(&std::fs::read_to_string(work_dir.path().join("main.tf")).unwrap());
        assert!(tf.contains(r#"vpc_id = "vpc-0abc""#));
        assert!(tf.contains(r#"subnet_id = "subnet-0abc""#));
        assert!(tf.contains(r#"iam_instance_profile = "enclave-00000000-profile""#));
        assert!(tf.contains(r#"DeploymentId = "11111111-1111-1111-1111-111111111111""#));
        assert!(tf.contains("value = aws_instance.enclave.public_ip"));
        for absent in [
            r#"resource "aws_vpc""#,
            r#"resource "aws_eip""#,
            r#"resource "aws_subnet""#,
            "aws_iam_role",
        ] {
            assert!(!tf.contains(absent), "unexpected {absent}");
        }
    }

    #[test]
    fn deployment_state_key_nests_under_the_app_key() {
        let org = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let app = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let dep = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();
        assert_eq!(
            deployment_state_key(org, app, dep),
            "organizations/00000000-0000-0000-0000-000000000001/resources/00000000-0000-0000-0000-000000000002/deployments/00000000-0000-0000-0000-000000000003/terraform.tfstate"
        );
    }

    #[tokio::test]
    async fn new_lifecycle_backends_enable_lockfile_and_legacy_does_not() {
        let dir = TempDir::new().unwrap();
        generate_backend_config_for_key(dir.path(), "a/b/terraform.tfstate", "bucket", true)
            .await
            .unwrap();
        assert!(
            norm(&std::fs::read_to_string(dir.path().join("backend.tf")).unwrap())
                .contains("use_lockfile = true")
        );

        let legacy = TempDir::new().unwrap();
        generate_backend_config(legacy.path(), Uuid::nil(), Uuid::nil(), "bucket")
            .await
            .unwrap();
        assert!(
            !std::fs::read_to_string(legacy.path().join("backend.tf"))
                .unwrap()
                .contains("use_lockfile")
        );
    }

    #[tokio::test]
    async fn deployment_backend_uses_the_deployment_key_and_a_lockfile() {
        let org = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let app = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let dep = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();
        let dir = TempDir::new().unwrap();
        deployment_backend(dir.path(), org, app, dep).await.unwrap();
        let backend = norm(&std::fs::read_to_string(dir.path().join("backend.tf")).unwrap());
        assert!(backend.contains(&format!(
            r#"key = "{}""#,
            deployment_state_key(org, app, dep)
        )));
        assert!(backend.contains("use_lockfile = true"));
    }

    #[test]
    fn app_network_outputs_parse_from_tofu_json() {
        let outputs = serde_json::json!({
            "vpc_id": {"value": "vpc-0abc"}, "subnet_id": {"value": "subnet-0abc"},
            "availability_zone": {"value": "us-west-2a"},
            "instance_profile_name": {"value": "enclave-profile"},
            "eip_allocation_id": {"value": "eipalloc-0abc"}, "eip_public_ip": {"value": "198.51.100.42"}
        });
        let network = parse_app_network_outputs(&outputs, "us-west-2").unwrap();
        assert_eq!(network.eip_public_ip, "198.51.100.42");
        assert_eq!(network.region, "us-west-2");
        assert!(parse_app_network_outputs(&serde_json::json!({}), "us-west-2").is_err());
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
        assert!(
            norm(&main_tf).contains("type = string"),
            "variable type constraints must render as the bare `string` keyword"
        );
        assert!(
            norm(&main_tf).contains("type = list(number)"),
            "the ports variable must render the bare list(number) type constraint"
        );
        assert!(
            norm(&main_tf).contains("type = number"),
            "the http_port variable must render the bare number type constraint"
        );
        assert!(
            !main_tf.contains(r#"type = "string""#) && !main_tf.contains(r#"type = "number""#),
            "a quoted type constraint is a value, not a type constraint, and OpenTofu rejects it"
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

    #[tokio::test]
    async fn test_tunnel_upload_skips_disabled_egress() {
        let mut request = deployment_request("/missing/enclave.eif", None);
        request.egress = false;
        upload_tap_framer(&request, "not-an-s3-uri").await.unwrap();
    }

    #[tokio::test]
    async fn test_tunnel_upload_skips_dedicated_builder_artifacts() {
        let mut request = deployment_request("/missing/enclave.eif", None);
        request.egress = true;
        request.managed_onprem = None;
        request.eif_s3_key = Some("eifs/test.eif".to_string());
        upload_tap_framer(&request, "s3://platform/eifs/test.eif")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_tunnel_upload_rejects_invalid_destination_before_io() {
        let mut request = deployment_request("/missing/enclave.eif", None);
        request.egress = true;
        request.eif_s3_key = None;
        assert!(matches!(
            upload_tap_framer(&request, "not-an-s3-uri").await,
            Err(TapFramerUploadError::InvalidDestination { .. })
        ));
    }

    #[test]
    fn deployment_request_without_restart_uses_legacy_defaults() {
        let mut value = serde_json::to_value(deployment_request("/tmp/enclave.eif", None)).unwrap();
        value.as_object_mut().unwrap().remove("restart");
        let parsed: NitroDeploymentRequest = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.restart, caution_config::RestartConfig::default());
    }

    #[tokio::test]
    async fn restart_policy_reaches_both_terraform_templates() {
        use caution_config::{RestartConfig, RestartPolicy};
        for policy in [
            RestartPolicy::Never,
            RestartPolicy::OnFailure,
            RestartPolicy::Always,
        ] {
            for delay_seconds in [0, 10] {
                let mut request = deployment_request("/tmp/enclave.eif", None);
                request.restart = RestartConfig {
                    policy,
                    delay_seconds,
                };
                for byoc in [false, true] {
                    let work_dir = TempDir::new().unwrap();
                    if byoc {
                        request.managed_onprem = Some(managed_onprem_config());
                        generate_managed_onprem_deployment_tf(
                            work_dir.path(),
                            &request,
                            "s3://bucket/enclave.eif",
                        )
                        .await
                        .unwrap();
                    } else {
                        request.managed_onprem = None;
                        generate_nitro_deployment_main_tf(
                            work_dir.path(),
                            &request,
                            "s3://bucket/enclave.eif",
                        )
                        .await
                        .unwrap();
                    }
                    let rendered =
                        norm(&std::fs::read_to_string(work_dir.path().join("main.tf")).unwrap());
                    assert!(
                        rendered.contains(&["restart_policy = \"", policy.as_str(), "\""].concat())
                    );
                    assert!(rendered.contains(
                        &["restart_delay_seconds = ", &delay_seconds.to_string()].concat()
                    ));
                }
            }
        }
    }

    #[test]
    fn test_user_data_proxy_guarded_by_egress() {
        let user_data = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("terraform/modules/aws/nitro-enclave/user-data.sh"),
        )
        .unwrap();
        assert!(user_data.contains("${eif_s3_path}.tap-framer"));
        assert!(!user_data.contains("VSOCK-LISTEN:3,"));
        assert!(user_data.contains("/usr/local/bin/tap-framer --listen 3 enclave0"));
        assert!(!user_data.contains("TUN,tun-type=tap"));
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
        assert!(user_data.contains("${http_routes}"));
        let request = deployment_request("/tmp/enclave.eif", None);
        let routes = crate::network_policy::http_routes(
            &request.network.policy().unwrap(),
            Some(8080),
            "steve",
            None,
        );
        assert!(routes.contains("reverse_proxy localhost:49500"));
        assert!(!routes.contains("localhost:8080"));
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
        let request = deployment_request("/tmp/enclave.eif", None);
        let routes = crate::network_policy::http_routes(
            &request.network.policy().unwrap(),
            Some(8080),
            "tls",
            Some("app.example.com"),
        );
        assert!(routes.contains("respond \"OK\" 200"));
        assert!(
            routes.find("handle /attestation").unwrap()
                < routes
                    .find("redir https://app.example.com{uri} 308")
                    .unwrap()
        );
        assert!(routes.contains("reverse_proxy localhost:49502"));
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
            "ExecStart=/usr/bin/socat TCP-LISTEN:49503,bind=127.0.0.1,reuseaddr,fork VSOCK-CONNECT:16:${http_port}"
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
    fn test_destroy_tf_body_type_constraints_are_bare_not_quoted() {
        let content = hcl::to_string(&build_destroy_tf_body(true, "us-west-2")).unwrap();
        assert!(
            content.contains("type = string"),
            "variable type constraints must render as the bare `string` keyword"
        );
        assert!(
            !content.contains(r#"type = "string""#),
            "a quoted type constraint is a value, not a type constraint, and OpenTofu rejects it"
        );
    }

    #[test]
    fn test_destroy_tf_body_has_no_default_tags() {
        let content = hcl::to_string(&build_destroy_tf_body(true, "us-west-2")).unwrap();
        assert!(!content.contains("default_tags"));
    }
}

struct TerraformConfig {
    s3_bucket: String,
}

/// The nitro-enclave module directory, which holds the `user-data.sh` template.
fn nitro_module_path() -> PathBuf {
    PathBuf::from("terraform/modules/aws/nitro-enclave")
}

/// The platform's OpenTofu state bucket (always in `us-west-2`).
fn terraform_state_bucket() -> String {
    std::env::var("TERRAFORM_STATE_BUCKET")
        .unwrap_or_else(|_| "caution-terraform-state".to_string())
}

/// The cached provider lock under `CAUTION_DATA_DIR`, generated on first use.
async fn provider_lockfile() -> Option<PathBuf> {
    let data_dir =
        std::env::var("CAUTION_DATA_DIR").unwrap_or_else(|_| "/var/cache/caution".to_string());
    get_or_generate_lockfile(&data_dir).await
}

impl Default for TerraformConfig {
    fn default() -> Self {
        Self {
            s3_bucket: std::env::var("TERRAFORM_STATE_BUCKET")
                .unwrap_or_else(|_| "caution-terraform-state".to_string()),
        }
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum DestroyEc2Error {
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

#[tracing::instrument(skip_all)]
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
pub enum GenerateBackendConfigError {
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

#[tracing::instrument(skip_all)]
async fn generate_backend_config(
    work_dir: &Path,
    org_id: Uuid,
    resource_id: Uuid,
    s3_bucket: &str,
) -> std::result::Result<(), GenerateBackendConfigError> {
    generate_backend_config_for_key(
        work_dir,
        &app_state_key(org_id, resource_id),
        s3_bucket,
        false,
    )
    .await
}

/// The state key of one deployment, nested under its app's key.
pub fn deployment_state_key(org_id: Uuid, resource_id: Uuid, deployment_id: Uuid) -> String {
    format!(
        "organizations/{org_id}/resources/{resource_id}/deployments/{deployment_id}/terraform.tfstate"
    )
}

fn app_state_key(org_id: Uuid, resource_id: Uuid) -> String {
    // The deployments lifecycle's app state reuses the per-app key.
    format!("organizations/{org_id}/resources/{resource_id}/terraform.tfstate")
}

/// The backend of one deployment's state, locked with `<key>.tflock`.
async fn deployment_backend(
    work_dir: &Path,
    org_id: Uuid,
    resource_id: Uuid,
    deployment_id: Uuid,
) -> std::result::Result<(), GenerateBackendConfigError> {
    generate_backend_config_for_key(
        work_dir,
        &deployment_state_key(org_id, resource_id, deployment_id),
        &terraform_state_bucket(),
        true,
    )
    .await
}

/// Writes the S3 backend for `key`. `use_lockfile` enables OpenTofu's S3 lock
/// (`<key>.tflock`), which [`clear_state_lock`] removes after a crash.
#[tracing::instrument(skip_all, err)]
async fn generate_backend_config_for_key(
    work_dir: &Path,
    key: &str,
    s3_bucket: &str,
    use_lockfile: bool,
) -> std::result::Result<(), GenerateBackendConfigError> {
    use GenerateBackendConfigErrorCtx as Ctx;

    let mut backend = hcl::Block::builder("backend")
        .add_label("s3")
        .add_attribute(("bucket", s3_bucket))
        .add_attribute(("key", key))
        .add_attribute(("region", "us-west-2"))
        .add_attribute(("encrypt", true));
    if use_lockfile {
        backend = backend.add_attribute(("use_lockfile", true));
    }
    let body = hcl::Body::builder()
        .add_block(
            hcl::Block::builder("terraform")
                .add_block(backend.build())
                .build(),
        )
        .build();

    let content = dterror::ResultExt::with_context(hcl::to_string(&body), Ctx::serialize())?;

    let backend_path = work_dir.join("backend.tf");
    dterror::ResultExt::with_context(fs::write(&backend_path, &content).await, Ctx::write())?;

    Ok(())
}

#[tracing::instrument(skip_all)]
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

#[tracing::instrument(skip_all)]
fn run_tofu_apply_with_provider_creds(
    work_dir: &Path,
    resource_name: &str,
    ports: &[u16],
    http_port: Option<u16>,
    credentials: Option<&AwsCredentials>,
) -> std::result::Result<(), TofuApplyError> {
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

    run_tofu_apply_command(&mut cmd)
}

/// `tofu apply` for a configuration that declares no port variables. With
/// `credentials` (a linked account) its AWS provider uses them; otherwise the
/// platform's environment credentials.
#[tracing::instrument(skip_all, err)]
fn run_tofu_apply_plain(
    work_dir: &Path,
    credentials: Option<&AwsCredentials>,
) -> std::result::Result<(), TofuApplyError> {
    tracing::info!("Running tofu apply in {}...", work_dir.display());

    let mut cmd = Command::new("tofu");
    cmd.arg("apply")
        .arg("-auto-approve")
        .arg("-no-color")
        .current_dir(work_dir);
    if let Some(creds) = credentials {
        cmd.env("TF_VAR_provider_access_key", &creds.access_key_id);
        cmd.env("TF_VAR_provider_secret_key", &creds.secret_access_key);
        cmd.env("TF_VAR_provider_region", &creds.region);
    }

    run_tofu_apply_command(&mut cmd)
}

/// Runs a prepared `tofu apply` command under the tofu timeout and logs its failure.
fn run_tofu_apply_command(cmd: &mut Command) -> std::result::Result<(), TofuApplyError> {
    use TofuApplyErrorCtx as Ctx;

    let output = dterror::ResultExt::with_context(
        run_with_timeout(cmd, TOFU_TIMEOUT_SECS),
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

/// Failure modes for `tofu output -json`.
#[derive(Debug, thiserror::Error, CtxError)]
pub enum TofuOutputError {
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
}

/// Runs `tofu output -json` and returns the parsed outputs object.
#[tracing::instrument(skip_all, err)]
fn run_tofu_output_json(
    work_dir: &Path,
) -> std::result::Result<serde_json::Value, TofuOutputError> {
    use TofuOutputErrorCtx as Ctx;

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
        return Err(TofuOutputError::NonZeroExit {
            exit_code: output.status.code(),
            location: std::panic::Location::caller(),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    dterror::ResultExt::with_context(serde_json::from_str(&stdout), Ctx::json_parse())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum GetTofuOutputsError {
    #[error("could not read tofu outputs [{location}]")]
    Output {
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

    let outputs = dterror::ResultExt::with_context(run_tofu_output_json(work_dir), Ctx::output())?;

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
pub enum GetManagedOnpremOutputsError {
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

#[tracing::instrument(skip_all)]
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
pub enum UpdateAsgLaunchTemplateError {
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
#[tracing::instrument(skip_all)]
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
pub enum WaitForAsgInstanceError {
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
#[tracing::instrument(skip_all)]
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
pub enum AssociateEipWithInstanceError {
    #[error("could not associate EIP with instance [{location}]")]
    AssociateAddress {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Associate an Elastic IP with an instance
#[tracing::instrument(skip_all)]
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

#[tracing::instrument(skip_all)]
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
pub enum UploadEifToS3Error {
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

#[derive(Debug, thiserror::Error, dterror::CtxError)]
enum TapFramerUploadError {
    #[error("invalid tunnel artifact destination [{location}]")]
    InvalidDestination { location: dterror::Location },
    #[error("could not transfer tunnel artifact '{artifact}' [{location}]")]
    Transfer {
        #[context(borrow = str)]
        artifact: String,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },
}

#[tracing::instrument(skip_all)]
async fn upload_tap_framer(
    request: &NitroDeploymentRequest,
    destination_eif: &str,
) -> std::result::Result<(), TapFramerUploadError> {
    use TapFramerUploadErrorCtx as Ctx;
    use dterror::ResultExt;
    if !request.egress {
        return Ok(());
    }
    if request.eif_s3_key.is_some()
        && (request.managed_onprem.is_none()
            || request.managed_onprem.as_ref().is_some_and(|managed| {
                managed_onprem_uses_direct_customer_bucket(request, managed)
            }))
    {
        return Ok(());
    }
    let (bucket, key) = destination_eif
        .strip_prefix("s3://")
        .and_then(|path| path.split_once('/'))
        .filter(|(bucket, key)| !bucket.is_empty() && !key.is_empty())
        .ok_or_else(|| TapFramerUploadError::InvalidDestination {
            location: std::panic::Location::caller(),
        })?;
    let key = format!("{key}.tap-framer");
    let platform_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .load()
        .await;
    let body = if let Some(source_key) = &request.eif_s3_key {
        let source_bucket = std::env::var("EIF_S3_BUCKET")
            .unwrap_or_else(|_| format!("caution-eif-storage-{}", request.aws_account_id));
        let source_key = format!("{source_key}.tap-framer");
        let object = ResultExt::with_context(
            aws_sdk_s3::Client::new(&platform_config)
                .get_object()
                .bucket(source_bucket)
                .key(&source_key)
                .send()
                .await,
            Ctx::transfer(&source_key),
        )?;
        ResultExt::with_context(object.body.collect().await, Ctx::transfer(&source_key))?
            .into_bytes()
            .into()
    } else {
        let path = Path::new(&request.eif_path).with_extension("tap-framer");
        ResultExt::with_context(
            aws_sdk_s3::primitives::ByteStream::from_path(path).await,
            Ctx::transfer(&request.eif_path),
        )?
    };
    let config = if let Some(credentials) = request
        .credentials
        .as_ref()
        .filter(|_| request.managed_onprem.is_some())
    {
        aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(credentials.region.clone()))
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                &credentials.access_key_id,
                &credentials.secret_access_key,
                None,
                None,
                "caution-managed-onprem",
            ))
            .load()
            .await
    } else {
        platform_config
    };
    ResultExt::with_context(
        aws_sdk_s3::Client::new(&config)
            .put_object()
            .bucket(bucket)
            .key(&key)
            .body(body)
            .send()
            .await,
        Ctx::transfer(&key),
    )?;
    Ok(())
}

#[tracing::instrument(skip_all)]
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
pub enum UploadEifToCustomerBucketError {
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

#[tracing::instrument(skip_all)]
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
pub enum UploadEifFromPlatformS3Error {
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

#[tracing::instrument(skip_all)]
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
pub enum ProvisionNitroEnclaveError {
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
    #[error("deploy request is missing the mechanism-provided user-data template [{location}]")]
    MissingUserData { location: Location },
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

#[tracing::instrument(skip_all)]
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

    if request.user_data.is_empty() {
        return Err(ProvisionNitroEnclaveError::MissingUserData {
            location: std::panic::Location::caller(),
        });
    }
    dterror::ResultExt::with_context(
        std::fs::write(work_dir.join("user-data.sh"), request.user_data.clone()),
        Ctx::write_user_data(),
    )?;
    std::fs::write(
        work_dir.join("network-policy.sh.tftpl"),
        include_str!("../../../terraform/modules/aws/nitro-enclave/network-policy.sh.tftpl"),
    )
    .with_context(Ctx::write_user_data())?;

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
pub enum ProvisionManagedOnpremError {
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
    #[error("deploy request is missing the mechanism-provided user-data template [{location}]")]
    MissingUserData { location: Location },
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

#[tracing::instrument(skip_all)]
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

    if request.user_data.is_empty() {
        return Err(ProvisionManagedOnpremError::MissingUserData {
            location: std::panic::Location::caller(),
        });
    }
    dterror::ResultExt::with_context(
        std::fs::write(work_dir.join("user-data.sh"), request.user_data.clone()),
        Ctx::write_user_data(),
    )?;
    std::fs::write(
        work_dir.join("network-policy.sh.tftpl"),
        include_str!("../../../terraform/modules/aws/nitro-enclave/network-policy.sh.tftpl"),
    )
    .with_context(Ctx::write_user_data())?;

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

// `CtxError` needs a variant with a source; this enum has none.
#[derive(Debug, thiserror::Error)]
pub enum ParseAppNetworkOutputsError {
    #[error("tofu output missing '{field}' [{location}]")]
    MissingField { field: String, location: Location },
}

/// Reads the app network state's `tofu output -json` object.
pub fn parse_app_network_outputs(
    outputs: &serde_json::Value,
    region: &str,
) -> std::result::Result<AppNetwork, ParseAppNetworkOutputsError> {
    let field = |name: &str| {
        outputs[name]["value"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| ParseAppNetworkOutputsError::MissingField {
                field: name.to_string(),
                location: std::panic::Location::caller(),
            })
    };
    Ok(AppNetwork {
        region: region.to_string(),
        vpc_id: field("vpc_id")?,
        subnet_id: field("subnet_id")?,
        availability_zone: field("availability_zone")?,
        instance_profile_name: field("instance_profile_name")?,
        eip_allocation_id: field("eip_allocation_id")?,
        eip_public_ip: field("eip_public_ip")?,
        scope_tag: None,
    })
}

/// A linked app network: the provisioner's network around the EIP its app state created.
pub fn parse_linked_network_outputs(
    outputs: &serde_json::Value,
    region: &str,
    linked: &LinkedNetwork,
) -> std::result::Result<AppNetwork, ParseAppNetworkOutputsError> {
    let field = |name: &str| {
        outputs[name]["value"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| ParseAppNetworkOutputsError::MissingField {
                field: name.to_string(),
                location: std::panic::Location::caller(),
            })
    };
    Ok(AppNetwork {
        region: region.to_string(),
        vpc_id: linked.vpc_id.clone(),
        subnet_id: linked.subnet_id.clone(),
        availability_zone: linked.availability_zone.clone(),
        instance_profile_name: linked.instance_profile_name.clone(),
        eip_allocation_id: field("eip_allocation_id")?,
        eip_public_ip: field("eip_public_ip")?,
        scope_tag: Some(linked.scope_tag.clone()),
    })
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum ProvisionAppNetworkError {
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
    #[error("could not generate main.tf [{location}]")]
    GenerateMainTf {
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
    Outputs {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Applies the app network state (VPC, IAM, unassociated EIP; only the EIP in a linked
/// account) on the per-app key. Idempotent: a re-apply leaves an existing network unchanged.
#[tracing::instrument(skip_all, err)]
pub async fn provision_app_network(
    request: &AppNetworkRequest,
) -> std::result::Result<AppNetwork, ProvisionAppNetworkError> {
    use ProvisionAppNetworkErrorCtx as Ctx;

    tracing::info!(
        "Provisioning app network for resource {} in {}",
        request.resource_id,
        request.region
    );

    let temp_dir = TempDir::new().with_context(Ctx::temp_dir())?;
    let work_dir = temp_dir.path();

    // No lock file: the app state is applied only inside the app's single active
    // operation, like the Legacy state on the same key, and a crash would leave a
    // lock that blocks every later push.
    generate_backend_config_for_key(
        work_dir,
        &app_state_key(request.org_id, request.resource_id),
        &terraform_state_bucket(),
        false,
    )
    .await
    .with_context(Ctx::backend())?;

    generate_app_network_main_tf(work_dir, request)
        .await
        .with_context(Ctx::generate_main_tf())?;

    run_tofu_init(work_dir, provider_lockfile().await.as_deref(), None)
        .await
        .with_context(Ctx::tofu_init())?;

    run_tofu_apply_plain(
        work_dir,
        request.linked.as_ref().map(|linked| &linked.credentials),
    )
    .with_context(Ctx::tofu_apply())?;

    let outputs = run_tofu_output_json(work_dir).with_context(Ctx::outputs())?;
    let network = match &request.linked {
        Some(linked) => parse_linked_network_outputs(&outputs, &request.region, linked),
        None => parse_app_network_outputs(&outputs, &request.region),
    }
    .with_context(Ctx::outputs())?;

    tracing::info!(
        "App network for resource {} ready: vpc {}, EIP {}",
        request.resource_id,
        network.vpc_id,
        network.eip_public_ip
    );

    Ok(network)
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum ProvisionDeploymentError {
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
    #[error("could not generate main.tf [{location}]")]
    GenerateMainTf {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("deploy request is missing the mechanism-provided user-data template [{location}]")]
    MissingUserData { location: Location },
    #[error("could not copy user-data.sh [{location}]")]
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
    Outputs {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Applies one deployment's state (security group and instance) inside the app network.
/// The result's `public_ip` is the instance's own temporary IP, not the app's EIP.
#[tracing::instrument(skip_all, err)]
pub async fn provision_deployment(
    request: &NitroDeploymentRequest,
    deployment_id: Uuid,
    network: &AppNetwork,
    eif_s3_path: &str,
) -> std::result::Result<DeploymentResult, ProvisionDeploymentError> {
    use ProvisionDeploymentErrorCtx as Ctx;

    tracing::info!(
        "Provisioning deployment {} for resource {} ({})",
        deployment_id,
        request.resource_id,
        request.resource_name
    );

    let temp_dir = TempDir::new().with_context(Ctx::temp_dir())?;
    let work_dir = temp_dir.path();

    deployment_backend(work_dir, request.org_id, request.resource_id, deployment_id)
        .await
        .with_context(Ctx::backend())?;

    generate_deployment_main_tf(work_dir, request, deployment_id, network, eif_s3_path)
        .await
        .with_context(Ctx::generate_main_tf())?;

    if request.user_data.is_empty() {
        return Err(ProvisionDeploymentError::MissingUserData {
            location: std::panic::Location::caller(),
        });
    }
    fs::write(work_dir.join("user-data.sh"), request.user_data.clone())
        .await
        .with_context(Ctx::write_user_data())?;
    fs::write(
        work_dir.join("network-policy.sh.tftpl"),
        include_str!("../../../terraform/modules/aws/nitro-enclave/network-policy.sh.tftpl"),
    )
    .await
    .with_context(Ctx::write_user_data())?;
    if request.tls_await_app_address {
        fs::copy(
            nitro_module_path().join("publish-public-ip.sh"),
            work_dir.join("publish-public-ip.sh"),
        )
        .await
        .with_context(Ctx::write_user_data())?;
    }

    run_tofu_init(work_dir, provider_lockfile().await.as_deref(), None)
        .await
        .with_context(Ctx::tofu_init())?;

    run_tofu_apply_with_provider_creds(
        work_dir,
        &request.resource_name,
        &request.ports,
        request.http_port,
        request.credentials.as_ref(),
    )
    .with_context(Ctx::tofu_apply())?;

    let result = get_tofu_outputs(work_dir).with_context(Ctx::outputs())?;

    tracing::info!(
        "Provisioned deployment {} as instance {} at {}",
        deployment_id,
        result.instance_id,
        result.public_ip
    );

    Ok(result)
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum DestroyDeploymentStateError {
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
    #[error("could not generate main.tf [{location}]")]
    GenerateMainTf {
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
    #[error("could not run tofu destroy [{location}]")]
    TofuDestroy {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Destroys one deployment's state, with `credentials` for a linked account
/// (the environment's otherwise). Re-runnable: an empty or missing state
/// destroys nothing and succeeds.
#[tracing::instrument(skip_all, err)]
pub async fn destroy_deployment_state(
    org_id: Uuid,
    resource_id: Uuid,
    deployment_id: Uuid,
    region: &str,
    credentials: Option<&AwsCredentials>,
) -> std::result::Result<(), DestroyDeploymentStateError> {
    use DestroyDeploymentStateErrorCtx as Ctx;

    tracing::info!(
        "Destroying deployment {} of resource {}",
        deployment_id,
        resource_id
    );

    let temp_dir = TempDir::new().with_context(Ctx::temp_dir())?;
    let work_dir = temp_dir.path();

    deployment_backend(work_dir, org_id, resource_id, deployment_id)
        .await
        .with_context(Ctx::backend())?;

    write_main_tf(
        work_dir,
        build_destroy_tf_body(credentials.is_some(), region),
    )
    .await
    .with_context(Ctx::generate_main_tf())?;

    run_tofu_init(work_dir, provider_lockfile().await.as_deref(), None)
        .await
        .with_context(Ctx::tofu_init())?;

    run_tofu_destroy(
        work_dir,
        &format!("deployment {deployment_id}"),
        credentials,
    )
    .with_context(Ctx::tofu_destroy())?;

    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum ClearStateLockError {
    #[error("could not delete the state lock of '{state_key}' [{location}]")]
    DeleteLock {
        #[context(borrow = str)]
        state_key: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Deletes `<state_key>.tflock` from the state bucket. Only for reconciling work whose
/// owning process is dead. Deleting an absent lock succeeds.
#[tracing::instrument(skip_all, err)]
pub async fn clear_state_lock(state_key: &str) -> std::result::Result<(), ClearStateLockError> {
    use ClearStateLockErrorCtx as Ctx;

    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new("us-west-2"))
        .load()
        .await;
    aws_sdk_s3::Client::new(&config)
        .delete_object()
        .bucket(terraform_state_bucket())
        .key(format!("{state_key}.tflock"))
        .send()
        .await
        .map(|_| ())
        .with_context(Ctx::delete_lock(state_key))
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

pub struct EnclaveSizing {
    pub cpu_count: u32,
    pub instance_type: &'static str,
    pub host_vcpus: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum EnclaveSizingError {
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

#[tracing::instrument(skip_all)]
pub fn enclave_sizing(
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

pub fn host_vcpus_for_instance_type(instance_type: &str) -> Option<u32> {
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

#[tracing::instrument(skip_all)]
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

#[tracing::instrument(skip_all)]
fn bootstrap_reference() -> hcl::Expression {
    hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked("local"))
        .attr("enclave_user_data")
        .build()
        .into()
}

#[tracing::instrument(skip_all)]
fn bootstrap_size_limit() -> hcl::Block {
    hcl::Block::builder("lifecycle")
        .add_block(hcl::Block::builder("precondition")
            .add_attribute(hcl::Attribute::new("condition", hcl::expr::BinaryOp::new(
                hcl::expr::FuncCall::builder("length").arg(bootstrap_reference()).build(),
                hcl::expr::BinaryOperator::LessEq,
                hcl::Expression::Number(21844u64.into()),
            )))
            .add_attribute(("error_message", "Compressed enclave bootstrap exceeds the EC2 16 KiB user-data limit; reduce the network policy."))
            .build())
        .build()
}

#[tracing::instrument(skip_all)]
fn bootstrap_locals(
    request: &NitroDeploymentRequest,
    cpu_count: u32,
    eif_s3_path: &str,
    policy: &caution_config::network_policy::NetworkPolicy,
) -> hcl::Block {
    let object = |values: Vec<(&str, hcl::Expression)>| {
        hcl::Expression::Object(
            values
                .into_iter()
                .map(|(key, value)| {
                    (
                        hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(key)),
                        value,
                    )
                })
                .collect(),
        )
    };
    let mode = effective_e2e_mode(request.e2e, &request.e2e_mode);
    let (ingress, guard) = crate::network_policy::ingress_input_rules(
        policy,
        request.http_port,
        mode,
        request.locksmith,
    );
    let firewall = hcl::expr::FuncCall::builder("templatefile")
        .arg(hcl::Expression::String("./network-policy.sh.tftpl".into()))
        .arg(object(vec![
            (
                "egress_forward_rules",
                crate::network_policy::egress_forward_rules(policy).into(),
            ),
            (
                "egress_dns_rules",
                crate::network_policy::egress_dns_rules(policy).into(),
            ),
            ("ingress_input_rules", ingress.into()),
            (
                "ingress_ipv6_rules",
                guard
                    .replace("CAUTION_INGRESS_GUARD", "CAUTION_INGRESS")
                    .into(),
            ),
            ("ingress_guard_rules", guard.into()),
        ]))
        .build();
    let variables = object(vec![
        ("eif_s3_path", hcl::Expression::String(eif_s3_path.into())),
        (
            "tap_framer_sha256",
            request
                .tap_framer_sha256
                .as_deref()
                .unwrap_or(SOURCE_TAP_FRAMER_SHA256.trim())
                .into(),
        ),
        (
            "memory_mb",
            hcl::Expression::Number(request.memory_mb.into()),
        ),
        ("cpu_count", hcl::Expression::Number(cpu_count.into())),
        ("debug_mode", request.debug_mode.to_string().into()),
        ("restart_policy", request.restart.policy.as_str().into()),
        (
            "restart_delay_seconds",
            hcl::Expression::Number(request.restart.delay_seconds.into()),
        ),
        (
            "ports",
            hcl::Expression::from(
                policy
                    .ports()
                    .into_iter()
                    .filter(|port| Some(*port) != request.http_port)
                    .collect::<Vec<_>>(),
            ),
        ),
        (
            "http_port",
            hcl::Expression::Number(u64::from(request.http_port.unwrap_or(0)).into()),
        ),
        ("e2e", request.e2e.to_string().into()),
        ("e2e_mode", mode.into()),
        ("locksmith", request.locksmith.to_string().into()),
        ("egress", request.egress.to_string().into()),
        ("ssh_keys", hcl::Expression::from(request.ssh_keys.clone())),
        ("domain", request.domain.as_deref().unwrap_or("").into()),
        ("network_policy_script", firewall.into()),
        (
            "http_routes",
            crate::network_policy::http_routes(
                policy,
                request.http_port.map(|_| 49503),
                mode,
                request.domain.as_deref(),
            )
            .into(),
        ),
    ]);
    let template: hcl::Expression = hcl::expr::FuncCall::builder("templatefile")
        .arg(hcl::Expression::String("./user-data.sh".into()))
        .arg(variables)
        .build()
        .into();
    let user_data = if request.tls_await_app_address {
        hcl::expr::FuncCall::builder("join")
            .arg(hcl::Expression::String(String::new()))
            .arg(hcl::Expression::Array(vec![
                template,
                hcl::expr::FuncCall::builder("file")
                    .arg(hcl::Expression::String("./publish-public-ip.sh".into()))
                    .build()
                    .into(),
            ]))
            .build()
            .into()
    } else {
        template
    };
    hcl::Block::builder("locals")
        .add_attribute(hcl::Attribute::new(
            "enclave_user_data",
            hcl::expr::FuncCall::builder("base64gzip")
                .arg(user_data)
                .build(),
        ))
        .build()
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum GenerateMainTfError {
    #[error("invalid deployment network policy [{location}]")]
    NetworkPolicy {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("invalid pinned host helper digest [{location}]")]
    ComponentDigest {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
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

/// The `terraform { required_providers { aws } }` block shared by every generated state.
fn tf_settings_block() -> hcl::Block {
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
        .build()
}

/// The AWS provider block, plus the credential variables when the request carries credentials.
fn managed_provider_blocks(
    credentials: Option<&AwsCredentials>,
    aws_region: &str,
    org_id_str: &str,
) -> Vec<hcl::Block> {
    let mut blocks = Vec::new();

    if credentials.is_some() {
        blocks.push(provider_credential_variable("provider_access_key", true));
        blocks.push(provider_credential_variable("provider_secret_key", true));
        blocks.push(provider_credential_variable("provider_region", false));

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
                    hcl::Expression::String(aws_region.to_string()),
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
                                    hcl::Expression::String(org_id_str.to_string()),
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
        blocks.push(provider_block);
    } else {
        blocks.push(
            hcl::Block::builder("provider")
                .add_label("aws")
                .add_attribute(("region", aws_region))
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
                                        hcl::Expression::String(org_id_str.to_string()),
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

    blocks
}

/// The availability-zone and instance-type-offering data sources that pick the subnet's AZ.
fn availability_zone_data_blocks(instance_type: &str) -> Vec<hcl::Block> {
    vec![
        // data "aws_availability_zones" "available"
        hcl::Block::builder("data")
            .add_label("aws_availability_zones")
            .add_label("available")
            .add_attribute(("state", "available"))
            .build(),
        // data "aws_ec2_instance_type_offerings" "enclave"
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
    ]
}

/// The Amazon Linux 2023 AMI data source the enclave host boots from.
fn amazon_linux_ami_data_block() -> hcl::Block {
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
        .build()
}

/// The enclave host IAM role, its EIF-read policy and its instance profile.
fn enclave_iam_blocks(
    short_id: &str,
    eif_bucket: &str,
    org_id_str: &str,
    resource_id_str: &str,
) -> Vec<hcl::Block> {
    vec![
        // resource "aws_iam_role" "enclave"
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
                            hcl::Expression::String(resource_id_str.to_string()),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ))
            .build(),
        // resource "aws_iam_role_policy" "enclave_s3"
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
        // resource "aws_iam_instance_profile" "enclave"
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
                            hcl::Expression::String(resource_id_str.to_string()),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ))
            .build(),
    ]
}

/// The VPC, internet gateway, subnet, route table and its association.
fn enclave_network_blocks(resource_id_str: &str) -> Vec<hcl::Block> {
    vec![
        // resource "aws_vpc" "enclave"
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
                            hcl::Expression::String(resource_id_str.to_string()),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ))
            .build(),
        // resource "aws_internet_gateway" "enclave"
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
                            hcl::Expression::String(resource_id_str.to_string()),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ))
            .build(),
        // resource "aws_subnet" "enclave"
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
                            hcl::Expression::String(resource_id_str.to_string()),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ))
            .build(),
        // resource "aws_route_table" "enclave"
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
                            hcl::Expression::String(resource_id_str.to_string()),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ))
            .build(),
        // resource "aws_route_table_association" "enclave"
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
    ]
}

/// The `ports` and `http_port` variables the security group and user data read.
fn port_variable_blocks() -> Vec<hcl::Block> {
    vec![
        // variable "ports"
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
        // variable "http_port"
        hcl::Block::builder("variable")
            .add_label("http_port")
            .add_attribute(hcl::Attribute::new(
                "type",
                hcl::Expression::from(hcl::expr::Variable::unchecked("number")),
            ))
            .add_attribute(("default", 0u64))
            .build(),
    ]
}

/// The provisioner's scope tag in a linked (BYOC) account. Its delegated policy
/// only terminates, edits and associates resources carrying it, so every
/// resource created there carries it from creation. Its value is the
/// provisioner's deployment ID, not a Caution deployment.
pub const SCOPE_TAG_KEY: &str = "caution:deployment-id";

/// `extra_tags` as object entries, appended after a resource's fixed tags.
fn extra_tag_entries<'a>(
    extra_tags: &'a [(&str, String)],
) -> impl Iterator<Item = (hcl::expr::ObjectKey, hcl::Expression)> + 'a {
    extra_tags.iter().map(|(key, value)| {
        // `caution:deployment-id` is no HCL identifier: quote it.
        let key = if key.contains(':') {
            hcl::expr::ObjectKey::Expression(hcl::Expression::String((*key).to_string()))
        } else {
            hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked(*key))
        };
        (key, hcl::Expression::String(value.clone()))
    })
}

/// The enclave security group. `extra_tags` are appended after the fixed tags.
fn enclave_security_group_block(
    request: &NitroDeploymentRequest,
    policy: &caution_config::network_policy::NetworkPolicy,
    short_id: &str,
    resource_id_str: &str,
    vpc_id: hcl::Expression,
    extra_tags: &[(&str, String)],
) -> hcl::Block {
    let mut sg_builder = hcl::Block::builder("resource")
        .add_label("aws_security_group")
        .add_label("enclave")
        .add_attribute(("name_prefix", format!("enclave-{short_id}-")))
        .add_attribute((
            "description",
            format!("Security group for {resource_id_str} Nitro Enclave"),
        ))
        .add_attribute(("vpc_id", vpc_id));

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

    for block in crate::network_policy::ingress_blocks(
        policy,
        request.http_port,
        effective_e2e_mode(request.e2e, &request.e2e_mode),
        request.locksmith,
    ) {
        sg_builder = sg_builder.add_block(block);
    }

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
    let mut tags = vec![
        (
            hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked("Name")),
            hcl::Expression::String(format!("enclave-{resource_id_str}")),
        ),
        (
            hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked("ResourceId")),
            hcl::Expression::String(resource_id_str.to_string()),
        ),
    ];
    tags.extend(extra_tag_entries(extra_tags));
    sg_builder =
        sg_builder.add_attribute(("tags", hcl::Expression::Object(tags.into_iter().collect())));

    sg_builder.build()
}

/// The enclave EC2 instance. `extra_tags` are appended after the fixed tags.
#[allow(clippy::too_many_arguments)]
fn enclave_instance_block(
    request: &NitroDeploymentRequest,
    instance_type: &str,
    resource_id_str: &str,
    subnet_id: hcl::Expression,
    instance_profile: hcl::Expression,
    extra_tags: &[(&str, String)],
) -> hcl::Block {
    // A key pair named in Caution's account does not exist in a linked one.
    let ssh_key_name = std::env::var("SSH_KEY_NAME")
        .ok()
        .filter(|_| request.managed_onprem.is_none());

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
        .add_attribute(("iam_instance_profile", instance_profile))
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
        .add_attribute(("subnet_id", subnet_id));

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

    let domain_str = request.domain.as_deref().unwrap_or("");

    instance_builder = instance_builder
        .add_attribute(hcl::Attribute::new(
            "user_data_base64",
            bootstrap_reference(),
        ))
        .add_block(bootstrap_size_limit());

    // instance tags
    let mut tags = vec![
        (
            hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked("Name")),
            hcl::Expression::String(resource_id_str.to_string()),
        ),
        (
            hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked("ResourceId")),
            hcl::Expression::String(resource_id_str.to_string()),
        ),
        (
            hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked("ConfigDomain")),
            hcl::Expression::String(domain_str.into()),
        ),
    ];
    tags.extend(extra_tag_entries(extra_tags));
    instance_builder = instance_builder
        .add_attribute(("tags", hcl::Expression::Object(tags.into_iter().collect())));

    instance_builder.build()
}

/// The enclave EIP. Associated with `instance` when given; unassociated otherwise.
/// `extra_tags` are appended after the fixed tags.
fn enclave_eip_block(
    resource_id_str: &str,
    instance: Option<hcl::Expression>,
    extra_tags: &[(&str, String)],
) -> hcl::Block {
    let mut builder = hcl::Block::builder("resource")
        .add_label("aws_eip")
        .add_label("enclave")
        .add_attribute(("domain", "vpc"));

    if let Some(instance) = instance {
        builder = builder.add_attribute(("instance", instance));
    }

    let mut tags = vec![
        (
            hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked("Name")),
            hcl::Expression::String(format!("enclave-{resource_id_str}")),
        ),
        (
            hcl::expr::ObjectKey::Identifier(hcl::Identifier::unchecked("ResourceId")),
            hcl::Expression::String(resource_id_str.to_string()),
        ),
    ];
    tags.extend(extra_tag_entries(extra_tags));

    builder
        .add_attribute(("tags", hcl::Expression::Object(tags.into_iter().collect())))
        .build()
}

/// Serializes `body` and writes it to `work_dir/main.tf`.
async fn write_main_tf(
    work_dir: &Path,
    body: hcl::Body,
) -> std::result::Result<(), GenerateMainTfError> {
    use GenerateMainTfErrorCtx as Ctx;

    let content = hcl::to_string(&body).with_context(Ctx::serialize())?;
    fs::write(work_dir.join("main.tf"), &content)
        .await
        .with_context(Ctx::write())?;

    Ok(())
}

/// A `root.attr.attr...` traversal expression.
fn traversal(root: &str, attrs: &[&str]) -> hcl::Expression {
    let mut builder = hcl::expr::Traversal::builder(hcl::expr::Variable::unchecked(root));
    for attr in attrs {
        builder = builder.attr(*attr);
    }
    builder.build().into()
}

#[tracing::instrument(skip_all, err)]
async fn generate_nitro_deployment_main_tf(
    work_dir: &Path,
    request: &NitroDeploymentRequest,
    eif_s3_path: &str,
) -> std::result::Result<(), GenerateMainTfError> {
    use GenerateMainTfErrorCtx as Ctx;

    let policy = request
        .network
        .policy()
        .with_context(Ctx::network_policy())?;
    if let Some(digest) = &request.tap_framer_sha256 {
        enclave_build::components::validate_digest(digest).with_context(Ctx::component_digest())?;
    }

    let aws_region = request
        .credentials
        .as_ref()
        .map(|c| c.region.clone())
        .or_else(|| request.region.clone())
        .ok_or_else(|| GenerateMainTfError::MissingRegion {
            location: std::panic::Location::caller(),
        })?;
    let (cpu_count_rounded, instance_type) =
        dterror::ResultExt::with_context(compute_enclave_sizing(request), Ctx::sizing())?;

    let short_id: String = request.resource_id.to_string()[..8].to_owned();
    let resource_id_str = request.resource_id.to_string();
    let org_id_str = request.org_id.to_string();

    let eif_bucket = std::env::var("EIF_S3_BUCKET")
        .unwrap_or_else(|_| format!("caution-eif-storage-{}", request.aws_account_id));

    let url_output = if let Some(ref d) = request.domain {
        format!("https://{d}")
    } else {
        "https://${aws_eip.enclave.public_ip}".to_string()
    };

    let mut body = hcl::Body::builder()
        .add_block(tf_settings_block())
        .add_block(bootstrap_locals(
            request,
            cpu_count_rounded,
            eif_s3_path,
            &policy,
        ));
    let blocks = managed_provider_blocks(request.credentials.as_ref(), &aws_region, &org_id_str)
        .into_iter()
        .chain(availability_zone_data_blocks(instance_type))
        .chain([amazon_linux_ami_data_block()])
        .chain(enclave_iam_blocks(
            &short_id,
            &eif_bucket,
            &org_id_str,
            &resource_id_str,
        ))
        .chain(enclave_network_blocks(&resource_id_str))
        .chain(port_variable_blocks())
        .chain([
            enclave_security_group_block(
                request,
                &policy,
                &short_id,
                &resource_id_str,
                traversal("aws_vpc", &["enclave", "id"]),
                &[],
            ),
            enclave_instance_block(
                request,
                instance_type,
                &resource_id_str,
                traversal("aws_subnet", &["enclave", "id"]),
                traversal("aws_iam_instance_profile", &["enclave", "name"]),
                &[],
            ),
            enclave_eip_block(
                &resource_id_str,
                Some(traversal("aws_instance", &["enclave", "id"])),
                &[],
            ),
        ]);
    for block in blocks {
        body = body.add_block(block);
    }

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

    write_main_tf(work_dir, body.build()).await
}

/// The per-app network state: VPC, IAM and an unassociated EIP. Applied once per app;
/// deployment states reference its outputs by literal ID. Stored as JSONB.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppNetwork {
    pub region: String,
    pub vpc_id: String,
    pub subnet_id: String,
    pub availability_zone: String,
    pub instance_profile_name: String,
    pub eip_allocation_id: String,
    pub eip_public_ip: String,
    /// The provisioner's deployment ID when the network lives in a linked (BYOC)
    /// account; absent (and absent from the JSON) in Caution's account. Every
    /// later operation on the app's deployments uses that environment
    /// (`app_deployments::account`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_tag: Option<String>,
}

pub struct AppNetworkRequest {
    pub org_id: Uuid,
    pub resource_id: Uuid,
    pub aws_account_id: String,
    pub region: String,
    /// The first deployment's instance type; selects the subnet's AZ.
    pub instance_type: String,
    /// A linked (BYOC) account's environment; `None` builds the network in Caution's account.
    pub linked: Option<LinkedNetwork>,
}

/// What a linked (BYOC) app network reuses from the provisioner's environment.
/// Only the app EIP is created there.
pub struct LinkedNetwork {
    pub credentials: AwsCredentials,
    /// The provisioner's deployment ID ([`SCOPE_TAG_KEY`]), not a Caution deployment.
    pub scope_tag: String,
    pub vpc_id: String,
    pub subnet_id: String,
    pub availability_zone: String,
    pub instance_profile_name: String,
}

/// Failure modes for [`linked_network`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum LinkedNetworkError {
    #[error("failed to read the provisioner's subnets [{location}]")]
    Subnets {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("failed to check instance type offerings [{location}]")]
    Offering {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("no provisioner subnet offers {instance_type} [{location}]")]
    NoSubnet {
        instance_type: String,
        location: Location,
    },
}

/// The linked environment of a BYOC app's first deployment: the first of the
/// provisioner's subnets, in its order, whose zone offers `instance_type`.
#[tracing::instrument(skip_all, err)]
pub async fn linked_network(
    credentials: &AwsCredentials,
    onprem: &ManagedOnPremConfig,
    instance_type: &str,
) -> std::result::Result<LinkedNetwork, LinkedNetworkError> {
    use LinkedNetworkErrorCtx as Ctx;

    let ec2 = crate::ec2::Ec2Client::new(credentials);
    let zones = ec2
        .subnet_zones(&onprem.subnet_ids)
        .await
        .with_context(Ctx::subnets())?;
    for subnet_id in &onprem.subnet_ids {
        let Some(zone) = zones.get(subnet_id) else {
            continue;
        };
        if ec2
            .instance_type_offered_in_zone(instance_type, zone)
            .await
            .with_context(Ctx::offering())?
        {
            return Ok(LinkedNetwork {
                credentials: credentials.clone(),
                scope_tag: onprem.deployment_id.clone(),
                vpc_id: onprem.vpc_id.clone(),
                subnet_id: subnet_id.clone(),
                availability_zone: zone.clone(),
                instance_profile_name: onprem.instance_profile_name.clone(),
            });
        }
    }
    Err(LinkedNetworkError::NoSubnet {
        instance_type: instance_type.to_string(),
        location: std::panic::Location::caller(),
    })
}

/// Generates the app network state: network, IAM and an unassociated EIP, with their IDs
/// as outputs.
#[tracing::instrument(skip_all, err)]
async fn generate_app_network_main_tf(
    work_dir: &Path,
    request: &AppNetworkRequest,
) -> std::result::Result<(), GenerateMainTfError> {
    let short_id: String = request.resource_id.to_string()[..8].to_owned();
    let resource_id_str = request.resource_id.to_string();
    let org_id_str = request.org_id.to_string();
    let eif_bucket = std::env::var("EIF_S3_BUCKET")
        .unwrap_or_else(|_| format!("caution-eif-storage-{}", request.aws_account_id));

    if let Some(linked) = &request.linked {
        // The provisioner owns the network and IAM: only the app EIP is created,
        // with the scope tag the delegated policy requires to allocate it.
        let mut body = hcl::Body::builder().add_block(tf_settings_block());
        let blocks =
            managed_provider_blocks(Some(&linked.credentials), &request.region, &org_id_str)
                .into_iter()
                .chain([enclave_eip_block(
                    &resource_id_str,
                    None,
                    &[(SCOPE_TAG_KEY, linked.scope_tag.clone())],
                )])
                .chain(
                    [
                        (
                            "eip_allocation_id",
                            traversal("aws_eip", &["enclave", "allocation_id"]),
                        ),
                        (
                            "eip_public_ip",
                            traversal("aws_eip", &["enclave", "public_ip"]),
                        ),
                    ]
                    .into_iter()
                    .map(|(name, value)| {
                        hcl::Block::builder("output")
                            .add_label(name)
                            .add_attribute(("value", value))
                            .build()
                    }),
                );
        for block in blocks {
            body = body.add_block(block);
        }
        return write_main_tf(work_dir, body.build()).await;
    }

    let mut body = hcl::Body::builder().add_block(tf_settings_block());
    let blocks = managed_provider_blocks(None, &request.region, &org_id_str)
        .into_iter()
        .chain(availability_zone_data_blocks(&request.instance_type))
        .chain(enclave_iam_blocks(
            &short_id,
            &eif_bucket,
            &org_id_str,
            &resource_id_str,
        ))
        .chain(enclave_network_blocks(&resource_id_str))
        .chain([enclave_eip_block(&resource_id_str, None, &[])])
        .chain(
            [
                ("vpc_id", traversal("aws_vpc", &["enclave", "id"])),
                ("subnet_id", traversal("aws_subnet", &["enclave", "id"])),
                (
                    "availability_zone",
                    traversal("aws_subnet", &["enclave", "availability_zone"]),
                ),
                (
                    "instance_profile_name",
                    traversal("aws_iam_instance_profile", &["enclave", "name"]),
                ),
                (
                    "eip_allocation_id",
                    traversal("aws_eip", &["enclave", "allocation_id"]),
                ),
                (
                    "eip_public_ip",
                    traversal("aws_eip", &["enclave", "public_ip"]),
                ),
            ]
            .into_iter()
            .map(|(name, value)| {
                hcl::Block::builder("output")
                    .add_label(name)
                    .add_attribute(("value", value))
                    .build()
            }),
        );
    for block in blocks {
        body = body.add_block(block);
    }
    write_main_tf(work_dir, body.build()).await
}

/// Generates one deployment's state: security group and instance, placed in the app
/// network by literal ID.
#[tracing::instrument(skip_all, err)]
async fn generate_deployment_main_tf(
    work_dir: &Path,
    request: &NitroDeploymentRequest,
    deployment_id: Uuid,
    network: &AppNetwork,
    eif_s3_path: &str,
) -> std::result::Result<(), GenerateMainTfError> {
    use GenerateMainTfErrorCtx as Ctx;

    let policy = request
        .network
        .policy()
        .with_context(Ctx::network_policy())?;
    if let Some(digest) = &request.tap_framer_sha256 {
        enclave_build::components::validate_digest(digest).with_context(Ctx::component_digest())?;
    }

    let (cpu_count_rounded, instance_type) =
        compute_enclave_sizing(request).with_context(Ctx::sizing())?;
    let short_id: String = request.resource_id.to_string()[..8].to_owned();
    let resource_id_str = request.resource_id.to_string();
    let org_id_str = request.org_id.to_string();
    let mut deployment_tags = vec![("DeploymentId", deployment_id.to_string())];
    if let Some(onprem) = request.managed_onprem.as_ref() {
        deployment_tags.push((SCOPE_TAG_KEY, onprem.deployment_id.clone()));
    }
    let url = match request.domain.as_deref() {
        Some(domain) => format!("https://{domain}"),
        None => "http://${aws_instance.enclave.public_ip}".to_string(),
    };

    let mut body = hcl::Body::builder()
        .add_block(tf_settings_block())
        .add_block(bootstrap_locals(
            request,
            cpu_count_rounded,
            eif_s3_path,
            &policy,
        ));
    // Linked (BYOC) candidates carry credentials; fully managed ones use the platform's.
    let credentials = request.credentials.as_ref();
    let blocks = managed_provider_blocks(credentials, &network.region, &org_id_str)
        .into_iter()
        .chain([amazon_linux_ami_data_block()])
        .chain(port_variable_blocks())
        .chain([
            enclave_security_group_block(
                request,
                &policy,
                &short_id,
                &resource_id_str,
                hcl::Expression::String(network.vpc_id.clone()),
                &deployment_tags,
            ),
            enclave_instance_block(
                request,
                instance_type,
                &resource_id_str,
                hcl::Expression::String(network.subnet_id.clone()),
                hcl::Expression::String(network.instance_profile_name.clone()),
                &deployment_tags,
            ),
        ])
        .chain(
            [
                ("instance_id", traversal("aws_instance", &["enclave", "id"])),
                (
                    "public_ip",
                    traversal("aws_instance", &["enclave", "public_ip"]),
                ),
                (
                    "instance_type",
                    traversal("aws_instance", &["enclave", "instance_type"]),
                ),
            ]
            .into_iter()
            .map(|(name, value)| {
                hcl::Block::builder("output")
                    .add_label(name)
                    .add_attribute(("value", value))
                    .build()
            }),
        )
        .chain([hcl::Block::builder("output")
            .add_label("url")
            .add_attribute(hcl::Attribute::new(
                "value",
                hcl::expr::TemplateExpr::from(url),
            ))
            .build()]);
    for block in blocks {
        body = body.add_block(block);
    }
    write_main_tf(work_dir, body.build()).await
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

/// A `variable` block whose constraint is the bare type keyword `type = <constraint>`
/// (optionally sensitive) with an empty default.
///
/// The constraint is rendered as an identifier expression: a quoted `"string"` would
/// evaluate to a plain value rather than a type constraint, which OpenTofu rejects.
fn provider_credential_variable(name: &str, sensitive: bool) -> hcl::Block {
    let mut builder = hcl::Block::builder("variable")
        .add_label(name)
        .add_attribute(hcl::Attribute::new(
            "type",
            hcl::Expression::from(hcl::expr::Variable::unchecked("string")),
        ));
    if sensitive {
        builder = builder.add_attribute(("sensitive", true));
    }
    builder.add_attribute(("default", "")).build()
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum GenerateOnpremTfError {
    #[error("invalid deployment network policy [{location}]")]
    NetworkPolicy {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("invalid pinned host helper digest [{location}]")]
    ComponentDigest {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
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

#[tracing::instrument(skip_all)]
async fn generate_managed_onprem_deployment_tf(
    work_dir: &Path,
    request: &NitroDeploymentRequest,
    eif_s3_path: &str,
) -> std::result::Result<(), GenerateOnpremTfError> {
    use GenerateOnpremTfErrorCtx as Ctx;
    let policy = request
        .network
        .policy()
        .with_context(Ctx::network_policy())?;
    if let Some(digest) = &request.tap_framer_sha256 {
        dterror::ResultExt::with_context(
            enclave_build::components::validate_digest(digest),
            Ctx::component_digest(),
        )?;
    }

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
            .add_attribute(hcl::Attribute::new(
                "type",
                hcl::Expression::from(hcl::expr::Variable::unchecked("string")),
            ))
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
            .add_attribute(hcl::Attribute::new(
                "type",
                hcl::Expression::from(hcl::expr::Variable::unchecked("number")),
            ))
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

    for block in crate::network_policy::ingress_blocks(
        &policy,
        request.http_port,
        effective_e2e_mode(request.e2e, &request.e2e_mode),
        request.locksmith,
    ) {
        sg_builder = sg_builder.add_block(block);
    }

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
    body = body.add_block(bootstrap_locals(
        request,
        cpu_count_rounded,
        eif_s3_path,
        &policy,
    ));

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
        .add_attribute(hcl::Attribute::new("user_data", bootstrap_reference()))
        .add_block(bootstrap_size_limit())
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

#[cfg(test)]
#[path = "deployment_tap_tests.rs"]
mod tap_tests;

#[cfg(test)]
#[path = "deployment_network_tests.rs"]
mod network_tests;
