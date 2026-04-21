// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;
use tokio::fs;
use uuid::Uuid;

/// Default timeout for tofu init/apply/destroy operations (10 minutes).
const TOFU_TIMEOUT_SECS: u64 = 600;

/// Run a command with a timeout. Kills the process if deadline expires.
fn run_with_timeout(cmd: &mut Command, timeout_secs: u64) -> Result<std::process::Output> {
    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("Failed to spawn command")?;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().context("Failed to read output"),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    bail!("Command timed out after {}s", timeout_secs);
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            Err(e) => bail!("Failed to wait on command: {}", e),
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
    pub ssh_keys: Vec<String>,
    pub domain: Option<String>,
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

pub async fn deploy_nitro_enclave(request: NitroDeploymentRequest) -> Result<DeploymentResult> {
    tracing::info!(
        "Starting Nitro Enclave deployment for resource {} ({})",
        request.resource_id,
        request.resource_name
    );

    let aws_region = request
        .credentials
        .as_ref()
        .map(|c| c.region.clone())
        .unwrap_or_else(|| std::env::var("AWS_REGION").unwrap_or_else(|_| "us-west-2".to_string()));

    let config = TerraformConfig {
        module_path: PathBuf::from("terraform/modules/aws/nitro-enclave"),
        s3_bucket: std::env::var("TERRAFORM_STATE_BUCKET")
            .unwrap_or_else(|_| "caution-terraform-state".to_string()),
        aws_region: aws_region.clone(),
    };

    if let Some(ref managed_onprem) = request.managed_onprem {
        tracing::info!("Using managed on-prem deployment flow");
        let customer_creds = request
            .credentials
            .as_ref()
            .context("Credentials required for managed on-prem")?;
        let eif_s3_path = if managed_onprem_uses_direct_customer_bucket(&request, managed_onprem) {
            tracing::info!(
                "Managed on-prem builder output already in customer bucket: {}",
                request.eif_path
            );
            Ok(request.eif_path.clone())
        } else if let Some(ref s3_key) = request.eif_s3_key {
            upload_eif_from_platform_s3_to_customer_bucket(
                s3_key,
                &request.resource_id,
                &managed_onprem.eif_bucket,
                customer_creds,
                &request.aws_account_id,
            )
            .await
        } else {
            upload_eif_to_customer_bucket(
                &request.eif_path,
                &request.resource_id,
                &managed_onprem.eif_bucket,
                customer_creds,
            )
            .await
        }
        .context("Failed to upload EIF to customer bucket")?;
        provision_managed_onprem(&request, &eif_s3_path, &config).await
    } else if let Some(ref s3_key) = request.eif_s3_key {
        // EIF already in S3 (uploaded by dedicated builder)
        let bucket = std::env::var("EIF_S3_BUCKET").unwrap_or_else(|_| {
            let account = std::env::var("AWS_ACCOUNT_ID").unwrap_or_default();
            format!("caution-eif-storage-{}", account)
        });
        let eif_s3_path = format!("s3://{}/{}", bucket, s3_key);
        tracing::info!("Using pre-uploaded EIF: {}", eif_s3_path);
        provision_nitro_enclave(&request, &eif_s3_path, &config).await
    } else {
        let eif_s3_path = upload_eif_to_s3(
            &request.eif_path,
            &request.org_id,
            &request.resource_id,
            &request.aws_account_id,
        )
        .await
        .context("Failed to upload EIF to S3")?;
        provision_nitro_enclave(&request, &eif_s3_path, &config).await
    }
}

pub async fn destroy_app(org_id: Uuid, resource_id: Uuid, resource_name: String) -> Result<()> {
    destroy_app_with_credentials(org_id, resource_id, resource_name, None, None).await
}

pub async fn destroy_app_with_credentials(
    org_id: Uuid,
    resource_id: Uuid,
    resource_name: String,
    credentials: Option<AwsCredentials>,
    asg_name: Option<String>,
) -> Result<()> {
    tracing::info!(
        "Starting Terraform destroy for resource {} ({})",
        resource_id,
        resource_name
    );

    let config = TerraformConfig::default();

    // For managed on-prem: scale ASG to 0 first so instance terminates cleanly
    // This ensures the EIP gets disassociated and security group can be deleted
    if let (Some(ref creds), Some(ref asg)) = (&credentials, &asg_name) {
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
    .await
}

/// Scale down ASG to 0 and wait for instances to terminate
async fn scale_down_asg(asg_name: &str, credentials: &AwsCredentials) -> Result<()> {
    use std::time::{Duration, Instant};

    let asg = crate::ec2::AsgClient::new(credentials);
    asg.set_desired_capacity(asg_name, 0)
        .await
        .context("Failed to set ASG desired capacity to 0")?;

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
            ssh_keys: vec![],
            domain: None,
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
}

struct TerraformConfig {
    module_path: PathBuf,
    s3_bucket: String,
    aws_region: String,
}

impl Default for TerraformConfig {
    fn default() -> Self {
        Self {
            module_path: PathBuf::from("terraform/modules/aws/nitro-enclave"),
            s3_bucket: std::env::var("TERRAFORM_STATE_BUCKET")
                .unwrap_or_else(|_| "caution-terraform-state".to_string()),
            aws_region: std::env::var("AWS_REGION").unwrap_or_else(|_| "us-west-2".to_string()),
        }
    }
}

async fn destroy_ec2_app(
    org_id: Uuid,
    resource_id: Uuid,
    resource_name: &str,
    config: &TerraformConfig,
    credentials: Option<&AwsCredentials>,
) -> Result<()> {
    tracing::info!("Starting Terraform destroy for resource: {}", resource_name);

    let temp_dir = TempDir::new().context("Failed to create temporary directory")?;
    let work_dir = temp_dir.path();

    generate_backend_config(work_dir, org_id, resource_id, &config.s3_bucket)
        .await
        .context("Failed to generate backend config")?;

    let aws_region = credentials
        .map(|c| c.region.clone())
        .unwrap_or_else(|| std::env::var("AWS_REGION").unwrap_or_else(|_| "us-west-2".to_string()));

    let minimal_tf = if credentials.is_some() {
        format!(
            r#"terraform {{
  required_version = ">= 1.0"

  required_providers {{
    aws = {{
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }}
  }}
}}

variable "provider_access_key" {{
  type      = string
  sensitive = true
  default   = ""
}}

variable "provider_secret_key" {{
  type      = string
  sensitive = true
  default   = ""
}}

variable "provider_region" {{
  type    = string
  default = ""
}}

provider "aws" {{
  region     = var.provider_region != "" ? var.provider_region : "{}"
  access_key = var.provider_access_key != "" ? var.provider_access_key : null
  secret_key = var.provider_secret_key != "" ? var.provider_secret_key : null
}}
"#,
            aws_region
        )
    } else {
        format!(
            r#"terraform {{
  required_version = ">= 1.0"

  required_providers {{
    aws = {{
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }}
  }}
}}

provider "aws" {{
  region = "{}"
}}
"#,
            aws_region
        )
    };

    fs::write(work_dir.join("main.tf"), minimal_tf)
        .await
        .context("Failed to write main.tf")?;

    run_tofu_init(work_dir, None).context("Failed to run tofu init")?;

    run_tofu_destroy(work_dir, resource_name, credentials).context("Failed to run tofu destroy")?;

    tracing::info!("Successfully destroyed EC2 for resource {}", resource_name);

    Ok(())
}

async fn generate_backend_config(
    work_dir: &Path,
    org_id: Uuid,
    resource_id: Uuid,
    s3_bucket: &str,
) -> Result<()> {
    let backend_content = format!(
        r#"terraform {{
  backend "s3" {{
    bucket  = "{}"
    key     = "organizations/{}/resources/{}/terraform.tfstate"
    region  = "us-west-2"
    encrypt = true
  }}
}}
"#,
        s3_bucket, org_id, resource_id
    );

    let backend_path = work_dir.join("backend.tf");
    fs::write(&backend_path, backend_content)
        .await
        .context("Failed to write backend.tf")?;

    Ok(())
}

fn run_tofu_init(work_dir: &Path, credentials: Option<&AwsCredentials>) -> Result<()> {
    tracing::info!("Running tofu init in {}...", work_dir.display());

    let mut cmd = Command::new("tofu");
    cmd.args(&["init", "-no-color", "-upgrade=false", "-reconfigure"])
        .current_dir(work_dir);

    if let Some(creds) = credentials {
        cmd.env("AWS_ACCESS_KEY_ID", &creds.access_key_id)
            .env("AWS_SECRET_ACCESS_KEY", &creds.secret_access_key)
            .env("AWS_REGION", &creds.region);
    }

    let output = run_with_timeout(&mut cmd, TOFU_TIMEOUT_SECS).context("tofu init failed")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        tracing::error!(
            "Tofu init failed (exit code {:?}):\nstderr: {}\nstdout: {}",
            output.status.code(),
            stderr,
            stdout
        );
        bail!("Infrastructure initialization failed");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    tracing::debug!("Tofu init output: {}", stdout);

    Ok(())
}

fn run_tofu_apply_with_provider_creds(
    work_dir: &Path,
    resource_name: &str,
    ports: &[u16],
    http_port: Option<u16>,
    credentials: Option<&AwsCredentials>,
) -> Result<()> {
    tracing::info!(
        "Running tofu apply for {} in {} (ports={:?}, http_port={:?})...",
        resource_name,
        work_dir.display(),
        ports,
        http_port
    );

    let mut cmd = Command::new("tofu");
    cmd.arg("apply")
        .arg("-auto-approve")
        .arg("-no-color")
        .current_dir(work_dir);

    let ports_var = if !ports.is_empty() {
        let ports_str: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
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

    let output = run_with_timeout(&mut cmd, TOFU_TIMEOUT_SECS).context("tofu apply failed")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        tracing::error!(
            "Tofu apply failed for {} (exit code {:?}):\nstderr: {}\nstdout: {}",
            resource_name,
            output.status.code(),
            stderr,
            stdout
        );
        bail!("Failed to run tofu apply");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    tracing::debug!("Tofu apply output: {}", stdout);

    Ok(())
}

fn get_tofu_outputs(work_dir: &Path) -> Result<DeploymentResult> {
    tracing::info!("Retrieving tofu outputs...");

    let output = run_with_timeout(
        Command::new("tofu")
            .args(&["output", "-json", "-no-color"])
            .current_dir(work_dir),
        TOFU_TIMEOUT_SECS,
    )
    .context("tofu output failed")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!("Tofu output failed: {}", stderr);
        bail!("Failed to read infrastructure outputs");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let outputs: serde_json::Value =
        serde_json::from_str(&stdout).context("Failed to parse tofu output JSON")?;

    let instance_id = outputs["instance_id"]["value"]
        .as_str()
        .context("Missing instance_id in tofu output")?
        .to_string();

    let public_ip = outputs["public_ip"]["value"]
        .as_str()
        .context("Missing public_ip in tofu output")?
        .to_string();

    let url = outputs["url"]["value"]
        .as_str()
        .context("Missing url in tofu output")?
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
    launch_template_version: String,
    eip_allocation_id: String,
    public_ip: String,
    url: String,
    instance_type: String,
}

fn get_managed_onprem_tofu_outputs(work_dir: &Path) -> Result<ManagedOnPremTerraformOutputs> {
    tracing::info!("Retrieving managed on-prem tofu outputs...");

    let output = run_with_timeout(
        Command::new("tofu")
            .args(&["output", "-json", "-no-color"])
            .current_dir(work_dir),
        TOFU_TIMEOUT_SECS,
    )
    .context("tofu output failed")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!("Tofu output failed: {}", stderr);
        bail!("Failed to read infrastructure outputs");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let outputs: serde_json::Value =
        serde_json::from_str(&stdout).context("Failed to parse tofu output JSON")?;

    Ok(ManagedOnPremTerraformOutputs {
        launch_template_id: outputs["launch_template_id"]["value"]
            .as_str()
            .context("Missing launch_template_id in tofu output")?
            .to_string(),
        launch_template_version: outputs["launch_template_version"]["value"]
            .as_str()
            .context("Missing launch_template_version in tofu output")?
            .to_string(),
        eip_allocation_id: outputs["eip_allocation_id"]["value"]
            .as_str()
            .context("Missing eip_allocation_id in tofu output")?
            .to_string(),
        public_ip: outputs["public_ip"]["value"]
            .as_str()
            .context("Missing public_ip in tofu output")?
            .to_string(),
        url: outputs["url"]["value"]
            .as_str()
            .context("Missing url in tofu output")?
            .to_string(),
        instance_type: outputs["instance_type"]["value"]
            .as_str()
            .unwrap_or("unknown")
            .to_string(),
    })
}

/// Update an existing ASG to use a new launch template
async fn update_asg_launch_template(
    asg_name: &str,
    launch_template_id: &str,
    credentials: &AwsCredentials,
) -> Result<()> {
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
        return Err(e).context("Failed to update ASG launch template after retries");
    }

    tracing::info!("Successfully updated ASG launch template");

    asg.set_desired_capacity(asg_name, 1)
        .await
        .context("Failed to set ASG desired capacity")?;

    tracing::info!("Successfully set ASG desired capacity to 1");

    Ok(())
}

/// Wait for an instance to be running in the ASG and return its instance ID
async fn wait_for_asg_instance(
    asg_name: &str,
    credentials: &AwsCredentials,
    timeout_secs: u64,
) -> Result<String> {
    use std::time::{Duration, Instant};

    tracing::info!("Waiting for instance to be running in ASG {}...", asg_name);

    let ec2 = crate::ec2::Ec2Client::new(credentials);

    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    loop {
        if start.elapsed() > timeout {
            bail!("Timeout waiting for instance in ASG {}", asg_name);
        }

        let instances = ec2
            .describe_instances(&[
                crate::ec2::Filter::new("tag:aws:autoscaling:groupName", &[asg_name]),
                crate::ec2::Filter::new("instance-state-name", &["running"]),
            ])
            .await
            .context("Failed to describe instances")?;

        if let Some(instance) = instances.first() {
            tracing::info!("Found running instance: {}", instance.instance_id);
            return Ok(instance.instance_id.clone());
        }

        tracing::debug!("No running instance found yet, waiting 10 seconds...");
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

/// Associate an Elastic IP with an instance
async fn associate_eip_with_instance(
    allocation_id: &str,
    instance_id: &str,
    credentials: &AwsCredentials,
) -> Result<()> {
    tracing::info!(
        "Associating EIP {} with instance {}",
        allocation_id,
        instance_id
    );

    let ec2 = crate::ec2::Ec2Client::new(credentials);
    ec2.associate_address(allocation_id, instance_id)
        .await
        .context("Failed to associate EIP with instance")?;

    tracing::info!("Successfully associated EIP with instance");

    Ok(())
}

fn run_tofu_destroy(
    work_dir: &Path,
    resource_name: &str,
    credentials: Option<&AwsCredentials>,
) -> Result<()> {
    tracing::info!("Running tofu destroy for {}...", resource_name);

    let mut cmd = Command::new("tofu");
    cmd.args(&["destroy", "-auto-approve", "-no-color"])
        .current_dir(work_dir);

    if let Some(creds) = credentials {
        tracing::info!("Passing user credentials to AWS provider via environment variables");
        cmd.env("TF_VAR_provider_access_key", &creds.access_key_id);
        cmd.env("TF_VAR_provider_secret_key", &creds.secret_access_key);
        cmd.env("TF_VAR_provider_region", &creds.region);
    }

    let output = run_with_timeout(&mut cmd, TOFU_TIMEOUT_SECS).context("tofu destroy failed")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        tracing::error!(
            "Tofu destroy failed for {} (exit code {:?}):\nstderr: {}\nstdout: {}",
            resource_name,
            output.status.code(),
            stderr,
            stdout
        );
        bail!("Infrastructure teardown failed");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    tracing::debug!("Tofu destroy output: {}", stdout);

    Ok(())
}

async fn upload_eif_to_s3(
    eif_path: &str,
    org_id: &Uuid,
    resource_id: &Uuid,
    aws_account_id: &str,
) -> Result<String> {
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
    let body = ByteStream::from_path(Path::new(eif_path))
        .await
        .context("Failed to read EIF file")?;

    // TODO(error-infra): S3 PutObject can fail with:
    //   Retryable:
    //     - HTTP 500/503 (InternalError/SlowDown): transient S3 errors
    //     - Network/connection errors or timeouts (large EIF files)
    //   Non-retryable:
    //     - HTTP 404 NoSuchBucket: EIF_S3_BUCKET misconfigured or bucket deleted
    //     - HTTP 403 AccessDenied: IAM role lacks s3:PutObject on this bucket/key
    //     - HTTP 400 EntityTooLarge: EIF exceeds S3 single-PUT 5GB limit (should use multipart)
    client
        .put_object()
        .bucket(&bucket_name)
        .key(&s3_key)
        .tagging(format!("org_id={}&resource_id={}", org_id, resource_id))
        .body(body)
        .send()
        .await
        .context("Failed to upload EIF to S3")?;

    let s3_path = format!("s3://{}/{}", bucket_name, s3_key);

    tracing::info!("EIF uploaded successfully to: {}", s3_path);

    Ok(s3_path)
}

async fn upload_eif_to_customer_bucket(
    eif_path: &str,
    resource_id: &Uuid,
    bucket_name: &str,
    credentials: &AwsCredentials,
) -> Result<String> {
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

        let body = ByteStream::from_path(Path::new(eif_path))
            .await
            .context("Failed to read EIF file")?;

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

    Err(last_err.unwrap()).context("Failed to upload EIF to customer bucket after retries")
}

async fn upload_eif_from_platform_s3_to_customer_bucket(
    source_s3_key: &str,
    resource_id: &Uuid,
    bucket_name: &str,
    credentials: &AwsCredentials,
    aws_account_id: &str,
) -> Result<String> {
    tracing::info!(
        "Copying EIF from platform bucket to customer bucket: source_key={}, bucket={}",
        source_s3_key,
        bucket_name
    );

    let source_bucket = std::env::var("EIF_S3_BUCKET")
        .unwrap_or_else(|_| format!("caution-eif-storage-{}", aws_account_id));
    let platform_config = aws_config::load_from_env().await;
    let platform_client = aws_sdk_s3::Client::new(&platform_config);

    let source_obj = platform_client
        .get_object()
        .bucket(&source_bucket)
        .key(source_s3_key)
        .send()
        .await
        .context("Failed to download EIF from platform bucket")?;

    let data = source_obj
        .body
        .collect()
        .await
        .context("Failed to read EIF from platform bucket")?;

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

    client
        .put_object()
        .bucket(bucket_name)
        .key(&s3_key)
        .body(data.into_bytes().into())
        .send()
        .await
        .context("Failed to upload EIF to customer bucket")?;

    let s3_path = format!("s3://{}/{}", bucket_name, s3_key);
    tracing::info!("EIF copied successfully to customer bucket: {}", s3_path);
    Ok(s3_path)
}

async fn provision_nitro_enclave(
    request: &NitroDeploymentRequest,
    eif_s3_path: &str,
    config: &TerraformConfig,
) -> Result<DeploymentResult> {
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
        tracing::info!("Using user-provided AWS credentials for provider (Caution credentials for state backend)");
    }

    let temp_dir = TempDir::new().context("Failed to create temporary directory")?;
    let work_dir = temp_dir.path();

    generate_backend_config(
        work_dir,
        request.org_id,
        request.resource_id,
        &config.s3_bucket,
    )
    .await
    .context("Failed to generate backend config")?;

    generate_nitro_deployment_main_tf(work_dir, request, eif_s3_path)
        .await
        .context("Failed to generate main.tf")?;

    let user_data_template = std::fs::read_to_string(config.module_path.join("user-data.sh"))
        .context("Failed to read user-data.sh template")?;
    std::fs::write(work_dir.join("user-data.sh"), user_data_template)
        .context("Failed to write user-data.sh")?;

    // Always use Caution's env credentials for init (S3 state backend access)
    run_tofu_init(work_dir, None).context("Failed to run tofu init")?;

    // Pass user credentials as Terraform variables, not env vars
    // This keeps Caution's creds for S3 state but uses user's creds for AWS provider
    run_tofu_apply_with_provider_creds(
        work_dir,
        &request.resource_name,
        &request.ports,
        request.http_port,
        request.credentials.as_ref(),
    )
    .context("Failed to run tofu apply")?;

    let result = get_tofu_outputs(work_dir).context("Failed to get tofu outputs")?;

    tracing::info!(
        "Successfully provisioned Nitro Enclave for resource {} at {}",
        request.resource_name,
        result.public_ip
    );

    Ok(result)
}

async fn provision_managed_onprem(
    request: &NitroDeploymentRequest,
    eif_s3_path: &str,
    config: &TerraformConfig,
) -> Result<DeploymentResult> {
    let onprem = request
        .managed_onprem
        .as_ref()
        .context("Missing managed_onprem config")?;

    tracing::info!(
        "Starting managed on-prem deployment for resource: {} (deployment_id: {})",
        request.resource_name,
        onprem.deployment_id
    );

    let temp_dir = TempDir::new().context("Failed to create temporary directory")?;
    let work_dir = temp_dir.path();

    generate_backend_config(
        work_dir,
        request.org_id,
        request.resource_id,
        &config.s3_bucket,
    )
    .await
    .context("Failed to generate backend config")?;

    generate_managed_onprem_deployment_tf(work_dir, request, eif_s3_path)
        .await
        .context("Failed to generate main.tf")?;

    let user_data_template = std::fs::read_to_string(config.module_path.join("user-data.sh"))
        .context("Failed to read user-data.sh template")?;
    std::fs::write(work_dir.join("user-data.sh"), user_data_template)
        .context("Failed to write user-data.sh")?;

    run_tofu_init(work_dir, None).context("Failed to run tofu init")?;

    run_tofu_apply_with_provider_creds(
        work_dir,
        &request.resource_name,
        &request.ports,
        request.http_port,
        request.credentials.as_ref(),
    )
    .context("Failed to run tofu apply")?;

    let tf_outputs =
        get_managed_onprem_tofu_outputs(work_dir).context("Failed to get tofu outputs")?;

    tracing::info!(
        "Terraform created launch template {} and EIP {}",
        tf_outputs.launch_template_id,
        tf_outputs.eip_allocation_id
    );

    let credentials = request
        .credentials
        .as_ref()
        .context("Missing AWS credentials for managed on-prem deployment")?;

    update_asg_launch_template(
        &onprem.asg_name,
        &tf_outputs.launch_template_id,
        credentials,
    )
    .await
    .context("Failed to update ASG")?;

    let instance_id = wait_for_asg_instance(&onprem.asg_name, credentials, 300)
        .await
        .context("Failed to wait for instance")?;

    associate_eip_with_instance(&tf_outputs.eip_allocation_id, &instance_id, credentials)
        .await
        .context("Failed to associate EIP")?;

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

fn select_instance_type(cpu_count: u32, memory_mb: u32) -> &'static str {
    let total_vcpus_needed = cpu_count + 2;
    let total_memory_gb_needed = (memory_mb / 1024) + 2;

    if total_vcpus_needed <= 4 && total_memory_gb_needed <= 16 {
        "m5.xlarge"
    } else if total_vcpus_needed <= 8 && total_memory_gb_needed <= 32 {
        "m5.2xlarge"
    } else if total_vcpus_needed <= 16 && total_memory_gb_needed <= 64 {
        "m5.4xlarge"
    } else {
        "m5.8xlarge"
    }
}

fn compute_enclave_sizing(request: &NitroDeploymentRequest) -> (u32, &'static str) {
    let cpu_count_rounded = if request.cpu_count % 2 == 0 {
        request.cpu_count
    } else {
        request.cpu_count + 1
    };

    if cpu_count_rounded != request.cpu_count {
        tracing::warn!(
            "Rounded CPU count from {} to {} (Nitro Enclaves requires even numbers)",
            request.cpu_count,
            cpu_count_rounded
        );
    }

    let instance_type = select_instance_type(cpu_count_rounded, request.memory_mb);
    tracing::info!(
        "Selected instance type {} for {} CPUs and {} MB memory (total needed: {} vCPUs, {} GB)",
        instance_type,
        cpu_count_rounded,
        request.memory_mb,
        cpu_count_rounded + 2,
        (request.memory_mb / 1024) + 2
    );

    (cpu_count_rounded, instance_type)
}

async fn generate_nitro_deployment_main_tf(
    work_dir: &Path,
    request: &NitroDeploymentRequest,
    eif_s3_path: &str,
) -> Result<()> {
    let aws_region = request
        .credentials
        .as_ref()
        .map(|c| c.region.clone())
        .unwrap_or_else(|| std::env::var("AWS_REGION").unwrap_or_else(|_| "us-west-2".to_string()));
    let ssh_key_name = std::env::var("SSH_KEY_NAME").ok();

    let (cpu_count_rounded, instance_type) = compute_enclave_sizing(request);

    let provider_block = if request.credentials.is_some() {
        format!(
            r#"variable "provider_access_key" {{
  type      = string
  sensitive = true
  default   = ""
}}

variable "provider_secret_key" {{
  type      = string
  sensitive = true
  default   = ""
}}

variable "provider_region" {{
  type    = string
  default = ""
}}

provider "aws" {{
  region     = var.provider_region != "" ? var.provider_region : "{region}"
  access_key = var.provider_access_key != "" ? var.provider_access_key : null
  secret_key = var.provider_secret_key != "" ? var.provider_secret_key : null

  default_tags {{
    tags = {{
      org_id    = "{org_id}"
      ManagedBy = "caution+tofu"
    }}
  }}
}}"#,
            region = aws_region,
            org_id = request.org_id,
        )
    } else {
        format!(
            r#"provider "aws" {{
  region = "{region}"

  default_tags {{
    tags = {{
      org_id    = "{org_id}"
      ManagedBy = "caution+tofu"
    }}
  }}
}}"#,
            region = aws_region,
            org_id = request.org_id,
        )
    };

    let eif_bucket = std::env::var("EIF_S3_BUCKET")
        .unwrap_or_else(|_| format!("caution-eif-storage-{}", request.aws_account_id));

    let main_tf_content = format!(
        r#"terraform {{
  required_version = ">= 1.0"

  required_providers {{
    aws = {{
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }}
  }}
}}

{provider_block}

# Data source for availability zones
data "aws_availability_zones" "available" {{
  state = "available"
}}

# Data source for latest Amazon Linux 2023 AMI
data "aws_ami" "amazon_linux_2023" {{
  most_recent = true
  owners      = ["amazon"]

  filter {{
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }}

  filter {{
    name   = "virtualization-type"
    values = ["hvm"]
  }}

  filter {{
    name   = "root-device-type"
    values = ["ebs"]
  }}
}}

# IAM role for EC2 instance to access S3
resource "aws_iam_role" "enclave" {{
  name_prefix = "enclave-{short_id}-"

  assume_role_policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {{
          Service = "ec2.amazonaws.com"
        }}
      }}
    ]
  }})

  tags = {{
    Name         = "enclave-role-{resource_id}"
    ResourceId   = "{resource_id}"
  }}
}}

# IAM policy for S3 access (scoped to org prefix)
resource "aws_iam_role_policy" "enclave_s3" {{
  name_prefix = "enclave-s3-{short_id}-"
  role        = aws_iam_role.enclave.id

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Effect = "Allow"
        Action = [
          "s3:GetObject"
        ]
        Resource = [
          "arn:aws:s3:::{eif_bucket}/eifs/{org_id}/*"
        ]
      }}
    ]
  }})
}}

# IAM instance profile
resource "aws_iam_instance_profile" "enclave" {{
  name_prefix = "enclave-{short_id}-"
  role        = aws_iam_role.enclave.name

  tags = {{
    Name         = "enclave-profile-{resource_id}"
    ResourceId   = "{resource_id}"
  }}
}}

# VPC for this resource
resource "aws_vpc" "enclave" {{
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {{
    Name         = "vpc-{resource_id}"
    ResourceId   = "{resource_id}"
  }}
}}

# Internet Gateway
resource "aws_internet_gateway" "enclave" {{
  vpc_id = aws_vpc.enclave.id

  tags = {{
    Name         = "igw-{resource_id}"
    ResourceId   = "{resource_id}"
  }}
}}

# Public subnet
resource "aws_subnet" "enclave" {{
  vpc_id                  = aws_vpc.enclave.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = data.aws_availability_zones.available.names[0]

  tags = {{
    Name         = "subnet-{resource_id}"
    ResourceId   = "{resource_id}"
  }}
}}

# Route table
resource "aws_route_table" "enclave" {{
  vpc_id = aws_vpc.enclave.id

  route {{
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.enclave.id
  }}

  tags = {{
    Name         = "rt-{resource_id}"
    ResourceId   = "{resource_id}"
  }}
}}

# Route table association
resource "aws_route_table_association" "enclave" {{
  subnet_id      = aws_subnet.enclave.id
  route_table_id = aws_route_table.enclave.id
}}

# User ports variable
# Note: Attestation is served via Caddy on port 443 at /attestation path

variable "ports" {{
  type    = list(number)
  default = []
}}

variable "http_port" {{
  type    = number
  default = 0
}}

# Security group for the enclave
resource "aws_security_group" "enclave" {{
  name_prefix = "enclave-{short_id}-"
  description = "Security group for {resource_id} Nitro Enclave"
  vpc_id      = aws_vpc.enclave.id

  {ssh_ingress}

  ingress {{
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTP"
  }}

  ingress {{
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS"
  }}

  # Dynamic user ports
  dynamic "ingress" {{
    for_each = var.ports
    content {{
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
      description = "Allow user port ${{ingress.value}}"
    }}
  }}

  egress {{
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound"
  }}

  tags = {{
    Name         = "enclave-{resource_id}"
    ResourceId   = "{resource_id}"
  }}
}}

# EC2 instance for Nitro Enclave
resource "aws_instance" "enclave" {{
  ami                  = data.aws_ami.amazon_linux_2023.id
  instance_type        = "{instance_type}"
  iam_instance_profile = aws_iam_instance_profile.enclave.name

  vpc_security_group_ids = [aws_security_group.enclave.id]
  subnet_id              = aws_subnet.enclave.id
{ssh_key_line}
  enclave_options {{
    enabled = true
  }}

  metadata_options {{
    http_endpoint = "enabled"
    http_tokens   = "required"
  }}

  root_block_device {{
    volume_size           = {disk_gb}
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }}

  user_data_replace_on_change = true
  user_data = base64encode(templatefile("./user-data.sh", {{
    eif_s3_path = "{eif_s3_path}"
    memory_mb   = {memory_mb}
    cpu_count   = {cpu_count}
    debug_mode  = "{debug_mode}"
    ports       = var.ports
    http_port   = var.http_port
    ssh_keys    = {ssh_keys_json}
    domain      = "{domain}"
  }}))

  tags = {{
    Name         = "{resource_id}"
    ResourceId   = "{resource_id}"
    ConfigDomain = "{domain}"
  }}
}}

# Elastic IP for the enclave
resource "aws_eip" "enclave" {{
  domain   = "vpc"
  instance = aws_instance.enclave.id

  tags = {{
    Name         = "enclave-{resource_id}"
    ResourceId   = "{resource_id}"
  }}
}}

output "instance_id" {{
  value = aws_instance.enclave.id
}}

output "public_ip" {{
  value = aws_eip.enclave.public_ip
}}

output "url" {{
  value = "{url_output}"
}}

output "instance_type" {{
  value = "{instance_type}"
}}
"#,
        provider_block = provider_block,
        instance_type = instance_type,
        ssh_key_line = ssh_key_name
            .as_ref()
            .map(|key| format!("\n  key_name = \"{}\"", key))
            .unwrap_or_default(),
        resource_id = request.resource_id,
        short_id = &request.resource_id.to_string()[..8],
        org_id = request.org_id,
        eif_s3_path = eif_s3_path,
        eif_bucket = eif_bucket,
        memory_mb = request.memory_mb,
        cpu_count = cpu_count_rounded,
        disk_gb = request.disk_gb,
        debug_mode = if request.debug_mode { "true" } else { "false" },
        ssh_keys_json =
            serde_json::to_string(&request.ssh_keys).unwrap_or_else(|_| "[]".to_string()),
        ssh_ingress = if request.ssh_keys.is_empty() {
            "# SSH ingress disabled (no ssh_keys in Procfile)".to_string()
        } else {
            "# SSH enabled (ssh_keys configured in Procfile)\n  ingress {\n    from_port   = 22\n    to_port     = 22\n    protocol    = \"tcp\"\n    cidr_blocks = [\"0.0.0.0/0\"]\n    description = \"Allow SSH\"\n  }".to_string()
        },
        domain = request.domain.as_deref().unwrap_or(""),
        url_output = if let Some(ref domain) = request.domain {
            format!("https://{}", domain)
        } else {
            "https://${aws_eip.enclave.public_ip}".to_string()
        },
    );

    fs::write(work_dir.join("main.tf"), main_tf_content)
        .await
        .context("Failed to write main.tf")?;

    Ok(())
}

async fn generate_managed_onprem_deployment_tf(
    work_dir: &Path,
    request: &NitroDeploymentRequest,
    eif_s3_path: &str,
) -> Result<()> {
    let onprem = request
        .managed_onprem
        .as_ref()
        .context("Missing managed_onprem config")?;

    let aws_region = request
        .credentials
        .as_ref()
        .map(|c| c.region.clone())
        .unwrap_or_else(|| std::env::var("AWS_REGION").unwrap_or_else(|_| "us-west-2".to_string()));

    let (cpu_count_rounded, instance_type) = compute_enclave_sizing(request);

    let main_tf_content = format!(
        r#"terraform {{
  required_version = ">= 1.0"

  required_providers {{
    aws = {{
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }}
  }}
}}

variable "provider_access_key" {{
  type      = string
  sensitive = true
  default   = ""
}}

variable "provider_secret_key" {{
  type      = string
  sensitive = true
  default   = ""
}}

variable "provider_region" {{
  type    = string
  default = ""
}}

variable "asg_name" {{
  type    = string
  default = "{asg_name}"
}}

provider "aws" {{
  region     = var.provider_region != "" ? var.provider_region : "{region}"
  access_key = var.provider_access_key != "" ? var.provider_access_key : null
  secret_key = var.provider_secret_key != "" ? var.provider_secret_key : null

  default_tags {{
    tags = {{
      org_id    = "{org_id}"
      ManagedBy = "caution+tofu"
    }}
  }}
}}

variable "ports" {{
  type    = list(number)
  default = []
}}

variable "http_port" {{
  type    = number
  default = 0
}}

locals {{
  deployment_tag = "{deployment_id}"
  scope_tag_key  = "caution:deployment-id"
  aws_region     = var.provider_region != "" ? var.provider_region : "{region}"
}}

data "aws_ami" "amazon_linux_2023" {{
  most_recent = true
  owners      = ["amazon"]

  filter {{
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }}

  filter {{
    name   = "virtualization-type"
    values = ["hvm"]
  }}

  filter {{
    name   = "root-device-type"
    values = ["ebs"]
  }}
}}

resource "aws_security_group" "enclave" {{
  name_prefix = "enclave-{short_id}-"
  description = "Security group for {resource_id} Nitro Enclave"
  vpc_id      = "{vpc_id}"

  {ssh_ingress}

  ingress {{
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTP"
  }}

  ingress {{
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS"
  }}

  dynamic "ingress" {{
    for_each = var.ports
    content {{
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
      description = "Allow user port ${{ingress.value}}"
    }}
  }}

  egress {{
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound"
  }}

  tags = {{
    Name                  = "enclave-{resource_id}"
    ResourceId            = "{resource_id}"
    (local.scope_tag_key) = local.deployment_tag
  }}
}}

resource "aws_launch_template" "enclave" {{
  name_prefix   = "enclave-{resource_id}-"
  image_id      = data.aws_ami.amazon_linux_2023.id
  instance_type = "{instance_type}"

  iam_instance_profile {{
    name = "{instance_profile_name}"
  }}

  vpc_security_group_ids = [aws_security_group.enclave.id]

  enclave_options {{
    enabled = true
  }}

  metadata_options {{
    http_endpoint = "enabled"
    http_tokens   = "required"
  }}

  block_device_mappings {{
    device_name = "/dev/xvda"
    ebs {{
      volume_size           = {disk_gb}
      volume_type           = "gp3"
      delete_on_termination = true
      encrypted             = true
    }}
  }}

  user_data = base64encode(templatefile("./user-data.sh", {{
    eif_s3_path = "{eif_s3_path}"
    memory_mb   = {memory_mb}
    cpu_count   = {cpu_count}
    debug_mode  = "{debug_mode}"
    ports       = var.ports
    http_port   = var.http_port
    ssh_keys    = {ssh_keys_json}
    domain      = "{domain}"
  }}))

  tag_specifications {{
    resource_type = "instance"
    tags = {{
      Name                  = "{resource_id}"
      ResourceId            = "{resource_id}"
      ConfigDomain          = "{domain}"
      (local.scope_tag_key) = local.deployment_tag
    }}
  }}

  tag_specifications {{
    resource_type = "volume"
    tags = {{
      Name                  = "enclave-{resource_id}"
      ResourceId            = "{resource_id}"
      (local.scope_tag_key) = local.deployment_tag
    }}
  }}

  tags = {{
    Name                  = "lt-{resource_id}"
    ResourceId            = "{resource_id}"
    (local.scope_tag_key) = local.deployment_tag
  }}
}}

resource "aws_eip" "enclave" {{
  domain = "vpc"

  tags = {{
    Name                  = "enclave-{resource_id}"
    ResourceId            = "{resource_id}"
    (local.scope_tag_key) = local.deployment_tag
  }}
}}

# Outputs - ASG update and EIP association are handled by the API server
output "launch_template_id" {{
  value = aws_launch_template.enclave.id
}}

output "launch_template_version" {{
  value = tostring(aws_launch_template.enclave.latest_version)
}}

output "eip_allocation_id" {{
  value = aws_eip.enclave.id
}}

output "public_ip" {{
  value = aws_eip.enclave.public_ip
}}

output "url" {{
  value = "{url_output}"
}}

output "instance_type" {{
  value = "{instance_type}"
}}
"#,
        region = aws_region,
        deployment_id = onprem.deployment_id,
        vpc_id = onprem.vpc_id,
        asg_name = onprem.asg_name,
        instance_type = instance_type,
        instance_profile_name = onprem.instance_profile_name,
        resource_id = request.resource_id,
        short_id = &request.resource_id.to_string()[..8],
        org_id = request.org_id,
        eif_s3_path = eif_s3_path,
        memory_mb = request.memory_mb,
        cpu_count = cpu_count_rounded,
        disk_gb = request.disk_gb,
        debug_mode = if request.debug_mode { "true" } else { "false" },
        ssh_keys_json =
            serde_json::to_string(&request.ssh_keys).unwrap_or_else(|_| "[]".to_string()),
        ssh_ingress = if request.ssh_keys.is_empty() {
            "# SSH ingress disabled (no ssh_keys in Procfile)".to_string()
        } else {
            "# SSH enabled (ssh_keys configured in Procfile)\n  ingress {\n    from_port   = 22\n    to_port     = 22\n    protocol    = \"tcp\"\n    cidr_blocks = [\"0.0.0.0/0\"]\n    description = \"Allow SSH\"\n  }".to_string()
        },
        domain = request.domain.as_deref().unwrap_or(""),
        url_output = if let Some(ref domain) = request.domain {
            format!("https://{}", domain)
        } else {
            "https://${aws_eip.enclave.public_ip}".to_string()
        },
    );

    fs::write(work_dir.join("main.tf"), main_tf_content)
        .await
        .context("Failed to write main.tf")?;

    Ok(())
}
