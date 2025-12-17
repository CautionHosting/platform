// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;
use tokio::fs;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub region: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentRequest {
    pub org_id: Uuid,
    pub resource_id: i64,
    pub resource_name: String,
    pub aws_account_id: String,
    pub role_arn: Option<String>,
    pub ami_id: String,
    pub app_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentResult {
    pub instance_id: String,
    pub public_ip: String,
    pub url: String,
}

pub async fn deploy_app(request: DeploymentRequest) -> Result<DeploymentResult> {
    tracing::info!(
        "Starting Terraform deployment for resource {} ({})",
        request.resource_id,
        request.resource_name
    );

    let config = TerraformConfig::default();

    provision_ec2_app(
        &request,
        &config,
    ).await
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NitroDeploymentRequest {
    pub org_id: Uuid,
    pub resource_id: i64,
    pub resource_name: String,
    pub aws_account_id: String,
    pub role_arn: Option<String>,
    pub eif_path: String,
    pub memory_mb: u32,
    pub cpu_count: u32,
    pub debug_mode: bool,
    pub ports: Vec<u16>,
    #[serde(skip)]
    pub credentials: Option<AwsCredentials>,
}

pub async fn deploy_nitro_enclave(request: NitroDeploymentRequest) -> Result<DeploymentResult> {
    tracing::info!(
        "Starting Nitro Enclave deployment for resource {} ({})",
        request.resource_id,
        request.resource_name
    );

    let eif_s3_path = upload_eif_to_s3(&request.eif_path, &request.org_id, &request.resource_name).await
        .context("Failed to upload EIF to S3")?;

    let aws_region = request.credentials.as_ref()
        .map(|c| c.region.clone())
        .unwrap_or_else(|| std::env::var("AWS_REGION").unwrap_or_else(|_| "us-west-2".to_string()));

    let config = TerraformConfig {
        module_path: PathBuf::from("terraform/modules/aws/nitro-enclave"),
        s3_bucket: std::env::var("TERRAFORM_STATE_BUCKET")
            .unwrap_or_else(|_| "caution-terraform-state".to_string()),
        aws_region,
    };

    provision_nitro_enclave(&request, &eif_s3_path, &config).await
}

pub async fn destroy_app(
    org_id: Uuid,
    resource_id: i64,
    resource_name: String,
) -> Result<()> {
    tracing::info!(
        "Starting Terraform destroy for resource {} ({})",
        resource_id,
        resource_name
    );

    let config = TerraformConfig::default();

    destroy_ec2_app(
        org_id,
        resource_id,
        &resource_name,
        &config,
    ).await
}

struct TerraformConfig {
    module_path: PathBuf,
    s3_bucket: String,
    aws_region: String,
}

impl Default for TerraformConfig {
    fn default() -> Self {
        Self {
            module_path: PathBuf::from("terraform/modules/aws/ec2-app"),
            s3_bucket: std::env::var("TERRAFORM_STATE_BUCKET")
                .unwrap_or_else(|_| "caution-terraform-state".to_string()),
            aws_region: std::env::var("AWS_REGION")
                .unwrap_or_else(|_| "us-west-2".to_string()),
        }
    }
}

async fn provision_ec2_app(
    request: &DeploymentRequest,
    config: &TerraformConfig,
) -> Result<DeploymentResult> {
    tracing::info!("Starting Terraform EC2 provisioning for resource: {}", request.resource_name);

    let temp_dir = TempDir::new()
        .context("Failed to create temporary directory")?;
    let work_dir = temp_dir.path();

    copy_module_directory(&config.module_path, work_dir).await
        .context("Failed to copy module directory")?;

    generate_backend_config(work_dir, request.org_id, request.resource_id, &config.s3_bucket).await
        .context("Failed to generate backend config")?;

    generate_deployment_main_tf(work_dir, request).await
        .context("Failed to generate root.tf")?;

    run_tofu_init(work_dir, None)
        .context("Failed to run tofu init")?;

    run_tofu_apply(work_dir, &request.resource_name, None)
        .context("Failed to run tofu apply")?;
    
    let result = get_tofu_outputs(work_dir)
        .context("Failed to get tofu outputs")?;
    
    tracing::info!(
        "Successfully provisioned EC2 for resource {} at {}",
        request.resource_name,
        result.public_ip
    );
    
    Ok(result)
}

async fn destroy_ec2_app(
    org_id: Uuid,
    resource_id: i64,
    resource_name: &str,
    config: &TerraformConfig,
) -> Result<()> {
    tracing::info!("Starting Terraform destroy for resource: {}", resource_name);

    let temp_dir = TempDir::new()
        .context("Failed to create temporary directory")?;
    let work_dir = temp_dir.path();

    generate_backend_config(work_dir, org_id, resource_id, &config.s3_bucket).await
        .context("Failed to generate backend config")?;
    
    let aws_region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-west-2".to_string());
    let minimal_tf = format!(
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
    );
    
    fs::write(work_dir.join("main.tf"), minimal_tf).await
        .context("Failed to write main.tf")?;

    run_tofu_init(work_dir, None)
        .context("Failed to run tofu init")?;

    run_tofu_destroy(work_dir, resource_name, None)
        .context("Failed to run tofu destroy")?;

    tracing::info!("Successfully destroyed EC2 for resource {}", resource_name);

    Ok(())
}

async fn copy_module_directory(source: &Path, dest: &Path) -> Result<()> {
    use tokio::fs;
    
    let modules_dir = dest.join("modules");
    fs::create_dir_all(&modules_dir).await
        .context("Failed to create modules directory")?;
    
    copy_dir_recursive(source, &modules_dir.join("ec2-app")).await
        .context("Failed to copy module files")?;
    
    Ok(())
}

async fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    use tokio::fs;
    
    fs::create_dir_all(dst).await?;
    
    let mut entries = fs::read_dir(src).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let file_name = entry.file_name();
        let dst_path = dst.join(&file_name);
        
        if path.is_dir() {
            Box::pin(copy_dir_recursive(&path, &dst_path)).await?;
        } else {
            fs::copy(&path, &dst_path).await?;
        }
    }
    
    Ok(())
}

async fn generate_backend_config(
    work_dir: &Path,
    org_id: Uuid,
    resource_id: i64,
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
    fs::write(&backend_path, backend_content).await
        .context("Failed to write backend.tf")?;
    
    Ok(())
}

async fn generate_deployment_main_tf(
    work_dir: &Path,
    request: &DeploymentRequest,
) -> Result<()> {
    let aws_region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-west-2".to_string());

    let main_content = format!(
        r#"# Auto-generated deployment configuration for {}

terraform {{
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

# Get default VPC (MVP)
data "aws_vpc" "default" {{
  default = true
}}

# Get default subnets
data "aws_subnets" "default" {{
  filter {{
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }}
  
  filter {{
    name   = "default-for-az"
    values = ["true"]
  }}
}}

module "app" {{
  source = "./modules/ec2-app"

  org_id        = "{}"
  resource_id   = "{}"
  resource_name = "{}"
  ami_id        = "{}"
  app_port      = {}
  aws_region    = "{}"

  # Use default VPC for MVP
  vpc_id    = data.aws_vpc.default.id
  subnet_id = data.aws_subnets.default.ids[0]
}}

# Expose module outputs at root level
output "instance_id" {{
  description = "EC2 instance ID"
  value       = module.app.instance_id
}}

output "public_ip" {{
  description = "Public IP address"
  value       = module.app.public_ip
}}

output "url" {{
  description = "Application URL"
  value       = module.app.url
}}
"#,
        request.resource_name,
        aws_region,
        request.org_id,
        request.resource_id,
        request.resource_name,
        request.ami_id,
        request.app_port,
        aws_region
    );
    
    let main_path = work_dir.join("root.tf");
    fs::write(&main_path, main_content).await
        .context("Failed to write root.tf")?;
    
    Ok(())
}

fn run_tofu_init(work_dir: &Path, credentials: Option<&AwsCredentials>) -> Result<()> {
    tracing::info!("Running tofu init...");

    let mut cmd = Command::new("tofu");
    cmd.args(&["init", "-no-color", "-upgrade=false", "-reconfigure"])
        .current_dir(work_dir);

    if let Some(creds) = credentials {
        cmd.env("AWS_ACCESS_KEY_ID", &creds.access_key_id)
            .env("AWS_SECRET_ACCESS_KEY", &creds.secret_access_key)
            .env("AWS_REGION", &creds.region);
    }

    let output = cmd.output()
        .context("Failed to execute tofu init")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!("Tofu init failed: {}", stderr);
        bail!("Tofu init failed: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    tracing::debug!("Tofu init output: {}", stdout);

    Ok(())
}

fn run_tofu_apply(work_dir: &Path, resource_name: &str, credentials: Option<&AwsCredentials>) -> Result<()> {
    run_tofu_apply_with_vars(work_dir, resource_name, &[], credentials)
}

fn run_tofu_apply_with_vars(work_dir: &Path, resource_name: &str, ports: &[u16], credentials: Option<&AwsCredentials>) -> Result<()> {
    tracing::info!("Running tofu apply for {}...", resource_name);

    let mut args = vec!["apply", "-auto-approve", "-no-color"];

    let ports_var = if !ports.is_empty() {
        let ports_str: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
        format!("ports=[{}]", ports_str.join(","))
    } else {
        "ports=[]".to_string()
    };

    args.push("-var");
    let ports_var_ref: &str = &ports_var;

    let mut cmd = Command::new("tofu");
    cmd.args(&args)
        .arg(ports_var_ref)
        .current_dir(work_dir);

    if let Some(creds) = credentials {
        cmd.env("AWS_ACCESS_KEY_ID", &creds.access_key_id)
            .env("AWS_SECRET_ACCESS_KEY", &creds.secret_access_key)
            .env("AWS_REGION", &creds.region);
    }

    let output = cmd.output()
        .context("Failed to execute tofu apply")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!("Tofu apply failed: {}", stderr);
        bail!("Tofu apply failed: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    tracing::debug!("Tofu apply output: {}", stdout);

    Ok(())
}

fn get_tofu_outputs(work_dir: &Path) -> Result<DeploymentResult> {
    tracing::info!("Retrieving tofu outputs...");
    
    let output = Command::new("tofu")
        .args(&["output", "-json", "-no-color"])
        .current_dir(work_dir)
        .output()
        .context("Failed to execute tofu output")?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Tofu output failed: {}", stderr);
    }
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let outputs: serde_json::Value = serde_json::from_str(&stdout)
        .context("Failed to parse tofu output JSON")?;
    
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
    
    Ok(DeploymentResult {
        instance_id,
        public_ip,
        url,
    })
}

fn run_tofu_destroy(work_dir: &Path, resource_name: &str, credentials: Option<&AwsCredentials>) -> Result<()> {
    tracing::info!("Running tofu destroy for {}...", resource_name);

    let mut cmd = Command::new("tofu");
    cmd.args(&["destroy", "-auto-approve", "-no-color"])
        .current_dir(work_dir);

    if let Some(creds) = credentials {
        cmd.env("AWS_ACCESS_KEY_ID", &creds.access_key_id)
            .env("AWS_SECRET_ACCESS_KEY", &creds.secret_access_key)
            .env("AWS_REGION", &creds.region);
    }

    let output = cmd.output()
        .context("Failed to execute tofu destroy")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!("Tofu destroy failed: {}", stderr);
        bail!("Tofu destroy failed: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    tracing::debug!("Tofu destroy output: {}", stdout);

    Ok(())
}

async fn upload_eif_to_s3(eif_path: &str, org_id: &Uuid, resource_name: &str) -> Result<String> {
    use aws_sdk_s3::primitives::ByteStream;

    tracing::info!("Uploading EIF to S3: {}", eif_path);

    let bucket_name = std::env::var("EIF_S3_BUCKET")
        .unwrap_or_else(|_| "caution-eif-storage".to_string());

    let s3_key = format!("eifs/{}/{}.eif", org_id, resource_name);

    let config = aws_config::load_from_env().await;
    let client = aws_sdk_s3::Client::new(&config);

    let body = ByteStream::from_path(Path::new(eif_path)).await
        .context("Failed to read EIF file")?;

    client
        .put_object()
        .bucket(&bucket_name)
        .key(&s3_key)
        .body(body)
        .send()
        .await
        .context("Failed to upload EIF to S3")?;

    let s3_path = format!("s3://{}/{}", bucket_name, s3_key);

    tracing::info!("EIF uploaded successfully to: {}", s3_path);

    Ok(s3_path)
}

async fn provision_nitro_enclave(
    request: &NitroDeploymentRequest,
    eif_s3_path: &str,
    config: &TerraformConfig,
) -> Result<DeploymentResult> {
    tracing::info!("Starting Terraform Nitro Enclave provisioning for resource: {}", request.resource_name);

    let temp_dir = TempDir::new()
        .context("Failed to create temporary directory")?;
    let work_dir = temp_dir.path();

    generate_backend_config(work_dir, request.org_id, request.resource_id, &config.s3_bucket).await
        .context("Failed to generate backend config")?;

    generate_nitro_deployment_main_tf(work_dir, request, eif_s3_path).await
        .context("Failed to generate main.tf")?;

    let user_data_template = std::fs::read_to_string(config.module_path.join("user-data.sh"))
        .context("Failed to read user-data.sh template")?;
    std::fs::write(work_dir.join("user-data.sh"), user_data_template)
        .context("Failed to write user-data.sh")?;

    run_tofu_init(work_dir, request.credentials.as_ref())
        .context("Failed to run tofu init")?;

    run_tofu_apply_with_vars(work_dir, &request.resource_name, &request.ports, request.credentials.as_ref())
        .context("Failed to run tofu apply")?;

    let result = get_tofu_outputs(work_dir)
        .context("Failed to get tofu outputs")?;

    tracing::info!(
        "Successfully provisioned Nitro Enclave for resource {} at {}",
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

async fn generate_nitro_deployment_main_tf(
    work_dir: &Path,
    request: &NitroDeploymentRequest,
    eif_s3_path: &str,
) -> Result<()> {
    let aws_region = request.credentials.as_ref()
        .map(|c| c.region.clone())
        .unwrap_or_else(|| std::env::var("AWS_REGION").unwrap_or_else(|_| "us-west-2".to_string()));
    let ssh_key_name = std::env::var("SSH_KEY_NAME").ok();

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

provider "aws" {{
  region = "{region}"
}}

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
  name_prefix = "enclave-{resource_name}-"

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
    Name         = "enclave-role-{resource_name}"
    ResourceId   = "{resource_id}"
    ResourceName = "{resource_name}"
    OrgId        = "{org_id}"
    ManagedBy    = "terraform"
  }}
}}

# IAM policy for S3 access
resource "aws_iam_role_policy" "enclave_s3" {{
  name_prefix = "enclave-s3-{resource_name}-"
  role        = aws_iam_role.enclave.id

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::caution-eif-storage",
          "arn:aws:s3:::caution-eif-storage/*"
        ]
      }}
    ]
  }})
}}

# IAM instance profile
resource "aws_iam_instance_profile" "enclave" {{
  name_prefix = "enclave-{resource_name}-"
  role        = aws_iam_role.enclave.name

  tags = {{
    Name         = "enclave-profile-{resource_name}"
    ResourceId   = "{resource_id}"
    ResourceName = "{resource_name}"
    OrgId        = "{org_id}"
    ManagedBy    = "terraform"
  }}
}}

# VPC for this resource
resource "aws_vpc" "enclave" {{
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {{
    Name         = "vpc-{resource_name}"
    ResourceId   = "{resource_id}"
    ResourceName = "{resource_name}"
    OrgId        = "{org_id}"
    ManagedBy    = "terraform"
  }}
}}

# Internet Gateway
resource "aws_internet_gateway" "enclave" {{
  vpc_id = aws_vpc.enclave.id

  tags = {{
    Name         = "igw-{resource_name}"
    ResourceId   = "{resource_id}"
    ResourceName = "{resource_name}"
    OrgId        = "{org_id}"
    ManagedBy    = "terraform"
  }}
}}

# Public subnet
resource "aws_subnet" "enclave" {{
  vpc_id                  = aws_vpc.enclave.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = data.aws_availability_zones.available.names[0]

  tags = {{
    Name         = "subnet-{resource_name}"
    ResourceId   = "{resource_id}"
    ResourceName = "{resource_name}"
    OrgId        = "{org_id}"
    ManagedBy    = "terraform"
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
    Name         = "rt-{resource_name}"
    ResourceId   = "{resource_id}"
    ResourceName = "{resource_name}"
    OrgId        = "{org_id}"
    ManagedBy    = "terraform"
  }}
}}

# Route table association
resource "aws_route_table_association" "enclave" {{
  subnet_id      = aws_subnet.enclave.id
  route_table_id = aws_route_table.enclave.id
}}

# Local variable for ports (attestation + user ports)
locals {{
  all_ports = concat([5000], var.ports)
}}

variable "ports" {{
  type    = list(number)
  default = []
}}

# Security group for the enclave
resource "aws_security_group" "enclave" {{
  name_prefix = "enclave-{resource_name}-"
  description = "Security group for {resource_name} Nitro Enclave"
  vpc_id      = aws_vpc.enclave.id

  # Attestation port (always open)
  ingress {{
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow attestation port"
  }}

  # SSH for debugging
  ingress {{
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow SSH for debugging"
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
    Name         = "enclave-{resource_name}"
    ResourceId   = "{resource_id}"
    ResourceName = "{resource_name}"
    OrgId        = "{org_id}"
    ManagedBy    = "terraform"
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
    volume_size           = 30
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }}

  user_data = base64encode(templatefile("./user-data.sh", {{
    eif_s3_path = "{eif_s3_path}"
    memory_mb   = {memory_mb}
    cpu_count   = {cpu_count}
    debug_mode  = "{debug_mode}"
    ports       = var.ports
  }}))

  tags = {{
    Name         = "{resource_name}"
    ResourceId   = "{resource_id}"
    ResourceName = "{resource_name}"
    OrgId        = "{org_id}"
    ManagedBy    = "terraform"
  }}
}}

# Elastic IP for the enclave
resource "aws_eip" "enclave" {{
  domain   = "vpc"
  instance = aws_instance.enclave.id

  tags = {{
    Name         = "enclave-{resource_name}"
    ResourceId   = "{resource_id}"
    ResourceName = "{resource_name}"
    OrgId        = "{org_id}"
    ManagedBy    = "terraform"
  }}
}}

output "instance_id" {{
  value = aws_instance.enclave.id
}}

output "public_ip" {{
  value = aws_eip.enclave.public_ip
}}

output "url" {{
  value = "http://${{aws_eip.enclave.public_ip}}:8080"
}}
"#,
        region = aws_region,
        instance_type = instance_type,
        ssh_key_line = ssh_key_name.as_ref()
            .map(|key| format!("\n  key_name = \"{}\"", key))
            .unwrap_or_default(),
        resource_id = request.resource_id,
        resource_name = request.resource_name,
        org_id = request.org_id,
        eif_s3_path = eif_s3_path,
        memory_mb = request.memory_mb,
        cpu_count = cpu_count_rounded,
        debug_mode = if request.debug_mode { "true" } else { "false" },
    );

    fs::write(work_dir.join("main.tf"), main_tf_content).await
        .context("Failed to write main.tf")?;

    Ok(())
}
