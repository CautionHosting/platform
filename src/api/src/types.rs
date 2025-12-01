// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use serde::{Deserialize, Serialize};
use sqlx::Type;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[sqlx(type_name = "user_role", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Owner,
    Admin,
    Member,
    Viewer,
}

impl UserRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            UserRole::Owner => "owner",
            UserRole::Admin => "admin",
            UserRole::Member => "member",
            UserRole::Viewer => "viewer",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "owner" => Some(UserRole::Owner),
            "admin" => Some(UserRole::Admin),
            "member" => Some(UserRole::Member),
            "viewer" => Some(UserRole::Viewer),
            _ => None,
        }
    }

    pub fn can_manage_org(&self) -> bool {
        matches!(self, UserRole::Owner | UserRole::Admin)
    }

    pub fn is_owner(&self) -> bool {
        matches!(self, UserRole::Owner)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[sqlx(type_name = "resource_state", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum ResourceState {
    Pending,
    Running,
    Stopped,
    Terminated,
    Failed,
}

impl ResourceState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResourceState::Pending => "pending",
            ResourceState::Running => "running",
            ResourceState::Stopped => "stopped",
            ResourceState::Terminated => "terminated",
            ResourceState::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[sqlx(type_name = "cloud_provider", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum CloudProvider {
    #[serde(rename = "aws")]
    AWS,
    #[serde(rename = "gcp")]
    GCP,
    #[serde(rename = "azure")]
    Azure,
    #[serde(rename = "digitalocean")]
    DigitalOcean,
    #[serde(rename = "hetzner")]
    Hetzner,
}

impl CloudProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            CloudProvider::AWS => "aws",
            CloudProvider::GCP => "gcp",
            CloudProvider::Azure => "azure",
            CloudProvider::DigitalOcean => "digitalocean",
            CloudProvider::Hetzner => "hetzner",
        }
    }

    pub fn provider_id(&self) -> i64 {
        match self {
            CloudProvider::AWS => 1,
            CloudProvider::GCP => 2,
            CloudProvider::Azure => 3,
            CloudProvider::DigitalOcean => 4,
            CloudProvider::Hetzner => 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AWSResourceType {
    #[serde(rename = "ec2-instance")]
    EC2Instance,
    #[serde(rename = "rds-instance")]
    RDSInstance,
    #[serde(rename = "s3-bucket")]
    S3Bucket,
}

impl AWSResourceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AWSResourceType::EC2Instance => "ec2-instance",
            AWSResourceType::RDSInstance => "rds-instance",
            AWSResourceType::S3Bucket => "s3-bucket",
        }
    }

    pub fn terraform_module_path(&self) -> &'static str {
        match self {
            AWSResourceType::EC2Instance => "terraform/modules/aws/ec2-app",
            AWSResourceType::RDSInstance => "terraform/modules/aws/rds",
            AWSResourceType::S3Bucket => "terraform/modules/aws/s3",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveConfig {
    pub binary_path: String,

    #[serde(default)]
    pub args: Vec<String>,

    #[serde(default = "default_memory_mb")]
    pub memory_mb: u32,

    #[serde(default = "default_cpu_count")]
    pub cpus: u32,

    #[serde(default)]
    pub debug: bool,
}

fn default_memory_mb() -> u32 {
    512
}

fn default_cpu_count() -> u32 {
    2
}

impl Default for EnclaveConfig {
    fn default() -> Self {
        Self {
            binary_path: "/app".to_string(),
            args: vec![],
            memory_mb: 512,
            cpus: 2,
            debug: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EIFBuildResult {
    pub eif_path: String,

    pub pcrs_path: String,

    pub eif_hash: String,

    pub eif_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildConfig {
    pub containerfile: String,

    pub build: Option<String>,

    pub oci_tarball: Option<String>,

    pub binary: Option<String>,

    pub run: Option<String>,

    pub source: Option<String>,

    pub enclave_source: Option<String>,

    pub metadata: Option<String>,

    pub memory_mb: u32,

    pub cpus: u32,

    pub debug: bool,

    pub no_cache: bool,
}

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            containerfile: "Dockerfile".to_string(),
            build: Some("docker build -t app .".to_string()),
            oci_tarball: None,
            binary: None, 
            run: None,
            source: None,
            enclave_source: None,
            metadata: None,
            memory_mb: 512,
            cpus: 2,
            debug: false,
            no_cache: false,
        }
    }
}

impl BuildConfig {
    pub fn from_procfile(content: &str) -> Result<Self, String> {
        let mut containerfile = None;
        let mut build = None;
        let mut oci_tarball = None;
        let mut binary = None;
        let mut run = None;
        let mut source = None;
        let mut enclave_source = None;
        let mut metadata = None;
        let mut memory_mb = None;
        let mut cpus = None;
        let mut debug = None;
        let mut no_cache = None;

        for line in content.lines() {
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim();
                let value = value.trim().to_string();

                match key {
                    "containerfile" => {
                        if !value.is_empty() {
                            containerfile = Some(value);
                        }
                    }
                    "build" => {
                        if !value.is_empty() {
                            build = Some(value);
                        }
                    }
                    "oci_tarball" => {
                        if !value.is_empty() {
                            tracing::info!("Parsed oci_tarball from Procfile: {}", value);
                            oci_tarball = Some(value);
                        } else {
                            tracing::warn!("oci_tarball field found but value is empty");
                        }
                    }
                    "binary" => {
                        if !value.is_empty() {
                            binary = Some(value);
                        }
                    }
                    "run" => {
                        if !value.is_empty() {
                            run = Some(value);
                        }
                    }
                    "source" => {
                        if !value.is_empty() {
                            source = Some(value);
                        }
                    }
                    "enclave_source" => {
                        if !value.is_empty() {
                            enclave_source = Some(value);
                        }
                    }
                    "metadata" => {
                        if !value.is_empty() {
                            metadata = Some(value);
                        }
                    }
                    "memory_mb" => {
                        if let Ok(val) = value.parse::<u32>() {
                            memory_mb = Some(val);
                        }
                    }
                    "cpus" => {
                        if let Ok(val) = value.parse::<u32>() {
                            cpus = Some(val);
                        }
                    }
                    "debug" => {
                        debug = Some(value.to_lowercase() == "true");
                    }
                    "no_cache" | "nocache" => {
                        no_cache = Some(value.to_lowercase() == "true");
                    }
                    _ => {}
                }
            }
        }

        let run_command = run.or_else(|| binary.clone());

        Ok(Self {
            containerfile: containerfile.unwrap_or_else(|| "Dockerfile".to_string()),
            build,
            oci_tarball,
            binary,
            run: run_command,
            source,
            enclave_source,
            metadata,
            memory_mb: memory_mb.unwrap_or(512),
            cpus: cpus.unwrap_or(2),
            debug: debug.unwrap_or(false),
            no_cache: no_cache.unwrap_or(false),
        })
    }
}
