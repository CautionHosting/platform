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
    Initialized,
    Pending,
    Running,
    Stopped,
    Terminated,
    Failed,
}

impl ResourceState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResourceState::Initialized => "initialized",
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
}

impl CloudProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            CloudProvider::AWS => "aws",
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

    #[serde(default)]
    pub ports: Vec<u16>,

    #[serde(default)]
    pub http_port: Option<u16>,
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
            ports: Vec::new(),
            http_port: None,
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
pub struct AwsDeploymentConfig {
    pub region: String,
    pub instance_type: Option<String>,
    pub vpc_id: Option<String>,
    pub subnet_id: Option<String>,
    pub security_group_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "lowercase")]
pub enum ManagedOnPremConfig {
    Aws(AwsDeploymentConfig),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildConfig {
    pub containerfile: Option<String>,

    pub build: Option<String>,

    pub oci_tarball: Option<String>,

    pub binary: Option<String>,

    pub run: Option<String>,

    #[serde(default)]
    pub app_sources: Vec<String>,

    #[serde(default)]
    pub enclave_sources: Vec<String>,

    pub metadata: Option<String>,

    pub memory_mb: u32,

    pub cpus: u32,

    pub disk_gb: u32,

    pub debug: bool,

    pub no_cache: bool,

    #[serde(default)]
    pub ports: Vec<u16>,

    pub http_port: Option<u16>,

    #[serde(default)]
    pub ssh_keys: Vec<String>,

    pub domain: Option<String>,

    pub managed_on_prem: Option<ManagedOnPremConfig>,

    /// Enable end-to-end encryption via STEVE proxy (default: false)
    #[serde(default)]
    pub e2e: bool,

    /// Enable locksmith secret management (default: false)
    #[serde(default)]
    pub locksmith: bool,
}

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            containerfile: None,
            build: None,
            oci_tarball: None,
            binary: None,
            run: None,
            app_sources: Vec::new(),
            enclave_sources: Vec::new(),
            metadata: None,
            memory_mb: 512,
            cpus: 2,
            disk_gb: 30,
            debug: false,
            no_cache: false,
            ports: Vec::new(),
            http_port: None,
            ssh_keys: Vec::new(),
            domain: None,
            managed_on_prem: None,
            e2e: false,
            locksmith: false,
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
        let mut app_sources: Vec<String> = Vec::new();
        let mut enclave_sources: Vec<String> = Vec::new();
        let mut metadata = None;
        let mut memory_mb = None;
        let mut cpus = None;
        let mut disk_gb = None;
        let mut debug = None;
        let mut no_cache = None;
        let mut e2e = None;
        let mut locksmith = None;
        let mut ports: Vec<u16> = Vec::new();
        let mut http_port: Option<u16> = None;
        let mut ssh_keys: Vec<String> = Vec::new();
        let mut domain: Option<String> = None;

        let mut managed_on_prem = false;
        let mut platform: Option<String> = None;
        let mut aws_region: Option<String> = None;
        let mut aws_instance_type: Option<String> = None;
        let mut aws_vpc_id: Option<String> = None;
        let mut aws_subnet_id: Option<String> = None;
        let mut aws_security_group_id: Option<String> = None;

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
                    "app_source" | "app_sources" => {
                        if !value.is_empty() {
                            app_sources = value
                                .split(',')
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                                .collect();
                            if !app_sources.is_empty() {
                                tracing::info!("Parsed {} app source URL(s) from Procfile", app_sources.len());
                            }
                        }
                    }
                    "enclave_source" | "enclave_sources" => {
                        if !value.is_empty() {
                            enclave_sources = value
                                .split(',')
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                                .collect();
                            if !enclave_sources.is_empty() {
                                tracing::info!("Parsed {} enclave source URL(s) from Procfile", enclave_sources.len());
                            }
                        }
                    }
                    "metadata" => {
                        if !value.is_empty() {
                            metadata = Some(value);
                        }
                    }
                    "memory" | "memory_mb" => {
                        if let Ok(val) = value.parse::<u32>() {
                            memory_mb = Some(val);
                        }
                    }
                    "cpu" | "cpus" => {
                        if let Ok(val) = value.parse::<u32>() {
                            cpus = Some(val);
                        }
                    }
                    "disk" | "disk_gb" => {
                        if let Ok(val) = value.parse::<u32>() {
                            disk_gb = Some(val);
                        }
                    }
                    "debug" => {
                        debug = Some(value.to_lowercase() == "true");
                    }
                    "no_cache" | "nocache" => {
                        no_cache = Some(value.to_lowercase() == "true");
                    }
                    "e2e" => {
                        e2e = Some(value.to_lowercase() == "true");
                    }
                    "locksmith" => {
                        locksmith = Some(value.to_lowercase() == "true");
                    }
                    "ports" => {
                        let mut parsed_ports: Vec<u16> = Vec::new();
                        for s in value.split(',') {
                            let trimmed = s.trim();
                            if trimmed.is_empty() {
                                continue;
                            }
                            match trimmed.parse::<u16>() {
                                Ok(port) if port > 0 => {
                                    parsed_ports.push(port);
                                }
                                Ok(_) => {
                                    tracing::warn!("Invalid port 0 in Procfile, ignoring");
                                }
                                Err(_) => {
                                    tracing::warn!("Invalid port '{}' in Procfile, ignoring", trimmed);
                                }
                            }
                        }
                        parsed_ports.sort();
                        parsed_ports.dedup();
                        ports = parsed_ports;
                        if !ports.is_empty() {
                            tracing::info!("Parsed ports from Procfile: {:?}", ports);
                        }
                    }
                    "http_port" => {
                        match value.parse::<u16>() {
                            Ok(port) if port > 0 => {
                                http_port = Some(port);
                                tracing::info!("Parsed http_port from Procfile: {}", port);
                            }
                            _ => {
                                tracing::warn!("Invalid http_port '{}' in Procfile, ignoring", value);
                            }
                        }
                    }
                    "ssh_keys" | "ssh_key" => {
                        if !value.is_empty() {
                            let unquoted = value.trim_matches('"').trim_matches('\'').trim();
                            if !unquoted.is_empty() && (unquoted.starts_with("ssh-") || unquoted.starts_with("ecdsa-") || unquoted.starts_with("sk-")) {
                                ssh_keys.push(unquoted.to_string());
                                tracing::info!("Parsed SSH key from Procfile");
                            }
                        }
                    }
                    "domain" => {
                        if !value.is_empty() {
                            domain = Some(value);
                            tracing::info!("Parsed domain from Procfile: {}", domain.as_ref().unwrap());
                        }
                    }
                    "managed_on_prem" => {
                        managed_on_prem = value.to_lowercase() == "true";
                    }
                    "platform" => {
                        if !value.is_empty() {
                            platform = Some(value.to_lowercase());
                        }
                    }
                    "aws_region" => {
                        if !value.is_empty() {
                            aws_region = Some(value);
                        }
                    }
                    "aws_instance_type" => {
                        if !value.is_empty() {
                            aws_instance_type = Some(value);
                        }
                    }
                    "aws_vpc_id" => {
                        if !value.is_empty() {
                            aws_vpc_id = Some(value);
                        }
                    }
                    "aws_subnet_id" => {
                        if !value.is_empty() {
                            aws_subnet_id = Some(value);
                        }
                    }
                    "aws_security_group_id" => {
                        if !value.is_empty() {
                            aws_security_group_id = Some(value);
                        }
                    }
                    _ => {}
                }
            }
        }

        // Ports 8080, 8081, 8082, 8084 are reserved for internal enclave services
        if ports.contains(&8080) {
            return Err(format!(
                "Port 8080 is reserved for internal enclave services. \
                Your application should listen on port 8083."
            ));
        }
        if ports.contains(&8081) {
            return Err(format!(
                "Port 8081 is reserved for internal enclave services. \
                Your application should listen on port 8083."
            ));
        }
        if ports.contains(&8082) {
            return Err(format!(
                "Port 8082 is reserved for bootproofd. \
                Your application should listen on a different port."
            ));
        }
        if ports.contains(&8084) {
            return Err(format!(
                "Port 8084 is reserved for locksmith (shard receiver). \
                Your application should listen on a different port."
            ));
        }

        // Default http_port to the single port if only one is specified
        let http_port = match http_port {
            Some(hp) => {
                if !ports.contains(&hp) {
                    return Err(format!(
                        "http_port {} must also be listed in ports", hp
                    ));
                }
                Some(hp)
            }
            None if ports.len() == 1 => {
                tracing::info!("Defaulting http_port to {} (only port specified)", ports[0]);
                Some(ports[0])
            }
            None => None,
        };

        let managed_on_prem_config = if managed_on_prem {
            let platform = platform.ok_or("managed_on_prem requires 'platform' to be specified")?;

            match platform.as_str() {
                "aws" => {
                    let region = aws_region.ok_or("managed_on_prem with platform 'aws' requires 'aws_region'")?;
                    Some(ManagedOnPremConfig::Aws(AwsDeploymentConfig {
                        region,
                        instance_type: aws_instance_type,
                        vpc_id: aws_vpc_id,
                        subnet_id: aws_subnet_id,
                        security_group_id: aws_security_group_id,
                    }))
                }
                other => {
                    return Err(format!("Unsupported platform '{}'. Currently only 'aws' is supported.", other));
                }
            }
        } else {
            None
        };

        Ok(Self {
            containerfile,
            build,
            oci_tarball,
            binary,
            run,
            app_sources,
            enclave_sources,
            metadata,
            memory_mb: memory_mb.unwrap_or(512),
            cpus: cpus.unwrap_or(2),
            disk_gb: disk_gb.unwrap_or(30),
            debug: debug.unwrap_or(false),
            no_cache: no_cache.unwrap_or(false),
            ports,
            http_port,
            ssh_keys,
            domain,
            managed_on_prem: managed_on_prem_config,
            e2e: e2e.unwrap_or(false),
            locksmith: locksmith.unwrap_or(false),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_config_default_locksmith_false() {
        let config = BuildConfig::default();
        assert!(!config.locksmith);
        assert!(!config.e2e);
    }

    #[test]
    fn test_parse_locksmith_true() {
        let procfile = "run: /app/server\nlocksmith: true\n";
        let config = BuildConfig::from_procfile(procfile).unwrap();
        assert!(config.locksmith);
    }

    #[test]
    fn test_parse_locksmith_false() {
        let procfile = "run: /app/server\nlocksmith: false\n";
        let config = BuildConfig::from_procfile(procfile).unwrap();
        assert!(!config.locksmith);
    }

    #[test]
    fn test_parse_locksmith_absent_defaults_false() {
        let procfile = "run: /app/server\n";
        let config = BuildConfig::from_procfile(procfile).unwrap();
        assert!(!config.locksmith);
    }

    #[test]
    fn test_parse_locksmith_case_insensitive() {
        let procfile = "run: /app/server\nlocksmith: True\n";
        let config = BuildConfig::from_procfile(procfile).unwrap();
        assert!(config.locksmith);

        let procfile = "run: /app/server\nlocksmith: TRUE\n";
        let config = BuildConfig::from_procfile(procfile).unwrap();
        assert!(config.locksmith);
    }

    #[test]
    fn test_parse_locksmith_and_e2e_together() {
        let procfile = "run: /app/server\ne2e: true\nlocksmith: true\n";
        let config = BuildConfig::from_procfile(procfile).unwrap();
        assert!(config.e2e);
        assert!(config.locksmith);
    }

    #[test]
    fn test_parse_locksmith_with_ports() {
        let procfile = "run: /app/server\nlocksmith: true\nports: 8083, 9090\n";
        let config = BuildConfig::from_procfile(procfile).unwrap();
        assert!(config.locksmith);
        assert_eq!(config.ports, vec![8083, 9090]);
    }

    #[test]
    fn test_rejects_reserved_port_8080() {
        let procfile = "run: /app/server\nports: 8080\n";
        let result = BuildConfig::from_procfile(procfile);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("8080"));
    }

    #[test]
    fn test_rejects_reserved_port_8081() {
        let procfile = "run: /app/server\nports: 8081\n";
        let result = BuildConfig::from_procfile(procfile);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("8081"));
    }

    #[test]
    fn test_rejects_reserved_port_8082() {
        let procfile = "run: /app/server\nports: 8082\n";
        let result = BuildConfig::from_procfile(procfile);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("8082"));
    }

    #[test]
    fn test_rejects_reserved_port_8084() {
        let procfile = "run: /app/server\nports: 8084\n";
        let result = BuildConfig::from_procfile(procfile);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("8084"));
    }
}
