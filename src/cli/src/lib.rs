// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use reqwest;
use serde::{Deserialize, Serialize};
use serde_cbor;
use base64::{Engine as _, engine::general_purpose};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::time::Duration;
use std::process::Command;
use authenticator::{
    authenticatorservice::{AuthenticatorService, RegisterArgs, SignArgs},
    ctap2::server::{
        PublicKeyCredentialParameters, RelyingParty,
        PublicKeyCredentialUserEntity, PublicKeyCredentialDescriptor,
        Transport,
    },
    crypto::COSEAlgorithm,
    errors::AuthenticatorError,
    statecallback::StateCallback,
    Pin, RegisterResult, SignResult, StatusUpdate, StatusPinUv,
};
use sha2::{Sha256, Digest};
use enclave_builder::{BuildConfig, build_user_image};
use bootproof_sdk::{VerifiableSignedAttestationFormat, format::nitro::{Nitro, NitroPcrs}};

mod loader;
use loader::{Loader, LoaderStyle};

mod attestation;
use attestation::verify_attestation;

fn prompt_for_pin() -> Result<Option<String>> {
    use std::io::{self, Write};

    print!("Enter your security key PIN (or press Enter if no PIN is set): ");
    io::stdout().flush()?;

    let mut pin = String::new();
    io::stdin().read_line(&mut pin)?;

    let trimmed = pin.trim().to_string();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed))
    }
}

fn is_pin_related_error(error: &anyhow::Error) -> bool {
    let error_msg = format!("{:?}", error).to_lowercase();
    error_msg.contains("pin")
        || error_msg.contains("pinuv")
        || error_msg.contains("pin required")
        || error_msg.contains("pin_required")
        || error_msg.contains("pin invalid")
        || error_msg.contains("pininvalid")
}

fn log_verbose(verbose: bool, msg: &str) {
    if verbose {
        eprintln!("[VERBOSE] {}", msg);
    }
}

fn check_dependencies(verbose: bool) -> Result<()> {
    log_verbose(verbose, "Checking dependencies...");

    let usb_dev_path = std::path::Path::new("/dev/bus/usb");
    if !usb_dev_path.exists() {
        log_verbose(verbose, "Warning: /dev/bus/usb not found - USB access may not work");
    } else {
        log_verbose(verbose, "USB device access available");
    }

    log_verbose(verbose, "FIDO2 authenticator library loaded");

    Ok(())
}

async fn check_gateway_connectivity(url: &str, verbose: bool) -> Result<()> {
    log_verbose(verbose, &format!("Testing connectivity to gateway: {}", url));

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    // Just verify we can reach the gateway base URL
    log_verbose(verbose, &format!("HEAD {}", url));

    match client.head(url).send().await {
        Ok(resp) => {
            log_verbose(verbose, &format!("Gateway reachable (status: {})", resp.status()));
            Ok(())
        }
        Err(e) => {
            log_verbose(verbose, &format!("HEAD request failed (this is ok): {}", e));
            log_verbose(verbose, "Skipping connectivity check, will test during auth");
            Ok(())
        }
    }
}

#[derive(Parser)]
#[command(name = "caution")]
#[command(version = "0.1.0")]
#[command(about = "Caution.co CLI for deploying and verifying reproducible enclaves")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short, long, default_value = "https://alpha.caution.co", env = "CAUTION_BACKEND_URL", help = "Caution API server URL")]
    url: String,

    #[arg(short, long, help = "Enable verbose output")]
    verbose: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(about = "Register a new account")]
    Register {
        #[arg(long)]
        beta_code: String,
    },
    #[command(about = "Login to your Caution account")]
    Login,
    #[command(about = "Initialize a new deployment in the current directory")]
    Init {
        #[arg(long, help = "Generate Procfile with managed on-premises deployment fields for AWS")]
        managed_on_prem: bool,
        #[arg(long, help = "Path to JSON config file from managed on-prem setup script")]
        config: Option<PathBuf>,
    },
    #[command(about = "Verify enclave attestation. By default, fetches manifest from the remote enclave and reproduces the build.")]
    Verify {
        #[arg(long, help = "Attestation endpoint URL (default: inferred from .caution/deployment)")]
        attestation_url: Option<String>,
        #[arg(long, help = "Build from current directory instead of remote manifest")]
        from_local: bool,
        #[arg(long, help = "Git URL to fetch application source")]
        app_source_url: Option<String>,
        #[arg(long, help = "Compare against PCRs from file instead of building")]
        pcrs: Option<String>,
        #[arg(long, help = "Force rebuild, ignore cache")]
        no_cache: bool,
    },
    #[command(about = "Manage deployed applications")]
    Apps {
        #[command(subcommand)]
        command: AppCommands,
    },
    #[command(about = "Manage SSH keys for git access")]
    SshKeys {
        #[command(subcommand)]
        command: SshKeyCommands,
    },
    #[command(about = "Manage local cache")]
    Cache {
        #[command(subcommand)]
        command: CacheCommands,
    },
    #[command(about = "Manage cloud provider credentials for managed on-premises deployments")]
    Credentials {
        #[command(subcommand)]
        command: CredentialCommands,
    },
}

#[derive(Subcommand, Debug)]
enum AppCommands {
    #[command(about = "Create a new application")]
    Create,
    #[command(about = "List all applications")]
    List,
    #[command(about = "Get details of an application")]
    Get {
        #[arg(help = "App ID (default: from .caution/deployment)")]
        id: Option<String>,
    },
    #[command(about = "Destroy an application")]
    Destroy {
        #[arg(help = "App ID (default: from .caution/deployment)")]
        id: Option<String>,
        #[arg(short, long, help = "Skip confirmation prompt")]
        force: bool,
        #[arg(long, help = "Force delete from database even if cloud resource cleanup fails")]
        force_delete: bool,
    },
    #[command(about = "Build enclave image locally for inspection")]
    Build {
        #[arg(long, help = "Force rebuild, ignore cache")]
        no_cache: bool,
    },
    #[command(about = "Rename an application")]
    Rename {
        #[arg(help = "New name for the app")]
        name: String,
        #[arg(help = "App ID (default: from .caution/deployment)")]
        id: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum SshKeyCommands {
    #[command(about = "Add an SSH public key")]
    Add {
        #[arg(conflicts_with_all = ["from_agent", "key"], help = "Path to public key file")]
        key_file: Option<PathBuf>,
        #[arg(long, conflicts_with_all = ["key_file", "key"], help = "Add keys from ssh-agent")]
        from_agent: bool,
        #[arg(long, conflicts_with_all = ["key_file", "from_agent"], help = "Public key string")]
        key: Option<String>,
        #[arg(long, help = "Name for the key")]
        name: Option<String>,
    },
    #[command(about = "List all SSH keys")]
    List,
    #[command(about = "Remove an SSH key")]
    Remove {
        #[arg(help = "Key fingerprint")]
        fingerprint: String,
    },
}

#[derive(Subcommand, Debug)]
enum CacheCommands {
    #[command(about = "Show cache directory path")]
    Path,
    #[command(about = "Show total cache size")]
    Size,
    #[command(about = "List cached items")]
    List,
    #[command(about = "Clear the cache")]
    Destroy {
        #[arg(short, long, help = "Skip confirmation prompt")]
        force: bool,
    },
}

#[derive(Subcommand, Debug)]
enum CredentialCommands {
    #[command(about = "Add cloud provider credentials")]
    Add {
        #[arg(value_enum, help = "Cloud platform")]
        platform: CredentialPlatform,
        #[arg(help = "Name for this credential")]
        name: String,
        #[arg(long, help = "Set as default for this platform")]
        default: bool,
        #[arg(long, help = "Default region")]
        region: Option<String>,
    },
    #[command(about = "List all credentials")]
    List,
    #[command(about = "Remove a credential")]
    Remove {
        #[arg(help = "Credential ID or name")]
        id: String,
        #[arg(short, long, help = "Skip confirmation prompt")]
        force: bool,
    },
    #[command(about = "Set a credential as the default for its platform")]
    SetDefault {
        #[arg(help = "Credential ID or name")]
        id: String,
    },
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum CredentialPlatform {
    Aws,
    Gcp,
    Azure,
    Digitalocean,
    Hetzner,
    Linode,
    Vultr,
    Ovh,
    Baremetal,
}

impl std::fmt::Display for CredentialPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aws => write!(f, "aws"),
            Self::Gcp => write!(f, "gcp"),
            Self::Azure => write!(f, "azure"),
            Self::Digitalocean => write!(f, "digitalocean"),
            Self::Hetzner => write!(f, "hetzner"),
            Self::Linode => write!(f, "linode"),
            Self::Vultr => write!(f, "vultr"),
            Self::Ovh => write!(f, "ovh"),
            Self::Baremetal => write!(f, "baremetal"),
        }
    }
}

#[derive(Deserialize)]
struct RegisterBeginResponse {
    #[serde(rename = "publicKey")]
    public_key: PublicKeyCredentialCreationOptions,
    session: String,
}

#[derive(Deserialize)]
struct RegisterFinishResponse {
    status: String,
    credential_id: String,
    session_id: String,
    expires_at: String,
}

#[derive(Deserialize)]
struct PublicKeyCredentialCreationOptions {
    challenge: String,
    rp: RelyingPartyInfo,
    user: UserInfo,
    #[serde(rename = "pubKeyCredParams")]
    pub_key_cred_params: Vec<PubKeyCredParam>,
    timeout: u64,
}

#[derive(Deserialize)]
struct LoginBeginResponse {
    #[serde(rename = "publicKey")]
    public_key: PublicKeyCredentialRequestOptions,
    session: String,
}

#[derive(Deserialize)]
struct Fido2SignResponse {
    #[serde(rename = "publicKey")]
    public_key: PublicKeyCredentialRequestOptions,
    challenge_id: String,
}

#[derive(Deserialize)]
struct PublicKeyCredentialRequestOptions {
    challenge: String,
    #[serde(rename = "rpId")]
    rp_id: String,
    timeout: u64,
    #[serde(rename = "allowCredentials", default)]
    allow_credentials: Vec<AllowCredential>,
}

#[derive(Deserialize, Clone)]
struct AllowCredential {
    #[serde(rename = "type")]
    cred_type: String,
    id: String,
    #[serde(default)]
    transports: Vec<String>,
}

#[derive(Deserialize)]
struct RelyingPartyInfo {
    id: String,
    name: String,
}

#[derive(Deserialize)]
struct UserInfo {
    id: String,
    name: String,
    #[serde(rename = "displayName")]
    display_name: String,
}

#[derive(Deserialize)]
struct PubKeyCredParam {
    #[serde(rename = "type")]
    type_: String,
    alg: i32,
}

#[derive(Deserialize)]
struct LoginFinishResponse {
    session_id: String,
    expires_at: String,
    credential_id: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct App {
    pub id: String,
    pub resource_name: Option<String>,
    pub state: String,
    pub provider_resource_id: String,
    pub public_ip: Option<String>,
    pub domain: Option<String>,
    pub configuration: Option<serde_json::Value>,
    #[serde(default)]
    pub git_url: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct CreateAppResponse {
    pub id: String,
    pub resource_name: String,
    pub git_url: String,
    pub state: String,
}

/// Minimal deployment info stored locally in .caution file
/// Contains only the resource ID - all other data is fetched fresh from API
#[derive(Serialize, Deserialize, Debug)]
struct DeploymentInfo {
    resource_id: String,
}

#[derive(Serialize, Deserialize)]
struct Config {
    session_id: String,
    expires_at: String,
    #[serde(default)]
    server_url: Option<String>,
}

#[derive(Deserialize)]
struct UserStatus {
    email_verified: bool,
    payment_method_added: bool,
    onboarding_complete: bool,
}

struct ApiClient {
    base_url: String,
    client: reqwest::Client,
    config_path: PathBuf,
    deployment_path: PathBuf,
    verbose: bool,
}

impl ApiClient {
    fn new(base_url: &str, verbose: bool) -> Result<Self> {
        log_verbose(verbose, "Initializing API client...");

        let config_dir = dirs::config_dir()
            .context("Could not find config directory")?
            .join("api-cli");

        log_verbose(verbose, &format!("Config directory: {:?}", config_dir));

        fs::create_dir_all(&config_dir)
            .context("Failed to create config directory")?;
        let config_path = config_dir.join("config.json");

        // Local deployment info in the current git repo
        let current_dir = std::env::current_dir()
            .context("Failed to get current directory")?;
        let caution_dir = current_dir.join(".caution");
        fs::create_dir_all(&caution_dir)
            .context("Failed to create .caution directory")?;
        let deployment_path = caution_dir.join("deployment.json");

        log_verbose(verbose, &format!("Config file: {:?}", config_path));
        log_verbose(verbose, &format!("Deployment file: {:?}", deployment_path));
        log_verbose(verbose, "API client initialized");

        Ok(Self {
            base_url: base_url.to_string(),
            client: reqwest::Client::new(),
            config_path,
            deployment_path,
            verbose,
        })
    }

    fn frontend_url(&self) -> String {
        std::env::var("FRONTEND_URL")
            .unwrap_or_else(|_| "http://localhost:3000".to_string())
    }

    fn save_config(&self, session_id: String, expires_at: String) -> Result<()> {
        let config = Config {
            session_id,
            expires_at,
            server_url: Some(self.base_url.clone()),
        };

        let json = serde_json::to_string_pretty(&config)?;
        fs::write(&self.config_path, json)?;
        Ok(())
    }

    fn load_config(&self) -> Result<Config> {
        let content = fs::read_to_string(&self.config_path)
            .context("Not logged in. Run 'login' command first")?;
        let config: Config = serde_json::from_str(&content)?;
        Ok(config)
    }

    fn is_session_expired(&self, config: &Config) -> bool {
        use chrono::{DateTime, Utc, NaiveDateTime};

        if let Ok(expires) = DateTime::parse_from_rfc3339(&config.expires_at) {
            return Utc::now() >= expires.with_timezone(&Utc);
        }

        if let Ok(naive) = NaiveDateTime::parse_from_str(&config.expires_at, "%Y-%m-%dT%H:%M:%S%.f") {
            return Utc::now() >= naive.and_utc();
        }

        let timestamp_part = config.expires_at.split(" +").next().unwrap_or(&config.expires_at);
        if let Ok(naive) = NaiveDateTime::parse_from_str(timestamp_part, "%Y-%m-%d %H:%M:%S%.f") {
            return Utc::now() >= naive.and_utc();
        }

        true
    }

    async fn ensure_authenticated(&self) -> Result<Config> {
        match self.load_config() {
            Ok(config) if !self.is_session_expired(&config) && self.is_same_server(&config) => Ok(config),
            _ => {
                self.login().await?;
                self.load_config()
            }
        }
    }

    fn is_same_server(&self, config: &Config) -> bool {
        config.server_url.as_ref().map_or(true, |url| url == &self.base_url)
    }

    fn save_deployment(&self, resource_id: &str) -> Result<()> {
        let deployment_info = DeploymentInfo {
            resource_id: resource_id.to_string(),
        };
        let json = serde_json::to_string_pretty(&deployment_info)?;
        fs::write(&self.deployment_path, json)?;
        log_verbose(self.verbose, &format!("Saved deployment info to {:?}", self.deployment_path));
        Ok(())
    }

    fn load_deployment(&self) -> Result<DeploymentInfo> {
        let content = fs::read_to_string(&self.deployment_path)
            .context("No deployment found. Run 'init' first")?;
        let deployment_info: DeploymentInfo = serde_json::from_str(&content)?;
        Ok(deployment_info)
    }

    fn check_git_repo(&self) -> Result<()> {
        let output = Command::new("git")
            .args(&["rev-parse", "--is-inside-work-tree"])
            .output()
            .context("Failed to execute git command. Is git installed?")?;

        if !output.status.success() {
            bail!("Not in a git repository. Please run this command from within a git repository.");
        }

        Ok(())
    }

    fn read_procfile(&self) -> Result<String> {
        let procfile_path = PathBuf::from("Procfile");

        if !procfile_path.exists() {
            println!("Procfile not found in current directory");
            println!("Add a Procfile with a build command like this:");
            println!();
            println!("build: docker build -t myapp .");
            println!();
            println!("To learn more visit https://docs.caution.co/quickstart");
            std::process::exit(1);
        }

        let content = fs::read_to_string(&procfile_path)
            .context("Failed to read Procfile")?;

        // Parse the Procfile to find the build command
        for line in content.lines() {
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(build_cmd) = line.strip_prefix("build:") {
                let cmd = build_cmd.trim();
                if cmd.is_empty() {
                    bail!("Procfile has empty build command. Expected format: build: docker build -t myapp .");
                }
                return Ok(cmd.to_string());
            }
        }

        // Auto-detect containerfile: prefer Containerfile, fall back to Dockerfile
        let containerfile = if PathBuf::from("Containerfile").exists() {
            "Containerfile"
        } else {
            "Dockerfile"
        };
        Ok(format!("docker build -f {} -t app .", containerfile))
    }

    fn read_procfile_field(&self, field: &str) -> Option<String> {
        let procfile_path = PathBuf::from("Procfile");
        if !procfile_path.exists() {
            return None;
        }

        let content = match fs::read_to_string(&procfile_path) {
            Ok(c) => c,
            Err(_) => return None,
        };

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let prefix = format!("{}:", field);
            if let Some(value) = line.strip_prefix(&prefix) {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
        None
    }

    fn read_procfile_ports(&self) -> Vec<u16> {
        match self.read_procfile_field("ports") {
            Some(ports_str) => {
                ports_str
                    .split(',')
                    .filter_map(|s| s.trim().parse::<u16>().ok())
                    .collect()
            }
            None => vec![8080], // Default port
        }
    }

    fn read_procfile_sources(&self) -> Vec<String> {
        self.read_procfile_field("app_sources")
            .or_else(|| self.read_procfile_field("app_source"))
            .map(|s| {
                s.split(',')
                    .map(|url| url.trim().to_string())
                    .filter(|url| !url.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn read_procfile_enclave_sources(&self) -> Vec<String> {
        self.read_procfile_field("enclave_sources")
            .or_else(|| self.read_procfile_field("enclave_source"))
            .map(|s| {
                s.split(',')
                    .map(|url| url.trim().to_string())
                    .filter(|url| !url.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn set_git_remote(&self, git_url: &str) -> Result<()> {
        let check_output = Command::new("git")
            .args(&["remote", "get-url", "caution"])
            .output()
            .context("Failed to check existing git remote")?;

        if check_output.status.success() {
            Command::new("git")
                .args(&["remote", "set-url", "caution", git_url])
                .output()
                .context("Failed to update git remote 'caution'")?;

            println!("Updated git remote 'caution' to: {}", git_url);
        } else {
            Command::new("git")
                .args(&["remote", "add", "caution", git_url])
                .output()
                .context("Failed to add git remote 'caution'")?;

            println!("Added git remote 'caution': {}", git_url);
        }

        Ok(())
    }

    fn create_procfile_if_needed(&self, managed_on_prem: bool) -> Result<()> {
        use std::fs;
        use std::path::Path;

        let procfile_path = Path::new("Procfile");

        if procfile_path.exists() {
            log_verbose(self.verbose, "Procfile already exists, skipping creation");
            return Ok(());
        }

        let source_line = self.detect_source_url()
            .map(|url| format!("app_sources: {}", url))
            .unwrap_or_else(|| "# app_sources: git@codeberg.org:user/repo.git".to_string());

        let managed_on_prem_section = if managed_on_prem {
            r#"
# Managed on-premises deployment configuration
managed_on_prem: true
platform: aws
aws_region: us-east-1
# aws_instance_type: m5.xlarge
# aws_vpc_id: vpc-xxxxxxxxx
# aws_subnet_id: subnet-xxxxxxxxx
# aws_security_group_id: sg-xxxxxxxxx
"#
        } else {
            ""
        };

        let procfile_content = format!(r#"binary: /app/myapp
build: docker build -t app .
{source_line}
{managed_on_prem_section}"#);

        fs::write(procfile_path, procfile_content)
            .context("Failed to create Procfile")?;

        println!("\nCreated Procfile in current directory");
        println!("Edit the required 'binary' field to match your application");
        if managed_on_prem {
            println!("Configure AWS deployment settings in the managed_on_prem section");
        }
        println!("To learn more visit https://git.distrust.co/public/caution");

        Ok(())
    }

    fn detect_source_url(&self) -> Option<String> {
        use std::process::Command;

        let output = Command::new("git")
            .args(&["remote", "get-url", "origin"])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let origin_url = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if origin_url.is_empty() {
            return None;
        }

        self.origin_to_archive_url(&origin_url)
    }

    fn origin_to_archive_url(&self, origin_url: &str) -> Option<String> {
        if origin_url.starts_with("git@") {
            let without_prefix = origin_url.strip_prefix("git@")?;
            let (host, path) = without_prefix.split_once(':')?;
            let path = path.trim_end_matches(".git");

            return Some(self.construct_archive_url(host, path));
        }

        if origin_url.starts_with("https://") || origin_url.starts_with("http://") {
            let url = url::Url::parse(origin_url).ok()?;
            let host = url.host_str()?;
            let path = url.path().trim_start_matches('/').trim_end_matches(".git");

            return Some(self.construct_archive_url(host, path));
        }

        None
    }

    fn construct_archive_url(&self, host: &str, path: &str) -> String {
        if host.contains("gitlab") {
            let repo_name = path.rsplit('/').next().unwrap_or("repo");
            format!("https://{}/{}/-/archive/${{COMMIT}}/{}-${{COMMIT}}.tar.gz", host, path, repo_name)
        } else {
            format!("https://{}/{}/archive/${{COMMIT}}.tar.gz", host, path)
        }
    }

    fn git_url_to_archive_urls(&self, git_url: &str, commit: &str) -> Result<Vec<String>> {
        let (host, path) = if git_url.starts_with("git@") {
            let without_prefix = git_url.strip_prefix("git@")
                .ok_or_else(|| anyhow::anyhow!("Invalid git URL format"))?;
            let (host, path) = without_prefix.split_once(':')
                .ok_or_else(|| anyhow::anyhow!("Invalid git SSH URL format"))?;
            (host.to_string(), path.trim_end_matches(".git").to_string())
        } else if git_url.starts_with("https://") || git_url.starts_with("http://") {
            let url = url::Url::parse(git_url)
                .context("Failed to parse git URL")?;
            let host = url.host_str()
                .ok_or_else(|| anyhow::anyhow!("Git URL has no host"))?
                .to_string();
            let path = url.path().trim_start_matches('/').trim_end_matches(".git").to_string();
            (host, path)
        } else {
            bail!("Unsupported git URL format: {}", git_url);
        };

        let repo_name = path.rsplit('/').next().unwrap_or("repo");

        Ok(vec![
            format!("http://{}/{}/archive/{}.tar.gz", host, path, commit),
            format!("https://{}/{}/archive/{}.tar.gz", host, path, commit),
            format!("http://{}/{}/-/archive/{}/{}-{}.tar.gz", host, path, commit, repo_name, commit),
            format!("https://{}/{}/-/archive/{}/{}-{}.tar.gz", host, path, commit, repo_name, commit),
            format!("http://{}/{}/get/{}.tar.gz", host, path, commit),
            format!("https://{}/{}/get/{}.tar.gz", host, path, commit),
        ])
    }

    fn git_url_to_archive_url(&self, git_url: &str, commit: &str) -> Result<String> {
        self.git_url_to_archive_urls(git_url, commit)?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No archive URLs generated"))
    }

    async fn register(&self, beta_code: &str) -> Result<()> {
        log_verbose(self.verbose, "Starting FIDO2 registration...");
        log_verbose(self.verbose, &format!("Target URL: {}", self.base_url));

        let cookie_store = reqwest::cookie::Jar::default();
        let client = reqwest::Client::builder()
            .cookie_provider(std::sync::Arc::new(cookie_store))
            .build()?;

        log_verbose(self.verbose, "Sending registration begin request with beta code...");
        let response = client
            .post(format!("{}/auth/register/begin", self.base_url))
            .json(&serde_json::json!({ "beta_code": beta_code }))
            .send()
            .await
            .context("Failed to send registration begin request")?;

        log_verbose(self.verbose, &format!("Response status: {}", response.status()));

        if !response.status().is_success() {
            let error = response.text().await?;
            bail!("Registration begin failed: {}", error);
        }

        let begin_resp: RegisterBeginResponse = response.json().await
            .context("Failed to parse registration begin response")?;
        log_verbose(self.verbose, "Registration challenge received");
        log_verbose(self.verbose, &format!("Challenge: {}", begin_resp.public_key.challenge));

        log_verbose(self.verbose, "Creating credential on security key...");

        let mut attestation = self.make_credential(&begin_resp, &self.base_url)?;

        println!("Credential created on device");

        if let Some(obj) = attestation.as_object_mut() {
            obj.insert("session".to_string(), serde_json::json!(begin_resp.session));
        }

        log_verbose(self.verbose, "Sending registration finish request...");
        let response = client
            .post(format!("{}/auth/register/finish", self.base_url))
            .json(&attestation)
            .send()
            .await
            .context("Failed to send registration finish request")?;

        log_verbose(self.verbose, &format!("Response status: {}", response.status()));

        if response.status().is_success() {
            let finish_resp: RegisterFinishResponse = response.json().await?;

            println!("\nFIDO2 registration successful!");
            println!("Credential ID: {}", finish_resp.credential_id);
            println!("\nYou are now logged in:");
            println!("Session ID: {}", finish_resp.session_id);
            println!("Expires: {}", finish_resp.expires_at);

            self.save_config(
                finish_resp.session_id.clone(),
                finish_resp.expires_at.clone(),
            )?;

            println!("\n=======================================================");
            println!("BETA ACCESS GRANTED");
            println!("=======================================================");
            println!("\nYou're registered as a beta user. You can now:");
            println!("  • Create apps with 'caution init'");
            println!("  • Deploy with 'git push caution main'");
            println!("\nDashboard: {}/dashboard?session={}", self.frontend_url(), finish_resp.session_id);
            println!("=======================================================\n");

            Ok(())
        } else {
            let error = response.text().await?;
            bail!("Registration failed: {}", error)
        }
    }

    async fn login(&self) -> Result<()> {
        log_verbose(self.verbose, "Starting FIDO2 login...");

        let (session_id, _expires_at) = self.perform_login().await?;
        println!("Session ID: {}", session_id);

        match self.check_onboarding_status(&session_id).await {
            Ok(status) => {
                if !status.onboarding_complete {
                    println!("\n=======================================================");
                    println!("COMPLETE YOUR ONBOARDING");
                    println!("=======================================================");
                    println!("\nYou need to complete onboarding to use this service:");
                    println!("  1. Verify your email address {}", if status.email_verified { "✓" } else { "✗" });
                    println!("  2. Add payment information {}", if status.payment_method_added { "✓" } else { "✗" });
                    println!("\nOnboarding URL:");
                    println!("  {}/onboarding?session={}", self.frontend_url(), session_id);
                    println!("\nYou must complete onboarding before you can create apps.");
                    println!("=======================================================\n");
                }
            }
            Err(e) => {
                log_verbose(self.verbose, &format!("Could not check onboarding status: {}", e));
            }
        }

        Ok(())
    }

    async fn check_onboarding_status(&self, session_id: &str) -> Result<UserStatus> {
        let response = self.client
            .get(format!("{}/api/user/status", self.base_url))
            .header("X-Session-ID", session_id)
            .send()
            .await?;

        if !response.status().is_success() {
            bail!("Failed to get user status: {}", response.status());
        }

        let status: UserStatus = response.json().await?;
        Ok(status)
    }

    fn make_credential(&self, options: &RegisterBeginResponse, base_url: &str) -> Result<serde_json::Value> {
        log_verbose(self.verbose, "Attempting registration without PIN first...");
        match self.try_make_credential(options, base_url, None) {
            Ok(result) => {
                log_verbose(self.verbose, "Registration succeeded without PIN");
                Ok(result)
            },
            Err(e) => {
                log_verbose(self.verbose, &format!("First attempt failed: {:?}", e));
                log_verbose(self.verbose, &format!("Full error details: {:#?}", e));

                // Only ask for PIN if the error is PIN-related
                if is_pin_related_error(&e) {
                    println!("Your security key requires a PIN.");
                    match prompt_for_pin()? {
                        Some(pin_string) => {
                            let pin = Pin::new(&pin_string);
                            log_verbose(self.verbose, "Retrying registration with PIN...");
                            self.try_make_credential(options, base_url, Some(pin))
                        },
                        None => {
                            log_verbose(self.verbose, "No PIN provided, returning original error");
                            Err(e)
                        }
                    }
                } else {
                    // Not a PIN error, return the original error
                    log_verbose(self.verbose, "Error is not PIN-related, not prompting for PIN");
                    Err(e)
                }
            }
        }
    }

    fn try_make_credential(&self, options: &RegisterBeginResponse, base_url: &str, pin: Option<Pin>) -> Result<serde_json::Value> {
        let opts = &options.public_key;

        log_verbose(self.verbose, "Creating FIDO2 credential...");

        let user_id = general_purpose::URL_SAFE_NO_PAD
            .decode(&opts.user.id)
            .context("Failed to decode user ID")?;

        let challenge = general_purpose::URL_SAFE_NO_PAD
            .decode(&opts.challenge)
            .context("Failed to decode challenge")?;

        log_verbose(self.verbose, &format!("user_id bytes: {:?}", user_id));
        log_verbose(self.verbose, &format!("challenge bytes: {:?}", challenge));
        log_verbose(self.verbose, &format!("rpId: {}", opts.rp.id));

        let user = PublicKeyCredentialUserEntity {
            id: user_id.clone(),
            name: Some(opts.user.name.clone()),
            display_name: Some(opts.user.display_name.clone()),
        };

        let rp = RelyingParty {
            id: opts.rp.id.clone(),
            name: Some(opts.rp.name.clone()),
        };

        let pub_key_params: Vec<PublicKeyCredentialParameters> = opts
            .pub_key_cred_params
            .iter()
            .filter_map(|p| {
                match p.alg {
                    -7 => Some(PublicKeyCredentialParameters {
                        alg: COSEAlgorithm::ES256,
                    }),
                    -257 => Some(PublicKeyCredentialParameters {
                        alg: COSEAlgorithm::RS256,
                    }),
                    _ => None,
                }
            })
            .collect();

        log_verbose(self.verbose, &format!("pub_key_params count: {}", pub_key_params.len()));
        log_verbose(self.verbose, &format!("timeout from server: {} ms", opts.timeout));

        let mut manager = AuthenticatorService::new()
            .context("Failed to create authenticator service")?;

        manager.add_u2f_usb_hid_platform_transports();

        let (status_tx, status_rx) = channel::<StatusUpdate>();
        let (callback_tx, callback_rx) = channel::<Result<RegisterResult, AuthenticatorError>>();

        let callback = StateCallback::new(Box::new(move |result| {
            let _ = callback_tx.send(result);
        }));

        let args = RegisterArgs {
            client_data_hash: Sha256::digest(serde_json::to_vec(&serde_json::json!({
                "type": "webauthn.create",
                "challenge": opts.challenge,
                "origin": base_url,
            }))?).into(),
            relying_party: rp,
            origin: base_url.to_string(),
            user,
            pub_cred_params: pub_key_params,
            exclude_list: vec![],
            user_verification_req: authenticator::ctap2::server::UserVerificationRequirement::Preferred,
            resident_key_req: authenticator::ctap2::server::ResidentKeyRequirement::Preferred,
            extensions: Default::default(),
            pin,
            use_ctap1_fallback: false,
        };

        log_verbose(self.verbose, "Sending register request to authenticator...");
        manager
            .register(opts.timeout, args, status_tx, callback)
            .context("Failed to start registration")?;

        log_verbose(self.verbose, "Waiting for callback result (up to 60 seconds)...");

        let mut loader = Loader::new("Tap your security key to continue", LoaderStyle::KeyTap);

        loop {
            // Check for status updates
            while let Ok(status) = status_rx.try_recv() {
                match status {
                    StatusUpdate::SelectResultNotice(sender, users) => {
                        loader.stop();
                        println!("Multiple credentials found. Please select one:");
                        for (idx, user) in users.iter().enumerate() {
                            let display = user.display_name.as_deref()
                                .or(user.name.as_deref())
                                .unwrap_or("Unknown");
                            println!("[{}] {}", idx, display);
                        }

                        use std::io::{self, Write};
                        print!("Enter selection (0-{}): ", users.len() - 1);
                        io::stdout().flush()?;

                        let mut input = String::new();
                        io::stdin().read_line(&mut input)?;
                        let selection: usize = input.trim().parse()
                            .context("Invalid selection")?;

                        if selection >= users.len() {
                            bail!("Selection out of range");
                        }

                        println!("Selected: {}", users[selection].name.as_deref().unwrap_or("Unknown"));
                        sender.send(Some(selection)).context("Failed to send selection")?;
                    }
                    StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender)) => {
                        loader.stop();
                        log_verbose(self.verbose, "PIN required by authenticator");
                        match prompt_for_pin()? {
                            Some(pin_string) => {
                                let pin = Pin::new(&pin_string);
                                sender.send(pin).context("Failed to send PIN")?;
                                loader = Loader::new("Tap your security key to continue", LoaderStyle::KeyTap);
                            }
                            None => {
                                bail!("PIN is required but none provided");
                            }
                        }
                    }
                    StatusUpdate::PinUvError(e) => {
                        loader.stop();
                        log_verbose(self.verbose, &format!("PIN/UV error: {:?}", e));
                        bail!("PIN/UV error: {:?}", e);
                    }
                    _ => {
                        log_verbose(self.verbose, &format!("Authenticator status: {:?}", status));
                    }
                }
            }

            if let Ok(result) = callback_rx.try_recv() {
                loader.stop();
                log_verbose(self.verbose, "Got registration result");
                let register_result = result.context("Registration failed")?;

                let att_obj = &register_result.att_obj;

                let client_data_json = serde_json::json!({
                    "type": "webauthn.create",
                    "challenge": opts.challenge,
                    "origin": base_url,
                });
                let client_data_json_bytes = serde_json::to_vec(&client_data_json)?;

                let auth_data_bytes = att_obj.auth_data.to_vec();

                if auth_data_bytes.len() < 37 {
                    bail!("Invalid authenticator data length: {}", auth_data_bytes.len());
                }

                let credential_id_len = u16::from_be_bytes([
                    auth_data_bytes[53],
                    auth_data_bytes[54],
                ]) as usize;

                let credential_id_start = 55;
                let credential_id_end = credential_id_start + credential_id_len;

                if auth_data_bytes.len() < credential_id_end {
                    bail!("Authenticator data too short for credential ID");
                }

                let credential_id = &auth_data_bytes[credential_id_start..credential_id_end];

                log_verbose(self.verbose, &format!("credential_id len: {}", credential_id.len()));
                log_verbose(self.verbose, &format!("credential_id: {}", hex::encode(credential_id)));

                let att_obj_bytes = serde_cbor::to_vec(&register_result.att_obj)?;

                let response_json = serde_json::json!({
                    "id": general_purpose::URL_SAFE_NO_PAD.encode(credential_id),
                    "rawId": general_purpose::URL_SAFE_NO_PAD.encode(credential_id),
                    "response": {
                        "clientDataJSON": general_purpose::URL_SAFE_NO_PAD.encode(&client_data_json_bytes),
                        "attestationObject": general_purpose::URL_SAFE_NO_PAD.encode(&att_obj_bytes),
                    },
                    "type": "public-key"
                });

                return Ok(response_json);
            }

            std::thread::sleep(Duration::from_millis(100));
        }
    }

    async fn perform_login(&self) -> Result<(String, String)> {
        let cookie_store = reqwest::cookie::Jar::default();
        let client = reqwest::Client::builder()
            .cookie_provider(std::sync::Arc::new(cookie_store))
            .build()?;

        log_verbose(self.verbose, "Sending login begin request...");
        let response = client
            .post(format!("{}/auth/login/begin", self.base_url))
            .send()
            .await?;

        if !response.status().is_success() {
            let error = response.text().await?;
            bail!("Login begin failed: {}", error);
        }

        let begin_resp: LoginBeginResponse = response.json().await?;
        log_verbose(self.verbose, "Login challenge received");
        log_verbose(self.verbose, &format!("Session from server: {:?}", begin_resp.session));

        let assertion = self.get_assertion(&begin_resp, &self.base_url)?;

        println!("Assertion created");

        let mut credential: serde_json::Value = serde_json::from_slice(&assertion.response_json)?;

        log_verbose(self.verbose, "Credential before adding session:");
        log_verbose(self.verbose, &serde_json::to_string_pretty(&credential)?);

        if let Some(obj) = credential.as_object_mut() {
            obj.insert("session".to_string(), serde_json::json!(begin_resp.session));
        }

        log_verbose(self.verbose, "Final payload being sent to /auth/login/finish:");
        log_verbose(self.verbose, &serde_json::to_string_pretty(&credential)?);

        let response = client
            .post(format!("{}/auth/login/finish", self.base_url))
            .json(&credential)
            .send()
            .await?;

        if response.status().is_success() {
            let finish_resp: LoginFinishResponse = response.json().await?;

            self.save_config(
                finish_resp.session_id.clone(),
                finish_resp.expires_at.clone(),
            )?;

            Ok((finish_resp.session_id, finish_resp.expires_at))
        } else {
            let status = response.status();
            let error = response.text().await?;
            log_verbose(self.verbose, &format!("Server error response (status {}): {}", status, error));
            bail!("Login failed: {}", error)
        }
    }

    async fn signed_post<T: serde::Serialize>(
        &self,
        session_id: &str,
        path: &str,
        body: &T,
    ) -> Result<reqwest::Response> {
        let body_json = serde_json::to_vec(body)?;
        let body_hash = hex::encode(Sha256::digest(&body_json));

        log_verbose(self.verbose, &format!("Requesting FIDO2 sign challenge for POST {}", path));

        let sign_req = serde_json::json!({
            "method": "POST",
            "path": path,
            "body_hash": body_hash,
        });

        let response = self.client
            .post(format!("{}/auth/sign-request", self.base_url))
            .header("X-Session-ID", session_id)
            .json(&sign_req)
            .send()
            .await?;

        if !response.status().is_success() {
            let error = response.text().await?;
            bail!("Failed to get sign challenge: {}", error);
        }

        let sign_resp: Fido2SignResponse = response.json().await?;
        log_verbose(self.verbose, "Got FIDO2 sign challenge");

        let login_resp = LoginBeginResponse {
            public_key: sign_resp.public_key,
            session: sign_resp.challenge_id.clone(),
        };

        println!("Tap your security key to sign the request...");
        let assertion = self.get_assertion(&login_resp, &self.base_url)?;

        let fido_response_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&assertion.response_json);

        log_verbose(self.verbose, "Sending FIDO2-signed request");

        let response = self.client
            .post(format!("{}{}", self.base_url, path))
            .header("X-Fido2-Challenge-Id", &sign_resp.challenge_id)
            .header("X-Fido2-Response", &fido_response_b64)
            .header("Content-Type", "application/json")
            .body(body_json)
            .send()
            .await?;

        Ok(response)
    }

    fn get_assertion(&self, options: &LoginBeginResponse, base_url: &str) -> Result<AssertionResult> {
        log_verbose(self.verbose, "Attempting assertion without PIN first...");
        match self.try_get_assertion(options, base_url, None) {
            Ok(result) => {
                log_verbose(self.verbose, "Assertion succeeded without PIN");
                Ok(result)
            },
            Err(e) => {
                log_verbose(self.verbose, &format!("First attempt failed: {:?}", e));
                log_verbose(self.verbose, &format!("Full error details: {:#?}", e));

                // Only ask for PIN if the error is PIN-related
                if is_pin_related_error(&e) {
                    println!("Your security key requires a PIN.");
                    match prompt_for_pin()? {
                        Some(pin_string) => {
                            let pin = Pin::new(&pin_string);
                            log_verbose(self.verbose, "Retrying assertion with PIN...");
                            self.try_get_assertion(options, base_url, Some(pin))
                        },
                        None => {
                            log_verbose(self.verbose, "No PIN provided, returning original error");
                            Err(e)
                        }
                    }
                } else {
                    // Not a PIN error, return the original error
                    log_verbose(self.verbose, "Error is not PIN-related, not prompting for PIN");
                    Err(e)
                }
            }
        }
    }

    fn try_get_assertion(&self, options: &LoginBeginResponse, base_url: &str, pin: Option<Pin>) -> Result<AssertionResult> {
        let opts = &options.public_key;

        log_verbose(self.verbose, "Getting assertion from authenticator...");

        let challenge = general_purpose::URL_SAFE_NO_PAD
            .decode(&opts.challenge)
            .context("Failed to decode challenge")?;

        log_verbose(self.verbose, &format!("challenge bytes: {:?}", challenge));
        log_verbose(self.verbose, &format!("rpId: {}", opts.rp_id));

        let mut manager = AuthenticatorService::new()
            .context("Failed to create authenticator service")?;

        manager.add_u2f_usb_hid_platform_transports();

        let (status_tx, status_rx) = channel::<StatusUpdate>();
        let (callback_tx, callback_rx) = channel::<Result<SignResult, AuthenticatorError>>();

        let callback = StateCallback::new(Box::new(move |result| {
            let _ = callback_tx.send(result);
        }));

        let allow_list: Vec<PublicKeyCredentialDescriptor> = opts.allow_credentials
            .iter()
            .filter_map(|cred| {
                general_purpose::URL_SAFE_NO_PAD
                    .decode(&cred.id)
                    .ok()
                    .map(|id_bytes| {
                        let transports: Vec<Transport> = cred.transports
                            .iter()
                            .filter_map(|t| match t.as_str() {
                                "usb" => Some(Transport::USB),
                                "nfc" => Some(Transport::NFC),
                                "ble" => Some(Transport::BLE),
                                "internal" => Some(Transport::Internal),
                                _ => None,
                            })
                            .collect();

                        PublicKeyCredentialDescriptor {
                            id: id_bytes,
                            transports: transports,
                        }
                    })
            })
            .collect();

        log_verbose(self.verbose, &format!("Allow list has {} credentials", allow_list.len()));

        let args = SignArgs {
            client_data_hash: Sha256::digest(serde_json::to_vec(&serde_json::json!({
                "type": "webauthn.get",
                "challenge": opts.challenge,
                "origin": base_url,
            }))?).into(),
            origin: base_url.to_string(),
            relying_party_id: opts.rp_id.clone(),
            allow_list,
            user_verification_req: authenticator::ctap2::server::UserVerificationRequirement::Preferred,
            user_presence_req: true,
            extensions: Default::default(),
            pin,
            use_ctap1_fallback: false,
        };

        log_verbose(self.verbose, "Sending sign request to authenticator...");
        manager
            .sign(opts.timeout, args, status_tx, callback)
            .context("Failed to start assertion")?;

        log_verbose(self.verbose, "Waiting for callback result (up to 60 seconds)...");

        let mut loader = Loader::new("Tap your security key to continue", LoaderStyle::KeyTap);

        loop {
            // Check for status updates
            while let Ok(status) = status_rx.try_recv() {
                match status {
                    StatusUpdate::SelectResultNotice(sender, users) => {
                        loader.stop();
                        println!("Multiple credentials found. Please select one:");
                        for (idx, user) in users.iter().enumerate() {
                            let display = user.display_name.as_deref()
                                .or(user.name.as_deref())
                                .unwrap_or("Unknown");
                            println!("[{}] {}", idx, display);
                        }

                        use std::io::{self, Write};
                        print!("Enter selection (0-{}): ", users.len() - 1);
                        io::stdout().flush()?;

                        let mut input = String::new();
                        io::stdin().read_line(&mut input)?;
                        let selection: usize = input.trim().parse()
                            .context("Invalid selection")?;

                        if selection >= users.len() {
                            bail!("Selection out of range");
                        }

                        println!("Selected: {}", users[selection].name.as_deref().unwrap_or("Unknown"));
                        sender.send(Some(selection)).context("Failed to send selection")?;
                    }
                    StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender)) => {
                        loader.stop();
                        log_verbose(self.verbose, "PIN required by authenticator");
                        match prompt_for_pin()? {
                            Some(pin_string) => {
                                let pin = Pin::new(&pin_string);
                                sender.send(pin).context("Failed to send PIN")?;
                                loader = Loader::new("Tap your security key to continue", LoaderStyle::KeyTap);
                            }
                            None => {
                                bail!("PIN is required but none provided");
                            }
                        }
                    }
                    StatusUpdate::PinUvError(e) => {
                        loader.stop();
                        log_verbose(self.verbose, &format!("PIN/UV error: {:?}", e));
                        bail!("PIN/UV error: {:?}", e);
                    }
                    _ => {
                        log_verbose(self.verbose, &format!("Authenticator status: {:?}", status));
                    }
                }
            }

            if let Ok(result) = callback_rx.try_recv() {
                loader.stop();
                log_verbose(self.verbose, "Got assertion result");
                let sign_result = result.context("Assertion failed")?;

                let credential_id = hex::encode(&sign_result.assertion.credentials
                    .as_ref()
                    .context("No credential in assertion")?
                    .id);

                let client_data_json = serde_json::json!({
                    "type": "webauthn.get",
                    "challenge": opts.challenge,
                    "origin": self.base_url.clone(),
                });
                let client_data_json_bytes = serde_json::to_vec(&client_data_json)?;

                let cred_id_bytes = &sign_result.assertion.credentials
                    .as_ref()
                    .context("No credential")?
                    .id;

                let response_json = serde_json::json!({
                    "id": general_purpose::URL_SAFE_NO_PAD.encode(cred_id_bytes),
                    "rawId": general_purpose::URL_SAFE_NO_PAD.encode(cred_id_bytes),
                    "response": {
                        "authenticatorData": general_purpose::URL_SAFE_NO_PAD.encode(&sign_result.assertion.auth_data.to_vec()),
                        "clientDataJSON": general_purpose::URL_SAFE_NO_PAD.encode(&client_data_json_bytes),
                        "signature": general_purpose::URL_SAFE_NO_PAD.encode(&sign_result.assertion.signature),
                        "userHandle": sign_result.assertion.user.as_ref()
                            .map(|u| general_purpose::URL_SAFE_NO_PAD.encode(&u.id))
                            .unwrap_or_default(),
                    },
                    "type": "public-key"
                });

                log_verbose(self.verbose, "Response JSON structure:");
                log_verbose(self.verbose, &serde_json::to_string_pretty(&response_json)?);

                return Ok(AssertionResult {
                    credential_id,
                    response_json: serde_json::to_vec(&response_json)?,
                });
            }

            std::thread::sleep(Duration::from_millis(100));
        }
    }

    async fn create_app(&self) -> Result<()> {
        println!("Creating new app...");

        log_verbose(self.verbose, "Checking git repository...");
        self.check_git_repo()?;
        println!("Git repository found");

        log_verbose(self.verbose, "Reading Procfile...");
        let cmd = self.read_procfile()?;
        println!("Procfile found");
        println!("Build command: {}", cmd);

        let config = self.ensure_authenticated().await?;

        log_verbose(self.verbose, "Creating app on server...");
        let body = serde_json::json!({
            "cmd": cmd
        });

        let mut loader = Loader::new("Setting up your app", LoaderStyle::Processing);

        let response = self.client
            .post(format!("{}/api/resources", self.base_url))
            .header("X-Session-ID", config.session_id)
            .json(&body)
            .send()
            .await
            .context("Failed to send create app request")?;

        if !response.status().is_success() {
            let status = response.status();
            let error = response.text().await?;
            loader.stop();

            if error.contains("initialize") || error.contains("provisioning") || error.contains("AWS account") {
                eprintln!("\n❌ Failed to initialize your AWS account");
                eprintln!("\nThis is your first time using Caution. We attempted to provision");
                eprintln!("a dedicated AWS account for your organization, but encountered an error:");
                eprintln!("\n{}", error);
                eprintln!("\nPlease check:");
                eprintln!("  • AWS Organizations is enabled in your main account");
                eprintln!("  • Your IAM user has organizations:CreateAccount permission");
                eprintln!("  • Run: aws organizations create-organization --feature-set ALL");
                bail!("Account initialization failed");
            }

            bail!("Failed to create app (status {}): {}", status, error);
        }

        let create_response: CreateAppResponse = response.json().await
            .context("Failed to parse create app response")?;

        loader.stop();

        println!("App created!");
        println!("ID: {}", create_response.id);
        println!("Name: {}", create_response.resource_name);
        println!("State: {}", create_response.state);
        println!("Git URL: {}", create_response.git_url);

        log_verbose(self.verbose, "Setting git remote...");
        self.set_git_remote(&create_response.git_url)?;

        self.create_procfile_if_needed(false)?;

        println!("\nYou can now push to 'caution' remote:");
        println!("  git push caution main");

        Ok(())
    }

    async fn list_apps(&self) -> Result<()> {
        let config = self.ensure_authenticated().await?;

        let response = self.client
            .get(format!("{}/api/resources", self.base_url))
            .header("X-Session-ID", config.session_id)
            .send()
            .await?;

        if response.status().is_success() {
            let apps: Vec<App> = response.json().await?;

            if apps.is_empty() {
                println!("No deployed apps found.");
            } else {
                println!("Apps:");
                for app in apps {
                    let name = app.resource_name.as_deref().unwrap_or("unnamed");
                    let mut details = vec![app.state.clone()];

                    if let Some(config) = &app.configuration {
                        if let Some(enclave_config) = config.get("enclave_config") {
                            if let (Some(mem), Some(cpus)) = (
                                enclave_config.get("memory_mb").and_then(|v| v.as_u64()),
                                enclave_config.get("cpus").and_then(|v| v.as_u64()),
                            ) {
                                details.push(format!("{}MB/{}cpu", mem, cpus));
                            }
                        }
                    }

                    if let Some(ip) = &app.public_ip {
                        details.push(ip.clone());
                    }

                    println!("  {} - {} ({})", app.id, name, details.join(", "));
                }
            }
            Ok(())
        } else {
            bail!("Failed to list apps: {}", response.status())
        }
    }

    async fn fetch_app(&self, id: &str) -> Result<App> {
        let config = self.ensure_authenticated().await?;

        let response = self.client
            .get(format!("{}/api/resources/{}", self.base_url, id))
            .header("X-Session-ID", config.session_id)
            .send()
            .await?;

        if response.status().is_success() {
            let app: App = response.json().await?;
            Ok(app)
        } else {
            bail!("Failed to get app: {}", response.status())
        }
    }

    async fn fetch_app_by_name(&self, resource_name: &str) -> Result<App> {
        let config = self.ensure_authenticated().await?;

        let response = self.client
            .get(format!("{}/api/resources", self.base_url))
            .header("X-Session-ID", config.session_id)
            .send()
            .await?;

        if response.status().is_success() {
            let apps: Vec<App> = response.json().await?;

            apps.into_iter()
                .find(|app| app.resource_name.as_deref() == Some(resource_name))
                .ok_or_else(|| anyhow::anyhow!("App '{}' not found. It may have been deleted.\nTo redeploy, run: git push caution <branch>\nTo re-initialize, run: caution init", resource_name))
        } else {
            bail!("Failed to list apps: {}", response.status())
        }
    }

    async fn get_current_app(&self) -> Result<App> {
        let deployment = self.load_deployment()?;
        self.fetch_app(&deployment.resource_id).await
    }

    async fn get_app(&self, id: Option<String>) -> Result<()> {
        let app = match id {
            Some(id) => self.fetch_app(&id).await?,
            None => self.get_current_app().await?,
        };
        let name = app.resource_name.as_deref().unwrap_or("unnamed");

        println!("App Details:");
        println!("  ID: {}", app.id);
        println!("  Name: {}", name);
        println!("  State: {}", app.state);

        if let Some(domain) = &app.domain {
            println!("  Domain: {}", domain);
        }

        if let Some(config) = &app.configuration {
            if let Some(enclave_config) = config.get("enclave_config") {
                if let Some(memory) = enclave_config.get("memory_mb").and_then(|v| v.as_u64()) {
                    println!("  Memory: {} MB", memory);
                }
                if let Some(cpus) = enclave_config.get("cpus").and_then(|v| v.as_u64()) {
                    println!("  CPUs: {}", cpus);
                }
                if let Some(debug) = enclave_config.get("debug").and_then(|v| v.as_bool()) {
                    if debug {
                        println!("  Debug Mode: enabled");
                    }
                }
                if let Some(ports) = enclave_config.get("ports").and_then(|v| v.as_array()) {
                    if !ports.is_empty() {
                        let ports_str: Vec<String> = ports.iter()
                            .filter_map(|p| p.as_u64().map(|n| n.to_string()))
                            .collect();
                        println!("  Ports: {}", ports_str.join(", "));
                    }
                }
            }
        }

        if let Some(ip) = &app.public_ip {
            println!("  Public IP: {}", ip);
            println!("  URL: http://{}", app.domain.as_deref().unwrap_or(ip));
            println!("  Attestation: http://{}/attestation", ip);
        }

        Ok(())
    }

    async fn destroy_app(&self, id: Option<String>, force: bool, force_delete: bool) -> Result<()> {
        let app = match id {
            Some(id) => self.fetch_app(&id).await?,
            None => self.get_current_app().await?,
        };

        let name = app.resource_name.as_deref().unwrap_or("unnamed");

        if !force {
            println!("About to destroy app:");
            println!("  ID: {}", app.id);
            println!("  Name: {}", name);
            println!("  State: {}", app.state);
            if let Some(ip) = &app.public_ip {
                println!("  Public IP: {}", ip);
            }
            if force_delete {
                println!();
                println!("  WARNING: --force-delete will remove from database even if cloud cleanup fails!");
            }
            println!();
            print!("Are you sure you want to destroy this app? [y/N] ");
            std::io::stdout().flush()?;

            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;

            if !input.trim().eq_ignore_ascii_case("y") {
                println!("Aborted.");
                return Ok(());
            }
        }

        let config = self.ensure_authenticated().await?;

        let mut loader = Loader::new(&format!("Destroying app {} ({})", name, app.id), LoaderStyle::Processing);

        let url = if force_delete {
            format!("{}/api/resources/{}?force=true", self.base_url, app.id)
        } else {
            format!("{}/api/resources/{}", self.base_url, app.id)
        };

        let response = self.client
            .delete(&url)
            .header("X-Session-ID", config.session_id)
            .send()
            .await?;

        if response.status().is_success() {
            loader.stop();
            println!("App {} ({}) destroyed", name, app.id);
            Ok(())
        } else {
            let status = response.status();
            let error = response.text().await?;
            loader.stop();
            bail!("Failed to destroy app (status {}): {}", status, error)
        }
    }

    async fn rename_app(&self, id: Option<String>, new_name: String) -> Result<()> {
        let app = match id {
            Some(id) => self.fetch_app(&id).await?,
            None => self.get_current_app().await?,
        };

        let old_name = app.resource_name.as_deref().unwrap_or("unnamed");

        println!("Renaming app '{}' to '{}'...", old_name, new_name);

        let config = self.ensure_authenticated().await?;

        let body = serde_json::json!({
            "name": new_name
        });

        let response = self.client
            .patch(format!("{}/api/resources/{}", self.base_url, app.id))
            .header("X-Session-ID", config.session_id)
            .json(&body)
            .send()
            .await
            .context("Failed to send rename request")?;

        if response.status().is_success() {
            let updated_app: App = response.json().await?;
            let updated_name = updated_app.resource_name.as_deref().unwrap_or("unnamed");
            println!("App renamed successfully: {} -> {}", old_name, updated_name);

            Ok(())
        } else {
            let status = response.status();
            let error = response.text().await?;
            bail!("Failed to rename app (status {}): {}", status, error)
        }
    }

    async fn init(&self, managed_on_prem: bool, config_path: Option<PathBuf>) -> Result<()> {
        println!("Initializing new deployment...");

        log_verbose(self.verbose, "Checking git repository...");
        self.check_git_repo()?;
        println!("Git repository found");

        if let Some(ref path) = config_path {
            return self.init_managed_onprem(path).await;
        }

        self.create_procfile_if_needed(managed_on_prem)?;

        log_verbose(self.verbose, "Reading Procfile...");
        let cmd = self.read_procfile()?;
        println!("Procfile found");
        println!("Build command: {}", cmd);

        let config = self.ensure_authenticated().await?;

        // Check if there's an existing deployment with a resource ID
        if let Ok(deployment) = self.load_deployment() {
            log_verbose(self.verbose, &format!("Found existing deployment with ID: {}", deployment.resource_id));

            if let Ok(app) = self.fetch_app(&deployment.resource_id).await {
                let name = app.resource_name.as_deref().unwrap_or("unnamed");
                println!("App already exists!");
                println!("ID: {}", app.id);
                println!("Name: {}", name);
                println!("State: {}", app.state);
                println!("Git URL: {}", app.git_url);

                self.save_deployment(&app.id)?;

                log_verbose(self.verbose, "Updating git remote...");
                self.set_git_remote(&app.git_url)?;

                println!("\nYou can now push to 'caution' remote:");
                println!("  git push caution main");
                return Ok(());
            } else {
                log_verbose(self.verbose, "Previous resource no longer exists, creating new one...");
            }
        }

        log_verbose(self.verbose, "Creating app on server...");
        let body = serde_json::json!({
            "cmd": cmd
        });

        let mut loader = Loader::new("Setting up your app", LoaderStyle::Processing);

        let response = self.client
            .post(format!("{}/api/resources", self.base_url))
            .header("X-Session-ID", config.session_id)
            .json(&body)
            .send()
            .await
            .context("Failed to send create app request")?;

        if !response.status().is_success() {
            let status = response.status();
            let error = response.text().await?;
            loader.stop();

            if error.contains("initialize") || error.contains("provisioning") || error.contains("AWS account") {
                eprintln!("\n❌ Failed to initialize your AWS account");
                eprintln!("\nThis is your first time using Caution. We attempted to provision");
                eprintln!("a dedicated AWS account for your organization, but encountered an error:");
                eprintln!("\n{}", error);
                eprintln!("\nPlease check:");
                eprintln!("  • AWS Organizations is enabled in your main account");
                eprintln!("  • Your IAM user has organizations:CreateAccount permission");
                eprintln!("  • Run: aws organizations create-organization --feature-set ALL");
                bail!("Account initialization failed");
            }

            bail!("Failed to create app (status {}): {}", status, error);
        }

        let create_response: CreateAppResponse = response.json().await
            .context("Failed to parse create app response")?;

        loader.stop();

        println!("App created!");
        println!("ID: {}", create_response.id);
        println!("Name: {}", create_response.resource_name);
        println!("State: {}", create_response.state);
        println!("Git URL: {}", create_response.git_url);

        log_verbose(self.verbose, "Saving deployment info...");
        self.save_deployment(&create_response.id)?;
        log_verbose(self.verbose, "Saved deployment info");

        log_verbose(self.verbose, "Setting git remote...");
        self.set_git_remote(&create_response.git_url)?;

        self.create_procfile_if_needed(false)?;

        println!("\nYou can now push to 'caution' remote:");
        println!("  git push caution main");
        println!("\nAfter pushing, check your app status:");
        println!("  caution apps list");
        println!("\nVerify attestation:");
        println!("  caution verify --reproduce");

        Ok(())
    }

    async fn init_managed_onprem(&self, config_path: &PathBuf) -> Result<()> {
        println!("Initializing managed on-premises deployment...");

        log_verbose(self.verbose, &format!("Reading config from {:?}", config_path));
        let config_content = fs::read_to_string(config_path)
            .context("Failed to read config file")?;

        let has_gpg_extension = config_path.extension()
            .map(|ext| ext == "gpg" || ext == "asc")
            .unwrap_or(false);
        let has_gpg_header = config_content.trim().starts_with("-----BEGIN PGP MESSAGE-----");
        let is_gpg_encrypted = has_gpg_extension || has_gpg_header;

        let request_body = if is_gpg_encrypted {
            log_verbose(self.verbose, "Config file is GPG-encrypted (will be decrypted server-side)");
            println!("Detected GPG-encrypted config file");

            let existing_resource_id = self.load_deployment().ok().map(|d| d.resource_id);
            if let Some(ref id) = existing_resource_id {
                println!("Found existing deployment: {}", id);
                println!("Note: For updates with encrypted config, ensure resource_id is in the decrypted JSON");
            }

            config_content
        } else {
            let mut config_json: serde_json::Value = serde_json::from_str(&config_content)
                .context("Failed to parse config file as JSON")?;

            let existing_resource_id = self.load_deployment().ok().map(|d| d.resource_id);
            if let Some(ref id) = existing_resource_id {
                println!("Found existing deployment: {}", id);
                println!("Updating existing resource with new configuration...");
                config_json["resource_id"] = serde_json::json!(id);
            }

            let platform = config_json.get("platform").and_then(|v| v.as_str());
            if platform != Some("aws") {
                bail!("Config file must have platform: \"aws\" (got: {:?})", platform);
            }

            let managed_on_prem = config_json.get("managed_on_prem").and_then(|v| v.as_bool());
            if managed_on_prem != Some(true) {
                bail!("Config file must have managed_on_prem: true");
            }

            let required_fields = [
                "aws_region", "aws_access_key_id", "aws_secret_access_key",
                "deployment_id", "asg_name", "eif_bucket", "launch_template_name",
                "launch_template_id", "vpc_id", "subnet_ids", "instance_profile_name",
                "iam_user", "aws_account_id", "scope_tag"
            ];
            for field in required_fields {
                if config_json.get(field).is_none() {
                    bail!("Config file missing required field: {}", field);
                }
            }

            log_verbose(self.verbose, "Config file validated");
            serde_json::to_string(&config_json)?
        };

        let auth_config = self.ensure_authenticated().await?;

        self.create_procfile_if_needed(true)?;

        log_verbose(self.verbose, "Reading Procfile...");
        let _cmd = self.read_procfile()?;
        println!("Procfile found");

        let existing_resource_id = self.load_deployment().ok().map(|d| d.resource_id);
        let is_update = existing_resource_id.is_some();
        let loader_msg = if is_update {
            "Updating managed on-premises resource"
        } else {
            "Creating managed on-premises resource"
        };
        let mut loader = Loader::new(loader_msg, LoaderStyle::Processing);

        let response = self.client
            .post(format!("{}/api/resources/managed-onprem", self.base_url))
            .header("X-Session-ID", &auth_config.session_id)
            .header("Content-Type", "text/plain")
            .body(request_body)
            .send()
            .await
            .context("Failed to send managed on-prem request")?;

        if !response.status().is_success() {
            let status = response.status();
            let error = response.text().await?;
            loader.stop();
            let action = if is_update { "update" } else { "create" };
            bail!("Failed to {} managed on-prem resource (status {}): {}", action, status, error);
        }

        let create_response: serde_json::Value = response.json().await
            .context("Failed to parse response")?;

        loader.stop();

        let id = create_response["id"].as_str().unwrap_or("unknown");
        let resource_name = create_response["resource_name"].as_str().unwrap_or("unnamed");
        let git_url = create_response["git_url"].as_str().unwrap_or("");
        let state = create_response["state"].as_str().unwrap_or("unknown");

        if is_update {
            println!("Managed on-premises resource updated!");
        } else {
            println!("Managed on-premises resource created!");
        }
        println!("ID: {}", id);
        println!("Name: {}", resource_name);
        println!("State: {}", state);
        println!("Git URL: {}", git_url);

        log_verbose(self.verbose, "Saving deployment info...");
        self.save_deployment(id)?;
        log_verbose(self.verbose, "Saved deployment info");

        if !git_url.is_empty() {
            log_verbose(self.verbose, "Setting git remote...");
            self.set_git_remote(git_url)?;
        }

        println!("\nYou can now push to 'caution' remote to deploy:");
        println!("  git push caution main");
        println!("\nAfter pushing, check your app status:");
        println!("  caution apps list");

        Ok(())
    }

    async fn get_attestation_url(&self) -> Result<String> {
        let app = self.get_current_app().await
            .context("No deployment found. Either run 'caution init' first or provide --url")?;

        match app.public_ip {
            Some(ref ip) if !ip.is_empty() => {
                Ok(format!("http://{}/attestation", ip))
            }
            _ => {
                bail!("No public IP available. Run 'caution describe' to check deployment status, or provide --url explicitly.")
            }
        }
    }

    async fn build_local(&self, no_cache: bool) -> Result<()> {
        println!("Building EIF locally for inspection...\n");

        let commit_sha = Command::new("git")
            .args(&["rev-parse", "HEAD"])
            .output()
            .ok()
            .and_then(|o| if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            })
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        let procfile_no_cache = self.read_procfile_field("no_cache")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false);
        let no_cache = no_cache || procfile_no_cache;

        let mut loader = Loader::new("Building application image", LoaderStyle::Processing);
        let image_ref = self.build_local_docker_image(no_cache).await?;
        loader.stop();
        println!("✓ Application image built: {}\n", image_ref);

        let builder = enclave_builder::EnclaveBuilder::new_with_cache(
            "unused-template",
            "local",
            enclave_builder::ENCLAVE_SOURCE,
            "unused",
            enclave_builder::FRAMEWORK_SOURCE,
            "local",
            &commit_sha,
            enclave_builder::CacheType::Build,
            no_cache,
        )?;

        let work_dir = builder.work_dir.clone();

        let user_image = enclave_builder::UserImage {
            reference: image_ref.clone(),
        };

        let binary_path = self.read_procfile_field("binary")
            .context("Procfile must specify 'binary' field")?;

        let run_command = self.read_procfile_field("run");
        let app_source_urls = self.read_procfile_sources();
        let app_source_urls_opt = if app_source_urls.is_empty() { None } else { Some(app_source_urls.clone()) };
        let ports = self.read_procfile_ports();

        let mut loader = Loader::new("Building enclave image", LoaderStyle::Processing);
        let deployment = builder
            .build_enclave_auto(&user_image, &binary_path, run_command, app_source_urls_opt, None, None, None, None, &ports, false)
            .await
            .context("Failed to build enclave")?;
        loader.stop();

        println!("✓ Enclave built successfully!\n");

        let stage_dir = work_dir.join("eif-stage");
        println!("=== Build Artifacts ===");
        println!("EIF file: {}", deployment.eif.path.display());
        println!("Size: {} bytes", deployment.eif.size);
        println!("SHA256: {}\n", deployment.eif.sha256);

        println!("=== PCR Values ===");
        println!("PCR0 (Enclave image): {}", deployment.pcrs.pcr0);
        println!("PCR1 (Kernel/boot): {}", deployment.pcrs.pcr1);
        println!("PCR2 (Application): {}\n", deployment.pcrs.pcr2);

        println!("=== Build Directory ===");
        println!("Location: {}\n", stage_dir.display());
        println!("You can inspect the exact build process:");
        println!("  Containerfile.eif - Shows exactly how the EIF is built");
        println!("  app/ - Your application files");
        println!("  enclave/ - Enclave source code");
        println!("  kernel/ - Kernel files");
        println!("  output/ - Final EIF and PCRs files\n");

        println!("To verify your deployed enclave matches this build:");
        println!("  caution verify --reproduce\n");

        Ok(())
    }

    async fn build_and_get_pcrs(&self, external_manifest: Option<enclave_builder::EnclaveManifest>, no_cache: bool) -> Result<enclave_builder::PcrValues> {
        let (enclave_source, enclave_version) = if let Some(ref manifest) = external_manifest {
            match &manifest.enclave_source {
                enclave_builder::EnclaveSource::GitArchive { urls, .. } => {
                    (urls.first().cloned().unwrap_or_default(), "unused".to_string())
                }
                enclave_builder::EnclaveSource::GitRepository { url, branch, .. } => {
                    (url.clone(), branch.clone())
                }
                enclave_builder::EnclaveSource::Local { path } => {
                    (path.clone(), "local".to_string())
                }
            }
        } else {
            let enclave_sources = self.read_procfile_enclave_sources();
            if !enclave_sources.is_empty() {
                log_verbose(self.verbose, &format!("Using enclave source from Procfile: {}", enclave_sources[0]));
                (enclave_sources[0].clone(), "unused".to_string())
            } else {
                log_verbose(self.verbose, &format!("Using default enclave source: {}", enclave_builder::ENCLAVE_SOURCE));
                (enclave_builder::ENCLAVE_SOURCE.to_string(), "unused".to_string())
            }
        };

        let cache_key = if let Some(ref manifest) = external_manifest {
            if let Some(ref app_src) = manifest.app_source {
                app_src.commit.clone()
            } else {
                uuid::Uuid::new_v4().to_string()
            }
        } else {
            Command::new("git")
                .args(&["rev-parse", "HEAD"])
                .output()
                .ok()
                .and_then(|o| if o.status.success() {
                    Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
                } else {
                    None
                })
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
        };

        let builder = enclave_builder::EnclaveBuilder::new_with_cache(
            "unused-template",
            "local",
            &enclave_source,
            &enclave_version,
            enclave_builder::FRAMEWORK_SOURCE,
            "local",
            &cache_key,
            enclave_builder::CacheType::Reproduction,
            no_cache,
        )?;

        if let Some(cached) = builder.get_cached_eif() {
            println!("Using cached reproduction build");
            println!("Cache key: {}", cache_key);
            return Ok(cached.pcrs);
        }

        log_verbose(self.verbose, "Building Docker image locally...");

        let mut loader = Loader::new("Reproducing enclave image", LoaderStyle::Processing);
        let image_ref = if let Some(ref manifest) = external_manifest {
            let app_source = manifest.app_source.as_ref()
                .ok_or_else(|| anyhow::anyhow!("Manifest does not contain app_source - cannot reproduce without source URL"))?;

            let archive_urls: Vec<String> = app_source.urls.iter()
                .filter_map(|url| self.git_url_to_archive_urls(url, &app_source.commit).ok())
                .flatten()
                .collect();

            let git_fallback = app_source.urls.first()
                .map(|url| (url.clone(), app_source.commit.clone(), app_source.branch.clone()));

            let app_dir = self.download_and_extract_app_source_with_git_fallback(
                &archive_urls,
                git_fallback.as_ref().map(|(u, c, b)| (u.as_str(), c.as_str(), b.as_deref())),
            ).await?;
            self.build_docker_image_from_dir(&app_dir, no_cache).await?
        } else {
            self.build_local_docker_image(no_cache).await?
        };

        log_verbose(self.verbose, "Building EIF locally to calculate expected PCRs...");

        let user_image = enclave_builder::UserImage {
            reference: image_ref.clone(),
        };

        let (binary_path, run_command, app_source_urls, app_branch, app_commit, metadata) = if let Some(ref manifest) = external_manifest {
            let binary = manifest.binary.clone();
            let run_cmd = manifest.run_command.clone();
            let source_urls: Option<Vec<String>> = manifest.app_source.as_ref().map(|s| s.urls.clone());
            let branch = manifest.app_source.as_ref().and_then(|s| s.branch.clone());
            let commit = manifest.app_source.as_ref().map(|s| s.commit.clone());

            log_verbose(self.verbose, &format!("Binary from manifest: {:?}", binary));
            log_verbose(self.verbose, &format!("Run command from manifest: {:?}", run_cmd));
            log_verbose(self.verbose, &format!("App source URLs from manifest: {:?}", source_urls));
            log_verbose(self.verbose, &format!("Branch from manifest: {:?}", branch));
            log_verbose(self.verbose, &format!("Commit from manifest: {:?}", commit));

            (binary, run_cmd, source_urls, branch, commit, manifest.metadata.clone())
        } else {
            let binary = self.read_procfile_field("binary");
            let run_cmd = self.read_procfile_field("run");
            let source_urls = self.read_procfile_sources();
            let source_urls_opt = if source_urls.is_empty() { None } else { Some(source_urls) };
            let metadata = self.read_procfile_field("metadata");

            let commit = Command::new("git")
                .args(&["rev-parse", "HEAD"])
                .output()
                .ok()
                .and_then(|o| if o.status.success() {
                    Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
                } else {
                    None
                });

            let branch = Command::new("git")
                .args(&["rev-parse", "--abbrev-ref", "HEAD"])
                .output()
                .ok()
                .and_then(|o| if o.status.success() {
                    Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
                } else {
                    None
                });

            log_verbose(self.verbose, &format!("Binary from Procfile: {:?}", binary));
            log_verbose(self.verbose, &format!("Run command from Procfile: {:?}", run_cmd));
            log_verbose(self.verbose, &format!("Source URLs from Procfile: {:?}", source_urls_opt));
            log_verbose(self.verbose, &format!("Git branch: {:?}", branch));
            log_verbose(self.verbose, &format!("Git commit: {:?}", commit));
            log_verbose(self.verbose, &format!("Metadata: {:?}", metadata));

            (binary, run_cmd, source_urls_opt, branch, commit, metadata)
        };

        let ports = self.read_procfile_ports();
        log_verbose(self.verbose, &format!("Ports: {:?}", ports));

        let deployment = if let Some(ref bin_path) = binary_path {
            log_verbose(self.verbose, &format!("Using build_enclave_auto with binary: {}", bin_path));
            builder.build_enclave_auto(
                &user_image,
                bin_path,
                run_command,
                app_source_urls,
                app_branch,
                app_commit,
                metadata,
                external_manifest,
                &ports,
                false,
            ).await
        } else {
            log_verbose(self.verbose, "Using build_enclave (no binary specified)");
            builder.build_enclave(
                &user_image,
                None,
                run_command,
                app_source_urls,
                app_branch,
                app_commit,
                metadata,
                external_manifest,
                &ports,
                false,
            ).await
        }.context("Failed to build enclave locally")?;
        loader.stop();

        if let Some(work_dir) = deployment.eif.path.parent() {
            let stage_dir = work_dir.join("eif-stage");
            if stage_dir.exists() {
                println!();
                println!("Build artifacts available at: {}", stage_dir.display());
                println!("You can review everything that went into building this enclave:");
                println!("  • Containerfile.eif - The complete build recipe");
                println!("  • app/ - Your application files");
                println!("  • enclave/ - EnclaveOS source (attestation-service, init)");
                println!("  • run.sh - Generated startup script");
                println!("  • manifest.json - Build provenance information");
            }
        }

        Ok(deployment.pcrs)
    }

    fn read_pcrs_from_file(&self, path: &str) -> Result<enclave_builder::PcrValues> {
        use std::fs;
        let content = fs::read_to_string(path)
            .context(format!("Failed to read PCRs file: {}", path))?;

        if let Ok(pcrs) = serde_json::from_str::<enclave_builder::PcrValues>(&content) {
            return Ok(pcrs);
        }

        let mut pcr0 = None;
        let mut pcr1 = None;
        let mut pcr2 = None;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // eif_build is weird... it is <digest> <pcr>
            if let Some((pcr_digest, pcr_name)) = line.split_once(' ') {
                match pcr_name.trim().to_lowercase().as_str() {
                    "pcr0" => pcr0 = Some(pcr_digest.trim().to_owned()),
                    "pcr1" => pcr1 = Some(pcr_digest.trim().to_owned()),
                    "pcr2" => pcr2 = Some(pcr_digest.trim().to_owned()),
                    _ => {}
                }
            }
        }

        match (pcr0, pcr1, pcr2) {
            (Some(pcr0), Some(pcr1), Some(pcr2)) => Ok(enclave_builder::PcrValues { pcr0, pcr1, pcr2, pcr3: None, pcr4: None }),
            _ => bail!("PCRs file must contain PCR0, PCR1, and PCR2 values")
        }
    }

    async fn verify(&self, attestation_url_opt: Option<String>, from_local: bool, app_source_url: Option<String>, pcrs_file: Option<String>, no_cache: bool) -> Result<()> {
        println!("Verifying enclave attestation...");

        let attestation_url = if let Some(u) = attestation_url_opt {
            u
        } else {
            self.get_attestation_url().await?
        };

        let nonce = {
            use rand::RngCore;
            let mut nonce = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut nonce);
            nonce
        };

        println!("\nChallenge nonce (sent): {}", hex::encode(&nonce));

        log_verbose(self.verbose, &format!("Requesting attestation from: {}", attestation_url));
        println!("Requesting attestation...");

        #[derive(Serialize)]
        struct AttestationRequest {
            nonce: Vec<u8>,
        }

        let response = self.client
            .post(&attestation_url)
            .json(&AttestationRequest { nonce: nonce.clone() })
            .send()
            .await
            .context("Failed to fetch attestation document")?;

        if !response.status().is_success() {
            bail!("Failed to fetch attestation: {}", response.status());
        }

        #[derive(Deserialize)]
        struct AttestationResponse {
            attestation_document: String,
            manifest: Option<serde_json::Value>,
        }

        let attest_resp: AttestationResponse = response.json().await
            .context("Failed to parse attestation response as JSON")?;

        let attestation_b64 = &attest_resp.attestation_document;
        log_verbose(self.verbose, &format!("Received attestation: {} bytes", attestation_b64.len()));
        let attestation_bytes = base64::engine::general_purpose::STANDARD.decode(attestation_b64)
            .context("Failed to decode inner attestation")?;

        println!("\nVerifying attestation...");
        let (remote_pcrs, document) = verify_attestation(&attestation_b64, &nonce)
            .context("Attestation verification failed")?;

        println!("✓ Challenge nonce (received): {}", hex::encode(&remote_pcrs.nonce));
        println!("✓ Attestation verified successfully");

        println!("\nRemote PCR values (from deployed enclave):");
        println!("  PCR0: {}", remote_pcrs.pcr0);
        println!("  PCR1: {}", remote_pcrs.pcr1);
        println!("  PCR2: {}", remote_pcrs.pcr2);

        let manifest: Option<enclave_builder::EnclaveManifest> = if let Some(manifest_val) = attest_resp.manifest {
            match serde_json::from_value(manifest_val) {
                Ok(m) => Some(m),
                Err(e) => {
                    log_verbose(self.verbose, &format!("Failed to parse manifest: {}", e));
                    None
                }
            }
        } else {
            None
        };

        if let Some(ref m) = manifest {
            println!("\nManifest information:");
            if let Some(ref app_src) = m.app_source {
                if app_src.urls.len() == 1 {
                    print!("  App source: {}", app_src.urls[0]);
                } else {
                    print!("  App source: ({} URLs)", app_src.urls.len());
                }
                print!(" commit: {}", app_src.commit);
                if let Some(ref b) = app_src.branch {
                    print!(" branch: {}", b);
                }
                println!();
                if app_src.urls.len() > 1 {
                    for (i, url) in app_src.urls.iter().enumerate() {
                        println!("    [{}] {}", i + 1, url);
                    }
                }
            } else {
                println!("  App source: (none - private code)");
            }

            match &m.enclave_source {
                enclave_builder::EnclaveSource::GitArchive { urls, commit } => {
                    if urls.len() == 1 {
                        print!("  Enclave source: {}", urls[0]);
                    } else {
                        print!("  Enclave source: ({} URLs)", urls.len());
                    }
                    if let Some(c) = commit {
                        print!(" commit: {}", c);
                    }
                    println!();
                    if urls.len() > 1 {
                        for (i, url) in urls.iter().enumerate() {
                            println!("    [{}] {}", i + 1, url);
                        }
                    }
                }
                enclave_builder::EnclaveSource::GitRepository { url, branch, commit } => {
                    print!("  Enclave source: {}", url);
                    if let Some(c) = commit {
                        print!(" commit: {}", c);
                    }
                    println!(" branch: {}", branch);
                }
                enclave_builder::EnclaveSource::Local { path } => {
                    println!("  Enclave source: {} (local)", path);
                }
            }
            match &m.framework_source {
                enclave_builder::FrameworkSource::GitArchive { url, commit } => {
                    print!("  Framework source: {}", url);
                    if let Some(c) = commit {
                        print!(" commit: {}", c);
                    }
                    println!();
                }
            }
            if let Some(ref metadata) = m.metadata {
                println!("  Metadata: {}", metadata);
            }
        }

        let expected_pcrs = if let Some(pcrs_path) = pcrs_file {
            println!("\nReading expected PCRs from file: {}", pcrs_path);
            self.read_pcrs_from_file(&pcrs_path)?
        } else if from_local {
            println!("\nBuilding from local directory...");
            self.build_and_get_pcrs(None, no_cache).await?
        } else if let Some(ref source_url) = app_source_url {
            println!("\nBuilding from provided source URL: {}", source_url);
            if let Some(ref m) = manifest {
                let mut modified_manifest = m.clone();
                let commit = m.app_source.as_ref()
                    .map(|s| s.commit.clone())
                    .unwrap_or_else(|| "HEAD".to_string());
                modified_manifest.app_source = Some(enclave_builder::AppSource {
                    urls: vec![source_url.clone()],
                    commit,
                    branch: None,
                });
                self.build_and_get_pcrs(Some(modified_manifest), no_cache).await?
            } else {
                println!("\n⚠️  Remote attestation does not include a manifest");
                println!("Cannot determine commit hash without manifest.");
                println!();
                println!("Options:");
                println!("  1. Build from local directory: caution verify --from-local");
                println!("  2. Use a PCRs file: caution verify --pcrs pcrs.txt");
                println!();
                bail!("Manifest required when using --app-source-url");
            }
        } else {
            if let Some(ref m) = manifest {
                if m.app_source.is_none() {
                    println!("\n⚠️  Cannot reproduce build - no application source code available");
                    println!();
                    println!("The remote manifest indicates this deployment uses private code.");
                    println!("You cannot reproduce this build from remote manifest.");
                    println!();
                    println!("Options:");
                    println!("  1. Provide the source URL: caution verify --app-source-url git@codeberg.org:org/repo.git");
                    println!("  2. Build from local directory: caution verify --from-local");
                    println!("  3. Use a PCRs file: caution verify --pcrs pcrs.txt");
                    println!();
                    bail!("Cannot reproduce private code deployment");
                }
                println!("\nReproducing build from remote manifest...");
                self.build_and_get_pcrs(manifest.clone(), no_cache).await?
            } else {
                println!("\n⚠️  Remote attestation does not include a manifest");
                println!();
                println!("The remote deployment was built without manifest support.");
                println!();
                println!("Options:");
                println!("  1. Build from local directory: caution verify --from-local");
                println!("  2. Use a PCRs file: caution verify --pcrs pcrs.txt");
                println!("  3. Redeploy your app to enable manifest support");
                println!();
                bail!("Manifest not available from remote");
            }
        };

        println!("\nExpected PCR values:");
        println!("  PCR0: {}", expected_pcrs.pcr0);
        println!("  PCR1: {}", expected_pcrs.pcr1);
        println!("  PCR2: {}", expected_pcrs.pcr2);

        let is_debug = remote_pcrs.pcr0.chars().all(|c| c == '0')
            || remote_pcrs.pcr1.chars().all(|c| c == '0')
            || remote_pcrs.pcr2.chars().all(|c| c == '0');

        if is_debug {
            println!("\n⚠ WARNING: The remote enclave is running in DEBUG MODE");
            println!("In debug mode, AWS Nitro Enclaves zero out PCR values.");
            println!("This means attestation cannot be verified.");
            println!("\nDebug mode should ONLY be used for development/testing.");
            println!("For production, the enclave must run in production mode.");
            bail!("Cannot verify attestation: enclave is in debug mode");
        }

        println!("\nDoing a bootproof-sdk verification");
        let pcrs: Result<NitroPcrs, hex::FromHexError> = [
            (0, &remote_pcrs.pcr0),
            (1, &remote_pcrs.pcr1),
            (2, &remote_pcrs.pcr2),
        ]
        .into_iter()
        .map(|(i, pcr)| hex::decode(pcr).map(|pcr| (i, pcr)))
        .collect();
        let nitro = Nitro::new(
            attestation_bytes,
            pcrs.context("bad pcr hex")?
        ).context("could not build bootproof nitro attestation")?;
        let duration_since_epoch = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .context("could not get time since epoch")?;
        nitro
            .verify(duration_since_epoch, &nonce)
            .context("could not verify Nitro attestation using bootproof-sdk")?;

        println!("\nComparing PCR values...");
        let pcrs_match = expected_pcrs.pcr0 == remote_pcrs.pcr0
            && expected_pcrs.pcr1 == remote_pcrs.pcr1
            && expected_pcrs.pcr2 == remote_pcrs.pcr2;

        if pcrs_match {
            if let serde_cbor::Value::Map(map) = &document &&
                let Some(serde_cbor::Value::Bytes(user_data)) = map.get(&"user_data".to_string().into()) {
                    println!();
                    match str::from_utf8(user_data) {
                        Ok(user_data) => {
                            println!("User data: {user_data}");
                        },
                        Err(_) => {
                            println!("User data: {user_data:?}");
                        },
                    }
            }

            println!("\n✓ Attestation verification PASSED");
            println!("The deployed enclave matches the expected PCRs.");
            println!("This means the code running in the enclave is exactly what you expect.");
            println!("\nPowered by: Caution (https://caution.co)");
            Ok(())
        } else {
            println!("\n✗ Attestation verification FAILED");
            println!("The deployed enclave does NOT match the expected PCRs.");
            println!("\nDifferences:");
            if expected_pcrs.pcr0 != remote_pcrs.pcr0 {
                println!("  PCR0: expected {} != remote {}", expected_pcrs.pcr0, remote_pcrs.pcr0);
            }
            if expected_pcrs.pcr1 != remote_pcrs.pcr1 {
                println!("  PCR1: expected {} != remote {}", expected_pcrs.pcr1, remote_pcrs.pcr1);
            }
            if expected_pcrs.pcr2 != remote_pcrs.pcr2 {
                println!("  PCR2: expected {} != remote {}", expected_pcrs.pcr2, remote_pcrs.pcr2);
            }
            bail!("PCR verification failed - the deployed code may have been tampered with");
        }
    }

    async fn build_local_docker_image(&self, no_cache: bool) -> Result<String> {
        let work_dir = std::env::current_dir()
            .context("Failed to get current directory")?;
        self.build_docker_image_from_dir(&work_dir, no_cache).await
    }

    async fn build_docker_image_from_dir(&self, work_dir: &std::path::Path, no_cache: bool) -> Result<String> {
        use tokio::process::Command;

        let commit_sha = Command::new("git")
            .args(&["rev-parse", "HEAD"])
            .current_dir(work_dir)
            .output()
            .await
            .ok()
            .and_then(|o| if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            })
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        let tag = format!("caution-local-build:{}", &commit_sha[..12.min(commit_sha.len())]);

        if !no_cache {
            let inspect = Command::new("docker")
                .args(&["inspect", "--type=image", &tag])
                .output()
                .await
                .context("Failed to inspect docker image")?;

            if inspect.status.success() {
                log_verbose(self.verbose, &format!("Using cached Docker image: {}", tag));
                return Ok(tag);
            }
        } else {
            log_verbose(self.verbose, "--no-cache specified, rebuilding Docker image...");
        }

        log_verbose(self.verbose, &format!("Building Docker image with tag: {}", tag));

        let procfile_path = work_dir.join("Procfile");
        let config = if procfile_path.exists() {
            let content = std::fs::read_to_string(&procfile_path)
                .context("Failed to read Procfile")?;
            let mut build_command = None;
            let mut containerfile = None;
            let mut oci_tarball = None;

            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((key, value)) = line.split_once(':') {
                    let key = key.trim().to_lowercase();
                    let value = value.trim().to_string();
                    match key.as_str() {
                        "build" => build_command = Some(value),
                        "containerfile" => containerfile = Some(value),
                        "oci_tarball" => oci_tarball = Some(value),
                        _ => {}
                    }
                }
            }

            BuildConfig {
                build_command,
                containerfile,
                oci_tarball,
                no_cache: false,
            }
        } else {
            BuildConfig {
                build_command: None,
                containerfile: None,
                oci_tarball: None,
                no_cache: false,
            }
        };

        log_verbose(self.verbose, &format!("work_dir = {:?}", work_dir));
        log_verbose(self.verbose, &format!("BuildConfig = {:?}", config));

        build_user_image(work_dir, &tag, &config).await?;

        log_verbose(self.verbose, &format!("Docker image built successfully: {}", tag));
        Ok(tag)
    }

    async fn download_and_extract_app_source(&self, url: &str) -> Result<PathBuf> {
        use flate2::read::GzDecoder;
        use tar::Archive;

        let cache_dir = dirs::home_dir()
            .context("Failed to determine home directory")?
            .join(".cache/caution/downloads");
        std::fs::create_dir_all(&cache_dir)
            .context("Failed to create downloads cache directory")?;

        use sha2::Digest;
        let url_hash = sha2::Sha256::digest(url.as_bytes());
        let extract_dir = cache_dir.join(hex::encode(&url_hash[..8]));

        // Check if already cached
        if extract_dir.exists() && extract_dir.read_dir().map(|mut d| d.next().is_some()).unwrap_or(false) {
            log_verbose(self.verbose, &format!("Using cached app source: {}", extract_dir.display()));
            return Ok(extract_dir);
        }

        log_verbose(self.verbose, &format!("Downloading app source: {}", url));

        // Clean up any partial extraction
        if extract_dir.exists() {
            std::fs::remove_dir_all(&extract_dir)
                .context("Failed to clean up partial extraction")?;
        }

        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(30))
            .timeout(std::time::Duration::from_secs(300))  // 5 minutes for full download
            .build()
            .context("Failed to create HTTP client")?;

        let response = client.get(url)
            .send()
            .await
            .context("Failed to download app source")?;

        if !response.status().is_success() {
            bail!("Failed to download app source: HTTP {}", response.status());
        }

        let archive_bytes = response.bytes()
            .await
            .context("Failed to read archive bytes")?;

        log_verbose(self.verbose, &format!("Downloaded {} bytes, extracting...", archive_bytes.len()));

        // Extract tar.gz archive with strip_components=1
        let decoder = GzDecoder::new(&archive_bytes[..]);
        let mut archive = Archive::new(decoder);

        for entry in archive.entries().context("Failed to read archive entries")? {
            let mut entry = entry.context("Failed to read archive entry")?;
            let path = entry.path().context("Failed to get entry path")?;

            // Skip the first path component (equivalent to --strip-components=1)
            let components: Vec<_> = path.components().collect();
            if components.len() <= 1 {
                continue;
            }

            let stripped_path: PathBuf = components[1..].iter().collect();
            let dest_path = extract_dir.join(&stripped_path);

            if let Some(parent) = dest_path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
            }

            entry.unpack(&dest_path)
                .with_context(|| format!("Failed to extract: {}", stripped_path.display()))?;
        }

        log_verbose(self.verbose, &format!("App source extracted to: {}", extract_dir.display()));

        Ok(extract_dir)
    }

    async fn download_and_extract_app_source_with_fallbacks(&self, urls: &[String]) -> Result<PathBuf> {
        if urls.is_empty() {
            bail!("No source URLs provided");
        }

        let mut last_error: Option<anyhow::Error> = None;

        for (i, url) in urls.iter().enumerate() {
            if i > 0 {
                log_verbose(self.verbose, &format!("Trying fallback URL ({}/{}): {}", i + 1, urls.len(), url));
            }

            match self.download_and_extract_app_source(url).await {
                Ok(path) => return Ok(path),
                Err(e) => {
                    if i < urls.len() - 1 {
                        eprintln!("Failed to download from {}: {}", url, e);
                        eprintln!("Trying next URL...");
                    }
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("All source URLs failed")))
    }

    async fn download_and_extract_app_source_with_git_fallback(
        &self,
        archive_urls: &[String],
        git_fallback: Option<(&str, &str, Option<&str>)>,
    ) -> Result<PathBuf> {
        if !archive_urls.is_empty() {
            match self.download_and_extract_app_source_with_fallbacks(archive_urls).await {
                Ok(path) => return Ok(path),
                Err(e) => {
                    log_verbose(self.verbose, &format!("Archive download failed: {}", e));
                }
            }
        }

        if let Some((git_url, commit, branch)) = git_fallback {
            println!("Archive download failed. Trying git clone (may require SSH access)...");

            let temp_dir = tempfile::TempDir::new()
                .context("Failed to create temp directory")?;
            let clone_path = temp_dir.path().join("repo");

            // If we have a branch, clone by branch first (works with Forgejo/Codeberg)
            // then checkout the specific commit
            if let Some(branch_name) = branch {
                log_verbose(self.verbose, &format!("Cloning branch '{}' then checking out commit '{}'", branch_name, commit));

                let clone_output = Command::new("git")
                    .args(&["clone", "--depth", "100", "--single-branch", "--branch", branch_name, git_url, clone_path.to_str().unwrap()])
                    .output()
                    .context("Failed to clone repository")?;

                if !clone_output.status.success() {
                    let stderr = String::from_utf8_lossy(&clone_output.stderr);
                    log_verbose(self.verbose, &format!("Branch clone failed: {}", stderr));
                    // Fall through to try commit-based fetch
                } else {
                    // Checkout the specific commit
                    let checkout_output = Command::new("git")
                        .args(&["checkout", commit])
                        .current_dir(&clone_path)
                        .output()
                        .context("Failed to checkout commit")?;

                    if checkout_output.status.success() {
                        let extract_dir = temp_dir.into_path().join("repo");
                        log_verbose(self.verbose, &format!("Git clone successful: {}", extract_dir.display()));
                        return Ok(extract_dir);
                    } else {
                        let stderr = String::from_utf8_lossy(&checkout_output.stderr);
                        log_verbose(self.verbose, &format!("Commit checkout failed: {}, will try deeper clone", stderr));

                        // Try fetching more history to find the commit
                        let _ = Command::new("git")
                            .args(&["fetch", "--unshallow"])
                            .current_dir(&clone_path)
                            .output();

                        let checkout_retry = Command::new("git")
                            .args(&["checkout", commit])
                            .current_dir(&clone_path)
                            .output()
                            .context("Failed to checkout commit after unshallow")?;

                        if checkout_retry.status.success() {
                            let extract_dir = temp_dir.into_path().join("repo");
                            log_verbose(self.verbose, &format!("Git clone successful after unshallow: {}", extract_dir.display()));
                            return Ok(extract_dir);
                        }
                    }
                }
            }

            // Fallback: try direct fetch by commit (works with GitHub)
            std::fs::create_dir_all(&clone_path)?;

            let init_output = Command::new("git")
                .args(&["init"])
                .current_dir(&clone_path)
                .output()
                .context("Failed to run git init")?;

            if !init_output.status.success() {
                let stderr = String::from_utf8_lossy(&init_output.stderr);
                bail!("Git init failed: {}", stderr);
            }

            let remote_output = Command::new("git")
                .args(&["remote", "add", "origin", git_url])
                .current_dir(&clone_path)
                .output()
                .context("Failed to add git remote")?;

            if !remote_output.status.success() {
                let stderr = String::from_utf8_lossy(&remote_output.stderr);
                bail!("Git remote add failed: {}", stderr);
            }

            let fetch_output = Command::new("git")
                .args(&["fetch", "--depth", "1", "origin", commit])
                .current_dir(&clone_path)
                .output()
                .context("Failed to fetch commit")?;

            if !fetch_output.status.success() {
                let stderr = String::from_utf8_lossy(&fetch_output.stderr);
                bail!("Git fetch failed: {}", stderr);
            }

            let checkout_output = Command::new("git")
                .args(&["checkout", "FETCH_HEAD"])
                .current_dir(&clone_path)
                .output()
                .context("Failed to checkout commit")?;

            if !checkout_output.status.success() {
                let stderr = String::from_utf8_lossy(&checkout_output.stderr);
                bail!("Git checkout failed: {}", stderr);
            }

            let extract_dir = temp_dir.into_path().join("repo");
            log_verbose(self.verbose, &format!("Git clone successful: {}", extract_dir.display()));
            return Ok(extract_dir);
        }

        bail!("No source URLs available and no git fallback configured")
    }

    async fn add_ssh_key(&self, key_file: Option<PathBuf>, from_agent: bool, key: Option<String>, name: Option<String>) -> Result<()> {
        let config = self.ensure_authenticated().await?;

        if from_agent {
            let keys = self.get_ssh_agent_keys();
            if keys.is_empty() {
                bail!("No keys found in ssh-agent. Run 'ssh-add' first.");
            }

            let mut added = 0;
            for (k, comment) in keys {
                let key_name = name.clone().unwrap_or(comment);
                match self.add_single_key(&config.session_id, &key_name, &k).await {
                    Ok(()) => {
                        println!("Added: {}", key_name);
                        added += 1;
                    }
                    Err(e) => println!("Skipped {}: {}", key_name, e),
                }
            }
            println!("{} key(s) added.", added);
        } else if let Some(key_str) = key {
            let key_content = key_str.trim();
            if !key_content.starts_with("ssh-") {
                bail!("Invalid SSH key format");
            }
            let key_name = name.unwrap_or_else(|| "key".to_string());
            self.add_single_key(&config.session_id, &key_name, key_content).await?;
            println!("Added: {}", key_name);
        } else if let Some(path) = key_file {
            let key_content = fs::read_to_string(&path)
                .context("Failed to read SSH key file")?
                .trim()
                .to_string();

            if !key_content.starts_with("ssh-") {
                bail!("Invalid SSH key format");
            }

            let key_name = name.unwrap_or_else(|| {
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("key")
                    .to_string()
            });

            self.add_single_key(&config.session_id, &key_name, &key_content).await?;
            println!("Added: {}", key_name);
        } else {
            bail!("Provide a key file, --key, or --from-agent");
        }

        Ok(())
    }

    async fn add_single_key(&self, session_id: &str, name: &str, key: &str) -> Result<()> {
        let body = serde_json::json!({ "name": name, "public_key": key });

        let response = self.signed_post(session_id, "/ssh-keys", &body).await?;

        if !response.status().is_success() {
            let error = response.text().await?;
            if error.contains("insert SSH key") || error.contains("duplicate") || error.contains("23505") {
                bail!("Key already exists");
            }
            bail!("{}", error);
        }
        Ok(())
    }

    async fn remove_ssh_key(&self, fingerprint: &str) -> Result<()> {
        let config = self.ensure_authenticated().await?;

        let response = self.client
            .delete(format!("{}/ssh-keys/{}", self.base_url, fingerprint))
            .header("X-Session-ID", config.session_id)
            .send()
            .await?;

        if !response.status().is_success() {
            let error = response.text().await?;
            bail!("Failed to remove key: {}", error);
        }

        println!("Key removed.");
        Ok(())
    }

    fn get_ssh_agent_keys(&self) -> Vec<(String, String)> {
        let output = Command::new("ssh-add").arg("-L").output();
        match output {
            Ok(out) if out.status.success() => {
                String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .filter(|line| line.starts_with("ssh-"))
                    .map(|line| {
                        let parts: Vec<&str> = line.splitn(3, ' ').collect();
                        let comment = parts.get(2).unwrap_or(&"unnamed").to_string();
                        (line.to_string(), comment)
                    })
                    .collect()
            }
            _ => Vec::new()
        }
    }

    async fn list_ssh_keys(&self) -> Result<()> {
        let config = self.ensure_authenticated().await?;

        let response = self.client
            .get(format!("{}/ssh-keys", self.base_url))
            .header("X-Session-ID", config.session_id)
            .send()
            .await?;

        if response.status().is_success() {
            let response_data: serde_json::Value = response.json().await?;
            let keys = response_data["keys"].as_array()
                .ok_or_else(|| anyhow::anyhow!("Invalid response format"))?;

            if keys.is_empty() {
                println!("No SSH keys found. Add one with 'ssh-keys add'");
            } else {
                println!("SSH Keys:");
                for key in keys {
                    let id = key["id"].as_str().unwrap_or("unknown");
                    let name = key["name"].as_str().unwrap_or("untitled");
                    let fingerprint = key["fingerprint"].as_str().unwrap_or("unknown");
                    println!("  [{}] {} - {}", id, name, fingerprint);
                }
            }
            Ok(())
        } else {
            bail!("Failed to list SSH keys: {}", response.status())
        }
    }

    fn get_cache_dir(&self) -> Result<PathBuf> {
        let cache_dir = dirs::home_dir()
            .context("Failed to determine home directory")?
            .join(".cache/caution");
        Ok(cache_dir)
    }

    fn cache_path(&self) -> Result<()> {
        let cache_dir = self.get_cache_dir()?;
        println!("{}", cache_dir.display());
        Ok(())
    }

    fn cache_size(&self) -> Result<()> {
        let cache_dir = self.get_cache_dir()?;

        if !cache_dir.exists() {
            println!("Cache is empty (0 bytes)");
            return Ok(());
        }

        let total_size = self.dir_size(&cache_dir)?;
        println!("{}", self.format_size(total_size));

        Ok(())
    }

    fn cache_list(&self) -> Result<()> {
        let cache_dir = self.get_cache_dir()?;

        if !cache_dir.exists() {
            println!("Cache is empty");
            return Ok(());
        }

        let downloads_dir = cache_dir.join("downloads");
        if downloads_dir.exists() {
            println!("Downloads:");
            if let Ok(entries) = fs::read_dir(&downloads_dir) {
                let mut items: Vec<_> = entries.filter_map(|e| e.ok()).collect();
                if items.is_empty() {
                    println!("  (empty)");
                } else {
                    items.sort_by_key(|e| e.path());
                    for entry in items {
                        let path = entry.path();
                        let size = self.dir_size(&path).unwrap_or(0);
                        let name = path.file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_else(|| "unknown".to_string());
                        println!("  {} ({})", name, self.format_size(size));
                    }
                }
            }
        } else {
            println!("Cache is empty");
        }

        Ok(())
    }

    fn cache_destroy(&self, force: bool) -> Result<()> {
        let cache_dir = self.get_cache_dir()?;

        if !cache_dir.exists() {
            println!("Cache is already empty");
            return Ok(());
        }

        let total_size = self.dir_size(&cache_dir)?;

        if !force {
            println!("About to delete cache:");
            println!("  Path: {}", cache_dir.display());
            println!("  Size: {}", self.format_size(total_size));
            println!();
            print!("Are you sure you want to delete the cache? [y/N] ");
            std::io::stdout().flush()?;

            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;

            if !input.trim().eq_ignore_ascii_case("y") {
                println!("Aborted.");
                return Ok(());
            }
        }

        fs::remove_dir_all(&cache_dir)
            .context("Failed to remove cache directory")?;

        println!("Cache cleared ({} freed)", self.format_size(total_size));
        Ok(())
    }

    fn dir_size(&self, path: &PathBuf) -> Result<u64> {
        let mut total = 0;
        if path.is_file() {
            return Ok(fs::metadata(path)?.len());
        }
        if path.is_dir() {
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    total += fs::metadata(&path)?.len();
                } else if path.is_dir() {
                    total += self.dir_size(&path)?;
                }
            }
        }
        Ok(total)
    }

    fn format_size(&self, bytes: u64) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;

        if bytes >= GB {
            format!("{:.2} GB", bytes as f64 / GB as f64)
        } else if bytes >= MB {
            format!("{:.2} MB", bytes as f64 / MB as f64)
        } else if bytes >= KB {
            format!("{:.2} KB", bytes as f64 / KB as f64)
        } else {
            format!("{} bytes", bytes)
        }
    }

    async fn add_credential(&self, platform: CredentialPlatform, name: String, is_default: bool, region: Option<String>) -> Result<()> {
        let config = self.ensure_authenticated().await?;

        let request_body = match platform {
            CredentialPlatform::Aws => {
                println!("Adding AWS credentials for '{}'", name);
                print!("AWS Access Key ID: ");
                std::io::stdout().flush()?;
                let mut access_key_id = String::new();
                std::io::stdin().read_line(&mut access_key_id)?;
                let access_key_id = access_key_id.trim().to_string();

                print!("AWS Secret Access Key: ");
                std::io::stdout().flush()?;
                let secret_access_key = rpassword::read_password()
                    .context("Failed to read secret access key")?;

                serde_json::json!({
                    "platform": "aws",
                    "name": name,
                    "access_key_id": access_key_id,
                    "secret_access_key": secret_access_key,
                    "default_region": region,
                    "is_default": is_default
                })
            }
            CredentialPlatform::Digitalocean | CredentialPlatform::Hetzner |
            CredentialPlatform::Linode | CredentialPlatform::Vultr | CredentialPlatform::Ovh => {
                println!("Adding {} credentials for '{}'", platform, name);
                print!("API Token: ");
                std::io::stdout().flush()?;
                let api_token = rpassword::read_password()
                    .context("Failed to read API token")?;

                serde_json::json!({
                    "platform": platform.to_string(),
                    "name": name,
                    "api_token": api_token,
                    "default_region": region,
                    "is_default": is_default
                })
            }
            CredentialPlatform::Gcp => {
                println!("Adding GCP credentials for '{}'", name);
                print!("Service Account Email: ");
                std::io::stdout().flush()?;
                let mut email = String::new();
                std::io::stdin().read_line(&mut email)?;
                let email = email.trim().to_string();

                print!("Path to service account JSON key file: ");
                std::io::stdout().flush()?;
                let mut key_path = String::new();
                std::io::stdin().read_line(&mut key_path)?;
                let key_path = key_path.trim();

                let key_content = fs::read_to_string(key_path)
                    .context("Failed to read service account key file")?;
                let key_json: serde_json::Value = serde_json::from_str(&key_content)
                    .context("Invalid JSON in service account key file")?;

                serde_json::json!({
                    "platform": "gcp",
                    "name": name,
                    "service_account_email": email,
                    "service_account_key": key_json,
                    "default_region": region,
                    "is_default": is_default
                })
            }
            CredentialPlatform::Azure => {
                println!("Adding Azure credentials for '{}'", name);
                print!("Tenant ID: ");
                std::io::stdout().flush()?;
                let mut tenant_id = String::new();
                std::io::stdin().read_line(&mut tenant_id)?;
                let tenant_id = tenant_id.trim().to_string();

                print!("Client ID: ");
                std::io::stdout().flush()?;
                let mut client_id = String::new();
                std::io::stdin().read_line(&mut client_id)?;
                let client_id = client_id.trim().to_string();

                print!("Client Secret: ");
                std::io::stdout().flush()?;
                let client_secret = rpassword::read_password()
                    .context("Failed to read client secret")?;

                print!("Subscription ID: ");
                std::io::stdout().flush()?;
                let mut subscription_id = String::new();
                std::io::stdin().read_line(&mut subscription_id)?;
                let subscription_id = subscription_id.trim().to_string();

                serde_json::json!({
                    "platform": "azure",
                    "name": name,
                    "tenant_id": tenant_id,
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "subscription_id": subscription_id,
                    "default_region": region,
                    "is_default": is_default
                })
            }
            CredentialPlatform::Baremetal => {
                println!("Adding bare metal credentials for '{}'", name);
                print!("Host address: ");
                std::io::stdout().flush()?;
                let mut host = String::new();
                std::io::stdin().read_line(&mut host)?;
                let host = host.trim().to_string();

                print!("SSH Port [22]: ");
                std::io::stdout().flush()?;
                let mut port_str = String::new();
                std::io::stdin().read_line(&mut port_str)?;
                let port: u16 = port_str.trim().parse().unwrap_or(22);

                print!("Username: ");
                std::io::stdout().flush()?;
                let mut username = String::new();
                std::io::stdin().read_line(&mut username)?;
                let username = username.trim().to_string();

                print!("Use SSH key (k) or password (p)? [k]: ");
                std::io::stdout().flush()?;
                let mut auth_type = String::new();
                std::io::stdin().read_line(&mut auth_type)?;
                let auth_type = auth_type.trim().to_lowercase();

                let (ssh_private_key, ssh_password) = if auth_type == "p" {
                    print!("SSH Password: ");
                    std::io::stdout().flush()?;
                    let password = rpassword::read_password()
                        .context("Failed to read password")?;
                    (None, Some(password))
                } else {
                    print!("Path to SSH private key [~/.ssh/id_ed25519]: ");
                    std::io::stdout().flush()?;
                    let mut key_path = String::new();
                    std::io::stdin().read_line(&mut key_path)?;
                    let key_path = key_path.trim();
                    let key_path = if key_path.is_empty() {
                        dirs::home_dir()
                            .map(|h| h.join(".ssh/id_ed25519"))
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_else(|| "~/.ssh/id_ed25519".to_string())
                    } else {
                        key_path.to_string()
                    };

                    let key_content = fs::read_to_string(&key_path)
                        .context(format!("Failed to read SSH key from {}", key_path))?;
                    (Some(key_content), None)
                };

                serde_json::json!({
                    "platform": "baremetal",
                    "name": name,
                    "host": host,
                    "port": port,
                    "username": username,
                    "ssh_private_key": ssh_private_key,
                    "ssh_password": ssh_password,
                    "is_default": is_default
                })
            }
        };

        let response = self.client
            .post(format!("{}/credentials", self.base_url))
            .header("X-Session-ID", &config.session_id)
            .json(&request_body)
            .send()
            .await?;

        if response.status().is_success() {
            let cred: serde_json::Value = response.json().await?;
            println!("Credential '{}' added successfully (ID: {})", name, cred["id"]);
            if is_default {
                println!("Set as default for {}", platform);
            }
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_default();
            bail!("Failed to add credential: {}", error_text)
        }
    }

    async fn list_credentials(&self) -> Result<()> {
        let config = self.ensure_authenticated().await?;

        let response = self.client
            .get(format!("{}/credentials", self.base_url))
            .header("X-Session-ID", &config.session_id)
            .send()
            .await?;

        if response.status().is_success() {
            let credentials: Vec<serde_json::Value> = response.json().await?;

            if credentials.is_empty() {
                println!("No cloud credentials found. Add one with 'caution credentials add <platform> <name>'");
            } else {
                println!("Cloud Credentials:");
                println!();
                for cred in credentials {
                    let id = cred["id"].as_str().unwrap_or("unknown");
                    let name = cred["name"].as_str().unwrap_or("untitled");
                    let platform = cred["platform"].as_str().unwrap_or("unknown");
                    let identifier = cred["identifier"].as_str().unwrap_or("");
                    let is_default = cred["is_default"].as_bool().unwrap_or(false);
                    let region = cred["default_region"].as_str();

                    let default_marker = if is_default { " (default)" } else { "" };
                    let region_str = region.map(|r| format!(" [{}]", r)).unwrap_or_default();

                    println!("  [{}] {} - {}{}{}", id, name, platform, default_marker, region_str);
                    println!("       Identifier: {}", identifier);
                }
            }
            Ok(())
        } else {
            bail!("Failed to list credentials: {}", response.status())
        }
    }

    async fn remove_credential(&self, id: &str, force: bool) -> Result<()> {
        let config = self.ensure_authenticated().await?;

        let credential_id = uuid::Uuid::parse_str(id)
            .context("Invalid credential ID - must be a valid UUID")?;

        let response = self.client
            .get(format!("{}/credentials/{}", self.base_url, credential_id))
            .header("X-Session-ID", &config.session_id)
            .send()
            .await?;

        if !response.status().is_success() {
            bail!("Credential '{}' not found", id);
        }

        let cred: serde_json::Value = response.json().await?;
        let name = cred["name"].as_str().unwrap_or("unknown");
        let platform = cred["platform"].as_str().unwrap_or("unknown");

        if !force {
            println!("About to delete credential:");
            println!("  Name: {}", name);
            println!("  Platform: {}", platform);
            println!();
            print!("Are you sure? [y/N] ");
            std::io::stdout().flush()?;

            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;

            if !input.trim().eq_ignore_ascii_case("y") {
                println!("Aborted.");
                return Ok(());
            }
        }

        let response = self.client
            .delete(format!("{}/credentials/{}", self.base_url, credential_id))
            .header("X-Session-ID", &config.session_id)
            .send()
            .await?;

        if response.status().is_success() {
            println!("Credential '{}' removed", name);
            Ok(())
        } else {
            bail!("Failed to remove credential: {}", response.status())
        }
    }

    async fn set_default_credential(&self, id: &str) -> Result<()> {
        let config = self.ensure_authenticated().await?;

        let credential_id = uuid::Uuid::parse_str(id)
            .context("Invalid credential ID - must be a valid UUID")?;

        let response = self.client
            .post(format!("{}/credentials/{}/default", self.base_url, credential_id))
            .header("X-Session-ID", &config.session_id)
            .send()
            .await?;

        if response.status().is_success() {
            println!("Credential set as default");
            Ok(())
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            bail!("Credential '{}' not found", id)
        } else {
            bail!("Failed to set default: {}", response.status())
        }
    }
}

struct AssertionResult {
    credential_id: String,
    response_json: Vec<u8>,
}

pub async fn run() -> Result<()> {
    let cli = Cli::parse();

    log_verbose(cli.verbose, "API CLI v0.1.0");
    log_verbose(cli.verbose, &format!("Gateway URL: {}", cli.url));
    log_verbose(cli.verbose, &format!("Command: {:?}", cli.command));

    if let Err(e) = check_dependencies(cli.verbose) {
        eprintln!("Dependency check failed: {}", e);
        return Err(e);
    }

    match &cli.command {
        Commands::Register { .. } | Commands::Login => {
            if let Err(e) = check_gateway_connectivity(&cli.url, cli.verbose).await {
                eprintln!("Pre-flight check failed");
                return Err(e);
            }
        }
        _ => {}
    }

    log_verbose(cli.verbose, "Initializing API client...");
    let client = ApiClient::new(&cli.url, cli.verbose).context("Failed to initialize API client")?;
    log_verbose(cli.verbose, "API client ready");

    match cli.command {
        Commands::Register { beta_code } => {
            client.register(&beta_code).await?;
        }
        Commands::Login => {
            client.login().await?;
        }
        Commands::Init { managed_on_prem, config } => {
            client.init(managed_on_prem, config).await?;
        }
        Commands::Verify { attestation_url, from_local, app_source_url, pcrs, no_cache } => {
            client.verify(attestation_url, from_local, app_source_url, pcrs, no_cache).await?;
        }
        Commands::Apps { command } => {
            match command {
                AppCommands::Create => {
                    client.create_app().await?;
                }
                AppCommands::List => {
                    client.list_apps().await?;
                }
                AppCommands::Get { id } => {
                    client.get_app(id).await?;
                }
                AppCommands::Destroy { id, force, force_delete } => {
                    client.destroy_app(id, force, force_delete).await?;
                }
                AppCommands::Build { no_cache } => {
                    client.build_local(no_cache).await?;
                }
                AppCommands::Rename { name, id } => {
                    client.rename_app(id, name).await?;
                }
            }
        }
        Commands::SshKeys { command } => {
            match command {
                SshKeyCommands::Add { key_file, from_agent, key, name } => {
                    client.add_ssh_key(key_file, from_agent, key, name).await?;
                }
                SshKeyCommands::List => {
                    client.list_ssh_keys().await?;
                }
                SshKeyCommands::Remove { fingerprint } => {
                    client.remove_ssh_key(&fingerprint).await?;
                }
            }
        }
        Commands::Cache { command } => {
            match command {
                CacheCommands::Path => {
                    client.cache_path()?;
                }
                CacheCommands::Size => {
                    client.cache_size()?;
                }
                CacheCommands::List => {
                    client.cache_list()?;
                }
                CacheCommands::Destroy { force } => {
                    client.cache_destroy(force)?;
                }
            }
        }
        Commands::Credentials { command } => {
            match command {
                CredentialCommands::Add { platform, name, default, region } => {
                    client.add_credential(platform, name, default, region).await?;
                }
                CredentialCommands::List => {
                    client.list_credentials().await?;
                }
                CredentialCommands::Remove { id, force } => {
                    client.remove_credential(&id, force).await?;
                }
                CredentialCommands::SetDefault { id } => {
                    client.set_default_credential(&id).await?;
                }
            }
        }
    }

    Ok(())
}
