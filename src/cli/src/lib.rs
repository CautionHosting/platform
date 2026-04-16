// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result, bail};
use authenticator::{
    Pin, RegisterResult, SignResult, StatusPinUv, StatusUpdate,
    authenticatorservice::{AuthenticatorService, RegisterArgs, SignArgs},
    crypto::COSEAlgorithm,
    ctap2::server::{
        PublicKeyCredentialDescriptor, PublicKeyCredentialParameters,
        PublicKeyCredentialUserEntity, RelyingParty, Transport,
    },
    errors::AuthenticatorError,
    statecallback::StateCallback,
};
use base64::{Engine as _, engine::general_purpose};
use bootproof_sdk::{
    VerifiableSignedAttestationFormat,
    format::nitro::{Nitro, NitroPcrs},
};
use clap::{Parser, Subcommand};
use enclave_builder::{BuildConfig, build_user_image};
use reqwest;
use serde::{Deserialize, Serialize};
use serde_cbor;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc::channel;
use std::time::Duration;

mod loader;
use loader::{Loader, LoaderStyle};

mod attestation;

fn prompt_for_pin() -> Result<Option<String>> {
    let pin = rpassword::prompt_password(
        "Enter your security key PIN (or press Enter if no PIN is set): ",
    )?;

    if pin.trim().is_empty() {
        Ok(None)
    } else {
        Ok(Some(pin))
    }
}

/// Wrapper that zeroizes the PIN string on drop.
struct ZeroizePin(String);

impl Drop for ZeroizePin {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
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

fn ssh_fingerprint(key: &str) -> String {
    let parts: Vec<&str> = key.split_whitespace().collect();
    parts
        .get(1)
        .and_then(|key_data| general_purpose::STANDARD.decode(key_data).ok())
        .map(|decoded| {
            format!(
                "SHA256:{}",
                general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(&decoded))
            )
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn render_qr_code(url: &str) -> Result<()> {
    use qrcode::{EcLevel, QrCode};

    let code = QrCode::with_error_correction_level(url.as_bytes(), EcLevel::L)
        .context("Failed to generate QR code")?;
    let modules = code.to_colors();
    let width = code.width();
    let height = modules.len() / width;

    // Quiet zone: 1 module each side (minimal but sufficient for scanning)
    let quiet = 1;
    let total_width = width + quiet * 2;
    let total_height = height + quiet * 2;

    // Inverted rendering for dark terminal backgrounds:
    // dark module = space (blends with background), light module = █
    // Half-block chars pack 2 rows per terminal line
    let is_dark = |row: usize, col: usize| -> bool {
        if row < quiet || row >= quiet + height || col < quiet || col >= quiet + width {
            false
        } else {
            modules[(row - quiet) * width + (col - quiet)] == qrcode::types::Color::Dark
        }
    };

    let mut row = 0;
    while row < total_height {
        let mut line = String::new();
        for col in 0..total_width {
            let top = is_dark(row, col);
            let bottom = if row + 1 < total_height {
                is_dark(row + 1, col)
            } else {
                false
            };

            match (top, bottom) {
                (true, true) => line.push(' '),
                (true, false) => line.push('▄'),
                (false, true) => line.push('▀'),
                (false, false) => line.push('█'),
            }
        }
        println!("{}", line);
        row += 2;
    }

    Ok(())
}

fn check_dependencies(verbose: bool) -> Result<()> {
    log_verbose(verbose, "Checking dependencies...");

    let usb_dev_path = std::path::Path::new("/dev/bus/usb");
    if !usb_dev_path.exists() {
        log_verbose(
            verbose,
            "Warning: /dev/bus/usb not found - USB access may not work",
        );
    } else {
        log_verbose(verbose, "USB device access available");
    }

    log_verbose(verbose, "FIDO2 authenticator library loaded");

    Ok(())
}

async fn check_gateway_connectivity(url: &str, verbose: bool) -> Result<()> {
    log_verbose(
        verbose,
        &format!("Testing connectivity to gateway: {}", url),
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    // Just verify we can reach the gateway base URL
    log_verbose(verbose, &format!("HEAD {}", url));

    match client.head(url).send().await {
        Ok(resp) => {
            log_verbose(
                verbose,
                &format!("Gateway reachable (status: {})", resp.status()),
            );
            Ok(())
        }
        Err(e) => {
            log_verbose(verbose, &format!("HEAD request failed (this is ok): {}", e));
            log_verbose(
                verbose,
                "Skipping connectivity check, will test during auth",
            );
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

    #[arg(
        short,
        long,
        default_value = "https://alpha.caution.co",
        env = "CAUTION_BACKEND_URL",
        help = "Caution API server URL",
        global = true
    )]
    url: String,

    #[arg(short, long, help = "Enable verbose output")]
    verbose: bool,

    #[arg(
        long,
        global = true,
        help = "Use QR code for cross-device FIDO2 signing (no local security key needed)"
    )]
    qr: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(about = "Register a new account")]
    Register {
        #[arg(long)]
        alpha_code: String,
    },
    #[command(about = "Login to your Caution account")]
    Login {
        #[arg(
            long,
            help = "Use QR code for cross-device authentication (no local security key needed)"
        )]
        qr: bool,
    },
    #[command(about = "Logout and clear local session")]
    Logout,
    #[command(about = "Initialize a new deployment in the current directory")]
    Init {
        #[arg(long, help = "Set up managed on-premises deployment")]
        managed_on_prem: bool,
        #[arg(
            long,
            requires = "managed_on_prem",
            help = "Cloud platform (default: aws)",
            default_value = "aws"
        )]
        platform: String,
        #[arg(long, help = "App name (default: current directory name)")]
        name: Option<String>,
        #[arg(
            long,
            requires = "managed_on_prem",
            help = "AWS region (default: us-west-2)"
        )]
        region: Option<String>,
        #[arg(
            long,
            requires = "managed_on_prem",
            help = "Use local provisioner image (skip docker pull)"
        )]
        local: bool,
        #[arg(
            long,
            requires = "managed_on_prem",
            help = "Path to encrypted credentials file from manual Docker setup"
        )]
        config: Option<PathBuf>,
    },
    #[command(about = "Tear down a managed on-premises deployment")]
    Teardown {
        #[arg(long, help = "Tear down managed on-premises infrastructure")]
        managed_on_prem: bool,
        #[arg(long, help = "Cloud platform (default: aws)", default_value = "aws")]
        platform: String,
        #[arg(short, long, help = "Skip confirmation prompt")]
        force: bool,
    },
    #[command(
        about = "Verify enclave attestation. By default, fetches manifest from the remote enclave and reproduces the build."
    )]
    Verify {
        #[arg(
            long,
            help = "Attestation endpoint URL (default: inferred from .caution/deployment)"
        )]
        attestation_url: Option<String>,
        #[arg(long, help = "Build from current directory instead of remote manifest")]
        from_local: bool,
        #[arg(long, help = "Git URL to fetch application source")]
        app_source_url: Option<String>,
        #[arg(long, help = "Compare against PCRs from file instead of building")]
        pcrs: Option<String>,
        #[arg(long, help = "Force rebuild, ignore cache")]
        no_cache: bool,
        #[arg(
            long,
            help = "Save verified PCR hashes to .caution/trusted_hashes.json for use by send-shard"
        )]
        save_pcrs: bool,
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
    #[command(about = "Manage cryptographic secrets")]
    Secret {
        #[command(subcommand)]
        command: SecretCommands,
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
        #[arg(
            long,
            help = "Force delete from database even if cloud resource cleanup fails"
        )]
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

#[derive(Subcommand, Debug)]
enum SecretCommands {
    #[command(about = "Generate a new cryptographic quorum")]
    New {
        #[arg(help = "Path to armored PGP keyring file")]
        keyring: PathBuf,
        #[arg(long, requires = "max", help = "Minimum shares needed to reconstruct")]
        threshold: Option<u8>,
        #[arg(
            long,
            requires = "threshold",
            help = "Total number of shares to generate"
        )]
        max: Option<u8>,
        #[arg(long, help = "Skip uploading bundle to Caution")]
        no_upload: bool,
        #[arg(long, help = "Name for the quorum bundle")]
        name: Option<String>,
        #[arg(
            long = "label",
            help = "Label in key=value format (can be repeated)",
            value_name = "KEY=VALUE"
        )]
        labels: Vec<String>,
    },
    #[command(about = "Rename a quorum bundle")]
    Rename {
        #[arg(help = "Bundle ID")]
        id: String,
        #[arg(help = "New name")]
        name: String,
    },
    #[command(about = "Manage labels on a quorum bundle")]
    Label {
        #[command(subcommand)]
        command: LabelCommands,
    },
    #[command(about = "Send a shard to a running enclave's locksmith daemon")]
    SendShard {
        #[arg(
            long,
            help = "App ID or resource name (defaults to current deployment)"
        )]
        app: Option<String>,
        #[arg(long, help = "Path to quorum bundle JSON file")]
        bundle: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum LabelCommands {
    #[command(about = "Set labels on a quorum bundle")]
    Set {
        #[arg(help = "Bundle ID")]
        id: String,
        #[arg(help = "Labels in key=value format", required = true)]
        labels: Vec<String>,
    },
    #[command(about = "Remove labels from a quorum bundle")]
    Remove {
        #[arg(help = "Bundle ID")]
        id: String,
        #[arg(help = "Label keys to remove", required = true)]
        keys: Vec<String>,
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
    id: String,
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
    alg: i32,
}

#[derive(Deserialize)]
struct LoginFinishResponse {
    expires_at: String,
}

#[derive(Deserialize)]
struct QrLoginBeginResponse {
    token: String,
    url: String,
    #[allow(dead_code)]
    expires_at: String,
}

#[derive(Deserialize)]
struct QrLoginStatusResponse {
    status: String,
    session_id: Option<String>,
    expires_at: Option<String>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct QrSignBeginResponse {
    challenge_id: String,
    token: String,
    url: String,
    expires_at: String,
}

#[derive(Deserialize)]
struct QrSignStatusResponse {
    status: String,
    fido2_response: Option<String>,
    challenge_id: Option<String>,
}

/// Extract session ID from Set-Cookie header
fn extract_session_from_cookies(response: &reqwest::Response) -> Option<String> {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|s| s.starts_with("caution_session="))
        .and_then(|cookie| {
            // Parse "caution_session=VALUE; path=/; ..."
            cookie
                .strip_prefix("caution_session=")
                .and_then(|rest| rest.split(';').next())
                .map(|s| s.to_string())
        })
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

#[derive(Deserialize)]
struct OrgSettings {
    require_pin: bool,
}

#[derive(Deserialize)]
struct Organization {
    id: String,
}

#[derive(Debug, Deserialize)]
struct LegalAcceptanceRequiredError {
    code: String,
    document_type: String,
    message: Option<String>,
}

struct ApiClient {
    base_url: String,
    client: reqwest::Client,
    config_path: PathBuf,
    deployment_path: Option<PathBuf>,
    verbose: bool,
    qr: bool,
}

impl ApiClient {
    fn new(base_url: &str, verbose: bool, qr: bool) -> Result<Self> {
        log_verbose(verbose, "Initializing API client...");

        let config_dir = dirs::config_dir()
            .context("Could not find config directory")?
            .join("api-cli");

        log_verbose(verbose, &format!("Config directory: {:?}", config_dir));

        fs::create_dir_all(&config_dir).context("Failed to create config directory")?;
        let config_path = config_dir.join("config.json");

        // Local deployment info in the current git repo (optional - may not have a valid cwd)
        let deployment_path = std::env::current_dir().ok().map(|current_dir| {
            let caution_dir = current_dir.join(".caution");
            // Try to create the directory, but don't fail if we can't
            let _ = fs::create_dir_all(&caution_dir);
            caution_dir.join("deployment.json")
        });

        log_verbose(verbose, &format!("Config file: {:?}", config_path));
        log_verbose(verbose, &format!("Deployment file: {:?}", deployment_path));
        log_verbose(verbose, "API client initialized");

        Ok(Self {
            base_url: base_url.to_string(),
            client: reqwest::Client::new(),
            config_path,
            deployment_path,
            verbose,
            qr,
        })
    }

    /// Get deployment path, creating .caution directory if needed
    fn get_deployment_path(&self) -> Result<&PathBuf> {
        self.deployment_path.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "Cannot access current directory. Please run this command from a valid directory."
            )
        })
    }

    fn frontend_url(&self) -> String {
        std::env::var("FRONTEND_URL").unwrap_or_else(|_| self.base_url.clone())
    }

    fn legal_document_label(document_type: &str) -> &'static str {
        match document_type {
            "terms_of_service" => "Terms of Service",
            "privacy_notice" => "Privacy Notice",
            _ => "legal document",
        }
    }

    fn legal_acceptance_message(&self, document_type: &str) -> String {
        let frontend_url = self.frontend_url().trim_end_matches('/').to_string();
        let document_label = Self::legal_document_label(document_type);

        format!(
            "You need to accept updated legal documents before continuing.\nRequired: {}\nOpen the Caution web app and accept the update:\n  {}/dashboard",
            document_label, frontend_url
        )
    }

    async fn api_error_message(&self, response: reqwest::Response) -> String {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        if status == reqwest::StatusCode::FORBIDDEN {
            if let Ok(payload) = serde_json::from_str::<LegalAcceptanceRequiredError>(&body) {
                if payload.code == "legal_acceptance_required" {
                    let mut message = self.legal_acceptance_message(&payload.document_type);
                    if let Some(server_message) = payload.message {
                        if !server_message.trim().is_empty() {
                            message.push_str("\n\n");
                            message.push_str(server_message.trim());
                        }
                    }
                    return message;
                }
            }
        }

        if body.trim().is_empty() {
            format!("HTTP {}", status)
        } else {
            body
        }
    }

    fn save_config(&self, session_id: String, expires_at: String) -> Result<()> {
        let config = Config {
            session_id,
            expires_at,
            server_url: Some(self.base_url.clone()),
        };

        let json = serde_json::to_string_pretty(&config)?;

        // Write with restricted permissions so other users cannot read session tokens
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&self.config_path)?;
            file.write_all(json.as_bytes())?;
        }

        Ok(())
    }

    fn load_config(&self) -> Result<Config> {
        let content = fs::read_to_string(&self.config_path)
            .context("Not logged in. Run 'login' command first")?;
        let config: Config = serde_json::from_str(&content)?;
        Ok(config)
    }

    fn is_session_expired(&self, config: &Config) -> bool {
        use chrono::{DateTime, NaiveDateTime, Utc};

        if let Ok(expires) = DateTime::parse_from_rfc3339(&config.expires_at) {
            return Utc::now() >= expires.with_timezone(&Utc);
        }

        if let Ok(naive) = NaiveDateTime::parse_from_str(&config.expires_at, "%Y-%m-%dT%H:%M:%S%.f")
        {
            return Utc::now() >= naive.and_utc();
        }

        let timestamp_part = config
            .expires_at
            .split(" +")
            .next()
            .unwrap_or(&config.expires_at);
        if let Ok(naive) = NaiveDateTime::parse_from_str(timestamp_part, "%Y-%m-%d %H:%M:%S%.f") {
            return Utc::now() >= naive.and_utc();
        }

        true
    }

    async fn ensure_authenticated(&self) -> Result<Config> {
        match self.load_config() {
            Ok(config) if !self.is_session_expired(&config) && self.is_same_server(&config) => {
                Ok(config)
            }
            _ => {
                if self.qr {
                    self.login_qr().await?;
                } else {
                    self.login().await?;
                }
                self.load_config()
            }
        }
    }

    fn is_same_server(&self, config: &Config) -> bool {
        config
            .server_url
            .as_ref()
            .map_or(true, |url| url == &self.base_url)
    }

    fn save_deployment(&self, resource_id: &str) -> Result<()> {
        let deployment_path = self.get_deployment_path()?;
        let deployment_info = DeploymentInfo {
            resource_id: resource_id.to_string(),
        };
        let json = serde_json::to_string_pretty(&deployment_info)?;
        fs::write(deployment_path, json)?;
        log_verbose(
            self.verbose,
            &format!("Saved deployment info to {:?}", deployment_path),
        );
        Ok(())
    }

    fn load_deployment(&self) -> Result<DeploymentInfo> {
        let deployment_path = self.get_deployment_path()?;
        let content =
            fs::read_to_string(deployment_path).context("No deployment found. Run 'init' first")?;
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

        let content = fs::read_to_string(&procfile_path).context("Failed to read Procfile")?;

        // Parse the Procfile to find the build command
        for line in content.lines() {
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(build_cmd) = line.strip_prefix("build:") {
                let cmd = build_cmd.trim();
                if cmd.is_empty() {
                    bail!(
                        "Procfile has empty build command. Expected format: build: docker build -t myapp ."
                    );
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
            Some(ports_str) => ports_str
                .split(',')
                .filter_map(|s| s.trim().parse::<u16>().ok())
                .collect(),
            None => vec![8080], // Default port
        }
    }

    fn read_procfile_http_port(&self) -> Option<u16> {
        self.read_procfile_field("http_port")
            .and_then(|s| s.trim().parse::<u16>().ok())
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

        let source_line = self
            .detect_source_url()
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

        let procfile_content = format!(
            r#"# Caution Procfile - https://docs.caution.co/reference/procfile/

# Build configuration
run: /app/myapp
build: docker build -t app .
# containerfile: Containerfile
# oci_tarball: image.tar
# binary: /app/myapp  # extracts only this binary, not the full container filesystem

# Source verification
{source_line}
# enclave_sources: https://codeberg.org/caution/enclave
# metadata:

# Resource allocation
# memory: 512
# cpus: 2

# Features
# domain: app.example.com
# ports: 8083
# http_port: 8083
# e2e: false
# locksmith: false
# debug: false
# no_cache: false
# ssh_keys: ssh-ed25519 AAAA...
{managed_on_prem_section}"#
        );

        fs::write(procfile_path, procfile_content).context("Failed to create Procfile")?;

        println!("\nCreated Procfile in current directory");
        println!("Edit the required 'run' field to match your application");
        if managed_on_prem {
            println!("Configure AWS deployment settings in the managed_on_prem section");
        }
        println!("Learn more: https://docs.caution.co/reference/procfile/");

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
            format!(
                "https://{}/{}/-/archive/${{COMMIT}}/{}-${{COMMIT}}.tar.gz",
                host, path, repo_name
            )
        } else {
            format!("https://{}/{}/archive/${{COMMIT}}.tar.gz", host, path)
        }
    }

    fn git_url_to_archive_urls(&self, git_url: &str, commit: &str) -> Result<Vec<String>> {
        // If the URL is already a direct archive URL, use it as-is
        if git_url.contains("/archive/")
            && (git_url.ends_with(".tar.gz") || git_url.ends_with(".tar"))
        {
            return Ok(vec![git_url.to_string()]);
        }

        let (host, path) = if git_url.starts_with("git@") {
            let without_prefix = git_url
                .strip_prefix("git@")
                .ok_or_else(|| anyhow::anyhow!("Invalid git URL format"))?;
            let (host, path) = without_prefix
                .split_once(':')
                .ok_or_else(|| anyhow::anyhow!("Invalid git SSH URL format"))?;
            (host.to_string(), path.trim_end_matches(".git").to_string())
        } else if git_url.starts_with("https://") || git_url.starts_with("http://") {
            let url = url::Url::parse(git_url).context("Failed to parse git URL")?;
            let host = url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("Git URL has no host"))?
                .to_string();
            let path = url
                .path()
                .trim_start_matches('/')
                .trim_end_matches(".git")
                .to_string();
            (host, path)
        } else {
            bail!("Unsupported git URL format: {}", git_url);
        };

        let repo_name = path.rsplit('/').next().unwrap_or("repo");

        Ok(vec![
            format!("http://{}/{}/archive/{}.tar.gz", host, path, commit),
            format!("https://{}/{}/archive/{}.tar.gz", host, path, commit),
            format!(
                "http://{}/{}/-/archive/{}/{}-{}.tar.gz",
                host, path, commit, repo_name, commit
            ),
            format!(
                "https://{}/{}/-/archive/{}/{}-{}.tar.gz",
                host, path, commit, repo_name, commit
            ),
            format!("http://{}/{}/get/{}.tar.gz", host, path, commit),
            format!("https://{}/{}/get/{}.tar.gz", host, path, commit),
        ])
    }

    async fn register(&self, alpha_code: &str) -> Result<()> {
        log_verbose(self.verbose, "Starting FIDO2 registration...");
        log_verbose(self.verbose, &format!("Target URL: {}", self.base_url));

        let cookie_store = reqwest::cookie::Jar::default();
        let client = reqwest::Client::builder()
            .cookie_provider(std::sync::Arc::new(cookie_store))
            .build()?;

        log_verbose(
            self.verbose,
            "Sending registration begin request with alpha code...",
        );
        let response = client
            .post(format!("{}/auth/register/begin", self.base_url))
            .json(&serde_json::json!({ "alpha_code": alpha_code }))
            .send()
            .await
            .context("Failed to send registration begin request")?;

        log_verbose(
            self.verbose,
            &format!("Response status: {}", response.status()),
        );

        if !response.status().is_success() {
            let error = response.text().await?;
            bail!("Registration begin failed: {}", error);
        }

        let begin_resp: RegisterBeginResponse = response
            .json()
            .await
            .context("Failed to parse registration begin response")?;
        log_verbose(self.verbose, "Registration challenge received");
        log_verbose(
            self.verbose,
            &format!("Challenge: {}", begin_resp.public_key.challenge),
        );

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

        log_verbose(
            self.verbose,
            &format!("Response status: {}", response.status()),
        );

        if response.status().is_success() {
            // Extract session from Set-Cookie header (not response body)
            let session_id = extract_session_from_cookies(&response)
                .ok_or_else(|| anyhow::anyhow!("No session cookie in response"))?;

            let finish_resp: RegisterFinishResponse = response.json().await?;

            println!("\nFIDO2 registration successful!");
            println!("\nYou are now logged in:");
            println!("Expires: {}", finish_resp.expires_at);

            self.save_config(session_id.clone(), finish_resp.expires_at.clone())?;

            println!("\n=======================================================");
            println!("ALPHA ACCESS GRANTED");
            println!("=======================================================");
            println!("\nYou're registered as an alpha user. You can now:");
            println!("  • Create apps with 'caution init'");
            println!("  • Deploy with 'git push caution main'");
            println!("\nDashboard: {}/dashboard", self.frontend_url());
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
        println!("Login successful");

        match self.check_onboarding_status(&session_id).await {
            Ok(status) => {
                if !status.onboarding_complete {
                    println!("\n=======================================================");
                    println!("COMPLETE YOUR ONBOARDING");
                    println!("=======================================================");
                    println!("\nYou need to complete onboarding to use this service:");
                    println!(
                        "  1. Verify your email address {}",
                        if status.email_verified { "✓" } else { "✗" }
                    );
                    println!(
                        "  2. Add payment information {}",
                        if status.payment_method_added {
                            "✓"
                        } else {
                            "✗"
                        }
                    );
                    println!("\nOnboarding URL:");
                    println!("  {}/onboarding", self.frontend_url());
                    println!("\nYou must complete onboarding before you can create apps.");
                    println!("=======================================================\n");
                }
            }
            Err(e) => {
                log_verbose(
                    self.verbose,
                    &format!("Could not check onboarding status: {}", e),
                );
            }
        }

        // Check if PIN requirement is disabled and warn the user
        match self.check_org_security_settings(&session_id).await {
            Ok(settings) => {
                if !settings.require_pin {
                    println!("\n⚠️  WARNING: PIN verification is disabled for your organization.");
                    println!("   For production use, enable PIN requirement.");
                }
            }
            Err(e) => {
                log_verbose(
                    self.verbose,
                    &format!("Could not check security settings: {}", e),
                );
            }
        }

        Ok(())
    }

    async fn login_qr(&self) -> Result<()> {
        log_verbose(self.verbose, "Starting QR code cross-device login...");

        // Step 1: Request a QR login token from the gateway
        let response = self
            .client
            .post(format!("{}/auth/qr-login/begin", self.base_url))
            .send()
            .await?;

        if !response.status().is_success() {
            let error = response.text().await?;
            bail!("Failed to start QR login: {}", error);
        }

        let begin_resp: QrLoginBeginResponse = response.json().await?;
        log_verbose(self.verbose, &format!("QR token: {}", begin_resp.token));
        log_verbose(self.verbose, &format!("QR URL: {}", begin_resp.url));

        // Step 2: Render the QR code in the terminal
        println!();
        render_qr_code(&begin_resp.url)?;
        println!();
        println!("Scan the QR code with your phone, or open this URL:");
        println!("  {}", begin_resp.url);
        println!();

        // Step 3: Poll for completion
        let mut loader = Loader::new("Waiting for authentication...", LoaderStyle::Processing);

        let poll_result = async {
            let timeout = Duration::from_secs(180); // 3 minutes
            let start = std::time::Instant::now();

            loop {
                if start.elapsed() > timeout {
                    bail!("QR login timed out. Please try again.");
                }

                tokio::time::sleep(Duration::from_secs(2)).await;

                let status_resp = self
                    .client
                    .get(format!("{}/auth/qr-login/status", self.base_url))
                    .query(&[("token", &begin_resp.token)])
                    .send()
                    .await?;

                if !status_resp.status().is_success() {
                    log_verbose(self.verbose, "Status poll failed, retrying...");
                    continue;
                }

                let status: QrLoginStatusResponse = status_resp.json().await?;
                log_verbose(self.verbose, &format!("Poll status: {}", status.status));

                match status.status.as_str() {
                    "completed" => {
                        let session_id = status.session_id.ok_or_else(|| {
                            anyhow::anyhow!("Completed but no session_id returned")
                        })?;
                        let expires_at = status.expires_at.ok_or_else(|| {
                            anyhow::anyhow!("Completed but no expires_at returned")
                        })?;

                        self.save_config(session_id.clone(), expires_at)?;
                        return Ok(session_id);
                    }
                    "expired" => {
                        bail!("QR login token expired. Please try again.");
                    }
                    // "pending" or "authenticated" — keep polling
                    _ => continue,
                }
            }
        }
        .await;

        loader.stop();

        let session_id = poll_result?;
        println!("Login successful");

        match self.check_org_security_settings(&session_id).await {
            Ok(settings) => {
                if !settings.require_pin {
                    println!("\n⚠️  WARNING: PIN verification is disabled for your organization.");
                    println!("   For production use, enable PIN requirement.");
                }
            }
            Err(e) => {
                log_verbose(
                    self.verbose,
                    &format!("Could not check security settings: {}", e),
                );
            }
        }

        Ok(())
    }

    async fn logout(&self) -> Result<()> {
        // Try to invalidate session on server if we have a config
        if let Ok(config) = self.load_config() {
            log_verbose(self.verbose, "Invalidating session on server...");
            match self
                .client
                .post(format!("{}/auth/logout", self.base_url))
                .header("X-Session-ID", &config.session_id)
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    log_verbose(self.verbose, "Session invalidated on server");
                }
                Ok(response) => {
                    log_verbose(
                        self.verbose,
                        &format!("Server returned {}", response.status()),
                    );
                }
                Err(e) => {
                    log_verbose(self.verbose, &format!("Could not reach server: {}", e));
                }
            }
        }

        // Delete local config
        if self.config_path.exists() {
            std::fs::remove_file(&self.config_path)?;
            println!("Logged out successfully");
        } else {
            println!("Not logged in");
        }

        Ok(())
    }

    async fn check_onboarding_status(&self, session_id: &str) -> Result<UserStatus> {
        let response = self
            .client
            .get(format!("{}/api/user/status", self.base_url))
            .header("X-Session-ID", session_id)
            .send()
            .await?;

        if !response.status().is_success() {
            let error = self.api_error_message(response).await;
            bail!("Failed to get user status: {}", error);
        }

        let status: UserStatus = response.json().await?;
        Ok(status)
    }

    async fn check_org_security_settings(&self, session_id: &str) -> Result<OrgSettings> {
        // Get the user's organizations
        let orgs_response = self
            .client
            .get(format!("{}/api/organizations", self.base_url))
            .header("X-Session-ID", session_id)
            .send()
            .await?;

        if !orgs_response.status().is_success() {
            let error = self.api_error_message(orgs_response).await;
            bail!("Failed to get organizations: {}", error);
        }

        let orgs: Vec<Organization> = orgs_response.json().await?;
        if orgs.is_empty() {
            bail!("No organizations found");
        }

        // Get the first org's settings
        let settings_response = self
            .client
            .get(format!(
                "{}/api/organizations/{}/settings",
                self.base_url, orgs[0].id
            ))
            .header("X-Session-ID", session_id)
            .send()
            .await?;

        if !settings_response.status().is_success() {
            let error = self.api_error_message(settings_response).await;
            bail!("Failed to get security settings: {}", error);
        }

        let settings: OrgSettings = settings_response.json().await?;
        Ok(settings)
    }

    fn make_credential(
        &self,
        options: &RegisterBeginResponse,
        base_url: &str,
    ) -> Result<serde_json::Value> {
        log_verbose(self.verbose, "Attempting registration without PIN first...");
        match self.try_make_credential(options, base_url, None) {
            Ok(result) => {
                log_verbose(self.verbose, "Registration succeeded without PIN");
                Ok(result)
            }
            Err(e) => {
                log_verbose(self.verbose, &format!("First attempt failed: {:?}", e));
                log_verbose(self.verbose, &format!("Full error details: {:#?}", e));

                // Only ask for PIN if the error is PIN-related
                if is_pin_related_error(&e) {
                    println!("Your security key requires a PIN.");
                    match prompt_for_pin()? {
                        Some(pin_string) => {
                            let pin_string = ZeroizePin(pin_string);
                            let pin = Pin::new(&pin_string.0);
                            log_verbose(self.verbose, "Retrying registration with PIN...");
                            self.try_make_credential(options, base_url, Some(pin))
                        }
                        None => {
                            log_verbose(self.verbose, "No PIN provided, returning original error");
                            Err(e)
                        }
                    }
                } else {
                    // Not a PIN error, return the original error
                    log_verbose(
                        self.verbose,
                        "Error is not PIN-related, not prompting for PIN",
                    );
                    Err(e)
                }
            }
        }
    }

    fn try_make_credential(
        &self,
        options: &RegisterBeginResponse,
        base_url: &str,
        pin: Option<Pin>,
    ) -> Result<serde_json::Value> {
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
            .filter_map(|p| match p.alg {
                -7 => Some(PublicKeyCredentialParameters {
                    alg: COSEAlgorithm::ES256,
                }),
                -257 => Some(PublicKeyCredentialParameters {
                    alg: COSEAlgorithm::RS256,
                }),
                _ => None,
            })
            .collect();

        log_verbose(
            self.verbose,
            &format!("pub_key_params count: {}", pub_key_params.len()),
        );
        log_verbose(
            self.verbose,
            &format!("timeout from server: {} ms", opts.timeout),
        );

        let mut manager =
            AuthenticatorService::new().context("Failed to create authenticator service")?;

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
            }))?)
            .into(),
            relying_party: rp,
            origin: base_url.to_string(),
            user,
            pub_cred_params: pub_key_params,
            exclude_list: vec![],
            user_verification_req:
                authenticator::ctap2::server::UserVerificationRequirement::Preferred,
            resident_key_req: authenticator::ctap2::server::ResidentKeyRequirement::Required,
            extensions: Default::default(),
            pin,
            use_ctap1_fallback: false,
        };

        log_verbose(self.verbose, "Sending register request to authenticator...");
        manager
            .register(opts.timeout, args, status_tx, callback)
            .context("Failed to start registration")?;

        log_verbose(
            self.verbose,
            "Waiting for callback result (up to 60 seconds)...",
        );

        let mut loader = Loader::new("Tap your security key to continue", LoaderStyle::KeyTap);

        loop {
            // Check for status updates
            while let Ok(status) = status_rx.try_recv() {
                match status {
                    StatusUpdate::SelectResultNotice(sender, users) => {
                        loader.stop();
                        println!("Multiple credentials found. Please select one:");
                        for (idx, user) in users.iter().enumerate() {
                            let display = user
                                .display_name
                                .as_deref()
                                .or(user.name.as_deref())
                                .unwrap_or("Unknown");
                            println!("[{}] {}", idx, display);
                        }

                        use std::io::{self, Write};
                        print!("Enter selection (0-{}): ", users.len() - 1);
                        io::stdout().flush()?;

                        let mut input = String::new();
                        io::stdin().read_line(&mut input)?;
                        let selection: usize = input.trim().parse().context("Invalid selection")?;

                        if selection >= users.len() {
                            bail!("Selection out of range");
                        }

                        println!(
                            "Selected: {}",
                            users[selection].name.as_deref().unwrap_or("Unknown")
                        );
                        sender
                            .send(Some(selection))
                            .context("Failed to send selection")?;
                    }
                    StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender)) => {
                        loader.stop();
                        log_verbose(self.verbose, "PIN required by authenticator");
                        match prompt_for_pin()? {
                            Some(pin_string) => {
                                let pin = Pin::new(&pin_string);
                                sender.send(pin).context("Failed to send PIN")?;
                                loader = Loader::new(
                                    "Tap your security key to continue",
                                    LoaderStyle::KeyTap,
                                );
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
                    bail!(
                        "Invalid authenticator data length: {}",
                        auth_data_bytes.len()
                    );
                }

                let credential_id_len =
                    u16::from_be_bytes([auth_data_bytes[53], auth_data_bytes[54]]) as usize;

                let credential_id_start = 55;
                let credential_id_end = credential_id_start + credential_id_len;

                if auth_data_bytes.len() < credential_id_end {
                    bail!("Authenticator data too short for credential ID");
                }

                let credential_id = &auth_data_bytes[credential_id_start..credential_id_end];

                log_verbose(
                    self.verbose,
                    &format!("credential_id len: {}", credential_id.len()),
                );
                log_verbose(
                    self.verbose,
                    &format!("credential_id: {}", hex::encode(credential_id)),
                );

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
        log_verbose(
            self.verbose,
            &format!("Session from server: {:?}", begin_resp.session),
        );

        let assertion = self.get_assertion(&begin_resp, &self.base_url)?;

        println!("Assertion created");

        let mut credential: serde_json::Value = serde_json::from_slice(&assertion.response_json)?;

        log_verbose(self.verbose, "Credential before adding session:");
        log_verbose(self.verbose, &serde_json::to_string_pretty(&credential)?);

        if let Some(obj) = credential.as_object_mut() {
            obj.insert("session".to_string(), serde_json::json!(begin_resp.session));
        }

        log_verbose(
            self.verbose,
            "Final payload being sent to /auth/login/finish:",
        );
        log_verbose(self.verbose, &serde_json::to_string_pretty(&credential)?);

        let response = client
            .post(format!("{}/auth/login/finish", self.base_url))
            .json(&credential)
            .send()
            .await?;

        if response.status().is_success() {
            // Extract session from Set-Cookie header (not response body)
            let session_id = extract_session_from_cookies(&response)
                .ok_or_else(|| anyhow::anyhow!("No session cookie in response"))?;

            let finish_resp: LoginFinishResponse = response.json().await?;

            self.save_config(session_id.clone(), finish_resp.expires_at.clone())?;

            Ok((session_id, finish_resp.expires_at))
        } else {
            let status = response.status();
            let error = response.text().await?;
            log_verbose(
                self.verbose,
                &format!("Server error response (status {}): {}", status, error),
            );
            bail!("Login failed: {}", error)
        }
    }

    async fn signed_post<T: serde::Serialize>(
        &self,
        session_id: &str,
        path: &str,
        body: &T,
    ) -> Result<reqwest::Response> {
        if self.qr {
            return self.signed_post_qr(session_id, path, body).await;
        }

        let body_json = serde_json::to_vec(body)?;
        let body_hash = hex::encode(Sha256::digest(&body_json));

        // The gateway nests /api routes, so the sign middleware sees paths with /api stripped
        let challenge_path = path.strip_prefix("/api").unwrap_or(path);

        log_verbose(
            self.verbose,
            &format!("Requesting FIDO2 sign challenge for POST {}", path),
        );

        let sign_req = serde_json::json!({
            "method": "POST",
            "path": challenge_path,
            "body_hash": body_hash,
        });

        let response = self
            .client
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

        println!("\nData to be signed:");
        println!("{}", serde_json::to_string_pretty(body)?);
        println!("\nTap your security key to sign the request.");
        let assertion = self.get_assertion(&login_resp, &self.base_url)?;

        let fido_response_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&assertion.response_json);

        log_verbose(self.verbose, "Sending FIDO2-signed request");

        let response = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .header("X-Fido2-Challenge-Id", &sign_resp.challenge_id)
            .header("X-Fido2-Response", &fido_response_b64)
            .header("Content-Type", "application/json")
            .body(body_json)
            .send()
            .await?;

        Ok(response)
    }

    async fn signed_post_qr<T: serde::Serialize>(
        &self,
        session_id: &str,
        path: &str,
        body: &T,
    ) -> Result<reqwest::Response> {
        let body_json = serde_json::to_vec(body)?;
        let body_hash = hex::encode(Sha256::digest(&body_json));

        // The gateway nests /api routes, so the sign middleware sees paths with /api stripped
        let challenge_path = path.strip_prefix("/api").unwrap_or(path);

        log_verbose(self.verbose, "Starting QR code cross-device signing...");

        // Step 1: Request a QR sign token from the gateway
        let body_str = String::from_utf8_lossy(&body_json);
        let sign_req = serde_json::json!({
            "method": "POST",
            "path": challenge_path,
            "body": body_str,
            "body_hash": body_hash,
        });

        let response = self
            .client
            .post(format!("{}/auth/qr-sign/begin", self.base_url))
            .header("X-Session-ID", session_id)
            .json(&sign_req)
            .send()
            .await?;

        if !response.status().is_success() {
            let error = response.text().await?;
            bail!("Failed to start QR signing: {}", error);
        }

        let begin_resp: QrSignBeginResponse = response.json().await?;
        log_verbose(
            self.verbose,
            &format!("QR sign token: {}", begin_resp.token),
        );

        // Step 2: Render QR code
        println!();
        render_qr_code(&begin_resp.url)?;
        println!();
        println!("Scan the QR code with your phone to approve the operation, or open:");
        println!("  {}", begin_resp.url);
        println!();

        // Step 3: Poll for completion
        let mut loader = Loader::new("Waiting for approval...", LoaderStyle::Processing);

        let poll_result = async {
            let timeout = Duration::from_secs(180);
            let start = std::time::Instant::now();

            loop {
                if start.elapsed() > timeout {
                    bail!("QR signing timed out. Please try again.");
                }

                tokio::time::sleep(Duration::from_secs(2)).await;

                let status_resp = self
                    .client
                    .get(format!("{}/auth/qr-sign/status", self.base_url))
                    .query(&[("token", &begin_resp.token)])
                    .send()
                    .await?;

                if !status_resp.status().is_success() {
                    log_verbose(self.verbose, "Status poll failed, retrying...");
                    continue;
                }

                let status: QrSignStatusResponse = status_resp.json().await?;
                log_verbose(self.verbose, &format!("Poll status: {}", status.status));

                match status.status.as_str() {
                    "completed" => {
                        let fido2_response = status.fido2_response.ok_or_else(|| {
                            anyhow::anyhow!("Completed but no fido2_response returned")
                        })?;
                        let challenge_id = status.challenge_id.ok_or_else(|| {
                            anyhow::anyhow!("Completed but no challenge_id returned")
                        })?;
                        return Ok((fido2_response, challenge_id));
                    }
                    "expired" => {
                        bail!("QR signing token expired. Please try again.");
                    }
                    // "pending" or "authenticated" — keep polling
                    _ => continue,
                }
            }
        }
        .await;

        loader.stop();

        let (fido2_response, challenge_id) = poll_result?;
        log_verbose(self.verbose, "Sending QR-signed request");

        // Step 4: Send the actual request with the FIDO2 assertion from the phone
        let response = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .header("X-Fido2-Challenge-Id", &challenge_id)
            .header("X-Fido2-Response", &fido2_response)
            .header("Content-Type", "application/json")
            .body(body_json)
            .send()
            .await?;

        Ok(response)
    }

    fn get_assertion(
        &self,
        options: &LoginBeginResponse,
        base_url: &str,
    ) -> Result<AssertionResult> {
        log_verbose(self.verbose, "Attempting assertion without PIN first...");
        match self.try_get_assertion(options, base_url, None) {
            Ok(result) => {
                log_verbose(self.verbose, "Assertion succeeded without PIN");
                Ok(result)
            }
            Err(e) => {
                log_verbose(self.verbose, &format!("First attempt failed: {:?}", e));
                log_verbose(self.verbose, &format!("Full error details: {:#?}", e));

                // Only ask for PIN if the error is PIN-related
                if is_pin_related_error(&e) {
                    println!("Your security key requires a PIN.");
                    match prompt_for_pin()? {
                        Some(pin_string) => {
                            let pin_string = ZeroizePin(pin_string);
                            let pin = Pin::new(&pin_string.0);
                            log_verbose(self.verbose, "Retrying assertion with PIN...");
                            self.try_get_assertion(options, base_url, Some(pin))
                        }
                        None => {
                            log_verbose(self.verbose, "No PIN provided, returning original error");
                            Err(e)
                        }
                    }
                } else {
                    // Not a PIN error, return the original error
                    log_verbose(
                        self.verbose,
                        "Error is not PIN-related, not prompting for PIN",
                    );
                    Err(e)
                }
            }
        }
    }

    fn try_get_assertion(
        &self,
        options: &LoginBeginResponse,
        base_url: &str,
        pin: Option<Pin>,
    ) -> Result<AssertionResult> {
        let opts = &options.public_key;

        log_verbose(self.verbose, "Getting assertion from authenticator...");

        let challenge = general_purpose::URL_SAFE_NO_PAD
            .decode(&opts.challenge)
            .context("Failed to decode challenge")?;

        log_verbose(self.verbose, &format!("challenge bytes: {:?}", challenge));
        log_verbose(self.verbose, &format!("rpId: {}", opts.rp_id));

        let mut manager =
            AuthenticatorService::new().context("Failed to create authenticator service")?;

        manager.add_u2f_usb_hid_platform_transports();

        let (status_tx, status_rx) = channel::<StatusUpdate>();
        let (callback_tx, callback_rx) = channel::<Result<SignResult, AuthenticatorError>>();

        let callback = StateCallback::new(Box::new(move |result| {
            let _ = callback_tx.send(result);
        }));

        let allow_list: Vec<PublicKeyCredentialDescriptor> = opts
            .allow_credentials
            .iter()
            .filter_map(|cred| {
                general_purpose::URL_SAFE_NO_PAD
                    .decode(&cred.id)
                    .ok()
                    .map(|id_bytes| PublicKeyCredentialDescriptor {
                        id: id_bytes,
                        transports: vec![Transport::USB],
                    })
            })
            .collect();

        log_verbose(
            self.verbose,
            &format!("Allow list has {} credentials", allow_list.len()),
        );

        let args = SignArgs {
            client_data_hash: Sha256::digest(serde_json::to_vec(&serde_json::json!({
                "type": "webauthn.get",
                "challenge": opts.challenge,
                "origin": base_url,
            }))?)
            .into(),
            origin: base_url.to_string(),
            relying_party_id: opts.rp_id.clone(),
            allow_list,
            user_verification_req:
                authenticator::ctap2::server::UserVerificationRequirement::Preferred,
            user_presence_req: true,
            extensions: Default::default(),
            pin,
            use_ctap1_fallback: false,
        };

        log_verbose(self.verbose, "Sending sign request to authenticator...");
        manager
            .sign(opts.timeout, args, status_tx, callback)
            .context("Failed to start assertion")?;

        log_verbose(
            self.verbose,
            "Waiting for callback result (up to 60 seconds)...",
        );

        let mut loader = Loader::new("Tap your security key to continue", LoaderStyle::KeyTap);

        loop {
            // Check for status updates
            while let Ok(status) = status_rx.try_recv() {
                match status {
                    StatusUpdate::SelectResultNotice(sender, users) => {
                        loader.stop();
                        println!("Multiple credentials found. Please select one:");
                        for (idx, user) in users.iter().enumerate() {
                            let display = user
                                .display_name
                                .as_deref()
                                .or(user.name.as_deref())
                                .unwrap_or("Unknown");
                            println!("[{}] {}", idx, display);
                        }

                        use std::io::{self, Write};
                        print!("Enter selection (0-{}): ", users.len() - 1);
                        io::stdout().flush()?;

                        let mut input = String::new();
                        io::stdin().read_line(&mut input)?;
                        let selection: usize = input.trim().parse().context("Invalid selection")?;

                        if selection >= users.len() {
                            bail!("Selection out of range");
                        }

                        println!(
                            "Selected: {}",
                            users[selection].name.as_deref().unwrap_or("Unknown")
                        );
                        sender
                            .send(Some(selection))
                            .context("Failed to send selection")?;
                    }
                    StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender)) => {
                        loader.stop();
                        log_verbose(self.verbose, "PIN required by authenticator");
                        match prompt_for_pin()? {
                            Some(pin_string) => {
                                let pin = Pin::new(&pin_string);
                                sender.send(pin).context("Failed to send PIN")?;
                                loader = Loader::new(
                                    "Tap your security key to continue",
                                    LoaderStyle::KeyTap,
                                );
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
                let sign_result = result.map_err(|e| {
                    let msg = format!("{:?}", e);
                    if msg.contains("NoCredentials") {
                        anyhow::anyhow!(
                            "No passkey found on this device for this server.\n\
                             If you haven't registered yet, run: caution register\n\
                             If you registered with a different key, try that one instead."
                        )
                    } else {
                        anyhow::anyhow!("Assertion failed: {}", e)
                    }
                })?;

                let client_data_json = serde_json::json!({
                    "type": "webauthn.get",
                    "challenge": opts.challenge,
                    "origin": self.base_url.clone(),
                });
                let client_data_json_bytes = serde_json::to_vec(&client_data_json)?;

                let cred_id_bytes = &sign_result
                    .assertion
                    .credentials
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

        let response = self
            .client
            .post(format!("{}/api/resources", self.base_url))
            .header("X-Session-ID", config.session_id)
            .json(&body)
            .send()
            .await
            .context("Failed to send create app request")?;

        if !response.status().is_success() {
            let status = response.status();
            let error = self.api_error_message(response).await;
            loader.stop();

            if error.contains("initialize")
                || error.contains("provisioning")
                || error.contains("AWS account")
            {
                eprintln!("\n❌ Failed to initialize your AWS account");
                eprintln!("\nThis is your first time using Caution. We attempted to provision");
                eprintln!(
                    "a dedicated AWS account for your organization, but encountered an error:"
                );
                eprintln!("\n{}", error);
                eprintln!("\nPlease check:");
                eprintln!("  • AWS Organizations is enabled in your main account");
                eprintln!("  • Your IAM user has organizations:CreateAccount permission");
                eprintln!("  • Run: aws organizations create-organization --feature-set ALL");
                bail!("Account initialization failed");
            }

            bail!("Failed to create app (status {}): {}", status, error);
        }

        let create_response: CreateAppResponse = response
            .json()
            .await
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

        let response = self
            .client
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
            let error = self.api_error_message(response).await;
            bail!("Failed to list apps: {}", error)
        }
    }

    async fn fetch_app(&self, id: &str) -> Result<App> {
        let config = self.ensure_authenticated().await?;

        let response = self
            .client
            .get(format!("{}/api/resources/{}", self.base_url, id))
            .header("X-Session-ID", config.session_id)
            .send()
            .await?;

        if response.status().is_success() {
            let app: App = response.json().await?;
            Ok(app)
        } else {
            let error = self.api_error_message(response).await;
            bail!("Failed to get app: {}", error)
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
                        let ports_str: Vec<String> = ports
                            .iter()
                            .filter_map(|p| p.as_u64().map(|n| n.to_string()))
                            .collect();
                        println!("  Ports: {}", ports_str.join(", "));
                    }
                }
                if let Some(http_port) = enclave_config.get("http_port").and_then(|v| v.as_u64()) {
                    if http_port > 0 {
                        println!("  HTTP Port: {}", http_port);
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
                println!(
                    "  WARNING: --force-delete will remove from database even if cloud cleanup fails!"
                );
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

        let mut loader = Loader::new(
            &format!("Destroying app {} ({})", name, app.id),
            LoaderStyle::Processing,
        );

        let url = if force_delete {
            format!("{}/api/resources/{}?force=true", self.base_url, app.id)
        } else {
            format!("{}/api/resources/{}", self.base_url, app.id)
        };

        let response = self
            .client
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
            let error = self.api_error_message(response).await;
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

        let response = self
            .client
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
            let error = self.api_error_message(response).await;
            bail!("Failed to rename app (status {}): {}", status, error)
        }
    }

    async fn init(
        &self,
        managed_on_prem: bool,
        name: Option<String>,
        region: Option<String>,
        local: bool,
        config_path: Option<PathBuf>,
    ) -> Result<()> {
        // If --managed-on-prem without --config, use the new interactive flow
        if managed_on_prem && config_path.is_none() {
            return self
                .init_managed_on_prem_interactive(name, region, local)
                .await;
        }

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
            log_verbose(
                self.verbose,
                &format!(
                    "Found existing deployment with ID: {}",
                    deployment.resource_id
                ),
            );

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
                log_verbose(
                    self.verbose,
                    "Previous resource no longer exists, creating new one...",
                );
            }
        }

        let app_name = name.unwrap_or_else(|| {
            std::env::current_dir()
                .ok()
                .and_then(|p| p.file_name().map(|s| s.to_string_lossy().to_string()))
                .map(|s| s.to_lowercase().replace(' ', "-"))
                .filter(|s| {
                    !s.is_empty()
                        && s.chars()
                            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
                })
                .unwrap_or_else(|| "app".to_string())
        });

        log_verbose(self.verbose, "Creating app on server...");
        let body = serde_json::json!({
            "cmd": cmd,
            "name": app_name
        });

        let mut loader = Loader::new("Setting up your app", LoaderStyle::Processing);

        let response = self
            .client
            .post(format!("{}/api/resources", self.base_url))
            .header("X-Session-ID", config.session_id)
            .json(&body)
            .send()
            .await
            .context("Failed to send create app request")?;

        if !response.status().is_success() {
            let status = response.status();
            let error = self.api_error_message(response).await;
            loader.stop();

            if error.contains("initialize")
                || error.contains("provisioning")
                || error.contains("AWS account")
            {
                eprintln!("\n❌ Failed to initialize your AWS account");
                eprintln!("\nThis is your first time using Caution. We attempted to provision");
                eprintln!(
                    "a dedicated AWS account for your organization, but encountered an error:"
                );
                eprintln!("\n{}", error);
                eprintln!("\nPlease check:");
                eprintln!("  • AWS Organizations is enabled in your main account");
                eprintln!("  • Your IAM user has organizations:CreateAccount permission");
                eprintln!("  • Run: aws organizations create-organization --feature-set ALL");
                bail!("Account initialization failed");
            }

            bail!("Failed to create app (status {}): {}", status, error);
        }

        let create_response: CreateAppResponse = response
            .json()
            .await
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

        log_verbose(
            self.verbose,
            &format!("Reading config from {:?}", config_path),
        );
        let config_content =
            fs::read_to_string(config_path).context("Failed to read config file")?;

        let has_gpg_extension = config_path
            .extension()
            .map(|ext| ext == "gpg" || ext == "asc")
            .unwrap_or(false);
        let has_gpg_header = config_content
            .trim()
            .starts_with("-----BEGIN PGP MESSAGE-----");
        let is_gpg_encrypted = has_gpg_extension || has_gpg_header;

        let request_body = if is_gpg_encrypted {
            log_verbose(
                self.verbose,
                "Config file is GPG-encrypted (will be decrypted server-side)",
            );
            println!("Detected GPG-encrypted config file");

            let existing_resource_id = self.load_deployment().ok().map(|d| d.resource_id);
            if let Some(ref id) = existing_resource_id {
                println!("Found existing deployment: {}", id);
                println!(
                    "Note: For updates with encrypted config, ensure resource_id is in the decrypted JSON"
                );
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
                bail!(
                    "Config file must have platform: \"aws\" (got: {:?})",
                    platform
                );
            }

            let managed_on_prem = config_json.get("managed_on_prem").and_then(|v| v.as_bool());
            if managed_on_prem != Some(true) {
                bail!("Config file must have managed_on_prem: true");
            }

            let required_fields = [
                "aws_region",
                "aws_access_key_id",
                "aws_secret_access_key",
                "deployment_id",
                "asg_name",
                "eif_bucket",
                "launch_template_name",
                "launch_template_id",
                "vpc_id",
                "subnet_ids",
                "instance_profile_name",
                "iam_user",
                "aws_account_id",
                "scope_tag",
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

        let response = self
            .client
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
            bail!(
                "Failed to {} managed on-prem resource (status {}): {}",
                action,
                status,
                error
            );
        }

        let create_response: serde_json::Value =
            response.json().await.context("Failed to parse response")?;

        loader.stop();

        let id = create_response["id"].as_str().unwrap_or("unknown");
        let resource_name = create_response["resource_name"]
            .as_str()
            .unwrap_or("unnamed");
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

    /// Detect AWS credentials from environment or ~/.aws/credentials
    /// Returns (access_key, secret_key, region, session_token)
    fn detect_aws_credentials() -> Option<(String, String, Option<String>, Option<String>)> {
        // First check environment variables
        if let (Ok(key), Ok(secret)) = (
            std::env::var("AWS_ACCESS_KEY_ID"),
            std::env::var("AWS_SECRET_ACCESS_KEY"),
        ) {
            let region = std::env::var("AWS_REGION")
                .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
                .ok();
            let session_token = std::env::var("AWS_SESSION_TOKEN").ok();
            return Some((key, secret, region, session_token));
        }

        // Determine which profile to use
        let profile = std::env::var("AWS_PROFILE").unwrap_or_else(|_| "default".to_string());

        // Fall back to ~/.aws/credentials and ~/.aws/config
        let home = dirs::home_dir()?;
        let creds_path = home.join(".aws").join("credentials");
        let config_path = home.join(".aws").join("config");

        // Parse credentials file for the selected profile
        let (access_key, secret_key, session_token) =
            if let Ok(creds_content) = fs::read_to_string(&creds_path) {
                Self::parse_aws_credentials_file(&creds_content, &profile)
            } else {
                (None, None, None)
            };

        // Parse config file for region (and potentially credentials for SSO profiles)
        let region = if let Ok(config_content) = fs::read_to_string(&config_path) {
            Self::parse_aws_config_region(&config_content, &profile)
        } else {
            None
        };

        match (access_key, secret_key) {
            (Some(k), Some(s)) => Some((k, s, region, session_token)),
            _ => None,
        }
    }

    fn parse_aws_credentials_file(
        content: &str,
        profile: &str,
    ) -> (Option<String>, Option<String>, Option<String>) {
        let mut access_key = None;
        let mut secret_key = None;
        let mut session_token = None;
        let mut in_target_section = false;

        let section_header = format!("[{}]", profile);

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                in_target_section = trimmed == section_header;
                continue;
            }
            if in_target_section {
                if let Some((key, value)) = trimmed.split_once('=') {
                    let key = key.trim();
                    let value = value.trim();
                    match key {
                        "aws_access_key_id" => access_key = Some(value.to_string()),
                        "aws_secret_access_key" => secret_key = Some(value.to_string()),
                        "aws_session_token" => session_token = Some(value.to_string()),
                        _ => {}
                    }
                }
            }
        }

        (access_key, secret_key, session_token)
    }

    fn parse_aws_config_region(content: &str, profile: &str) -> Option<String> {
        let mut region = None;
        let mut in_target_section = false;

        // In config file, default profile is [default], others are [profile name]
        let section_headers: Vec<String> = if profile == "default" {
            vec!["[default]".to_string(), "[profile default]".to_string()]
        } else {
            vec![format!("[profile {}]", profile)]
        };

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                in_target_section = section_headers.iter().any(|h| h == trimmed);
                continue;
            }
            if in_target_section {
                if let Some((key, value)) = trimmed.split_once('=') {
                    if key.trim() == "region" {
                        region = Some(value.trim().to_string());
                    }
                }
            }
        }

        region
    }

    /// Interactive managed on-prem initialization
    async fn init_managed_on_prem_interactive(
        &self,
        name: Option<String>,
        region: Option<String>,
        local: bool,
    ) -> Result<()> {
        use std::io::{self, Write};

        println!("\n╔══════════════════════════════════════════════════════════════════╗");
        println!("║          Managed On-Premises Deployment Setup (AWS)              ║");
        println!("╚══════════════════════════════════════════════════════════════════╝\n");

        // Check for Docker
        let docker_check = Command::new("docker").arg("--version").output();
        if docker_check.is_err() || !docker_check.unwrap().status.success() {
            bail!("Docker is required but not found. Please install Docker first.");
        }

        let app_name = name.unwrap_or_else(|| {
            std::env::current_dir()
                .ok()
                .and_then(|p| p.file_name().map(|s| s.to_string_lossy().to_string()))
                .map(|s| s.to_lowercase().replace(' ', "-"))
                .filter(|s| {
                    !s.is_empty()
                        && s.chars()
                            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
                })
                .unwrap_or_else(|| "app".to_string())
        });

        if !app_name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            bail!("App name must contain only alphanumeric characters, hyphens, and underscores");
        }

        println!("App name: {}", app_name);

        // Check AWS credentials
        let aws_profile = std::env::var("AWS_PROFILE").unwrap_or_else(|_| "default".to_string());
        let (aws_key, aws_secret, detected_region, aws_session_token) =
            Self::detect_aws_credentials().ok_or_else(|| {
                anyhow::anyhow!(
                    "AWS credentials not found.\n\n\
                Please set up AWS credentials using one of these methods:\n\
                1. Set environment variables:\n\
                   export AWS_ACCESS_KEY_ID=your_key\n\
                   export AWS_SECRET_ACCESS_KEY=your_secret\n\
                   export AWS_REGION=us-west-2\n\n\
                2. Configure ~/.aws/credentials:\n\
                   [default]\n\
                   aws_access_key_id = your_key\n\
                   aws_secret_access_key = your_secret\n\n\
                3. Use a named profile:\n\
                   export AWS_PROFILE=my-profile\n\n\
                Required IAM policies:\n\
                • ec2:* (VPC, subnets, security groups)\n\
                • autoscaling:* (Auto Scaling Groups, launch templates)\n\
                • s3:* (bucket creation and management)\n\
                • iam:* (create user, role, instance profile)\n\
                • sts:GetCallerIdentity"
                )
            })?;

        let aws_region = region
            .or(detected_region)
            .unwrap_or_else(|| "us-west-2".to_string());

        if std::env::var("AWS_ACCESS_KEY_ID").is_ok() {
            println!("AWS credentials detected (from environment)");
        } else if aws_profile == "default" {
            println!("AWS credentials detected (from ~/.aws/credentials)");
        } else {
            println!("AWS credentials detected (profile: {})", aws_profile);
        }
        println!("Region: {}", aws_region);

        // Display what will be created
        println!("\nThis will create the following AWS resources:");
        println!("  • VPC with 3 subnets across availability zones");
        println!("  • S3 bucket for enclave images");
        println!("  • EC2 Auto Scaling Group and Launch Template");
        println!("  • IAM user with scoped permissions");
        println!("  • IAM role and instance profile for EC2");
        println!("\nAll resources will be tagged for easy identification and cleanup.\n");

        print!("Do you want to proceed? [y/N]: ");
        io::stdout().flush()?;
        let mut confirm = String::new();
        io::stdin().read_line(&mut confirm)?;
        if !confirm.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }

        // Pull the provisioner image (unless --local is set)
        if local {
            println!("\nUsing local provisioner image (--local)...");
        } else {
            println!("\nPulling provisioner image...");
            let pull_output = Command::new("docker")
                .args(&[
                    "pull",
                    "codeberg.org/caution/caution-managed-on-prem-aws-provisioner:latest",
                ])
                .output()
                .context("Failed to pull provisioner image")?;

            if !pull_output.status.success() {
                let stderr = String::from_utf8_lossy(&pull_output.stderr);
                bail!("Failed to pull provisioner image: {}", stderr);
            }
        }

        // Run the provisioner
        println!("Provisioning AWS resources (this may take a few minutes)...");
        println!("---");

        let mut docker_args = vec![
            "run".to_string(),
            "--rm".to_string(),
            "-e".to_string(),
            format!("AWS_ACCESS_KEY_ID={}", aws_key),
            "-e".to_string(),
            format!("AWS_SECRET_ACCESS_KEY={}", aws_secret),
            "-e".to_string(),
            format!("AWS_REGION={}", aws_region),
            "-e".to_string(),
            "CLI_MODE=true".to_string(),
        ];

        // Add session token if present (needed for temporary credentials/SSO)
        if let Some(token) = aws_session_token {
            docker_args.push("-e".to_string());
            docker_args.push(format!("AWS_SESSION_TOKEN={}", token));
        }

        docker_args.push(
            "codeberg.org/caution/caution-managed-on-prem-aws-provisioner:latest".to_string(),
        );

        let output = Command::new("docker")
            .args(&docker_args)
            .output()
            .context("Failed to run provisioner container")?;

        // Always print stderr (contains progress messages)
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.is_empty() {
            eprint!("{}", stderr);
        }

        println!("---");

        if !output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if !stdout.is_empty() {
                eprintln!("stdout: {}", stdout);
            }
            bail!(
                "Provisioning failed (exit code: {:?})",
                output.status.code()
            );
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse the JSON output from the provisioner (CLI_MODE outputs to stdout)
        let credentials_json: serde_json::Value =
            serde_json::from_str(&stdout).with_context(|| {
                if stdout.trim().is_empty() {
                    "Provisioner returned empty output (expected JSON)".to_string()
                } else {
                    format!(
                        "Failed to parse provisioner output as JSON. Raw output:\n{}",
                        stdout
                    )
                }
            })?;

        let deployment_id = credentials_json["deployment_id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing deployment_id in provisioner output"))?;

        // Authenticate with Caution
        let auth_config = self.ensure_authenticated().await?;

        let create_cmd = if PathBuf::from("Procfile").exists() {
            self.read_procfile()?
        } else if PathBuf::from("Containerfile").exists() {
            "docker build -f Containerfile -t app .".to_string()
        } else if PathBuf::from("Dockerfile").exists() {
            "docker build -f Dockerfile -t app .".to_string()
        } else {
            "echo 'Please configure your Procfile'".to_string()
        };

        // Create app on Caution
        println!("\nCreating app on Caution...");
        let mut loader = Loader::new("Creating app", LoaderStyle::Processing);

        // Create the app first
        let create_body = serde_json::json!({
            "name": app_name,
            "cmd": create_cmd
        });

        let create_response = self
            .client
            .post(format!("{}/api/resources", self.base_url))
            .header("X-Session-ID", &auth_config.session_id)
            .json(&create_body)
            .send()
            .await
            .context("Failed to create app")?;

        if !create_response.status().is_success() {
            loader.stop();
            let status = create_response.status();
            let error = create_response.text().await?;
            bail!("Failed to create app (status {}): {}", status, error);
        }

        let app_data: serde_json::Value = create_response
            .json()
            .await
            .context("Failed to parse create app response")?;

        let resource_id = app_data["id"].as_str().unwrap_or("");
        let git_url = app_data["git_url"].as_str().unwrap_or("");

        loader.stop();
        println!("App created: {}", app_name);

        // Now register the managed on-prem credentials
        println!("Registering managed on-prem configuration...");
        let mut loader = Loader::new("Registering credentials", LoaderStyle::Processing);

        // Add resource_id to credentials
        let mut creds_with_resource = credentials_json.clone();
        creds_with_resource["resource_id"] = serde_json::json!(resource_id);

        let register_response = self
            .client
            .post(format!("{}/api/resources/managed-onprem", self.base_url))
            .header("X-Session-ID", &auth_config.session_id)
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(&creds_with_resource)?)
            .send()
            .await
            .context("Failed to register managed on-prem credentials")?;

        if !register_response.status().is_success() {
            loader.stop();
            let status = register_response.status();
            let error = register_response.text().await?;
            bail!(
                "Failed to register credentials (status {}): {}",
                status,
                error
            );
        }

        loader.stop();

        // Save local state
        let caution_dir = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("Cannot find home directory"))?
            .join(".caution")
            .join(&app_name);

        fs::create_dir_all(&caution_dir)?;

        let managed_state = serde_json::json!({
            "deployment_id": deployment_id,
            "resource_id": resource_id,
            "app_name": app_name,
            "aws_region": aws_region,
            "created_at": chrono::Utc::now().to_rfc3339(),
        });

        fs::write(
            caution_dir.join("managed-on-prem.json"),
            serde_json::to_string_pretty(&managed_state)?,
        )?;

        // Also save deployment.json in current directory
        self.save_deployment(resource_id)?;

        // Set up git remote
        if !git_url.is_empty() {
            self.set_git_remote(git_url)?;
        }

        println!("\n╔══════════════════════════════════════════════════════════════════╗");
        println!("║                    Setup Complete!                               ║");
        println!("╚══════════════════════════════════════════════════════════════════╝");
        println!("\nApp: {}", app_name);
        println!("Resource ID: {}", resource_id);
        println!("Deployment ID: {}", deployment_id);
        println!("Git URL: {}", git_url);
        println!("\nState saved to: {}", caution_dir.display());
        println!("\nNext steps:");
        println!("  1. Create your Procfile with 'build:' and 'run:' commands");
        println!("  2. Push to deploy: git push caution main");
        println!("\nTo tear down this deployment:");
        println!("  caution teardown --managed-on-prem");

        Ok(())
    }

    /// Tear down managed on-prem deployment
    async fn teardown_managed_on_prem(&self, force: bool) -> Result<()> {
        use std::io::{self, Write};

        println!("\n╔══════════════════════════════════════════════════════════════════╗");
        println!("║          Managed On-Premises Teardown (AWS)                      ║");
        println!("╚══════════════════════════════════════════════════════════════════╝\n");

        // Try to find local state
        let deployment = self.load_deployment().ok();
        let resource_id = deployment.as_ref().map(|d| d.resource_id.clone());

        // Look for managed-on-prem.json in ~/.caution/*/
        let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot find home directory"))?;
        let caution_dir = home.join(".caution");

        let mut managed_state: Option<serde_json::Value> = None;
        let mut managed_state_path: Option<PathBuf> = None;

        if let Some(ref rid) = resource_id {
            // Look for state file that matches this resource_id
            if let Ok(entries) = fs::read_dir(&caution_dir) {
                for entry in entries.flatten() {
                    let state_path = entry.path().join("managed-on-prem.json");
                    if state_path.exists() {
                        if let Ok(content) = fs::read_to_string(&state_path) {
                            if let Ok(state) = serde_json::from_str::<serde_json::Value>(&content) {
                                if state.get("resource_id").and_then(|v| v.as_str()) == Some(rid) {
                                    managed_state = Some(state);
                                    managed_state_path = Some(entry.path());
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        let (deployment_id, app_name, aws_region) = match &managed_state {
            Some(state) => {
                let did = state["deployment_id"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("Missing deployment_id in state file"))?;
                let name = state["app_name"].as_str().unwrap_or("unknown");
                let region = state["aws_region"].as_str().unwrap_or("us-west-2");
                (did.to_string(), name.to_string(), region.to_string())
            }
            None => {
                bail!(
                    "No managed on-prem state found.\n\
                       Run this command from your app directory or ensure ~/.caution/<app>/managed-on-prem.json exists."
                );
            }
        };

        println!("Found managed on-prem deployment:");
        println!("  App: {}", app_name);
        println!("  Deployment ID: {}", deployment_id);
        println!("  Region: {}", aws_region);

        if !force {
            println!("\n⚠️  WARNING: This will permanently destroy:");
            println!("    • The Caution app and all deployment data");
            println!("    • AWS VPC and all associated resources");
            println!("    • S3 bucket and all stored images");
            println!("    • IAM user, role, and policies");
            println!("\n    This action cannot be undone!\n");

            print!("Type the app name to confirm deletion [{}]: ", app_name);
            io::stdout().flush()?;
            let mut confirm = String::new();
            io::stdin().read_line(&mut confirm)?;
            if confirm.trim() != app_name {
                println!("Aborted.");
                return Ok(());
            }
        }

        // Check AWS credentials for teardown
        let (aws_key, aws_secret, _, aws_session_token) = Self::detect_aws_credentials()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "AWS credentials required for teardown.\n\
                 Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables."
                )
            })?;

        // Destroy Caution resource first
        if let Some(ref rid) = resource_id {
            println!("\nDestroying Caution app...");
            let mut loader = Loader::new("Destroying app", LoaderStyle::Processing);

            let auth_config = self.ensure_authenticated().await?;
            let response = self
                .client
                .delete(format!("{}/api/resources/{}", self.base_url, rid))
                .header("X-Session-ID", &auth_config.session_id)
                .query(&[("force_delete", "true")])
                .send()
                .await;

            loader.stop();

            match response {
                Ok(resp) if resp.status().is_success() => {
                    println!("Caution app destroyed");
                }
                Ok(resp) => {
                    let error = resp.text().await.unwrap_or_default();
                    eprintln!("Warning: Failed to destroy Caution app: {}", error);
                }
                Err(e) => {
                    eprintln!("Warning: Failed to destroy Caution app: {}", e);
                }
            }
        }

        // Run teardown container
        println!("\nDestroying AWS infrastructure...");
        let mut loader = Loader::new("Running teardown", LoaderStyle::Processing);

        // Pull the image first (in case it's not cached)
        let _ = Command::new("docker")
            .args(&[
                "pull",
                "codeberg.org/caution/caution-managed-on-prem-aws-provisioner:latest",
            ])
            .output();

        let mut teardown_args = vec![
            "run".to_string(),
            "--rm".to_string(),
            "-e".to_string(),
            format!("AWS_ACCESS_KEY_ID={}", aws_key),
            "-e".to_string(),
            format!("AWS_SECRET_ACCESS_KEY={}", aws_secret),
            "-e".to_string(),
            format!("AWS_REGION={}", aws_region),
            "-e".to_string(),
            format!("DEPLOYMENT_ID={}", deployment_id),
            "-e".to_string(),
            "TEARDOWN=true".to_string(),
        ];

        // Add session token if present (needed for temporary credentials/SSO)
        if let Some(token) = aws_session_token {
            teardown_args.push("-e".to_string());
            teardown_args.push(format!("AWS_SESSION_TOKEN={}", token));
        }

        teardown_args.push(
            "codeberg.org/caution/caution-managed-on-prem-aws-provisioner:latest".to_string(),
        );

        let output = Command::new("docker")
            .args(&teardown_args)
            .output()
            .context("Failed to run teardown")?;

        loader.stop();

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("Warning: AWS teardown may have failed: {}", stderr);
            eprintln!("You may need to manually clean up resources in AWS console.");
        } else {
            println!("AWS infrastructure destroyed");
        }

        // Clean up local state
        if let Some(path) = managed_state_path {
            if let Err(e) = fs::remove_dir_all(&path) {
                eprintln!("Warning: Failed to remove local state: {}", e);
            } else {
                println!("Local state cleaned up");
            }
        }

        // Remove .caution/deployment.json
        let deployment_file = PathBuf::from(".caution").join("deployment.json");
        if deployment_file.exists() {
            let _ = fs::remove_file(&deployment_file);
        }

        println!("\n╔══════════════════════════════════════════════════════════════════╗");
        println!("║                    Teardown Complete                             ║");
        println!("╚══════════════════════════════════════════════════════════════════╝");
        println!("\nAll managed on-prem resources have been destroyed.");

        Ok(())
    }

    async fn get_attestation_url(&self) -> Result<String> {
        let app = self
            .get_current_app()
            .await
            .context("No deployment found. Either run 'caution init' first or provide --url")?;

        match app.public_ip {
            Some(ref ip) if !ip.is_empty() => Ok(format!("http://{}/attestation", ip)),
            _ => {
                bail!(
                    "No public IP available. Run 'caution describe' to check deployment status, or provide --url explicitly."
                )
            }
        }
    }

    async fn build_local(&self, no_cache: bool) -> Result<()> {
        println!("Building EIF locally for inspection...\n");

        let commit_sha = Command::new("git")
            .args(&["rev-parse", "HEAD"])
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        let procfile_no_cache = self
            .read_procfile_field("no_cache")
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
            enclave_builder::enclave_source_url(&enclave_builder::build::resolve_enclaveos_commit()),
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

        let binary_path = self
            .read_procfile_field("binary")
            .context("Procfile must specify 'binary' field")?;

        let run_command = self.read_procfile_field("run");
        let app_source_urls = self.read_procfile_sources();
        let app_source_urls_opt = if app_source_urls.is_empty() {
            None
        } else {
            Some(app_source_urls.clone())
        };
        let ports = self.read_procfile_ports();

        let mut loader = Loader::new("Building enclave image", LoaderStyle::Processing);
        let deployment = builder
            .build_enclave_auto(
                &user_image,
                &binary_path,
                run_command,
                app_source_urls_opt,
                None,
                None,
                None,
                None,
                &ports,
                false,
                false,
            )
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

    fn pin_archive_url_to_commit(url: &str, commit: &str) -> String {
        if let Some(archive_pos) = url.find("/archive/") {
            format!("{}/archive/{}.tar.gz", &url[..archive_pos], commit)
        } else {
            url.to_string()
        }
    }

    async fn build_and_get_pcrs(
        &self,
        external_manifest: Option<enclave_builder::EnclaveManifest>,
        no_cache: bool,
    ) -> Result<enclave_builder::PcrValues> {
        let (enclave_source, enclave_version) = if let Some(ref manifest) = external_manifest {
            match &manifest.enclave_source {
                enclave_builder::EnclaveSource::GitArchive { urls, commit } => {
                    let url = urls.first().cloned().unwrap_or_default();
                    let pinned = if let Some(commit) = commit {
                        Self::pin_archive_url_to_commit(&url, commit)
                    } else {
                        url
                    };
                    (pinned, "unused".to_string())
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
                log_verbose(
                    self.verbose,
                    &format!("Using enclave source from Procfile: {}", enclave_sources[0]),
                );
                (enclave_sources[0].clone(), "unused".to_string())
            } else {
                let source = enclave_builder::enclave_source_url(
                    &enclave_builder::build::resolve_enclaveos_commit(),
                );
                log_verbose(
                    self.verbose,
                    &format!("Using default enclave source: {}", source),
                );
                (source, "unused".to_string())
            }
        };

        let framework_source = if let Some(ref manifest) = external_manifest {
            match &manifest.framework_source {
                enclave_builder::FrameworkSource::GitArchive { url, commit } => {
                    if let Some(commit) = commit {
                        Self::pin_archive_url_to_commit(url, commit)
                    } else {
                        url.clone()
                    }
                }
            }
        } else {
            enclave_builder::FRAMEWORK_SOURCE.to_string()
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
                .and_then(|o| {
                    if o.status.success() {
                        Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
        };

        let builder = enclave_builder::EnclaveBuilder::new_with_cache(
            "unused-template",
            "local",
            &enclave_source,
            &enclave_version,
            &framework_source,
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
            let app_source = manifest.app_source.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "Manifest does not contain app_source - cannot reproduce without source URL"
                )
            })?;

            let archive_urls: Vec<String> = app_source
                .urls
                .iter()
                .filter_map(|url| self.git_url_to_archive_urls(url, &app_source.commit).ok())
                .flatten()
                .collect();

            let git_fallback = app_source.urls.first().map(|url| {
                (
                    url.clone(),
                    app_source.commit.clone(),
                    app_source.branch.clone(),
                )
            });

            let app_dir = self
                .download_and_extract_app_source_with_git_fallback(
                    &archive_urls,
                    git_fallback
                        .as_ref()
                        .map(|(u, c, b)| (u.as_str(), c.as_str(), b.as_deref())),
                )
                .await?;
            self.build_docker_image_from_dir(&app_dir, no_cache).await?
        } else {
            self.build_local_docker_image(no_cache).await?
        };

        log_verbose(
            self.verbose,
            "Building EIF locally to calculate expected PCRs...",
        );

        let user_image = enclave_builder::UserImage {
            reference: image_ref.clone(),
        };

        let (binary_path, run_command, app_source_urls, app_branch, app_commit, metadata) =
            if let Some(ref manifest) = external_manifest {
                let binary = manifest.binary.clone();
                let run_cmd = manifest.run_command.clone();
                let source_urls: Option<Vec<String>> =
                    manifest.app_source.as_ref().map(|s| s.urls.clone());
                let branch = manifest.app_source.as_ref().and_then(|s| s.branch.clone());
                let commit = manifest.app_source.as_ref().map(|s| s.commit.clone());

                log_verbose(self.verbose, &format!("Binary from manifest: {:?}", binary));
                log_verbose(
                    self.verbose,
                    &format!("Run command from manifest: {:?}", run_cmd),
                );
                log_verbose(
                    self.verbose,
                    &format!("App source URLs from manifest: {:?}", source_urls),
                );
                log_verbose(self.verbose, &format!("Branch from manifest: {:?}", branch));
                log_verbose(self.verbose, &format!("Commit from manifest: {:?}", commit));

                (
                    binary,
                    run_cmd,
                    source_urls,
                    branch,
                    commit,
                    manifest.metadata.clone(),
                )
            } else {
                let binary = self.read_procfile_field("binary");
                let run_cmd = self.read_procfile_field("run");
                let source_urls = self.read_procfile_sources();
                let source_urls_opt = if source_urls.is_empty() {
                    None
                } else {
                    Some(source_urls)
                };
                let metadata = self.read_procfile_field("metadata");

                let commit = Command::new("git")
                    .args(&["rev-parse", "HEAD"])
                    .output()
                    .ok()
                    .and_then(|o| {
                        if o.status.success() {
                            Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
                        } else {
                            None
                        }
                    });

                let branch = Command::new("git")
                    .args(&["rev-parse", "--abbrev-ref", "HEAD"])
                    .output()
                    .ok()
                    .and_then(|o| {
                        if o.status.success() {
                            Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
                        } else {
                            None
                        }
                    });

                log_verbose(self.verbose, &format!("Binary from Procfile: {:?}", binary));
                log_verbose(
                    self.verbose,
                    &format!("Run command from Procfile: {:?}", run_cmd),
                );
                log_verbose(
                    self.verbose,
                    &format!("Source URLs from Procfile: {:?}", source_urls_opt),
                );
                log_verbose(self.verbose, &format!("Git branch: {:?}", branch));
                log_verbose(self.verbose, &format!("Git commit: {:?}", commit));
                log_verbose(self.verbose, &format!("Metadata: {:?}", metadata));

                (binary, run_cmd, source_urls_opt, branch, commit, metadata)
            };

        let ports = self.read_procfile_ports();
        log_verbose(self.verbose, &format!("Ports: {:?}", ports));

        let e2e = self
            .read_procfile_field("e2e")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false);
        log_verbose(self.verbose, &format!("E2E encryption: {}", e2e));

        let locksmith = self
            .read_procfile_field("locksmith")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false);
        log_verbose(self.verbose, &format!("Locksmith secrets: {}", locksmith));

        let deployment = if let Some(ref bin_path) = binary_path {
            log_verbose(
                self.verbose,
                &format!("Using build_enclave_auto with binary: {}", bin_path),
            );
            builder
                .build_enclave_auto(
                    &user_image,
                    bin_path,
                    run_command,
                    app_source_urls,
                    app_branch,
                    app_commit,
                    metadata,
                    external_manifest,
                    &ports,
                    e2e,
                    locksmith,
                )
                .await
        } else {
            log_verbose(self.verbose, "Using build_enclave (no binary specified)");
            builder
                .build_enclave(
                    &user_image,
                    None,
                    run_command,
                    app_source_urls,
                    app_branch,
                    app_commit,
                    metadata,
                    external_manifest,
                    &ports,
                    e2e,
                    locksmith,
                )
                .await
        }
        .context("Failed to build enclave locally")?;
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
        let content =
            fs::read_to_string(path).context(format!("Failed to read PCRs file: {}", path))?;

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
            (Some(pcr0), Some(pcr1), Some(pcr2)) => Ok(enclave_builder::PcrValues {
                pcr0,
                pcr1,
                pcr2,
                pcr3: None,
                pcr4: None,
            }),
            _ => bail!("PCRs file must contain PCR0, PCR1, and PCR2 values"),
        }
    }

    async fn verify(
        &self,
        attestation_url_opt: Option<String>,
        from_local: bool,
        app_source_url: Option<String>,
        pcrs_file: Option<String>,
        no_cache: bool,
        save_pcrs: bool,
    ) -> Result<()> {
        println!("Verifying enclave attestation...");
        println!("Learn more: https://docs.caution.co/concepts/attestation/");

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

        log_verbose(
            self.verbose,
            &format!("Requesting attestation from: {}", attestation_url),
        );
        println!("Requesting attestation...");

        let response = self
            .client
            .post(&attestation_url)
            .json(&serde_json::json!({"nonce": general_purpose::STANDARD.encode(&nonce)}))
            .send()
            .await
            .context("Failed to fetch attestation document")?;

        if !response.status().is_success() {
            bail!("Failed to fetch attestation: {}", response.status());
        }

        let attest_resp: serde_json::Value = response
            .json()
            .await
            .context("Failed to parse attestation response as JSON")?;

        let attestation_b64 = attest_resp
            .get("attestation_document")
            .or_else(|| attest_resp.get("document"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No attestation document in response. Fields: {:?}",
                    attest_resp
                        .as_object()
                        .map(|o| o.keys().collect::<Vec<_>>())
                )
            })?;
        log_verbose(
            self.verbose,
            &format!("Received attestation: {} bytes", attestation_b64.len()),
        );
        let attestation_bytes = base64::engine::general_purpose::STANDARD
            .decode(attestation_b64)
            .context("Failed to decode attestation document")?;

        println!("\nExtracting remote PCR values...");
        let remote_pcrs = attestation::extract_pcrs(&attestation_bytes)
            .context("Failed to extract PCRs from attestation document")?;

        println!("\nRemote PCR values (from deployed enclave):");
        println!("  PCR0: {}", remote_pcrs.pcr0);
        println!("  PCR1: {}", remote_pcrs.pcr1);
        println!("  PCR2: {}", remote_pcrs.pcr2);

        let manifest: Option<enclave_builder::EnclaveManifest> =
            if let Some(manifest_val) = attest_resp.get("manifest").cloned() {
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
                enclave_builder::EnclaveSource::GitRepository {
                    url,
                    branch,
                    commit,
                } => {
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
                let commit = m
                    .app_source
                    .as_ref()
                    .map(|s| s.commit.clone())
                    .unwrap_or_else(|| "HEAD".to_string());
                modified_manifest.app_source = Some(enclave_builder::AppSource {
                    urls: vec![source_url.clone()],
                    commit,
                    branch: None,
                });
                self.build_and_get_pcrs(Some(modified_manifest), no_cache)
                    .await?
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
                    println!(
                        "  1. Provide the source URL: caution verify --app-source-url git@codeberg.org:org/repo.git"
                    );
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

        println!("\nVerifying attestation with bootproof-sdk...");
        let expected_nitro_pcrs: NitroPcrs = [
            (
                0u8,
                hex::decode(&expected_pcrs.pcr0).context("bad PCR0 hex")?,
            ),
            (
                1u8,
                hex::decode(&expected_pcrs.pcr1).context("bad PCR1 hex")?,
            ),
            (
                2u8,
                hex::decode(&expected_pcrs.pcr2).context("bad PCR2 hex")?,
            ),
        ]
        .into_iter()
        .collect();
        let nitro = Nitro::new(attestation_bytes, expected_nitro_pcrs)
            .context("could not build bootproof nitro attestation")?;
        let duration_since_epoch = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .context("could not get time since epoch")?;
        match nitro.verify(duration_since_epoch, &nonce) {
            Ok(payload) => {
                println!("✓ Certificate chain verified against AWS Nitro root CA");
                println!("✓ All certificates are within validity period");
                println!("✓ COSE signature verified");
                println!("✓ Nonce verified (prevents replay attacks)");
                println!("✓ PCR values match expected");

                if let serde_cbor::Value::Map(map) = &payload {
                    if let Some(serde_cbor::Value::Bytes(user_data)) =
                        map.get(&serde_cbor::Value::Text("user_data".to_string()))
                    {
                        println!();
                        match str::from_utf8(user_data) {
                            Ok(user_data) => {
                                println!("User data: {user_data}");
                            }
                            Err(_) => {
                                println!("User data: {user_data:?}");
                            }
                        }
                    }
                }

                println!("\n✓ Attestation verification PASSED");
                println!("The deployed enclave matches the expected PCRs.");
                println!("This means the code running in the enclave is exactly what you expect.");
                println!("\nPowered by: Caution (https://caution.co)");

                if save_pcrs {
                    let trusted = serde_json::json!({
                        "pcr0": remote_pcrs.pcr0,
                        "pcr1": remote_pcrs.pcr1,
                        "pcr2": remote_pcrs.pcr2,
                        "verified_at": chrono::Utc::now().to_rfc3339(),
                    });
                    let hashes_path = PathBuf::from(".caution/trusted_hashes.json");
                    fs::write(&hashes_path, serde_json::to_string_pretty(&trusted)?).with_context(
                        || format!("Failed to save trusted hashes to {}", hashes_path.display()),
                    )?;
                    println!("Trusted hashes saved to {}", hashes_path.display());
                }

                Ok(())
            }
            Err(e) => {
                println!("\n✗ Attestation verification FAILED");
                println!("Error: {e}");
                println!("\nPCR comparison:");
                if expected_pcrs.pcr0 != remote_pcrs.pcr0 {
                    println!("  PCR0: MISMATCH");
                    println!("    expected: {}", expected_pcrs.pcr0);
                    println!("    remote:   {}", remote_pcrs.pcr0);
                } else {
                    println!("  PCR0: match");
                }
                if expected_pcrs.pcr1 != remote_pcrs.pcr1 {
                    println!("  PCR1: MISMATCH");
                    println!("    expected: {}", expected_pcrs.pcr1);
                    println!("    remote:   {}", remote_pcrs.pcr1);
                } else {
                    println!("  PCR1: match");
                }
                if expected_pcrs.pcr2 != remote_pcrs.pcr2 {
                    println!("  PCR2: MISMATCH");
                    println!("    expected: {}", expected_pcrs.pcr2);
                    println!("    remote:   {}", remote_pcrs.pcr2);
                } else {
                    println!("  PCR2: match");
                }
                bail!("Attestation verification failed - {e}");
            }
        }
    }

    async fn build_local_docker_image(&self, no_cache: bool) -> Result<String> {
        let work_dir = std::env::current_dir().context("Failed to get current directory")?;
        self.build_docker_image_from_dir(&work_dir, no_cache).await
    }

    async fn build_docker_image_from_dir(
        &self,
        work_dir: &std::path::Path,
        no_cache: bool,
    ) -> Result<String> {
        use tokio::process::Command;

        let commit_sha = Command::new("git")
            .args(&["rev-parse", "HEAD"])
            .current_dir(work_dir)
            .output()
            .await
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        let tag = format!(
            "caution-local-build:{}",
            &commit_sha[..12.min(commit_sha.len())]
        );

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
            log_verbose(
                self.verbose,
                "--no-cache specified, rebuilding Docker image...",
            );
        }

        log_verbose(
            self.verbose,
            &format!("Building Docker image with tag: {}", tag),
        );

        let procfile_path = work_dir.join("Procfile");
        let config = if procfile_path.exists() {
            let content =
                std::fs::read_to_string(&procfile_path).context("Failed to read Procfile")?;
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
                no_cache,
            }
        } else {
            BuildConfig {
                build_command: None,
                containerfile: None,
                oci_tarball: None,
                no_cache,
            }
        };

        log_verbose(self.verbose, &format!("work_dir = {:?}", work_dir));
        log_verbose(self.verbose, &format!("BuildConfig = {:?}", config));

        build_user_image(work_dir, &tag, &config).await?;

        log_verbose(
            self.verbose,
            &format!("Docker image built successfully: {}", tag),
        );
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
        if extract_dir.exists()
            && extract_dir
                .read_dir()
                .map(|mut d| d.next().is_some())
                .unwrap_or(false)
        {
            log_verbose(
                self.verbose,
                &format!("Using cached app source: {}", extract_dir.display()),
            );
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
            .timeout(std::time::Duration::from_secs(300)) // 5 minutes for full download
            .build()
            .context("Failed to create HTTP client")?;

        let response = client
            .get(url)
            .send()
            .await
            .context("Failed to download app source")?;

        if !response.status().is_success() {
            bail!("Failed to download app source: HTTP {}", response.status());
        }

        let archive_bytes = response
            .bytes()
            .await
            .context("Failed to read archive bytes")?;

        log_verbose(
            self.verbose,
            &format!("Downloaded {} bytes, extracting...", archive_bytes.len()),
        );

        // Extract tar.gz archive with strip_components=1
        let decoder = GzDecoder::new(&archive_bytes[..]);
        let mut archive = Archive::new(decoder);

        std::fs::create_dir_all(&extract_dir)
            .with_context(|| format!("Failed to create extract dir: {}", extract_dir.display()))?;
        let canonical_extract = extract_dir.canonicalize().with_context(|| {
            format!(
                "Failed to canonicalize extract dir: {}",
                extract_dir.display()
            )
        })?;

        for entry in archive
            .entries()
            .context("Failed to read archive entries")?
        {
            let mut entry = entry.context("Failed to read archive entry")?;
            let path = entry.path().context("Failed to get entry path")?;

            // Skip the first path component (equivalent to --strip-components=1)
            let components: Vec<_> = path.components().collect();
            if components.len() <= 1 {
                continue;
            }

            let stripped_path: PathBuf = components[1..].iter().collect();
            let dest_path = canonical_extract.join(&stripped_path);

            if let Some(parent) = dest_path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create directory: {}", parent.display()))?;

                // Security: verify the resolved path stays within the extract directory
                let canonical_parent = parent
                    .canonicalize()
                    .with_context(|| format!("Failed to canonicalize: {}", parent.display()))?;
                if !canonical_parent.starts_with(&canonical_extract) {
                    bail!(
                        "Archive path traversal detected: {}",
                        stripped_path.display()
                    );
                }
            }

            entry
                .unpack(&dest_path)
                .with_context(|| format!("Failed to extract: {}", stripped_path.display()))?;
        }

        log_verbose(
            self.verbose,
            &format!("App source extracted to: {}", extract_dir.display()),
        );

        Ok(extract_dir)
    }

    async fn download_and_extract_app_source_with_fallbacks(
        &self,
        urls: &[String],
    ) -> Result<PathBuf> {
        if urls.is_empty() {
            bail!("No source URLs provided");
        }

        let mut last_error: Option<anyhow::Error> = None;

        for (i, url) in urls.iter().enumerate() {
            if i > 0 {
                log_verbose(
                    self.verbose,
                    &format!("Trying fallback URL ({}/{}): {}", i + 1, urls.len(), url),
                );
            }

            match self.download_and_extract_app_source(url).await {
                Ok(path) => return Ok(path),
                Err(e) => {
                    log_verbose(
                        self.verbose,
                        &format!("Failed to download from {}: {}", url, e),
                    );
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
            match self
                .download_and_extract_app_source_with_fallbacks(archive_urls)
                .await
            {
                Ok(path) => return Ok(path),
                Err(e) => {
                    log_verbose(self.verbose, &format!("Archive download failed: {}", e));
                }
            }
        }

        if let Some((git_url, commit, branch)) = git_fallback {
            log_verbose(self.verbose, "Archive download failed. Trying git clone...");

            let temp_dir = tempfile::TempDir::new().context("Failed to create temp directory")?;
            let clone_path = temp_dir.path().join("repo");

            // If we have a branch, clone by branch first (works with Forgejo/Codeberg)
            // then checkout the specific commit
            if let Some(branch_name) = branch {
                log_verbose(
                    self.verbose,
                    &format!(
                        "Cloning branch '{}' then checking out commit '{}'",
                        branch_name, commit
                    ),
                );

                let clone_output = Command::new("git")
                    .args(&[
                        "clone",
                        "--depth",
                        "100",
                        "--single-branch",
                        "--branch",
                        branch_name,
                        git_url,
                        clone_path.to_str().unwrap(),
                    ])
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
                        let extract_dir = temp_dir.keep().join("repo");
                        log_verbose(
                            self.verbose,
                            &format!("Git clone successful: {}", extract_dir.display()),
                        );
                        return Ok(extract_dir);
                    } else {
                        let stderr = String::from_utf8_lossy(&checkout_output.stderr);
                        log_verbose(
                            self.verbose,
                            &format!("Commit checkout failed: {}, will try deeper clone", stderr),
                        );

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
                            let extract_dir = temp_dir.keep().join("repo");
                            log_verbose(
                                self.verbose,
                                &format!(
                                    "Git clone successful after unshallow: {}",
                                    extract_dir.display()
                                ),
                            );
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

            let extract_dir = temp_dir.keep().join("repo");
            log_verbose(
                self.verbose,
                &format!("Git clone successful: {}", extract_dir.display()),
            );
            return Ok(extract_dir);
        }

        bail!("No source URLs available and no git fallback configured")
    }

    async fn add_ssh_key(
        &self,
        key_file: Option<PathBuf>,
        from_agent: bool,
        key: Option<String>,
        name: Option<String>,
    ) -> Result<()> {
        let config = self.ensure_authenticated().await?;

        if from_agent {
            let keys = self.get_ssh_agent_keys();
            if keys.is_empty() {
                bail!("No keys found in ssh-agent. Run 'ssh-add' first.");
            }

            let index = if keys.len() > 1 {
                for (i, (k, comment)) in keys.iter().enumerate() {
                    let key_name = name.clone().unwrap_or_else(|| comment.clone());
                    let fingerprint = ssh_fingerprint(k);
                    println!("{}. [{}], [{}]", i + 1, key_name, fingerprint);
                }

                print!("Which key would you like to add? (1-{}): ", keys.len());
                io::stdout().flush().unwrap();

                let mut input = String::new();
                io::stdin().read_line(&mut input).unwrap();

                match input.trim().parse::<usize>() {
                    Ok(n) if n >= 1 && n <= keys.len() => n - 1,
                    _ => bail!(
                        "Invalid number, please select a number between 1 and {}",
                        keys.len()
                    ),
                }
            } else {
                let (k, comment) = &keys[0];
                let key_name = name.clone().unwrap_or(comment.clone());
                let fingerprint = ssh_fingerprint(k);
                println!("Adding SSH key: {} ({})", key_name, fingerprint);
                0
            };

            let (k, comment) = &keys[index];
            let fingerprint = ssh_fingerprint(k);
            let key_name = name.clone().unwrap_or(comment.clone());

            self.add_single_key(&config.session_id, &key_name, k)
                .await?;
            println!("Added SSH key: [{}] [{}]", key_name, fingerprint);
        } else if let Some(key_str) = key {
            let key_content = key_str.trim();
            if !key_content.starts_with("ssh-") {
                bail!("Invalid SSH key format");
            }
            let key_name = name.unwrap_or_else(|| "key".to_string());
            self.add_single_key(&config.session_id, &key_name, key_content)
                .await?;
            println!("Added: {}", key_name);
            println!("  {}", key_content);
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

            self.add_single_key(&config.session_id, &key_name, &key_content)
                .await?;
            println!("Added: {}", key_name);
            println!("  {}", key_content);
        } else {
            bail!("Provide a key file, --key, or --from-agent");
        }

        Ok(())
    }

    async fn add_single_key(&self, session_id: &str, name: &str, key: &str) -> Result<()> {
        let body = serde_json::json!({ "name": name, "public_key": key });

        let response = self.signed_post(session_id, "/ssh-keys", &body).await?;

        if !response.status().is_success() {
            let error = self.api_error_message(response).await;
            if error.contains("insert SSH key")
                || error.contains("duplicate")
                || error.contains("23505")
            {
                bail!("Key already exists");
            }
            bail!("{}", error);
        }
        Ok(())
    }

    async fn remove_ssh_key(&self, fingerprint: &str) -> Result<()> {
        let config = self.ensure_authenticated().await?;

        let response = self
            .client
            .delete(format!("{}/ssh-keys/{}", self.base_url, fingerprint))
            .header("X-Session-ID", config.session_id)
            .send()
            .await?;

        if !response.status().is_success() {
            let error = self.api_error_message(response).await;
            bail!("Failed to remove key: {}", error);
        }

        println!("Key removed.");
        Ok(())
    }

    fn get_ssh_agent_keys(&self) -> Vec<(String, String)> {
        let output = Command::new("ssh-add").arg("-L").output();
        match output {
            Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter(|line| line.starts_with("ssh-"))
                .map(|line| {
                    let parts: Vec<&str> = line.splitn(3, ' ').collect();
                    let comment = parts.get(2).unwrap_or(&"unnamed").to_string();
                    (line.to_string(), comment)
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    async fn list_ssh_keys(&self) -> Result<()> {
        let config = self.ensure_authenticated().await?;

        let response = self
            .client
            .get(format!("{}/ssh-keys", self.base_url))
            .header("X-Session-ID", config.session_id)
            .send()
            .await?;

        if response.status().is_success() {
            let response_data: serde_json::Value = response.json().await?;
            let keys = response_data["keys"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("Invalid response format"))?;

            if keys.is_empty() {
                println!("No SSH keys found. Add one with 'caution ssh-keys add'");
            } else {
                println!("SSH Keys:");
                for key in keys {
                    let name = key["name"].as_str().unwrap_or("untitled");
                    let public_key = key["public_key"].as_str().unwrap_or("");
                    let fingerprint = ssh_fingerprint(public_key);
                    println!("  {} ({})", name, fingerprint);
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
                        let name = path
                            .file_name()
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

        fs::remove_dir_all(&cache_dir).context("Failed to remove cache directory")?;

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

    async fn add_credential(
        &self,
        platform: CredentialPlatform,
        name: String,
        is_default: bool,
        region: Option<String>,
    ) -> Result<()> {
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
                let secret_access_key =
                    rpassword::read_password().context("Failed to read secret access key")?;

                serde_json::json!({
                    "platform": "aws",
                    "name": name,
                    "access_key_id": access_key_id,
                    "secret_access_key": secret_access_key,
                    "default_region": region,
                    "is_default": is_default
                })
            }
            CredentialPlatform::Digitalocean
            | CredentialPlatform::Hetzner
            | CredentialPlatform::Linode
            | CredentialPlatform::Vultr
            | CredentialPlatform::Ovh => {
                println!("Adding {} credentials for '{}'", platform, name);
                print!("API Token: ");
                std::io::stdout().flush()?;
                let api_token = rpassword::read_password().context("Failed to read API token")?;

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
                let client_secret =
                    rpassword::read_password().context("Failed to read client secret")?;

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
                    let password = rpassword::read_password().context("Failed to read password")?;
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

        let response = self
            .client
            .post(format!("{}/credentials", self.base_url))
            .header("X-Session-ID", &config.session_id)
            .json(&request_body)
            .send()
            .await?;

        if response.status().is_success() {
            let cred: serde_json::Value = response.json().await?;
            println!(
                "Credential '{}' added successfully (ID: {})",
                name, cred["id"]
            );
            if is_default {
                println!("Set as default for {}", platform);
            }
            Ok(())
        } else {
            let error_text = self.api_error_message(response).await;
            bail!("Failed to add credential: {}", error_text)
        }
    }

    async fn list_credentials(&self) -> Result<()> {
        let config = self.ensure_authenticated().await?;

        let response = self
            .client
            .get(format!("{}/credentials", self.base_url))
            .header("X-Session-ID", &config.session_id)
            .send()
            .await?;

        if response.status().is_success() {
            let credentials: Vec<serde_json::Value> = response.json().await?;

            if credentials.is_empty() {
                println!(
                    "No cloud credentials found. Add one with 'caution credentials add <platform> <name>'"
                );
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

                    println!(
                        "  [{}] {} - {}{}{}",
                        id, name, platform, default_marker, region_str
                    );
                    println!("       Identifier: {}", identifier);
                }
            }
            Ok(())
        } else {
            let error = self.api_error_message(response).await;
            bail!("Failed to list credentials: {}", error)
        }
    }

    async fn remove_credential(&self, id: &str, force: bool) -> Result<()> {
        let config = self.ensure_authenticated().await?;

        let credential_id =
            uuid::Uuid::parse_str(id).context("Invalid credential ID - must be a valid UUID")?;

        let response = self
            .client
            .get(format!("{}/credentials/{}", self.base_url, credential_id))
            .header("X-Session-ID", &config.session_id)
            .send()
            .await?;

        if !response.status().is_success() {
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                bail!("Credential '{}' not found", id);
            }
            let error = self.api_error_message(response).await;
            bail!("Failed to fetch credential '{}': {}", id, error);
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

        let response = self
            .client
            .delete(format!("{}/credentials/{}", self.base_url, credential_id))
            .header("X-Session-ID", &config.session_id)
            .send()
            .await?;

        if response.status().is_success() {
            println!("Credential '{}' removed", name);
            Ok(())
        } else {
            let error = self.api_error_message(response).await;
            bail!("Failed to remove credential: {}", error)
        }
    }

    async fn set_default_credential(&self, id: &str) -> Result<()> {
        let config = self.ensure_authenticated().await?;

        let credential_id =
            uuid::Uuid::parse_str(id).context("Invalid credential ID - must be a valid UUID")?;

        let response = self
            .client
            .post(format!(
                "{}/credentials/{}/default",
                self.base_url, credential_id
            ))
            .header("X-Session-ID", &config.session_id)
            .send()
            .await?;

        if response.status().is_success() {
            println!("Credential set as default");
            Ok(())
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            bail!("Credential '{}' not found", id)
        } else {
            let error = self.api_error_message(response).await;
            bail!("Failed to set default: {}", error)
        }
    }

    async fn secret_new(
        &self,
        keyring: PathBuf,
        threshold: Option<u8>,
        max: Option<u8>,
        upload: bool,
        name: Option<String>,
        labels: Vec<String>,
    ) -> Result<()> {
        let keymaker_url = std::env::var("KEYMAKER_URL")
            .context("KEYMAKER_URL environment variable is required")?;

        let keyring_data = fs::read_to_string(&keyring)
            .with_context(|| format!("Failed to read keyring file: {}", keyring.display()))?;

        let threshold = threshold.unwrap_or(1);
        let max = max.unwrap_or(1);

        let request_body = serde_json::json!({
            "threshold": threshold,
            "max": max,
            "keyring": keyring_data,
            "label": {},
        });

        eprintln!(
            "Generating quorum (threshold={}, max={})...",
            threshold, max
        );

        let response = self
            .client
            .post(format!("{}/generate_quorum", keymaker_url))
            .json(&request_body)
            .send()
            .await
            .context("Failed to connect to Keymaker service")?;

        if !response.status().is_success() {
            let status = response.status();
            let error = response.text().await?;
            bail!("Keymaker error ({}): {}", status, error);
        }

        let quorum_response: serde_json::Value = response
            .json()
            .await
            .context("Failed to parse Keymaker response")?;

        let json = serde_json::to_string_pretty(&quorum_response)?;

        let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdout());
        let in_caution_repo = PathBuf::from("Procfile").exists()
            || PathBuf::from(".caution/deployment.json").exists();

        // Always save to file when in a caution repo
        if in_caution_repo {
            let secret_path = PathBuf::from(".caution/quorum-bundle.json");
            fs::write(&secret_path, &json)
                .with_context(|| format!("Failed to write secret to {}", secret_path.display()))?;
            eprintln!("Saved to: {}", secret_path.display());
        }

        // When not uploading (no QR, not in caution repo), output to stdout
        if !self.qr && (!is_tty || !in_caution_repo) {
            if !in_caution_repo {
                eprintln!("Warning: not in a Caution repository, outputting bundle to stdout");
            }
            print!("{}", json);
            return Ok(());
        }

        if upload || self.qr {
            if self.qr {
                eprintln!(
                    "\nUploading public key material bundle to Caution via QR code signing..."
                );
            } else {
                eprintln!("\nTo back up public key material bundle to Caution, tap your key.");
            }
            if in_caution_repo {
                eprintln!(
                    "The key material bundle is also accessible at .caution/quorum-bundle.json"
                );
            }
            eprintln!("Press Ctrl+C to cancel.");

            let config = self.ensure_authenticated().await?;

            let label_map: serde_json::Map<String, serde_json::Value> = labels
                .iter()
                .filter_map(|l| l.split_once('='))
                .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
                .collect();

            let upload_body = serde_json::json!({
                "data": quorum_response,
                "name": name,
                "labels": label_map,
            });

            let response = self
                .signed_post(&config.session_id, "/api/quorum-bundles", &upload_body)
                .await?;

            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                if let Some(id) = result.get("id") {
                    eprintln!("\nQuorum bundle stored successfully (bundle ID: {})", id);
                } else {
                    eprintln!("\nQuorum bundle stored successfully.");
                }
            } else {
                let status = response.status();
                let error = self.api_error_message(response).await;
                bail!("Failed to store quorum bundle ({}): {}", status, error);
            }
        }

        Ok(())
    }

    async fn secret_rename(&self, id: String, name: String) -> Result<()> {
        let config = self.ensure_authenticated().await?;

        let body = serde_json::json!({
            "name": name,
        });

        let response = self
            .client
            .patch(format!("{}/api/quorum-bundles/{}", self.base_url, id))
            .header("X-Session-ID", &config.session_id)
            .json(&body)
            .send()
            .await
            .context("Failed to connect to server")?;

        if response.status().is_success() {
            eprintln!("Quorum bundle renamed to \"{}\"", name);
        } else {
            let status = response.status();
            let error = self.api_error_message(response).await;
            bail!("Failed to rename quorum bundle ({}): {}", status, error);
        }

        Ok(())
    }

    async fn secret_label_set(&self, id: String, labels: Vec<String>) -> Result<()> {
        let config = self.ensure_authenticated().await?;

        // Get current bundle to read existing labels
        let response = self
            .client
            .get(format!("{}/api/quorum-bundles/{}", self.base_url, id))
            .header("X-Session-ID", &config.session_id)
            .send()
            .await
            .context("Failed to connect to server")?;

        if !response.status().is_success() {
            let status = response.status();
            let error = self.api_error_message(response).await;
            bail!("Failed to fetch quorum bundle ({}): {}", status, error);
        }

        let bundle: serde_json::Value = response.json().await?;
        let mut current_labels = bundle
            .get("labels")
            .and_then(|l| l.as_object().cloned())
            .unwrap_or_default();

        // Merge new labels
        for label in &labels {
            let (k, v) = label.split_once('=').ok_or_else(|| {
                anyhow::anyhow!("Invalid label format '{}', expected key=value", label)
            })?;
            current_labels.insert(k.to_string(), serde_json::Value::String(v.to_string()));
        }

        let body = serde_json::json!({ "labels": current_labels });

        let response = self
            .client
            .patch(format!("{}/api/quorum-bundles/{}", self.base_url, id))
            .header("X-Session-ID", &config.session_id)
            .json(&body)
            .send()
            .await
            .context("Failed to connect to server")?;

        if response.status().is_success() {
            eprintln!("Labels updated successfully");
        } else {
            let status = response.status();
            let error = self.api_error_message(response).await;
            bail!("Failed to update labels ({}): {}", status, error);
        }

        Ok(())
    }

    async fn secret_label_remove(&self, id: String, keys: Vec<String>) -> Result<()> {
        let config = self.ensure_authenticated().await?;

        // Get current bundle to read existing labels
        let response = self
            .client
            .get(format!("{}/api/quorum-bundles/{}", self.base_url, id))
            .header("X-Session-ID", &config.session_id)
            .send()
            .await
            .context("Failed to connect to server")?;

        if !response.status().is_success() {
            let status = response.status();
            let error = self.api_error_message(response).await;
            bail!("Failed to fetch quorum bundle ({}): {}", status, error);
        }

        let bundle: serde_json::Value = response.json().await?;
        let mut current_labels = bundle
            .get("labels")
            .and_then(|l| l.as_object().cloned())
            .unwrap_or_default();

        for key in &keys {
            current_labels.remove(key);
        }

        let body = serde_json::json!({ "labels": current_labels });

        let response = self
            .client
            .patch(format!("{}/api/quorum-bundles/{}", self.base_url, id))
            .header("X-Session-ID", &config.session_id)
            .json(&body)
            .send()
            .await
            .context("Failed to connect to server")?;

        if response.status().is_success() {
            eprintln!("Labels removed successfully");
        } else {
            let status = response.status();
            let error = self.api_error_message(response).await;
            bail!("Failed to remove labels ({}): {}", status, error);
        }

        Ok(())
    }

    async fn secret_send_shard(
        &self,
        app: Option<String>,
        bundle_path: Option<PathBuf>,
    ) -> Result<()> {
        // Resolve the app to get the enclave's public IP
        let app_info = match app {
            Some(id) => self.fetch_app(&id).await?,
            None => self.get_current_app().await?,
        };

        let public_ip = app_info
            .public_ip
            .context("App has no public IP. Is the enclave running?")?;

        // Resolve the bundle file
        let bundle_file = if let Some(path) = bundle_path {
            path
        } else {
            // Check local paths first
            let local_paths = [
                PathBuf::from(".caution/secrets/bundle.json"),
                PathBuf::from(".caution/quorum-bundle.json"),
            ];
            let found = local_paths.iter().find(|p| p.exists());

            if let Some(path) = found {
                path.clone()
            } else {
                // Try to pull from Caution API
                eprintln!("No local bundle found, checking Caution...");
                let config = self.ensure_authenticated().await?;
                let response = self
                    .client
                    .get(format!("{}/api/quorum-bundles", self.base_url))
                    .header("X-Session-ID", &config.session_id)
                    .send()
                    .await
                    .context("Failed to fetch quorum bundles from Caution")?;

                if !response.status().is_success() {
                    bail!(
                        "No bundle found locally or on Caution. Create one with: caution secret new <keyring>"
                    );
                }

                let bundles: Vec<serde_json::Value> = response
                    .json()
                    .await
                    .context("Failed to parse bundles response")?;

                if bundles.is_empty() {
                    bail!(
                        "No bundle found locally or on Caution. Create one with: caution secret new <keyring>"
                    );
                }

                // Use the first bundle's data
                let bundle_data = bundles[0].get("data").context("Bundle has no data field")?;

                let secrets_dir = PathBuf::from(".caution/secrets");
                fs::create_dir_all(&secrets_dir).context("Failed to create .caution/secrets/")?;
                let path = secrets_dir.join("bundle.json");
                let json = serde_json::to_string_pretty(bundle_data)?;
                fs::write(&path, &json)
                    .with_context(|| format!("Failed to write bundle to {}", path.display()))?;
                eprintln!("Bundle saved to {}", path.display());
                path
            }
        };

        anyhow::ensure!(
            bundle_file.exists(),
            "Bundle file not found: {}",
            bundle_file.display()
        );

        // Load trusted hashes from a prior `caution verify --save-pcrs`
        let hashes_path = PathBuf::from(".caution/trusted_hashes.json");
        let hashes_text = fs::read_to_string(&hashes_path).context(
            "No trusted hashes found. Run `caution verify --save-pcrs` first to establish trusted PCR values."
        )?;
        let hashes: serde_json::Value = serde_json::from_str(&hashes_text)
            .context("Failed to parse .caution/trusted_hashes.json")?;

        let pcrs = std::collections::HashMap::from([
            (
                0u8,
                hex::decode(hashes["pcr0"].as_str().context("missing pcr0")?)
                    .context("invalid pcr0 hex")?,
            ),
            (
                1u8,
                hex::decode(hashes["pcr1"].as_str().context("missing pcr1")?)
                    .context("invalid pcr1 hex")?,
            ),
            (
                2u8,
                hex::decode(hashes["pcr2"].as_str().context("missing pcr2")?)
                    .context("invalid pcr2 hex")?,
            ),
        ]);

        if let Some(verified_at) = hashes["verified_at"].as_str() {
            eprintln!("Using trusted hashes from {}", verified_at);
        }

        // Parse the quorum bundle
        let bundle_text = fs::read_to_string(&bundle_file)
            .with_context(|| format!("Failed to read bundle file: {}", bundle_file.display()))?;
        let bundle: keymaker_models::generate_quorum::GenerateQuorumResponse =
            serde_json::from_str(&bundle_text).context("Failed to parse bundle JSON")?;

        let address_str = format!("{}:8084", public_ip);
        eprintln!("Sending shard to enclave at {}...", address_str);
        let address: std::net::SocketAddr = address_str.parse().context("Invalid address")?;

        let status = locksmith::client::send_shard(address, pcrs, &bundle)
            .await
            .context("Failed to send shard to enclave")?;

        match status {
            locksmith::models::SendSignedEncryptedShardResponse::Accepted { remaining } => {
                eprintln!(
                    "Shard accepted, {} remaining shards until reconstitution",
                    remaining
                );
            }
            locksmith::models::SendSignedEncryptedShardResponse::Rejected { reason } => {
                bail!("Shard rejected by enclave: {}", reason);
            }
        }

        Ok(())
    }
}

struct AssertionResult {
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
        Commands::Register { .. } | Commands::Login { .. } => {
            if let Err(e) = check_gateway_connectivity(&cli.url, cli.verbose).await {
                eprintln!("Pre-flight check failed");
                return Err(e);
            }
        }
        _ => {}
    }

    log_verbose(cli.verbose, "Initializing API client...");
    let client =
        ApiClient::new(&cli.url, cli.verbose, cli.qr).context("Failed to initialize API client")?;
    log_verbose(cli.verbose, "API client ready");

    match cli.command {
        Commands::Register { alpha_code } => {
            client.register(&alpha_code).await?;
        }
        Commands::Login { qr } => {
            if qr {
                client.login_qr().await?;
            } else {
                client.login().await?;
            }
        }
        Commands::Logout => {
            client.logout().await?;
        }
        Commands::Init {
            managed_on_prem,
            platform,
            name,
            region,
            local,
            config,
        } => {
            if managed_on_prem && platform != "aws" {
                bail!("Only --platform aws is currently supported for managed on-prem deployments");
            }
            client
                .init(managed_on_prem, name, region, local, config)
                .await?;
        }
        Commands::Teardown {
            managed_on_prem,
            platform,
            force,
        } => {
            if managed_on_prem {
                if platform != "aws" {
                    bail!(
                        "Only --platform aws is currently supported for managed on-prem deployments"
                    );
                }
                client.teardown_managed_on_prem(force).await?;
            } else {
                bail!("Please specify --managed-on-prem to tear down managed infrastructure");
            }
        }
        Commands::Verify {
            attestation_url,
            from_local,
            app_source_url,
            pcrs,
            no_cache,
            save_pcrs,
        } => {
            client
                .verify(
                    attestation_url,
                    from_local,
                    app_source_url,
                    pcrs,
                    no_cache,
                    save_pcrs,
                )
                .await?;
        }
        Commands::Apps { command } => match command {
            AppCommands::Create => {
                client.create_app().await?;
            }
            AppCommands::List => {
                client.list_apps().await?;
            }
            AppCommands::Get { id } => {
                client.get_app(id).await?;
            }
            AppCommands::Destroy {
                id,
                force,
                force_delete,
            } => {
                client.destroy_app(id, force, force_delete).await?;
            }
            AppCommands::Build { no_cache } => {
                client.build_local(no_cache).await?;
            }
            AppCommands::Rename { name, id } => {
                client.rename_app(id, name).await?;
            }
        },
        Commands::SshKeys { command } => match command {
            SshKeyCommands::Add {
                key_file,
                from_agent,
                key,
                name,
            } => {
                client.add_ssh_key(key_file, from_agent, key, name).await?;
            }
            SshKeyCommands::List => {
                client.list_ssh_keys().await?;
            }
            SshKeyCommands::Remove { fingerprint } => {
                client.remove_ssh_key(&fingerprint).await?;
            }
        },
        Commands::Cache { command } => match command {
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
        },
        Commands::Credentials { command } => match command {
            CredentialCommands::Add {
                platform,
                name,
                default,
                region,
            } => {
                client
                    .add_credential(platform, name, default, region)
                    .await?;
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
        },
        Commands::Secret { command } => match command {
            SecretCommands::New {
                keyring,
                threshold,
                max,
                no_upload,
                name,
                labels,
            } => {
                client
                    .secret_new(keyring, threshold, max, !no_upload, name, labels)
                    .await?;
            }
            SecretCommands::Rename { id, name } => {
                client.secret_rename(id, name).await?;
            }
            SecretCommands::Label { command } => match command {
                LabelCommands::Set { id, labels } => {
                    client.secret_label_set(id, labels).await?;
                }
                LabelCommands::Remove { id, keys } => {
                    client.secret_label_remove(id, keys).await?;
                }
            },
            SecretCommands::SendShard { app, bundle } => {
                client.secret_send_shard(app, bundle).await?;
            }
        },
    }

    Ok(())
}
