// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use base64::{Engine as _, engine::general_purpose};
use clap::{Parser, Subcommand};
use dterror::{BoxError, CtxError, FromContext, Location, ResultExt};
use enclave_builder::{
    has_explicit_build_command, resolve_build_command_in_dir, validate_explicit_containerfile_path,
};
use keymaker_models::generate_quorum::v0::GenerateQuorumResponse;
use reqwest;
use sequoia_openpgp as openpgp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openpgp::policy::StandardPolicy as OpenPgpPolicy;
use openpgp::{cert::CertParser, parse::Parse, serialize::Serialize as _};

pub mod output;
pub mod prompt;

mod apps;
mod attestation;
mod auth;
mod byoc;
mod cache;
mod credentials;
mod pgp_keys;
mod secrets;
mod ssh_keys;
mod verify;

const SSH_SIGNING_NAMESPACE: &str = "caution-api";
const PGP_PUBLIC_KEY_MAX_BYTES: usize = 64 * 1024;
const PGP_KEY_NAME_MAX_CHARS: usize = 255;
const PGP_PUBLIC_KEY_ARMOR_BEGIN: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
const PGP_PUBLIC_KEY_ARMOR_END: &str = "-----END PGP PUBLIC KEY BLOCK-----";
const PGP_PRIVATE_KEY_ARMOR_BEGIN: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----";

#[derive(Debug, FromContext)]
enum SshSignedRequestErrorKind {
    PublicKeyForIdentity,
    FingerprintPublicKey,
    SystemClockBeforeUnixEpoch,
    SignPayload,
    SendRequest,
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error(
    "Unable to send SSH-signed request {method} {path} with identity {identity:?}: {kind:?} [{location:?}]"
)]
struct SshSignedRequestError {
    #[context(from = SshSignedRequestErrorKindCtx)]
    kind: SshSignedRequestErrorKind,
    method: reqwest::Method,
    #[context(borrow = str)]
    path: String,
    #[context(borrow = Path)]
    identity: PathBuf,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

#[derive(Debug, FromContext)]
enum FetchAppViaSshHttpsErrorKind {
    SendSignedRequest,
    DecodeResponse,
    ApiStatus {
        status: reqwest::StatusCode,
        #[context(borrow = str)]
        message: String,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("Unable to fetch app {id} via SSH-signed HTTPS at {path}: {kind:?} [{location:?}]")]
struct FetchAppViaSshHttpsError {
    #[context(from = FetchAppViaSshHttpsErrorKindCtx<'a>)]
    kind: FetchAppViaSshHttpsErrorKind,
    #[context(borrow = str)]
    id: String,
    #[context(borrow = str)]
    path: String,
    #[location]
    location: Location,
    #[source]
    source: Option<BoxError>,
}

#[derive(Debug, FromContext)]
enum DestroyAppViaSshHttpsErrorKind {
    SendSignedRequest,
    ApiStatus {
        status: reqwest::StatusCode,
        #[context(borrow = str)]
        message: String,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error(
    "Unable to destroy app {id} via SSH-signed HTTPS at {path} with force_delete={force_delete}: {kind:?} [{location:?}]"
)]
struct DestroyAppViaSshHttpsError {
    #[context(from = DestroyAppViaSshHttpsErrorKindCtx<'a>)]
    kind: DestroyAppViaSshHttpsErrorKind,
    #[context(borrow = str)]
    id: String,
    #[context(borrow = str)]
    path: String,
    force_delete: bool,
    #[location]
    location: Location,
    #[source]
    source: Option<BoxError>,
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum PreparePgpPublicKeyForUploadError {
    #[error("PGP public key is empty [{location:?}]")]
    Empty {
        #[location]
        location: Location,
    },

    #[error("PGP public key is too large (maximum {max_bytes} bytes) [{location:?}]")]
    TooLarge {
        max_bytes: usize,
        #[location]
        location: Location,
    },

    #[error(
        "PGP input contains private key material; export and submit only the public certificate [{location:?}]"
    )]
    PrivateMaterial {
        #[location]
        location: Location,
    },

    #[error("PGP public key must be an ASCII-armored public certificate [{location:?}]")]
    NotArmored {
        #[location]
        location: Location,
    },

    #[error("failed to parse PGP public key [{location:?}]")]
    Parse {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("PGP input must contain exactly one public certificate (got {count}) [{location:?}]")]
    CertCount {
        count: usize,
        #[location]
        location: Location,
    },

    #[error("PGP input did not contain a public certificate [{location:?}]")]
    MissingCert {
        #[location]
        location: Location,
    },

    #[error("PGP public certificate is not valid under the standard OpenPGP policy [{location:?}]")]
    InvalidPolicy {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to normalize PGP public certificate [{location:?}]")]
    Normalize {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("normalized PGP public certificate is not valid UTF-8 [{location:?}]")]
    NotUtf8 {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

fn prepare_pgp_public_key_for_upload(
    public_key: &str,
) -> Result<(String, String), PreparePgpPublicKeyForUploadError> {
    use PreparePgpPublicKeyForUploadErrorCtx as Ctx;

    let public_key = public_key.trim();
    if public_key.is_empty() {
        return Err(PreparePgpPublicKeyForUploadError::Empty {
            location: std::panic::Location::caller(),
        });
    }
    if public_key.len() > PGP_PUBLIC_KEY_MAX_BYTES {
        return Err(PreparePgpPublicKeyForUploadError::TooLarge {
            max_bytes: PGP_PUBLIC_KEY_MAX_BYTES,
            location: std::panic::Location::caller(),
        });
    }
    if public_key.starts_with(PGP_PRIVATE_KEY_ARMOR_BEGIN) {
        return Err(PreparePgpPublicKeyForUploadError::PrivateMaterial {
            location: std::panic::Location::caller(),
        });
    }
    if !(public_key.starts_with(PGP_PUBLIC_KEY_ARMOR_BEGIN)
        && public_key.ends_with(PGP_PUBLIC_KEY_ARMOR_END))
    {
        return Err(PreparePgpPublicKeyForUploadError::NotArmored {
            location: std::panic::Location::caller(),
        });
    }

    let cert_parser = CertParser::from_bytes(public_key.as_bytes()).with_context(Ctx::parse())?;
    let certs = cert_parser
        .collect::<openpgp::Result<Vec<_>>>()
        .with_context(Ctx::parse())?;
    if certs.len() != 1 {
        return Err(PreparePgpPublicKeyForUploadError::CertCount {
            count: certs.len(),
            location: std::panic::Location::caller(),
        });
    }

    let cert =
        certs
            .into_iter()
            .next()
            .ok_or_else(|| PreparePgpPublicKeyForUploadError::MissingCert {
                location: std::panic::Location::caller(),
            })?;
    if cert.is_tsk() {
        return Err(PreparePgpPublicKeyForUploadError::PrivateMaterial {
            location: std::panic::Location::caller(),
        });
    }
    cert.with_policy(&OpenPgpPolicy::new(), None)
        .with_context(Ctx::invalid_policy())?;

    let fingerprint = cert.fingerprint().to_string();
    let mut serialized = Vec::new();
    cert.armored()
        .serialize(&mut serialized)
        .with_context(Ctx::normalize())?;
    let mut armored = String::from_utf8(serialized).with_context(Ctx::not_utf8())?;
    if !armored.ends_with('\n') {
        armored.push('\n');
    }
    if armored.len() > PGP_PUBLIC_KEY_MAX_BYTES {
        return Err(PreparePgpPublicKeyForUploadError::TooLarge {
            max_bytes: PGP_PUBLIC_KEY_MAX_BYTES,
            location: std::panic::Location::caller(),
        });
    }

    Ok((armored, fingerprint))
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CheckDependenciesError {}

fn check_dependencies(verbose: bool) -> Result<(), CheckDependenciesError> {
    output::verbose(verbose, "Checking dependencies...");

    let usb_dev_path = std::path::Path::new("/dev/bus/usb");
    if !usb_dev_path.exists() {
        output::verbose(
            verbose,
            "Warning: /dev/bus/usb not found - USB access may not work",
        );
    } else {
        output::verbose(verbose, "USB device access available");
    }

    output::verbose(verbose, "FIDO2 authenticator library loaded");

    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum CheckGatewayConnectivityError {
    #[error("failed to build HTTP client [{location:?}]")]
    BuildClient {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

async fn check_gateway_connectivity(
    url: &str,
    verbose: bool,
) -> Result<(), CheckGatewayConnectivityError> {
    use CheckGatewayConnectivityErrorCtx as Ctx;

    output::verbose(
        verbose,
        &format!("Testing connectivity to gateway: {}", url),
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .with_context(Ctx::build_client())?;

    // Just verify we can reach the gateway base URL
    output::verbose(verbose, &format!("HEAD {}", url));

    match client.head(url).send().await {
        Ok(resp) => {
            output::verbose(
                verbose,
                &format!("Gateway reachable (status: {})", resp.status()),
            );
            Ok(())
        }
        Err(e) => {
            output::verbose(verbose, &format!("HEAD request failed (this is ok): {}", e));
            output::verbose(
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
        default_value = "https://dashboard.caution.co",
        env = "CAUTION_BACKEND_URL",
        help = "Caution API server URL",
        global = true
    )]
    url: String,

    #[arg(short, long, global = true, help = "Enable verbose output")]
    verbose: bool,

    #[arg(
        long,
        global = true,
        help = "Use QR code for cross-device FIDO2 signing (no local security key needed)"
    )]
    qr: bool,

    #[arg(
        long,
        global = true,
        env = "CAUTION_WORKDIR",
        help = "Working directory for cache (default: ~/.cache/caution)"
    )]
    workdir: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(about = "Register a new account")]
    Register {
        #[arg(long)]
        alpha_code: String,
        #[arg(
            long,
            help = "Username to register with (prompted interactively if omitted)"
        )]
        username: Option<String>,
    },
    #[command(about = "Login to your Caution account")]
    Login {
        #[arg(
            long,
            help = "Use QR code for cross-device authentication (--username required; no local security key needed)"
        )]
        qr: bool,
        #[arg(
            long,
            required_if_eq("qr", "true"),
            help = "Username to log in with (required when using --qr; prompted interactively otherwise)"
        )]
        username: Option<String>,
    },
    #[command(about = "Logout and clear local session")]
    Logout,
    #[command(about = "Show account information")]
    Account {
        #[command(subcommand)]
        command: AccountCommands,
    },
    #[command(about = "Initialize a new deployment in the current directory")]
    Init {
        #[arg(
            long = "byoc",
            alias = "bring-your-own-compute",
            help = "Set up a bring-your-own-compute (BYOC) deployment"
        )]
        bring_your_own_cloud: bool,
        #[arg(
            long,
            requires = "bring_your_own_cloud",
            help = "Cloud platform (default: aws)",
            default_value = "aws"
        )]
        platform: String,
        #[arg(long, help = "App name (default: current directory name)")]
        name: Option<String>,
        #[arg(
            long,
            requires = "bring_your_own_cloud",
            help = "AWS region (default: us-west-2)"
        )]
        region: Option<String>,
        #[arg(
            long,
            requires = "bring_your_own_cloud",
            help = "Use local provisioner image (skip docker pull)"
        )]
        local: bool,
        #[arg(
            long,
            requires = "bring_your_own_cloud",
            help = "Path to encrypted credentials file from manual BYOC setup"
        )]
        config: Option<PathBuf>,
        #[arg(
            long,
            requires = "bring_your_own_cloud",
            conflicts_with = "config",
            help = "Skip the BYOC provisioning confirmation"
        )]
        yes: bool,
    },
    #[command(about = "Tear down a bring-your-own-compute (BYOC) deployment")]
    Teardown {
        #[arg(
            long = "byoc",
            alias = "bring-your-own-compute",
            help = "Tear down bring-your-own-compute infrastructure"
        )]
        bring_your_own_cloud: bool,
        #[arg(long, help = "Cloud platform (default: aws)", default_value = "aws")]
        platform: String,
        #[arg(
            long,
            requires = "bring_your_own_cloud",
            help = "Use local provisioner image (skip docker pull)"
        )]
        local: bool,
        #[arg(short, long, help = "Skip confirmation prompt")]
        force: bool,
    },
    #[command(
        about = "Verify enclave attestation against the local source at the manifest commit."
    )]
    Verify {
        #[arg(
            long,
            help = "Attestation endpoint URL (default: inferred from .caution/deployment)"
        )]
        attestation_url: Option<String>,
        #[arg(
            long,
            group = "verify_source",
            help = "Deprecated: local source is now the default"
        )]
        from_local: bool,
        #[arg(
            long,
            group = "verify_source",
            help = "Build from a local source tarball laid out like git archive"
        )]
        from_tarball: Option<PathBuf>,
        #[arg(
            long,
            group = "verify_source",
            help = "Git URL to fetch application source"
        )]
        app_source_url: Option<String>,
        #[arg(
            long,
            group = "verify_source",
            help = "Compare against PCRs from file without TLS certificate binding"
        )]
        pcrs: Option<String>,
        #[arg(long, help = "Force rebuild, ignore cache")]
        no_cache: bool,
        #[arg(
            long,
            help = "Deprecated: verified trust state is now saved automatically"
        )]
        save_pcrs: bool,
        #[arg(
            long,
            conflicts_with_all = [
                "from_local",
                "from_tarball",
                "app_source_url",
                "pcrs",
                "no_cache",
                "save_pcrs"
            ],
            help = "Print the unverified parsed remote attestation and exit"
        )]
        inspect_attestation: bool,
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
    #[command(about = "Manage OpenPGP public keys for your account")]
    PgpKeys {
        #[command(subcommand)]
        command: PgpKeyCommands,
    },
    #[command(about = "Manage local cache")]
    Cache {
        #[command(subcommand)]
        command: CacheCommands,
    },
    #[command(about = "Manage cloud provider credentials for BYOC deployments")]
    Credentials {
        #[command(subcommand)]
        command: CredentialCommands,
    },
    #[command(about = "Manage fully managed capacity requests")]
    Capacity {
        #[command(subcommand)]
        command: CapacityCommands,
    },
    #[command(about = "Manage cryptographic secrets", alias = "secrets")]
    Secret {
        #[command(subcommand)]
        command: SecretCommands,
    },
}

#[derive(Subcommand, Debug)]
enum AccountCommands {
    #[command(about = "Print the current account ID")]
    Id,
}

#[derive(Subcommand, Debug)]
enum AppCommands {
    #[command(about = "Create a new Caution-managed application")]
    Create,
    #[command(about = "List all applications")]
    List,
    #[command(about = "Get details of an application")]
    Get {
        #[arg(help = "App ID (default: from .caution/deployment)")]
        id: Option<String>,
        #[arg(
            long,
            help = "CI-only: allow SSH-signed API access without a logged-in session"
        )]
        this_is_a_ci_machine: bool,
    },
    #[command(about = "Destroy an application")]
    Destroy {
        #[arg(help = "App ID (default: from .caution/deployment)")]
        id: Option<String>,
        #[arg(short, long, help = "Skip confirmation prompt")]
        force: bool,
        #[arg(
            long,
            help = "After managed DNS withdrawal, delete from the database even if cloud cleanup fails"
        )]
        force_delete: bool,
        #[arg(
            long,
            help = "CI-only: allow SSH-signed API access without a logged-in session"
        )]
        this_is_a_ci_machine: bool,
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
    #[command(about = "Download the latest completed EIF for an app")]
    DownloadEif(apps::download_eif::DownloadEif),

    #[command(name = "migrate-procfile", about = "Convert a Procfile to caution.hcl")]
    MigrateProcfile(apps::migrate_procfile::MigrateProcfileArgs),
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
enum PgpKeyCommands {
    #[command(about = "Add an armored OpenPGP public key")]
    Add {
        #[arg(help = "Path to an armored OpenPGP public key file")]
        key_file: PathBuf,
        #[arg(long, help = "Name for the key")]
        name: Option<String>,
    },
    #[command(about = "List all OpenPGP public keys")]
    List,
    #[command(about = "Remove an OpenPGP public key")]
    Remove {
        #[arg(help = "Full key fingerprint")]
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
enum CapacityCommands {
    #[command(about = "Join the fully managed capacity notification waitlist")]
    Waitlist {
        #[arg(long, help = "Email address to notify when capacity is available")]
        email: String,
        #[arg(long, help = "Requested enclave vCPUs, up to 46")]
        vcpus: Option<u32>,
    },
}

#[derive(Subcommand, Debug)]
enum SecretCommands {
    #[command(about = "Generate unsafe plaintext Keymaker-compatible OpenPGP keyrings")]
    Keygen {
        #[arg(help = "Path to write the armored public keyring")]
        output: PathBuf,
        #[arg(
            long,
            help = "Path to write the armored private keyring (default: public path with .private before the extension)"
        )]
        private_keyring: Option<PathBuf>,
        #[arg(long, help = "Shard-holder display name")]
        name: String,
        #[arg(long, help = "Shard-holder email address")]
        email: String,
        #[arg(long, help = "Overwrite output files if they exist")]
        force: bool,
        #[arg(long, help = "Acknowledge unsafe plaintext private keyring generation")]
        shoot_self_in_foot: bool,
    },
    #[command(about = "Generate a new cryptographic quorum")]
    New {
        #[arg(help = "Path to armored PGP keyring file")]
        keyring: PathBuf,
        #[arg(long, requires = "max", help = "Minimum shares needed to reconstruct")]
        threshold: Option<u8>,
        #[arg(
            long,
            requires = "threshold",
            help = "Total shares to generate (defaults to the eligible cert count)"
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
    #[command(about = "Encrypt env file values into .caution/secrets/*.asc")]
    Encrypt {
        #[arg(help = "Env keys to encrypt (defaults to every key in the env file)")]
        keys: Vec<String>,
        #[arg(
            long = "env-file",
            default_value = ".env",
            value_name = "PATH",
            help = "Path to the env file to encrypt"
        )]
        env_file: PathBuf,
        #[arg(
            long,
            default_value = ".caution/quorum-bundle.json",
            value_name = "PATH",
            help = "Path to the Keymaker quorum bundle JSON"
        )]
        bundle: PathBuf,
        #[arg(
            long = "secrets-dir",
            default_value = ".caution/secrets",
            value_name = "PATH",
            help = "Directory for encrypted secret files"
        )]
        secrets_dir: PathBuf,
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
        #[arg(
            long,
            help = "Path for private OpenPGP Keyring (if not using smartcards)"
        )]
        keyring: Option<PathBuf>,
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

#[derive(Deserialize, Serialize, Debug)]
pub struct App {
    pub id: String,
    pub resource_name: Option<String>,
    pub state: String,
    pub provider_resource_id: String,
    pub public_ip: Option<String>,
    pub domain: Option<String>,
    #[serde(default)]
    pub managed_hostname: Option<String>,
    #[serde(default)]
    pub dns_status: Option<String>,
    #[serde(default)]
    pub dns_error: Option<String>,
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
    #[serde(default)]
    pub managed_hostname: Option<String>,
    #[serde(default)]
    pub dns_status: Option<String>,
    #[serde(default)]
    pub dns_error: Option<String>,
}

fn print_managed_dns_details(
    hostname: Option<&str>,
    status: Option<&str>,
    error: Option<&str>,
    domain: Option<&str>,
) {
    let Some(hostname) = hostname else {
        return;
    };
    output::status(["DNS target: ", hostname].concat());
    if let Some(status) = status {
        output::status(["Managed DNS: ", status].concat());
    }
    if let Some(error) = error {
        output::warning(["Managed DNS retry error: ", error].concat());
    }
    if let Some(domain) = domain {
        output::status(["Create a CNAME for ", domain, " pointing to ", hostname].concat());
    }
}

/// Minimal deployment info stored locally in .caution file
/// Contains only the resource ID - all other data is fetched fresh from API
#[derive(Serialize, Deserialize, Debug)]
struct DeploymentInfo {
    resource_id: String,
}

#[derive(Debug, PartialEq, Eq)]
struct CheckoutLink {
    deployment_file_exists: bool,
    resource_id: Option<String>,
    caution_remote: Option<String>,
    byoc_provider: bool,
}

impl CheckoutLink {
    fn is_linked(&self) -> bool {
        self.deployment_file_exists || self.caution_remote.is_some()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn blocks_explicit_byoc_creation(&self) -> bool {
        self.resource_id.is_none() && self.is_linked()
    }

    fn blocks_managed_creation(&self) -> bool {
        self.is_linked() || self.byoc_provider
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum InspectCheckoutLinkError {
    #[error("failed to check existing git remote [{location:?}]")]
    CheckRemote {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to list git remotes [{location:?}]")]
    ListRemotes {
        #[location]
        location: Location,
    },

    #[error("failed to read existing caution git remote [{location:?}]")]
    ReadCautionRemote {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to list caution git remotes [{location:?}]")]
    ListCautionRemotes {
        #[location]
        location: Location,
    },
}

#[cfg_attr(not(test), allow(dead_code))]
fn inspect_checkout_link(
    deployment_path: &Path,
    repo_dir: &Path,
    config: Option<&caution_config::ConfigurationFile>,
) -> Result<CheckoutLink, InspectCheckoutLinkError> {
    use InspectCheckoutLinkErrorCtx as Ctx;

    let deployment_file_exists = deployment_path.exists();
    let resource_id = if deployment_file_exists {
        fs::read_to_string(deployment_path)
            .ok()
            .and_then(|contents| serde_json::from_str::<DeploymentInfo>(&contents).ok())
            .and_then(|deployment| {
                uuid::Uuid::parse_str(&deployment.resource_id)
                    .ok()
                    .map(|id| id.to_string())
            })
    } else {
        None
    };
    let remotes = Command::new("git")
        .arg("-C")
        .arg(repo_dir)
        .arg("remote")
        .output()
        .with_context(Ctx::check_remote())?;
    if !remotes.status.success() {
        return Err(InspectCheckoutLinkError::ListRemotes {
            location: std::panic::Location::caller(),
        });
    }
    let has_caution_remote = String::from_utf8_lossy(&remotes.stdout)
        .lines()
        .any(|remote| remote.trim() == "caution");
    let caution_remote = if has_caution_remote {
        let remote = Command::new("git")
            .arg("-C")
            .arg(repo_dir)
            .args(["remote", "get-url", "caution"])
            .output()
            .with_context(Ctx::read_caution_remote())?;
        if !remote.status.success() {
            return Err(InspectCheckoutLinkError::ListCautionRemotes {
                location: std::panic::Location::caller(),
            });
        }
        Some(String::from_utf8_lossy(&remote.stdout).trim().to_string())
    } else {
        None
    };
    let byoc_provider = config
        .and_then(|config| config.caution.as_ref())
        .and_then(|caution| caution.provider.as_ref())
        .is_some();

    Ok(CheckoutLink {
        deployment_file_exists,
        resource_id,
        caution_remote,
        byoc_provider,
    })
}

fn linked_checkout_error(link: &CheckoutLink) -> String {
    let mut message = String::from(
        "Refusing to create a separate app because this checkout records an app identity or BYOC intent.",
    );
    if let Some(resource_id) = link.resource_id.as_deref() {
        message.push_str("\nLinked app: ");
        message.push_str(resource_id);
    } else if link.deployment_file_exists {
        message.push_str(
            "\n.caution/deployment.json exists but is unreadable; preserve and inspect it.",
        );
    }
    if let Some(remote) = link.caution_remote.as_deref() {
        message.push_str("\nExisting caution remote: ");
        message.push_str(remote);
    }
    if link.byoc_provider {
        message.push_str("\ncaution.hcl declares BYOC with caution.provider.");
    }
    if link.is_linked() {
        message.push_str(
            "\nFor a redeploy: `caution apps destroy <app-id>`, then `git push caution HEAD:main`. Do not run `caution apps create` or plain `caution init`. For BYOC apps, do not run `caution teardown --byoc`.",
        );
    } else if link.byoc_provider {
        message.push_str("\nUse `caution init --byoc`; `caution apps create` is managed capacity.");
    }
    message
}

fn deployment_target_summary(capacity: &str, aws_account: &str, region: &str) -> String {
    [
        "Deployment target: capacity=",
        capacity,
        ", aws_account=",
        aws_account,
        ", region=",
        region,
    ]
    .concat()
}

#[derive(Serialize, Deserialize)]
struct Config {
    session_id: String,
    expires_at: String,
    #[serde(default)]
    server_url: Option<String>,
}

impl Config {
    fn session_id(&self) -> &str {
        &self.session_id
    }
}

#[derive(Deserialize)]
struct CapacityWaitlistResponse {
    status: String,
}

#[derive(Debug, Deserialize)]
struct LegalAcceptanceRequiredError {
    code: String,
    document_type: String,
    message: Option<String>,
}

/// Body of the username-claim gate: `{"error":"username_required"}`, returned
/// by any protected endpoint (except username status/claim and logout) while
/// the authenticated user still has a placeholder username.
#[derive(Debug, Deserialize)]
struct UsernameRequiredError {
    error: String,
}

#[derive(Debug, Deserialize)]
struct PublicBuildInputs {
    platform: Option<PublicBuildInput>,
}

#[derive(Debug, Deserialize)]
struct PublicBuildInput {
    commit: String,
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error(
    "Invalid Platform framework commit {commit:?}; expected a 40-character Git SHA [{location:?}]"
)]
struct PinPlatformFrameworkSourceError {
    commit: String,
    #[location]
    location: Location,
    #[source]
    source: Option<BoxError>,
}

#[track_caller]
fn pinned_platform_framework_source(
    commit: &str,
) -> std::result::Result<String, PinPlatformFrameworkSourceError> {
    let normalized = commit.trim();
    if normalized.len() != 40 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(PinPlatformFrameworkSourceError {
            commit: commit.to_string(),
            location: std::panic::Location::caller(),
            source: None,
        });
    }
    Ok(enclave_builder::pin_archive_url_to_commit(
        enclave_builder::FRAMEWORK_SOURCE,
        &normalized.to_ascii_lowercase(),
    ))
}

#[derive(Debug, FromContext)]
enum CurrentPlatformFrameworkSourceErrorKind {
    InvalidServerUrl,
    FetchBuildInputs,
    BuildInputsStatus,
    DecodeBuildInputs,
    MissingPlatformCommit,
    PinFrameworkSource,
}

#[derive(Debug, thiserror::Error)]
#[error("Public build-input endpoint returned HTTP {status}")]
struct PublicBuildInputsStatusError {
    status: reqwest::StatusCode,
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error(
    "Unable to resolve the current Platform framework source from {endpoint}: {kind:?} [{location:?}]"
)]
pub(crate) struct CurrentPlatformFrameworkSourceError {
    #[context(from = CurrentPlatformFrameworkSourceErrorKindCtx)]
    kind: CurrentPlatformFrameworkSourceErrorKind,
    #[context(borrow = str)]
    endpoint: String,
    #[location]
    location: Location,
    #[source]
    source: Option<BoxError>,
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum RunError {
    #[error("dependency check failed [{location:?}]")]
    DependencyCheck {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("gateway connectivity check failed [{location:?}]")]
    GatewayConnectivity {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to initialize API client [{location:?}]")]
    ApiClientInit {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("{detail} [{location:?}]")]
    ArgValidation {
        detail: &'static str,
        #[location]
        location: Location,
    },

    #[error("command execution failed [{location:?}]")]
    CommandDispatch {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ReadConfigError {
    #[error("failed to read caution.hcl [{location:?}]")]
    ReadHcl {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("invalid caution.hcl [{location:?}]")]
    ParseHcl {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to read Procfile [{location:?}]")]
    ReadProcfile {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("invalid Procfile [{location:?}]")]
    ParseProcfile {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error(
        "no configuration file found; run `caution init` to generate a caution.hcl template [{location:?}]"
    )]
    ConfigNotFound {
        #[location]
        location: Location,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ReadConfigFromDirError {
    #[error("failed to read {path} [{location:?}]")]
    ReadHcl {
        path: PathBuf,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("invalid caution.hcl [{location:?}]")]
    ParseHcl {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to read {path} [{location:?}]")]
    ReadProcfile {
        path: PathBuf,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("invalid Procfile [{location:?}]")]
    ParseProcfile {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error(
        "no configuration file found in {path}; create a caution.hcl or Procfile file [{location:?}]"
    )]
    ConfigNotFound {
        path: PathBuf,
        #[location]
        location: Location,
    },
}

struct ApiClient {
    base_url: String,
    client: reqwest::Client,
    config_path: PathBuf,
    deployment_path: Option<PathBuf>,
    verbose: bool,
    qr: bool,
    workdir: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ApiClientNewError {
    #[error("could not find config directory [{location:?}]")]
    ConfigDir {
        #[location]
        location: Location,
    },

    #[error("failed to create config directory [{location:?}]")]
    CreateConfigDir {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum GetDeploymentPathError {
    #[error(
        "cannot access current directory. Please run this command from a valid directory [{location:?}]"
    )]
    MissingCwd { location: Location },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SaveConfigError {
    #[error("failed to serialize config [{location:?}]")]
    Serialize {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to open config file '{path}' [{location:?}]")]
    Open {
        #[context(borrow = Path)]
        path: PathBuf,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to write config file [{location:?}]")]
    Write {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum LoadConfigError {
    #[error("not logged in. Run 'login' command first [{location:?}]")]
    ReadConfig {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to parse config file '{path}' [{location:?}]")]
    Parse {
        #[context(borrow = Path)]
        path: PathBuf,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum EnsureAuthenticatedError {
    #[error("QR login failed [{location:?}]")]
    LoginQr {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("login failed [{location:?}]")]
    Login {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to load config after authenticating [{location:?}]")]
    LoadConfig {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum RequireExistingAuthenticatedConfigError {
    #[error("failed to load config [{location:?}]")]
    LoadConfig {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("session expired. Run 'login' command first [{location:?}]")]
    SessionExpired {
        #[location]
        location: Location,
    },

    #[error("session is for a different server. Run 'login' command first [{location:?}]")]
    DifferentServer {
        #[location]
        location: Location,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SaveDeploymentError {
    #[error("failed to get deployment path [{location:?}]")]
    GetDeploymentPath {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to serialize deployment info [{location:?}]")]
    Serialize {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to write deployment info to '{path}' [{location:?}]")]
    Write {
        #[context(borrow = Path)]
        path: PathBuf,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum LoadDeploymentError {
    #[error("failed to get deployment path [{location:?}]")]
    GetDeploymentPath {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("no deployment found. Run 'init' first [{location:?}]")]
    ReadFile {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to parse deployment info [{location:?}]")]
    Parse {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum PublicKeyForIdentityError {
    #[error("failed to read SSH public key '{path}' [{location:?}]")]
    ReadFile {
        #[context(borrow = Path)]
        path: PathBuf,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to run ssh-keygen to derive SSH public key [{location:?}]")]
    RunSshKeygen {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to derive SSH public key [{location:?}]")]
    DeriveFailed {
        stderr: String,
        #[location]
        location: Location,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SshFingerprintError {
    #[error("invalid SSH public key [{location:?}]")]
    Decode {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SignSshPayloadError {
    #[error("failed to create SSH signing temp dir [{location:?}]")]
    TempDir {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to write SSH signing payload [{location:?}]")]
    WritePayload {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to run ssh-keygen for SSH request signing [{location:?}]")]
    RunSshKeygen {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to sign request with SSH key [{location:?}]")]
    SignFailed {
        stderr: String,
        #[location]
        location: Location,
    },

    #[error("failed to read SSH signature '{path}' [{location:?}]")]
    ReadSignature {
        #[context(borrow = Path)]
        path: PathBuf,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum CheckGitRepoError {
    #[error("failed to execute git command. Is git installed? [{location:?}]")]
    RunGitCommand {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error(
        "not in a git repository. Please run this command from within a git repository [{location:?}]"
    )]
    NotGitRepo {
        #[location]
        location: Location,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SetGitRemoteError {
    #[error("failed to check existing git remote [{location:?}]")]
    CheckRemote {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to update git remote 'caution' [{location:?}]")]
    UpdateRemote {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to add git remote 'caution' [{location:?}]")]
    AddRemote {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum CreateConfigFileInDirIfNeededError {
    #[error("failed to create caution.hcl [{location:?}]")]
    WriteConfig {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GitUrlToArchiveUrlsError {
    #[error("failed to parse git URL [{location:?}]")]
    ParseUrl {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("invalid git URL format [{location:?}]")]
    InvalidUrlFormat {
        #[location]
        location: Location,
    },

    #[error("invalid git SSH URL format [{location:?}]")]
    InvalidSSHFormat {
        #[location]
        location: Location,
    },

    #[error("git URL has no host [{location:?}]")]
    NoHost {
        #[location]
        location: Location,
    },

    #[error("unsupported git URL format: {url} [{location:?}]")]
    UnsupportedFormat {
        url: String,
        #[location]
        location: Location,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SignedRequestError {
    #[error("failed to get FIDO2 sign challenge [{location:?}]")]
    GetSignChallenge {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to get sign challenge: {error} [{location:?}]")]
    ChallengeFailure {
        error: String,
        #[location]
        location: Location,
    },

    #[error("failed to parse FIDO2 sign response [{location:?}]")]
    ParseSignResponse {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to get FIDO2 assertion [{location:?}]")]
    GetAssertion {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to send signed request [{location:?}]")]
    SendRequest {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SignedPostError {
    #[error("failed to serialize request body [{location:?}]")]
    SerializeBody {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to serialize request body for display [{location:?}]")]
    SerializePretty {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("signed request failed [{location:?}]")]
    SignedRequest {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SignedDeleteError {
    #[error("signed request failed [{location:?}]")]
    SignedRequest {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetProtectedJsonError {
    #[error("{failure_context} [{location:?}]")]
    SendRequest {
        #[context(borrow = str)]
        failure_context: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to read response body [{location:?}]")]
    ReadBody {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("{failure_context} [{location:?}]")]
    ParseJson {
        #[context(borrow = str)]
        failure_context: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("{failure_context}: {api_response} [{location:?}]")]
    ApiFailure {
        #[context(borrow = str)]
        failure_context: String,
        api_response: String,
        #[location]
        location: Location,
    },

    #[error("{failure_context} [{location:?}]")]
    ClaimUsername {
        #[context(borrow = str)]
        failure_context: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum JoinCapacityWaitlistError {
    #[error("--email must not be empty [{location:?}]")]
    EmptyEmail {
        #[location]
        location: Location,
    },

    #[error("--email is invalid [{location:?}]")]
    InvalidEmail {
        #[location]
        location: Location,
    },

    #[error("--email must be an email address [{location:?}]")]
    NoAtSymbol {
        #[location]
        location: Location,
    },

    #[error("--vcpus must be between 1 and 46; contact support for larger requests [{location:?}]")]
    InvalidVcpus {
        vcpus: u32,
        #[location]
        location: Location,
    },

    #[error("authentication failed [{location:?}]")]
    EnsureAuthenticated {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to determine organization [{location:?}]")]
    GetOrgId {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to send capacity waitlist request [{location:?}]")]
    SendRequest {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to join capacity waitlist: {error} [{location:?}]")]
    ApiFailure {
        error: String,
        #[location]
        location: Location,
    },

    #[error("failed to parse capacity waitlist response [{location:?}]")]
    ParseResponse {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum FetchAppError {
    #[error("authentication failed [{location:?}]")]
    EnsureAuthenticated {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to fetch app [{location:?}]")]
    GetProtectedJson {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetCurrentAppError {
    #[error("failed to load deployment [{location:?}]")]
    LoadDeployment {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to fetch app [{location:?}]")]
    FetchApp {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetAttestationUrlError {
    #[error("failed to get current app [{location:?}]")]
    GetCurrentApp {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error(
        "no public IP available. Run 'caution app get <id/null>' to check deployment status, or provide --url explicitly [{location:?}]"
    )]
    NoPublicIp {
        #[location]
        location: Location,
    },
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum GetCacheDirError {
    #[error("failed to determine home directory [{location:?}]")]
    HomeDir { location: Location },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ResolveProcfileBuildCommandError {
    #[error(
        "Procfile has empty build command. Expected format: build: docker build -t myapp . [{location:?}]"
    )]
    EmptyBuildCommand {
        #[location]
        location: Location,
    },

    #[error(
        "Procfile has empty containerfile path. Expected format: containerfile: Containerfile [{location:?}]"
    )]
    EmptyContainerfile {
        #[location]
        location: Location,
    },

    #[error("Procfile field `containerfile:` points to missing file: {path} [{location:?}]")]
    MissingContainerfile {
        path: String,
        #[location]
        location: Location,
    },

    #[error("invalid containerfile path [{location:?}]")]
    InvalidContainerfile {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ResolveLocalBuildCommandFromDirError {
    #[error("failed to read caution.hcl [{location:?}]")]
    ReadCautionHcl {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("invalid caution.hcl [{location:?}]")]
    ParseCautionHcl {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to read Procfile [{location:?}]")]
    ReadProcfile {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("no caution.hcl or Procfile found [{location:?}]")]
    NoConfigFound {
        #[location]
        location: Location,
    },

    #[error("caution.hcl `containerfile` points to missing file: {path} [{location:?}]")]
    MissingContainerfile {
        path: String,
        #[location]
        location: Location,
    },

    #[error("invalid containerfile path [{location:?}]")]
    InvalidContainerfile {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to resolve build command [{location:?}]")]
    ProcfileResolve {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl ApiClient {
    fn new(
        base_url: &str,
        verbose: bool,
        qr: bool,
        workdir: Option<PathBuf>,
    ) -> Result<Self, ApiClientNewError> {
        use ApiClientNewErrorCtx as Ctx;

        output::verbose(verbose, "Initializing API client...");

        let base_config = dirs::config_dir().ok_or_else(|| ApiClientNewError::ConfigDir {
            location: std::panic::Location::caller(),
        })?;
        let legacy_dir = base_config.join("api-cli");
        let config_dir = base_config.join("caution-cli");

        // Migrate from the old api-cli directory name if present
        if legacy_dir.exists() && !config_dir.exists() {
            if let Err(e) = fs::rename(&legacy_dir, &config_dir) {
                output::warning(format!(
                    "Warning: could not migrate config from {} to {}: {e}. You may need to log in again.",
                    legacy_dir.display(),
                    config_dir.display()
                ));
            }
        }

        output::verbose(verbose, &format!("Config directory: {:?}", config_dir));

        fs::create_dir_all(&config_dir).with_context(Ctx::create_config_dir())?;
        let config_path = config_dir.join("config.json");

        // Local deployment info in the current git repo (optional - may not have a valid cwd)
        let deployment_path = std::env::current_dir().ok().map(|current_dir| {
            let caution_dir = current_dir.join(".caution");
            // Try to create the directory, but don't fail if we can't
            let _ = fs::create_dir_all(&caution_dir);
            caution_dir.join("deployment.json")
        });

        output::verbose(verbose, &format!("Config file: {:?}", config_path));
        output::verbose(verbose, &format!("Deployment file: {:?}", deployment_path));
        if let Some(ref wd) = workdir {
            output::verbose(verbose, &format!("Working directory: {:?}", wd));
        }
        output::verbose(verbose, "API client initialized");

        Ok(Self {
            base_url: base_url.to_string(),
            // A connect timeout bounds the TCP+TLS handshake for every request so
            // an unresponsive host (e.g. an enclave IP that accepts the connection
            // but never replies) can't hang the CLI forever. It does not cap body
            // transfer, so large downloads are unaffected.
            client: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            config_path,
            deployment_path,
            verbose,
            qr,
            workdir,
        })
    }

    fn http_client(&self) -> &reqwest::Client {
        &self.client
    }

    fn api_base_url(&self) -> &str {
        &self.base_url
    }

    async fn current_platform_framework_source(
        &self,
    ) -> std::result::Result<(String, String), CurrentPlatformFrameworkSourceError> {
        use CurrentPlatformFrameworkSourceErrorCtx as Ctx;
        use CurrentPlatformFrameworkSourceErrorKindCtx as KindCtx;

        let mut endpoint = reqwest::Url::parse(&self.base_url)
            .with_context(Ctx::new(KindCtx::invalid_server_url(), &self.base_url))?;
        endpoint.set_path("/.well-known/caution/build-inputs");
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        let response = self
            .client
            .get(endpoint.clone())
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .with_context(Ctx::new(KindCtx::fetch_build_inputs(), endpoint.as_str()))?;
        if !response.status().is_success() {
            return Err(CurrentPlatformFrameworkSourceError {
                kind: KindCtx::build_inputs_status().into(),
                endpoint: endpoint.as_str().to_string(),
                location: std::panic::Location::caller(),
                source: Some(Box::new(PublicBuildInputsStatusError {
                    status: response.status(),
                })),
            });
        }
        let inputs: PublicBuildInputs = response
            .json()
            .await
            .with_context(Ctx::new(KindCtx::decode_build_inputs(), endpoint.as_str()))?;
        let commit = inputs
            .platform
            .ok_or_else(|| CurrentPlatformFrameworkSourceError {
                kind: KindCtx::missing_platform_commit().into(),
                endpoint: endpoint.as_str().to_string(),
                location: std::panic::Location::caller(),
                source: None,
            })?
            .commit;
        let source = pinned_platform_framework_source(&commit)
            .with_context(Ctx::new(KindCtx::pin_framework_source(), endpoint.as_str()))?;
        let commit = commit.trim().to_ascii_lowercase();
        Ok((commit, source))
    }

    /// Get deployment path, creating .caution directory if needed
    fn get_deployment_path(&self) -> Result<&PathBuf, GetDeploymentPathError> {
        self.deployment_path
            .as_ref()
            .ok_or_else(|| GetDeploymentPathError::MissingCwd {
                location: std::panic::Location::caller(),
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
        self.format_api_error(status, &body)
    }

    fn format_api_error(&self, status: reqwest::StatusCode, body: &str) -> String {
        if status == reqwest::StatusCode::FORBIDDEN {
            if let Ok(payload) = serde_json::from_str::<LegalAcceptanceRequiredError>(body) {
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
            body.to_string()
        }
    }

    /// Whether `body` is the username-claim gate response
    /// (`{"error":"username_required"}`) returned with HTTP 403.
    fn is_username_required(status: reqwest::StatusCode, body: &str) -> bool {
        status == reqwest::StatusCode::FORBIDDEN
            && serde_json::from_str::<UsernameRequiredError>(body)
                .map(|e| e.error == "username_required")
                .unwrap_or(false)
    }

    /// Prompts for a username and claims it via `POST /user/username`
    /// (a FIDO2-signed protected mutation), reprompting on 409 (taken).

    /// GETs `path` with the session header, transparently handling the
    /// username-claim gate: on 403 `username_required`, prompts for and
    /// claims a username, then retries the request once.
    async fn get_protected_json<T: serde::de::DeserializeOwned>(
        &self,
        session_id: &str,
        path: &str,
        failure_context: &str,
    ) -> Result<T, GetProtectedJsonError> {
        use GetProtectedJsonErrorCtx as Ctx;

        let mut gate_claimed = false;

        loop {
            let response = self
                .client
                .get(format!("{}{}", self.base_url, path))
                .header("X-Session-ID", session_id)
                .send()
                .await
                .with_context(Ctx::send_request(failure_context))?;

            let status = response.status();
            let body = response.text().await.with_context(Ctx::read_body())?;

            if status.is_success() {
                return serde_json::from_str(&body).with_context(Ctx::parse_json(failure_context));
            }

            if !gate_claimed && Self::is_username_required(status, &body) {
                gate_claimed = true;
                auth::claim_username_interactively(self, session_id)
                    .await
                    .with_context(Ctx::claim_username(failure_context))?;
                continue;
            }

            return Err(GetProtectedJsonError::ApiFailure {
                failure_context: failure_context.to_string(),
                api_response: self.format_api_error(status, &body),
                location: std::panic::Location::caller(),
            });
        }
    }

    fn save_config(&self, session_id: String, expires_at: String) -> Result<(), SaveConfigError> {
        use SaveConfigErrorCtx as Ctx;

        let config = Config {
            session_id,
            expires_at,
            server_url: Some(self.base_url.clone()),
        };

        let json = serde_json::to_string_pretty(&config).with_context(Ctx::serialize())?;

        // Write with restricted permissions so other users cannot read session tokens
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&self.config_path)
                .with_context(Ctx::open(&self.config_path))?;
            file.write_all(json.as_bytes()).with_context(Ctx::write())?;
        }

        Ok(())
    }

    fn load_config(&self) -> Result<Config, LoadConfigError> {
        use LoadConfigErrorCtx as Ctx;

        let content = fs::read_to_string(&self.config_path).with_context(Ctx::read_config())?;
        let config: Config =
            serde_json::from_str(&content).with_context(Ctx::parse(&self.config_path))?;
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

    async fn ensure_authenticated(&self) -> Result<Config, EnsureAuthenticatedError> {
        use EnsureAuthenticatedErrorCtx as Ctx;

        match self.load_config() {
            Ok(config) if !self.is_session_expired(&config) && self.is_same_server(&config) => {
                Ok(config)
            }
            _ => {
                if self.qr {
                    auth::login_qr(self, None)
                        .await
                        .with_context(Ctx::login_qr())?;
                } else {
                    auth::login(self, None).await.with_context(Ctx::login())?;
                }
                self.load_config().with_context(Ctx::load_config())
            }
        }
    }

    fn require_existing_authenticated_config(
        &self,
    ) -> Result<Config, RequireExistingAuthenticatedConfigError> {
        use RequireExistingAuthenticatedConfigErrorCtx as Ctx;

        let config = self.load_config().with_context(Ctx::load_config())?;
        if self.is_session_expired(&config) {
            return Err(RequireExistingAuthenticatedConfigError::SessionExpired {
                location: std::panic::Location::caller(),
            });
        }
        if !self.is_same_server(&config) {
            return Err(RequireExistingAuthenticatedConfigError::DifferentServer {
                location: std::panic::Location::caller(),
            });
        }
        Ok(config)
    }

    fn is_same_server(&self, config: &Config) -> bool {
        config
            .server_url
            .as_ref()
            .map_or(true, |url| url == &self.base_url)
    }

    fn save_deployment(&self, resource_id: &str) -> Result<(), SaveDeploymentError> {
        use SaveDeploymentErrorCtx as Ctx;

        let deployment_path = self
            .get_deployment_path()
            .with_context(Ctx::get_deployment_path())?;
        let deployment_info = DeploymentInfo {
            resource_id: resource_id.to_string(),
        };
        let json = serde_json::to_string_pretty(&deployment_info).with_context(Ctx::serialize())?;
        fs::write(deployment_path, json).with_context(Ctx::write(deployment_path))?;
        output::verbose(
            self.verbose,
            &format!("Saved deployment info to {:?}", deployment_path),
        );
        Ok(())
    }

    fn load_deployment(&self) -> Result<DeploymentInfo, LoadDeploymentError> {
        use LoadDeploymentErrorCtx as Ctx;

        let deployment_path = self
            .get_deployment_path()
            .with_context(Ctx::get_deployment_path())?;
        let content = fs::read_to_string(deployment_path).with_context(Ctx::read_file())?;
        let deployment_info: DeploymentInfo =
            serde_json::from_str(&content).with_context(Ctx::parse())?;
        Ok(deployment_info)
    }

    fn read_config(&self) -> Result<caution_config::ConfigurationFile, ReadConfigError> {
        use ReadConfigErrorCtx as Ctx;
        use std::path::Path;

        let hcl_path = Path::new("caution.hcl");
        if hcl_path.exists() {
            let content = std::fs::read_to_string(hcl_path).with_context(Ctx::read_hcl())?;
            let config = caution_config::ConfigurationFile::from_str(&content)
                .with_context(Ctx::parse_hcl())?;
            return Ok(config);
        }

        let procfile_path = Path::new("Procfile");
        if procfile_path.exists() {
            let content =
                std::fs::read_to_string(procfile_path).with_context(Ctx::read_procfile())?;
            let config = caution_config::ConfigurationFile::from_procfile(&content)
                .with_context(Ctx::parse_procfile())?;
            return Ok(config);
        }

        Err(ReadConfigError::ConfigNotFound {
            location: std::panic::Location::caller(),
        })
    }

    fn read_config_from_dir(
        &self,
        dir: &Path,
    ) -> Result<caution_config::ConfigurationFile, ReadConfigFromDirError> {
        use ReadConfigFromDirErrorCtx as Ctx;

        let hcl_path = dir.join("caution.hcl");
        if hcl_path.exists() {
            let content =
                std::fs::read_to_string(&hcl_path).with_context(Ctx::read_hcl(hcl_path.clone()))?;
            let config = caution_config::ConfigurationFile::from_str(&content)
                .with_context(Ctx::parse_hcl())?;
            return Ok(config);
        }

        let procfile_path = dir.join("Procfile");
        if procfile_path.exists() {
            let content = std::fs::read_to_string(&procfile_path)
                .with_context(Ctx::read_procfile(procfile_path.clone()))?;
            let config = caution_config::ConfigurationFile::from_procfile(&content)
                .with_context(Ctx::parse_procfile())?;
            return Ok(config);
        }

        Err(ReadConfigFromDirError::ConfigNotFound {
            path: dir.to_path_buf(),
            location: std::panic::Location::caller(),
        })
    }

    fn read_caution_git_remote(&self) -> Option<String> {
        let output = Command::new("git")
            .args(["remote", "get-url", "caution"])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if url.is_empty() { None } else { Some(url) }
    }

    fn ssh_args_identity_file(args: &[String]) -> Option<PathBuf> {
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            if arg == "-i" {
                if let Some(value) = iter.next() {
                    return Some(Self::expand_identity_path(value));
                }
            } else if let Some(value) = arg.strip_prefix("-i") {
                if !value.is_empty() {
                    return Some(Self::expand_identity_path(value));
                }
            }

            if arg == "-o" {
                if let Some(value) = iter.next() {
                    if let Some(identity) = Self::identity_from_ssh_option(value) {
                        return Some(identity);
                    }
                }
            } else if let Some(value) = arg.strip_prefix("-o") {
                if let Some(identity) = Self::identity_from_ssh_option(value) {
                    return Some(identity);
                }
            }
        }
        None
    }

    fn identity_from_ssh_option(option: &str) -> Option<PathBuf> {
        let (key, value) = option.split_once('=')?;
        if key.eq_ignore_ascii_case("identityfile") && !value.is_empty() {
            Some(Self::expand_identity_path(value))
        } else {
            None
        }
    }

    fn expand_identity_path(path: &str) -> PathBuf {
        if let Some(rest) = path.strip_prefix("~/") {
            if let Some(home) = dirs::home_dir() {
                return home.join(rest);
            }
        }
        PathBuf::from(path)
    }

    fn identity_from_ssh_command(command: &str) -> Option<PathBuf> {
        let parts = shlex::split(command)?;
        if parts.len() <= 1 {
            return None;
        }
        Self::ssh_args_identity_file(&parts[1..])
    }

    fn configured_ssh_signing_identity(&self) -> Option<PathBuf> {
        if let Ok(path) = std::env::var("CAUTION_SSH_SIGNING_KEY") {
            let trimmed = path.trim();
            if !trimmed.is_empty() {
                let path = Self::expand_identity_path(trimmed);
                if path.exists() {
                    return Some(path);
                }
            }
        }

        if let Ok(command) = std::env::var("GIT_SSH_COMMAND") {
            if let Some(path) = Self::identity_from_ssh_command(&command) {
                if path.exists() {
                    return Some(path);
                }
            }
        }

        if let Ok(output) = Command::new("git")
            .args(["config", "--get", "core.sshCommand"])
            .output()
        {
            if output.status.success() {
                let command = String::from_utf8_lossy(&output.stdout);
                if let Some(path) = Self::identity_from_ssh_command(command.trim()) {
                    if path.exists() {
                        return Some(path);
                    }
                }
            }
        }

        if self.read_caution_git_remote().is_some() {
            for name in ["id_ed25519", "id_ecdsa", "id_rsa"] {
                if let Some(home) = dirs::home_dir() {
                    let path = home.join(".ssh").join(name);
                    if path.exists() {
                        return Some(path);
                    }
                }
            }
        }

        None
    }

    fn signing_key_path(identity: &Path) -> PathBuf {
        if identity.extension().is_some_and(|ext| ext == "pub") {
            identity.to_path_buf()
        } else {
            let public_key = PathBuf::from(format!("{}.pub", identity.display()));
            if public_key.exists() {
                public_key
            } else {
                identity.to_path_buf()
            }
        }
    }

    fn public_key_for_identity(identity: &Path) -> Result<String, PublicKeyForIdentityError> {
        use PublicKeyForIdentityErrorCtx as Ctx;

        let public_key_path = if identity.extension().is_some_and(|ext| ext == "pub") {
            identity.to_path_buf()
        } else {
            PathBuf::from(format!("{}.pub", identity.display()))
        };

        if public_key_path.exists() {
            return Ok(fs::read_to_string(&public_key_path)
                .with_context(Ctx::read_file(&public_key_path))?
                .trim()
                .to_string());
        }

        let output = Command::new("ssh-keygen")
            .arg("-y")
            .arg("-f")
            .arg(identity)
            .output()
            .with_context(Ctx::run_ssh_keygen())?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(PublicKeyForIdentityError::DeriveFailed {
                stderr,
                location: std::panic::Location::caller(),
            });
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    fn ssh_fingerprint(public_key: &str) -> Result<String, SshFingerprintError> {
        use SshFingerprintErrorCtx as Ctx;

        let parts: Vec<&str> = public_key.split_whitespace().collect();
        let key_data = if parts.len() >= 2 {
            parts[1]
        } else {
            public_key.trim()
        };
        let decoded = general_purpose::STANDARD
            .decode(key_data)
            .with_context(Ctx::decode())?;
        Ok(general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(&decoded)))
    }

    fn ssh_key_identity(public_key: &str) -> Option<String> {
        let parts: Vec<&str> = public_key.trim().split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }
        Some(format!("{} {}", parts[0], parts[1]))
    }

    fn canonical_ssh_request(method: &str, path: &str, timestamp: u64, body: &[u8]) -> String {
        let canonical_path = path.strip_prefix("/api").unwrap_or(path);
        let body_hash = hex::encode(Sha256::digest(body));
        format!("caution-ssh-http-v1\n{method}\n{canonical_path}\n{timestamp}\n{body_hash}\n")
    }

    fn sign_ssh_payload(identity: &Path, payload: &str) -> Result<String, SignSshPayloadError> {
        use SignSshPayloadErrorCtx as Ctx;

        let signing_key = Self::signing_key_path(identity);
        let temp_dir = tempfile::tempdir().with_context(Ctx::temp_dir())?;
        let payload_path = temp_dir.path().join("request.txt");
        fs::write(&payload_path, payload).with_context(Ctx::write_payload())?;

        let output = Command::new("ssh-keygen")
            .arg("-Y")
            .arg("sign")
            .arg("-f")
            .arg(&signing_key)
            .arg("-n")
            .arg(SSH_SIGNING_NAMESPACE)
            .arg(&payload_path)
            .output()
            .with_context(Ctx::run_ssh_keygen())?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(SignSshPayloadError::SignFailed {
                stderr,
                location: std::panic::Location::caller(),
            });
        }

        let signature_path = payload_path.with_extension("txt.sig");
        let signature =
            fs::read(&signature_path).with_context(Ctx::read_signature(&signature_path))?;
        Ok(general_purpose::URL_SAFE_NO_PAD.encode(signature))
    }

    async fn ssh_signed_request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> std::result::Result<Option<reqwest::Response>, SshSignedRequestError> {
        use SshSignedRequestErrorCtx as Ctx;
        use SshSignedRequestErrorKindCtx as KindCtx;

        let Some(identity) = self.configured_ssh_signing_identity() else {
            return Ok(None);
        };

        let body = body.unwrap_or_default();
        let public_key = Self::public_key_for_identity(&identity).with_context(Ctx::new(
            KindCtx::public_key_for_identity(),
            method.clone(),
            path,
            &identity,
        ))?;
        let fingerprint = Self::ssh_fingerprint(&public_key).with_context(Ctx::new(
            KindCtx::fingerprint_public_key(),
            method.clone(),
            path,
            &identity,
        ))?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .with_context(Ctx::new(
                KindCtx::system_clock_before_unix_epoch(),
                method.clone(),
                path,
                &identity,
            ))?
            .as_secs();
        let payload = Self::canonical_ssh_request(method.as_str(), path, timestamp, &body);
        let signature = Self::sign_ssh_payload(&identity, &payload).with_context(Ctx::new(
            KindCtx::sign_payload(),
            method.clone(),
            path,
            &identity,
        ))?;

        output::verbose(
            self.verbose,
            &format!("Sending SSH-signed HTTPS request for {}", path),
        );

        let mut request = self
            .client
            .request(method.clone(), format!("{}{}", self.base_url, path))
            .header("X-Caution-SSH-Key-Fingerprint", fingerprint)
            .header("X-Caution-SSH-Timestamp", timestamp.to_string())
            .header("X-Caution-SSH-Signature", signature);

        if !body.is_empty() {
            request = request
                .header("Content-Type", "application/json")
                .body(body);
        }

        Ok(Some(request.send().await.with_context(Ctx::new(
            KindCtx::send_request(),
            method,
            path,
            &identity,
        ))?))
    }

    async fn fetch_app_via_ssh_https(
        &self,
        id: &str,
    ) -> std::result::Result<Option<App>, FetchAppViaSshHttpsError> {
        use FetchAppViaSshHttpsErrorCtx as Ctx;
        use FetchAppViaSshHttpsErrorKindCtx as KindCtx;

        let path = format!("/api/resources/{}", id);
        let Some(response) = self
            .ssh_signed_request(reqwest::Method::GET, &path, None)
            .await
            .with_context(Ctx::new(KindCtx::send_signed_request(), id, &path))?
        else {
            return Ok(None);
        };

        if response.status().is_success() {
            Ok(Some(response.json().await.with_context(Ctx::new(
                KindCtx::decode_response(),
                id,
                &path,
            ))?))
        } else {
            let status = response.status();
            let message = self.api_error_message(response).await;
            Err(FetchAppViaSshHttpsError {
                kind: FetchAppViaSshHttpsErrorKind::ApiStatus { status, message },
                id: id.to_string(),
                path: path.clone(),
                location: std::panic::Location::caller(),
                source: None,
            })
        }
    }

    async fn destroy_app_via_ssh_https(
        &self,
        id: &str,
        force_delete: bool,
    ) -> std::result::Result<bool, DestroyAppViaSshHttpsError> {
        use DestroyAppViaSshHttpsErrorCtx as Ctx;
        use DestroyAppViaSshHttpsErrorKindCtx as KindCtx;

        let path = if force_delete {
            format!("/api/resources/{}?force=true", id)
        } else {
            format!("/api/resources/{}", id)
        };
        let Some(response) = self
            .ssh_signed_request(reqwest::Method::DELETE, &path, None)
            .await
            .with_context(Ctx::new(
                KindCtx::send_signed_request(),
                id,
                &path,
                force_delete,
            ))?
        else {
            return Ok(false);
        };

        if response.status().is_success() {
            Ok(true)
        } else {
            let status = response.status();
            let message = self.api_error_message(response).await;
            Err(DestroyAppViaSshHttpsError {
                kind: DestroyAppViaSshHttpsErrorKind::ApiStatus { status, message },
                id: id.to_string(),
                path: path.clone(),
                force_delete,
                location: std::panic::Location::caller(),
                source: None,
            })
        }
    }

    fn check_git_repo(&self) -> Result<(), CheckGitRepoError> {
        use CheckGitRepoErrorCtx as Ctx;

        let output = Command::new("git")
            .args(&["rev-parse", "--is-inside-work-tree"])
            .output()
            .with_context(Ctx::run_git_command())?;

        if !output.status.success() {
            return Err(CheckGitRepoError::NotGitRepo {
                location: std::panic::Location::caller(),
            });
        }

        Ok(())
    }

    fn set_git_remote(&self, git_url: &str) -> Result<(), SetGitRemoteError> {
        use SetGitRemoteErrorCtx as Ctx;

        let check_output = Command::new("git")
            .args(&["remote", "get-url", "caution"])
            .output()
            .with_context(Ctx::check_remote())?;

        if check_output.status.success() {
            Command::new("git")
                .args(&["remote", "set-url", "caution", git_url])
                .output()
                .with_context(Ctx::update_remote())?;

            output::success(format!("Updated git remote 'caution' to: {}", git_url));
        } else {
            Command::new("git")
                .args(&["remote", "add", "caution", git_url])
                .output()
                .with_context(Ctx::add_remote())?;

            output::success(format!("Added git remote 'caution': {}", git_url));
        }

        Ok(())
    }

    fn generate_config_hcl(source_url: &str, byoc: bool) -> String {
        let byoc_section = if byoc {
            r#"
caution {
  provider {
    type         = "aws"
    region       = "us-east-1"
    # vpc_id        = "vpc-xxxxxxxxx"
    # subnet_ids    = ["subnet-xxxxxxxxx"]
    # security_group_id = "sg-xxxxxxxxx"
  }
}
"#
        } else {
            ""
        };

        format!(
            r#"# Caution configuration - https://docs.caution.co/reference/caution-hcl/

enclave "default" {{
  build {{
    # containerfile = "Containerfile"   # defaults to repo-root Containerfile/Dockerfile
    # app_sources = ["{source_url}"]    # git URLs published in unsigned response metadata
    # cache       = true
  }}

  resources {{
    cpu       = 2
    memory_mb = 512
  }}

  network {{
    ingress {{
      cidr_ipv4 = "0.0.0.0/0"
      port      = 8080
    }}

    # http {{
    #   domain = "app.example.com"
    #   port   = 8080
    #   e2e_encryption {{
    #     enabled      = true
    #     cors_origins = ["https://app.example.com"]
    #     key_exchange = "x25519"
    #     allow_plaintext_fallback = false
    #   }}
    # }}
  }}

  # debug {{
  #   enabled  = true
  #   ssh_keys = ["ssh-ed25519 AAAA..."]
  # }}

  unit "default" {{
    command = "/app/myapp"
    # args = []
    # env = {{
    #   API_KEY = env::vault("API_KEY")   # using env::vault enables Locksmith secrets
    # }}
  }}
}}
{byoc_section}"#
        )
    }

    fn create_config_file_if_needed(
        &self,
        byoc: bool,
    ) -> Result<(), CreateConfigFileInDirIfNeededError> {
        use std::path::Path;

        self.create_config_file_in_dir_if_needed(Path::new("."), byoc)
    }

    fn create_config_file_in_dir_if_needed(
        &self,
        dir: &Path,
        byoc: bool,
    ) -> Result<(), CreateConfigFileInDirIfNeededError> {
        use CreateConfigFileInDirIfNeededErrorCtx as Ctx;

        let config_path = dir.join("caution.hcl");

        if config_path.exists() {
            output::verbose(
                self.verbose,
                "caution.hcl already exists, skipping creation",
            );
            return Ok(());
        }

        let source_url = self
            .detect_source_url()
            .unwrap_or_else(|| "git@codeberg.org:user/repo.git".to_string());

        let hcl_content = Self::generate_config_hcl(&source_url, byoc);

        fs::write(&config_path, hcl_content).with_context(Ctx::write_config())?;

        output::success("\nCreated caution.hcl in current directory");
        output::status("Edit the unit \"default\" command to match your application");
        output::status(
            "Build file precedence: containerfile: -> repo-root Containerfile -> Dockerfile",
        );
        if byoc {
            output::status("Configure AWS deployment settings in the BYOC section");
        }
        output::status("Learn more: https://docs.caution.co/reference/caution-hcl/");

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

    fn git_url_to_archive_urls(
        &self,
        git_url: &str,
        commit: &str,
    ) -> Result<Vec<String>, GitUrlToArchiveUrlsError> {
        use GitUrlToArchiveUrlsErrorCtx as Ctx;

        // If the URL is already a direct archive URL, use it as-is
        if git_url.contains("/archive/")
            && (git_url.ends_with(".tar.gz") || git_url.ends_with(".tar"))
        {
            return Ok(vec![git_url.to_string()]);
        }

        // An explicit ssh:// URL signals the caller expects an authenticated
        // clone. Guessing at anonymous HTTP(S) archive endpoints for it just
        // wastes round trips on hosts that require auth, so skip straight to
        // the git-clone fallback instead.
        if git_url.starts_with("ssh://") {
            return Ok(vec![]);
        }

        let (host, path) = if git_url.starts_with("git@") {
            let without_prefix = git_url.strip_prefix("git@").ok_or_else(|| {
                GitUrlToArchiveUrlsError::InvalidUrlFormat {
                    location: std::panic::Location::caller(),
                }
            })?;
            let (host, path) = without_prefix.split_once(':').ok_or_else(|| {
                GitUrlToArchiveUrlsError::InvalidSSHFormat {
                    location: std::panic::Location::caller(),
                }
            })?;
            (host.to_string(), path.trim_end_matches(".git").to_string())
        } else if git_url.starts_with("https://") || git_url.starts_with("http://") {
            let url = url::Url::parse(git_url).with_context(Ctx::parse_url())?;
            let host = url
                .host_str()
                .ok_or_else(|| GitUrlToArchiveUrlsError::NoHost {
                    location: std::panic::Location::caller(),
                })?;
            let path = url.path().trim_start_matches('/').trim_end_matches(".git");
            (host.to_string(), path.to_string())
        } else {
            return Err(GitUrlToArchiveUrlsError::UnsupportedFormat {
                url: git_url.to_string(),
                location: std::panic::Location::caller(),
            });
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

    async fn signed_post<T: serde::Serialize>(
        &self,
        session_id: &str,
        path: &str,
        body: &T,
    ) -> Result<reqwest::Response, SignedPostError> {
        use SignedPostErrorCtx as Ctx;

        let body_json = serde_json::to_vec(body).with_context(Ctx::serialize_body())?;

        if !self.qr {
            output::status("\nData to be signed:");
            output::status(
                serde_json::to_string_pretty(body)
                    .with_context(Ctx::serialize_pretty())?
                    .to_string(),
            );
        }

        self.signed_request(session_id, path, reqwest::Method::POST, body_json)
            .await
            .with_context(Ctx::signed_request())
    }

    async fn signed_delete(
        &self,
        session_id: &str,
        path: &str,
    ) -> Result<reqwest::Response, SignedDeleteError> {
        use SignedDeleteErrorCtx as Ctx;

        if !self.qr {
            output::status("\nRequest to be signed:");
            output::status(format!("DELETE {}", path));
        }

        self.signed_request(session_id, path, reqwest::Method::DELETE, Vec::new())
            .await
            .with_context(Ctx::signed_request())
    }

    async fn signed_request(
        &self,
        session_id: &str,
        path: &str,
        method: reqwest::Method,
        body: Vec<u8>,
    ) -> Result<reqwest::Response, SignedRequestError> {
        use SignedRequestErrorCtx as Ctx;

        if self.qr {
            return auth::signed_request_qr(self, session_id, path, method, body)
                .await
                .with_context(Ctx::get_assertion());
        }

        let body_json = body;
        let body_hash = hex::encode(Sha256::digest(&body_json));
        let method_name = method.as_str();

        // The gateway nests /api routes, so the sign middleware sees paths with /api stripped
        let challenge_path = path.strip_prefix("/api").unwrap_or(path);

        output::verbose(
            self.verbose,
            &format!(
                "Requesting FIDO2 sign challenge for {} {}",
                method_name, path
            ),
        );

        let sign_req = serde_json::json!({
            "method": method_name,
            "path": challenge_path,
            "body_hash": body_hash,
        });

        let response = self
            .client
            .post(format!("{}/auth/sign-request", self.base_url))
            .header("X-Session-ID", session_id)
            .json(&sign_req)
            .send()
            .await
            .with_context(Ctx::get_sign_challenge())?;

        if !response.status().is_success() {
            let error = response
                .text()
                .await
                .with_context(Ctx::get_sign_challenge())?;
            return Err(SignedRequestError::ChallengeFailure {
                error,
                location: std::panic::Location::caller(),
            });
        }

        let sign_resp: auth::Fido2SignResponse = response
            .json()
            .await
            .with_context(Ctx::parse_sign_response())?;
        output::verbose(self.verbose, "Got FIDO2 sign challenge");

        let login_resp = auth::LoginBeginResponse {
            public_key: sign_resp.public_key,
            session: sign_resp.challenge_id.clone(),
        };

        output::status("\nTap your security key to sign the request.");
        let assertion = auth::get_assertion(self, &login_resp, &self.base_url)
            .with_context(Ctx::get_assertion())?;

        let fido_response_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&assertion.response_json);

        output::verbose(self.verbose, "Sending FIDO2-signed request");

        let response = self
            .client
            .request(method, format!("{}{}", self.base_url, path))
            .header("X-Fido2-Challenge-Id", &sign_resp.challenge_id)
            .header("X-Fido2-Response", &fido_response_b64)
            .header("Content-Type", "application/json")
            .body(body_json)
            .send()
            .await
            .with_context(Ctx::send_request())?;

        Ok(response)
    }

    async fn join_capacity_waitlist(
        &self,
        email: &str,
        vcpus: Option<u32>,
    ) -> Result<(), JoinCapacityWaitlistError> {
        use JoinCapacityWaitlistErrorCtx as Ctx;

        let email = email.trim();
        if email.is_empty() {
            return Err(JoinCapacityWaitlistError::EmptyEmail {
                location: std::panic::Location::caller(),
            });
        }
        if email.contains('\n') || email.contains('\r') {
            return Err(JoinCapacityWaitlistError::InvalidEmail {
                location: std::panic::Location::caller(),
            });
        }
        if !email.contains('@') {
            return Err(JoinCapacityWaitlistError::NoAtSymbol {
                location: std::panic::Location::caller(),
            });
        }

        if let Some(vcpus) = vcpus
            && !(1..=46).contains(&vcpus)
        {
            return Err(JoinCapacityWaitlistError::InvalidVcpus {
                vcpus,
                location: std::panic::Location::caller(),
            });
        }

        let config = self
            .ensure_authenticated()
            .await
            .with_context(Ctx::ensure_authenticated())?;
        let org_id = auth::primary_organization_id(self, config.session_id())
            .await
            .with_context(Ctx::get_org_id())?;

        let response = self
            .client
            .post(format!(
                "{}/api/organizations/{}/fully-managed/waitlist",
                self.base_url, org_id
            ))
            .header("X-Session-ID", config.session_id())
            .json(&serde_json::json!({
                "email": email,
                "requested_enclave_vcpus": vcpus,
            }))
            .send()
            .await
            .with_context(Ctx::send_request())?;

        if !response.status().is_success() {
            let error = self.api_error_message(response).await;
            return Err(JoinCapacityWaitlistError::ApiFailure {
                error,
                location: std::panic::Location::caller(),
            });
        }

        let waitlist_response: CapacityWaitlistResponse =
            response.json().await.with_context(Ctx::parse_response())?;

        if waitlist_response.status == "already_waiting" {
            output::status(format!(
                "{} is already on the fully managed capacity waitlist.",
                email
            ));
        } else {
            output::success(format!(
                "{} has been added to the fully managed capacity waitlist.",
                email
            ));
        }

        Ok(())
    }

    async fn fetch_app(&self, id: &str) -> Result<App, FetchAppError> {
        use FetchAppErrorCtx as Ctx;

        let config = self
            .ensure_authenticated()
            .await
            .with_context(Ctx::ensure_authenticated())?;

        self.get_protected_json(
            &config.session_id,
            &format!("/api/resources/{}", id),
            "Failed to get app",
        )
        .await
        .with_context(Ctx::get_protected_json())
    }

    async fn get_current_app(&self) -> Result<App, GetCurrentAppError> {
        use GetCurrentAppErrorCtx as Ctx;

        let deployment = self
            .load_deployment()
            .with_context(Ctx::load_deployment())?;
        self.fetch_app(&deployment.resource_id)
            .await
            .with_context(Ctx::fetch_app())
    }

    async fn get_attestation_url(&self) -> Result<String, GetAttestationUrlError> {
        use GetAttestationUrlErrorCtx as Ctx;

        let app = self
            .get_current_app()
            .await
            .with_context(Ctx::get_current_app())?;

        match app.public_ip {
            Some(ref ip) if !ip.is_empty() => Ok(format!("http://{}/attestation", ip)),
            _ => Err(GetAttestationUrlError::NoPublicIp {
                location: std::panic::Location::caller(),
            }),
        }
    }

    fn get_cache_dir(&self) -> Result<PathBuf, GetCacheDirError> {
        if let Some(ref workdir) = self.workdir {
            return Ok(workdir.clone());
        }
        let cache_dir = dirs::home_dir()
            .ok_or_else(|| GetCacheDirError::HomeDir {
                location: std::panic::Location::caller(),
            })?
            .join(".cache/caution");
        Ok(cache_dir)
    }
}

fn resolve_procfile_build_command(
    content: &str,
    work_dir: &Path,
) -> Result<String, ResolveProcfileBuildCommandError> {
    use ResolveProcfileBuildCommandErrorCtx as Ctx;

    let mut build_command = None;
    let mut containerfile = None;

    for line in content.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();

            match key {
                "build" => {
                    if value.is_empty() {
                        return Err(ResolveProcfileBuildCommandError::EmptyBuildCommand {
                            location: std::panic::Location::caller(),
                        });
                    }
                    build_command = Some(value.to_string());
                }
                "containerfile" => {
                    if value.is_empty() {
                        return Err(ResolveProcfileBuildCommandError::EmptyContainerfile {
                            location: std::panic::Location::caller(),
                        });
                    }
                    containerfile = Some(value.to_string());
                }
                _ => {}
            }
        }
    }

    let containerfile =
        if !has_explicit_build_command(build_command.as_deref()) {
            match containerfile.as_deref() {
                Some(containerfile) => {
                    let containerfile =
                        validate_explicit_containerfile_path(containerfile).with_context(
                            Ctx::invalid_containerfile(),
                        )?;
                    if !work_dir.join(&containerfile).is_file() {
                        return Err(ResolveProcfileBuildCommandError::MissingContainerfile {
                            path: containerfile,
                            location: std::panic::Location::caller(),
                        });
                    }
                    Some(containerfile)
                }
                None => None,
            }
        } else {
            None
        };

    Ok(resolve_build_command_in_dir(
        build_command.as_deref(),
        containerfile.as_deref(),
        work_dir,
    ))
}

fn resolve_local_build_command_from_dir(
    work_dir: &Path,
    allow_missing_procfile: bool,
) -> Result<String, ResolveLocalBuildCommandFromDirError> {
    use ResolveLocalBuildCommandFromDirErrorCtx as Ctx;

    let config_path = work_dir.join("caution.hcl");
    let procfile_path = work_dir.join("Procfile");
    let has_containerfile = work_dir.join("Containerfile").is_file();
    let has_dockerfile = work_dir.join("Dockerfile").is_file();

    if config_path.exists() {
        let content = fs::read_to_string(&config_path).with_context(Ctx::read_caution_hcl())?;
        let config = caution_config::ConfigurationFile::from_str(&content)
            .with_context(Ctx::parse_caution_hcl())?;
        let containerfile = config
            .enclave
            .and_then(|e| e.into_iter().next().map(|(_, v)| v))
            .and_then(|e| e.build)
            .and_then(|b| b.containerfile);

        if let Some(ref cf) = containerfile {
            let cf = validate_explicit_containerfile_path(cf)
                .with_context(Ctx::invalid_containerfile())?;
            if !work_dir.join(&cf).is_file() {
                return Err(ResolveLocalBuildCommandFromDirError::MissingContainerfile {
                    path: cf,
                    location: std::panic::Location::caller(),
                });
            }
        }

        return Ok(resolve_build_command_in_dir(
            None,
            containerfile.as_deref(),
            work_dir,
        ));
    }

    if procfile_path.exists() {
        let content = fs::read_to_string(&procfile_path).with_context(Ctx::read_procfile())?;
        return resolve_procfile_build_command(&content, work_dir)
            .with_context(Ctx::procfile_resolve());
    }

    if !allow_missing_procfile {
        return Err(ResolveLocalBuildCommandFromDirError::NoConfigFound {
            location: std::panic::Location::caller(),
        });
    }

    if has_containerfile || has_dockerfile {
        return Ok(resolve_build_command_in_dir(None, None, work_dir));
    }

    Ok("echo 'Please configure your configuration file'".to_string())
}

/// `--qr` is global, so it parses on every subcommand. It only means something
/// for flows that authenticate an existing credential (signing, login);
/// registration creates one and has no cross-device path.
fn validate_global_qr(command: &Commands, qr: bool) -> Result<(), RunError> {
    if qr && matches!(command, Commands::Register { .. }) {
        return Err(RunError::ArgValidation {
            detail: "--qr is not supported for register: creating a credential requires a local authenticator. Register on this device, then use --qr for login and deploys.",
            location: std::panic::Location::caller(),
        });
    }
    Ok(())
}

pub async fn run() -> Result<(), RunError> {
    use RunErrorCtx as Ctx;

    let cli = Cli::parse();

    output::verbose(cli.verbose, "API CLI v0.1.0");
    output::verbose(cli.verbose, &format!("Gateway URL: {}", cli.url));
    output::verbose(cli.verbose, &format!("Command: {:?}", cli.command));

    validate_global_qr(&cli.command, cli.qr)?;

    if let Err(e) = check_dependencies(cli.verbose) {
        output::error(format!("Dependency check failed: {}", e));
        return Err(RunError::DependencyCheck {
            location: std::panic::Location::caller(),
            source: e.into(),
        });
    }

    match &cli.command {
        Commands::Register { .. } | Commands::Login { .. } => {
            if let Err(e) = check_gateway_connectivity(&cli.url, cli.verbose).await {
                output::error("Pre-flight check failed");
                return Err(RunError::GatewayConnectivity {
                    location: std::panic::Location::caller(),
                    source: e.into(),
                });
            }
        }
        _ => {}
    }

    output::verbose(cli.verbose, "Initializing API client...");
    let client = ApiClient::new(&cli.url, cli.verbose, cli.qr, cli.workdir.clone())
        .with_context(Ctx::api_client_init())?;
    output::verbose(cli.verbose, "API client ready");

    match cli.command {
        Commands::Register {
            alpha_code,
            username,
        } => {
            let username = auth::resolve_register_username(
                username,
                std::io::IsTerminal::is_terminal(&std::io::stdin()),
                &mut std::io::stdin().lock(),
            )
            .with_context(Ctx::command_dispatch())?;
            auth::register(&client, &alpha_code, &username)
                .await
                .with_context(Ctx::command_dispatch())?;
        }
        Commands::Login { qr, username } => {
            if qr {
                auth::login_qr(&client, username.as_deref())
                    .await
                    .with_context(Ctx::command_dispatch())?;
            } else {
                auth::login(&client, username)
                    .await
                    .with_context(Ctx::command_dispatch())?;
            }
        }
        Commands::Logout => {
            auth::logout(&client)
                .await
                .with_context(Ctx::command_dispatch())?;
        }
        Commands::Account { command } => match command {
            AccountCommands::Id => {
                auth::print_account_id(&client)
                    .await
                    .with_context(Ctx::command_dispatch())?;
            }
        },
        Commands::Init {
            bring_your_own_cloud,
            platform,
            name,
            region,
            local,
            config,
            yes,
        } => {
            if bring_your_own_cloud && platform != "aws" {
                return Err(RunError::ArgValidation {
                    detail: "Only --platform aws is currently supported for bring-your-own-compute deployments",
                    location: std::panic::Location::caller(),
                });
            }
            byoc::init(
                &client,
                bring_your_own_cloud,
                name,
                region,
                local,
                config,
                yes,
            )
            .await
            .with_context(Ctx::command_dispatch())?;
        }
        Commands::Teardown {
            bring_your_own_cloud,
            platform,
            local,
            force,
        } => {
            if bring_your_own_cloud {
                if platform != "aws" {
                    return Err(RunError::ArgValidation {
                        detail: "Only --platform aws is currently supported for bring-your-own-compute deployments",
                        location: std::panic::Location::caller(),
                    });
                }
                byoc::teardown(&client, force, local)
                    .await
                    .with_context(Ctx::command_dispatch())?;
            } else {
                return Err(RunError::ArgValidation {
                    detail: "Please specify --byoc to tear down BYOC infrastructure",
                    location: std::panic::Location::caller(),
                });
            }
        }
        Commands::Verify {
            attestation_url,
            from_local,
            from_tarball,
            app_source_url,
            pcrs,
            no_cache,
            save_pcrs,
            inspect_attestation,
        } => {
            verify::verify(
                &client,
                attestation_url,
                from_local,
                from_tarball,
                app_source_url,
                pcrs,
                no_cache,
                save_pcrs,
                inspect_attestation,
            )
            .await
            .with_context(Ctx::command_dispatch())?;
        }
        Commands::Apps { command } => match command {
            AppCommands::Create => {
                apps::crud::create(&client)
                    .await
                    .with_context(Ctx::command_dispatch())?;
            }
            AppCommands::List => {
                apps::crud::list(&client)
                    .await
                    .with_context(Ctx::command_dispatch())?;
            }
            AppCommands::Get {
                id,
                this_is_a_ci_machine,
            } => {
                apps::crud::get(&client, id, this_is_a_ci_machine)
                    .await
                    .with_context(Ctx::command_dispatch())?;
            }
            AppCommands::Destroy {
                id,
                force,
                force_delete,
                this_is_a_ci_machine,
            } => {
                apps::crud::destroy(&client, id, force, force_delete, this_is_a_ci_machine)
                    .await
                    .with_context(Ctx::command_dispatch())?;
            }
            AppCommands::Build { no_cache } => {
                verify::build_local(&client, no_cache)
                    .await
                    .with_context(Ctx::command_dispatch())?;
            }
            AppCommands::Rename { name, id } => {
                apps::crud::rename(&client, id, name)
                    .await
                    .with_context(Ctx::command_dispatch())?;
            }
            AppCommands::DownloadEif(args) => {
                apps::download_eif::download_eif(&client, &args)
                    .await
                    .with_context(Ctx::command_dispatch())?;
            }
            AppCommands::MigrateProcfile(args) => {
                apps::migrate_procfile::migrate_procfile(&client, &args)
                    .await
                    .with_context(Ctx::command_dispatch())?;
            }
        },
        Commands::SshKeys { command } => match command {
            SshKeyCommands::Add {
                key_file,
                from_agent,
                key,
                name,
            } => {
                ssh_keys::add(&client, key_file, from_agent, key, name)
                    .await
                    .with_context(Ctx::command_dispatch())?;
            }
            SshKeyCommands::List => {
                ssh_keys::list(&client)
                    .await
                    .with_context(Ctx::command_dispatch())?;
            }
            SshKeyCommands::Remove { fingerprint } => {
                ssh_keys::remove(&client, &fingerprint)
                    .await
                    .with_context(Ctx::command_dispatch())?;
            }
        },
        Commands::PgpKeys { command } => match command {
            PgpKeyCommands::Add { key_file, name } => {
                pgp_keys::add(&client, key_file, name)
                    .await
                    .with_context(Ctx::command_dispatch())?;
            }
            PgpKeyCommands::List => {
                pgp_keys::list(&client)
                    .await
                    .with_context(Ctx::command_dispatch())?;
            }
            PgpKeyCommands::Remove { fingerprint } => {
                pgp_keys::remove(&client, &fingerprint)
                    .await
                    .with_context(Ctx::command_dispatch())?;
            }
        },
        Commands::Cache { command } => match command {
            CacheCommands::Path => {
                cache::path(&client).with_context(Ctx::command_dispatch())?;
            }
            CacheCommands::Size => {
                cache::size(&client).with_context(Ctx::command_dispatch())?;
            }
            CacheCommands::List => {
                cache::list(&client).with_context(Ctx::command_dispatch())?;
            }
            CacheCommands::Destroy { force } => {
                cache::destroy(&client, force).with_context(Ctx::command_dispatch())?;
            }
        },
        Commands::Credentials { command } => match command {
            CredentialCommands::Add {
                platform,
                name,
                default,
                region,
            } => {
                credentials::add(&client, platform, name, default, region)
                    .await
                    .with_context(Ctx::command_dispatch())?;
            }
            CredentialCommands::List => {
                credentials::list(&client)
                    .await
                    .with_context(Ctx::command_dispatch())?;
            }
            CredentialCommands::Remove { id, force } => {
                credentials::remove(&client, &id, force)
                    .await
                    .with_context(Ctx::command_dispatch())?;
            }
            CredentialCommands::SetDefault { id } => {
                credentials::set_default(&client, &id)
                    .await
                    .with_context(Ctx::command_dispatch())?;
            }
        },
        Commands::Capacity { command } => match command {
            CapacityCommands::Waitlist { email, vcpus } => {
                client
                    .join_capacity_waitlist(&email, vcpus)
                    .await
                    .with_context(Ctx::command_dispatch())?;
            }
        },
        Commands::Secret { command } => match command {
            SecretCommands::Keygen {
                output,
                private_keyring,
                name,
                email,
                force,
                shoot_self_in_foot,
            } => {
                secrets::keygen(
                    output,
                    private_keyring,
                    name,
                    email,
                    force,
                    shoot_self_in_foot,
                )
                .with_context(Ctx::command_dispatch())?;
            }
            SecretCommands::New {
                keyring,
                threshold,
                max,
                no_upload,
                name,
                labels,
            } => {
                secrets::new(&client, keyring, threshold, max, !no_upload, name, labels)
                    .await
                    .with_context(Ctx::command_dispatch())?;
            }
            SecretCommands::Encrypt {
                keys,
                env_file,
                bundle,
                secrets_dir,
            } => {
                secrets::encrypt(keys, env_file, bundle, secrets_dir)
                    .with_context(Ctx::command_dispatch())?;
            }
            SecretCommands::Rename { id, name } => {
                secrets::rename(&client, id, name)
                    .await
                    .with_context(Ctx::command_dispatch())?;
            }
            SecretCommands::Label { command } => match command {
                LabelCommands::Set { id, labels } => {
                    secrets::label_set(&client, id, labels)
                        .await
                        .with_context(Ctx::command_dispatch())?;
                }
                LabelCommands::Remove { id, keys } => {
                    secrets::label_remove(&client, id, keys)
                        .await
                        .with_context(Ctx::command_dispatch())?;
                }
            },
            SecretCommands::SendShard {
                app,
                bundle,
                keyring,
            } => {
                secrets::send_shard(&client, app, bundle, keyring)
                    .await
                    .with_context(Ctx::command_dispatch())?;
            }
        },
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::openpgp;
    use super::verify::{
        ARCHIVE_PREFLIGHT_ATTEMPTS, ArchivePreflightStatus, MAX_ATTESTATION_RESPONSE_BYTES,
        TlsConnection, TlsExpectation, TrustedHashes, TrustedTls,
        append_attestation_response_chunk, archive_preflight_urls, attestation_inspection_json,
        attestation_user_data, classify_app_source_refs, classify_archive_preflight,
        configured_enclave, display_user_data, dns_answer_is_absent, dns_contains_deployment_ip,
        git_command, measured_build_cache_key, persist_trusted_hashes,
        persist_trusted_hashes_with_backup, preflight_archive_urls, reproduction_uses_steve,
        resolve_reproduction_e2e_mode, tls_connection, tls_expectation_from_config,
        validate_attested_tls, verify_deprecation_warnings,
    };
    use super::{
        AccountCommands, ApiClient, Cli, Commands, PgpKeyCommands, RunError,
        deployment_target_summary, inspect_checkout_link, linked_checkout_error,
        prepare_pgp_public_key_for_upload, resolve_local_build_command_from_dir,
        resolve_procfile_build_command, validate_global_qr,
    };
    use caution_config::{ConfigurationFile, E2eEncryption, E2eMode};
    use clap::Parser;
    use openpgp::cert::prelude::*;
    use openpgp::serialize::SerializeInto;
    use sha2::Digest;
    use std::collections::HashMap;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::{Path, PathBuf};
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn reproduction_e2e_mode_preserves_explicit_config_and_manifest_fallback() {
        let config = |enabled, mode| E2eEncryption {
            enabled,
            mode,
            cors_origins: None,
            key_exchange: None,
            allow_plaintext_fallback: None,
        };
        let disabled = config(Some(false), None);
        let legacy_steve = config(Some(true), None);
        let steve = config(None, Some(E2eMode::Steve));
        let tls = config(None, Some(E2eMode::Tls));
        let unspecified = config(None, None);

        assert_eq!(
            resolve_reproduction_e2e_mode(None, true),
            Some(E2eMode::Steve)
        );
        assert_eq!(
            resolve_reproduction_e2e_mode(Some(&unspecified), true),
            Some(E2eMode::Steve)
        );
        assert_eq!(resolve_reproduction_e2e_mode(Some(&disabled), true), None);
        assert_eq!(
            resolve_reproduction_e2e_mode(Some(&steve), false),
            Some(E2eMode::Steve)
        );
        assert_eq!(
            resolve_reproduction_e2e_mode(Some(&legacy_steve), false),
            Some(E2eMode::Steve)
        );
        assert_eq!(
            resolve_reproduction_e2e_mode(Some(&tls), true),
            Some(E2eMode::Tls)
        );
    }

    #[test]
    fn verify_defaults_to_local_source_and_rejects_selector_conflicts() {
        let cli = Cli::try_parse_from(["caution", "verify"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Verify {
                from_local: false,
                from_tarball: None,
                app_source_url: None,
                pcrs: None,
                ..
            }
        ));

        let selectors = [
            ("--from-local", None),
            ("--from-tarball", Some("source.tar.gz")),
            ("--app-source-url", Some("https://example.com/app.git")),
            ("--pcrs", Some("pcrs.txt")),
        ];
        for (left_index, left) in selectors.iter().enumerate() {
            for right in selectors.iter().skip(left_index + 1) {
                let mut args = vec!["caution", "verify", left.0];
                args.extend(left.1);
                args.push(right.0);
                args.extend(right.1);
                assert_eq!(
                    Cli::try_parse_from(args).err().unwrap().kind(),
                    clap::error::ErrorKind::ArgumentConflict
                );
            }
        }
    }

    #[test]
    fn inspect_attestation_rejects_verification_only_options() {
        for option in [
            vec!["--from-local"],
            vec!["--from-tarball", "source.tar.gz"],
            vec!["--app-source-url", "https://example.com/app.git"],
            vec!["--pcrs", "pcrs.txt"],
            vec!["--no-cache"],
            vec!["--save-pcrs"],
        ] {
            let mut args = vec!["caution", "verify", "--inspect-attestation"];
            args.extend(option);
            assert_eq!(
                Cli::try_parse_from(args).err().unwrap().kind(),
                clap::error::ErrorKind::ArgumentConflict
            );
        }

        let cli = Cli::try_parse_from([
            "caution",
            "verify",
            "--inspect-attestation",
            "--attestation-url",
            "https://app.example.com/attestation",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Verify {
                inspect_attestation: true,
                ..
            }
        ));
    }

    #[test]
    fn verify_legacy_flags_have_concise_warnings() {
        assert!(verify_deprecation_warnings(false, false).is_empty());
        assert_eq!(
            verify_deprecation_warnings(true, true),
            vec![
                "--from-local is deprecated; local source is now the default",
                "--save-pcrs is deprecated; trusted state is now saved automatically",
            ]
        );
    }

    fn config_with_e2e(body: &str, domain: Option<&str>) -> ConfigurationFile {
        let domain = domain
            .map(|domain| format!("domain = \"{domain}\""))
            .unwrap_or_default();
        ConfigurationFile::from_str(&format!(
            r#"
enclave "main" {{
  network {{
    ingress {{
      cidr_ipv4 = "0.0.0.0/0"
      port = 8080
    }}
    http {{
      port = 8080
      {domain}
      e2e_encryption {{
        {body}
      }}
    }}
  }}
}}
"#
        ))
        .unwrap()
    }

    #[test]
    fn tls_expectation_requires_tls_mode_and_domain() {
        let tls = config_with_e2e(r#"mode = "tls""#, Some("app.example.com"));
        assert_eq!(
            tls_expectation_from_config(&tls).unwrap(),
            Some(TlsExpectation {
                domain: "app.example.com".to_string()
            })
        );

        let steve = config_with_e2e(r#"mode = "steve""#, None);
        assert_eq!(tls_expectation_from_config(&steve).unwrap(), None);

        let missing_domain = config_with_e2e(r#"mode = "tls""#, None);
        assert!(tls_expectation_from_config(&missing_domain).is_err());
    }

    #[test]
    fn tls_connection_accepts_only_same_https_domain_or_raw_ip() {
        let same = reqwest::Url::parse("https://app.example.com/attestation").unwrap();
        assert_eq!(
            tls_connection(&same, "app.example.com").unwrap(),
            TlsConnection::AttestationResponse
        );

        let raw_ip = reqwest::Url::parse("http://192.0.2.10/attestation").unwrap();
        assert_eq!(
            tls_connection(&raw_ip, "app.example.com").unwrap(),
            TlsConnection::PinnedIp(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
        );

        for rejected in [
            "http://app.example.com/attestation",
            "https://proxy.example.net/attestation",
        ] {
            assert!(
                tls_connection(&reqwest::Url::parse(rejected).unwrap(), "app.example.com").is_err()
            );
        }
    }

    #[test]
    fn dns_absence_does_not_include_transient_errors() {
        assert!(dns_answer_is_absent(&io::Error::new(
            io::ErrorKind::NotFound,
            "missing"
        )));
        assert!(dns_answer_is_absent(&io::Error::other(
            "Name or service not known"
        )));
        assert!(!dns_answer_is_absent(&io::Error::new(
            io::ErrorKind::TimedOut,
            "resolver timed out"
        )));

        let deployment_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        assert!(!dns_contains_deployment_ip("app.example.com", deployment_ip, &[]).unwrap());
        assert!(
            dns_contains_deployment_ip(
                "app.example.com",
                deployment_ip,
                &[SocketAddr::new(deployment_ip, 443)]
            )
            .unwrap()
        );
        assert!(
            dns_contains_deployment_ip(
                "app.example.com",
                deployment_ip,
                &[SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)),
                    443
                )]
            )
            .is_err()
        );
    }

    #[test]
    fn tls_metadata_is_strict_and_binds_the_live_fingerprint() {
        let expected = TlsExpectation {
            domain: "app.example.com".to_string(),
        };
        let certfp = "ab".repeat(32);
        let metadata = |mode: &str, domain: &str, fingerprint: &str| {
            serde_json::to_vec(&serde_json::json!({
                "tls": { "mode": mode, "domain": domain, "certfp": fingerprint }
            }))
            .unwrap()
        };

        assert_eq!(
            validate_attested_tls(
                &expected,
                &metadata("tls", "app.example.com", &certfp),
                &certfp
            )
            .unwrap(),
            TrustedTls {
                domain: "app.example.com".to_string(),
                certfp: certfp.clone(),
            }
        );

        for invalid in [
            metadata("steve", "app.example.com", &certfp),
            metadata("tls", "other.example.com", &certfp),
            metadata("tls", "app.example.com", &certfp.to_uppercase()),
            metadata("tls", "app.example.com", "abcd"),
            serde_json::to_vec(&serde_json::json!({
                "tls": {
                    "mode": "tls",
                    "domain": "app.example.com",
                    "certfp": certfp,
                    "extra": true
                }
            }))
            .unwrap(),
        ] {
            assert!(validate_attested_tls(&expected, &invalid, &"ab".repeat(32)).is_err());
        }
        assert!(
            validate_attested_tls(
                &expected,
                &metadata("tls", "app.example.com", &"ab".repeat(32)),
                &"cd".repeat(32)
            )
            .is_err()
        );
    }

    #[test]
    fn attestation_user_data_handles_optional_and_wrong_payload_shapes() {
        let key = serde_cbor::Value::Text("user_data".to_string());
        let bytes = serde_cbor::Value::Bytes(b"metadata".to_vec());
        let payload = serde_cbor::Value::Map([(key.clone(), bytes)].into_iter().collect());
        assert_eq!(
            attestation_user_data(&payload).unwrap(),
            Some(&b"metadata"[..])
        );

        let missing = serde_cbor::Value::Map(Default::default());
        assert_eq!(attestation_user_data(&missing).unwrap(), None);
        let null = serde_cbor::Value::Map(
            [(key.clone(), serde_cbor::Value::Null)]
                .into_iter()
                .collect(),
        );
        assert_eq!(attestation_user_data(&null).unwrap(), None);
        let wrong = serde_cbor::Value::Map(
            [(key, serde_cbor::Value::Text("metadata".to_string()))]
                .into_iter()
                .collect(),
        );
        assert!(attestation_user_data(&wrong).is_err());
        assert!(attestation_user_data(&serde_cbor::Value::Null).is_err());
    }

    #[test]
    fn user_data_display_escapes_utf8_and_hex_encodes_other_bytes() {
        assert_eq!(
            display_user_data(b"line\nnext"),
            (false, "line\\nnext".to_string())
        );
        assert_eq!(display_user_data(&[0xff, 0x00]), (true, "ff00".to_string()));
    }

    #[test]
    fn inspection_json_is_explicitly_unverified_and_separates_manifest() {
        let payload = serde_cbor::Value::Map(
            [(
                serde_cbor::Value::Text("user_data".to_string()),
                serde_cbor::Value::Bytes(b"metadata".to_vec()),
            )]
            .into_iter()
            .collect(),
        );
        let manifest = serde_json::json!({"app_source": {"commit": "abc"}});
        let output: serde_json::Value = serde_json::from_str(
            &attestation_inspection_json(b"nonce", &payload, Some(&manifest)).unwrap(),
        )
        .unwrap();

        assert_eq!(output["verification"], "not_performed");
        assert_eq!(output["challenge_nonce"], "bm9uY2U=");
        assert_eq!(
            output["attestation_payload"]["user_data"],
            "base64:bWV0YWRhdGE="
        );
        assert_eq!(output["response_metadata"]["manifest"], manifest);
    }

    #[test]
    fn attestation_response_limit_accepts_boundary_and_rejects_excess() {
        let mut body = vec![0; MAX_ATTESTATION_RESPONSE_BYTES - 1];
        append_attestation_response_chunk(&mut body, &[0]).unwrap();
        assert_eq!(body.len(), MAX_ATTESTATION_RESPONSE_BYTES);
        assert!(append_attestation_response_chunk(&mut body, &[0]).is_err());

        let mut oversized = vec![0; MAX_ATTESTATION_RESPONSE_BYTES + 1];
        assert!(append_attestation_response_chunk(&mut oversized, &[]).is_err());
    }

    fn trusted_hashes<'a>(pcr: &'a str, tls: Option<TrustedTls>) -> TrustedHashes<'a> {
        TrustedHashes {
            pcr0: pcr,
            pcr1: pcr,
            pcr2: pcr,
            verified_at: "2026-08-05T00:00:00Z".to_string(),
            tls,
        }
    }

    #[test]
    fn trusted_state_is_atomic_compatible_and_removes_stale_tls() {
        let work_dir = tempdir().unwrap();
        let path = work_dir.path().join(".caution/trusted_hashes.json");
        assert!(
            persist_trusted_hashes(&path, &trusted_hashes("first", None))
                .unwrap()
                .is_none()
        );

        let tls = TrustedTls {
            domain: "app.example.com".to_string(),
            certfp: "ab".repeat(32),
        };
        let first_backup =
            persist_trusted_hashes(&path, &trusted_hashes("second", Some(tls.clone())))
                .unwrap()
                .unwrap();
        let second_backup = persist_trusted_hashes(&path, &trusted_hashes("third", None))
            .unwrap()
            .unwrap();

        assert_ne!(first_backup, second_backup);
        let canonical: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(canonical["pcr0"], "third");
        assert!(canonical.get("tls").is_none());
        assert_eq!(canonical["pcr1"], "third"); // send-shard reads these top-level fields

        let previous: serde_json::Value =
            serde_json::from_slice(&std::fs::read(second_backup).unwrap()).unwrap();
        assert_eq!(previous["pcr0"], "second");
        assert_eq!(previous["tls"]["domain"], tls.domain);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(first_backup).unwrap())
                .unwrap()["pcr0"],
            "first"
        );
    }

    #[test]
    fn trusted_state_backup_failure_preserves_the_canonical_file() {
        let work_dir = tempdir().unwrap();
        let state_dir = work_dir.path().join(".caution");
        std::fs::create_dir(&state_dir).unwrap();
        let path = state_dir.join("trusted_hashes.json");
        std::fs::write(&path, b"original").unwrap();

        assert!(
            persist_trusted_hashes_with_backup(&path, &trusted_hashes("new", None), |_, _| Err(
                io::Error::new(io::ErrorKind::PermissionDenied, "injected")
            ))
            .is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
    }

    #[cfg(unix)]
    #[test]
    fn trusted_state_rejects_symlinks_without_touching_the_target() {
        use std::os::unix::fs::symlink;

        let work_dir = tempdir().unwrap();
        let state_dir = work_dir.path().join(".caution");
        std::fs::create_dir(&state_dir).unwrap();
        let target = work_dir.path().join("victim.json");
        std::fs::write(&target, b"do not replace").unwrap();
        let state = state_dir.join("trusted_hashes.json");
        symlink(&target, &state).unwrap();

        assert!(persist_trusted_hashes(&state, &trusted_hashes("new", None)).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"do not replace");

        let linked_dir = work_dir.path().join("linked");
        symlink(&state_dir, &linked_dir).unwrap();
        assert!(
            persist_trusted_hashes(
                &linked_dir.join("trusted_hashes.json"),
                &trusted_hashes("new", None)
            )
            .is_err()
        );

        let directory_state = work_dir.path().join("directory-state");
        std::fs::create_dir(&directory_state).unwrap();
        assert!(persist_trusted_hashes(&directory_state, &trusted_hashes("new", None)).is_err());
        assert!(directory_state.is_dir());
    }

    #[test]
    fn reproduction_steve_cache_binding_follows_effective_mode() {
        let config = |enabled, mode| E2eEncryption {
            enabled,
            mode,
            cors_origins: None,
            key_exchange: None,
            allow_plaintext_fallback: None,
        };
        let disabled = config(Some(false), None);
        let legacy_steve = config(Some(true), None);
        let steve = config(None, Some(E2eMode::Steve));
        let tls = config(None, Some(E2eMode::Tls));

        assert!(reproduction_uses_steve(Some(&steve), false));
        assert!(reproduction_uses_steve(Some(&legacy_steve), false));
        assert!(!reproduction_uses_steve(Some(&tls), true));
        assert!(!reproduction_uses_steve(Some(&disabled), true));
        assert!(reproduction_uses_steve(None, true));
        assert!(!reproduction_uses_steve(None, false));
    }

    fn test_api_client() -> ApiClient {
        ApiClient {
            base_url: "http://localhost".to_string(),
            client: reqwest::Client::new(),
            config_path: PathBuf::new(),
            deployment_path: None,
            verbose: false,
            qr: false,
            workdir: None,
        }
    }

    async fn serve_preflight_responses(
        responses: Vec<(reqwest::StatusCode, Option<String>)>,
    ) -> (String, tokio::task::JoinHandle<usize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut requests = 0;
            for (status, location) in responses {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 1024];
                let _ = socket.read(&mut request).await.unwrap();
                requests += 1;

                let code = status.as_u16().to_string();
                let mut response = [
                    "HTTP/1.1 ",
                    code.as_str(),
                    " ",
                    status.canonical_reason().unwrap_or(""),
                    "\r\nContent-Length: 0\r\nConnection: close\r\n",
                ]
                .concat();
                if let Some(location) = location {
                    response.push_str("Location: ");
                    response.push_str(&location);
                    response.push_str("\r\n");
                }
                response.push_str("\r\n");
                socket.write_all(response.as_bytes()).await.unwrap();
            }
            requests
        });
        let address = address.to_string();
        (
            ["http://", address.as_str(), "/archive.tar.gz"].concat(),
            handle,
        )
    }

    #[test]
    fn cli_parses_account_id_command() {
        let cli = Cli::try_parse_from(["caution", "account", "id"]).unwrap();

        assert!(matches!(
            cli.command,
            Commands::Account {
                command: AccountCommands::Id
            }
        ));
    }

    #[test]
    fn cli_parses_pgp_key_add_command() {
        let cli = Cli::try_parse_from([
            "caution",
            "pgp-keys",
            "add",
            "public-key.asc",
            "--name",
            "Work key",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Commands::PgpKeys {
                command: PgpKeyCommands::Add {
                    key_file,
                    name: Some(name),
                }
            } if key_file.as_path() == std::path::Path::new("public-key.asc") && name == "Work key"
        ));
    }

    #[test]
    fn cli_parses_pgp_key_remove_command() {
        let cli = Cli::try_parse_from([
            "caution",
            "pgp-keys",
            "remove",
            "0123456789ABCDEF0123456789ABCDEF01234567",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Commands::PgpKeys {
                command: PgpKeyCommands::Remove { fingerprint }
            } if fingerprint == "0123456789ABCDEF0123456789ABCDEF01234567"
        ));
    }

    #[test]
    fn pgp_key_upload_preparation_rejects_private_material() {
        let (cert, _revocation) = CertBuilder::new()
            .add_userid("private@example.org")
            .add_signing_subkey()
            .generate()
            .unwrap();
        let private_key = String::from_utf8(cert.as_tsk().armored().to_vec().unwrap()).unwrap();

        let error = prepare_pgp_public_key_for_upload(&private_key).unwrap_err();
        assert!(error.to_string().contains("private key material"));
    }

    #[test]
    fn resolve_procfile_build_command_prefers_explicit_build_over_containerfile() {
        let work_dir = tempdir().unwrap();
        std::fs::write(work_dir.path().join("Containerfile"), "").unwrap();

        let command = resolve_procfile_build_command(
            "\
build: docker build -f Custom.Containerfile .\n\
containerfile: Missing.Containerfile\n",
            work_dir.path(),
        )
        .unwrap();

        assert_eq!(command, "docker build -f Custom.Containerfile .");
    }

    #[test]
    fn resolve_procfile_build_command_uses_explicit_containerfile() {
        let work_dir = tempdir().unwrap();
        std::fs::write(work_dir.path().join("Custom.Containerfile"), "").unwrap();
        let command = resolve_procfile_build_command(
            "containerfile: Custom.Containerfile\n",
            work_dir.path(),
        )
        .unwrap();

        assert_eq!(command, "docker build -f Custom.Containerfile .");
    }

    #[test]
    fn resolve_procfile_build_command_prefers_explicit_containerfile_over_auto_detected_containerfile()
     {
        let work_dir = tempdir().unwrap();
        std::fs::write(work_dir.path().join("Custom.Containerfile"), "").unwrap();
        std::fs::write(work_dir.path().join("Containerfile"), "").unwrap();
        std::fs::write(work_dir.path().join("Dockerfile"), "").unwrap();

        let command = resolve_procfile_build_command(
            "containerfile: Custom.Containerfile\n",
            work_dir.path(),
        )
        .unwrap();

        assert_eq!(command, "docker build -f Custom.Containerfile .");
    }

    #[test]
    fn resolve_procfile_build_command_rejects_empty_explicit_containerfile() {
        let work_dir = tempdir().unwrap();
        let err = resolve_procfile_build_command("containerfile:\n", work_dir.path()).unwrap_err();

        assert!(
            err.to_string().contains("empty containerfile"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_procfile_build_command_rejects_missing_explicit_containerfile() {
        let work_dir = tempdir().unwrap();
        let err = resolve_procfile_build_command(
            "containerfile: Missing.Containerfile\n",
            work_dir.path(),
        )
        .unwrap_err();

        assert!(
            err.to_string().contains("missing file"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_local_build_command_without_procfile_prefers_containerfile() {
        let work_dir = tempdir().unwrap();
        std::fs::write(work_dir.path().join("Containerfile"), "").unwrap();
        std::fs::write(work_dir.path().join("Dockerfile"), "").unwrap();

        let command = resolve_local_build_command_from_dir(work_dir.path(), true).unwrap();

        assert_eq!(command, "docker build -f Containerfile .");
    }

    #[test]
    fn resolve_local_build_command_without_procfile_falls_back_to_dockerfile() {
        let work_dir = tempdir().unwrap();
        std::fs::write(work_dir.path().join("Dockerfile"), "").unwrap();

        let command = resolve_local_build_command_from_dir(work_dir.path(), true).unwrap();

        assert_eq!(command, "docker build -f Dockerfile .");
    }

    #[test]
    fn resolve_local_build_command_without_build_files_returns_placeholder() {
        let work_dir = tempdir().unwrap();

        let command = resolve_local_build_command_from_dir(work_dir.path(), true).unwrap();

        assert_eq!(command, "echo 'Please configure your configuration file'");
    }

    #[test]
    fn git_url_to_archive_urls_skips_archive_guessing_for_ssh_scheme_urls() {
        let client = test_api_client();
        let commit = "50e2608f857ee2c9777b89af0f9af02ffba9999d";

        let urls = client
            .git_url_to_archive_urls(
                "ssh://git@codeberg.org/caution/demo-pq-enclave-binding.git",
                commit,
            )
            .unwrap();

        assert!(urls.is_empty());
    }

    #[test]
    fn git_command_disables_interactive_ssh_prompts() {
        let cmd = git_command(&[
            "ls-remote",
            "ssh://git@codeberg.org/caution/demo-pq-enclave-binding.git",
        ]);
        let envs: HashMap<_, _> = cmd
            .get_envs()
            .filter_map(|(key, value)| Some((key.to_str()?, value?.to_str()?)))
            .collect();

        assert_eq!(envs.get("GIT_TERMINAL_PROMPT"), Some(&"0"));
        assert_eq!(envs.get("GIT_ASKPASS"), Some(&"true"));

        let ssh_command = envs
            .get("GIT_SSH_COMMAND")
            .expect("git SSH fallback must not be able to prompt through /dev/tty");
        assert!(ssh_command.contains("BatchMode=yes"));
        assert!(ssh_command.contains("StrictHostKeyChecking=accept-new"));
    }

    #[test]
    fn generated_config_hcl_parses_as_valid_configuration_file() {
        for byoc in [false, true] {
            let hcl = ApiClient::generate_config_hcl("git@codeberg.org:user/repo.git", byoc);
            let config = ConfigurationFile::from_str(&hcl);
            assert!(
                config.is_ok(),
                "generated HCL should parse for byoc={byoc}: {:?}",
                config.err()
            );
            assert!(hcl.contains("key_exchange = \"x25519\""));
        }
    }

    #[test]
    fn configured_enclave_accepts_non_default_label() {
        let config = ConfigurationFile::from_str(
            r#"
enclave "main" {
  resources {
    cpu = 2
    memory_mb = 2048
  }
}
"#,
        )
        .unwrap();

        let enclave = configured_enclave(&config).expect("single enclave");
        assert_eq!(enclave.resources.as_ref().unwrap().memory_mb, 2048);
    }

    #[test]
    fn measured_build_cache_key_changes_with_configuration() {
        let e2e_enabled = ConfigurationFile::from_str(
            r#"
enclave "default" {
  network {
    ingress {
      cidr_ipv4 = "0.0.0.0/0"
      port = 8080
    }
    http {
      port = 8080
      e2e_encryption {
        enabled = true
      }
    }
  }
}
"#,
        )
        .unwrap();
        let e2e_disabled = ConfigurationFile::from_str(
            r#"
enclave "default" {
  network {
    ingress {
      cidr_ipv4 = "0.0.0.0/0"
      port = 8080
    }
    http {
      port = 8080
      e2e_encryption {
        enabled = false
      }
    }
  }
}
"#,
        )
        .unwrap();

        let e2e_enabled_key =
            measured_build_cache_key("deadbeef", &e2e_enabled, Some("steve-v1")).unwrap();
        let e2e_disabled_key = measured_build_cache_key("deadbeef", &e2e_disabled, None).unwrap();
        assert_ne!(e2e_enabled_key, e2e_disabled_key);
    }

    #[test]
    fn local_cache_keys_bind_steve_only_for_e2e() {
        let e2e_config = ConfigurationFile::from_str(
            r#"
enclave "default" {
  network {
    ingress {
      cidr_ipv4 = "0.0.0.0/0"
      port = 8080
    }
    http {
      port = 8080
      e2e_encryption {
        enabled = true
      }
    }
  }
}
"#,
        )
        .unwrap();

        let e2e_v1 = measured_build_cache_key("deadbeef", &e2e_config, Some("steve-v1")).unwrap();
        let e2e_v2 = measured_build_cache_key("deadbeef", &e2e_config, Some("steve-v2")).unwrap();
        assert_ne!(e2e_v1, e2e_v2);

        let plain = measured_build_cache_key("deadbeef", &e2e_config, None).unwrap();
        let config_json = serde_json::to_vec(&e2e_config).unwrap();
        assert_eq!(
            plain,
            format!(
                "deadbeef-config-{}",
                hex::encode(sha2::Sha256::digest(&config_json))
            )
        );
    }

    #[test]
    fn create_config_file_in_dir_writes_byoc_template() {
        let work_dir = tempdir().unwrap();
        let client = test_api_client();

        client
            .create_config_file_in_dir_if_needed(work_dir.path(), true)
            .unwrap();

        let hcl = std::fs::read_to_string(work_dir.path().join("caution.hcl")).unwrap();
        assert!(hcl.contains("caution {"));
        assert!(hcl.contains("type         = \"aws\""));
        assert!(hcl.contains("region       = \"us-east-1\""));
        ConfigurationFile::from_str(&hcl).unwrap();
    }

    fn init_test_git_repo(path: &Path) {
        assert!(
            std::process::Command::new("git")
                .arg("-C")
                .arg(path)
                .arg("init")
                .output()
                .unwrap()
                .status
                .success()
        );
    }

    #[test]
    fn linked_checkout_preflight_matrix() {
        use crate::apps::crud::relink_candidate;
        let state_id = "550e8400-e29b-41d4-a716-446655440000";
        let remote_id = "123e4567-e89b-12d3-a456-426614174000";
        let work_dir = tempdir().unwrap();
        init_test_git_repo(work_dir.path());
        let deployment_path = work_dir.path().join(".caution/deployment.json");
        let fresh = inspect_checkout_link(&deployment_path, work_dir.path(), None).unwrap();
        assert!(!fresh.blocks_managed_creation());
        assert!(!fresh.blocks_explicit_byoc_creation());
        assert_eq!(relink_candidate(&fresh).unwrap(), None);

        let provider = ConfigurationFile::from_str(
            "caution {\n provider {\n type = \"aws\"\n region = \"us-east-1\"\n }\n }\n\
             enclave \"main\" {\n unit \"default\" {\n command = \"/app\"\n }\n }",
        )
        .unwrap();
        let provider_only =
            inspect_checkout_link(&deployment_path, work_dir.path(), Some(&provider)).unwrap();
        assert!(provider_only.blocks_managed_creation());
        assert!(!provider_only.blocks_explicit_byoc_creation());
        let provider_error = linked_checkout_error(&provider_only);
        assert!(provider_error.contains("caution init --byoc"));
        assert!(!provider_error.contains("apps destroy"));

        std::fs::create_dir_all(deployment_path.parent().unwrap()).unwrap();
        std::fs::write(
            &deployment_path,
            format!(r#"{{"resource_id":"{}"}}"#, state_id),
        )
        .unwrap();
        let valid_state = inspect_checkout_link(&deployment_path, work_dir.path(), None).unwrap();
        assert!(valid_state.blocks_managed_creation());
        assert!(!valid_state.blocks_explicit_byoc_creation());
        assert_eq!(
            relink_candidate(&valid_state).unwrap(),
            Some((state_id.to_string(), false))
        );

        std::fs::write(&deployment_path, "not json").unwrap();
        let malformed_state =
            inspect_checkout_link(&deployment_path, work_dir.path(), None).unwrap();
        assert!(malformed_state.blocks_managed_creation());
        assert!(malformed_state.blocks_explicit_byoc_creation());
        assert!(relink_candidate(&malformed_state).is_err());

        std::fs::write(&deployment_path, r#"{"resource_id":"not-a-uuid"}"#).unwrap();
        let invalid_state = inspect_checkout_link(&deployment_path, work_dir.path(), None).unwrap();
        assert!(relink_candidate(&invalid_state).is_err());

        std::fs::remove_file(&deployment_path).unwrap();
        assert!(
            std::process::Command::new("git")
                .arg("-C")
                .arg(work_dir.path())
                .args([
                    "remote",
                    "add",
                    "caution",
                    &format!("git@example.test:{}.git", remote_id),
                ])
                .output()
                .unwrap()
                .status
                .success()
        );
        let remote = inspect_checkout_link(&deployment_path, work_dir.path(), None).unwrap();
        assert!(remote.blocks_managed_creation());
        assert!(remote.blocks_explicit_byoc_creation());
        assert!(linked_checkout_error(&remote).contains("git push caution HEAD:main"));
        assert_eq!(
            relink_candidate(&remote).unwrap(),
            Some((remote_id.to_string(), true))
        );

        std::fs::create_dir_all(deployment_path.parent().unwrap()).unwrap();
        std::fs::write(&deployment_path, "not json").unwrap();
        let malformed_state_with_remote =
            inspect_checkout_link(&deployment_path, work_dir.path(), None).unwrap();
        assert_eq!(
            relink_candidate(&malformed_state_with_remote).unwrap(),
            Some((remote_id.to_string(), true))
        );

        std::fs::write(
            &deployment_path,
            format!(r#"{{"resource_id":"{}"}}"#, state_id),
        )
        .unwrap();
        assert!(
            std::process::Command::new("git")
                .arg("-C")
                .arg(work_dir.path())
                .args([
                    "remote",
                    "set-url",
                    "caution",
                    "git@example.test:not-an-id.git"
                ])
                .output()
                .unwrap()
                .status
                .success()
        );
        let state_precedes_remote =
            inspect_checkout_link(&deployment_path, work_dir.path(), None).unwrap();
        assert_eq!(
            relink_candidate(&state_precedes_remote).unwrap(),
            Some((state_id.to_string(), false))
        );

        std::fs::remove_file(&deployment_path).unwrap();
        let invalid_remote =
            inspect_checkout_link(&deployment_path, work_dir.path(), None).unwrap();
        assert!(relink_candidate(&invalid_remote).is_err());
    }

    #[tokio::test]
    async fn relink_api_failures_preserve_local_state() {
        let resource_id = "550e8400-e29b-41d4-a716-446655440000";

        for status in [
            reqwest::StatusCode::NOT_FOUND,
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
        ] {
            let work_dir = tempdir().unwrap();
            let deployment_path = work_dir.path().join("deployment.json");
            let deployment = format!(r#"{{"resource_id":"{}"}}"#, resource_id);
            std::fs::write(&deployment_path, &deployment).unwrap();

            let (url, server) = serve_preflight_responses(vec![(status, None)]).await;
            let base_url = url.trim_end_matches("/archive.tar.gz").to_string();
            let config_path = work_dir.path().join("config.json");
            std::fs::write(
                &config_path,
                serde_json::json!({
                    "session_id": "test-session",
                    "expires_at": "2099-01-01T00:00:00Z",
                    "server_url": &base_url,
                })
                .to_string(),
            )
            .unwrap();

            let client = ApiClient {
                base_url,
                config_path,
                deployment_path: Some(deployment_path.clone()),
                ..test_api_client()
            };
            let checkout_link = super::CheckoutLink {
                deployment_file_exists: true,
                resource_id: Some(resource_id.to_string()),
                caution_remote: None,
                byoc_provider: false,
            };

            let error = crate::apps::crud::try_relink(&client, &checkout_link)
                .await
                .unwrap_err();
            assert!(error.to_string().contains("refusing to create a successor"));
            assert_eq!(
                std::fs::read_to_string(&deployment_path).unwrap(),
                deployment
            );
            assert_eq!(server.await.unwrap(), 1);
        }
    }

    #[test]
    fn byoc_yes_and_target_help_are_explicit() {
        assert!(matches!(
            Cli::try_parse_from(["caution", "init", "--byoc", "--yes"])
                .unwrap()
                .command,
            Commands::Init { yes: true, .. }
        ));
        assert!(Cli::try_parse_from(["caution", "init", "--yes"]).is_err());
        assert!(
            Cli::try_parse_from([
                "caution",
                "init",
                "--byoc",
                "--config",
                "credentials.json",
                "--yes"
            ])
            .is_err()
        );
        assert_eq!(
            deployment_target_summary("BYOC", "123456789012", "us-east-1"),
            "Deployment target: capacity=BYOC, aws_account=123456789012, region=us-east-1"
        );
        let error = crate::byoc::aws_credentials_error("production", "caution init --byoc");
        assert!(
            error.contains("aws configure export-credentials --profile production --format env")
        );
    }

    // Sample `git ls-remote` output: "<sha>\t<ref>" lines.
    const LS_REMOTE: &str = "\
1111111111111111111111111111111111111111\tHEAD\n\
1111111111111111111111111111111111111111\trefs/heads/main\n\
2222222222222222222222222222222222222222\trefs/heads/deploy-tests\n\
3333333333333333333333333333333333333333\trefs/tags/v1.0\n";

    #[test]
    fn archive_preflight_classifies_pass_failure_retry_and_exhaustion() {
        for (status, attempt, expected) in [
            (reqwest::StatusCode::OK, 1, ArchivePreflightStatus::Passed),
            (
                reqwest::StatusCode::NOT_FOUND,
                1,
                ArchivePreflightStatus::Missing,
            ),
            (
                reqwest::StatusCode::GONE,
                1,
                ArchivePreflightStatus::Missing,
            ),
            (
                reqwest::StatusCode::FOUND,
                1,
                ArchivePreflightStatus::Failed,
            ),
            (
                reqwest::StatusCode::METHOD_NOT_ALLOWED,
                1,
                ArchivePreflightStatus::Failed,
            ),
            (
                reqwest::StatusCode::REQUEST_TIMEOUT,
                1,
                ArchivePreflightStatus::Retry,
            ),
            (
                reqwest::StatusCode::TOO_MANY_REQUESTS,
                1,
                ArchivePreflightStatus::Retry,
            ),
            (
                reqwest::StatusCode::SERVICE_UNAVAILABLE,
                1,
                ArchivePreflightStatus::Retry,
            ),
            (
                reqwest::StatusCode::SERVICE_UNAVAILABLE,
                2,
                ArchivePreflightStatus::Failed,
            ),
        ] {
            assert_eq!(
                classify_archive_preflight(status, attempt, ARCHIVE_PREFLIGHT_ATTEMPTS),
                expected
            );
        }
    }

    #[test]
    fn archive_preflight_mirrors_framework_but_not_enclave_source() {
        let url = "https://codeberg.org/caution/platform/archive/abc123.tar.gz";

        assert_eq!(archive_preflight_urls(url, false), vec![url.to_string()]);
        assert_eq!(
            archive_preflight_urls(url, true),
            vec![
                url.to_string(),
                "https://github.com/CautionHosting/platform/archive/abc123.tar.gz".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn archive_preflight_falls_back_and_follows_redirects() {
        let (target, target_server) =
            serve_preflight_responses(vec![(reqwest::StatusCode::OK, None)]).await;
        let (mirror, mirror_server) =
            serve_preflight_responses(vec![(reqwest::StatusCode::FOUND, Some(target))]).await;
        let (primary, primary_server) =
            serve_preflight_responses(vec![(reqwest::StatusCode::SERVICE_UNAVAILABLE, None)]).await;
        let client = test_api_client();

        preflight_archive_urls(&client, "Framework source", &[primary, mirror])
            .await
            .unwrap();

        assert_eq!(primary_server.await.unwrap(), 1);
        assert_eq!(mirror_server.await.unwrap(), 1);
        assert_eq!(target_server.await.unwrap(), 1);
    }

    #[tokio::test]
    async fn archive_preflight_retries_transient_primary_before_mirror() {
        let (primary, primary_server) = serve_preflight_responses(vec![
            (reqwest::StatusCode::SERVICE_UNAVAILABLE, None),
            (reqwest::StatusCode::OK, None),
        ])
        .await;
        let mirror = "http://127.0.0.1:1/archive.tar.gz".to_string();
        let client = test_api_client();

        preflight_archive_urls(&client, "Framework source", &[primary, mirror])
            .await
            .unwrap();

        assert_eq!(primary_server.await.unwrap(), 2);
    }

    #[tokio::test]
    async fn archive_preflight_retries_a_single_unmapped_url() {
        let (url, server) = serve_preflight_responses(vec![
            (reqwest::StatusCode::SERVICE_UNAVAILABLE, None),
            (reqwest::StatusCode::OK, None),
        ])
        .await;
        let client = test_api_client();

        preflight_archive_urls(&client, "Enclave source", &[url])
            .await
            .unwrap();

        assert_eq!(server.await.unwrap(), 2);
    }

    #[tokio::test]
    async fn archive_preflight_follows_redirect_for_single_url() {
        // Regression: a single forge URL that redirects (e.g. GitHub → codeload)
        // must still pass. Disabling redirects for single URLs misclassified the
        // 3xx as Failed and hard-failed the preflight with "archive is not
        // available on the remote."
        let (target, target_server) =
            serve_preflight_responses(vec![(reqwest::StatusCode::OK, None)]).await;
        let (primary, primary_server) =
            serve_preflight_responses(vec![(reqwest::StatusCode::FOUND, Some(target))]).await;
        let client = test_api_client();

        preflight_archive_urls(&client, "Enclave source", &[primary])
            .await
            .unwrap();

        assert_eq!(primary_server.await.unwrap(), 1);
        assert_eq!(target_server.await.unwrap(), 1);
    }

    #[test]
    fn preflight_fails_when_branch_absent_from_remote() {
        // The reported regression: branch was never pushed.
        let result = classify_app_source_refs(
            LS_REMOTE,
            "6d1c5d3550cdaf45411052e7194bdcd34c41dac4",
            Some("deploy-tests-missing"),
        );
        assert_eq!(result, Err("deploy-tests-missing".to_string()));
    }

    #[test]
    fn preflight_passes_when_branch_present() {
        // Branch exists even though the deployed commit is an older,
        // non-tip commit on that branch — reachable, proceed.
        let result = classify_app_source_refs(
            LS_REMOTE,
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            Some("deploy-tests"),
        );
        assert_eq!(result, Ok(true));
    }

    #[test]
    fn preflight_passes_when_commit_is_ref_tip_without_branch_hint() {
        // No branch in the manifest, but the commit is a current ref tip.
        let result =
            classify_app_source_refs(LS_REMOTE, "2222222222222222222222222222222222222222", None);
        assert_eq!(result, Ok(true));
    }

    #[test]
    fn preflight_inconclusive_when_commit_not_tip_without_branch_hint() {
        // No branch hint and the commit isn't a ref tip; can't prove it's gone
        // (may be deep in history), so stay inconclusive and let the fetch decide.
        let result =
            classify_app_source_refs(LS_REMOTE, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", None);
        assert_eq!(result, Ok(false));
    }

    #[test]
    fn preflight_matches_short_commit_against_full_ref_sha() {
        // Manifests may carry an abbreviated commit; it should still match the
        // full SHA advertised by ls-remote.
        let result = classify_app_source_refs(LS_REMOTE, "3333333", None);
        assert_eq!(result, Ok(true));
    }

    #[test]
    fn preflight_dangerously_short_commit_does_not_false_match() {
        // A 1-char commit prefixes "1111..." but must NOT be treated as a ref
        // tip — below the 7-char minimum it's not matchable.
        let result = classify_app_source_refs(LS_REMOTE, "1", None);
        assert_eq!(result, Ok(false));
    }

    #[test]
    fn preflight_empty_commit_is_inconclusive_not_a_match() {
        // An empty commit must never match a ref tip (would otherwise prefix-match
        // every line). No branch hint => inconclusive.
        let result = classify_app_source_refs(LS_REMOTE, "", None);
        assert_eq!(result, Ok(false));
    }

    #[test]
    fn preflight_blank_ls_remote_line_does_not_false_match() {
        // A malformed/blank line yields an empty sha field; it must not match the
        // commit and flip an inconclusive result to reachable.
        let listing = "\n   \n\t\n";
        let result =
            classify_app_source_refs(listing, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", None);
        assert_eq!(result, Ok(false));
    }

    #[test]
    fn preflight_empty_branch_name_absent_bails() {
        // Defensive: Some("") builds refs/heads/ which won't be present, so it is
        // reported absent rather than silently passing.
        let result = classify_app_source_refs(LS_REMOTE, "1111111", Some(""));
        assert_eq!(result, Err("".to_string()));
    }

    // --- WebAuthn phase 1: `caution login --username` -------------------

    #[test]
    fn login_parses_username_flag() {
        let cli = Cli::try_parse_from(["caution", "login", "--username", "alice"]).unwrap();
        match cli.command {
            Commands::Login { qr, username } => {
                assert!(!qr);
                assert_eq!(username.as_deref(), Some("alice"));
            }
            other => panic!("expected Commands::Login, got {:?}", other),
        }
    }

    #[test]
    fn login_without_username_flag_leaves_it_unset_for_interactive_prompt() {
        let cli = Cli::try_parse_from(["caution", "login"]).unwrap();
        match cli.command {
            Commands::Login { qr, username } => {
                assert!(!qr);
                // `login()` falls back to `prompt_for_login_username()` when this is `None`.
                assert_eq!(username, None);
            }
            other => panic!("expected Commands::Login, got {:?}", other),
        }
    }

    #[test]
    fn login_username_flag_combines_with_qr() {
        let cli = Cli::try_parse_from(["caution", "login", "--qr", "--username", "bob"]).unwrap();
        match cli.command {
            Commands::Login { qr, username } => {
                assert!(qr);
                assert_eq!(username.as_deref(), Some("bob"));
            }
            other => panic!("expected Commands::Login, got {:?}", other),
        }
    }

    #[test]
    fn register_rejects_qr_flag() {
        let cli =
            Cli::try_parse_from(["caution", "register", "--qr", "--alpha-code", "abc"]).unwrap();
        let err = validate_global_qr(&cli.command, cli.qr)
            .expect_err("register --qr must be rejected, not silently fall back to a local key");
        assert!(matches!(err, RunError::ArgValidation { .. }));
    }

    #[test]
    fn register_without_qr_is_allowed() {
        let cli = Cli::try_parse_from(["caution", "register", "--alpha-code", "abc"]).unwrap();
        assert!(validate_global_qr(&cli.command, cli.qr).is_ok());
    }

    #[test]
    fn global_qr_requires_username_for_login() {
        // --qr now requires --username on login
        let result = Cli::try_parse_from(["caution", "login", "--qr"]);
        assert!(result.is_err());
        let err_str = match result {
            Err(error) => error.to_string(),
            Ok(_) => unreachable!(),
        };
        assert!(err_str.contains("--username") || err_str.contains("MissingRequiredArgument"));
    }

    #[test]
    fn ssh_key_identity_extracts_type_and_data_without_comment() {
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMatchingKeyMaterial user@example";
        assert_eq!(
            ApiClient::ssh_key_identity(key),
            Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMatchingKeyMaterial".to_string())
        );
    }

    #[test]
    fn ssh_key_identity_handles_extra_whitespace() {
        let key = "  ssh-rsa   AAAAB3NzaC1yc2EAAAADAQABAAABAQ...  comment  ";
        assert_eq!(
            ApiClient::ssh_key_identity(key),
            Some("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...".to_string())
        );
    }

    #[test]
    fn ssh_key_identity_rejects_malformed_keys() {
        assert_eq!(ApiClient::ssh_key_identity("not-a-valid-key"), None);
        assert_eq!(ApiClient::ssh_key_identity(""), None);
        assert_eq!(ApiClient::ssh_key_identity("ssh-ed25519"), None);
    }
}
