// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! The `caution verify` build and attestation domain: local-source staging,
//! archive preflight reachability checks, build reproducibility, and attested
//! TLS verification. Extracted from the monolith; see also `secrets`, `cache`,
//! `ssh_keys`, and `pgp_keys`.

use std::fs;
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose};
use bootproof_sdk::VerifiableSignedAttestationFormat;
use bootproof_sdk::format::nitro::{Nitro, NitroPcrs};
use dterror::{BoxError, CtxError, FromContext, Location, ResultExt};
use enclave_builder::{BuildConfig, build_user_image};
use reqwest::tls::TlsInfo;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ApiClient;
use crate::attestation;
use crate::output;
use crate::output::{Spinner, SpinnerStyle};

const ARCHIVE_PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const ARCHIVE_PREFLIGHT_ATTEMPTS: usize = 2;
pub(crate) const MAX_ATTESTATION_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ArchivePreflightStatus {
    Passed,
    Missing,
    Retry,
    Failed,
}

pub(crate) fn classify_archive_preflight(
    status: reqwest::StatusCode,
    attempt: usize,
    attempts: usize,
) -> ArchivePreflightStatus {
    if status.is_success() {
        ArchivePreflightStatus::Passed
    } else if matches!(
        status,
        reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::GONE
    ) {
        ArchivePreflightStatus::Missing
    } else if attempt < attempts
        && (matches!(
            status,
            reqwest::StatusCode::REQUEST_TIMEOUT | reqwest::StatusCode::TOO_MANY_REQUESTS
        ) || status.is_server_error())
    {
        ArchivePreflightStatus::Retry
    } else {
        ArchivePreflightStatus::Failed
    }
}

pub(crate) fn archive_preflight_urls(url: &str, use_platform_mirror: bool) -> Vec<String> {
    if use_platform_mirror {
        enclave_builder::archive_url_candidates(url)
    } else {
        vec![url.to_string()]
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum AppendAttestationResponseChunkError {
    #[error("Attestation response exceeds 1 MiB limit [{location:?}]")]
    ExceedsLimit {
        #[location]
        location: Location,

        #[source]
        #[context(option)]
        source: Option<BoxError>,
    },
}

pub(crate) fn append_attestation_response_chunk(
    body: &mut Vec<u8>,
    chunk: &[u8],
) -> Result<(), AppendAttestationResponseChunkError> {
    if body.len() > MAX_ATTESTATION_RESPONSE_BYTES
        || chunk.len() > MAX_ATTESTATION_RESPONSE_BYTES - body.len()
    {
        return Err(AppendAttestationResponseChunkError::ExceedsLimit {
            location: std::panic::Location::caller(),
            source: None,
        });
    }
    body.extend_from_slice(chunk);
    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum BoundedAttestationResponseJsonError {
    #[error("failed to read attestation response [{location:?}]")]
    ReadChunk {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("attestation response exceeds the allowed size [{location:?}]")]
    AppendChunk {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to parse attestation response as JSON [{location:?}]")]
    ParseJson {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

async fn bounded_attestation_response_json(
    mut response: reqwest::Response,
) -> Result<serde_json::Value, BoundedAttestationResponseJsonError> {
    use BoundedAttestationResponseJsonErrorCtx as Ctx;

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.with_context(Ctx::read_chunk())? {
        append_attestation_response_chunk(&mut body, &chunk).with_context(Ctx::append_chunk())?;
    }
    serde_json::from_slice(&body).with_context(Ctx::parse_json())
}

pub(crate) fn resolve_reproduction_e2e_mode(
    config: Option<&caution_config::E2eEncryption>,
    manifest_has_steve: bool,
) -> Option<caution_config::E2eMode> {
    match config {
        Some(config) if config.mode.is_some() || config.enabled.is_some() => {
            config.effective_mode()
        }
        _ => manifest_has_steve.then_some(caution_config::E2eMode::Steve),
    }
}

pub(crate) fn reproduction_uses_steve(
    config: Option<&caution_config::E2eEncryption>,
    manifest_has_steve: bool,
) -> bool {
    resolve_reproduction_e2e_mode(config, manifest_has_steve)
        == Some(caution_config::E2eMode::Steve)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TlsExpectation {
    pub(crate) domain: String,
}

#[derive(Debug)]
struct ReproductionResult {
    pcrs: enclave_builder::PcrValues,
    tls: Option<TlsExpectation>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub(crate) struct TrustedTls {
    pub(crate) domain: String,
    pub(crate) certfp: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct TrustedHashes<'a> {
    pub(crate) pcr0: &'a str,
    pub(crate) pcr1: &'a str,
    pub(crate) pcr2: &'a str,
    pub(crate) verified_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) tls: Option<TrustedTls>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestedUserData {
    tls: AttestedTls,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestedTls {
    mode: String,
    domain: String,
    certfp: String,
}

#[derive(Debug, PartialEq, Eq)]
enum TlsVerification {
    NotApplicable,
    PcrOnly,
    SkippedNoDns,
    Verified(TrustedTls),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TlsConnection {
    AttestationResponse,
    PinnedIp(IpAddr),
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum TlsConnectionError {
    #[error("TLS verification requires an attestation URL host [{location:?}]")]
    NoHost {
        #[location]
        location: Location,
    },

    #[error(
        "TLS verification requires either the configured HTTPS domain or a raw deployment IP [{location:?}]"
    )]
    InvalidHost {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

pub(crate) fn tls_connection(
    attestation_url: &reqwest::Url,
    configured_domain: &str,
) -> Result<TlsConnection, TlsConnectionError> {
    use TlsConnectionErrorCtx as Ctx;

    if attestation_url.scheme() == "https"
        && attestation_url
            .host_str()
            .is_some_and(|host| host.eq_ignore_ascii_case(configured_domain))
    {
        return Ok(TlsConnection::AttestationResponse);
    }

    let deployment_ip = attestation_url
        .host_str()
        .ok_or(TlsConnectionError::NoHost {
            location: std::panic::Location::caller(),
        })?
        .parse()
        .with_context(Ctx::invalid_host())?;
    Ok(TlsConnection::PinnedIp(deployment_ip))
}

pub(crate) fn dns_answer_is_absent(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::NotFound {
        return true;
    }

    // std does not expose getaddrinfo's EAI_NONAME portably. Match only the
    // platform messages for a definitive no-name/no-data response; all other
    // resolver failures remain fatal.
    let message = error.to_string().to_ascii_lowercase();
    [
        "name or service not known",
        "nodename nor servname provided, or not known",
        "no address associated with hostname",
    ]
    .iter()
    .any(|needle| message.contains(needle))
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum DnsContainsDeploymentIpError {
    #[error(
        "configured TLS domain {domain} does not resolve to deployment IP {deployment_ip} [{location:?}]"
    )]
    NotResolved {
        domain: String,
        deployment_ip: IpAddr,

        #[location]
        location: Location,

        #[source]
        #[context(option)]
        source: Option<BoxError>,
    },
}

pub(crate) fn dns_contains_deployment_ip(
    domain: &str,
    deployment_ip: IpAddr,
    addresses: &[SocketAddr],
) -> Result<bool, DnsContainsDeploymentIpError> {
    if addresses.is_empty() {
        return Ok(false);
    }
    if !addresses
        .iter()
        .any(|address| address.ip() == deployment_ip)
    {
        return Err(DnsContainsDeploymentIpError::NotResolved {
            domain: domain.to_string(),
            deployment_ip,
            location: std::panic::Location::caller(),
            source: None,
        });
    }
    Ok(true)
}

pub(crate) fn verify_deprecation_warnings(from_local: bool, save_pcrs: bool) -> Vec<&'static str> {
    let mut warnings = Vec::new();
    if from_local {
        warnings.push("--from-local is deprecated; local source is now the default");
    }
    if save_pcrs {
        warnings.push("--save-pcrs is deprecated; trusted state is now saved automatically");
    }
    warnings
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum TlsExpectationFromConfigError {
    #[error("tls mode requires a configured domain [{location:?}]")]
    NoDomain {
        #[location]
        location: Location,

        #[source]
        #[context(option)]
        source: Option<BoxError>,
    },
}

pub(crate) fn tls_expectation_from_config(
    config: &caution_config::ConfigurationFile,
) -> Result<Option<TlsExpectation>, TlsExpectationFromConfigError> {
    let http = config
        .enclave
        .as_ref()
        .and_then(|enclaves| enclaves.values().next())
        .and_then(|enclave| enclave.network.as_ref())
        .and_then(|network| network.http.as_ref());
    let is_tls = http
        .and_then(|http| http.e2e_encryption.as_ref())
        .and_then(caution_config::E2eEncryption::effective_mode)
        == Some(caution_config::E2eMode::Tls);

    if !is_tls {
        return Ok(None);
    }

    let domain = http.and_then(|http| http.domain.clone()).ok_or(
        TlsExpectationFromConfigError::NoDomain {
            location: std::panic::Location::caller(),
            source: None,
        },
    )?;
    Ok(Some(TlsExpectation { domain }))
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum AttestationUserDataError {
    #[error("Nitro payload is not a CBOR map [{location:?}]")]
    NotMap {
        #[location]
        location: Location,

        #[source]
        #[context(option)]
        source: Option<BoxError>,
    },

    #[error("Nitro user_data is neither bytes nor null [{location:?}]")]
    NotBytes {
        #[location]
        location: Location,

        #[source]
        #[context(option)]
        source: Option<BoxError>,
    },
}

pub(crate) fn attestation_user_data(
    payload: &serde_cbor::Value,
) -> Result<Option<&[u8]>, AttestationUserDataError> {
    let serde_cbor::Value::Map(payload) = payload else {
        return Err(AttestationUserDataError::NotMap {
            location: std::panic::Location::caller(),
            source: None,
        });
    };
    let Some(value) = payload.get(&serde_cbor::Value::Text("user_data".to_string())) else {
        return Ok(None);
    };
    if value == &serde_cbor::Value::Null {
        return Ok(None);
    }
    let serde_cbor::Value::Bytes(value) = value else {
        return Err(AttestationUserDataError::NotBytes {
            location: std::panic::Location::caller(),
            source: None,
        });
    };
    Ok(Some(value))
}

pub(crate) fn display_user_data(user_data: &[u8]) -> (bool, String) {
    match std::str::from_utf8(user_data) {
        Ok(user_data) => (false, user_data.escape_debug().to_string()),
        Err(_) => (true, hex::encode(user_data)),
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum AttestationInspectionJsonError {
    #[error("failed to serialize parsed attestation payload [{location:?}]")]
    Payload {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to serialize parsed attestation [{location:?}]")]
    SerializeJson {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

pub(crate) fn attestation_inspection_json(
    nonce: &[u8],
    payload: &serde_cbor::Value,
    manifest: Option<&serde_json::Value>,
) -> Result<String, AttestationInspectionJsonError> {
    use AttestationInspectionJsonErrorCtx as Ctx;

    let value = serde_json::json!({
        "verification": "not_performed",
        "challenge_nonce": general_purpose::STANDARD.encode(nonce),
        "attestation_payload": attestation::payload_json(payload).with_context(Ctx::payload())?,
        "response_metadata": {
            "manifest": manifest.cloned().unwrap_or(serde_json::Value::Null),
        },
    });
    serde_json::to_string_pretty(&value).with_context(Ctx::serialize_json())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ValidateAttestedTlsError {
    #[error("verified Nitro user_data is not valid TLS metadata [{location:?}]")]
    ParseUserData {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("attested TLS mode is not tls [{location:?}]")]
    ModeNotTls {
        #[location]
        location: Location,
    },

    #[error(
        "attested TLS domain does not match configured domain {expected_domain} [{location:?}]"
    )]
    DomainMismatch {
        expected_domain: String,

        #[location]
        location: Location,
    },

    #[error("attested TLS certfp is not lowercase SHA-256 hex [{location:?}]")]
    InvalidCertfp {
        #[location]
        location: Location,
    },

    #[error("attested TLS certfp does not match the live leaf certificate [{location:?}]")]
    CertfpMismatch {
        #[location]
        location: Location,
    },
}

pub(crate) fn validate_attested_tls(
    expected: &TlsExpectation,
    user_data: &[u8],
    observed_certfp: &str,
) -> Result<TrustedTls, ValidateAttestedTlsError> {
    use ValidateAttestedTlsErrorCtx as Ctx;

    let user_data: AttestedUserData =
        serde_json::from_slice(user_data).with_context(Ctx::parse_user_data())?;
    if user_data.tls.mode != "tls" {
        return Err(ValidateAttestedTlsError::ModeNotTls {
            location: std::panic::Location::caller(),
        });
    }
    if user_data.tls.domain != expected.domain {
        return Err(ValidateAttestedTlsError::DomainMismatch {
            expected_domain: expected.domain.clone(),
            location: std::panic::Location::caller(),
        });
    }
    if user_data.tls.certfp.len() != 64
        || !user_data
            .tls
            .certfp
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ValidateAttestedTlsError::InvalidCertfp {
            location: std::panic::Location::caller(),
        });
    }
    if user_data.tls.certfp != observed_certfp {
        return Err(ValidateAttestedTlsError::CertfpMismatch {
            location: std::panic::Location::caller(),
        });
    }

    Ok(TrustedTls {
        domain: user_data.tls.domain,
        certfp: user_data.tls.certfp,
    })
}

fn peer_certificate_der(response: &reqwest::Response) -> Option<Vec<u8>> {
    response
        .extensions()
        .get::<TlsInfo>()
        .and_then(TlsInfo::peer_certificate)
        .map(ToOwned::to_owned)
}

#[derive(Debug, thiserror::Error)]
enum TrustedStateBackupPathError {
    #[error("Trusted-state path has no parent: {path} [{location:?}]")]
    NoParent { path: String, location: Location },
}

fn trusted_state_backup_path(path: &Path) -> Result<PathBuf, TrustedStateBackupPathError> {
    let parent = path
        .parent()
        .ok_or_else(|| TrustedStateBackupPathError::NoParent {
            path: path.display().to_string(),
            location: std::panic::Location::caller(),
        })?;
    let timestamp = chrono::Utc::now().format("%Y%m%dT%H%M%S%.fZ");
    for suffix in 0u32.. {
        let suffix = if suffix == 0 {
            String::new()
        } else {
            format!("-{suffix}")
        };
        let candidate = parent.join(format!("trusted_hashes.{timestamp}{suffix}.json"));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    unreachable!("u32 backup suffix space exhausted")
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum PersistTrustedHashesError {
    #[error("failed to persist trusted hashes [{location:?}]")]
    Failure {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

pub(crate) fn persist_trusted_hashes(
    path: &Path,
    trusted: &TrustedHashes<'_>,
) -> Result<Option<PathBuf>, PersistTrustedHashesError> {
    use PersistTrustedHashesErrorCtx as Ctx;

    persist_trusted_hashes_with_backup(path, trusted, |from, to| fs::copy(from, to).map(|_| ()))
        .with_context(Ctx::failure())
}

#[derive(Debug, FromContext)]
pub(crate) enum PersistTrustedHashesWithBackupErrorKind {
    NoParent,

    InvalidParentDir,

    CreateParentDir,

    InspectParentDir,

    InvalidStateFile,

    InspectStateFile,

    Serialize,

    CreateTemp,

    WriteTemp,

    SyncTemp,

    #[allow(dead_code, reason = "used in Display of error")]
    BackupPath {
        backup: Option<PathBuf>,
    },

    #[allow(dead_code, reason = "used in Display of error")]
    BackupFile {
        #[context(borrow = Path)]
        backup: PathBuf,
    },

    ReplaceState,
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("failed to persist trusted hashes at {path:?} ({kind:?}) [{location:?}]")]
pub(crate) struct PersistTrustedHashesWithBackupError {
    #[context(borrow = Path)]
    path: PathBuf,

    #[context(from = PersistTrustedHashesWithBackupErrorKindCtx<'a>)]
    kind: PersistTrustedHashesWithBackupErrorKind,

    #[location]
    location: Location,

    #[source]
    source: Option<BoxError>,
}

pub(crate) fn persist_trusted_hashes_with_backup<F>(
    path: &Path,
    trusted: &TrustedHashes<'_>,
    mut backup_file: F,
) -> Result<Option<PathBuf>, PersistTrustedHashesWithBackupError>
where
    F: FnMut(&Path, &Path) -> io::Result<()>,
{
    use PersistTrustedHashesWithBackupErrorCtx as Ctx;
    use PersistTrustedHashesWithBackupErrorKindCtx as KindCtx;

    let parent = path
        .parent()
        .ok_or_else(|| PersistTrustedHashesWithBackupError {
            kind: PersistTrustedHashesWithBackupErrorKind::NoParent,
            path: path.to_path_buf(),
            location: std::panic::Location::caller(),
            source: None,
        })?;

    match fs::symlink_metadata(parent) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(PersistTrustedHashesWithBackupError {
                    kind: PersistTrustedHashesWithBackupErrorKind::InvalidParentDir,
                    path: path.to_path_buf(),
                    location: std::panic::Location::caller(),
                    source: None,
                });
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(parent).with_context(Ctx::new(path, KindCtx::create_parent_dir()))?;
        }
        Err(source) => {
            return Err(PersistTrustedHashesWithBackupError::from_context(
                Ctx::new(path, KindCtx::inspect_parent_dir()),
                std::panic::Location::caller(),
                source.into(),
            ));
        }
    }

    let existing = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(PersistTrustedHashesWithBackupError {
                    kind: PersistTrustedHashesWithBackupErrorKind::InvalidStateFile,
                    path: path.to_path_buf(),
                    location: std::panic::Location::caller(),
                    source: None,
                });
            }
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(source) => {
            return Err(PersistTrustedHashesWithBackupError::from_context(
                Ctx::new(path, KindCtx::inspect_state_file()),
                std::panic::Location::caller(),
                source.into(),
            ));
        }
    };

    let mut serialized =
        serde_json::to_string_pretty(trusted).with_context(Ctx::new(path, KindCtx::serialize()))?;
    serialized.push('\n');
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(Ctx::new(path, KindCtx::create_temp()))?;
    temporary
        .write_all(serialized.as_bytes())
        .with_context(Ctx::new(path, KindCtx::write_temp()))?;
    temporary
        .as_file()
        .sync_all()
        .with_context(Ctx::new(path, KindCtx::sync_temp()))?;

    let backup = if existing {
        loop {
            let backup = trusted_state_backup_path(path)
                .with_context(Ctx::new(path, KindCtx::backup_path(None)))?;
            match backup_file(path, &backup) {
                Ok(()) => break Some(backup),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(source) => {
                    return Err(PersistTrustedHashesWithBackupError::from_context(
                        Ctx::new(path, KindCtx::backup_file(&backup)),
                        std::panic::Location::caller(),
                        source.into(),
                    ));
                }
            }
        }
    } else {
        None
    };

    temporary
        .persist(path)
        .with_context(Ctx::new(path, KindCtx::replace_state()))?;

    Ok(backup)
}
/// Egress is enabled iff the (single) enclave's network block declares >=1 egress rule.
/// Derived solely from the parsed HCL config — never from a manifest.
pub(crate) fn configured_enclave(
    cfg: &caution_config::ConfigurationFile,
) -> Option<&caution_config::EnclaveConfig> {
    cfg.enclave
        .as_ref()
        .and_then(|enclaves| enclaves.values().next())
}

fn config_egress_enabled(cfg: &caution_config::ConfigurationFile) -> bool {
    configured_enclave(cfg)
        .and_then(|enc| enc.network.as_ref())
        .map(|n| n.egress_enabled())
        .unwrap_or(false)
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum MeasuredBuildCacheKeyError {
    #[error("failed to serialize deployment config for cache key [{location:?}]")]
    SerializeConfig {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

/// Add the normalized deployment configuration to a local EIF cache key.
///
/// Git identity alone is insufficient because local builds may consume an
/// uncommitted `caution.hcl`. The generated, measured `run.sh` depends on this
/// configuration and, for E2E builds, the effective STEVE commit.
pub(crate) fn measured_build_cache_key(
    source_key: &str,
    cfg: &caution_config::ConfigurationFile,
    steve_commit: Option<&str>,
) -> Result<String, MeasuredBuildCacheKeyError> {
    use MeasuredBuildCacheKeyErrorCtx as Ctx;

    let config_json = serde_json::to_vec(cfg).with_context(Ctx::serialize_config())?;
    let mut hasher = Sha256::new();
    hasher.update(&config_json);
    if let Some(steve_commit) = steve_commit {
        hasher.update(b"|steve|");
        hasher.update(steve_commit.as_bytes());
    }
    let config_hash = hex::encode(hasher.finalize());
    Ok(format!("{}-config-{}", source_key, config_hash))
}
fn framework_cache_key(source_key: &str, framework_commit: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(source_key.as_bytes());
    hasher.update(b"|framework|");
    hasher.update(framework_commit.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Interpret the result of a `git rev-parse` invocation.
///
/// Returns `Some(value)` only when the command exited successfully AND produced
/// non-empty stdout after trimming. A successful run that emits no output (or
/// only whitespace) is treated as a failure so callers fall back to their UUID
/// fallback instead of building an invalid Docker tag (an empty tag suffix such
/// as `caution-local-build:`) or an empty cache key.
fn parse_git_rev_parse_output(success: bool, stdout: &[u8]) -> Option<String> {
    if !success {
        return None;
    }
    let value = String::from_utf8_lossy(stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}

struct StagedSource {
    path: PathBuf,
    cache_key: String,
    app_commit: Option<String>,
    _temp_dir: tempfile::TempDir,
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum BuildLocalError {
    #[error("failed to read deployment config")]
    ReadConfig {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to resolve the Platform framework build input")]
    BuildInput {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to build Docker image")]
    BuildDockerImage {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to resolve cache directory")]
    CacheDir {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to derive measured build cache key")]
    CacheKey {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to initialize enclave builder")]
    InitBuilder {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to parse run command")]
    ParseRunCommand {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to build enclave")]
    BuildEnclave {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}
pub(crate) async fn build_local(client: &ApiClient, no_cache: bool) -> Result<(), BuildLocalError> {
    use BuildLocalErrorCtx as Ctx;

    output::status("Building EIF locally for inspection...");

    let (framework_commit, framework_source) = client
        .current_platform_framework_source()
        .await
        .with_context(Ctx::build_input())?;

    let app_commit = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|o| parse_git_rev_parse_output(o.status.success(), &o.stdout));
    let app_branch = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()
        .and_then(|o| parse_git_rev_parse_output(o.status.success(), &o.stdout));
    let source_cache_key = app_commit
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let cfg = client.read_config().with_context(Ctx::read_config())?;
    let enclave = configured_enclave(&cfg);
    let e2e_config = enclave
        .and_then(|e| e.network.as_ref())
        .and_then(|n| n.http.as_ref())
        .and_then(|h| h.e2e_encryption.as_ref());
    let e2e_mode = e2e_config.and_then(|config| config.effective_mode());
    let e2e = e2e_mode == Some(caution_config::E2eMode::Steve);
    let e2e_mode_value = e2e_mode.map(|mode| mode.as_str()).unwrap_or("disabled");
    let steve_commit = e2e.then(enclave_builder::build::resolve_steve_commit);
    let measured_cache_key =
        measured_build_cache_key(&source_cache_key, &cfg, steve_commit.as_deref())
            .with_context(Ctx::cache_key())?;
    let cache_key = framework_cache_key(&measured_cache_key, &framework_commit);

    let config_no_cache = enclave
        .and_then(|e| e.build.as_ref())
        .and_then(|b| b.cache)
        .map(|c| !c)
        .unwrap_or(false);
    let no_cache = no_cache || config_no_cache;

    let loader = Spinner::new("Building application image", SpinnerStyle::Processing);
    let image_ref = build_local_docker_image(client, no_cache)
        .await
        .with_context(Ctx::build_docker_image())?;
    loader.finish();
    output::success(format!("✓ Application image built: {}", image_ref));

    let cache_dir = client.get_cache_dir().with_context(Ctx::cache_dir())?;
    let builder = enclave_builder::EnclaveBuilder::new_with_cache(
        enclave_builder::enclave_source_url(&enclave_builder::build::resolve_enclaveos_commit()),
        "unused",
        &framework_source,
        "local",
        &cache_key,
        enclave_builder::CacheType::Build,
        no_cache,
        &cache_dir,
    )
    .with_context(Ctx::init_builder())?;

    let work_dir = builder.work_dir.clone();

    let user_image = enclave_builder::UserImage {
        reference: image_ref.clone(),
    };

    let run_command = enclave
        .and_then(|e| e.unit.as_ref())
        .and_then(|u| u.values().next())
        .map(|u| u.run_command_string())
        .transpose()
        .with_context(Ctx::parse_run_command())?;

    let app_source_urls_opt = enclave
        .and_then(|e| e.build.as_ref())
        .map(|b| b.app_sources.clone())
        .filter(|s| !s.is_empty());

    let ports: Vec<u16> = enclave
        .and_then(|e| e.network.as_ref())
        .map(|n| {
            n.ingress
                .iter()
                .filter_map(|rule| match &rule.port_spec {
                    Some(caution_config::PortSpec::Exact { port }) => Some(*port),
                    _ => None,
                })
                .collect::<Vec<u16>>()
        })
        .unwrap_or_default();

    let http_port = enclave
        .and_then(|config| config.network.as_ref())
        .and_then(|network| network.http.as_ref())
        .map(|http| http.port);
    output::verbose(client.verbose, format!("HTTP port: {:?}", http_port));

    let domain = enclave
        .and_then(|config| config.network.as_ref())
        .and_then(|network| network.http.as_ref())
        .and_then(|http| http.domain.clone());

    let e2e_key_exchange = e2e_config
        .map(|ee| ee.key_exchange().steve_env_value())
        .unwrap_or(caution_config::KeyExchange::X25519.steve_env_value());
    let allow_plaintext_fallback = e2e_config
        .map(|ee| ee.allow_plaintext_fallback())
        .unwrap_or(false);
    output::verbose(client.verbose, format!("E2E encryption: {}", e2e));

    let locksmith = cfg.has_vault_env();
    output::verbose(client.verbose, format!("Locksmith secrets: {}", locksmith));

    let egress = config_egress_enabled(&cfg);
    output::verbose(client.verbose, format!("Egress: {}", egress));

    let e2e_cors_origins = e2e_config
        .and_then(|e2e| e2e.cors_origins.as_ref())
        .map(|origins| origins.join(","));

    let http_upstream_protocol = enclave
        .and_then(|config| config.network.as_ref())
        .and_then(|network| network.http.as_ref())
        .and_then(|http| http.upstream_protocol)
        .map(|protocol| protocol.as_str())
        .unwrap_or("http");
    output::verbose(
        client.verbose,
        format!("HTTP upstream protocol: {}", http_upstream_protocol),
    );

    let loader = Spinner::new("Building enclave image", SpinnerStyle::Processing);
    output::verbose(client.verbose, "Using build_enclave");
    let deployment = builder
        .build_enclave(
            &user_image,
            None,
            run_command,
            app_source_urls_opt,
            app_branch.clone(),
            app_commit.clone(),
            None,
            None,
            &ports,
            http_port,
            e2e,
            e2e_mode_value,
            e2e_key_exchange,
            allow_plaintext_fallback,
            domain.as_deref(),
            http_upstream_protocol,
            locksmith,
            e2e_cors_origins,
            egress,
        )
        .await
        .with_context(Ctx::build_enclave())?;
    loader.finish();

    output::success("✓ Enclave built successfully!");

    let stage_dir = work_dir.join("eif-stage");
    output::status("=== Build Artifacts ===");
    output::status(format!("EIF file: {}", deployment.eif.path.display()));
    output::status(format!("Size: {} bytes", deployment.eif.size));
    output::status(format!("SHA256: {}", deployment.eif.sha256));

    output::status("=== PCR Values ===");
    output::status(format!("PCR0 (Enclave image): {}", deployment.pcrs.pcr0));
    output::status(format!("PCR1 (Kernel/boot): {}", deployment.pcrs.pcr1));
    output::status(format!("PCR2 (Application): {}", deployment.pcrs.pcr2));

    output::status("=== Build Directory ===");
    output::status(format!("Location: {}", stage_dir.display()));
    output::status("You can inspect the exact build process:");
    output::status("  Containerfile.eif - Shows exactly how the EIF is built");
    output::status("  app/ - Your application files");
    output::status("  enclave/ - Enclave source code");
    output::status("  kernel/ - Kernel files");
    output::status("  output/ - Final EIF and PCRs files");

    output::status("To verify your deployed enclave matches this build:");
    output::status("  caution verify");

    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum BuildAndGetPcrsError {
    #[error("failed to resolve platform framework source [{location:?}]")]
    FrameworkSource {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to serialize manifest for cache key [{location:?}]")]
    SerializeManifest {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error(
        "manifest does not contain app_source - cannot reproduce without source URL [{location:?}]"
    )]
    MissingAppSource {
        #[location]
        location: Location,
    },

    #[error("app source preflight failed [{location:?}]")]
    PreflightAppSourceRef {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to download app source [{location:?}]")]
    DownloadAppSource {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to read caution configuration from directory [{location:?}]")]
    ReadConfigDir {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to read caution configuration [{location:?}]")]
    ReadConfig {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to derive TLS expectation from configuration [{location:?}]")]
    TlsExpectation {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to compute measured build cache key [{location:?}]")]
    MeasuredBuildCacheKey {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to resolve cache directory [{location:?}]")]
    GetCacheDir {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to construct enclave builder [{location:?}]")]
    NewBuilder {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("source archive preflight failed [{location:?}]")]
    PreflightArchive {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to build Docker image from directory [{location:?}]")]
    BuildDockerImageFromDir {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to build local Docker image [{location:?}]")]
    BuildLocalDockerImage {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to build run command string [{location:?}]")]
    RunCommandString {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to build enclave locally [{location:?}]")]
    BuildEnclave {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

async fn build_and_get_pcrs(
    client: &ApiClient,
    external_manifest: Option<enclave_builder::EnclaveManifest>,
    no_cache: bool,
    local_source: Option<&StagedSource>,
) -> Result<ReproductionResult, BuildAndGetPcrsError> {
    use BuildAndGetPcrsErrorCtx as Ctx;

    let public_framework = if external_manifest.is_none() {
        Some(
            client
                .current_platform_framework_source()
                .await
                .with_context(Ctx::framework_source())?,
        )
    } else {
        None
    };
    let no_cache = if let Some(source) = local_source {
        no_cache
            || client
                .read_config_from_dir(&source.path)
                .ok()
                .and_then(|cfg| {
                    cfg.enclave
                        .and_then(|e| e.into_iter().next().map(|(_, v)| v))
                })
                .and_then(|e| e.build)
                .and_then(|b| b.cache)
                .map(|c| !c)
                .unwrap_or(false)
    } else {
        no_cache
    };

    let (enclave_source, enclave_version) = if let Some(ref manifest) = external_manifest {
        match &manifest.enclave_source {
            enclave_builder::EnclaveSource::GitArchive { urls, commit } => {
                let url = urls.first().cloned().unwrap_or_default();
                let pinned = if let Some(commit) = commit {
                    enclave_builder::pin_archive_url_to_commit(&url, commit)
                } else {
                    url
                };
                (pinned, "unused".to_string())
            }
            enclave_builder::EnclaveSource::GitRepository { url, branch, .. } => {
                (url.clone(), branch.clone())
            }
            enclave_builder::EnclaveSource::Local { path } => (path.clone(), "local".to_string()),
        }
    } else {
        let source = enclave_builder::enclave_source_url(
            &enclave_builder::build::resolve_enclaveos_commit(),
        );
        output::verbose(
            client.verbose,
            format!("Using default enclave source: {}", source),
        );
        (source, "unused".to_string())
    };

    let framework_source = if let Some(ref manifest) = external_manifest {
        match &manifest.framework_source {
            enclave_builder::FrameworkSource::GitArchive { url, commit } => {
                if let Some(commit) = commit {
                    enclave_builder::pin_archive_url_to_commit(url, commit)
                } else {
                    url.clone()
                }
            }
        }
    } else {
        public_framework
            .as_ref()
            .expect("manifestless builds resolve public framework input")
            .1
            .clone()
    };

    let source_cache_key = if let Some(source) = local_source {
        if let Some(ref manifest) = external_manifest {
            let manifest_json =
                serde_json::to_vec(manifest).with_context(Ctx::serialize_manifest())?;
            let manifest_hash = hex::encode(Sha256::digest(&manifest_json));
            format!("{}-{}", source.cache_key, &manifest_hash[..16])
        } else {
            framework_cache_key(
                &source.cache_key,
                &public_framework
                    .as_ref()
                    .expect("manifestless builds resolve public framework input")
                    .0,
            )
        }
    } else if let Some(ref manifest) = external_manifest {
        let manifest_json = serde_json::to_vec(manifest).with_context(Ctx::serialize_manifest())?;
        let manifest_hash = hex::encode(Sha256::digest(&manifest_json));
        if let Some(ref app_src) = manifest.app_source {
            format!("{}-{}", app_src.commit, &manifest_hash[..16])
        } else {
            format!("manifest-{}", &manifest_hash[..16])
        }
    } else {
        let source_key = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()
            .and_then(|o| parse_git_rev_parse_output(o.status.success(), &o.stdout))
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        framework_cache_key(
            &source_key,
            &public_framework
                .as_ref()
                .expect("manifestless builds resolve public framework input")
                .0,
        )
    };

    let app_source_dir =
        if let Some(source) = local_source {
            Some(source.path.clone())
        } else if let Some(ref manifest) = external_manifest {
            let app_source = manifest.app_source.as_ref().ok_or_else(|| {
                BuildAndGetPcrsError::MissingAppSource {
                    location: std::panic::Location::caller(),
                }
            })?;
            let archive_urls: Vec<String> = app_source
                .urls
                .iter()
                .filter_map(|url| client.git_url_to_archive_urls(url, &app_source.commit).ok())
                .flatten()
                .collect();
            let git_fallback = app_source.urls.first().map(|url| {
                (
                    url.clone(),
                    app_source.commit.clone(),
                    app_source.branch.clone(),
                )
            });

            if let Some((ref url, ref commit, ref branch)) = git_fallback {
                preflight_app_source_ref(client, url, commit, branch.as_deref())
                    .with_context(Ctx::preflight_app_source_ref())?;
            }

            Some(
                download_and_extract_app_source_with_git_fallback(
                    client,
                    &archive_urls,
                    git_fallback
                        .as_ref()
                        .map(|(u, c, b)| (u.as_str(), c.as_str(), b.as_deref())),
                )
                .await
                .with_context(Ctx::download_app_source())?,
            )
        } else {
            None
        };

    let measured_config = if let Some(ref app_dir) = app_source_dir {
        Some(
            client
                .read_config_from_dir(app_dir)
                .with_context(Ctx::read_config_dir())?,
        )
    } else if external_manifest.is_none() {
        Some(client.read_config().with_context(Ctx::read_config())?)
    } else {
        None
    };
    let tls = measured_config
        .as_ref()
        .map(tls_expectation_from_config)
        .transpose()
        .with_context(Ctx::tls_expectation())?
        .flatten();
    let cache_key = match measured_config.as_ref() {
        Some(cfg) => {
            let e2e_config = cfg
                .enclave
                .as_ref()
                .and_then(|e| e.values().next())
                .and_then(|enc| enc.network.as_ref())
                .and_then(|network| network.http.as_ref())
                .and_then(|http| http.e2e_encryption.as_ref());
            let manifest_steve_commit = external_manifest
                .as_ref()
                .and_then(|manifest| manifest.steve_commit.as_ref());
            let e2e = reproduction_uses_steve(e2e_config, manifest_steve_commit.is_some());
            let steve_commit = e2e.then(|| {
                manifest_steve_commit
                    .cloned()
                    .unwrap_or_else(enclave_builder::build::resolve_steve_commit)
            });
            measured_build_cache_key(&source_cache_key, cfg, steve_commit.as_deref())
                .with_context(Ctx::measured_build_cache_key())?
        }
        // Manifest reproductions already hash the full manifest, including
        // steve_commit, into source_cache_key.
        None => source_cache_key,
    };

    let cache_dir = client.get_cache_dir().with_context(Ctx::get_cache_dir())?;
    let builder = enclave_builder::EnclaveBuilder::new_with_cache(
        &enclave_source,
        &enclave_version,
        &framework_source,
        "local",
        &cache_key,
        enclave_builder::CacheType::Reproduction,
        no_cache,
        &cache_dir,
    )
    .with_context(Ctx::new_builder())?;

    if let Some(cached) = builder.get_cached_eif() {
        output::status("Using cached reproduction build");
        output::status(format!("Cache key: {}", cache_key));
        return Ok(ReproductionResult {
            pcrs: cached.pcrs,
            tls,
        });
    }

    // Preflight the enclave/framework source archives before the expensive
    // build. They are deterministic URLs derived from the manifest; a 404'd
    // commit otherwise only surfaces after the Docker image build and
    // user-filesystem extraction (minutes in). Only meaningful when
    // reproducing from a manifest.
    if external_manifest.is_some() {
        preflight_archive_url(client, "Enclave source", &enclave_source, false)
            .await
            .with_context(Ctx::preflight_archive())?;
        preflight_archive_url(client, "Framework source", &framework_source, true)
            .await
            .with_context(Ctx::preflight_archive())?;
    }

    output::verbose(client.verbose, "Building Docker image locally...");

    let loader = Spinner::new("Reproducing enclave image", SpinnerStyle::Processing);
    let image_ref = if let Some(ref app_dir) = app_source_dir {
        build_docker_image_from_dir(client, app_dir, no_cache)
            .await
            .with_context(Ctx::build_docker_image_from_dir())?
    } else {
        build_local_docker_image(client, no_cache)
            .await
            .with_context(Ctx::build_local_docker_image())?
    };

    output::verbose(
        client.verbose,
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

            output::verbose(
                client.verbose,
                format!("Binary from manifest: {:?}", binary),
            );
            output::verbose(
                client.verbose,
                format!("Run command from manifest: {:?}", run_cmd),
            );
            output::verbose(
                client.verbose,
                format!("App source URLs from manifest: {:?}", source_urls),
            );
            output::verbose(
                client.verbose,
                format!("Branch from manifest: {:?}", branch),
            );
            output::verbose(
                client.verbose,
                format!("Commit from manifest: {:?}", commit),
            );

            (
                binary,
                run_cmd,
                source_urls,
                branch,
                commit,
                manifest.metadata.clone(),
            )
        } else {
            let config_dir = app_source_dir.as_deref().unwrap_or(Path::new("."));
            let cfg = client
                .read_config_from_dir(config_dir)
                .with_context(Ctx::read_config_dir())?;
            let enclave = configured_enclave(&cfg);

            let binary = None;
            let run_cmd = enclave
                .and_then(|e| e.unit.as_ref())
                .and_then(|u| u.values().next())
                .map(|u| u.run_command_string())
                .transpose()
                .with_context(Ctx::run_command_string())?;
            let source_urls = enclave
                .and_then(|e| e.build.as_ref())
                .map(|b| b.app_sources.clone())
                .filter(|s| !s.is_empty());
            let commit = local_source
                .and_then(|source| source.app_commit.clone())
                .or_else(|| {
                    Command::new("git")
                        .args(["rev-parse", "HEAD"])
                        .current_dir(config_dir)
                        .output()
                        .ok()
                        .and_then(|o| parse_git_rev_parse_output(o.status.success(), &o.stdout))
                });

            let branch = Command::new("git")
                .args(["rev-parse", "--abbrev-ref", "HEAD"])
                .current_dir(config_dir)
                .output()
                .ok()
                .and_then(|o| parse_git_rev_parse_output(o.status.success(), &o.stdout));

            output::verbose(
                client.verbose,
                format!("Run command from config: {:?}", run_cmd),
            );
            output::verbose(
                client.verbose,
                format!("Source URLs from config: {:?}", source_urls),
            );
            output::verbose(client.verbose, format!("Git branch: {:?}", branch));
            output::verbose(client.verbose, format!("Git commit: {:?}", commit));

            (binary, run_cmd, source_urls, branch, commit, None)
        };

    let ports: Vec<u16> = {
        let config_dir = app_source_dir.as_deref().unwrap_or(Path::new("."));
        client
            .read_config_from_dir(config_dir)
            .ok()
            .and_then(|cfg| {
                cfg.enclave
                    .and_then(|e| e.into_iter().next().map(|(_, v)| v))
            })
            .and_then(|e| e.network)
            .map(|n| {
                n.ingress
                    .iter()
                    .filter_map(|rule| match &rule.port_spec {
                        Some(caution_config::PortSpec::Exact { port }) => Some(*port),
                        _ => None,
                    })
                    .collect::<Vec<u16>>()
            })
            .unwrap_or_default()
    };
    output::verbose(client.verbose, format!("Ports: {:?}", ports));

    let http_config = {
        let config_dir = app_source_dir.as_deref().unwrap_or(Path::new("."));
        client
            .read_config_from_dir(config_dir)
            .ok()
            .and_then(|cfg| {
                cfg.enclave
                    .and_then(|e| e.into_iter().next().map(|(_, v)| v))
            })
            .and_then(|config| config.network)
            .and_then(|network| network.http)
    };
    let http_port = http_config.as_ref().map(|http| http.port);
    output::verbose(client.verbose, format!("HTTP port: {:?}", http_port));

    let http_upstream_protocol = http_config
        .as_ref()
        .and_then(|http| http.upstream_protocol)
        .map(|protocol| protocol.as_str())
        .unwrap_or("http");
    output::verbose(
        client.verbose,
        format!("HTTP upstream protocol: {}", http_upstream_protocol),
    );

    let domain = http_config.as_ref().and_then(|http| http.domain.clone());
    let e2e_config = http_config
        .as_ref()
        .and_then(|http| http.e2e_encryption.clone());

    let manifest_has_steve = external_manifest
        .as_ref()
        .and_then(|manifest| manifest.steve_commit.as_ref())
        .is_some();
    let e2e_mode = resolve_reproduction_e2e_mode(e2e_config.as_ref(), manifest_has_steve);
    let e2e = e2e_mode == Some(caution_config::E2eMode::Steve);
    let e2e_mode_value = e2e_mode.map(|mode| mode.as_str()).unwrap_or("disabled");
    let e2e_key_exchange = e2e_config
        .as_ref()
        .map(|e2e| e2e.key_exchange().steve_env_value().to_string())
        .unwrap_or_else(|| {
            // No readable config: fall back to what the deployment recorded,
            // otherwise reproduction would silently rebuild with X25519.
            external_manifest
                .as_ref()
                .and_then(|manifest| manifest.steve_key_exchange.clone())
                .unwrap_or_else(|| {
                    caution_config::KeyExchange::X25519
                        .steve_env_value()
                        .to_string()
                })
        });
    let allow_plaintext_fallback = e2e_config
        .as_ref()
        .map(|e2e| e2e.allow_plaintext_fallback())
        .unwrap_or_else(|| {
            external_manifest
                .as_ref()
                .map(|manifest| manifest.steve_allow_plaintext_fallback)
                .unwrap_or(false)
        });
    output::verbose(client.verbose, format!("E2E encryption: {}", e2e));

    let locksmith = if let Some(ref app_dir) = app_source_dir {
        client
            .read_config_from_dir(app_dir)
            .ok()
            .map(|cfg| cfg.has_vault_env())
            .unwrap_or_else(|| {
                external_manifest
                    .as_ref()
                    .map(|manifest| manifest.locksmith || manifest.locksmith_commit.is_some())
                    .unwrap_or(false)
            })
    } else if let Some(ref manifest) = external_manifest {
        manifest.locksmith || manifest.locksmith_commit.is_some()
    } else {
        client
            .read_config()
            .ok()
            .map(|cfg| cfg.has_vault_env())
            .unwrap_or(false)
    };
    output::verbose(client.verbose, format!("Locksmith secrets: {}", locksmith));

    let egress = if let Some(ref app_dir) = app_source_dir {
        client
            .read_config_from_dir(app_dir)
            .ok()
            .map(|cfg| config_egress_enabled(&cfg))
            .unwrap_or(false)
    } else if external_manifest.is_some() {
        // Egress is intentionally never read from the manifest; default-deny.
        false
    } else {
        client
            .read_config()
            .ok()
            .map(|cfg| config_egress_enabled(&cfg))
            .unwrap_or(false)
    };
    output::verbose(client.verbose, format!("Egress: {}", egress));

    let e2e_cors_origins = if e2e {
        e2e_config
            .as_ref()
            .and_then(|e2e| e2e.cors_origins.as_ref())
            .map(|origins| origins.join(","))
    } else {
        None
    };

    let deployment = if let Some(ref bin_path) = binary_path {
        output::verbose(
            client.verbose,
            format!("Using build_enclave_auto with binary: {}", bin_path),
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
                http_port,
                e2e,
                e2e_mode_value,
                &e2e_key_exchange,
                allow_plaintext_fallback,
                domain.as_deref(),
                http_upstream_protocol,
                locksmith,
                e2e_cors_origins,
                egress,
            )
            .await
    } else {
        output::verbose(client.verbose, "Using build_enclave (no binary specified)");
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
                http_port,
                e2e,
                e2e_mode_value,
                &e2e_key_exchange,
                allow_plaintext_fallback,
                domain.as_deref(),
                http_upstream_protocol,
                locksmith,
                e2e_cors_origins,
                egress,
            )
            .await
    }
    .with_context(Ctx::build_enclave())?;
    loader.finish();

    if let Some(work_dir) = deployment.eif.path.parent() {
        let stage_dir = work_dir.join("eif-stage");
        if stage_dir.exists() {
            output::status("");
            output::status(format!(
                "Build artifacts available at: {}",
                stage_dir.display()
            ));
            output::status("You can review everything that went into building this enclave:");
            output::status("  • Containerfile.eif - The complete build recipe");
            output::status("  • app/ - Your application files");
            output::status("  • enclave/ - EnclaveOS source (attestation-service, init)");
            output::status("  • run.sh - Generated startup script");
            output::status("  • manifest.json - Build provenance information");
        }
    }

    Ok(ReproductionResult {
        pcrs: deployment.pcrs,
        tls,
    })
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum ReadPcrsFromFileErrorKind {
    Read,
    Incomplete,
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("failed to read PCRs file at {path} ({kind:?}) [{location:?}]")]
pub(crate) struct ReadPcrsFromFileError {
    #[context(borrow = str)]
    path: String,

    kind: ReadPcrsFromFileErrorKind,

    #[location]
    location: Location,

    #[source]
    source: Option<BoxError>,
}

fn read_pcrs_from_file(path: &str) -> Result<enclave_builder::PcrValues, ReadPcrsFromFileError> {
    use ReadPcrsFromFileErrorCtx as Ctx;

    let content =
        fs::read_to_string(path).with_context(Ctx::new(path, ReadPcrsFromFileErrorKind::Read))?;

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
        _ => Err(ReadPcrsFromFileError {
            path: path.to_string(),
            kind: ReadPcrsFromFileErrorKind::Incomplete,
            location: std::panic::Location::caller(),
            source: None,
        }),
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
enum VerifyTlsBindingError {
    #[error("failed to read TLS user_data from the attestation [{location:?}]")]
    UserData {
        #[location]
        location: Location,

        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    #[error("verified Nitro attestation is missing TLS user_data [{location:?}]")]
    MissingUserData {
        #[location]
        location: Location,
    },

    #[error("failed to determine the TLS connection mode [{location:?}]")]
    TlsConnection {
        #[location]
        location: Location,

        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    #[error("HTTPS attestation response did not expose its leaf certificate [{location:?}]")]
    MissingLeaf {
        #[location]
        location: Location,
    },

    #[error("failed to validate the attested TLS metadata [{location:?}]")]
    Validate {
        #[location]
        location: Location,

        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    #[error("failed to resolve configured TLS domain {domain} [{location:?}]")]
    ResolveDns {
        domain: String,

        #[location]
        location: Location,

        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    #[error("failed to check the deployment IP against configured TLS domain [{location:?}]")]
    DnsCheck {
        #[location]
        location: Location,

        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    #[error("failed to create pinned TLS verification client [{location:?}]")]
    BuildClient {
        #[location]
        location: Location,

        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    #[error("TLS health request failed for {domain} [{location:?}]")]
    HealthRequest {
        domain: String,

        #[location]
        location: Location,

        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    #[error("TLS health request returned {status} [{location:?}]")]
    HealthStatus {
        status: reqwest::StatusCode,

        #[location]
        location: Location,
    },

    #[error("TLS health response did not expose its leaf certificate [{location:?}]")]
    MissingHealthLeaf {
        #[location]
        location: Location,
    },
}

async fn verify_tls_binding(
    expected: &TlsExpectation,
    payload: &serde_cbor::Value,
    attestation_url: &reqwest::Url,
    attestation_leaf: Option<&[u8]>,
) -> Result<TlsVerification, VerifyTlsBindingError> {
    use VerifyTlsBindingErrorCtx as Ctx;

    let user_data = attestation_user_data(payload)
        .with_context(Ctx::user_data())?
        .ok_or(VerifyTlsBindingError::MissingUserData {
            location: std::panic::Location::caller(),
        })?;

    let deployment_ip = match tls_connection(attestation_url, &expected.domain)
        .with_context(Ctx::tls_connection())?
    {
        TlsConnection::AttestationResponse => {
            let leaf = attestation_leaf.ok_or(VerifyTlsBindingError::MissingLeaf {
                location: std::panic::Location::caller(),
            })?;
            let observed_certfp = hex::encode(Sha256::digest(leaf));
            let tls = validate_attested_tls(expected, user_data, &observed_certfp)
                .with_context(Ctx::validate())?;
            return Ok(TlsVerification::Verified(tls));
        }
        TlsConnection::PinnedIp(ip) => ip,
    };
    let addresses: Vec<SocketAddr> = match tokio::net::lookup_host((&*expected.domain, 443)).await {
        Ok(addresses) => addresses.collect(),
        Err(error) if dns_answer_is_absent(&error) => {
            return Ok(TlsVerification::SkippedNoDns);
        }
        Err(source) => {
            return Err(VerifyTlsBindingError::ResolveDns {
                domain: expected.domain.clone(),
                location: std::panic::Location::caller(),
                source: source.into(),
            });
        }
    };
    if !dns_contains_deployment_ip(&expected.domain, deployment_ip, &addresses)
        .with_context(Ctx::dns_check())?
    {
        return Ok(TlsVerification::SkippedNoDns);
    }

    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .tls_info(true)
        .resolve(&expected.domain, SocketAddr::new(deployment_ip, 443))
        .build()
        .with_context(Ctx::build_client())?;
    let health_url = format!("https://{}/.well-known/caution/health", expected.domain);
    let response = client
        .get(&health_url)
        .send()
        .await
        .with_context(Ctx::health_request(expected.domain.clone()))?;
    if !response.status().is_success() {
        return Err(VerifyTlsBindingError::HealthStatus {
            status: response.status(),
            location: std::panic::Location::caller(),
        });
    }
    let leaf = peer_certificate_der(&response).ok_or(VerifyTlsBindingError::MissingHealthLeaf {
        location: std::panic::Location::caller(),
    })?;
    let observed_certfp = hex::encode(Sha256::digest(&leaf));

    let tls = validate_attested_tls(expected, user_data, &observed_certfp)
        .with_context(Ctx::validate())?;
    Ok(TlsVerification::Verified(tls))
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum VerifyError {
    #[error("failed to resolve attestation URL [{location:?}]")]
    GetAttestationUrl {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("attestation endpoint is not a valid URL [{location:?}]")]
    ParseAttestationUrl {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to create attestation client [{location:?}]")]
    BuildAttestationClient {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to fetch attestation document (timed out or unreachable) [{location:?}]")]
    FetchAttestation {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to fetch attestation: {status} [{location:?}]")]
    FetchAttestationStatus {
        status: reqwest::StatusCode,

        #[location]
        location: Location,
    },

    #[error("failed to read bounded attestation response [{location:?}]")]
    BoundedAttestationResponse {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("no attestation document in response. Fields: {fields} [{location:?}]")]
    MissingAttestationDocument {
        #[context(borrow = str)]
        fields: String,

        #[location]
        location: Location,
    },

    #[error("failed to decode attestation document [{location:?}]")]
    DecodeAttestation {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to parse attestation document [{location:?}]")]
    ParseAttestation {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to build attestation inspection JSON [{location:?}]")]
    InspectionJson {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to write attestation inspection data [{location:?}]")]
    WriteInspectionData {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to extract PCRs from attestation document [{location:?}]")]
    ExtractPcrs {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to decode attestation user data [{location:?}]")]
    AttestationUserData {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("attestation response contains an invalid manifest [{location:?}]")]
    ParseManifest {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("manifest required when using --app-source-url [{location:?}]")]
    MissingAppSourceUrlManifest {
        #[location]
        location: Location,
    },

    #[error("failed to read PCRs from file [{location:?}]")]
    ReadPcrsFromFile {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to stage source tarball [{location:?}]")]
    StageTarballSource {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to stage Git source [{location:?}]")]
    StageGitSource {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to build and retrieve reference PCRs [{location:?}]")]
    BuildAndGetPcrs {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("cannot verify attestation: enclave is in debug mode [{location:?}]")]
    DebugMode {
        #[location]
        location: Location,
    },

    #[error("failed to decode expected PCR hex [{location:?}]")]
    BadPcrHex {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("could not build bootproof nitro attestation [{location:?}]")]
    BuildNitro {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("could not get time since epoch [{location:?}]")]
    SystemTime {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("TLS certificate binding failed [{location:?}]")]
    VerifyTlsBinding {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to persist trusted hashes [{location:?}]")]
    PersistTrustedHashes {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("{details} [{location:?}]")]
    VerificationFailed {
        #[context(borrow = str)]
        details: String,

        #[location]
        location: Location,
    },
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn verify(
    client: &ApiClient,
    attestation_url_opt: Option<String>,
    from_local: bool,
    from_tarball: Option<PathBuf>,
    app_source_url: Option<String>,
    pcrs_file: Option<String>,
    no_cache: bool,
    save_pcrs: bool,
    inspect_attestation: bool,
) -> Result<(), VerifyError> {
    use VerifyErrorCtx as Ctx;

    if inspect_attestation {
        output::status("Inspecting remote attestation...");
    } else {
        output::status("Verifying enclave attestation...");
        output::status("Learn more: https://docs.caution.co/concepts/attestation/");
    }

    for warning in verify_deprecation_warnings(from_local, save_pcrs) {
        output::warning(warning);
    }

    let attestation_url = if let Some(u) = attestation_url_opt {
        u
    } else {
        client
            .get_attestation_url()
            .await
            .with_context(Ctx::get_attestation_url())?
    };
    let attestation_url =
        reqwest::Url::parse(&attestation_url).with_context(Ctx::parse_attestation_url())?;

    let nonce = {
        use rand::RngCore;
        let mut nonce = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        nonce
    };

    output::status(format!("\nChallenge nonce (sent): {}", hex::encode(&nonce)));

    output::verbose(
        client.verbose,
        format!("Requesting attestation from: {}", attestation_url),
    );
    output::status("Requesting attestation...");

    // Bound the challenge/response: a reachable-but-unresponsive enclave must
    // not hang verify indefinitely. The connect phase is already bounded by
    // the client's connect_timeout; this caps the whole request.
    let attestation_client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .tls_info(true)
        .build()
        .with_context(Ctx::build_attestation_client())?;
    let response = attestation_client
        .post(attestation_url.clone())
        .timeout(Duration::from_secs(60))
        .json(&serde_json::json!({"nonce": general_purpose::STANDARD.encode(&nonce)}))
        .send()
        .await
        .with_context(Ctx::fetch_attestation())?;

    if !response.status().is_success() {
        return Err(VerifyError::FetchAttestationStatus {
            status: response.status(),
            location: std::panic::Location::caller(),
        });
    }
    let attestation_leaf = peer_certificate_der(&response);

    let attest_resp = bounded_attestation_response_json(response)
        .await
        .with_context(Ctx::bounded_attestation_response())?;

    let attestation_b64 = attest_resp
        .get("attestation_document")
        .or_else(|| attest_resp.get("document"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            let fields = format!(
                "{:?}",
                attest_resp
                    .as_object()
                    .map(|o| o.keys().collect::<Vec<_>>())
            );
            VerifyError::MissingAttestationDocument {
                fields,
                location: std::panic::Location::caller(),
            }
        })?;
    output::verbose(
        client.verbose,
        format!("Received attestation: {} bytes", attestation_b64.len()),
    );
    let attestation_bytes = base64::engine::general_purpose::STANDARD
        .decode(attestation_b64)
        .with_context(Ctx::decode_attestation())?;

    let attestation_payload =
        attestation::parse(&attestation_bytes).with_context(Ctx::parse_attestation())?;

    if inspect_attestation {
        output::warning(
            "UNVERIFIED: parsing succeeded, but Nitro, expected PCRs, and TLS were not verified",
        );
        let inspection_json =
            attestation_inspection_json(&nonce, &attestation_payload, attest_resp.get("manifest"))
                .with_context(Ctx::inspection_json())?;
        output::data_ln(inspection_json).with_context(Ctx::write_inspection_data())?;
        return Ok(());
    }

    output::status("\nExtracting remote attestation values...");
    let remote_pcrs =
        attestation::extract_pcrs(&attestation_payload).with_context(Ctx::extract_pcrs())?;

    output::status("\nRemote PCR values (unverified until verification succeeds):");
    output::status(format!("  PCR0: {}", remote_pcrs.pcr0));
    output::status(format!("  PCR1: {}", remote_pcrs.pcr1));
    output::status(format!("  PCR2: {}", remote_pcrs.pcr2));

    if let Some(user_data) =
        attestation_user_data(&attestation_payload).with_context(Ctx::attestation_user_data())?
    {
        let (is_hex, user_data) = display_user_data(user_data);
        if is_hex {
            output::status(format_args!(
                "Remote user data (unverified, hex): {user_data}"
            ));
        } else {
            output::status(format_args!("Remote user data (unverified): {user_data}"));
        }
    }

    let manifest: Option<enclave_builder::EnclaveManifest> = attest_resp
        .get("manifest")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .with_context(Ctx::parse_manifest())?;

    if let Some(ref m) = manifest {
        output::status("\nResponse manifest information (unsigned):");
        if let Some(ref app_src) = m.app_source {
            if app_src.urls.len() == 1 {
                output::status(format!(
                    "  App source: {} commit: {}",
                    app_src.urls[0], app_src.commit
                ));
            } else {
                output::status(format!(
                    "  App source: ({} URLs) commit: {}",
                    app_src.urls.len(),
                    app_src.commit
                ));
            }
            if let Some(ref b) = app_src.branch {
                output::status(format!("    branch: {}", b));
            }
            if app_src.urls.len() > 1 {
                for (i, url) in app_src.urls.iter().enumerate() {
                    output::status(format!("    [{}] {}", i + 1, url));
                }
            }
        } else {
            output::status("  App source: (none - private code)");
        }

        match &m.enclave_source {
            enclave_builder::EnclaveSource::GitArchive { urls, commit } => {
                if urls.len() == 1 {
                    output::status(format!(
                        "  Enclave source: {}{}",
                        urls[0],
                        commit
                            .as_ref()
                            .map(|c| format!(" commit: {}", c))
                            .unwrap_or_default()
                    ));
                } else {
                    output::status(format!(
                        "  Enclave source: ({} URLs){}",
                        urls.len(),
                        commit
                            .as_ref()
                            .map(|c| format!(" commit: {}", c))
                            .unwrap_or_default()
                    ));
                }
                if urls.len() > 1 {
                    for (i, url) in urls.iter().enumerate() {
                        output::status(format!("    [{}] {}", i + 1, url));
                    }
                }
            }
            enclave_builder::EnclaveSource::GitRepository {
                url,
                branch,
                commit,
            } => {
                output::status(format!(
                    "  Enclave source: {}{} branch: {}",
                    url,
                    commit
                        .as_ref()
                        .map(|c| format!(" commit: {}", c))
                        .unwrap_or_default(),
                    branch
                ));
            }
            enclave_builder::EnclaveSource::Local { path } => {
                output::status(format!("  Enclave source: {} (local)", path));
            }
        }
        match &m.framework_source {
            enclave_builder::FrameworkSource::GitArchive { url, commit } => {
                output::status(format!(
                    "  Framework source: {}{}",
                    url,
                    commit
                        .as_ref()
                        .map(|c| format!(" commit: {}", c))
                        .unwrap_or_default()
                ));
            }
        }
        if let Some(ref metadata) = m.metadata {
            output::status(format!("  Metadata: {}", metadata));
        }
    }

    let pcr_only = pcrs_file.is_some();
    let reproduction = if let Some(pcrs_path) = pcrs_file {
        output::status(format!("\nReading expected PCRs from file: {}", pcrs_path));
        ReproductionResult {
            pcrs: read_pcrs_from_file(&pcrs_path).with_context(Ctx::read_pcrs_from_file())?,
            tls: None,
        }
    } else if let Some(ref tarball_path) = from_tarball {
        output::status(format!(
            "\nBuilding from source tarball: {}",
            tarball_path.display()
        ));
        let source =
            stage_tarball_source(client, tarball_path).with_context(Ctx::stage_tarball_source())?;
        build_and_get_pcrs(client, manifest.clone(), no_cache, Some(&source))
            .await
            .with_context(Ctx::build_and_get_pcrs())?
    } else if let Some(ref source_url) = app_source_url {
        output::status(format!(
            "\nBuilding from provided source URL: {}",
            source_url
        ));
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
            build_and_get_pcrs(client, Some(modified_manifest), no_cache, None)
                .await
                .with_context(Ctx::build_and_get_pcrs())?
        } else {
            output::warning("⚠️  Remote attestation does not include a manifest");
            output::status("Cannot determine commit hash without manifest.");
            output::status("");
            output::status("Options:");
            output::status("  1. Build from local directory: caution verify");
            output::status("  2. Use a PCRs file: caution verify --pcrs pcrs.txt");
            return Err(VerifyError::MissingAppSourceUrlManifest {
                location: std::panic::Location::caller(),
            });
        }
    } else {
        let manifest_commit = manifest
            .as_ref()
            .and_then(|manifest| manifest.app_source.as_ref())
            .map(|source| source.commit.as_str());
        if let Some(commit) = manifest_commit {
            output::status(format!(
                "\nBuilding local source at manifest commit: {commit}"
            ));
        } else {
            output::status("\nBuilding local source at HEAD (manifest has no app commit)");
        }
        let source = stage_git_source(client, manifest_commit)
            .await
            .with_context(Ctx::stage_git_source())?;
        build_and_get_pcrs(client, manifest.clone(), no_cache, Some(&source))
            .await
            .with_context(Ctx::build_and_get_pcrs())?
    };

    let ReproductionResult {
        pcrs: expected_pcrs,
        tls: expected_tls,
    } = reproduction;

    output::status("\nExpected PCR values:");
    output::status(format!("  PCR0: {}", expected_pcrs.pcr0));
    output::status(format!("  PCR1: {}", expected_pcrs.pcr1));
    output::status(format!("  PCR2: {}", expected_pcrs.pcr2));

    let is_debug = remote_pcrs.pcr0.chars().all(|c| c == '0')
        || remote_pcrs.pcr1.chars().all(|c| c == '0')
        || remote_pcrs.pcr2.chars().all(|c| c == '0');

    if is_debug {
        output::warning("\n⚠ WARNING: The remote enclave is running in DEBUG MODE");
        output::warning("In debug mode, AWS Nitro Enclaves zero out PCR values.");
        output::warning("This means attestation cannot be verified.");
        output::warning("\nDebug mode should ONLY be used for development/testing.");
        output::warning("For production, the enclave must run in production mode.");
        return Err(VerifyError::DebugMode {
            location: std::panic::Location::caller(),
        });
    }

    output::status("\nVerifying attestation with bootproof-sdk...");
    let expected_nitro_pcrs: NitroPcrs = [
        (
            0u8,
            hex::decode(&expected_pcrs.pcr0).with_context(Ctx::bad_pcr_hex())?,
        ),
        (
            1u8,
            hex::decode(&expected_pcrs.pcr1).with_context(Ctx::bad_pcr_hex())?,
        ),
        (
            2u8,
            hex::decode(&expected_pcrs.pcr2).with_context(Ctx::bad_pcr_hex())?,
        ),
    ]
    .into_iter()
    .collect();
    let nitro =
        Nitro::new(attestation_bytes, expected_nitro_pcrs).with_context(Ctx::build_nitro())?;
    let duration_since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .with_context(Ctx::system_time())?;
    match nitro.verify(duration_since_epoch, &nonce) {
        Ok(payload) => {
            output::success("\n✓ Base Nitro attestation and expected PCR0/1/2 verified");
            let verified_pcrs =
                attestation::extract_pcrs(&payload).with_context(Ctx::extract_pcrs())?;

            let tls = if pcr_only {
                TlsVerification::PcrOnly
            } else if let Some(ref expected) = expected_tls {
                verify_tls_binding(
                    expected,
                    &payload,
                    &attestation_url,
                    attestation_leaf.as_deref(),
                )
                .await
                .with_context(Ctx::verify_tls_binding())?
            } else {
                TlsVerification::NotApplicable
            };

            match &tls {
                TlsVerification::NotApplicable => {
                    output::status("TLS certificate binding: not applicable")
                }
                TlsVerification::PcrOnly => {
                    output::status("TLS certificate binding: not performed (--pcrs)")
                }
                TlsVerification::SkippedNoDns => output::warning(
                    "TLS certificate binding: skipped because the configured domain has no DNS answer",
                ),
                TlsVerification::Verified(_) => {
                    output::success("✓ TLS certificate binding verified")
                }
            }

            let trusted = TrustedHashes {
                pcr0: &verified_pcrs.pcr0,
                pcr1: &verified_pcrs.pcr1,
                pcr2: &verified_pcrs.pcr2,
                verified_at: chrono::Utc::now().to_rfc3339(),
                tls: match tls {
                    TlsVerification::Verified(tls) => Some(tls),
                    _ => None,
                },
            };
            let hashes_path = PathBuf::from(".caution/trusted_hashes.json");
            let backup = persist_trusted_hashes(&hashes_path, &trusted)
                .with_context(Ctx::persist_trusted_hashes())?;
            output::success("✓ Attestation verification PASSED");
            output::status(format!("Trusted state: {}", hashes_path.display()));
            if let Some(backup) = backup {
                output::status(format!("Previous state: {}", backup.display()));
            }

            Ok(())
        }
        Err(e) => {
            output::error("\n✗ Attestation verification FAILED");
            output::error(format!("Error: {e}"));
            output::status("\nPCR comparison:");
            if expected_pcrs.pcr0 != remote_pcrs.pcr0 {
                output::error("  PCR0: MISMATCH");
                output::status(format!("    expected: {}", expected_pcrs.pcr0));
                output::status(format!("    remote:   {}", remote_pcrs.pcr0));
            } else {
                output::status("  PCR0: match");
            }
            if expected_pcrs.pcr1 != remote_pcrs.pcr1 {
                output::error("  PCR1: MISMATCH");
                output::status(format!("    expected: {}", expected_pcrs.pcr1));
                output::status(format!("    remote:   {}", remote_pcrs.pcr1));
            } else {
                output::status("  PCR1: match");
            }
            if expected_pcrs.pcr2 != remote_pcrs.pcr2 {
                output::error("  PCR2: MISMATCH");
                output::status(format!("    expected: {}", expected_pcrs.pcr2));
                output::status(format!("    remote:   {}", remote_pcrs.pcr2));
            } else {
                output::status("  PCR2: match");
            }
            Err(VerifyError::VerificationFailed {
                details: format!("Attestation verification failed - {}", e),
                location: std::panic::Location::caller(),
            })
        }
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
enum BuildLocalDockerImageError {
    #[error("failed to get current directory [{location:?}]")]
    CurrentDir {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to build the Docker image from the current directory [{location:?}]")]
    BuildImage {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

async fn build_local_docker_image(
    client: &ApiClient,
    no_cache: bool,
) -> Result<String, BuildLocalDockerImageError> {
    use BuildLocalDockerImageErrorCtx as Ctx;

    let work_dir = std::env::current_dir().with_context(Ctx::current_dir())?;
    build_docker_image_from_dir(client, &work_dir, no_cache)
        .await
        .with_context(Ctx::build_image())
}

#[derive(Debug, thiserror::Error, CtxError)]
enum StageGitSourceError {
    #[error("failed to locate Git repository [{location:?}]")]
    LocateRepo {
        #[location]
        location: Location,

        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    #[error(
        "Default source verification must be run inside a Git repository: {stderr} [{location:?}]"
    )]
    NotAGitRepo {
        stderr: String,

        #[location]
        location: Location,
    },

    #[error("failed to resolve local Git commit {commit_ish} [{location:?}]")]
    ResolveCommit {
        commit_ish: String,

        #[location]
        location: Location,

        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    #[error(
        "failed to resolve manifest app commit {commit_ish} in local repository. Fetch it locally or use --from-tarball. Git error: {stderr} [{location:?}]"
    )]
    ResolveManifestCommit {
        commit_ish: String,
        stderr: String,

        #[location]
        location: Location,
    },

    #[error("failed to resolve local Git commit {commit_ish}: {stderr} [{location:?}]")]
    ResolveLocalCommit {
        commit_ish: String,
        stderr: String,

        #[location]
        location: Location,
    },

    #[error("failed to archive local Git commit {commit} [{location:?}]")]
    ArchiveCommit {
        commit: String,

        #[location]
        location: Location,

        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    #[error("git archive failed for {commit}: {stderr} [{location:?}]")]
    ArchiveFailed {
        commit: String,
        stderr: String,

        #[location]
        location: Location,
    },

    #[error("failed to create temp source dir [{location:?}]")]
    CreateTemp {
        #[location]
        location: Location,

        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    #[error("failed to extract staged Git source [{location:?}]")]
    Extract {
        #[location]
        location: Location,

        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
}

async fn stage_git_source(
    client: &ApiClient,
    requested_commit: Option<&str>,
) -> Result<StagedSource, StageGitSourceError> {
    use StageGitSourceErrorCtx as Ctx;

    let root_output = tokio::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .await
        .with_context(Ctx::locate_repo())?;

    if !root_output.status.success() {
        let stderr = String::from_utf8_lossy(&root_output.stderr);
        return Err(StageGitSourceError::NotAGitRepo {
            stderr: stderr.trim().to_string(),
            location: std::panic::Location::caller(),
        });
    }

    let repo_root = PathBuf::from(String::from_utf8_lossy(&root_output.stdout).trim());
    let requested_commit = requested_commit
        .map(str::trim)
        .filter(|commit| !commit.is_empty());
    let commit_ish = requested_commit.unwrap_or("HEAD");
    let commit_rev = format!("{commit_ish}^{{commit}}");

    let commit_output = tokio::process::Command::new("git")
        .args(["rev-parse", "--verify", &commit_rev])
        .current_dir(&repo_root)
        .output()
        .await
        .with_context(Ctx::resolve_commit(commit_ish))?;

    if !commit_output.status.success() {
        let stderr = String::from_utf8_lossy(&commit_output.stderr);
        if requested_commit.is_some() {
            return Err(StageGitSourceError::ResolveManifestCommit {
                commit_ish: commit_ish.to_string(),
                stderr: stderr.trim().to_string(),
                location: std::panic::Location::caller(),
            });
        } else {
            return Err(StageGitSourceError::ResolveLocalCommit {
                commit_ish: commit_ish.to_string(),
                stderr: stderr.trim().to_string(),
                location: std::panic::Location::caller(),
            });
        }
    }

    let commit = String::from_utf8_lossy(&commit_output.stdout)
        .trim()
        .to_string();

    let archive_output = tokio::process::Command::new("git")
        .args(["archive", "--format=tar.gz", &commit])
        .current_dir(&repo_root)
        .output()
        .await
        .with_context(Ctx::archive_commit(commit.clone()))?;

    if !archive_output.status.success() {
        let stderr = String::from_utf8_lossy(&archive_output.stderr);
        return Err(StageGitSourceError::ArchiveFailed {
            commit: commit.clone(),
            stderr: stderr.trim().to_string(),
            location: std::panic::Location::caller(),
        });
    }

    let temp_dir = tempfile::TempDir::new().with_context(Ctx::create_temp())?;
    extract_tarball_bytes_to_dir(&archive_output.stdout, temp_dir.path())
        .with_context(Ctx::extract())?;

    output::verbose(
        client.verbose,
        format!(
            "Staged local Git commit {} from {} into {}",
            commit,
            repo_root.display(),
            temp_dir.path().display()
        ),
    );

    Ok(StagedSource {
        path: temp_dir.path().to_path_buf(),
        cache_key: commit.clone(),
        app_commit: Some(commit),
        _temp_dir: temp_dir,
    })
}

#[derive(Debug, thiserror::Error, CtxError)]
enum StageTarballSourceError {
    #[error("failed to read tarball: {path} [{location:?}]")]
    Read {
        path: String,

        #[location]
        location: Location,

        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    #[error("failed to create temp source dir [{location:?}]")]
    CreateTemp {
        #[location]
        location: Location,

        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    #[error("failed to extract source tarball [{location:?}]")]
    Extract {
        #[location]
        location: Location,

        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
}

fn stage_tarball_source(
    client: &ApiClient,
    tarball_path: &Path,
) -> Result<StagedSource, StageTarballSourceError> {
    use StageTarballSourceErrorCtx as Ctx;

    let archive_bytes =
        fs::read(tarball_path).with_context(Ctx::read(tarball_path.display().to_string()))?;
    let archive_hash = hex::encode(Sha256::digest(&archive_bytes));
    let temp_dir = tempfile::TempDir::new().with_context(Ctx::create_temp())?;

    extract_tarball_bytes_to_dir(&archive_bytes, temp_dir.path()).with_context(Ctx::extract())?;

    output::verbose(
        client.verbose,
        format!(
            "Staged source tarball {} into {}",
            tarball_path.display(),
            temp_dir.path().display()
        ),
    );

    Ok(StagedSource {
        path: temp_dir.path().to_path_buf(),
        cache_key: format!("tarball-{}", &archive_hash[..16]),
        app_commit: None,
        _temp_dir: temp_dir,
    })
}

#[derive(Debug, thiserror::Error, CtxError)]
enum ExtractTarballBytesToDirError {
    #[error("Failed to extract archive [{location:?}]")]
    Extract {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

fn extract_tarball_bytes_to_dir(
    archive_bytes: &[u8],
    extract_dir: &Path,
) -> Result<(), ExtractTarballBytesToDirError> {
    use ExtractTarballBytesToDirErrorCtx as Ctx;

    if archive_bytes.starts_with(&[0x1f, 0x8b]) {
        let decoder = flate2::read::GzDecoder::new(archive_bytes);
        extract_tar_archive_to_dir(tar::Archive::new(decoder), extract_dir)
            .with_context(Ctx::extract())
    } else {
        extract_tar_archive_to_dir(tar::Archive::new(archive_bytes), extract_dir)
            .with_context(Ctx::extract())
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
enum ExtractTarArchiveToDirError {
    #[error("Failed to read archive entries [{location:?}]")]
    ReadEntries {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to read archive entry [{location:?}]")]
    ReadEntry {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to extract entry [{location:?}]")]
    ExtractEntry {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

fn extract_tar_archive_to_dir<R: std::io::Read>(
    mut archive: tar::Archive<R>,
    extract_dir: &Path,
) -> Result<(), ExtractTarArchiveToDirError> {
    use ExtractTarArchiveToDirErrorCtx as Ctx;

    for entry in archive.entries().with_context(Ctx::read_entries())? {
        let mut entry = entry.with_context(Ctx::read_entry())?;
        entry
            .unpack_in(extract_dir)
            .with_context(Ctx::extract_entry())?;
    }

    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
enum BuildDockerImageFromDirError {
    #[error("failed to inspect docker image [{location:?}]")]
    InspectImage {
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

    #[error("failed to build user image [{location:?}]")]
    BuildUserImage {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

async fn build_docker_image_from_dir(
    client: &ApiClient,
    work_dir: &std::path::Path,
    no_cache: bool,
) -> Result<String, BuildDockerImageFromDirError> {
    use BuildDockerImageFromDirErrorCtx as Ctx;
    use tokio::process::Command;

    let commit_sha = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(work_dir)
        .output()
        .await
        .ok()
        .and_then(|o| parse_git_rev_parse_output(o.status.success(), &o.stdout))
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let tag = format!(
        "caution-local-build:{}",
        &commit_sha[..12.min(commit_sha.len())]
    );

    if !no_cache {
        let inspect = Command::new("docker")
            .args(["inspect", "--type=image", &tag])
            .output()
            .await
            .with_context(Ctx::inspect_image())?;

        if inspect.status.success() {
            output::verbose(
                client.verbose,
                format!("Using cached Docker image: {}", tag),
            );
            return Ok(tag);
        }
    } else {
        output::verbose(
            client.verbose,
            "--no-cache specified, rebuilding Docker image...",
        );
    }

    output::verbose(
        client.verbose,
        format!("Building Docker image with tag: {}", tag),
    );

    let containerfile = client
        .read_config_from_dir(work_dir)
        .ok()
        .and_then(|c| c.enclave)
        .and_then(|e| e.into_iter().next().map(|(_, v)| v))
        .and_then(|e| e.build)
        .and_then(|b| b.containerfile);

    let procfile_path = work_dir.join("Procfile");
    let config = if procfile_path.exists() {
        let content = std::fs::read_to_string(&procfile_path).with_context(Ctx::read_procfile())?;
        let mut build_command = None;
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
            containerfile,
            oci_tarball: None,
            no_cache,
        }
    };

    output::verbose(client.verbose, format!("work_dir = {:?}", work_dir));
    output::verbose(client.verbose, format!("BuildConfig = {:?}", config));

    build_user_image(work_dir, &tag, &config)
        .await
        .with_context(Ctx::build_user_image())?;

    output::verbose(
        client.verbose,
        format!("Docker image built successfully: {}", tag),
    );
    Ok(tag)
}

#[derive(Debug, thiserror::Error, CtxError)]
enum DownloadAndExtractAppSourceError {
    #[error("failed to determine home directory [{location:?}]")]
    NoHomeDir {
        #[location]
        location: Location,
    },

    #[error("failed to create downloads cache directory [{location:?}]")]
    CreateCacheDir {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to clean up partial extraction [{location:?}]")]
    Cleanup {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to create HTTP client [{location:?}]")]
    BuildClient {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to download app source [{location:?}]")]
    Download {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to download app source: HTTP {status} [{location:?}]")]
    DownloadStatus {
        status: reqwest::StatusCode,

        #[location]
        location: Location,
    },

    #[error("failed to read archive bytes [{location:?}]")]
    ReadBytes {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to extract downloaded app source [{location:?}]")]
    Extract {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

async fn download_and_extract_app_source(
    client: &ApiClient,
    url: &str,
) -> Result<PathBuf, DownloadAndExtractAppSourceError> {
    use DownloadAndExtractAppSourceErrorCtx as Ctx;

    let cache_dir = if let Some(ref workdir) = client.workdir {
        workdir.join("downloads")
    } else {
        dirs::home_dir()
            .ok_or(DownloadAndExtractAppSourceError::NoHomeDir {
                location: std::panic::Location::caller(),
            })?
            .join(".cache/caution/downloads")
    };
    std::fs::create_dir_all(&cache_dir).with_context(Ctx::create_cache_dir())?;

    let url_hash = sha2::Sha256::digest(url.as_bytes());
    let extract_dir = cache_dir.join(hex::encode(&url_hash[..8]));

    // Check if already cached
    if extract_dir.exists()
        && extract_dir
            .read_dir()
            .map(|mut d| d.next().is_some())
            .unwrap_or(false)
    {
        output::verbose(
            client.verbose,
            format!("Using cached app source: {}", extract_dir.display()),
        );
        return Ok(extract_dir);
    }

    output::verbose(client.verbose, format!("Downloading app source: {}", url));

    // Clean up any partial extraction
    if extract_dir.exists() {
        std::fs::remove_dir_all(&extract_dir).with_context(Ctx::cleanup())?;
    }

    let http = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(30))
        .timeout(std::time::Duration::from_secs(300)) // 5 minutes for full download
        .build()
        .with_context(Ctx::build_client())?;

    let response = http.get(url).send().await.with_context(Ctx::download())?;

    if !response.status().is_success() {
        return Err(DownloadAndExtractAppSourceError::DownloadStatus {
            status: response.status(),
            location: std::panic::Location::caller(),
        });
    }

    let archive_bytes = response.bytes().await.with_context(Ctx::read_bytes())?;

    output::verbose(
        client.verbose,
        format!("Downloaded {} bytes, extracting...", archive_bytes.len()),
    );

    extract_tarball_bytes_to_dir(&archive_bytes, &extract_dir).with_context(Ctx::extract())?;

    output::verbose(
        client.verbose,
        format!("App source extracted to: {}", extract_dir.display()),
    );

    Ok(extract_dir)
}

#[derive(Debug, thiserror::Error, CtxError)]
enum DownloadAndExtractAppSourceWithFallbacksError {
    #[error("no source URLs provided [{location:?}]")]
    NoUrls {
        #[location]
        location: Location,
    },

    #[error("all source URLs failed [{location:?}]")]
    AllFailed {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

async fn download_and_extract_app_source_with_fallbacks(
    client: &ApiClient,
    urls: &[String],
) -> Result<PathBuf, DownloadAndExtractAppSourceWithFallbacksError> {
    if urls.is_empty() {
        return Err(DownloadAndExtractAppSourceWithFallbacksError::NoUrls {
            location: std::panic::Location::caller(),
        });
    }

    let mut last_error: Option<DownloadAndExtractAppSourceError> = None;

    for (i, url) in urls.iter().enumerate() {
        if i > 0 {
            output::verbose(
                client.verbose,
                format!("Trying fallback URL ({}/{}): {}", i + 1, urls.len(), url),
            );
        }

        match download_and_extract_app_source(client, url).await {
            Ok(path) => return Ok(path),
            Err(e) => {
                output::verbose(
                    client.verbose,
                    format!("Failed to download from {}: {}", url, e),
                );
                last_error = Some(e);
            }
        }
    }

    // `urls` is non-empty here (we return `NoUrls` above for empty input), so at
    // least one download was attempted and `last_error` is populated.
    let source = last_error.expect("a non-empty URL list always yields a failed attempt");
    Err(DownloadAndExtractAppSourceWithFallbacksError::AllFailed {
        location: std::panic::Location::caller(),
        source: source.into(),
    })
}

/// Build a non-interactive, stall-bounded `git` command that cannot prompt
/// for credentials or block on a TTY. During verification the source URL
/// comes from the remote response manifest and may point at a repo the
/// host refuses to serve anonymously — e.g. a non-existent Codeberg/Forgejo
/// repo, which returns `401` (rather than `404`, to avoid leaking
/// existence). Without these guards, `git` falls back to prompting
/// `Username for ...` on the inherited `/dev/tty` and blocks forever,
/// leaving the "Reproducing enclave image" spinner spinning. Verification
/// sources are public and reproducible, so a credential prompt is always a
/// failure, never an interaction.
pub(crate) fn git_command(args: &[&str]) -> std::process::Command {
    let mut cmd = std::process::Command::new("git");
    cmd.args([
        // Abort a transfer that drips below 1000 B/s for 300s, so a server
        // that accepts the connection but never makes progress can't hang
        // the build. (git has no working connect-timeout config knob; the
        // connect phase falls back to libcurl's default. A hard wall-clock
        // bound would need a process-level deadline.) These precede the
        // subcommand so git applies them; harmless for local ops.
        "-c",
        "http.lowSpeedLimit=1000",
        "-c",
        "http.lowSpeedTime=300",
    ])
    .args(args)
    // Never prompt on /dev/tty for a username/password.
    .env("GIT_TERMINAL_PROMPT", "0")
    // Belt-and-suspenders: if a credential helper/askpass is somehow
    // configured, make it non-interactive. `true` exits 0 with empty
    // output, so git gets empty credentials and fails fast.
    .env("GIT_ASKPASS", "true")
    // Detach stdin so git can't wait on the parent's TTY either.
    .stdin(std::process::Stdio::null())
    // Prevent SSH from prompting for host-key confirmation or credentials
    // via /dev/tty, which hangs non-interactive callers. BatchMode=yes
    // makes SSH fail immediately instead. accept-new accepts unknown hosts
    // on first contact (no TOFU hang in fresh CI) while still rejecting
    // changed keys (MITM protection). Preserve any caller-set
    // GIT_SSH_COMMAND (e.g. a custom -i key) by appending rather than
    // replacing.
    .env(
        "GIT_SSH_COMMAND",
        format!(
            "{} -o BatchMode=yes -o StrictHostKeyChecking=accept-new",
            std::env::var("GIT_SSH_COMMAND").unwrap_or_else(|_| "ssh".to_string())
        ),
    );
    cmd
}

/// Fail-fast reachability check for an enclave/framework source archive.
/// Try configured mirrors in order, then stop before the expensive build.
#[derive(Debug, thiserror::Error, CtxError)]
enum PreflightArchiveUrlError {
    #[error("archive preflight failed [{location:?}]")]
    Preflight {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

async fn preflight_archive_url(
    client: &ApiClient,
    label: &str,
    url: &str,
    use_platform_mirror: bool,
) -> Result<(), PreflightArchiveUrlError> {
    use PreflightArchiveUrlErrorCtx as Ctx;

    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Ok(());
    }

    let candidates = archive_preflight_urls(url, use_platform_mirror);
    preflight_archive_urls(client, label, &candidates)
        .await
        .with_context(Ctx::preflight())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum PreflightArchiveUrlsError {
    #[error("no archive URLs provided for {label} [{location:?}]")]
    NoUrls {
        label: String,

        #[location]
        location: Location,
    },

    #[error("failed to create archive preflight client [{location:?}]")]
    BuildClient {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error(
        "{label} archive is not available on the remote (HTTP {code}):\n  \
             {url}\n\n\
             The deployed enclave references a {lower} commit that the remote \
             no longer serves — it may have been garbage-collected, or the \
             manifest is stale. This build cannot be reproduced from the \
             remote manifest. [{location:?}]"
    )]
    MissingSingle {
        label: String,
        lower: String,
        code: u16,
        url: String,

        #[location]
        location: Location,
    },

    #[error(
        "{label} preflight failed (HTTP {code}):\n  {url}\n\n\
             Refusing to start the reproduction build. [{location:?}]"
    )]
    FailedSingle {
        label: String,
        code: u16,
        url: String,

        #[location]
        location: Location,
    },

    #[error(
        "{label} preflight failed after {attempts} attempts:\n  {url}\n  \
             {error}\n\nRefusing to start the reproduction build. [{location:?}]"
    )]
    FailedAfterAttempts {
        label: String,
        attempts: usize,
        url: String,
        error: String,

        #[location]
        location: Location,
    },

    #[error(
        "all {label} archive preflights failed:\n  {failures}\n\n\
             Refusing to start the reproduction build. [{location:?}]"
    )]
    AllFailed {
        label: String,
        failures: String,

        #[location]
        location: Location,
    },
}

pub(crate) async fn preflight_archive_urls(
    client: &ApiClient,
    label: &str,
    urls: &[String],
) -> Result<(), PreflightArchiveUrlsError> {
    use PreflightArchiveUrlsErrorCtx as Ctx;

    if urls.is_empty() {
        return Err(PreflightArchiveUrlsError::NoUrls {
            label: label.to_string(),
            location: std::panic::Location::caller(),
        });
    }
    let verbose = client.verbose;

    output::status(format_args!(
        "\nChecking {} is reachable on remote...",
        label.to_lowercase()
    ));
    // Always follow redirects (reqwest's default policy, up to 10 hops). The
    // URL comes from the user's own manifest, so there is no threat model where
    // a redirect matters; forges legitimately redirect (GitHub → codeload,
    // reverse-proxied Forgejo), and disabling redirects would misclassify those
    // valid archives as unavailable.
    let http_client = reqwest::Client::builder()
        .build()
        .with_context(Ctx::build_client())?;
    let attempts = ARCHIVE_PREFLIGHT_ATTEMPTS;
    let mut failures = Vec::new();

    for url in urls {
        for attempt in 1..=attempts {
            match http_client
                .head(url)
                .timeout(ARCHIVE_PREFLIGHT_TIMEOUT)
                .send()
                .await
            {
                Ok(response) => {
                    match classify_archive_preflight(response.status(), attempt, attempts) {
                        ArchivePreflightStatus::Passed => {
                            output::verbose(
                                verbose,
                                format_args!(
                                    "{} reachable via {} (HTTP {})",
                                    label,
                                    url,
                                    response.status().as_u16()
                                ),
                            );
                            output::status(format_args!("  {} preflight passed ✓", label));
                            return Ok(());
                        }
                        ArchivePreflightStatus::Missing if urls.len() == 1 => {
                            return Err(PreflightArchiveUrlsError::MissingSingle {
                                label: label.to_string(),
                                lower: label.to_lowercase(),
                                code: response.status().as_u16(),
                                url: url.to_string(),
                                location: std::panic::Location::caller(),
                            });
                        }
                        ArchivePreflightStatus::Retry => {
                            output::warning(format_args!(
                                "  {} preflight returned HTTP {}; retrying once",
                                label,
                                response.status().as_u16()
                            ));
                        }
                        ArchivePreflightStatus::Failed if urls.len() == 1 => {
                            return Err(PreflightArchiveUrlsError::FailedSingle {
                                label: label.to_string(),
                                code: response.status().as_u16(),
                                url: url.to_string(),
                                location: std::panic::Location::caller(),
                            });
                        }
                        ArchivePreflightStatus::Missing | ArchivePreflightStatus::Failed => {
                            let code = response.status().as_u16().to_string();
                            failures.push([url.as_str(), ": HTTP ", code.as_str()].concat());
                            break;
                        }
                    }
                }
                Err(error) if attempt < attempts => {
                    output::warning(format_args!(
                        "  {} preflight failed: {}; retrying once",
                        label, error
                    ));
                }
                Err(error) if urls.len() == 1 => {
                    return Err(PreflightArchiveUrlsError::FailedAfterAttempts {
                        label: label.to_string(),
                        attempts,
                        url: url.to_string(),
                        error: error.to_string(),
                        location: std::panic::Location::caller(),
                    });
                }
                Err(error) => {
                    let details = error.to_string();
                    failures.push([url.as_str(), ": ", details.as_str()].concat());
                    break;
                }
            }
        }
    }

    let failures = failures.join("\n  ");
    let lower_label = label.to_lowercase();
    Err(PreflightArchiveUrlsError::AllFailed {
        label: lower_label,
        failures,
        location: std::panic::Location::caller(),
    })
}

/// Cheap network preflight: confirm the app source branch is present on the
/// remote before kicking off an expensive reproduce build.
///
/// `git ls-remote` lists refs without transferring any objects, so a branch
/// that was never pushed (or was renamed/deleted) fails here in seconds
/// instead of after minutes of archive downloads and clone/fetch fallbacks.
///
/// Scope and limits (intentionally conservative — never blocks a valid build):
/// - We run `ls-remote` with credentials disabled, so a **private** repo
///   auth-fails and is treated as inconclusive: the fast-fail only fires for
///   public (or SSH-agent-reachable) remotes.
/// - A missing/unreachable repo (`ls-remote` non-zero) is also inconclusive,
///   not a hard fail — only an *existing, reachable* remote that lacks the
///   branch fast-fails.
/// - A commit force-pushed off an existing branch is **not** caught here
///   (we only check branch presence, not commit reachability); the real fetch
///   surfaces that.
#[derive(Debug, thiserror::Error)]
enum PreflightAppSourceRefError {
    #[error(
        "App source branch '{branch}' is not present on the remote:\n  \
             {url}\n\n\
             The deployed enclave was built from commit {commit} on branch \
             '{branch}', but that branch is not on the remote — it was never \
             pushed, or was renamed/deleted. This build cannot be reproduced \
             from the remote manifest.\n\n\
             Fixes:\n  \
             - Push the branch:        git push <remote> {branch}\n  \
             - Verify a local checkout: caution verify\n  \
             - Verify a source tarball: caution verify --from-tarball <path> \
             [{location:?}]"
    )]
    MissingBranch {
        branch: String,
        url: String,
        commit: String,

        location: Location,
    },
}

fn preflight_app_source_ref(
    client: &ApiClient,
    git_url: &str,
    commit: &str,
    branch: Option<&str>,
) -> Result<(), PreflightAppSourceRefError> {
    // Archive tarball URLs aren't ls-remote-able and 404 quickly on their own.
    if git_url.contains("/archive/") && (git_url.ends_with(".tar.gz") || git_url.ends_with(".tar"))
    {
        return Ok(());
    }

    output::status("\nChecking app source is reachable on remote...");
    let output = match git_command(&["ls-remote", git_url]).output() {
        Ok(output) => output,
        Err(e) => {
            output::verbose(
                client.verbose,
                format!(
                    "App source preflight skipped (ls-remote could not run): {}",
                    e
                ),
            );
            return Ok(());
        }
    };

    if !output.status.success() {
        // Likely auth/network rather than a missing ref; don't hard-block.
        let stderr = String::from_utf8_lossy(&output.stderr);
        output::verbose(
            client.verbose,
            format!(
                "App source preflight inconclusive (ls-remote failed): {}",
                stderr.trim()
            ),
        );
        return Ok(());
    }

    let listing = String::from_utf8_lossy(&output.stdout);
    match classify_app_source_refs(&listing, commit, branch) {
        Ok(true) => {
            output::status("  App source reachable ✓");
        }
        Ok(false) => {
            // No branch hint and the commit is not a current ref tip. It may
            // still live in history; only warn and let the fetch resolve it.
            output::verbose(
                client.verbose,
                format!(
                    "App source commit {} is not a current ref tip; relying on fetch to resolve",
                    commit
                ),
            );
        }
        Err(missing_branch) => {
            return Err(PreflightAppSourceRefError::MissingBranch {
                branch: missing_branch,
                url: git_url.to_string(),
                commit: commit.to_string(),
                location: std::panic::Location::caller(),
            });
        }
    }

    Ok(())
}

/// Decide whether a `git ls-remote` listing confirms the app source is
/// reachable. Pure logic split out from [`Self::preflight_app_source_ref`]
/// so it can be unit-tested without the network.
///
/// - `Ok(true)`  — reachable confirmed (branch present, or commit is a ref tip)
/// - `Ok(false)` — inconclusive (no branch hint and commit isn't a tip; proceed)
/// - `Err(branch)` — the named branch is definitively absent from the remote
pub(crate) fn classify_app_source_refs(
    listing: &str,
    commit: &str,
    branch: Option<&str>,
) -> std::result::Result<bool, String> {
    // Require a meaningful abbreviation before prefix-matching a commit against
    // a ref tip. Without this, a blank ls-remote field (empty `sha`) or a
    // 1-char `commit` would falsely match an unrelated ref. Git's default
    // minimum abbreviation is 7; deployed manifests carry full 40-char SHAs.
    const MIN_SHA_PREFIX: usize = 7;
    let commit_matchable = commit.len() >= MIN_SHA_PREFIX;

    let branch_ref = branch.map(|b| format!("refs/heads/{}", b));
    let mut branch_present = false;
    let mut commit_is_ref_tip = false;
    for line in listing.lines() {
        let mut parts = line.split('\t');
        let sha = parts.next().unwrap_or("");
        let r = parts.next().unwrap_or("");
        if commit_matchable
            && sha.len() >= MIN_SHA_PREFIX
            && (sha.starts_with(commit) || commit.starts_with(sha))
        {
            commit_is_ref_tip = true;
        }
        if let Some(ref br) = branch_ref
            && r == br {
                branch_present = true;
            }
    }

    match branch {
        Some(branch_name) if !branch_present => Err(branch_name.to_string()),
        Some(_) => Ok(true),
        None if commit_is_ref_tip => Ok(true),
        None => Ok(false),
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
enum DownloadAndExtractAppSourceWithGitFallbackError {
    #[error("failed to create temp directory [{location:?}]")]
    CreateTempDir {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to clone repository [{location:?}]")]
    CloneRepo {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to checkout commit [{location:?}]")]
    CheckoutCommit {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to checkout commit after unshallow [{location:?}]")]
    CheckoutAfterUnshallow {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to reset git checkout [{location:?}]")]
    ResetCheckout {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to create git checkout directory [{location:?}]")]
    CreateCloneDir {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to run git init [{location:?}]")]
    GitInit {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("git init failed: {stderr} [{location:?}]")]
    GitInitFailed {
        stderr: String,

        #[location]
        location: Location,
    },

    #[error("failed to fetch branch [{location:?}]")]
    FetchBranch {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("failed to fetch commit [{location:?}]")]
    FetchCommit {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("git fetch failed: {details} [{location:?}]")]
    FetchFailed {
        details: String,

        #[location]
        location: Location,
    },

    #[error("git checkout failed: {stderr} [{location:?}]")]
    CheckoutFailed {
        stderr: String,

        #[location]
        location: Location,
    },

    #[error("no source URLs available and no git fallback configured [{location:?}]")]
    NoSource {
        #[location]
        location: Location,
    },
}

async fn download_and_extract_app_source_with_git_fallback(
    client: &ApiClient,
    archive_urls: &[String],
    git_fallback: Option<(&str, &str, Option<&str>)>,
) -> Result<PathBuf, DownloadAndExtractAppSourceWithGitFallbackError> {
    use DownloadAndExtractAppSourceWithGitFallbackErrorCtx as Ctx;

    if !archive_urls.is_empty() {
        match download_and_extract_app_source_with_fallbacks(client, archive_urls).await {
            Ok(path) => return Ok(path),
            Err(e) => {
                output::verbose(client.verbose, format!("Archive download failed: {}", e));
            }
        }
    }

    if let Some((git_url, commit, branch)) = git_fallback {
        output::verbose(
            client.verbose,
            "Archive download failed. Trying git clone...",
        );

        let temp_dir = tempfile::TempDir::new().with_context(Ctx::create_temp_dir())?;
        let clone_path = temp_dir.path().join("repo");

        // If we have a branch, clone by branch first (works with Forgejo/Codeberg)
        // then checkout the specific commit
        if let Some(branch_name) = branch {
            output::verbose(
                client.verbose,
                format!(
                    "Cloning branch '{}' then checking out commit '{}'",
                    branch_name, commit
                ),
            );

            let clone_output = git_command(&[
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
            .with_context(Ctx::clone_repo())?;

            if !clone_output.status.success() {
                let stderr = String::from_utf8_lossy(&clone_output.stderr);
                output::verbose(client.verbose, format!("Branch clone failed: {}", stderr));
                // Fall through to try commit-based fetch
            } else {
                // Checkout the specific commit
                let checkout_output = git_command(&["checkout", commit])
                    .current_dir(&clone_path)
                    .output()
                    .with_context(Ctx::checkout_commit())?;

                if checkout_output.status.success() {
                    let extract_dir = temp_dir.keep().join("repo");
                    output::verbose(
                        client.verbose,
                        format!("Git clone successful: {}", extract_dir.display()),
                    );
                    return Ok(extract_dir);
                } else {
                    let stderr = String::from_utf8_lossy(&checkout_output.stderr);
                    output::verbose(
                        client.verbose,
                        format!("Commit checkout failed: {}, will try deeper clone", stderr),
                    );

                    // Try fetching more history to find the commit
                    let _ = git_command(&["fetch", "--unshallow"])
                        .current_dir(&clone_path)
                        .output();

                    let checkout_retry = git_command(&["checkout", commit])
                        .current_dir(&clone_path)
                        .output()
                        .with_context(Ctx::checkout_after_unshallow())?;

                    if checkout_retry.status.success() {
                        let extract_dir = temp_dir.keep().join("repo");
                        output::verbose(
                            client.verbose,
                            format!(
                                "Git clone successful after unshallow: {}",
                                extract_dir.display()
                            ),
                        );
                        return Ok(extract_dir);
                    }
                }
            }
        }

        // Fallback: fetch the full advertised branch ref into a fresh repo.
        // Some forges reject raw SHA fetches unless the object is reachable
        // from a requested ref, and reusing a failed shallow clone can leave
        // the object database incomplete.
        let mut branch_fetch_error = None;
        if let Some(branch_name) = branch {
            if clone_path.exists() {
                std::fs::remove_dir_all(&clone_path).with_context(Ctx::reset_checkout())?;
            }

            std::fs::create_dir_all(&clone_path).with_context(Ctx::create_clone_dir())?;

            let init_output = git_command(&["init"])
                .current_dir(&clone_path)
                .output()
                .with_context(Ctx::git_init())?;

            if !init_output.status.success() {
                let stderr = String::from_utf8_lossy(&init_output.stderr);
                return Err(
                    DownloadAndExtractAppSourceWithGitFallbackError::GitInitFailed {
                        stderr: stderr.to_string(),
                        location: std::panic::Location::caller(),
                    },
                );
            }

            let branch_ref = format!("refs/heads/{}", branch_name);
            let fetch_branch_output = git_command(&["fetch", git_url, &branch_ref])
                .current_dir(&clone_path)
                .output()
                .with_context(Ctx::fetch_branch())?;

            if fetch_branch_output.status.success() {
                let checkout_output = git_command(&["checkout", commit])
                    .current_dir(&clone_path)
                    .output()
                    .with_context(Ctx::checkout_commit())?;

                if checkout_output.status.success() {
                    let extract_dir = temp_dir.keep().join("repo");
                    output::verbose(
                        client.verbose,
                        format!("Git fetch successful: {}", extract_dir.display()),
                    );
                    return Ok(extract_dir);
                }

                let stderr = String::from_utf8_lossy(&checkout_output.stderr);
                branch_fetch_error = Some(format!(
                    "Fetched branch '{}' but could not checkout commit '{}': {}",
                    branch_name, commit, stderr
                ));
            } else {
                let stderr = String::from_utf8_lossy(&fetch_branch_output.stderr);
                branch_fetch_error = Some(format!(
                    "Git branch fetch failed for '{}': {}",
                    branch_name, stderr
                ));
            }
        }

        // Last resort: direct fetch by commit. This works on hosts that allow
        // fetching reachable objects by SHA, but not all forges permit it.
        if clone_path.exists() {
            std::fs::remove_dir_all(&clone_path).with_context(Ctx::reset_checkout())?;
        }
        std::fs::create_dir_all(&clone_path).with_context(Ctx::create_clone_dir())?;

        let init_output = git_command(&["init"])
            .current_dir(&clone_path)
            .output()
            .with_context(Ctx::git_init())?;

        if !init_output.status.success() {
            let stderr = String::from_utf8_lossy(&init_output.stderr);
            return Err(
                DownloadAndExtractAppSourceWithGitFallbackError::GitInitFailed {
                    stderr: stderr.to_string(),
                    location: std::panic::Location::caller(),
                },
            );
        }

        let fetch_output = git_command(&["fetch", "--depth", "1", git_url, commit])
            .current_dir(&clone_path)
            .output()
            .with_context(Ctx::fetch_commit())?;

        if !fetch_output.status.success() {
            let stderr = String::from_utf8_lossy(&fetch_output.stderr);
            let details = if let Some(branch_error) = branch_fetch_error {
                format!("{}\n{}", stderr, branch_error)
            } else {
                stderr.to_string()
            };
            return Err(
                DownloadAndExtractAppSourceWithGitFallbackError::FetchFailed {
                    details,
                    location: std::panic::Location::caller(),
                },
            );
        }

        let checkout_output = git_command(&["checkout", "FETCH_HEAD"])
            .current_dir(&clone_path)
            .output()
            .with_context(Ctx::checkout_commit())?;

        if !checkout_output.status.success() {
            let stderr = String::from_utf8_lossy(&checkout_output.stderr);
            return Err(
                DownloadAndExtractAppSourceWithGitFallbackError::CheckoutFailed {
                    stderr: stderr.to_string(),
                    location: std::panic::Location::caller(),
                },
            );
        }

        let extract_dir = temp_dir.keep().join("repo");
        output::verbose(
            client.verbose,
            format!("Git clone successful: {}", extract_dir.display()),
        );
        return Ok(extract_dir);
    }

    Err(DownloadAndExtractAppSourceWithGitFallbackError::NoSource {
        location: std::panic::Location::caller(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_git_rev_parse_output_returns_value_on_success() {
        let stdout = b"0123456789abcdef0123456789abcdef01234567\n";
        assert_eq!(
            parse_git_rev_parse_output(true, stdout).as_deref(),
            Some("0123456789abcdef0123456789abcdef01234567")
        );
    }

    #[test]
    fn parse_git_rev_parse_output_trims_surrounding_whitespace() {
        assert_eq!(
            parse_git_rev_parse_output(true, b"  deadbeef  \n").as_deref(),
            Some("deadbeef")
        );
    }

    #[test]
    fn parse_git_rev_parse_output_treats_empty_stdout_as_failure() {
        // The bug this guards against: `git rev-parse HEAD` exits 0 but emits
        // nothing. Without the empty guard the Docker tag becomes the invalid
        // `caution-local-build:` and the UUID fallback never fires.
        assert_eq!(parse_git_rev_parse_output(true, b""), None);
    }

    #[test]
    fn parse_git_rev_parse_output_treats_whitespace_only_stdout_as_failure() {
        assert_eq!(parse_git_rev_parse_output(true, b"   \n\t  "), None);
    }

    #[test]
    fn parse_git_rev_parse_output_returns_none_on_nonzero_exit() {
        assert_eq!(parse_git_rev_parse_output(false, b"deadbeef\n"), None);
    }
}
