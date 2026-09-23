// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use locksmith::bundle::RecoverySource;
use std::collections::HashSet;
use std::fs;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use dterror::{BoxError, CtxError, FromContext, Location, ResultExt};
use openpgp::cert::{CertParser, prelude::CertBuilder};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy as OpenPgpPolicy;
use openpgp::serialize::Serialize as _;
use openpgp::serialize::stream::{Armorer, Encryptor2, LiteralWriter, Message};
use sequoia_openpgp as openpgp;

use crate::{ApiClient, output};

const PLAINTEXT_KEYGEN_WARNING: &str = "This helper writes private OpenPGP key material to an \
unencrypted file on disk. That is unsafe for real shard holders: anyone who can read the file can \
submit that holder's shard. Prefer a smart card containing the OpenPGP key. Keyfork supports \
offline OpenPGP key derivation and smart-card-oriented workflows: https://git.distrust.co/public/keyfork";

#[derive(Debug, Clone, PartialEq, Eq)]
struct EnvAssignment {
    key: String,
    value: String,
}

fn is_valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn parse_env_value(value: &str) -> String {
    // Parse the first shell compatible word
    // $() and embedded variations will be maintained, but quotes will be stripped.
    let first_word = if let Some(mut words) = shlex::split(value)
        && !words.is_empty()
    {
        words.swap_remove(0)
    } else {
        String::new()
    };

    shlex::try_quote(&first_word)
        .expect("only possible error is null byte, impossible with str")
        .into()
}

fn parse_env_assignments(content: &str) -> Vec<EnvAssignment> {
    let mut assignments = Vec::new();

    for line in content.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let assignment = match trimmed.strip_prefix("export") {
            Some(rest)
                if rest
                    .chars()
                    .next()
                    .is_some_and(|ch| ch.is_ascii_whitespace()) =>
            {
                rest.trim_start()
            }
            _ => trimmed,
        };

        let Some((key, value)) = assignment.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();

        if !is_valid_env_key(key) {
            continue;
        }

        assignments.push(EnvAssignment {
            key: key.to_string(),
            value: parse_env_value(value),
        });
    }

    assignments
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum ParseQuorumBundlePublicKeyError {
    #[error("Failed to verify proofed quorum bundle [{location:?}]")]
    ParseJson {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

fn parse_quorum_bundle_public_key(
    bundle_text: &str,
    allow_legacy: bool,
) -> Result<(String, bool), ParseQuorumBundlePublicKeyError> {
    use ParseQuorumBundlePublicKeyErrorCtx as Ctx;

    let (bundle, _) = crate::quorum_legacy::load(bundle_text, allow_legacy, None)
        .with_context(Ctx::parse_json())?;
    if bundle.recovery().legacy { output::status("Legacy V0 — no Keymaker generation proof (--allow-legacy accepted)"); }
    Ok((bundle.recovery().public_key.to_owned(), bundle.recovery().legacy))
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum LoadRecipientCertError {
    #[error("Failed to parse recipient public key [{location:?}]")]
    ParseCert {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

fn load_recipient_cert(public_key: &str) -> Result<openpgp::Cert, LoadRecipientCertError> {
    use LoadRecipientCertErrorCtx as Ctx;

    openpgp::Cert::from_reader(public_key.as_bytes()).with_context(Ctx::parse_cert())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum EncryptSecretValueError {
    #[error("Recipient public key has no suitable encryption subkey [{location:?}]")]
    NoEncryptionKey {
        #[location]
        location: Location,
    },

    #[error("Failed to armor encrypted secret [{location:?}]")]
    Armor {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to create OpenPGP encryptor [{location:?}]")]
    Encryptor {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to create OpenPGP literal writer [{location:?}]")]
    LiteralWriter {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to write secret plaintext [{location:?}]")]
    WritePlaintext {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to finalize encrypted secret [{location:?}]")]
    Finalize {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Encrypted OpenPGP armor was not valid UTF-8 [{location:?}]")]
    Utf8 {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

fn encrypt_secret_value(
    recipient: &openpgp::Cert,
    plaintext: &str,
    legacy: bool,
) -> Result<String, EncryptSecretValueError> {
    use EncryptSecretValueErrorCtx as Ctx;

    let policy = &OpenPgpPolicy::new();
    if legacy && matches!(recipient.revocation_status(policy, None), openpgp::types::RevocationStatus::Revoked(_)) {
        return Err(EncryptSecretValueError::NoEncryptionKey {
            location: std::panic::Location::caller(),
        });
    }
    // Only an explicitly accepted ImportedV0 artifact may use expired keys.
    // Keep algorithm support, certificate bindings and revocation checks intact.
    let keys = || {
        let keys = recipient.keys().with_policy(policy, None).supported().revoked(false);
        if legacy { keys } else { keys.alive() }
    };
    let mut recipients: Vec<_> = keys().for_storage_encryption().collect();
    if recipients.is_empty() {
        recipients = keys().for_transport_encryption().collect();
    }

    if recipients.is_empty() {
        return Err(EncryptSecretValueError::NoEncryptionKey {
            location: std::panic::Location::caller(),
        });
    }

    let mut ciphertext = Vec::new();
    let message = Message::new(&mut ciphertext);
    let message = Armorer::new(message).build().with_context(Ctx::armor())?;
    let message = Encryptor2::for_recipients(message, recipients)
        .build()
        .with_context(Ctx::encryptor())?;
    let mut message = LiteralWriter::new(message)
        .build()
        .with_context(Ctx::literal_writer())?;

    message
        .write_all(plaintext.as_bytes())
        .with_context(Ctx::write_plaintext())?;
    message.finalize().with_context(Ctx::finalize())?;

    String::from_utf8(ciphertext).with_context(Ctx::utf8())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum WriteSecretFileAtomicallyError {
    #[error("Output path has no parent: {path} [{location:?}]")]
    NoParent {
        path: PathBuf,

        #[location]
        location: Location,
    },

    #[error("Output path has invalid file name: {path} [{location:?}]")]
    InvalidFileName {
        path: PathBuf,

        #[location]
        location: Location,
    },

    #[error("Failed to write temporary file {tmp_path} [{location:?}]")]
    WriteTmp {
        #[context(borrow = Path)]
        tmp_path: PathBuf,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to move encrypted secret to {path} [{location:?}]")]
    Rename {
        #[context(borrow = Path)]
        path: PathBuf,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

fn write_secret_file_atomically(
    path: &Path,
    content: &str,
) -> Result<(), WriteSecretFileAtomicallyError> {
    use WriteSecretFileAtomicallyErrorCtx as Ctx;

    let parent = match path.parent() {
        Some(parent) => parent,
        None => {
            return Err(WriteSecretFileAtomicallyError::NoParent {
                path: path.to_path_buf(),
                location: std::panic::Location::caller(),
            });
        }
    };
    let file_name = match path.file_name().and_then(|name| name.to_str()) {
        Some(file_name) => file_name,
        None => {
            return Err(WriteSecretFileAtomicallyError::InvalidFileName {
                path: path.to_path_buf(),
                location: std::panic::Location::caller(),
            });
        }
    };
    let tmp_path = parent.join(format!(".{}.tmp.{}", file_name, std::process::id()));

    fs::write(&tmp_path, content).with_context(Ctx::write_tmp(&tmp_path))?;

    fs::rename(&tmp_path, path)
        .inspect_err(|_| {
            let _ = fs::remove_file(&tmp_path);
        })
        .with_context(Ctx::rename(path))?;

    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum EncryptEnvFileError {
    #[error("Invalid env key: {key} [{location:?}]")]
    InvalidEnvKey {
        key: String,

        #[location]
        location: Location,
    },

    #[error("Missing env file: {env_file} [{location:?}]")]
    MissingEnvFile {
        env_file: PathBuf,

        #[location]
        location: Location,
    },

    #[error("Missing quorum bundle: {bundle_file} [{location:?}]")]
    MissingBundleFile {
        bundle_file: PathBuf,

        #[location]
        location: Location,
    },

    #[error("Failed to read env file {env_file} [{location:?}]")]
    ReadEnvFile {
        #[context(borrow = Path)]
        env_file: PathBuf,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Env key(s) not found in {env_file}: {missing:?} [{location:?}]")]
    MissingRequestedKeys {
        env_file: PathBuf,

        missing: Vec<String>,

        #[location]
        location: Location,
    },

    #[error("Failed to read quorum bundle {bundle_file} [{location:?}]")]
    ReadBundleFile {
        #[context(borrow = Path)]
        bundle_file: PathBuf,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to parse quorum bundle {bundle_file} [{location:?}]")]
    ParseBundle {
        #[context(borrow = Path)]
        bundle_file: PathBuf,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to load recipient certificate [{location:?}]")]
    LoadRecipient {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to create {secrets_dir} [{location:?}]")]
    CreateSecretsDir {
        #[context(borrow = Path)]
        secrets_dir: PathBuf,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to encrypt {key} [{location:?}]")]
    EncryptValue {
        #[context(borrow = str)]
        key: String,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to write encrypted secret to {path} [{location:?}]")]
    WriteValue {
        #[context(borrow = Path)]
        path: PathBuf,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

fn encrypt_env_file(
    env_file: &Path,
    bundle_file: &Path,
    secrets_dir: &Path,
    requested_keys: &[String],
    allow_legacy: bool,
) -> Result<usize, EncryptEnvFileError> {
    use EncryptEnvFileErrorCtx as Ctx;

    for key in requested_keys {
        if !is_valid_env_key(key) {
            return Err(EncryptEnvFileError::InvalidEnvKey {
                key: key.clone(),
                location: std::panic::Location::caller(),
            });
        }
    }

    if !env_file.is_file() {
        return Err(EncryptEnvFileError::MissingEnvFile {
            env_file: env_file.to_path_buf(),
            location: std::panic::Location::caller(),
        });
    }
    if !bundle_file.is_file() {
        return Err(EncryptEnvFileError::MissingBundleFile {
            bundle_file: bundle_file.to_path_buf(),
            location: std::panic::Location::caller(),
        });
    }

    let env_text = fs::read_to_string(env_file).with_context(Ctx::read_env_file(env_file))?;
    let assignments = parse_env_assignments(&env_text);
    let requested: HashSet<&str> = requested_keys.iter().map(String::as_str).collect();

    if !requested.is_empty() {
        let env_keys: HashSet<&str> = assignments
            .iter()
            .map(|assignment| assignment.key.as_str())
            .collect();
        let mut missing: Vec<&str> = requested
            .iter()
            .copied()
            .filter(|key| !env_keys.contains(key))
            .collect();
        missing.sort_unstable();

        if !missing.is_empty() {
            return Err(EncryptEnvFileError::MissingRequestedKeys {
                env_file: env_file.to_path_buf(),
                missing: missing.iter().map(|key| (*key).to_string()).collect(),
                location: std::panic::Location::caller(),
            });
        }
    }

    let bundle_text =
        fs::read_to_string(bundle_file).with_context(Ctx::read_bundle_file(bundle_file))?;
    let (public_key, legacy) = parse_quorum_bundle_public_key(&bundle_text, allow_legacy)
        .with_context(Ctx::parse_bundle(bundle_file))?;
    let recipient = load_recipient_cert(&public_key).with_context(Ctx::load_recipient())?;

    fs::create_dir_all(secrets_dir).with_context(Ctx::create_secrets_dir(secrets_dir))?;

    let mut count = 0usize;
    for assignment in assignments {
        if !requested.is_empty() && !requested.contains(assignment.key.as_str()) {
            continue;
        }

        if assignment.value.is_empty() {
            output::status(format!("skipping empty value for {}", assignment.key));
            continue;
        }

        let encrypted = encrypt_secret_value(&recipient, &assignment.value, legacy)
            .with_context(Ctx::encrypt_value(&assignment.key))?;
        let output = secrets_dir.join(format!("{}.asc", assignment.key));
        write_secret_file_atomically(&output, &encrypted)
            .with_context(Ctx::write_value(&output))?;

        output::status(format!(
            "encrypted {} -> {}",
            assignment.key,
            output.display()
        ));
        count += 1;
    }

    output::success(format!("encrypted {} secret(s)", count));

    Ok(count)
}

/// Key roles used to determine Keymaker eligibility of a single certificate.
struct CertEligibility {
    has_sign: bool,
    has_auth: bool,
    has_enc: bool,
}

impl CertEligibility {
    fn is_eligible(&self) -> bool {
        self.has_sign && self.has_auth && self.has_enc
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum KeymakerCertEligibilityError {
    #[error("Failed to parse keyring as OpenPGP public certificates [{location:?}]")]
    ParseKeyring {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to parse OpenPGP public certificate [{location:?}]")]
    ParseCert {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("OpenPGP public certificate is not valid under the standard policy [{location:?}]")]
    InvalidCert {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

/// Inspect each certificate in an armored keyring for Keymaker eligibility.
///
/// A certificate is eligible only if it carries signing, authentication, and
/// storage-encryption subkeys valid under the standard policy.
fn keymaker_cert_eligibility(
    armored_keyring: &str,
) -> Result<Vec<CertEligibility>, KeymakerCertEligibilityError> {
    use KeymakerCertEligibilityErrorCtx as Ctx;

    let cert_parser = CertParser::from_bytes(armored_keyring).with_context(Ctx::parse_keyring())?;
    let policy = openpgp::policy::StandardPolicy::new();
    let mut certs = Vec::new();

    for parseable_cert in cert_parser {
        let cert = parseable_cert.with_context(Ctx::parse_cert())?;
        let valid_cert = cert
            .with_policy(&policy, None)
            .with_context(Ctx::invalid_cert())?;

        certs.push(CertEligibility {
            has_sign: valid_cert.keys().for_signing().next().is_some(),
            has_auth: valid_cert.keys().for_authentication().next().is_some(),
            has_enc: valid_cert.keys().for_storage_encryption().next().is_some(),
        });
    }

    Ok(certs)
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum KeymakerEligibleCertCountError {
    #[error("Failed to inspect keyring eligibility [{location:?}]")]
    InspectKeyring {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

fn keymaker_eligible_cert_count(
    armored_keyring: &str,
) -> Result<usize, KeymakerEligibleCertCountError> {
    use KeymakerEligibleCertCountErrorCtx as Ctx;

    Ok(keymaker_cert_eligibility(armored_keyring)
        .with_context(Ctx::inspect_keyring())?
        .iter()
        .filter(|cert| cert.is_eligible())
        .count())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum ResolveQuorumParametersError {
    #[error(
        "keyring contains no Keymaker-eligible public certificates \
         (each certificate needs signing, authentication, and storage-encryption keys) [{location:?}]"
    )]
    NoEligibleCerts {
        #[location]
        location: Location,
    },

    #[error(
        "keyring contains more than 254 Keymaker-eligible public certificates (found {eligible_certs}) [{location:?}]"
    )]
    TooManyCerts {
        eligible_certs: usize,

        #[location]
        location: Location,

        #[source]
        source: Option<BoxError>,
    },

    #[error(
        "--max ({max}) must match the number of Keymaker-eligible public certificates \
         in the keyring ({eligible_certs}); use --max {eligible_certs}, or pass a keyring with \
         exactly {max} eligible certificate(s) [{location:?}]"
    )]
    MaxMismatch {
        max: u8,

        eligible_certs: usize,

        #[location]
        location: Location,
    },

    #[error(
        "--threshold must be between 1 and --max (got threshold={threshold}, max={max}) [{location:?}]"
    )]
    InvalidThreshold {
        threshold: u8,

        max: u8,

        #[location]
        location: Location,
    },
}

pub(crate) fn resolve_quorum_parameters(
    threshold: Option<u8>,
    max: Option<u8>,
    eligible_certs: usize,
) -> Result<(u8, u8), ResolveQuorumParametersError> {
    if eligible_certs == 0 {
        return Err(ResolveQuorumParametersError::NoEligibleCerts {
            location: std::panic::Location::caller(),
        });
    }

    if eligible_certs > 254 {
        return Err(ResolveQuorumParametersError::TooManyCerts {
            eligible_certs,
            location: std::panic::Location::caller(),
            source: None,
        });
    }
    let inferred_max = eligible_certs as u8;
    let threshold = threshold.unwrap_or(1);
    let max = max.unwrap_or(inferred_max);

    if max as usize != eligible_certs {
        return Err(ResolveQuorumParametersError::MaxMismatch {
            max,
            eligible_certs,
            location: std::panic::Location::caller(),
        });
    }

    if threshold == 0 || threshold > max {
        return Err(ResolveQuorumParametersError::InvalidThreshold {
            threshold,
            max,
            location: std::panic::Location::caller(),
        });
    }

    Ok((threshold, max))
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum KeymakerCertError {
    #[error("Failed to generate OpenPGP key [{location:?}]")]
    Generate {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

fn keymaker_cert(user_id: String) -> Result<openpgp::Cert, KeymakerCertError> {
    use KeymakerCertErrorCtx as Ctx;

    let (cert, _) = CertBuilder::new()
        .add_userid(user_id)
        .add_signing_subkey()
        .add_storage_encryption_subkey()
        .add_authentication_subkey()
        .generate()
        .with_context(Ctx::generate())?;

    Ok(cert)
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum ArmoredKeyringsForCertError {
    #[error("Failed to serialize public keyring [{location:?}]")]
    SerializePublic {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to serialize private keyring [{location:?}]")]
    SerializePrivate {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

fn armored_keyrings_for_cert(
    cert: &openpgp::Cert,
) -> Result<(Vec<u8>, Vec<u8>), ArmoredKeyringsForCertError> {
    use ArmoredKeyringsForCertErrorCtx as Ctx;

    let mut public_keyring = Vec::new();
    cert.armored()
        .serialize(&mut public_keyring)
        .with_context(Ctx::serialize_public())?;

    let mut private_keyring = Vec::new();
    cert.as_tsk()
        .armored()
        .serialize(&mut private_keyring)
        .with_context(Ctx::serialize_private())?;

    Ok((public_keyring, private_keyring))
}

fn default_private_keyring_path(public_keyring: &Path) -> PathBuf {
    let mut private_keyring = public_keyring.to_path_buf();
    let extension = public_keyring
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| format!("private.{extension}"))
        .unwrap_or_else(|| "private".to_string());
    private_keyring.set_extension(extension);
    private_keyring
}

/// Which step of writing the keyring file failed, plus any step-specific context.
#[derive(Debug, FromContext)]
pub enum WriteKeyringErrorKind {
    // `parent` surfaces in the message through the kind's derived `Debug`; rustc intentionally
    // ignores reads through derived impls during dead-code analysis, so silence it explicitly.
    #[expect(
        dead_code,
        reason = "read via the kind's derived Debug when formatting the error"
    )]
    CreateParentDir {
        #[context(borrow = Path)]
        parent: PathBuf,
    },
    OpenFile,
    AlreadyExists,
    Write,
    SetPermissions,
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("failed to write keyring {path} ({kind:?}) [{location:?}]")]
pub struct WriteKeyringError {
    #[context(borrow = Path)]
    path: PathBuf,

    #[context(from = WriteKeyringErrorKindCtx<'a>)]
    kind: WriteKeyringErrorKind,

    #[location]
    location: Location,

    #[source]
    source: BoxError,
}

fn write_keyring(
    path: &Path,
    contents: &[u8],
    force: bool,
    sensitive: bool,
) -> Result<(), WriteKeyringError> {
    use WriteKeyringErrorCtx as Ctx;
    use WriteKeyringErrorKindCtx as KindCtx;

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(Ctx::new(path, KindCtx::create_parent_dir(parent)))?;
    }

    let mut options = fs::OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    #[cfg(unix)]
    if sensitive {
        options.mode(0o600);
    }

    let kind_ctx = if force {
        KindCtx::open_file()
    } else {
        KindCtx::already_exists()
    };
    let mut file = options.open(path).with_context(Ctx::new(path, kind_ctx))?;
    file.write_all(contents)
        .with_context(Ctx::new(path, KindCtx::write()))?;

    #[cfg(unix)]
    if sensitive {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(Ctx::new(path, KindCtx::set_permissions()))?;
    }

    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum KeygenError {
    #[error(
        "Refusing to generate an unencrypted private keyring without \
         --shoot-self-in-foot.\n\n{warning} [{location:?}]"
    )]
    NotAcknowledged {
        warning: &'static str,

        #[location]
        location: Location,
    },

    #[error("--name must not be empty [{location:?}]")]
    EmptyName {
        #[location]
        location: Location,
    },

    #[error("--email must not be empty [{location:?}]")]
    EmptyEmail {
        #[location]
        location: Location,
    },

    #[error("--name and --email must not contain newlines or angle brackets [{location:?}]")]
    InvalidCharacters {
        #[location]
        location: Location,
    },

    #[error("--email must be an email address [{location:?}]")]
    InvalidEmail {
        #[location]
        location: Location,
    },

    #[error("public and private keyring paths must be different [{location:?}]")]
    IdenticalPaths {
        #[location]
        location: Location,
    },

    #[error("{path} already exists; pass --force to overwrite it [{location:?}]")]
    AlreadyExists {
        path: PathBuf,

        #[location]
        location: Location,
    },

    #[error("Failed to generate OpenPGP key [{location:?}]")]
    GenerateKey {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to serialize keyrings [{location:?}]")]
    SerializeKeyrings {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Generated public keyring is not valid UTF-8 [{location:?}]")]
    PublicKeyringUtf8 {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Generated keyring is not Keymaker-eligible [{location:?}]")]
    EligibleCount {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error(
        "generated keyring should contain exactly one eligible certificate, found {count} [{location:?}]"
    )]
    UnexpectedEligibleCount {
        count: usize,

        #[location]
        location: Location,
    },

    #[error("Failed to write public keyring to {path} [{location:?}]")]
    WritePublicKeyring {
        #[context(borrow = Path)]
        path: PathBuf,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to write private keyring to {path} [{location:?}]")]
    WritePrivateKeyring {
        #[context(borrow = Path)]
        path: PathBuf,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

/// Generate unsafe plaintext Keymaker-compatible OpenPGP keyrings.
pub fn keygen(
    output: PathBuf,
    private_keyring: Option<PathBuf>,
    name: String,
    email: String,
    force: bool,
    shoot_self_in_foot: bool,
) -> Result<(), KeygenError> {
    use KeygenErrorCtx as Ctx;

    if !shoot_self_in_foot {
        return Err(KeygenError::NotAcknowledged {
            warning: PLAINTEXT_KEYGEN_WARNING,
            location: std::panic::Location::caller(),
        });
    }

    let name = name.trim();
    let email = email.trim();

    if name.is_empty() {
        return Err(KeygenError::EmptyName {
            location: std::panic::Location::caller(),
        });
    }
    if email.is_empty() {
        return Err(KeygenError::EmptyEmail {
            location: std::panic::Location::caller(),
        });
    }
    if name.chars().any(|ch| matches!(ch, '\n' | '\r' | '<' | '>'))
        || email
            .chars()
            .any(|ch| matches!(ch, '\n' | '\r' | '<' | '>'))
    {
        return Err(KeygenError::InvalidCharacters {
            location: std::panic::Location::caller(),
        });
    }
    if !email.contains('@') {
        return Err(KeygenError::InvalidEmail {
            location: std::panic::Location::caller(),
        });
    }

    let private_keyring = private_keyring.unwrap_or_else(|| default_private_keyring_path(&output));
    if output == private_keyring {
        return Err(KeygenError::IdenticalPaths {
            location: std::panic::Location::caller(),
        });
    }
    if !force {
        if output.exists() {
            return Err(KeygenError::AlreadyExists {
                path: output.clone(),
                location: std::panic::Location::caller(),
            });
        }
        if private_keyring.exists() {
            return Err(KeygenError::AlreadyExists {
                path: private_keyring.clone(),
                location: std::panic::Location::caller(),
            });
        }
    }

    let user_id = format!("{name} <{email}>");
    output::status(format!("Generating OpenPGP key for {user_id}..."));

    let cert = keymaker_cert(user_id).with_context(Ctx::generate_key())?;
    let fingerprint = cert.fingerprint();
    let (public_keyring, private_keyring_contents) =
        armored_keyrings_for_cert(&cert).with_context(Ctx::serialize_keyrings())?;

    let public_keyring_text =
        std::str::from_utf8(&public_keyring).with_context(Ctx::public_keyring_utf8())?;
    let eligible_certs =
        keymaker_eligible_cert_count(public_keyring_text).with_context(Ctx::eligible_count())?;
    if eligible_certs != 1 {
        return Err(KeygenError::UnexpectedEligibleCount {
            count: eligible_certs,
            location: std::panic::Location::caller(),
        });
    }

    write_keyring(&output, &public_keyring, force, false)
        .with_context(Ctx::write_public_keyring(&output))?;
    write_keyring(&private_keyring, &private_keyring_contents, force, true)
        .with_context(Ctx::write_private_keyring(&private_keyring))?;

    output::success(format!("Wrote public keyring to {}", output.display()));
    output::status(format!("Fingerprint: {}", fingerprint));
    output::success(format!(
        "Wrote private keyring to {}",
        private_keyring.display()
    ));
    output::warning(PLAINTEXT_KEYGEN_WARNING);
    output::warning(format!(
        "Use the private keyring with: caution secret send-shard --keyring {}",
        private_keyring.display()
    ));

    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum EncryptError {
    #[error("Failed to encrypt env file [{location:?}]")]
    EncryptEnvFile {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

/// Encrypt env file values into `.caution/secrets/*.asc`.
pub fn encrypt(
    keys: Vec<String>,
    env_file: PathBuf,
    bundle: PathBuf,
    secrets_dir: PathBuf,
    allow_legacy: bool,
) -> Result<(), EncryptError> {
    use EncryptErrorCtx as Ctx;

    encrypt_env_file(&env_file, &bundle, &secrets_dir, &keys, allow_legacy)
        .with_context(Ctx::encrypt_env_file())?;

    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum RenameError {
    #[error("Failed to authenticate with Caution [{location:?}]")]
    EnsureAuthenticated {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to connect to server [{location:?}]")]
    ConnectPatch {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to rename quorum bundle ({status}): {message} [{location:?}]")]
    RenameFailed {
        status: reqwest::StatusCode,

        message: String,

        #[location]
        location: Location,
    },
}

/// Rename a quorum bundle.
pub async fn rename(client: &ApiClient, id: String, name: String) -> Result<(), RenameError> {
    use RenameErrorCtx as Ctx;

    let config = client
        .ensure_authenticated()
        .await
        .with_context(Ctx::ensure_authenticated())?;

    let body = serde_json::json!({
        "name": name,
    });

    let response = client
        .signed_request(
            &config.session_id,
            &["/api/quorum-bundles/", &id].concat(),
            reqwest::Method::PATCH,
            serde_json::to_vec(&body).with_context(Ctx::connect_patch())?,
        )
        .await
        .with_context(Ctx::connect_patch())?;

    if response.status().is_success() {
        output::success(format!("Quorum bundle renamed to \"{}\"", name));
    } else {
        let status = response.status();
        let error = client.api_error_message(response).await;
        return Err(RenameError::RenameFailed {
            status,
            message: error,
            location: std::panic::Location::caller(),
        });
    }

    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum LabelSetError {
    #[error("Failed to authenticate with Caution [{location:?}]")]
    EnsureAuthenticated {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to fetch quorum bundle {id} [{location:?}]")]
    FetchBundle {
        #[context(borrow = str)]
        id: String,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Invalid label format '{label}', expected key=value [{location:?}]")]
    InvalidLabel {
        label: String,

        #[location]
        location: Location,
    },

    #[error("Failed to connect to server [{location:?}]")]
    ConnectPatch {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to update labels ({status}): {message} [{location:?}]")]
    UpdateFailed {
        status: reqwest::StatusCode,

        message: String,

        #[location]
        location: Location,
    },
}

/// Set labels on a quorum bundle.
pub async fn label_set(
    client: &ApiClient,
    id: String,
    labels: Vec<String>,
) -> Result<(), LabelSetError> {
    use LabelSetErrorCtx as Ctx;

    let config = client
        .ensure_authenticated()
        .await
        .with_context(Ctx::ensure_authenticated())?;

    // Get current bundle to read existing labels
    let bundle: serde_json::Value = client
        .get_protected_json(
            &config.session_id,
            &format!("/api/quorum-bundles/{}", id),
            "Failed to fetch quorum bundle",
        )
        .await
        .with_context(Ctx::fetch_bundle(&id))?;

    let mut current_labels = bundle
        .get("labels")
        .and_then(|l| l.as_object().cloned())
        .unwrap_or_default();

    // Merge new labels
    for label in &labels {
        let (k, v) = label
            .split_once('=')
            .ok_or_else(|| LabelSetError::InvalidLabel {
                label: label.clone(),
                location: std::panic::Location::caller(),
            })?;
        current_labels.insert(k.to_string(), serde_json::Value::String(v.to_string()));
    }

    let body = serde_json::json!({ "labels": current_labels });

    let response = client
        .signed_request(
            &config.session_id,
            &["/api/quorum-bundles/", &id].concat(),
            reqwest::Method::PATCH,
            serde_json::to_vec(&body).with_context(Ctx::connect_patch())?,
        )
        .await
        .with_context(Ctx::connect_patch())?;

    if response.status().is_success() {
        output::success("Labels updated successfully");
    } else {
        let status = response.status();
        let error = client.api_error_message(response).await;
        return Err(LabelSetError::UpdateFailed {
            status,
            message: error,
            location: std::panic::Location::caller(),
        });
    }

    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum LabelRemoveError {
    #[error("Failed to authenticate with Caution [{location:?}]")]
    EnsureAuthenticated {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to fetch quorum bundle {id} [{location:?}]")]
    FetchBundle {
        #[context(borrow = str)]
        id: String,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to connect to server [{location:?}]")]
    ConnectPatch {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to remove labels ({status}): {message} [{location:?}]")]
    RemoveFailed {
        status: reqwest::StatusCode,

        message: String,

        #[location]
        location: Location,
    },
}

/// Remove labels from a quorum bundle.
pub async fn label_remove(
    client: &ApiClient,
    id: String,
    keys: Vec<String>,
) -> Result<(), LabelRemoveError> {
    use LabelRemoveErrorCtx as Ctx;

    let config = client
        .ensure_authenticated()
        .await
        .with_context(Ctx::ensure_authenticated())?;

    // Get current bundle to read existing labels
    let bundle: serde_json::Value = client
        .get_protected_json(
            &config.session_id,
            &format!("/api/quorum-bundles/{}", id),
            "Failed to fetch quorum bundle",
        )
        .await
        .with_context(Ctx::fetch_bundle(&id))?;

    let mut current_labels = bundle
        .get("labels")
        .and_then(|l| l.as_object().cloned())
        .unwrap_or_default();

    for key in &keys {
        current_labels.remove(key);
    }

    let body = serde_json::json!({ "labels": current_labels });

    let response = client
        .signed_request(
            &config.session_id,
            &["/api/quorum-bundles/", &id].concat(),
            reqwest::Method::PATCH,
            serde_json::to_vec(&body).with_context(Ctx::connect_patch())?,
        )
        .await
        .with_context(Ctx::connect_patch())?;

    if response.status().is_success() {
        output::success("Labels removed successfully");
    } else {
        let status = response.status();
        let error = client.api_error_message(response).await;
        return Err(LabelRemoveError::RemoveFailed {
            status,
            message: error,
            location: std::panic::Location::caller(),
        });
    }

    Ok(())
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum SendShardError {
    #[error("Failed to fetch app [{location:?}]")]
    FetchApp {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to fetch current app [{location:?}]")]
    GetCurrentApp {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("App has no public IP. Is the enclave running? [{location:?}]")]
    NoPublicIp {
        #[location]
        location: Location,
    },

    #[error("Failed to authenticate with Caution [{location:?}]")]
    EnsureAuthenticated {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to fetch quorum bundles from Caution [{location:?}]")]
    FetchBundles {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error(
        "No bundle found locally or on Caution. Create one with: caution secret new <keyring> [{location:?}]"
    )]
    NoBundleFound {
        #[location]
        location: Location,
    },

    #[error("Bundle has no data field [{location:?}]")]
    MissingBundleData {
        #[location]
        location: Location,
    },

    #[error("Failed to create .caution/secrets/ [{location:?}]")]
    CreateSecretsDir {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to serialize fetched bundle [{location:?}]")]
    SerializeBundle {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to write bundle to {path} [{location:?}]")]
    WriteBundle {
        #[context(borrow = Path)]
        path: PathBuf,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Bundle file not found: {bundle_file} [{location:?}]")]
    BundleMissing {
        bundle_file: PathBuf,

        #[location]
        location: Location,
    },

    #[error(
        "No trusted hashes found. Run `caution verify` first to establish trusted PCR values [{location:?}]"
    )]
    ReadTrustedHashes {
        #[context(borrow = Path)]
        path: PathBuf,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to parse .caution/trusted_hashes.json [{location:?}]")]
    ParseTrustedHashes {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("missing pcr{pcr} [{location:?}]")]
    MissingPcr {
        pcr: u8,

        #[location]
        location: Location,
    },

    #[error("invalid pcr{pcr} hex [{location:?}]")]
    InvalidPcrHex {
        pcr: u8,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to read bundle file: {bundle_file} [{location:?}]")]
    ReadBundleFile {
        #[context(borrow = Path)]
        bundle_file: PathBuf,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to parse bundle JSON [{location:?}]")]
    ParseBundle {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Unable to select share holder [{location:?}]")]
    SelectHolder {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Could not obtain destination attestation from {address}. No share was sent; check that the app is awaiting quorum shares and port 49504 is reachable (30-second connection/response timeout) [{location:?}]")]
    DestinationAttestation {
        address: std::net::SocketAddr,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Destination attestation verification failed at {address} against .caution/trusted_hashes.json. No share was sent [{location:?}]")]
    DestinationVerification {
        address: std::net::SocketAddr,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Destination PCR mismatch ({pcr}) at {address}: the app does not match .caution/trusted_hashes.json. No share was sent. If you intended to change the deployment, complete `caution verify` from the intended app checkout before retrying. --recryptor-pcr-policy verifies the custody service, not this app [{location:?}]")]
    DestinationPcrMismatch {
        address: std::net::SocketAddr,
        pcr: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Connection closed during quorum unlocking; share acceptance was not confirmed. The application may already be unlocked; check its status before retrying [{location:?}]")]
    ConnectionClosed {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Invalid address: {address} [{location:?}]")]
    InvalidAddress {
        #[context(borrow = str)]
        address: String,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to send shard to enclave at {address} [{location:?}]")]
    SendShard {
        #[context(borrow = str)]
        address: String,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Shard rejected by enclave: {reason} [{location:?}]")]
    ShardRejected {
        reason: String,

        #[location]
        location: Location,
    },
}

fn connection_closed(mut error: &(dyn std::error::Error + 'static)) -> bool {
    loop {
        if let Some(io) = error.downcast_ref::<std::io::Error>() {
            if matches!(io.kind(), std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::BrokenPipe) {
                return true;
            }
        }
        match error.source() { Some(source) => error = source, None => return false }
    }
}

fn share_acceptance_message(remaining: u8) -> String {
    match remaining {
        0 => "Quorum reconstructed successfully.".to_owned(),
        1 => "Share accepted. 1 more share required.".to_owned(),
        n => format!("Share accepted. {n} more shares required."),
    }
}

fn verify_destination_attestation(
    address: std::net::SocketAddr,
    attestation: Vec<u8>,
    pcrs: std::collections::HashMap<u8, Vec<u8>>,
    nonce: &[u8],
    now: std::time::Duration,
) -> Result<(), SendShardError> {
    use bootproof_sdk::format::{Error, VerifiableSignedAttestationFormat, nitro::Nitro};
    // Use the same live verifier as the external-PGP transport. The real release
    // still verifies its own fresh nonce and destination key on its own connection.
    Nitro::new(attestation, pcrs)
        .and_then(|proof| proof.verify(now, &nonce))
        .map(|_| ())
        .map_err(|source| match &source {
            Error::InvalidAAD(pcr) if matches!(pcr.as_ref(), "pcr 0" | "pcr 1" | "pcr 2") => {
                SendShardError::DestinationPcrMismatch {
                    address, pcr: pcr.to_string(),
                    location: std::panic::Location::caller(), source: Box::new(source),
                }
            }
            _ => SendShardError::DestinationVerification {
                address, location: std::panic::Location::caller(), source: Box::new(source),
            },
        })
}

async fn preflight_destination(
    address: std::net::SocketAddr,
    pcrs: &std::collections::HashMap<u8, Vec<u8>>,
) -> Result<(), SendShardError> {
    use SendShardErrorCtx as Ctx;
    let nonce = locksmith::release::random_nonce();
    let destination = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        locksmith::release::crypto::Destination::connect(address, nonce.clone()),
    ).await.with_context(Ctx::destination_attestation(address))?
        .with_context(Ctx::destination_attestation(address))?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .with_context(Ctx::destination_verification(address))?;
    verify_destination_attestation(address, destination.attestation, pcrs.clone(), nonce.as_bytes(), now)
}

fn local_quorum_bundle(root: &Path) -> Option<PathBuf> {
    [".caution/quorum-bundle.json", ".caution/secrets/bundle.json"]
        .into_iter().map(|path| root.join(path)).find(|path| path.exists())
}

/// Send a shard to a running enclave's locksmith daemon.
pub async fn send_shard(
    client: &ApiClient,
    app: Option<String>,
    bundle_path: Option<PathBuf>,
    private_keyring: Option<PathBuf>,
    release_options: crate::share_release::Options,
) -> Result<(), SendShardError> {
    use SendShardErrorCtx as Ctx;

    // Resolve the app to get the enclave's public IP
    let app_info = match app {
        Some(id) => client.fetch_app(&id).await.with_context(Ctx::fetch_app())?,
        None => client
            .get_current_app()
            .await
            .with_context(Ctx::get_current_app())?,
    };

    let public_ip = app_info
        .public_ip
        .ok_or_else(|| SendShardError::NoPublicIp {
            location: std::panic::Location::caller(),
        })?;

    // Resolve the bundle file
    let bundle_file = if let Some(path) = bundle_path {
        path
    } else {
        if let Some(path) = local_quorum_bundle(Path::new(".")) {
            path
        } else {
            // Try to pull from Caution API
            output::status("No local bundle found, checking Caution...");
            let config = client
                .ensure_authenticated()
                .await
                .with_context(Ctx::ensure_authenticated())?;

            let bundles: Vec<serde_json::Value> = client
                .get_protected_json(
                    &config.session_id,
                    "/api/quorum-bundles",
                    "Failed to fetch quorum bundles from Caution",
                )
                .await
                .with_context(Ctx::fetch_bundles())?;

            if bundles.is_empty() {
                return Err(SendShardError::NoBundleFound {
                    location: std::panic::Location::caller(),
                });
            }

            // Use the first bundle's data
            let bundle_data =
                bundles[0]
                    .get("data")
                    .ok_or_else(|| SendShardError::MissingBundleData {
                        location: std::panic::Location::caller(),
                    })?;

            let secrets_dir = PathBuf::from(".caution/secrets");
            fs::create_dir_all(&secrets_dir).with_context(Ctx::create_secrets_dir())?;
            let path = secrets_dir.join("bundle.json");
            let json =
                serde_json::to_string_pretty(bundle_data).with_context(Ctx::serialize_bundle())?;
            fs::write(&path, &json).with_context(Ctx::write_bundle(&path))?;
            output::status(format!("Bundle saved to {}", path.display()));
            path
        }
    };

    if !bundle_file.exists() {
        return Err(SendShardError::BundleMissing {
            bundle_file,
            location: std::panic::Location::caller(),
        });
    }

    // Load trusted hashes from a prior `caution verify`
    let hashes_path = PathBuf::from(".caution/trusted_hashes.json");
    let hashes_text =
        fs::read_to_string(&hashes_path).with_context(Ctx::read_trusted_hashes(&hashes_path))?;
    let hashes: serde_json::Value =
        serde_json::from_str(&hashes_text).with_context(Ctx::parse_trusted_hashes())?;

    let pcrs = std::collections::HashMap::from([
        (
            0u8,
            hex::decode(
                hashes["pcr0"]
                    .as_str()
                    .ok_or_else(|| SendShardError::MissingPcr {
                        pcr: 0,
                        location: std::panic::Location::caller(),
                    })?,
            )
            .with_context(Ctx::invalid_pcr_hex(0))?,
        ),
        (
            1u8,
            hex::decode(
                hashes["pcr1"]
                    .as_str()
                    .ok_or_else(|| SendShardError::MissingPcr {
                        pcr: 1,
                        location: std::panic::Location::caller(),
                    })?,
            )
            .with_context(Ctx::invalid_pcr_hex(1))?,
        ),
        (
            2u8,
            hex::decode(
                hashes["pcr2"]
                    .as_str()
                    .ok_or_else(|| SendShardError::MissingPcr {
                        pcr: 2,
                        location: std::panic::Location::caller(),
                    })?,
            )
            .with_context(Ctx::invalid_pcr_hex(2))?,
        ),
    ]);

    output::status("Loaded destination policy from .caution/trusted_hashes.json");
    if let Some(verified_at) = hashes["verified_at"].as_str() {
        output::verbose(client.verbose, format!("Recorded verification time: {} (stored metadata)", crate::share_release::terminal_label(verified_at)));
    }
    output::verbose(client.verbose, format!("Destination PCR policy: {:?}", pcrs.iter().map(|(i, value)| (*i, hex::encode(value))).collect::<std::collections::BTreeMap<_, _>>()));

    // Parse the quorum bundle
    let bundle_text =
        fs::read_to_string(&bundle_file).with_context(Ctx::read_bundle_file(&bundle_file))?;
    let (bundle, generation_time) = crate::quorum_legacy::load(&bundle_text, release_options.allow_legacy, None).with_context(Ctx::parse_bundle())?;
    let proof: serde_json::Value = serde_json::from_str(&bundle_text).with_context(Ctx::parse_bundle())?;
    let names = crate::share_release::holder_names(client, &proof).await;
    let view = bundle.recovery();
    if view.legacy {
        output::status(format!("Legacy V0 — no Keymaker generation proof (--allow-legacy accepted)\nContent hash: {}", bundle.content_hash().with_context(Ctx::parse_bundle())?));
    }
    let keys = view.keyring;
    let address_str = format!("{}:49504", public_ip);
    let address: std::net::SocketAddr = address_str
        .parse()
        .with_context(Ctx::invalid_address(&address_str))?;

    let select_holder = || crate::share_release::select_holder(keys, release_options.holder.as_deref(), private_keyring.as_deref(), &names)
        .with_context(Ctx::select_holder());
    // Preserve useful offline input errors in scripts, but never prompt before
    // checking the destination. Neither branch accesses a smartcard or passkey.
    let selected = if std::io::stdin().is_terminal() { None } else { Some(select_holder()?) };
    output::status(format!("Checking destination attestation at {address} against .caution/trusted_hashes.json…"));
    preflight_destination(address, &pcrs).await?;
    output::status("Destination attestation verified. Release will verify a fresh connection again.");
    let (holder, webauthn) = match selected { Some(holder) => holder, None => select_holder()? };
    let holder_display = crate::share_release::holder_label(keys, &holder, webauthn, &names);
    output::verbose(client.verbose, format!("Holder certificate: {holder}"));

    let latest = bundle.recovery();
    let summary = crate::share_release::ReleaseSummary {
        application_id: app_info.id.clone(),
        application_name: app_info.resource_name,
        holder: holder_display,
        address,
        threshold: latest.threshold,
        holders: latest.max,
        method: match (webauthn, client.qr, private_keyring.is_some()) {
            (true, true, _) => "Browser passkey",
            (true, false, _) => "Native passkey",
            (false, _, true) => "Private-key file",
            (false, _, false) => "OpenPGP smartcard",
        },
    };
    output::verbose(client.verbose, format!("Application ID: {}; bundle identity: {}", crate::share_release::terminal_label(&app_info.id), bundle.bundle_id().map(hex::encode).unwrap_or_else(|| "Legacy V0".into())));
    let status: Result<_, BoxError> = if webauthn {
        let proof = serde_json::from_str(&bundle_text).with_context(Ctx::parse_bundle())?;
        let measurements = pcrs.iter().map(|(&i, v)| (i, hex::encode(v))).collect();
        crate::share_release::recover(client, &release_options, proof, holder, summary, measurements, generation_time)
            .await.map_err(|error| Box::new(error) as BoxError)
    } else {
        summary.print(None);
        output::status("Connecting to the destination for attestation and share submission…");
        locksmith::client::send_selected_shard(address, pcrs, &bundle, private_keyring, Some(holder))
            .await.map_err(|error| Box::new(error) as BoxError)
    };
    let status = status.map_err(|source| {
        if connection_closed(source.as_ref()) {
            SendShardError::ConnectionClosed { location: std::panic::Location::caller(), source }
        } else {
            SendShardError::SendShard { address: address_str, location: std::panic::Location::caller(), source }
        }
    })?;

    match status {
        locksmith::models::SendSignedEncryptedShardResponse::Accepted { remaining } => {
            output::success(share_acceptance_message(remaining));
        }
        locksmith::models::SendSignedEncryptedShardResponse::Rejected { reason } => {
            return Err(SendShardError::ShardRejected {
                reason,
                location: std::panic::Location::caller(),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn imported_bundle_allows_unchanged_expired_recipient_only_with_opt_in() {
        let public_key = include_str!("../../../tests/fixtures/expired-v0-recipient.asc");
        let recipient = load_recipient_cert(public_key).unwrap();
        assert!(recipient.with_policy(&super::OpenPgpPolicy::new(), None).unwrap().alive().is_err());
        assert!(encrypt_secret_value(&recipient, "secret", false).is_err());
        assert!(encrypt_secret_value(&recipient, "secret", true).is_ok());
        let work = tempdir().unwrap();
        let env = work.path().join(".env");
        let bundle = work.path().join("bundle.json");
        let output = work.path().join("secrets");
        let mut imported: serde_json::Value = serde_json::from_str(include_str!("../../../tests/fixtures/imported-v0.json")).unwrap();
        imported["original"]["public_key"] = serde_json::json!(public_key);
        let original = serde_json::to_vec(&imported).unwrap();
        std::fs::write(&bundle, &original).unwrap();
        std::fs::write(&env, "SECRET=legacy-expired-recipient\n").unwrap();
        assert!(encrypt_env_file(&env, &bundle, &output, &[], false).is_err());
        assert_eq!(encrypt_env_file(&env, &bundle, &output, &[], true).unwrap(), 1);
        assert_eq!(std::fs::read(bundle).unwrap(), original);
    }

    #[test]
    fn legacy_encryption_still_rejects_revoked_recipients() {
        let (cert, revocation) = CertBuilder::new().add_userid("revoked recipient")
            .add_storage_encryption_subkey().generate().unwrap();
        let revoked = cert.insert_packets([revocation]).unwrap();
        assert!(encrypt_secret_value(&revoked, "secret", true).is_err());
    }

    #[test]
    fn default_release_prefers_imported_output_and_preserves_raw_source() {
        let work = tempdir().unwrap();
        let source = work.path().join(".caution/secrets/bundle.json");
        let imported = work.path().join(".caution/quorum-bundle.json");
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        assert!(super::local_quorum_bundle(work.path()).is_none());
        std::fs::write(&source, "raw V0").unwrap();
        assert_eq!(super::local_quorum_bundle(work.path()), Some(source.clone()));
        std::fs::write(&imported, include_str!("../../../tests/fixtures/imported-v0.json")).unwrap();
        let selected = super::local_quorum_bundle(work.path()).unwrap();
        assert_eq!(selected, imported);
        assert!(crate::quorum_legacy::load(&std::fs::read_to_string(selected).unwrap(), true, None).is_ok());
        assert_eq!(std::fs::read_to_string(source).unwrap(), "raw V0");
    }

    #[test]
    fn imported_bundle_encryption_requires_acceptance_and_preserves_recipient() {
        let work = tempdir().unwrap();
        let env = work.path().join(".env");
        let bundle = work.path().join("bundle.json");
        let output = work.path().join("secrets");
        let text = include_str!("../../../tests/fixtures/imported-v0.json");
        std::fs::write(&env, "SECRET=legacy-test\n").unwrap();
        std::fs::write(&bundle, text).unwrap();
        assert!(encrypt_env_file(&env, &bundle, &output, &[], false).is_err());
        assert!(!output.exists());
        assert_eq!(encrypt_env_file(&env, &bundle, &output, &[], true).unwrap(), 1);
        let legacy: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(super::parse_quorum_bundle_public_key(text, true).unwrap().0, legacy["original"]["public_key"].as_str().unwrap());
        assert!(output.join("SECRET.asc").exists());
    }

    #[test]
    fn destination_preflight_distinguishes_pcr_mismatch_from_invalid_evidence() {
        let proof = include_bytes!("../tests/data/aws-test.cbor").to_vec();
        let pcr01 = hex::decode("ef093e4c1fd13878956589833c0e396b935cdf5ae45c1cc595e1a19a6da5812850f0ef3e77df918cb2a86d88ddf9cc03").unwrap();
        let pcr2 = hex::decode("21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a").unwrap();
        let pcrs = std::collections::HashMap::from([(0, pcr01.clone()), (1, pcr01), (2, pcr2)]);
        let nonce = hex::decode("d041b23bce8678bbc7c174bd8494c4f9759386eec963ec69bfd45c1452b10636").unwrap();
        let now = std::time::Duration::from_millis(1766509563435);
        let address = "127.0.0.1:49504".parse().unwrap();
        assert!(super::verify_destination_attestation(address, proof.clone(), pcrs.clone(), &nonce, now).is_ok());
        for pcr in 0..=2 {
            let mut wrong = pcrs.clone();
            wrong.insert(pcr, vec![0xff; 48]);
            let error = super::verify_destination_attestation(address, proof.clone(), wrong, &nonce, now).unwrap_err();
            assert!(matches!(&error, super::SendShardError::DestinationPcrMismatch { pcr: name, .. } if name == &format!("pcr {pcr}")));
            let message = error.to_string();
            assert!(message.contains(".caution/trusted_hashes.json"));
            assert!(message.contains("No share was sent"));
            assert!(message.contains("caution verify"));
        }
        let wrong_nonce = super::verify_destination_attestation(address, proof, pcrs.clone(), &[1; 32], now).unwrap_err();
        assert!(matches!(wrong_nonce, super::SendShardError::DestinationVerification { .. }));
        let malformed = super::verify_destination_attestation(address, vec![0; 64], pcrs, &nonce, now).unwrap_err();
        assert!(matches!(malformed, super::SendShardError::DestinationVerification { .. }));
    }

    #[tokio::test]
    async fn destination_preflight_eof_is_not_ambiguous_share_acceptance() {
        use tokio::io::AsyncReadExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let receiver = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 4096];
            assert!(stream.read(&mut bytes).await.unwrap() > 0);
        });
        let error = super::preflight_destination(address, &Default::default()).await.unwrap_err();
        assert!(matches!(error, super::SendShardError::DestinationAttestation { .. }));
        assert!(error.to_string().contains("No share was sent"));
        receiver.await.unwrap();
    }

    #[test]
    fn share_results_distinguish_acceptance_from_reconstruction() {
        assert_eq!(super::share_acceptance_message(0), "Quorum reconstructed successfully.");
        assert_eq!(super::share_acceptance_message(1), "Share accepted. 1 more share required.");
        assert_eq!(super::share_acceptance_message(2), "Share accepted. 2 more shares required.");
        let io = std::io::Error::other("unexpected end of file");
        assert!(!super::connection_closed(&io), "do not classify errors by their text");
        let selected = super::SendShardError::SelectHolder {
            location: std::panic::Location::caller(), source: Box::new(io),
        };
        assert!(selected.to_string().contains("Unable to select share holder"));
        assert!(!selected.to_string().contains("parse bundle"));
    }

    #[tokio::test]
    async fn destination_eof_is_detected_through_real_locksmith_error_chain() {
        use tokio::io::AsyncReadExt;
        use keymaker_models::generate_quorum::{GenerateQuorumBundle, v1};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let receiver = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 4096];
            stream.read(&mut bytes).await.unwrap();
            // Close after the client's attestation request, before any share is sent.
        });
        let bundle = GenerateQuorumBundle::V1(v1::GenerateQuorumResponse {
            bundle_id: [0; 16], label: Default::default(), keyring: vec![],
            threshold: 1, max: 1, shardfile: String::new(), public_key: String::new(),
        });
        let error = locksmith::client::send_selected_shard(address, Default::default(), &bundle, None, None).await.unwrap_err();
        assert!(super::connection_closed(&error), "{error:?}");
        receiver.await.unwrap();
    }

    use super::openpgp;
    use super::{
        encrypt_env_file, encrypt_secret_value, keymaker_cert_eligibility, load_recipient_cert,
        parse_env_assignments, resolve_quorum_parameters,
    };
    use openpgp::cert::prelude::*;
    use openpgp::serialize::SerializeInto;
    use tempfile::tempdir;

    fn test_public_key() -> String {
        let (cert, _revocation) = CertBuilder::new()
            .add_userid("test@example.org")
            .add_storage_encryption_subkey()
            .generate()
            .unwrap();

        String::from_utf8(cert.armored().to_vec().unwrap()).unwrap()
    }

    #[test]
    fn parse_env_assignments_supports_export_and_matching_quotes() {
        let assignments = parse_env_assignments(
            "\
# comment\n\
export FOO=\"bar\"\n\
BAR='baz'\n\
EMPTY=\n\
INLINE=\"value # preserved\"\n\
BAD-KEY=no\n\
SPACED =no\n\
PADDED = \" spaced \" \n\
ESCAPED=\"say \\\"hi\\\"\"\n\
COMMENTED=\"bar\" # trailing comment\n\
export MISSING_EQUALS\n",
        );

        let pairs: Vec<_> = assignments
            .iter()
            .map(|assignment| (assignment.key.as_str(), assignment.value.as_str()))
            .collect();

        assert_eq!(
            pairs,
            vec![
                ("FOO", "bar"),
                ("BAR", "baz"),
                ("EMPTY", "''"),
                ("INLINE", "'value # preserved'"),
                ("SPACED", "no"),
                ("PADDED", "' spaced '"),
                ("ESCAPED", "'say \"hi\"'"),
                ("COMMENTED", "bar"),
            ]
        );
    }

    #[test]
    fn encrypt_secret_value_outputs_armored_pgp_message() {
        let public_key = test_public_key();
        let recipient = load_recipient_cert(&public_key).unwrap();
        let encrypted = encrypt_secret_value(&recipient, "super-secret", false).unwrap();

        assert!(encrypted.starts_with("-----BEGIN PGP MESSAGE-----"));
        assert!(encrypted.contains("-----END PGP MESSAGE-----"));
    }

    #[test]
    fn encrypt_env_file_rejects_unverified_bundle() {
        let work_dir = tempdir().unwrap();
        let caution_dir = work_dir.path().join(".caution");
        let env_file = work_dir.path().join(".env");
        let bundle_file = caution_dir.join("quorum-bundle.json");
        let secrets_dir = caution_dir.join("secrets");

        std::fs::create_dir_all(&caution_dir).unwrap();
        std::fs::write(
            &env_file,
            "\
FOO=bar\n\
EMPTY=\n\
export QUOTED=\"baz\"\n\
UNREQUESTED=nope\n",
        )
        .unwrap();

        std::fs::write(&bundle_file, r#"{"data":{},"necroproof":[]}"#).unwrap();
        assert!(
            encrypt_env_file(
                &env_file,
                &bundle_file,
                &secrets_dir,
                &["FOO".to_string(), "QUOTED".to_string()],
                false,
            )
            .is_err()
        );
        assert!(!secrets_dir.join("FOO.asc").exists());
    }

    #[test]
    fn resolve_quorum_parameters_infers_max_from_keyring() {
        assert_eq!(resolve_quorum_parameters(None, None, 10).unwrap(), (1, 10));
    }

    #[test]
    fn resolve_quorum_parameters_enforces_keymaker_holder_limit() {
        assert!(resolve_quorum_parameters(None, None, 0).is_err());
        assert_eq!(
            resolve_quorum_parameters(Some(254), None, 254).unwrap(),
            (254, 254)
        );
        for count in [255, 256] {
            let error = resolve_quorum_parameters(None, None, count).unwrap_err();
            assert!(matches!(
                error,
                super::ResolveQuorumParametersError::TooManyCerts { .. }
            ));
            assert!(error.to_string().contains("more than 254"));
        }
        assert!(resolve_quorum_parameters(Some(255), Some(255), 255).is_err());
    }

    #[test]
    fn resolve_quorum_parameters_rejects_mismatched_max() {
        let err = resolve_quorum_parameters(Some(2), Some(4), 10).unwrap_err();

        assert!(
            err.to_string().contains("--max (4) must match"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_quorum_parameters_rejects_threshold_above_max() {
        let err = resolve_quorum_parameters(Some(11), Some(10), 10).unwrap_err();

        assert!(
            err.to_string()
                .contains("--threshold must be between 1 and --max"),
            "unexpected error: {err}"
        );
    }

    fn cert_armor(builder: CertBuilder) -> String {
        let (cert, _revocation) = builder.generate().unwrap();
        String::from_utf8(cert.armored().to_vec().unwrap()).unwrap()
    }

    // A3: a cert carrying all three subkeys is Keymaker-eligible.
    #[test]
    fn cert_eligibility_accepts_full_cert() {
        let keyring = cert_armor(
            CertBuilder::new()
                .add_userid("alice@example.org")
                .add_signing_subkey()
                .add_authentication_subkey()
                .add_storage_encryption_subkey(),
        );

        let certs = keymaker_cert_eligibility(&keyring).unwrap();
        assert_eq!(certs.len(), 1);
        assert!(certs[0].is_eligible());
    }

    // A3: a default-style cert without an authentication subkey is ineligible.
    #[test]
    fn cert_eligibility_rejects_missing_authentication_subkey() {
        let keyring = cert_armor(
            CertBuilder::new()
                .add_userid("bob@example.org")
                .add_signing_subkey()
                .add_storage_encryption_subkey(),
        );

        let certs = keymaker_cert_eligibility(&keyring).unwrap();
        assert_eq!(certs.len(), 1);
        assert!(!certs[0].is_eligible());
    }
}
