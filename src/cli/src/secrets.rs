// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use dterror::{BoxError, CtxError, FromContext, Location, ResultExt};
use keymaker_models::generate_quorum::v0::GenerateQuorumResponse;
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
    #[error("Failed to parse quorum bundle JSON [{location:?}]")]
    ParseJson {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

fn parse_quorum_bundle_public_key(
    bundle_text: &str,
) -> Result<String, ParseQuorumBundlePublicKeyError> {
    use ParseQuorumBundlePublicKeyErrorCtx as Ctx;

    let bundle: GenerateQuorumResponse =
        serde_json::from_str(bundle_text).with_context(Ctx::parse_json())?;

    Ok(bundle.public_key)
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
) -> Result<String, EncryptSecretValueError> {
    use EncryptSecretValueErrorCtx as Ctx;

    let policy = &OpenPgpPolicy::new();
    let mut recipients: Vec<_> = recipient
        .keys()
        .with_policy(policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_storage_encryption()
        .collect();

    if recipients.is_empty() {
        recipients = recipient
            .keys()
            .with_policy(policy, None)
            .supported()
            .alive()
            .revoked(false)
            .for_transport_encryption()
            .collect();
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
    let public_key = parse_quorum_bundle_public_key(&bundle_text)
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

        let encrypted = encrypt_secret_value(&recipient, &assignment.value)
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

/// Keymaker-eligibility of a single certificate, with per-subkey detail so we can tell the
/// user exactly which subkey is missing instead of an opaque "no eligible certificates".
struct CertEligibility {
    user_id: String,
    has_sign: bool,
    has_auth: bool,
    has_enc: bool,
}

impl CertEligibility {
    fn is_eligible(&self) -> bool {
        self.has_sign && self.has_auth && self.has_enc
    }

    /// Human-readable list of the missing subkey roles, in keygen order.
    fn missing(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if !self.has_sign {
            missing.push("signing");
        }
        if !self.has_auth {
            missing.push("authentication");
        }
        if !self.has_enc {
            missing.push("storage-encryption");
        }
        missing
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
        let user_id = valid_cert
            .userids()
            .next()
            .map(|uid| String::from_utf8_lossy(uid.userid().value()).into_owned())
            .unwrap_or_else(|| valid_cert.fingerprint().to_string());

        certs.push(CertEligibility {
            user_id,
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
pub enum NormalizeKeyringError {
    #[error("Failed to parse keyring as OpenPGP public certificates [{location:?}]")]
    ParseKeyring {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to create armor writer [{location:?}]")]
    CreateWriter {
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

    #[error("Failed to serialize OpenPGP public certificate [{location:?}]")]
    SerializeCert {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to finalize armor [{location:?}]")]
    FinalizeArmor {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Normalized keyring is not valid UTF-8 [{location:?}]")]
    Utf8 {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

/// Re-serialize all certificates into a single ASCII-armored block.
///
/// Keyrings assembled by concatenating armored files (`cat alice.asc bob.asc`)
/// contain multiple armor blocks. Sequoia and GnuPG read all of them, but the
/// rpgp-based Locksmith/Keymaker stack only parses the first block and
/// silently drops the remaining certificates, which later breaks send-shard
/// for the dropped holders.
fn normalize_keyring(armored_keyring: &str) -> Result<String, NormalizeKeyringError> {
    use NormalizeKeyringErrorCtx as Ctx;

    let cert_parser = CertParser::from_bytes(armored_keyring).with_context(Ctx::parse_keyring())?;

    let mut writer = openpgp::armor::Writer::new(Vec::new(), openpgp::armor::Kind::PublicKey)
        .with_context(Ctx::create_writer())?;
    for parseable_cert in cert_parser {
        let cert = parseable_cert.with_context(Ctx::parse_cert())?;
        cert.serialize(&mut writer)
            .with_context(Ctx::serialize_cert())?;
    }
    let bytes = writer.finalize().with_context(Ctx::finalize_armor())?;

    String::from_utf8(bytes)
        .with_context(Ctx::utf8())
        .map(|mut keyring| {
            if !keyring.ends_with('\n') {
                keyring.push('\n');
            }
            keyring
        })
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
        "keyring contains more than 255 Keymaker-eligible public certificates (found {eligible_certs}) [{location:?}]"
    )]
    TooManyCerts {
        eligible_certs: usize,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
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

fn resolve_quorum_parameters(
    threshold: Option<u8>,
    max: Option<u8>,
    eligible_certs: usize,
) -> Result<(u8, u8), ResolveQuorumParametersError> {
    use ResolveQuorumParametersErrorCtx as Ctx;

    if eligible_certs == 0 {
        return Err(ResolveQuorumParametersError::NoEligibleCerts {
            location: std::panic::Location::caller(),
        });
    }

    let inferred_max =
        u8::try_from(eligible_certs).with_context(Ctx::too_many_certs(eligible_certs))?;
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
pub enum NewSecretError {
    #[error("KEYMAKER_URL environment variable is required [{location:?}]")]
    KeymakerUrlMissing {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to read keyring file: {keyring} [{location:?}]")]
    ReadKeyring {
        #[context(borrow = Path)]
        keyring: PathBuf,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to inspect keyring file: {keyring} [{location:?}]")]
    InspectKeyring {
        #[context(borrow = Path)]
        keyring: PathBuf,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error(
        "No Keymaker-eligible certificates in {keyring}. Fix: generate a compatible key with \
         `caution secret keygen` (non-prod), or derive one offline with keyfork: \
         https://git.distrust.co/public/keyfork [{location:?}]"
    )]
    NoEligibleCerts {
        keyring: PathBuf,

        #[location]
        location: Location,
    },

    #[error("Failed to resolve quorum parameters [{location:?}]")]
    ResolveQuorum {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to normalize keyring file: {keyring} [{location:?}]")]
    NormalizeKeyring {
        #[context(borrow = Path)]
        keyring: PathBuf,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to connect to Keymaker service [{location:?}]")]
    ConnectKeymaker {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to read Keymaker error response [{location:?}]")]
    ReadKeymakerErrorBody {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Keymaker error ({status}): {message} [{location:?}]")]
    KeymakerFailure {
        status: reqwest::StatusCode,

        message: String,

        #[location]
        location: Location,
    },

    #[error("Failed to parse Keymaker response [{location:?}]")]
    ParseKeymakerResponse {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to serialize quorum bundle [{location:?}]")]
    SerializeBundle {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to write secret to {secret_path} [{location:?}]")]
    WriteBundle {
        #[context(borrow = Path)]
        secret_path: PathBuf,

        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to write bundle to stdout [{location:?}]")]
    OutputData {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to authenticate with Caution [{location:?}]")]
    EnsureAuthenticated {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to upload quorum bundle to Caution [{location:?}]")]
    UploadBundle {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to parse upload response [{location:?}]")]
    ParseUploadResponse {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("Failed to store quorum bundle ({status}): {message} [{location:?}]")]
    StoreFailure {
        status: reqwest::StatusCode,

        message: String,

        #[location]
        location: Location,
    },
}

/// Generate a new cryptographic quorum from a Keymaker-compatible keyring.
pub async fn new(
    client: &ApiClient,
    keyring: PathBuf,
    threshold: Option<u8>,
    max: Option<u8>,
    upload: bool,
    name: Option<String>,
    labels: Vec<String>,
) -> Result<(), NewSecretError> {
    use NewSecretErrorCtx as Ctx;

    let keymaker_url = std::env::var("KEYMAKER_URL").with_context(Ctx::keymaker_url_missing())?;

    let keyring_data = fs::read_to_string(&keyring).with_context(Ctx::read_keyring(&keyring))?;

    let eligibility =
        keymaker_cert_eligibility(&keyring_data).with_context(Ctx::inspect_keyring(&keyring))?;
    let eligible_certs = eligibility.iter().filter(|cert| cert.is_eligible()).count();

    if eligible_certs == 0 {
        output::warning(
            "Keyring has no Keymaker-eligible certificates (each needs signing + \
             authentication + storage-encryption subkeys):",
        );
        if eligibility.is_empty() {
            output::warning("  (no certificates found in keyring)");
        }
        for cert in &eligibility {
            output::warning(format!(
                "  - {} — missing: {}",
                cert.user_id,
                cert.missing().join(", ")
            ));
        }
        return Err(NewSecretError::NoEligibleCerts {
            keyring,
            location: std::panic::Location::caller(),
        });
    }

    // Warn about any certs that lack required subkeys and will be silently excluded.
    let ineligible: Vec<&CertEligibility> = eligibility
        .iter()
        .filter(|cert| !cert.is_eligible())
        .collect();
    if !ineligible.is_empty() {
        output::warning(format!(
            "Warning: {} certificate(s) in the keyring lack required subkeys and will be \
             excluded from the quorum:",
            ineligible.len()
        ));
        for cert in ineligible {
            output::warning(format!(
                "  - {} — missing: {}",
                cert.user_id,
                cert.missing().join(", ")
            ));
        }
    }

    let (threshold, max) = resolve_quorum_parameters(threshold, max, eligible_certs)
        .with_context(Ctx::resolve_quorum())?;

    let keyring_data =
        normalize_keyring(&keyring_data).with_context(Ctx::normalize_keyring(&keyring))?;

    let request_body = serde_json::json!({
        "threshold": threshold,
        "max": max,
        "keyring": keyring_data,
        "label": {},
    });

    output::status(format!(
        "Generating quorum (threshold={}, max={})...",
        threshold, max
    ));

    let response = client
        .client
        .post(format!("{}/generate_quorum", keymaker_url))
        .json(&request_body)
        .send()
        .await
        .with_context(Ctx::connect_keymaker())?;

    if !response.status().is_success() {
        let status = response.status();
        let error = response
            .text()
            .await
            .with_context(Ctx::read_keymaker_error_body())?;
        return Err(NewSecretError::KeymakerFailure {
            status,
            message: error,
            location: std::panic::Location::caller(),
        });
    }

    let quorum_response: GenerateQuorumResponse = response
        .json()
        .await
        .with_context(Ctx::parse_keymaker_response())?;

    let json =
        serde_json::to_string_pretty(&quorum_response).with_context(Ctx::serialize_bundle())?;

    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdout());
    let in_caution_repo =
        PathBuf::from("Procfile").exists() || PathBuf::from(".caution/deployment.json").exists();

    // Always save to file when in a caution repo
    if in_caution_repo {
        let secret_path = PathBuf::from(".caution/quorum-bundle.json");
        fs::write(&secret_path, &json).with_context(Ctx::write_bundle(&secret_path))?;
        output::status(format!("Saved to: {}", secret_path.display()));
    }

    // When not uploading (no QR, not in caution repo), output to stdout
    if !client.qr && (!is_tty || !in_caution_repo) {
        if !in_caution_repo {
            output::warning("Warning: not in a Caution repository, outputting bundle to stdout");
        }
        output::data(&json).with_context(Ctx::output_data())?;
        return Ok(());
    }

    if upload || client.qr {
        if client.qr {
            output::status(
                "\nUploading public key material bundle to Caution via QR code signing...",
            );
        } else {
            output::status("\nTo back up public key material bundle to Caution, tap your key.");
        }
        if in_caution_repo {
            output::status(
                "The key material bundle is also accessible at .caution/quorum-bundle.json",
            );
        }
        output::status("Press Ctrl+C to cancel.");

        let config = client
            .ensure_authenticated()
            .await
            .with_context(Ctx::ensure_authenticated())?;

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

        let response = client
            .signed_post(&config.session_id, "/api/quorum-bundles", &upload_body)
            .await
            .with_context(Ctx::upload_bundle())?;

        if response.status().is_success() {
            let result: serde_json::Value = response
                .json()
                .await
                .with_context(Ctx::parse_upload_response())?;
            if let Some(id) = result.get("id") {
                output::success(format!(
                    "\nQuorum bundle stored successfully (bundle ID: {})",
                    id
                ));
            } else {
                output::success("\nQuorum bundle stored successfully.");
            }
        } else {
            let status = response.status();
            let error = client.api_error_message(response).await;
            return Err(NewSecretError::StoreFailure {
                status,
                message: error,
                location: std::panic::Location::caller(),
            });
        }
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
) -> Result<(), EncryptError> {
    use EncryptErrorCtx as Ctx;

    encrypt_env_file(&env_file, &bundle, &secrets_dir, &keys)
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
        .client
        .patch(format!("{}/api/quorum-bundles/{}", client.base_url, id))
        .header("X-Session-ID", &config.session_id)
        .json(&body)
        .send()
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
        .client
        .patch(format!("{}/api/quorum-bundles/{}", client.base_url, id))
        .header("X-Session-ID", &config.session_id)
        .json(&body)
        .send()
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
        .client
        .patch(format!("{}/api/quorum-bundles/{}", client.base_url, id))
        .header("X-Session-ID", &config.session_id)
        .json(&body)
        .send()
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

/// Send a shard to a running enclave's locksmith daemon.
pub async fn send_shard(
    client: &ApiClient,
    app: Option<String>,
    bundle_path: Option<PathBuf>,
    private_keyring: Option<PathBuf>,
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

    if let Some(verified_at) = hashes["verified_at"].as_str() {
        output::status(format!("Using trusted hashes from {}", verified_at));
    }

    // Parse the quorum bundle
    let bundle_text =
        fs::read_to_string(&bundle_file).with_context(Ctx::read_bundle_file(&bundle_file))?;
    let bundle: GenerateQuorumResponse =
        serde_json::from_str(&bundle_text).with_context(Ctx::parse_bundle())?;

    let address_str = format!("{}:49504", public_ip);
    output::status(format!("Sending shard to enclave at {}...", address_str));
    let address: std::net::SocketAddr = address_str
        .parse()
        .with_context(Ctx::invalid_address(&address_str))?;

    let status = locksmith::client::send_shard(address, pcrs, &bundle, private_keyring)
        .await
        .with_context(Ctx::send_shard(&address_str))?;

    match status {
        locksmith::models::SendSignedEncryptedShardResponse::Accepted { remaining } => {
            output::success(format!(
                "Shard accepted, {} remaining shards until reconstitution",
                remaining
            ));
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
    use super::openpgp;
    use super::{
        encrypt_env_file, encrypt_secret_value, keymaker_cert_eligibility, load_recipient_cert,
        normalize_keyring, parse_env_assignments, resolve_quorum_parameters,
    };
    use keymaker_models::generate_quorum::v0::GenerateQuorumResponse;
    use openpgp::cert::prelude::*;
    use openpgp::parse::Parse;
    use openpgp::serialize::SerializeInto;
    use std::collections::HashMap;
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
    fn normalize_keyring_merges_concatenated_armor_blocks() {
        // Simulate `cat alice.asc bob.asc > keyring.asc`
        let concatenated = format!("{}{}", test_public_key(), test_public_key());
        assert_eq!(concatenated.matches("BEGIN PGP").count(), 2);

        let normalized = normalize_keyring(&concatenated).unwrap();
        assert_eq!(normalized.matches("BEGIN PGP").count(), 1);

        // Both certificates survive normalization.
        let certs: Vec<_> = openpgp::cert::CertParser::from_bytes(normalized.as_bytes())
            .unwrap()
            .collect::<openpgp::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(certs.len(), 2);
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
        let encrypted = encrypt_secret_value(&recipient, "super-secret").unwrap();

        assert!(encrypted.starts_with("-----BEGIN PGP MESSAGE-----"));
        assert!(encrypted.contains("-----END PGP MESSAGE-----"));
    }

    #[test]
    fn encrypt_env_file_writes_requested_secret_files() {
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

        let bundle = GenerateQuorumResponse {
            label: HashMap::new(),
            keyring: String::new(),
            keyring_hash: Vec::new(),
            shardfile: String::new(),
            public_key: test_public_key(),
            necroproof: Vec::new(),
        };
        std::fs::write(&bundle_file, serde_json::to_string(&bundle).unwrap()).unwrap();

        let count = encrypt_env_file(
            &env_file,
            &bundle_file,
            &secrets_dir,
            &["FOO".to_string(), "QUOTED".to_string()],
        )
        .unwrap();

        assert_eq!(count, 2);
        assert!(
            std::fs::read_to_string(secrets_dir.join("FOO.asc"))
                .unwrap()
                .starts_with("-----BEGIN PGP MESSAGE-----")
        );
        assert!(
            std::fs::read_to_string(secrets_dir.join("QUOTED.asc"))
                .unwrap()
                .starts_with("-----BEGIN PGP MESSAGE-----")
        );
        assert!(!secrets_dir.join("EMPTY.asc").exists());
        assert!(!secrets_dir.join("UNREQUESTED.asc").exists());
    }

    #[test]
    fn resolve_quorum_parameters_infers_max_from_keyring() {
        assert_eq!(resolve_quorum_parameters(None, None, 10).unwrap(), (1, 10));
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
        assert!(certs[0].missing().is_empty());
        assert_eq!(certs[0].user_id, "alice@example.org");
    }

    // A3: a default-style cert without an authentication subkey is reported as ineligible,
    // naming exactly the missing role.
    #[test]
    fn cert_eligibility_reports_missing_authentication_subkey() {
        let keyring = cert_armor(
            CertBuilder::new()
                .add_userid("bob@example.org")
                .add_signing_subkey()
                .add_storage_encryption_subkey(),
        );

        let certs = keymaker_cert_eligibility(&keyring).unwrap();
        assert_eq!(certs.len(), 1);
        assert!(!certs[0].is_eligible());
        assert_eq!(certs[0].missing(), vec!["authentication"]);
    }
}
