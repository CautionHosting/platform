// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial

use dterror::{BoxError, CtxError, Location, ResultExt};
use keymaker_models::generate_quorum::{
    GenerateQuorumRequest, GenerateQuorumResponse,
    v1::{self, Key},
};
use locksmith::bundle::KeymakerPcrPolicy;
use sequoia_openpgp::{Cert, parse::Parse, policy::StandardPolicy};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};
use uuid::Uuid;
use webauthn_rs::prelude::SecurityKey;

#[path = "certificates.rs"]
mod certificates;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;

pub(crate) mod handlers;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OrgQuorumKeySource {
    ExistingPgp,
    CautionBackedPgp,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OrgQuorumParticipantSelection {
    pub user_id: Uuid,
    pub key_source: OrgQuorumKeySource,
    pub pgp_key_id: Option<Uuid>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerateOrgQuorumBundleRequest {
    pub name: Option<String>,
    pub threshold: u8,
    #[serde(default)]
    pub participants: Vec<OrgQuorumParticipantSelection>,
    #[serde(default)]
    pub pgp_certificates: Vec<String>,
    #[serde(default)]
    pub allow_caution_backed_keys: bool,
    #[serde(default)]
    pub labels: serde_json::Value,
    /// The client's trusted Keymaker policy. It can only reject a proof, never accept one,
    /// so a bundle the client would refuse is not stored.
    #[serde(default)]
    pub keymaker_pcr_policy: Option<serde_json::Value>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct RegisteredPgpKey {
    pub id: Uuid,
    pub fingerprint: String,
    pub public_key: String,
}
#[derive(Serialize)]
pub struct OrgQuorumMember {
    pub user_id: Uuid,
    pub username: String,
    pub pgp_keys: Vec<RegisteredPgpKey>,
    pub webauthn_credentials: i64,
    pub webauthn_uv_credentials: i64,
}

/// Failure modes for [`list_participants`]: one variant per fallible query.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ListParticipantsError {
    #[error("unable to list organization members for organization {org_id} [{location}]")]
    Members {
        org_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("unable to list PGP keys for user {user_id} [{location}]")]
    PgpKeys {
        org_id: Uuid,
        user_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, fields(org_id = %org_id))]
pub async fn list_participants(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<OrgQuorumMember>, ListParticipantsError> {
    use ListParticipantsErrorCtx as Ctx;

    let users: Vec<(Uuid, String, i64, i64)> = sqlx::query_as(
        "SELECT u.id, u.username, (SELECT count(*) FROM fido2_credentials f WHERE f.user_id = u.id),
         (SELECT count(*) FROM fido2_credentials f WHERE f.user_id = u.id AND f.uv_verified)
         FROM organization_members om JOIN users u ON u.id = om.user_id
         WHERE om.organization_id = $1 AND u.is_active = true ORDER BY u.username, u.id",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await
    .with_context(Ctx::members(org_id))?;
    let mut members = Vec::with_capacity(users.len());
    for (user_id, username, webauthn_credentials, webauthn_uv_credentials) in users {
        let pgp_keys = sqlx::query_as(
            "SELECT id, fingerprint, public_key FROM pgp_keys
             WHERE user_id = $1 AND removed_at IS NULL ORDER BY fingerprint, id",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await
        .with_context(Ctx::pgp_keys(org_id, user_id))?;
        members.push(OrgQuorumMember {
            user_id,
            username,
            pgp_keys,
            webauthn_credentials,
            webauthn_uv_credentials,
        });
    }
    Ok(members)
}

/// Failure modes for [`validate_request`]: one variant per rejected condition.
/// Source-less (leaf error), so it derives plain `thiserror` without a `Ctx` twin.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ValidateRequestError {
    #[error("select between 1 and 254 quorum holders [{location}]")]
    HolderCount { location: Location },
    #[error("threshold must be between 1 and the holder count [{location}]")]
    Threshold { location: Location },
    #[error("duplicate quorum participant {user_id} [{location}]")]
    DuplicateParticipant { user_id: Uuid, location: Location },
    #[error("existing PGP holders require a PGP key ID [{location}]")]
    MissingPgpKeyId { user_id: Uuid, location: Location },
    #[error("Caution-backed holders require explicit opt-in and no PGP key ID [{location}]")]
    CautionBackedOptIn { user_id: Uuid, location: Location },
    #[error("labels must be an object [{location}]")]
    LabelsNotObject { location: Location },
    #[error("name and label 'name' must match [{location}]")]
    NameMismatch { location: Location },
}

fn validate_request(request: &GenerateOrgQuorumBundleRequest) -> Result<(), ValidateRequestError> {
    let count = request.participants.len() + request.pgp_certificates.len();
    if count == 0 || count > 254 {
        return Err(ValidateRequestError::HolderCount {
            location: std::panic::Location::caller(),
        });
    }
    if request.threshold == 0 || usize::from(request.threshold) > count {
        return Err(ValidateRequestError::Threshold {
            location: std::panic::Location::caller(),
        });
    }
    let mut seen = HashSet::new();
    for participant in &request.participants {
        if !seen.insert(participant.user_id) {
            return Err(ValidateRequestError::DuplicateParticipant {
                user_id: participant.user_id,
                location: std::panic::Location::caller(),
            });
        }
        match participant.key_source {
            OrgQuorumKeySource::ExistingPgp if participant.pgp_key_id.is_none() => {
                return Err(ValidateRequestError::MissingPgpKeyId {
                    user_id: participant.user_id,
                    location: std::panic::Location::caller(),
                });
            }
            OrgQuorumKeySource::CautionBackedPgp
                if !request.allow_caution_backed_keys || participant.pgp_key_id.is_some() =>
            {
                return Err(ValidateRequestError::CautionBackedOptIn {
                    user_id: participant.user_id,
                    location: std::panic::Location::caller(),
                });
            }
            _ => {}
        }
    }
    if !request.labels.is_null() && !request.labels.is_object() {
        return Err(ValidateRequestError::LabelsNotObject {
            location: std::panic::Location::caller(),
        });
    }
    if let (Some(name), Some(label)) = (&request.name, request.labels.get("name"))
        && label.as_str() != Some(name.as_str())
    {
        return Err(ValidateRequestError::NameMismatch {
            location: std::panic::Location::caller(),
        });
    }
    Ok(())
}

/// Failure modes for [`eligible_certificate`]: one variant per rejected input.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum EligibleCertificateError {
    #[error("invalid OpenPGP certificate [{location}]")]
    Parser {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("invalid OpenPGP certificate [{location}]")]
    Parse {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("missing OpenPGP certificate [{location}]")]
    Missing { location: Location },
    #[error("each holder must contain exactly one certificate [{location}]")]
    Multiple { location: Location },
    #[error(
        "each holder needs a public certificate with signing, authentication and storage-encryption keys [{location}]"
    )]
    Ineligible { location: Location },
}

fn eligible_certificate(
    armored: &str,
    at: Option<SystemTime>,
) -> Result<Cert, EligibleCertificateError> {
    use EligibleCertificateErrorCtx as Ctx;

    let mut parser = sequoia_openpgp::cert::CertParser::from_bytes(armored.as_bytes())
        .with_context(Ctx::parser())?;
    let cert = parser
        .next()
        .ok_or_else(|| EligibleCertificateError::Missing {
            location: std::panic::Location::caller(),
        })?
        .with_context(Ctx::parse())?;
    if parser.next().is_some() {
        return Err(EligibleCertificateError::Multiple {
            location: std::panic::Location::caller(),
        });
    }
    let mut policy = StandardPolicy::new();
    policy.good_critical_notations(&["organization-id@caution.co", "bundle-id@caution.co"]);
    let keys = || {
        cert.keys()
            .with_policy(&policy, at)
            .supported()
            .alive()
            .revoked(false)
    };
    if cert.is_tsk()
        || keys().for_signing().next().is_none()
        || keys().for_authentication().next().is_none()
        || keys().for_storage_encryption().next().is_none()
    {
        return Err(EligibleCertificateError::Ineligible {
            location: std::panic::Location::caller(),
        });
    }
    Ok(cert)
}

/// Failure modes for [`validate_keyring`]: one variant per rejected keyring.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ValidateKeyringError {
    #[error("ineligible holder certificate [{location}]")]
    Certificate {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("duplicate effective OpenPGP holder [{location}]")]
    DuplicateHolder { location: Location },
    #[error("holders must not share an encryption key [{location}]")]
    SharedEncryptionKey { location: Location },
}

fn validate_keyring(keyring: &[Key], at: Option<SystemTime>) -> Result<(), ValidateKeyringError> {
    use ValidateKeyringErrorCtx as Ctx;

    let mut primary_keys = HashSet::new();
    let mut encryption_keys = HashSet::new();
    for key in keyring {
        let cert = eligible_certificate(
            match key {
                Key::OpenPGP { cert } | Key::WebAuthn { cert, .. } => cert,
            },
            at,
        )
        .with_context(Ctx::certificate())?;
        if !primary_keys.insert(cert.fingerprint()) {
            return Err(ValidateKeyringError::DuplicateHolder {
                location: std::panic::Location::caller(),
            });
        }
        let mut policy = StandardPolicy::new();
        policy.good_critical_notations(&["organization-id@caution.co", "bundle-id@caution.co"]);
        let mut holder_encryption_keys = HashSet::new();
        for key in cert
            .keys()
            .with_policy(&policy, at)
            .supported()
            .revoked(false)
            .for_storage_encryption()
        {
            // Fingerprints include creation time, so compare the key material itself.
            // KDF parameters do not change the private scalar that can decrypt.
            let mut identity = key.key().mpis().clone();
            if let sequoia_openpgp::crypto::mpi::PublicKey::ECDH { hash, sym, .. } = &mut identity {
                *hash = sequoia_openpgp::types::HashAlgorithm::SHA256;
                *sym = sequoia_openpgp::types::SymmetricAlgorithm::AES256;
            }
            holder_encryption_keys.insert(identity);
        }
        for identity in holder_encryption_keys {
            if !encryption_keys.insert(identity) {
                return Err(ValidateKeyringError::SharedEncryptionKey {
                    location: std::panic::Location::caller(),
                });
            }
        }
    }
    Ok(())
}

// Must match Locksmith Authorizer::begin; count every credential, never truncate.
const MAX_HOLDER_CREDENTIALS: usize = 64;

/// Failure modes for [`credential_snapshot`]: one variant per rejected snapshot.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum CredentialSnapshotError {
    #[error("Caution-backed holder has no registered WebAuthn credentials [{location}]")]
    Empty { location: Location },
    #[error(
        "Caution-backed holder has {count} credentials; reduce to 64 or fewer before generation [{location}]"
    )]
    TooMany { count: usize, location: Location },
    #[error(
        "Caution-backed holder must verify a passkey with PIN/biometrics in Dashboard Authentication before generation, or use external PGP [{location}]"
    )]
    Unverified { location: Location },
    #[error("invalid registered WebAuthn credential [{location}]")]
    Decode {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("unable to encode registered WebAuthn credential [{location}]")]
    Encode {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

fn credential_snapshot(rows: Vec<(Vec<u8>, bool)>) -> Result<Vec<String>, CredentialSnapshotError> {
    use CredentialSnapshotErrorCtx as Ctx;

    if rows.is_empty() {
        return Err(CredentialSnapshotError::Empty {
            location: std::panic::Location::caller(),
        });
    }
    if rows.len() > MAX_HOLDER_CREDENTIALS {
        return Err(CredentialSnapshotError::TooMany {
            count: rows.len(),
            location: std::panic::Location::caller(),
        });
    }
    if !rows.iter().any(|(_, verified)| *verified) {
        return Err(CredentialSnapshotError::Unverified {
            location: std::panic::Location::caller(),
        });
    }
    rows.into_iter()
        .map(|(bytes, _)| {
            let credential: SecurityKey =
                serde_json::from_slice(&bytes).with_context(Ctx::decode())?;
            serde_json::to_string(&credential).with_context(Ctx::encode())
        })
        .collect()
}

enum Holder {
    Pgp(String),
    WebAuthn(Vec<String>),
}

/// Failure modes for [`resolve_holders`]: one variant per fallible branch.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ResolveHoldersError {
    #[error("unable to verify organization membership for user {user_id} [{location}]")]
    MembershipQuery {
        org_id: Uuid,
        user_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("selected user {user_id} is not an active organization member [{location}]")]
    NotMember {
        org_id: Uuid,
        user_id: Uuid,
        location: Location,
    },
    #[error("unable to load PGP key for user {user_id} [{location}]")]
    PgpKeyQuery {
        org_id: Uuid,
        user_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("PGP key does not belong to the selected user {user_id} [{location}]")]
    PgpKeyMissing {
        org_id: Uuid,
        user_id: Uuid,
        location: Location,
    },
    #[error("unable to load holder credentials for user {user_id} [{location}]")]
    CredentialsQuery {
        org_id: Uuid,
        user_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("invalid holder credentials for user {user_id} [{location}]")]
    Credentials {
        org_id: Uuid,
        user_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("invalid external holder keyring [{location}]")]
    Keyring {
        org_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, fields(org_id = %org_id))]
async fn resolve_holders(
    pool: &PgPool,
    org_id: Uuid,
    request: &GenerateOrgQuorumBundleRequest,
) -> Result<Vec<Holder>, ResolveHoldersError> {
    use ResolveHoldersErrorCtx as Ctx;

    let mut holders: Vec<_> = request
        .pgp_certificates
        .iter()
        .cloned()
        .map(Holder::Pgp)
        .collect();
    for participant in &request.participants {
        let member: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM organization_members om JOIN users u ON u.id = om.user_id
             WHERE om.organization_id = $1 AND u.id = $2 AND u.is_active = true)",
        )
        .bind(org_id)
        .bind(participant.user_id)
        .fetch_one(pool)
        .await
        .with_context(Ctx::membership_query(org_id, participant.user_id))?;
        if !member {
            return Err(ResolveHoldersError::NotMember {
                org_id,
                user_id: participant.user_id,
                location: std::panic::Location::caller(),
            });
        }
        match participant.key_source {
            OrgQuorumKeySource::ExistingPgp => {
                let cert: Option<String> = sqlx::query_scalar(
                    "SELECT public_key FROM pgp_keys WHERE id = $1 AND user_id = $2 AND removed_at IS NULL")
                    .bind(participant.pgp_key_id).bind(participant.user_id).fetch_optional(pool).await
                    .with_context(Ctx::pgp_key_query(org_id, participant.user_id))?;
                holders.push(Holder::Pgp(cert.ok_or_else(|| {
                    ResolveHoldersError::PgpKeyMissing {
                        org_id,
                        user_id: participant.user_id,
                        location: std::panic::Location::caller(),
                    }
                })?));
            }
            OrgQuorumKeySource::CautionBackedPgp => {
                let rows = sqlx::query_as(
                    "SELECT public_key, uv_verified FROM fido2_credentials WHERE user_id = $1 ORDER BY credential_id")
                    .bind(participant.user_id).fetch_all(pool).await
                    .with_context(Ctx::credentials_query(org_id, participant.user_id))?;
                holders
                    .push(Holder::WebAuthn(credential_snapshot(rows).with_context(
                        Ctx::credentials(org_id, participant.user_id),
                    )?));
            }
        }
    }
    // Reject invalid external keys before requesting derived certificates.
    let external: Vec<_> = holders
        .iter()
        .filter_map(|holder| match holder {
            Holder::Pgp(cert) => Some(Key::OpenPGP { cert: cert.clone() }),
            _ => None,
        })
        .collect();
    validate_keyring(&external, None).with_context(Ctx::keyring(org_id))?;
    Ok(holders)
}

/// Failure modes for [`configured`]: the required variable is unset or blank.
/// Source-less (leaf error), so it derives plain `thiserror` without a `Ctx` twin.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ConfiguredError {
    #[error("required configuration '{name}' is missing or empty [{location}]")]
    Missing { name: String, location: Location },
}

fn configured(name: &str) -> Result<String, ConfiguredError> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ConfiguredError::Missing {
            name: name.to_owned(),
            location: std::panic::Location::caller(),
        })
}

/// Failure modes for [`load_policy`]: one variant per rejected policy input.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum LoadPolicyError {
    #[error("unable to read key-service PCR policy '{path}' [{location}]")]
    Read {
        #[context(borrow = Path)]
        path: PathBuf,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("invalid key-service PCR policy '{path}' [{location}]")]
    Parse {
        #[context(borrow = Path)]
        path: PathBuf,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("key-service PCR policy '{path}' must pin non-debug PCR0, PCR1 and PCR2 [{location}]")]
    Unpinned {
        #[context(borrow = Path)]
        path: PathBuf,
        location: Location,
    },
}

fn load_policy(path: &Path) -> Result<KeymakerPcrPolicy, LoadPolicyError> {
    use LoadPolicyErrorCtx as Ctx;

    let json = std::fs::read_to_string(path).with_context(Ctx::read(path))?;
    let policy = KeymakerPcrPolicy::from_json(&json).with_context(Ctx::parse(path))?;
    if !pins_release_pcrs(&policy) {
        return Err(LoadPolicyError::Unpinned {
            path: path.to_path_buf(),
            location: std::panic::Location::caller(),
        });
    }
    Ok(policy)
}

fn pins_release_pcrs(policy: &KeymakerPcrPolicy) -> bool {
    !policy.sets.is_empty()
        && policy.sets.iter().all(|set| {
            (0..=2).all(|index| {
                set.pcrs
                    .get(&index)
                    .is_some_and(|pcr| pcr.len() == 48 && pcr.iter().any(|b| *b != 0))
            })
        })
}

const MAX_CLIENT_POLICY_SETS: usize = 8;

/// Failure modes for [`client_policy`]: one variant per rejected policy input.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ClientPolicyError {
    #[error("invalid client Keymaker PCR policy [{location}]")]
    Parse {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("client Keymaker PCR policy must pin non-debug PCR0, PCR1 and PCR2 [{location}]")]
    Unpinned { location: Location },
    #[error("client Keymaker PCR policy must have between 1 and {max} unexpired sets [{location}]")]
    Sets { max: usize, location: Location },
}

fn client_policy(
    value: Option<&serde_json::Value>,
) -> Result<Option<KeymakerPcrPolicy>, ClientPolicyError> {
    use ClientPolicyErrorCtx as Ctx;

    let Some(value) = value else {
        return Ok(None);
    };
    let mut policy = KeymakerPcrPolicy::deserialize(value).with_context(Ctx::parse())?;
    if !pins_release_pcrs(&policy) {
        return Err(ClientPolicyError::Unpinned {
            location: std::panic::Location::caller(),
        });
    }
    // Each set repeats attestation verification. Expired sets cannot validate a fresh
    // generation, so drop them and bound the caller-controlled remainder.
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    policy.sets.retain(|set| {
        set.expires_at_unix_seconds
            .is_none_or(|expiry| expiry > now)
    });
    if policy.sets.is_empty() || policy.sets.len() > MAX_CLIENT_POLICY_SETS {
        return Err(ClientPolicyError::Sets {
            max: MAX_CLIENT_POLICY_SETS,
            location: std::panic::Location::caller(),
        });
    }
    Ok(Some(policy))
}

/// Failure modes for [`post`]: the key-service call failed.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum PostError {
    #[error("key-service request to {url} failed [{location}]")]
    Send {
        url: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

async fn post<T: Serialize, R: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    body: &T,
) -> Result<R, PostError> {
    use PostErrorCtx as Ctx;

    send(client.post(url).json(body))
        .await
        .with_context(Ctx::send(url))
}

/// Failure modes for [`send`]: one variant per request/response failure.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SendError {
    #[error("key-service request timed out [{location}]")]
    RequestTimeout {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("key-service request failed [{location}]")]
    Request {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("key service returned status {upstream_status} [{location}]")]
    Upstream {
        upstream_status: u16,
        location: Location,
    },
    #[error("key-service response timed out [{location}]")]
    ResponseTimeout {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("invalid key-service response [{location}]")]
    Response {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

async fn send<R: serde::de::DeserializeOwned>(
    request: reqwest::RequestBuilder,
) -> Result<R, SendError> {
    let response = match request.send().await {
        Ok(response) => response,
        Err(source) if source.is_timeout() => {
            return Err(SendError::RequestTimeout {
                location: std::panic::Location::caller(),
                source: Box::new(source),
            });
        }
        Err(source) => {
            return Err(SendError::Request {
                location: std::panic::Location::caller(),
                source: Box::new(source),
            });
        }
    };
    if !response.status().is_success() {
        return Err(SendError::Upstream {
            upstream_status: response.status().as_u16(),
            location: std::panic::Location::caller(),
        });
    }
    match response.json().await {
        Ok(value) => Ok(value),
        Err(source) if source.is_timeout() => Err(SendError::ResponseTimeout {
            location: std::panic::Location::caller(),
            source: Box::new(source),
        }),
        Err(source) => Err(SendError::Response {
            location: std::panic::Location::caller(),
            source: Box::new(source),
        }),
    }
}

/// Failure modes for [`assemble_request`]: one variant per rejected assembly.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum AssembleRequestError {
    #[error("missing derived holder certificate [{location}]")]
    MissingDerived { location: Location },
    #[error("unexpected derived holder certificate [{location}]")]
    UnexpectedDerived { location: Location },
    #[error("invalid holder keyring [{location}]")]
    Keyring {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

fn assemble_request(
    request: &GenerateOrgQuorumBundleRequest,
    bundle_id: [u8; 16],
    holders: Vec<Holder>,
    certificates: Vec<String>,
) -> Result<GenerateQuorumRequest, AssembleRequestError> {
    use AssembleRequestErrorCtx as Ctx;

    let mut derived = certificates.into_iter();
    let mut keyring = Vec::with_capacity(holders.len());
    for holder in holders {
        keyring.push(match holder {
            Holder::Pgp(cert) => Key::OpenPGP { cert },
            Holder::WebAuthn(credential) => Key::WebAuthn {
                credential,
                cert: derived
                    .next()
                    .ok_or_else(|| AssembleRequestError::MissingDerived {
                        location: std::panic::Location::caller(),
                    })?,
            },
        });
    }
    if derived.next().is_some() {
        return Err(AssembleRequestError::UnexpectedDerived {
            location: std::panic::Location::caller(),
        });
    }
    validate_keyring(&keyring, None).with_context(Ctx::keyring())?;
    let mut label = HashMap::new();
    if let Some(name) = &request.name {
        label.insert("name".to_owned(), name.clone());
    }
    if let Some(labels) = request.labels.as_object() {
        for (key, value) in labels {
            label.insert(
                key.clone(),
                value
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| value.to_string()),
            );
        }
    }
    Ok(GenerateQuorumRequest::V1(v1::GenerateQuorumRequest {
        bundle_id,
        label,
        threshold: request.threshold,
        max: keyring.len() as u8,
        keyring,
    }))
}

/// Failure modes for [`check_response`]: response fields that must match.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum CheckResponseError {
    #[error("Keymaker response does not match the requested quorum [{location}]")]
    Mismatch { location: Location },
    #[error("invalid quorum public key [{location}]")]
    PublicKey {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("empty quorum shardfile [{location}]")]
    EmptyShardfile { location: Location },
}

fn check_response(
    request: &GenerateQuorumRequest,
    response: &GenerateQuorumResponse,
) -> Result<(), CheckResponseError> {
    use CheckResponseErrorCtx as Ctx;

    let request = request.clone().to_latest();
    let bundle = response.data.clone().to_latest();
    if bundle.threshold != request.threshold
        || bundle.max != request.max
        || bundle.bundle_id != request.bundle_id
        || bundle.keyring != request.keyring
        || bundle.label != request.label
    {
        return Err(CheckResponseError::Mismatch {
            location: std::panic::Location::caller(),
        });
    }
    Cert::from_bytes(bundle.public_key.as_bytes()).with_context(Ctx::public_key())?;
    if bundle.shardfile.is_empty() {
        return Err(CheckResponseError::EmptyShardfile {
            location: std::panic::Location::caller(),
        });
    }
    Ok(())
}

/// Failure modes for [`generate_org_quorum_bundle`]: one variant per fallible branch.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GenerateOrgQuorumBundleError {
    #[error("invalid quorum request [{location}]")]
    ValidateRequest {
        org_id: Uuid,
        user_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("invalid client Keymaker policy [{location}]")]
    ClientPolicy {
        org_id: Uuid,
        user_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("unable to resolve quorum holders [{location}]")]
    ResolveHolders {
        org_id: Uuid,
        user_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("key-service endpoint is not configured [{location}]")]
    KeymakerUrl {
        org_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("key-service trust policy path is not configured [{location}]")]
    PolicyPath {
        org_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("unable to load the key-service PCR policy [{location}]")]
    LoadPolicy {
        org_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("unable to create the key-service client [{location}]")]
    ClientBuild {
        org_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("certificate issuance failed [{location}]")]
    Derive {
        org_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("unable to assemble the Keymaker request [{location}]")]
    AssembleRequest {
        org_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("Keymaker request failed [{location}]")]
    Post {
        org_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("Keymaker proof verification failed [{location}]")]
    VerifyProof {
        org_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("Keymaker response does not match the requested quorum [{location}]")]
    CheckResponse {
        org_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("Keymaker proof does not satisfy the client's trusted policy [{location}]")]
    ClientPolicyProof {
        org_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("unable to encode the quorum bundle [{location}]")]
    Encode {
        org_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("unable to store the verified quorum bundle [{location}]")]
    Store {
        org_id: Uuid,
        user_id: Uuid,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, fields(org_id = %org_id))]
pub async fn generate_org_quorum_bundle(
    pool: &PgPool,
    org_id: Uuid,
    created_by: Uuid,
    request: GenerateOrgQuorumBundleRequest,
) -> Result<crate::cryptographic_bundles::QuorumBundle, GenerateOrgQuorumBundleError> {
    use GenerateOrgQuorumBundleErrorCtx as Ctx;

    validate_request(&request).with_context(Ctx::validate_request(org_id, created_by))?;
    let client_policy = client_policy(request.keymaker_pcr_policy.as_ref())
        .with_context(Ctx::client_policy(org_id, created_by))?;
    let holders = resolve_holders(pool, org_id, &request)
        .await
        .with_context(Ctx::resolve_holders(org_id, created_by))?;
    let keymaker_url = configured("KEYMAKER_URL").with_context(Ctx::keymaker_url(org_id))?;
    let policy_path =
        configured("KEYMAKER_PCR_POLICY_PATH").with_context(Ctx::policy_path(org_id))?;
    let policy = load_policy(Path::new(&policy_path)).with_context(Ctx::load_policy(org_id))?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .with_context(Ctx::client_build(org_id))?;
    let count = holders
        .iter()
        .filter(|h| matches!(h, Holder::WebAuthn(_)))
        .count();
    let (bundle_id, certs) = if let Some(count) = std::num::NonZeroU8::new(count as u8) {
        certificates::derive(&client, org_id, count)
            .await
            .with_context(Ctx::derive(org_id))?
    } else {
        (*Uuid::new_v4().as_bytes(), Vec::new())
    };
    let keymaker_request = assemble_request(&request, bundle_id, holders, certs)
        .with_context(Ctx::assemble_request(org_id))?;
    let response: GenerateQuorumResponse = post(
        &client,
        &[keymaker_url.trim_end_matches('/'), "/generate_quorum"].concat(),
        &keymaker_request,
    )
    .await
    .with_context(Ctx::post(org_id))?;
    locksmith::bundle::load_response(response.clone(), &policy)
        .with_context(Ctx::verify_proof(org_id))?;
    check_response(&keymaker_request, &response).with_context(Ctx::check_response(org_id))?;
    if let Some(client_policy) = &client_policy {
        locksmith::bundle::load_response(response.clone(), client_policy)
            .with_context(Ctx::client_policy_proof(org_id))?;
    }
    let data = serde_json::to_value(response).with_context(Ctx::encode(org_id))?;
    crate::cryptographic_bundles::create_quorum_bundle(
        pool,
        org_id,
        created_by,
        crate::cryptographic_bundles::CreateBundleRequest {
            allow_legacy: false,
            data,
            name: request.name,
            labels: (!request.labels.is_null()).then_some(request.labels),
        },
    )
    .await
    .with_context(Ctx::store(org_id, created_by))
}

/// Failure modes for [`verify_upload`]: one variant per rejected upload.
#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum VerifyUploadError {
    #[error("legacy upload requires explicit allow_legacy: true [{location}]")]
    LegacyOptIn { location: Location },
    #[error("invalid imported legacy bundle (public validation only) [{location}]")]
    LegacyParse {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("expected proofed v1 quorum bundle [{location}]")]
    Parse {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("required key-service endpoint or trust policy is not configured [{location}]")]
    PolicyPath {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("invalid key-service PCR policy [{location}]")]
    Policy {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("uploaded quorum proof verification failed [{location}]")]
    Proof {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("invalid uploaded quorum [{location}]")]
    InvalidBundle { location: Location },
    #[error("invalid uploaded quorum keyring [{location}]")]
    Keyring {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("invalid quorum public key [{location}]")]
    PublicKey {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Verify V1 proofs or explicitly accepted legacy public structure.
pub(crate) fn verify_upload(
    data: &serde_json::Value,
    allow_legacy: bool,
) -> Result<(), VerifyUploadError> {
    use VerifyUploadErrorCtx as Ctx;

    if data.get("format").is_some() {
        if !allow_legacy {
            return Err(VerifyUploadError::LegacyOptIn {
                location: std::panic::Location::caller(),
            });
        }
        locksmith::legacy::ImportedV0::from_json(&data.to_string())
            .with_context(Ctx::legacy_parse())?;
        return Ok(());
    }
    let response: GenerateQuorumResponse =
        serde_json::from_value(data.clone()).with_context(Ctx::parse())?;
    let policy_path = configured("KEYMAKER_PCR_POLICY_PATH").with_context(Ctx::policy_path())?;
    let policy = load_policy(Path::new(&policy_path)).with_context(Ctx::policy())?;
    let (bundle, at) = locksmith::bundle::load_response_with_timestamp(response, &policy)
        .with_context(Ctx::proof())?;
    let bundle = bundle.to_latest();
    if bundle.keyring.is_empty() || bundle.keyring.len() > 254 || bundle.shardfile.is_empty() {
        return Err(VerifyUploadError::InvalidBundle {
            location: std::panic::Location::caller(),
        });
    }
    // Only the explicitly gated synthetic test proof has no authenticated time.
    validate_keyring(&bundle.keyring, at).with_context(Ctx::keyring())?;
    Cert::from_bytes(bundle.public_key.as_bytes()).with_context(Ctx::public_key())?;
    Ok(())
}
