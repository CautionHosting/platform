// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
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
    path::Path,
    time::{Duration, SystemTime},
};
use uuid::Uuid;
use webauthn_rs::prelude::SecurityKey;

#[path = "org_quorum/certificates.rs"]
mod certificates;
#[cfg(test)]
#[path = "org_quorum/tests.rs"]
mod tests;

#[derive(Debug, thiserror::Error, CtxError)]
#[error("{message} [{location:?}]")]
pub struct OrgQuorumError {
    status: StatusCode,
    message: &'static str,
    #[location]
    location: Location,
    #[source]
    source: Option<BoxError>,
}

impl OrgQuorumError {
    #[track_caller]
    pub(crate) fn new(status: StatusCode, message: &'static str) -> Self {
        Self {
            status,
            message,
            location: std::panic::Location::caller(),
            source: None,
        }
    }
    #[track_caller]
    fn invalid(message: &'static str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }
}

impl IntoResponse for OrgQuorumError {
    fn into_response(self) -> Response {
        tracing::warn!(error = %self, "quorum operation failed");
        (self.status, self.message).into_response()
    }
}
use OrgQuorumErrorCtx as Ctx;

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
}

pub async fn list_participants(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<OrgQuorumMember>, OrgQuorumError> {
    let users: Vec<(Uuid, String, i64)> = sqlx::query_as(
        "SELECT u.id, u.username, (SELECT count(*) FROM fido2_credentials f WHERE f.user_id = u.id)
         FROM organization_members om JOIN users u ON u.id = om.user_id
         WHERE om.organization_id = $1 AND u.is_active = true ORDER BY u.username, u.id",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await
    .with_context(Ctx::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "unable to list quorum participants",
    ))?;
    let mut members = Vec::with_capacity(users.len());
    for (user_id, username, webauthn_credentials) in users {
        let pgp_keys = sqlx::query_as(
            "SELECT id, fingerprint, public_key FROM pgp_keys
             WHERE user_id = $1 AND removed_at IS NULL ORDER BY fingerprint, id",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await
        .with_context(Ctx::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "unable to list participant PGP keys",
        ))?;
        members.push(OrgQuorumMember {
            user_id,
            username,
            pgp_keys,
            webauthn_credentials,
        });
    }
    Ok(members)
}

fn validate_request(request: &GenerateOrgQuorumBundleRequest) -> Result<(), OrgQuorumError> {
    let count = request.participants.len() + request.pgp_certificates.len();
    if count == 0 || count > 254 {
        return Err(OrgQuorumError::invalid(
            "select between 1 and 254 quorum holders",
        ));
    }
    if request.threshold == 0 || usize::from(request.threshold) > count {
        return Err(OrgQuorumError::invalid(
            "threshold must be between 1 and the holder count",
        ));
    }
    let mut seen = HashSet::new();
    for participant in &request.participants {
        if !seen.insert(participant.user_id) {
            return Err(OrgQuorumError::invalid("duplicate quorum participant"));
        }
        match participant.key_source {
            OrgQuorumKeySource::ExistingPgp if participant.pgp_key_id.is_none() => {
                return Err(OrgQuorumError::invalid(
                    "existing PGP holders require a PGP key ID",
                ));
            }
            OrgQuorumKeySource::CautionBackedPgp => {
                if !request.allow_caution_backed_keys || participant.pgp_key_id.is_some() {
                    return Err(OrgQuorumError::invalid(
                        "Caution-backed holders require explicit opt-in and no PGP key ID",
                    ));
                }
            }
            _ => {}
        }
    }
    if !request.labels.is_null() && !request.labels.is_object() {
        return Err(OrgQuorumError::invalid("labels must be an object"));
    }
    if let (Some(name), Some(label)) = (&request.name, request.labels.get("name")) {
        if label.as_str() != Some(name.as_str()) {
            return Err(OrgQuorumError::invalid("name and label 'name' must match"));
        }
    }
    Ok(())
}

fn eligible_certificate(armored: &str, at: Option<SystemTime>) -> Result<Cert, OrgQuorumError> {
    let mut parser =
        sequoia_openpgp::cert::CertParser::from_bytes(armored.as_bytes()).with_context(
            Ctx::new(StatusCode::BAD_REQUEST, "invalid OpenPGP certificate"),
        )?;
    let cert = parser
        .next()
        .ok_or_else(|| OrgQuorumError::invalid("missing OpenPGP certificate"))?
        .with_context(Ctx::new(
            StatusCode::BAD_REQUEST,
            "invalid OpenPGP certificate",
        ))?;
    if parser.next().is_some() {
        return Err(OrgQuorumError::invalid(
            "each holder must contain exactly one certificate",
        ));
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
        return Err(OrgQuorumError::invalid(
            "each holder needs a public certificate with signing, authentication and storage-encryption keys",
        ));
    }
    Ok(cert)
}

fn validate_keyring(keyring: &[Key], at: Option<SystemTime>) -> Result<(), OrgQuorumError> {
    let mut primary_keys = HashSet::new();
    let mut encryption_keys = HashSet::new();
    for key in keyring {
        let cert = eligible_certificate(
            match key {
                Key::OpenPGP { cert } | Key::WebAuthn { cert, .. } => cert,
            },
            at,
        )?;
        if !primary_keys.insert(cert.fingerprint()) {
            return Err(OrgQuorumError::invalid(
                "duplicate effective OpenPGP holder",
            ));
        }
        let mut policy = StandardPolicy::new();
        policy.good_critical_notations(&["organization-id@caution.co", "bundle-id@caution.co"]);
        for key in cert
            .keys()
            .with_policy(&policy, at)
            .supported()
            .revoked(false)
            .for_storage_encryption()
        {
            if !encryption_keys.insert(key.key().fingerprint()) {
                return Err(OrgQuorumError::invalid(
                    "holders must not share an encryption key",
                ));
            }
        }
    }
    Ok(())
}

fn credential_snapshot(rows: Vec<Vec<u8>>) -> Result<Vec<String>, OrgQuorumError> {
    if rows.is_empty() {
        return Err(OrgQuorumError::invalid(
            "Caution-backed holder has no registered WebAuthn credentials",
        ));
    }
    rows.into_iter()
        .map(|bytes| {
            let credential: SecurityKey = serde_json::from_slice(&bytes).with_context(Ctx::new(
                StatusCode::BAD_REQUEST,
                "invalid registered WebAuthn credential",
            ))?;
            serde_json::to_string(&credential).with_context(Ctx::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "unable to encode registered WebAuthn credential",
            ))
        })
        .collect()
}

enum Holder {
    Pgp(String),
    WebAuthn(Vec<String>),
}

async fn resolve_holders(
    pool: &PgPool,
    org_id: Uuid,
    request: &GenerateOrgQuorumBundleRequest,
) -> Result<Vec<Holder>, OrgQuorumError> {
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
        .with_context(Ctx::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "unable to verify organization membership",
        ))?;
        if !member {
            return Err(OrgQuorumError::invalid(
                "selected user is not an active organization member",
            ));
        }
        match participant.key_source {
            OrgQuorumKeySource::ExistingPgp => {
                let cert: Option<String> = sqlx::query_scalar(
                    "SELECT public_key FROM pgp_keys WHERE id = $1 AND user_id = $2 AND removed_at IS NULL")
                    .bind(participant.pgp_key_id).bind(participant.user_id).fetch_optional(pool).await
                    .with_context(Ctx::new(StatusCode::INTERNAL_SERVER_ERROR, "unable to load participant PGP key"))?;
                holders.push(Holder::Pgp(cert.ok_or_else(|| {
                    OrgQuorumError::invalid("PGP key does not belong to the selected user")
                })?));
            }
            OrgQuorumKeySource::CautionBackedPgp => {
                let rows = sqlx::query_scalar(
                    "SELECT public_key FROM fido2_credentials WHERE user_id = $1 ORDER BY credential_id")
                    .bind(participant.user_id).fetch_all(pool).await
                    .with_context(Ctx::new(StatusCode::INTERNAL_SERVER_ERROR, "unable to load holder credentials"))?;
                holders.push(Holder::WebAuthn(credential_snapshot(rows)?));
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
    validate_keyring(&external, None)?;
    Ok(holders)
}

fn configured(name: &str) -> Result<String, OrgQuorumError> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            OrgQuorumError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "required key-service endpoint or trust policy is not configured",
            )
        })
}

fn load_policy(path: &Path) -> Result<KeymakerPcrPolicy, OrgQuorumError> {
    let json = std::fs::read_to_string(path).with_context(Ctx::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "unable to read key-service PCR policy",
    ))?;
    let policy = KeymakerPcrPolicy::from_json(&json).with_context(Ctx::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "invalid key-service PCR policy",
    ))?;
    if policy.sets.is_empty()
        || policy.sets.iter().any(|set| {
            (0..=2).any(|index| {
                set.pcrs
                    .get(&index)
                    .is_none_or(|pcr| pcr.len() != 48 || pcr.iter().all(|b| *b == 0))
            })
        })
    {
        return Err(OrgQuorumError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "PCR policy must pin non-debug PCR0, PCR1 and PCR2",
        ));
    }
    Ok(policy)
}

async fn post<T: Serialize, R: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    body: &T,
) -> Result<R, OrgQuorumError> {
    let response = client
        .post(url)
        .json(body)
        .send()
        .await
        .map_err(|source| OrgQuorumError {
            status: if source.is_timeout() {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                StatusCode::BAD_GATEWAY
            },
            message: "key-service request failed; generation was not retried",
            location: std::panic::Location::caller(),
            source: Some(source.into()),
        })?;
    if !response.status().is_success() {
        let status = match response.status().as_u16() {
            429 => StatusCode::TOO_MANY_REQUESTS,
            503 => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::BAD_GATEWAY,
        };
        return Err(OrgQuorumError::new(
            status,
            "key service is busy or unavailable; generation was not retried",
        ));
    }
    response.json().await.map_err(|source| OrgQuorumError {
        status: if source.is_timeout() {
            StatusCode::GATEWAY_TIMEOUT
        } else {
            StatusCode::BAD_GATEWAY
        },
        message: "invalid or timed-out key-service response; generation was not retried",
        location: std::panic::Location::caller(),
        source: Some(source.into()),
    })
}

fn assemble_request(
    request: &GenerateOrgQuorumBundleRequest,
    bundle_id: [u8; 16],
    holders: Vec<Holder>,
    certificates: Vec<String>,
) -> Result<GenerateQuorumRequest, OrgQuorumError> {
    let mut derived = certificates.into_iter();
    let mut keyring = Vec::with_capacity(holders.len());
    for holder in holders {
        keyring.push(match holder {
            Holder::Pgp(cert) => Key::OpenPGP { cert },
            Holder::WebAuthn(credential) => Key::WebAuthn {
                credential,
                cert: derived.next().ok_or_else(|| {
                    OrgQuorumError::new(
                        StatusCode::BAD_GATEWAY,
                        "missing derived holder certificate",
                    )
                })?,
            },
        });
    }
    if derived.next().is_some() {
        return Err(OrgQuorumError::new(
            StatusCode::BAD_GATEWAY,
            "unexpected derived holder certificate",
        ));
    }
    validate_keyring(&keyring, None)?;
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

fn check_response(
    request: &GenerateQuorumRequest,
    response: &GenerateQuorumResponse,
) -> Result<(), OrgQuorumError> {
    let request = request.clone().to_latest();
    let bundle = response.data.clone().to_latest();
    if bundle.threshold != request.threshold
        || bundle.max != request.max
        || bundle.bundle_id != request.bundle_id
        || bundle.keyring != request.keyring
        || bundle.label != request.label
    {
        return Err(OrgQuorumError::new(
            StatusCode::BAD_GATEWAY,
            "Keymaker response does not match the requested quorum",
        ));
    }
    Cert::from_bytes(bundle.public_key.as_bytes()).with_context(Ctx::new(
        StatusCode::BAD_GATEWAY,
        "invalid quorum public key",
    ))?;
    if bundle.shardfile.is_empty() {
        return Err(OrgQuorumError::new(
            StatusCode::BAD_GATEWAY,
            "empty quorum shardfile",
        ));
    }
    Ok(())
}

pub async fn generate_org_quorum_bundle(
    pool: &PgPool,
    org_id: Uuid,
    created_by: Uuid,
    request: GenerateOrgQuorumBundleRequest,
) -> Result<crate::cryptographic_bundles::QuorumBundle, OrgQuorumError> {
    validate_request(&request)?;
    let holders = resolve_holders(pool, org_id, &request).await?;
    let keymaker_url = configured("KEYMAKER_URL")?;
    let policy_path = configured("KEYMAKER_PCR_POLICY_PATH")?;
    let policy = load_policy(Path::new(&policy_path))?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .with_context(Ctx::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "unable to create key-service client",
        ))?;
    let count = holders
        .iter()
        .filter(|h| matches!(h, Holder::WebAuthn(_)))
        .count();
    let (bundle_id, certs) = if let Some(count) = std::num::NonZeroU8::new(count as u8) {
        certificates::derive(&client, org_id, count).await?
    } else {
        (*Uuid::new_v4().as_bytes(), Vec::new())
    };
    let keymaker_request = assemble_request(&request, bundle_id, holders, certs)?;
    let response: GenerateQuorumResponse = post(
        &client,
        &[keymaker_url.trim_end_matches('/'), "/generate_quorum"].concat(),
        &keymaker_request,
    )
    .await?;
    locksmith::bundle::load_response(response.clone(), &policy).with_context(Ctx::new(
        StatusCode::BAD_GATEWAY,
        "Keymaker proof verification failed",
    ))?;
    check_response(&keymaker_request, &response)?;
    let data = serde_json::to_value(response).with_context(Ctx::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "unable to encode quorum bundle",
    ))?;
    crate::cryptographic_bundles::create_quorum_bundle(
        pool,
        org_id,
        created_by,
        crate::cryptographic_bundles::CreateBundleRequest {
            data,
            name: request.name,
            labels: (!request.labels.is_null()).then_some(request.labels),
        },
    )
    .await
    .map_err(|_| {
        OrgQuorumError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "unable to store verified quorum bundle",
        )
    })
}

/// Uploads must preserve and verify the same envelope as hosted generation.
pub(crate) fn verify_upload(data: &serde_json::Value) -> Result<(), OrgQuorumError> {
    let response: GenerateQuorumResponse = serde_json::from_value(data.clone()).with_context(
        Ctx::new(StatusCode::BAD_REQUEST, "expected proofed v1 quorum bundle"),
    )?;
    let policy = load_policy(Path::new(&configured("KEYMAKER_PCR_POLICY_PATH")?))?;
    let (bundle, at) = locksmith::bundle::load_response_with_timestamp(response, &policy)
        .with_context(Ctx::new(
            StatusCode::BAD_REQUEST,
            "uploaded quorum proof verification failed",
        ))?;
    let bundle = bundle.to_latest();
    if bundle.keyring.is_empty() || bundle.keyring.len() > 254 || bundle.shardfile.is_empty() {
        return Err(OrgQuorumError::invalid("invalid uploaded quorum"));
    }
    // Only the explicitly gated synthetic test proof has no authenticated time.
    validate_keyring(&bundle.keyring, at)?;
    Cert::from_bytes(bundle.public_key.as_bytes()).with_context(Ctx::new(
        StatusCode::BAD_REQUEST,
        "invalid quorum public key",
    ))?;
    Ok(())
}
