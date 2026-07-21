// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial

use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::{HashMap, HashSet};
use std::env;
use uuid::Uuid;


#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Proofed<T> {
    data: T,
    necroproof: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "version")]
enum PublicCertificateBundle {
    V1(PublicCertificateBundleV1),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicCertificateBundleV1 {
    organization_id: [u8; 16],
    bundle_id: [u8; 16],
    certificates: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "version")]
enum PublicCertificateRequest {
    V1(PublicCertificateRequestV1),
}

#[derive(Clone, Debug, Serialize)]
struct PublicCertificateRequestV1 {
    organization_id: [u8; 16],
    certificate_count: u8,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "version")]
enum GenerateQuorumBundle {
    V1(GenerateQuorumBundleV1),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GenerateQuorumBundleV1 {
    bundle_id: [u8; 16],
    label: HashMap<String, String>,
    keyring: Vec<KeymakerKey>,
    shardfile: String,
    public_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "version")]
enum GenerateQuorumRequest {
    V1(GenerateQuorumRequestV1),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GenerateQuorumRequestV1 {
    bundle_id: [u8; 16],
    label: HashMap<String, String>,
    threshold: u8,
    max: u8,
    keyring: Vec<KeymakerKey>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum KeymakerKey {
    OpenPGP { cert: String },
}

type PublicCertificateResponse = Proofed<PublicCertificateBundle>;
type GenerateQuorumResponse = Proofed<GenerateQuorumBundle>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrgQuorumKeySource {
    ExistingPgp,
    CautionBackedPgp,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OrgQuorumParticipantSelection {
    pub user_id: Uuid,
    pub key_source: OrgQuorumKeySource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pgp_key_id: Option<Uuid>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GenerateOrgQuorumBundleRequest {
    pub name: Option<String>,
    #[serde(default)]
    pub threshold: u8,
    pub participants: Vec<OrgQuorumParticipantSelection>,
    #[serde(default)]
    pub allow_caution_backed_keys: bool,
    #[serde(default)]
    pub labels: serde_json::Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidateOrgQuorumRequestError {
    EmptyParticipants,
    ThresholdIsZero,
    ThresholdExceedsParticipants { threshold: u8, participants: usize },
    DuplicateParticipant { user_id: Uuid },
    CautionBackedKeysRequireExplicitOptIn { user_id: Uuid },
    ExistingPgpSelectionRequiresPgpKeyId { user_id: Uuid },
    CautionBackedSelectionMustNotSetPgpKeyId { user_id: Uuid },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyServiceEndpoints {
    pub keymaker_url: String,
    pub public_certificate_url: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyServiceEndpointConfigError {
    MissingKeymakerUrl,
    MissingPublicCertificateUrl,
}

pub fn key_service_endpoints_from_lookup(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<KeyServiceEndpoints, KeyServiceEndpointConfigError> {
    let keymaker_url = lookup("KEYMAKER_URL")
        .filter(|value| !value.trim().is_empty())
        .ok_or(KeyServiceEndpointConfigError::MissingKeymakerUrl)?;
    let public_certificate_url = lookup("PUBLIC_CERTIFICATE_SERVICE_URL")
        .filter(|value| !value.trim().is_empty())
        .ok_or(KeyServiceEndpointConfigError::MissingPublicCertificateUrl)?;

    Ok(KeyServiceEndpoints {
        keymaker_url,
        public_certificate_url,
    })
}

fn key_service_endpoints_from_env() -> Result<KeyServiceEndpoints, KeyServiceEndpointConfigError> {
    key_service_endpoints_from_lookup(|name| env::var(name).ok())
}

impl KeyServiceEndpointConfigError {
    fn into_api_error(self) -> (StatusCode, String) {
        match self {
            Self::MissingKeymakerUrl => (
                StatusCode::SERVICE_UNAVAILABLE,
                "keymaker service endpoint is not configured".to_string(),
            ),
            Self::MissingPublicCertificateUrl => (
                StatusCode::SERVICE_UNAVAILABLE,
                "public certificate service endpoint is not configured".to_string(),
            ),
        }
    }
}

pub fn validate_org_quorum_request(
    request: &GenerateOrgQuorumBundleRequest,
) -> Result<(), ValidateOrgQuorumRequestError> {
    if request.participants.is_empty() {
        return Err(ValidateOrgQuorumRequestError::EmptyParticipants);
    }
    if request.threshold == 0 {
        return Err(ValidateOrgQuorumRequestError::ThresholdIsZero);
    }
    if usize::from(request.threshold) > request.participants.len() {
        return Err(
            ValidateOrgQuorumRequestError::ThresholdExceedsParticipants {
                threshold: request.threshold,
                participants: request.participants.len(),
            },
        );
    }

    let mut seen_users = HashSet::with_capacity(request.participants.len());
    for participant in &request.participants {
        if !seen_users.insert(participant.user_id) {
            return Err(ValidateOrgQuorumRequestError::DuplicateParticipant {
                user_id: participant.user_id,
            });
        }

        match participant.key_source {
            OrgQuorumKeySource::ExistingPgp => {
                if participant.pgp_key_id.is_none() {
                    return Err(
                        ValidateOrgQuorumRequestError::ExistingPgpSelectionRequiresPgpKeyId {
                            user_id: participant.user_id,
                        },
                    );
                }
            }
            OrgQuorumKeySource::CautionBackedPgp => {
                if !request.allow_caution_backed_keys {
                    return Err(
                        ValidateOrgQuorumRequestError::CautionBackedKeysRequireExplicitOptIn {
                            user_id: participant.user_id,
                        },
                    );
                }
                if participant.pgp_key_id.is_some() {
                    return Err(
                        ValidateOrgQuorumRequestError::CautionBackedSelectionMustNotSetPgpKeyId {
                            user_id: participant.user_id,
                        },
                    );
                }
            }
        }
    }

    Ok(())
}

impl ValidateOrgQuorumRequestError {
    fn into_api_error(self) -> (StatusCode, String) {
        let message = match self {
            Self::EmptyParticipants => "select at least one organization user".to_string(),
            Self::ThresholdIsZero => "threshold must be at least 1".to_string(),
            Self::ThresholdExceedsParticipants {
                threshold,
                participants,
            } => format!(
                "threshold ({threshold}) cannot exceed selected participant count ({participants})"
            ),
            Self::DuplicateParticipant { user_id } => {
                format!("user {user_id} was selected more than once")
            }
            Self::CautionBackedKeysRequireExplicitOptIn { user_id } => format!(
                "user {user_id} uses a Caution-backed key; pass allow_caution_backed_keys=true"
            ),
            Self::ExistingPgpSelectionRequiresPgpKeyId { user_id } => {
                format!("user {user_id} existing_pgp selection requires pgp_key_id")
            }
            Self::CautionBackedSelectionMustNotSetPgpKeyId { user_id } => {
                format!("user {user_id} caution_backed_pgp selection must not set pgp_key_id")
            }
        };

        (StatusCode::BAD_REQUEST, message)
    }
}

pub async fn generate_org_quorum_bundle(
    pool: &PgPool,
    org_id: Uuid,
    created_by: Uuid,
    request: GenerateOrgQuorumBundleRequest,
) -> Result<crate::cryptographic_bundles::QuorumBundle, (StatusCode, String)> {
    validate_org_quorum_request(&request).map_err(ValidateOrgQuorumRequestError::into_api_error)?;
    let _key_service_endpoints =
        key_service_endpoints_from_env().map_err(KeyServiceEndpointConfigError::into_api_error)?;
    let existing_keys = verify_request_membership_and_keys(pool, org_id, &request).await?;
    let keymaker_response = generate_keymaker_bundle(&request, org_id, &_key_service_endpoints, existing_keys).await?;
    let data = serde_json::to_value(keymaker_response).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to serialize keymaker quorum response: {e}"),
        )
    })?;

    crate::cryptographic_bundles::create_quorum_bundle(
        pool,
        org_id,
        created_by,
        crate::cryptographic_bundles::CreateBundleRequest {
            data,
            name: request.name,
            labels: Some(request.labels),
        },
    )
    .await
}

async fn verify_request_membership_and_keys(
    pool: &PgPool,
    org_id: Uuid,
    request: &GenerateOrgQuorumBundleRequest,
) -> Result<HashMap<Uuid, String>, (StatusCode, String)> {
    let mut existing_keys = HashMap::new();

    for participant in &request.participants {
        let member_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                SELECT 1 FROM organization_members om
                INNER JOIN users u ON u.id = om.user_id
                WHERE om.organization_id = $1 AND om.user_id = $2 AND u.is_active = true
            )",
        )
        .bind(org_id)
        .bind(participant.user_id)
        .fetch_one(pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        if !member_exists {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "user {} is not an active member of this organization",
                    participant.user_id
                ),
            ));
        }

        match participant.key_source {
            OrgQuorumKeySource::ExistingPgp => {
                let pgp_key_id = participant.pgp_key_id.ok_or_else(|| {
                    ValidateOrgQuorumRequestError::ExistingPgpSelectionRequiresPgpKeyId {
                        user_id: participant.user_id,
                    }
                    .into_api_error()
                })?;
                let public_key: Option<String> = sqlx::query_scalar(
                    "SELECT public_key FROM pgp_keys
                     WHERE id = $1 AND user_id = $2 AND removed_at IS NULL",
                )
                .bind(pgp_key_id)
                .bind(participant.user_id)
                .fetch_optional(pool)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

                let public_key = public_key.ok_or_else(|| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!(
                            "PGP key {} does not belong to active organization user {}",
                            pgp_key_id, participant.user_id
                        ),
                    )
                })?;
                existing_keys.insert(participant.user_id, public_key);
            }
            OrgQuorumKeySource::CautionBackedPgp => {
                // The public certificate service derives the final certificate in the next
                // service-integration slice. For PR 1 the API only accepts this source with
                // explicit opt-in and active org membership.
            }
        }
    }

    Ok(existing_keys)
}

fn labels_to_map(labels: &serde_json::Value, name: Option<&str>) -> HashMap<String, String> {
    let mut label = HashMap::new();
    if let Some(name) = name {
        label.insert("name".to_string(), name.to_string());
    }
    if let Some(labels) = labels.as_object() {
        for (key, value) in labels {
            match value {
                serde_json::Value::String(value) => {
                    label.insert(key.clone(), value.clone());
                }
                other => {
                    label.insert(key.clone(), other.to_string());
                }
            }
        }
    }
    label
}

fn keymaker_url(base_url: &str) -> Result<String, (StatusCode, String)> {
    Ok(format!("{}/generate_quorum", base_url.trim_end_matches('/')))
}

fn public_certificate_url(base_url: &str) -> Result<String, (StatusCode, String)> {
    Ok(format!(
        "{}/v1/public-certificates",
        base_url.trim_end_matches('/')
    ))
}

fn keymaker_request_from_certificates(
    request: &GenerateOrgQuorumBundleRequest,
    bundle_id: Uuid,
    certificates: Vec<String>,
) -> Result<GenerateQuorumRequest, (StatusCode, String)> {
    let max = u8::try_from(certificates.len()).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "selected participant count cannot exceed 255".to_string(),
        )
    })?;
    let keyring = certificates
        .into_iter()
        .map(|cert| KeymakerKey::OpenPGP { cert })
        .collect();

    Ok(GenerateQuorumRequest::V1(GenerateQuorumRequestV1 {
        bundle_id: *bundle_id.as_bytes(),
        label: labels_to_map(&request.labels, request.name.as_deref()),
        threshold: request.threshold,
        max,
        keyring,
    }))
}

async fn derive_caution_backed_certificates(
    client: &reqwest::Client,
    endpoints: &KeyServiceEndpoints,
    org_id: Uuid,
    count: u8,
) -> Result<Vec<String>, (StatusCode, String)> {
    let request = PublicCertificateRequest::V1(PublicCertificateRequestV1 {
        organization_id: *org_id.as_bytes(),
        certificate_count: count,
    });
    let response = client
        .post(public_certificate_url(&endpoints.public_certificate_url)?)
        .json(&request)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("public certificate service request failed: {e}")))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_else(|_| "<unreadable body>".to_string());
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("public certificate service returned {status}: {body}"),
        ));
    }
    let response: PublicCertificateResponse = response.json().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("public certificate service returned invalid response: {e}"),
        )
    })?;
    let PublicCertificateBundle::V1(bundle) = response.data;
    if bundle.organization_id != *org_id.as_bytes() {
        return Err((
            StatusCode::BAD_GATEWAY,
            "public certificate service returned a bundle for the wrong organization".to_string(),
        ));
    }
    if bundle.certificates.len() != usize::from(count) {
        return Err((
            StatusCode::BAD_GATEWAY,
            format!(
                "public certificate service returned {} certificates, expected {count}",
                bundle.certificates.len()
            ),
        ));
    }
    Ok(bundle.certificates)
}

async fn generate_keymaker_bundle(
    request: &GenerateOrgQuorumBundleRequest,
    org_id: Uuid,
    endpoints: &KeyServiceEndpoints,
    existing_keys: HashMap<Uuid, String>,
) -> Result<GenerateQuorumResponse, (StatusCode, String)> {
    let client = reqwest::Client::new();
    let caution_backed_count = request
        .participants
        .iter()
        .filter(|participant| participant.key_source == OrgQuorumKeySource::CautionBackedPgp)
        .count();
    let caution_backed_count = u8::try_from(caution_backed_count).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "selected Caution-backed participant count cannot exceed 255".to_string(),
        )
    })?;
    let caution_backed_certs = if caution_backed_count > 0 {
        derive_caution_backed_certificates(&client, endpoints, org_id, caution_backed_count).await?
    } else {
        Vec::new()
    };
    let mut caution_backed_certs = caution_backed_certs.into_iter();
    let mut certificates = Vec::with_capacity(request.participants.len());
    for participant in &request.participants {
        match participant.key_source {
            OrgQuorumKeySource::ExistingPgp => {
                let cert = existing_keys.get(&participant.user_id).ok_or_else(|| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("missing verified PGP key for user {}", participant.user_id),
                    )
                })?;
                certificates.push(cert.clone());
            }
            OrgQuorumKeySource::CautionBackedPgp => {
                let cert = caution_backed_certs.next().ok_or_else(|| {
                    (
                        StatusCode::BAD_GATEWAY,
                        "public certificate service returned too few certificates".to_string(),
                    )
                })?;
                certificates.push(cert);
            }
        }
    }

    let keymaker_request = keymaker_request_from_certificates(request, Uuid::new_v4(), certificates)?;
    let response = client
        .post(keymaker_url(&endpoints.keymaker_url)?)
        .json(&keymaker_request)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("keymaker request failed: {e}")))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_else(|_| "<unreadable body>".to_string());
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("keymaker returned {status}: {body}"),
        ));
    }
    response.json().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("keymaker returned invalid response: {e}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uuid(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn existing_pgp(user_id: Uuid, pgp_key_id: Uuid) -> OrgQuorumParticipantSelection {
        OrgQuorumParticipantSelection {
            user_id,
            key_source: OrgQuorumKeySource::ExistingPgp,
            pgp_key_id: Some(pgp_key_id),
        }
    }

    fn caution_backed(user_id: Uuid) -> OrgQuorumParticipantSelection {
        OrgQuorumParticipantSelection {
            user_id,
            key_source: OrgQuorumKeySource::CautionBackedPgp,
            pgp_key_id: None,
        }
    }

    #[test]
    fn builds_keymaker_v1_request_from_selected_certificates() {
        let request = GenerateOrgQuorumBundleRequest {
            name: Some("prod".to_string()),
            threshold: 2,
            participants: vec![caution_backed(uuid(1)), caution_backed(uuid(2))],
            allow_caution_backed_keys: true,
            labels: serde_json::json!({"env": "prod"}),
        };
        let bundle_id = uuid(9);

        let keymaker_request = keymaker_request_from_certificates(
            &request,
            bundle_id,
            vec!["cert-a".to_string(), "cert-b".to_string()],
        )
        .unwrap();

        let GenerateQuorumRequest::V1(request) = keymaker_request;
        assert_eq!(request.bundle_id, *bundle_id.as_bytes());
        assert_eq!(request.threshold, 2);
        assert_eq!(request.max, 2);
        assert_eq!(request.label.get("name").unwrap(), "prod");
        assert_eq!(request.label.get("env").unwrap(), "prod");
        assert_eq!(
            request.keyring,
            vec![
                KeymakerKey::OpenPGP {
                    cert: "cert-a".to_string(),
                },
                KeymakerKey::OpenPGP {
                    cert: "cert-b".to_string(),
                },
            ]
        );
    }

    #[test]
    fn resolves_required_key_service_endpoints_from_server_lookup() {
        let endpoints = key_service_endpoints_from_lookup(|name| match name {
            "KEYMAKER_URL" => Some("http://keymaker:8080".to_string()),
            "PUBLIC_CERTIFICATE_SERVICE_URL" => Some("http://public-cert:8080".to_string()),
            _ => None,
        })
        .unwrap();

        assert_eq!(endpoints.keymaker_url, "http://keymaker:8080");
        assert_eq!(endpoints.public_certificate_url, "http://public-cert:8080");
    }

    #[test]
    fn fails_closed_when_key_service_endpoints_are_missing() {
        assert_eq!(
            key_service_endpoints_from_lookup(|_| None),
            Err(KeyServiceEndpointConfigError::MissingKeymakerUrl)
        );
        assert_eq!(
            key_service_endpoints_from_lookup(|name| match name {
                "KEYMAKER_URL" => Some("http://keymaker:8080".to_string()),
                _ => None,
            }),
            Err(KeyServiceEndpointConfigError::MissingPublicCertificateUrl)
        );
    }

    #[test]
    fn rejects_caution_backed_participants_without_explicit_opt_in() {
        let request = GenerateOrgQuorumBundleRequest {
            name: Some("production".to_string()),
            threshold: 1,
            participants: vec![caution_backed(uuid(1))],
            allow_caution_backed_keys: false,
            labels: serde_json::json!({}),
        };

        assert_eq!(
            validate_org_quorum_request(&request),
            Err(
                ValidateOrgQuorumRequestError::CautionBackedKeysRequireExplicitOptIn {
                    user_id: uuid(1),
                }
            )
        );
    }

    #[test]
    fn rejects_duplicate_users_even_when_key_sources_differ() {
        let request = GenerateOrgQuorumBundleRequest {
            name: None,
            threshold: 1,
            participants: vec![existing_pgp(uuid(1), uuid(2)), caution_backed(uuid(1))],
            allow_caution_backed_keys: true,
            labels: serde_json::json!({}),
        };

        assert_eq!(
            validate_org_quorum_request(&request),
            Err(ValidateOrgQuorumRequestError::DuplicateParticipant { user_id: uuid(1) })
        );
    }

    #[test]
    fn rejects_threshold_larger_than_selected_participant_count() {
        let request = GenerateOrgQuorumBundleRequest {
            name: None,
            threshold: 3,
            participants: vec![
                existing_pgp(uuid(1), uuid(2)),
                existing_pgp(uuid(3), uuid(4)),
            ],
            allow_caution_backed_keys: false,
            labels: serde_json::json!({}),
        };

        assert_eq!(
            validate_org_quorum_request(&request),
            Err(
                ValidateOrgQuorumRequestError::ThresholdExceedsParticipants {
                    threshold: 3,
                    participants: 2,
                }
            )
        );
    }

    #[test]
    fn accepts_mixed_existing_and_explicit_caution_backed_participants() {
        let request = GenerateOrgQuorumBundleRequest {
            name: Some("mixed".to_string()),
            threshold: 2,
            participants: vec![existing_pgp(uuid(1), uuid(2)), caution_backed(uuid(3))],
            allow_caution_backed_keys: true,
            labels: serde_json::json!({"env":"prod"}),
        };

        assert_eq!(validate_org_quorum_request(&request), Ok(()));
    }
}
