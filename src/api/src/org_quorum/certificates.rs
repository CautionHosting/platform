// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial

use super::*;
use bootproof_sdk::format::nitro::Nitro;
use public_certificate_models::{
    PublicCertificateBundle, PublicCertificateRequest, PublicCertificateResponse,
};
use sequoia_openpgp::packet::signature::subpacket::SubpacketValue;
use serde_cbor::Value;
use sha2::{Digest, Sha256};
use std::{num::NonZeroU8, time::SystemTime};

const ORG_NOTATION: &str = "organization-id@caution.co";
const BUNDLE_NOTATION: &str = "bundle-id@caution.co";

fn rejected(message: &'static str) -> OrgQuorumError {
    OrgQuorumError::new(StatusCode::BAD_GATEWAY, message)
}

pub(super) async fn derive(
    client: &reqwest::Client,
    org_id: Uuid,
    count: NonZeroU8,
) -> Result<([u8; 16], Vec<String>), OrgQuorumError> {
    let url = configured("PUBLIC_CERTIFICATE_SERVICE_URL")?;
    let policy = load_policy(Path::new(&configured(
        "PUBLIC_CERTIFICATE_PCR_POLICY_PATH",
    )?))?;
    let ca_bytes = std::fs::read(configured("CAUTION_CA_CERT_PATH")?).with_context(Ctx::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "unable to read Caution CA certificate",
    ))?;
    let ca = Cert::from_bytes(&ca_bytes).with_context(Ctx::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "invalid Caution CA certificate",
    ))?;
    if ca.is_tsk() {
        return Err(OrgQuorumError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Caution CA configuration must contain only a public certificate",
        ));
    }
    let request =
        PublicCertificateRequest::V1(public_certificate_models::v1::PublicCertificateRequest {
            organization_id: *org_id.as_bytes(),
            certificate_count: count,
        });
    let token = configured("PUBLIC_CERTIFICATE_SERVICE_TOKEN")?;
    let endpoint = [url.trim_end_matches('/'), "/v1/public-certificates"].concat();
    let local_test = cfg!(feature = "e2e-testing-unsafe")
        && std::env::var("CAUTION_UNSAFE_KEY_SERVICE_E2E").as_deref() == Ok("1");
    let response: PublicCertificateResponse =
        send(issuance_request(client, &endpoint, &token, local_test)?.json(&request)).await?;
    let at = verify_proof(&response, &policy)?;
    verify_certificates(response.data, *org_id.as_bytes(), count, &ca, at)
}

// The service hashes the serialized struct, NOT Keymaker's canonical Value map.
fn bundle_hash(data: &PublicCertificateBundle) -> Result<Vec<u8>, OrgQuorumError> {
    let bytes = serde_cbor::to_vec(data).with_context(Ctx::new(
        StatusCode::BAD_GATEWAY,
        "unable to hash certificate-service response",
    ))?;
    Ok(Sha256::digest(bytes).to_vec())
}

fn verify_proof(
    response: &PublicCertificateResponse,
    policy: &KeymakerPcrPolicy,
) -> Result<SystemTime, OrgQuorumError> {
    let hash = bundle_hash(&response.data)?;
    #[cfg(feature = "e2e-testing-unsafe")]
    if std::env::var("CAUTION_UNSAFE_KEY_SERVICE_E2E").as_deref() == Ok("1")
        && policy.sets.len() == 1
        && policy.sets[0].expires_at_unix_seconds.is_none()
        && policy.sets[0].pcrs.len() == 3
        && (0..=2).all(|index| {
            policy.sets[0]
                .pcrs
                .get(&index)
                .is_some_and(|pcr| pcr == &[0xab; 48])
        })
        && response.necroproof == hash
    {
        tracing::warn!("UNSAFE E2E: accepting synthetic certificate-service proof");
        return Ok(SystemTime::now());
    }

    for set in &policy.sets {
        let nitro =
            Nitro::new(response.necroproof.as_slice(), set.pcrs.clone()).with_context(Ctx::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "invalid certificate-service PCR policy",
            ))?;
        // Only Bootproof parses/verifies the untrusted COSE evidence. No data is
        // consumed until AWS chain, signature, nonce absence and PCR checks pass.
        if let Ok(document) = nitro.verify_at_attestation_time(None) {
            let at = verify_payload(document, &hash)?;
            if valid_at(set, at) {
                return Ok(at);
            }
        }
    }
    Err(rejected("certificate-service proof verification failed"))
}

fn valid_at(set: &locksmith::bundle::KeymakerPcrSet, at: SystemTime) -> bool {
    match set.expires_at_unix_seconds {
        None => true,
        Some(seconds) => SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .is_some_and(|expiry| at < expiry),
    }
}

// Input must be the authenticated payload returned by Bootproof.
fn verify_payload(document: Value, expected_hash: &[u8]) -> Result<SystemTime, OrgQuorumError> {
    let Value::Map(map) = document else {
        return Err(rejected("invalid certificate proof payload"));
    };
    if !matches!(map.get(&Value::Text("user_data".into())), Some(Value::Bytes(bytes)) if bytes == expected_hash)
    {
        return Err(rejected(
            "certificate proof does not bind the returned bundle",
        ));
    }
    let Some(Value::Integer(timestamp)) = map.get(&Value::Text("timestamp".into())) else {
        return Err(rejected("missing certificate proof timestamp"));
    };
    u64::try_from(*timestamp)
        .ok()
        .and_then(|millis| SystemTime::UNIX_EPOCH.checked_add(Duration::from_millis(millis)))
        .ok_or_else(|| rejected("invalid certificate proof timestamp"))
}

fn verify_certificates(
    data: PublicCertificateBundle,
    organization_id: [u8; 16],
    count: NonZeroU8,
    ca: &Cert,
    at: SystemTime,
) -> Result<([u8; 16], Vec<String>), OrgQuorumError> {
    let bundle = data.to_latest();
    if bundle.organization_id != organization_id
        || bundle.certificates.len() != usize::from(count.get())
    {
        return Err(rejected(
            "certificate response does not match the requested organization and count",
        ));
    }
    let mut policy = StandardPolicy::new();
    policy.good_critical_notations(&[ORG_NOTATION, BUNDLE_NOTATION]);
    locksmith::custody::validate_ca_anchor(ca, at).with_context(Ctx::new(
        StatusCode::BAD_GATEWAY,
        "invalid or revoked configured Caution CA anchor",
    ))?;
    let org = hex::encode(organization_id);
    let id = hex::encode(bundle.bundle_id);
    for (index, armored) in bundle.certificates.iter().enumerate() {
        let cert = eligible_certificate(armored, None).with_context(Ctx::new(
            StatusCode::BAD_GATEWAY,
            "ineligible derived holder certificate",
        ))?;
        let valid = cert.with_policy(&policy, at).with_context(Ctx::new(
            StatusCode::BAD_GATEWAY,
            "derived certificate was not valid at generation time",
        ))?;
        let expected_uid = format!("Caution public certificate index={index}");
        let uid = valid
            .userids()
            .revoked(false)
            .find(|uid| uid.userid().value() == expected_uid.as_bytes())
            .ok_or_else(|| rejected("derived certificate index does not match its position"))?;
        let certifications: Vec<_> = uid
            .valid_certifications_by_key(&policy, at, ca.primary_key().key())
            .collect();
        if certifications.is_empty() {
            return Err(rejected(
                "derived certificate lacks a valid Caution CA certification",
            ));
        }
        for signature in certifications {
            // Reject context in the unhashed area, even when the hashed value is
            // correct: there must be exactly one authenticated value per name.
            if signature.unhashed_area().iter().any(|packet| matches!(packet.value(),
                SubpacketValue::NotationData(n) if [ORG_NOTATION, BUNDLE_NOTATION].contains(&n.name()))) {
                return Err(rejected("certificate context must be hashed"));
            }
            for (name, expected) in [
                (ORG_NOTATION, org.as_bytes()),
                (BUNDLE_NOTATION, id.as_bytes()),
            ] {
                let values: Vec<_> = signature
                    .notation_data()
                    .filter(|n| n.name() == name)
                    .collect();
                if values.len() != 1 || values[0].value() != expected {
                    return Err(rejected(
                        "Caution CA certification has missing, duplicate or mismatched context",
                    ));
                }
            }
        }
    }
    let keys: Vec<_> = bundle
        .certificates
        .iter()
        .map(|cert| Key::OpenPGP { cert: cert.clone() })
        .collect();
    validate_keyring(&keys, None).with_context(Ctx::new(
        StatusCode::BAD_GATEWAY,
        "duplicate derived recipients",
    ))?;
    Ok((bundle.bundle_id, bundle.certificates))
}

#[cfg(test)]
#[path = "certificate_tests.rs"]
mod tests;

// The shared HTTP client also calls Keymaker: never install this as a default header.
fn issuance_request(
    client: &reqwest::Client,
    endpoint: &str,
    token: &str,
    local_test: bool,
) -> Result<reqwest::RequestBuilder, OrgQuorumError> {
    let url = reqwest::Url::parse(endpoint).with_context(Ctx::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "invalid certificate-service URL",
    ))?;
    let loopback = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if !(url.scheme() == "https" || (local_test && url.scheme() == "http" && loopback))
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(OrgQuorumError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "certificate issuance requires HTTPS",
        ));
    }
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(OrgQuorumError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "certificate-service token must be 32 random bytes encoded as hex",
        ));
    }
    let mut header = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
        .with_context(Ctx::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "invalid certificate-service token",
        ))?;
    header.set_sensitive(true);
    Ok(client
        .post(url)
        .header(reqwest::header::AUTHORIZATION, header))
}

#[cfg(test)]
mod issuance_tests {
    use super::*;
    #[test]
    fn issuance_token_is_scoped_sensitive_and_requires_secure_transport() {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let token = "ab".repeat(32);
        let request = issuance_request(
            &client,
            "https://cert.example/v1/public-certificates",
            &token,
            false,
        )
        .unwrap()
        .build()
        .unwrap();
        let auth = &request.headers()[reqwest::header::AUTHORIZATION];
        assert_eq!(auth.to_str().unwrap(), format!("Bearer {token}"));
        assert!(auth.is_sensitive());
        assert!(
            !client
                .post("https://keymaker.example")
                .build()
                .unwrap()
                .headers()
                .contains_key(reqwest::header::AUTHORIZATION)
        );
        for endpoint in [
            "http://cert.example",
            "http://127.0.0.1",
            "https://user:password@cert.example",
        ] {
            assert!(issuance_request(&client, endpoint, &token, false).is_err());
        }
        assert!(issuance_request(&client, "http://127.0.0.1", &token, true).is_ok());
        assert!(issuance_request(&client, "http://cert.example", &token, true).is_err());
        assert!(issuance_request(&client, "https://cert.example", "", false).is_err());
        assert!(issuance_request(&client, "https://cert.example", "short", false).is_err());
    }
}
