// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Verification of Device Bound Session Credentials (DBSC) ES256 proofs.
//!
//! Pure functions, no database and no HTTP types. A proof is a compact JWS
//! (`typ=dbsc+jwt`, `alg=ES256`) signed by the device-bound key. Registration
//! proofs carry the public key in the header `jwk`; refresh proofs must not.

// The `CtxError` derive generates a `{Error}Ctx` mirror type whose struct
// initialisations trip `redundant_field_names`.
#![allow(
    clippy::redundant_field_names,
    reason = "generated {Error}Ctx mirrors trip redundant_field_names"
)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use dterror::{BoxError, CtxError, Location, ResultExt};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::elliptic_curve::JwkEcKey;

use crate::csrf::constant_time_compare;

const DBSC_TYP: &str = "dbsc+jwt";
const DBSC_ALG: &str = "ES256";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DbscProofErrorKind {
    /// Not a three-part base64url JWS, or the header/payload is not valid JSON.
    Malformed,
    /// Header `typ` is not `dbsc+jwt`.
    WrongType,
    /// Header `alg` is not `ES256`.
    UnsupportedAlgorithm,
    /// Registration proof without a `jwk` header.
    MissingJwk,
    /// Refresh proof that carries a `jwk` header.
    UnexpectedJwk,
    /// `jwk` / SEC1 bytes are not a valid P-256 public key.
    InvalidKey,
    /// Signature is not 64 bytes of `r||s` or does not verify.
    BadSignature,
    /// Signature is valid but `jti` is not the expected challenge.
    ChallengeMismatch,
}

#[derive(Debug, thiserror::Error, CtxError)]
#[context(derive(Debug))]
#[error("invalid DBSC proof ({kind:?}) [{location}]")]
pub(crate) struct DbscProofError {
    kind: DbscProofErrorKind,
    #[location]
    location: Location,
    #[source]
    source: Option<BoxError>,
}

impl DbscProofError {
    pub(crate) fn kind(&self) -> DbscProofErrorKind {
        self.kind
    }

    /// Source-less failure (a domain rule, not a wrapped library error).
    #[track_caller]
    fn new_kind(kind: DbscProofErrorKind) -> Self {
        DbscProofError {
            kind,
            location: std::panic::Location::caller(),
            source: None,
        }
    }
}

/// Verify a registration proof: the public key comes from the header `jwk`.
/// Returns that key once the signature and `jti == expected_challenge` check out.
pub(crate) fn verify_registration_proof(
    jwt: &str,
    expected_challenge: &str,
) -> Result<VerifyingKey, DbscProofError> {
    use DbscProofErrorCtx as Ctx;

    let proof = Proof::parse(jwt)?;
    let jwk = match proof.header.get("jwk") {
        None | Some(serde_json::Value::Null) => {
            return Err(DbscProofError::new_kind(DbscProofErrorKind::MissingJwk))
        }
        Some(jwk) => jwk,
    };
    let jwk: JwkEcKey = serde_json::from_value(jwk.clone())
        .with_context(Ctx::new(DbscProofErrorKind::InvalidKey))?;
    let public_key =
        p256::PublicKey::from_jwk(&jwk).with_context(Ctx::new(DbscProofErrorKind::InvalidKey))?;
    let key = VerifyingKey::from(&public_key);
    proof.verify(&key, expected_challenge)?;
    Ok(key)
}

/// Verify a refresh proof against the key stored at registration.
pub(crate) fn verify_refresh_proof(
    jwt: &str,
    expected_challenge: &str,
    key: &VerifyingKey,
) -> Result<(), DbscProofError> {
    let proof = Proof::parse(jwt)?;
    if proof.header.contains_key("jwk") {
        return Err(DbscProofError::new_kind(DbscProofErrorKind::UnexpectedJwk));
    }
    proof.verify(key, expected_challenge)
}

/// SEC1 uncompressed encoding of a P-256 public key.
pub(crate) fn encode_public_key(key: &VerifyingKey) -> Vec<u8> {
    key.to_encoded_point(false).as_bytes().to_vec()
}

/// Inverse of [`encode_public_key`].
pub(crate) fn decode_public_key(bytes: &[u8]) -> Result<VerifyingKey, DbscProofError> {
    use DbscProofErrorCtx as Ctx;

    VerifyingKey::from_sec1_bytes(bytes).with_context(Ctx::new(DbscProofErrorKind::InvalidKey))
}

type JsonObject = serde_json::Map<String, serde_json::Value>;

/// A compact JWS that has been split and decoded, with `typ` and `alg` checked.
struct Proof<'a> {
    header: JsonObject,
    /// ASCII `"<b64header>.<b64payload>"`, the bytes the signature covers.
    signing_input: &'a str,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

impl<'a> Proof<'a> {
    fn parse(jwt: &'a str) -> Result<Self, DbscProofError> {
        use DbscProofErrorCtx as Ctx;

        let malformed = || Ctx::new(DbscProofErrorKind::Malformed);
        let mut parts = jwt.split('.');
        let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(DbscProofError::new_kind(DbscProofErrorKind::Malformed));
        };
        let header = URL_SAFE_NO_PAD
            .decode(header_b64)
            .with_context(malformed())?;
        let payload = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .with_context(malformed())?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature_b64)
            .with_context(malformed())?;
        let header: JsonObject = serde_json::from_slice(&header).with_context(malformed())?;

        if header.get("typ").and_then(|v| v.as_str()) != Some(DBSC_TYP) {
            return Err(DbscProofError::new_kind(DbscProofErrorKind::WrongType));
        }
        if header.get("alg").and_then(|v| v.as_str()) != Some(DBSC_ALG) {
            return Err(DbscProofError::new_kind(
                DbscProofErrorKind::UnsupportedAlgorithm,
            ));
        }

        // The header and payload parts are adjacent in `jwt`, separated by one dot.
        let signing_input = &jwt[..header_b64.len() + 1 + payload_b64.len()];
        Ok(Proof {
            header,
            signing_input,
            payload,
            signature,
        })
    }

    /// Check the signature, and only then that `jti` is the expected challenge.
    fn verify(&self, key: &VerifyingKey, expected_challenge: &str) -> Result<(), DbscProofError> {
        use DbscProofErrorCtx as Ctx;

        let signature = Signature::from_slice(&self.signature)
            .with_context(Ctx::new(DbscProofErrorKind::BadSignature))?;
        key.verify(self.signing_input.as_bytes(), &signature)
            .with_context(Ctx::new(DbscProofErrorKind::BadSignature))?;

        let payload: JsonObject = serde_json::from_slice(&self.payload)
            .with_context(Ctx::new(DbscProofErrorKind::Malformed))?;
        match payload.get("jti").and_then(|v| v.as_str()) {
            Some(jti) if constant_time_compare(jti, expected_challenge) => Ok(()),
            _ => Err(DbscProofError::new_kind(
                DbscProofErrorKind::ChallengeMismatch,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};
    use serde_json::{json, Value};

    const CHALLENGE: &str = "challenge-abc";

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn jwt(sk: &SigningKey, header: Value, payload: Value) -> String {
        let signing_input = format!(
            "{}.{}",
            b64(header.to_string().as_bytes()),
            b64(payload.to_string().as_bytes())
        );
        let sig: Signature = sk.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", b64(&sig.to_bytes()))
    }

    fn jwk_of(sk: &SigningKey) -> Value {
        let public = p256::PublicKey::from(sk.verifying_key());
        serde_json::from_str(&public.to_jwk_string()).unwrap()
    }

    fn reg_header(sk: &SigningKey) -> Value {
        json!({"typ": "dbsc+jwt", "alg": "ES256", "jwk": jwk_of(sk)})
    }

    fn refresh_header() -> Value {
        json!({"typ": "dbsc+jwt", "alg": "ES256"})
    }

    fn payload() -> Value {
        json!({"jti": CHALLENGE, "iat": 1})
    }

    fn key() -> SigningKey {
        SigningKey::random(&mut rand::thread_rng())
    }

    fn kind<T: std::fmt::Debug>(r: Result<T, DbscProofError>) -> DbscProofErrorKind {
        r.unwrap_err().kind()
    }

    #[test]
    fn registration_valid_returns_key() {
        let sk = key();
        let t = jwt(&sk, reg_header(&sk), payload());
        let vk = verify_registration_proof(&t, CHALLENGE).unwrap();
        assert_eq!(&vk, sk.verifying_key());
    }

    #[test]
    fn refresh_valid() {
        let sk = key();
        let t = jwt(&sk, refresh_header(), payload());
        verify_refresh_proof(&t, CHALLENGE, sk.verifying_key()).unwrap();
    }

    #[test]
    fn rejects_wrong_typ() {
        let sk = key();
        let mut h = reg_header(&sk);
        h["typ"] = json!("JWT");
        let t = jwt(&sk, h, payload());
        assert_eq!(
            kind(verify_registration_proof(&t, CHALLENGE)),
            DbscProofErrorKind::WrongType
        );
        let mut h = refresh_header();
        h.as_object_mut().unwrap().remove("typ");
        let t = jwt(&sk, h, payload());
        assert_eq!(
            kind(verify_refresh_proof(&t, CHALLENGE, sk.verifying_key())),
            DbscProofErrorKind::WrongType
        );
    }

    #[test]
    fn rejects_rs256_and_none() {
        let sk = key();
        for alg in ["RS256", "none", "ES384"] {
            let mut h = reg_header(&sk);
            h["alg"] = json!(alg);
            let t = jwt(&sk, h, payload());
            assert_eq!(
                kind(verify_registration_proof(&t, CHALLENGE)),
                DbscProofErrorKind::UnsupportedAlgorithm,
                "alg {alg}"
            );
        }
    }

    #[test]
    fn registration_requires_jwk() {
        let sk = key();
        let t = jwt(&sk, refresh_header(), payload());
        assert_eq!(
            kind(verify_registration_proof(&t, CHALLENGE)),
            DbscProofErrorKind::MissingJwk
        );
    }

    #[test]
    fn registration_rejects_invalid_jwk() {
        let sk = key();
        // Not a JWK at all.
        let mut h = reg_header(&sk);
        h["jwk"] = json!({"kty": "EC"});
        let t = jwt(&sk, h, payload());
        assert_eq!(
            kind(verify_registration_proof(&t, CHALLENGE)),
            DbscProofErrorKind::InvalidKey
        );
        // A different curve.
        let mut h = reg_header(&sk);
        h["jwk"]["crv"] = json!("P-384");
        let t = jwt(&sk, h, payload());
        assert_eq!(
            kind(verify_registration_proof(&t, CHALLENGE)),
            DbscProofErrorKind::InvalidKey
        );
        // A point that is not on the curve.
        let mut h = reg_header(&sk);
        h["jwk"]["y"] = h["jwk"]["x"].clone();
        let t = jwt(&sk, h, payload());
        assert_eq!(
            kind(verify_registration_proof(&t, CHALLENGE)),
            DbscProofErrorKind::InvalidKey
        );
    }

    #[test]
    fn refresh_rejects_jwk() {
        let sk = key();
        let t = jwt(&sk, reg_header(&sk), payload());
        assert_eq!(
            kind(verify_refresh_proof(&t, CHALLENGE, sk.verifying_key())),
            DbscProofErrorKind::UnexpectedJwk
        );
    }

    #[test]
    fn tampered_payload_is_bad_signature() {
        let sk = key();
        let t = jwt(&sk, reg_header(&sk), payload());
        let parts: Vec<&str> = t.split('.').collect();
        let forged = b64(json!({"jti": "other", "iat": 1}).to_string().as_bytes());
        let t = format!("{}.{}.{}", parts[0], forged, parts[2]);
        assert_eq!(
            kind(verify_registration_proof(&t, "other")),
            DbscProofErrorKind::BadSignature
        );
    }

    #[test]
    fn other_key_is_bad_signature() {
        let sk = key();
        let other = key();
        // Header advertises sk's key but is signed by `other`.
        let t = jwt(&other, reg_header(&sk), payload());
        assert_eq!(
            kind(verify_registration_proof(&t, CHALLENGE)),
            DbscProofErrorKind::BadSignature
        );
        let t = jwt(&other, refresh_header(), payload());
        assert_eq!(
            kind(verify_refresh_proof(&t, CHALLENGE, sk.verifying_key())),
            DbscProofErrorKind::BadSignature
        );
    }

    #[test]
    fn wrong_signature_length_is_bad_signature() {
        let sk = key();
        let t = jwt(&sk, refresh_header(), payload());
        let parts: Vec<&str> = t.split('.').collect();
        let t = format!("{}.{}.{}", parts[0], parts[1], b64(&[0u8; 63]));
        assert_eq!(
            kind(verify_refresh_proof(&t, CHALLENGE, sk.verifying_key())),
            DbscProofErrorKind::BadSignature
        );
    }

    #[test]
    fn wrong_jti_is_challenge_mismatch() {
        let sk = key();
        let t = jwt(&sk, reg_header(&sk), json!({"jti": "stale"}));
        assert_eq!(
            kind(verify_registration_proof(&t, CHALLENGE)),
            DbscProofErrorKind::ChallengeMismatch
        );
        let t = jwt(&sk, refresh_header(), json!({"jti": "stale"}));
        assert_eq!(
            kind(verify_refresh_proof(&t, CHALLENGE, sk.verifying_key())),
            DbscProofErrorKind::ChallengeMismatch
        );
        // Missing or non-string jti is also a mismatch (after a valid signature).
        let t = jwt(&sk, refresh_header(), json!({"jti": 5}));
        assert_eq!(
            kind(verify_refresh_proof(&t, CHALLENGE, sk.verifying_key())),
            DbscProofErrorKind::ChallengeMismatch
        );
        let t = jwt(&sk, refresh_header(), json!({}));
        assert_eq!(
            kind(verify_refresh_proof(&t, CHALLENGE, sk.verifying_key())),
            DbscProofErrorKind::ChallengeMismatch
        );
    }

    #[test]
    fn bad_signature_takes_precedence_over_jti_mismatch() {
        let sk = key();
        let other = key();
        let t = jwt(&other, refresh_header(), json!({"jti": "stale"}));
        assert_eq!(
            kind(verify_refresh_proof(&t, CHALLENGE, sk.verifying_key())),
            DbscProofErrorKind::BadSignature
        );
    }

    #[test]
    fn two_part_or_bad_base64_is_malformed() {
        let sk = key();
        let t = jwt(&sk, reg_header(&sk), payload());
        let parts: Vec<&str> = t.split('.').collect();
        for bad in [
            format!("{}.{}", parts[0], parts[1]),
            format!("{}.{}.{}.x", parts[0], parts[1], parts[2]),
            format!("!!!.{}.{}", parts[1], parts[2]),
            format!("{}.{}.{}=", parts[0], parts[1], parts[2]),
            String::new(),
        ] {
            assert_eq!(
                kind(verify_registration_proof(&bad, CHALLENGE)),
                DbscProofErrorKind::Malformed,
                "input {bad:?}"
            );
            assert_eq!(
                kind(verify_refresh_proof(&bad, CHALLENGE, sk.verifying_key())),
                DbscProofErrorKind::Malformed,
                "input {bad:?}"
            );
        }
        // Header that is valid base64 but not JSON.
        let bad = format!("{}.{}.{}", b64(b"not json"), parts[1], parts[2]);
        assert_eq!(
            kind(verify_registration_proof(&bad, CHALLENGE)),
            DbscProofErrorKind::Malformed
        );
    }

    #[test]
    fn public_key_roundtrip() {
        let sk = key();
        let bytes = encode_public_key(sk.verifying_key());
        assert_eq!(bytes.len(), 65);
        assert_eq!(bytes[0], 0x04);
        assert_eq!(&decode_public_key(&bytes).unwrap(), sk.verifying_key());
        assert_eq!(
            kind(decode_public_key(&bytes[..64])),
            DbscProofErrorKind::InvalidKey
        );
        assert_eq!(kind(decode_public_key(&[])), DbscProofErrorKind::InvalidKey);
    }
}
