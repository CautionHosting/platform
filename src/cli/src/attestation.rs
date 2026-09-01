// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use base64::{Engine as _, engine::general_purpose};
use coset::CborSerializable;
use dterror::{BoxError, CtxError, Location, ResultExt};
use serde_cbor::Value as CborValue;
use serde_json::{Map as JsonMap, Number as JsonNumber, Value as JsonValue};

#[derive(Debug, Clone)]
pub struct AttestationPcrs {
    pub pcr0: String,
    pub pcr1: String,
    pub pcr2: String,
}

/// Errors produced by [`parse`] while decoding a COSE_Sign1 attestation document.
#[derive(Debug, thiserror::Error, CtxError)]
pub enum ParseError {
    #[error("failed to parse COSE_Sign1 [{location:?}]")]
    ParseCoseSign1 {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },

    #[error("no payload in COSE_Sign1 [{location:?}]")]
    NoPayload {
        #[location]
        location: Location,
    },

    #[error("failed to parse attestation payload as CBOR [{location:?}]")]
    DecodePayload {
        #[location]
        location: Location,

        #[source]
        source: BoxError,
    },
}

pub fn parse(attestation_bytes: &[u8]) -> Result<CborValue, ParseError> {
    use ParseErrorCtx as Ctx;

    fn as_boxdyne(e: &(dyn std::error::Error + Send + Sync + 'static)) {
        ();
    }

    let cose_sign1 = coset::CoseSign1::from_slice(attestation_bytes)
        .with_context(Ctx::parse_cose_sign1())?;

    let payload = cose_sign1.payload.as_ref().ok_or_else(|| ParseError::NoPayload {
        location: std::panic::Location::caller(),
    })?;
    serde_cbor::from_slice(payload).with_context(Ctx::decode_payload())
}

/// Errors produced by [`extract_pcrs`] while reading PCR values from an attestation document.
#[derive(Debug, thiserror::Error)]
pub enum ExtractPcrsError {
    #[error("attestation payload is not a CBOR map [{location:?}]")]
    NotAMap { location: Location },

    #[error("no PCRs found in attestation document [{location:?}]")]
    MissingPcrsKey { location: Location },

    #[error("PCR{index} not found in attestation document [{location:?}]")]
    MissingPcr { index: i128, location: Location },
}

pub fn extract_pcrs(attestation: &CborValue) -> Result<AttestationPcrs, ExtractPcrsError> {
    let attestation_map = match attestation {
        CborValue::Map(map) => map,
        _ => {
            return Err(ExtractPcrsError::NotAMap {
                location: std::panic::Location::caller(),
            });
        }
    };

    let pcrs_key = CborValue::Text("pcrs".to_string());
    let pcrs_map = match attestation_map.get(&pcrs_key) {
        Some(CborValue::Map(map)) => map,
        _ => {
            return Err(ExtractPcrsError::MissingPcrsKey {
                location: std::panic::Location::caller(),
            });
        }
    };

    let pcr = |index: i128| -> Result<String, ExtractPcrsError> {
        match pcrs_map.get(&CborValue::Integer(index)) {
            Some(CborValue::Bytes(bytes)) => Ok(hex::encode(bytes)),
            _ => Err(ExtractPcrsError::MissingPcr {
                index,
                location: std::panic::Location::caller(),
            }),
        }
    };

    Ok(AttestationPcrs {
        pcr0: pcr(0)?,
        pcr1: pcr(1)?,
        pcr2: pcr(2)?,
    })
}

/// Errors produced by [`payload_json`] while losslessly converting a CBOR value to JSON.
#[derive(Debug, thiserror::Error)]
pub enum PayloadJsonError {
    #[error("CBOR float cannot be represented as JSON [{location:?}]")]
    FloatNotRepresentable { location: Location },

    #[error("CBOR map key cannot be represented as a JSON object key [{location:?}]")]
    UnrepresentableMapKey { location: Location },

    #[error("CBOR map keys collide when represented as JSON [{location:?}]")]
    CollidingMapKeys { location: Location },

    #[error("unsupported CBOR value [{location:?}]")]
    UnsupportedValue { location: Location },
}

pub fn payload_json(value: &CborValue) -> Result<JsonValue, PayloadJsonError> {
    Ok(match value {
        CborValue::Null => JsonValue::Null,
        CborValue::Bool(value) => JsonValue::Bool(*value),
        CborValue::Integer(value) => {
            if let Ok(value) = i64::try_from(*value) {
                JsonValue::Number(JsonNumber::from(value))
            } else if let Ok(value) = u64::try_from(*value) {
                JsonValue::Number(JsonNumber::from(value))
            } else {
                JsonValue::String(value.to_string())
            }
        }
        CborValue::Float(value) => JsonNumber::from_f64(*value).map(JsonValue::Number).ok_or(
            PayloadJsonError::FloatNotRepresentable {
                location: std::panic::Location::caller(),
            },
        )?,
        CborValue::Bytes(value) => {
            let mut encoded = String::from("base64:");
            general_purpose::STANDARD.encode_string(value, &mut encoded);
            JsonValue::String(encoded)
        }
        CborValue::Text(value) => JsonValue::String(value.clone()),
        CborValue::Array(values) => {
            JsonValue::Array(values.iter().map(payload_json).collect::<Result<Vec<_>, _>>()?)
        }
        CborValue::Map(values) => {
            let mut map = JsonMap::new();
            for (key, value) in values {
                let key = match key {
                    CborValue::Text(key) => key.clone(),
                    CborValue::Integer(key) => key.to_string(),
                    _ => {
                        return Err(PayloadJsonError::UnrepresentableMapKey {
                            location: std::panic::Location::caller(),
                        });
                    }
                };
                if map.insert(key, payload_json(value)?).is_some() {
                    return Err(PayloadJsonError::CollidingMapKeys {
                        location: std::panic::Location::caller(),
                    });
                }
            }
            JsonValue::Object(map)
        }
        CborValue::Tag(tag, value) => serde_json::json!({
            "tag": tag,
            "value": payload_json(value)?,
        }),
        _ => {
            return Err(PayloadJsonError::UnsupportedValue {
                location: std::panic::Location::caller(),
            });
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal COSE_Sign1 structure containing an attestation document
    /// with the given PCR map entries.
    fn build_cose_sign1_with_pcrs(pcrs: &[(i128, &[u8])]) -> Vec<u8> {
        use serde_cbor::Value as CborValue;
        use std::collections::BTreeMap;

        // Build PCR map
        let mut pcr_map = BTreeMap::new();
        for (idx, bytes) in pcrs {
            pcr_map.insert(CborValue::Integer(*idx), CborValue::Bytes(bytes.to_vec()));
        }

        // Build attestation document payload
        let mut att_map = BTreeMap::new();
        att_map.insert(CborValue::Text("pcrs".to_string()), CborValue::Map(pcr_map));
        let payload_bytes = serde_cbor::to_vec(&CborValue::Map(att_map)).unwrap();

        // Build COSE_Sign1: [protected, unprotected, payload, signature]
        let cose_sign1 = coset::CoseSign1Builder::new()
            .payload(payload_bytes)
            .build();

        cose_sign1.to_vec().unwrap()
    }

    #[test]
    fn test_extract_pcrs_valid() {
        let cose_bytes = build_cose_sign1_with_pcrs(&[
            (0, &[0xAA, 0xBB, 0xCC]),
            (1, &[0x11, 0x22, 0x33]),
            (2, &[0xDD, 0xEE, 0xFF]),
        ]);

        let payload = parse(&cose_bytes).unwrap();
        let result = extract_pcrs(&payload).unwrap();
        assert_eq!(result.pcr0, "aabbcc");
        assert_eq!(result.pcr1, "112233");
        assert_eq!(result.pcr2, "ddeeff");
    }

    #[test]
    fn test_extract_pcrs_missing_pcr0() {
        let cose_bytes = build_cose_sign1_with_pcrs(&[(1, &[0x11]), (2, &[0x22])]);

        let payload = parse(&cose_bytes).unwrap();
        let result = extract_pcrs(&payload);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("PCR0"));
    }

    #[test]
    fn test_extract_pcrs_missing_pcr1() {
        let cose_bytes = build_cose_sign1_with_pcrs(&[(0, &[0xAA]), (2, &[0x22])]);

        let payload = parse(&cose_bytes).unwrap();
        let result = extract_pcrs(&payload);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("PCR1"));
    }

    #[test]
    fn test_extract_pcrs_missing_pcr2() {
        let cose_bytes = build_cose_sign1_with_pcrs(&[(0, &[0xAA]), (1, &[0x11])]);

        let payload = parse(&cose_bytes).unwrap();
        let result = extract_pcrs(&payload);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("PCR2"));
    }

    #[test]
    fn test_extract_pcrs_ignores_extra_pcrs() {
        let cose_bytes = build_cose_sign1_with_pcrs(&[
            (0, &[0xAA]),
            (1, &[0xBB]),
            (2, &[0xCC]),
            (3, &[0xDD]),
            (4, &[0xEE]),
            (15, &[0xFF]),
        ]);

        let payload = parse(&cose_bytes).unwrap();
        let result = extract_pcrs(&payload).unwrap();
        assert_eq!(result.pcr0, "aa");
        assert_eq!(result.pcr1, "bb");
        assert_eq!(result.pcr2, "cc");
    }

    #[test]
    fn test_extract_pcrs_realistic_hash_length() {
        // PCRs are SHA-384 hashes (48 bytes = 96 hex chars)
        let hash = vec![0xABu8; 48];
        let cose_bytes = build_cose_sign1_with_pcrs(&[(0, &hash), (1, &hash), (2, &hash)]);

        let payload = parse(&cose_bytes).unwrap();
        let result = extract_pcrs(&payload).unwrap();
        assert_eq!(result.pcr0.len(), 96);
    }

    #[test]
    fn test_extract_pcrs_invalid_cbor() {
        let result = parse(&[0xFF, 0xFF, 0xFF]);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_pcrs_empty_input() {
        let result = parse(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_pcrs_from_payload_no_pcrs_key() {
        use serde_cbor::Value as CborValue;
        use std::collections::BTreeMap;

        let mut att_map = BTreeMap::new();
        att_map.insert(
            CborValue::Text("other".to_string()),
            CborValue::Text("value".to_string()),
        );
        let payload = serde_cbor::to_vec(&CborValue::Map(att_map)).unwrap();

        let attestation = serde_cbor::from_slice(&payload).unwrap();
        let result = extract_pcrs(&attestation);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("PCRs"));
    }

    #[test]
    fn test_extract_pcrs_from_payload_not_map() {
        let payload =
            serde_cbor::to_vec(&serde_cbor::Value::Text("not a map".to_string())).unwrap();

        let attestation = serde_cbor::from_slice(&payload).unwrap();
        let result = extract_pcrs(&attestation);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_pcrs_does_not_wrap_oversized_integer_keys() {
        let wrapped_zero = -(1_i128 << 64);
        let cose_bytes =
            build_cose_sign1_with_pcrs(&[(wrapped_zero, &[0xAA]), (1, &[0xBB]), (2, &[0xCC])]);

        let payload = parse(&cose_bytes).unwrap();
        let result = extract_pcrs(&payload);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("PCR0"));
    }

    #[test]
    fn payload_json_encodes_bytes_and_integer_keys_losslessly() {
        use std::collections::BTreeMap;

        let value = CborValue::Map(
            [(CborValue::Integer(0), CborValue::Bytes(vec![0x00, 0x01]))]
                .into_iter()
                .collect::<BTreeMap<_, _>>(),
        );

        assert_eq!(
            payload_json(&value).unwrap(),
            serde_json::json!({"0": "base64:AAE="})
        );
    }

    #[test]
    fn test_attestation_pcrs_clone() {
        let pcrs = AttestationPcrs {
            pcr0: "aaa".to_string(),
            pcr1: "bbb".to_string(),
            pcr2: "ccc".to_string(),
        };

        let cloned = pcrs.clone();
        assert_eq!(cloned.pcr0, pcrs.pcr0);
        assert_eq!(cloned.pcr1, pcrs.pcr1);
        assert_eq!(cloned.pcr2, pcrs.pcr2);
    }
}
