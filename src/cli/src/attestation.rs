// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose};
use coset::CborSerializable;
use serde_cbor::Value as CborValue;
use serde_json::{Map as JsonMap, Number as JsonNumber, Value as JsonValue};

#[derive(Debug, Clone)]
pub struct AttestationPcrs {
    pub pcr0: String,
    pub pcr1: String,
    pub pcr2: String,
}

pub fn parse(attestation_bytes: &[u8]) -> Result<CborValue> {
    let cose_sign1 = coset::CoseSign1::from_slice(attestation_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse COSE_Sign1: {:?}", e))?;

    let payload = cose_sign1
        .payload
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No payload in COSE_Sign1"))?;
    serde_cbor::from_slice(payload).context("Failed to parse attestation payload as CBOR")
}

pub fn extract_pcrs(attestation: &CborValue) -> Result<AttestationPcrs> {
    let attestation_map = match attestation {
        CborValue::Map(map) => map,
        _ => bail!("Attestation payload is not a CBOR map"),
    };

    let pcrs_key = CborValue::Text("pcrs".to_string());
    let pcrs_map = match attestation_map.get(&pcrs_key) {
        Some(CborValue::Map(map)) => map,
        _ => bail!("No PCRs found in attestation document"),
    };

    let pcr = |index: i128, missing: &'static str| match pcrs_map.get(&CborValue::Integer(index)) {
        Some(CborValue::Bytes(bytes)) => Ok(hex::encode(bytes)),
        _ => Err(anyhow::anyhow!(missing)),
    };

    Ok(AttestationPcrs {
        pcr0: pcr(0, "PCR0 not found in attestation document")?,
        pcr1: pcr(1, "PCR1 not found in attestation document")?,
        pcr2: pcr(2, "PCR2 not found in attestation document")?,
    })
}

pub fn payload_json(value: &CborValue) -> Result<JsonValue> {
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
        CborValue::Float(value) => JsonNumber::from_f64(*value)
            .map(JsonValue::Number)
            .context("CBOR float cannot be represented as JSON")?,
        CborValue::Bytes(value) => {
            let mut encoded = String::from("base64:");
            general_purpose::STANDARD.encode_string(value, &mut encoded);
            JsonValue::String(encoded)
        }
        CborValue::Text(value) => JsonValue::String(value.clone()),
        CborValue::Array(values) => JsonValue::Array(
            values
                .iter()
                .map(payload_json)
                .collect::<Result<Vec<_>>>()?,
        ),
        CborValue::Map(values) => {
            let mut map = JsonMap::new();
            for (key, value) in values {
                let key = match key {
                    CborValue::Text(key) => key.clone(),
                    CborValue::Integer(key) => key.to_string(),
                    _ => bail!("CBOR map key cannot be represented as a JSON object key"),
                };
                if map.insert(key, payload_json(value)?).is_some() {
                    bail!("CBOR map keys collide when represented as JSON");
                }
            }
            JsonValue::Object(map)
        }
        CborValue::Tag(tag, value) => serde_json::json!({
            "tag": tag,
            "value": payload_json(value)?,
        }),
        _ => bail!("Unsupported CBOR value"),
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

        let result = parse(&cose_bytes).and_then(|payload| extract_pcrs(&payload));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("PCR0"));
    }

    #[test]
    fn test_extract_pcrs_missing_pcr1() {
        let cose_bytes = build_cose_sign1_with_pcrs(&[(0, &[0xAA]), (2, &[0x22])]);

        let result = parse(&cose_bytes).and_then(|payload| extract_pcrs(&payload));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("PCR1"));
    }

    #[test]
    fn test_extract_pcrs_missing_pcr2() {
        let cose_bytes = build_cose_sign1_with_pcrs(&[(0, &[0xAA]), (1, &[0x11])]);

        let result = parse(&cose_bytes).and_then(|payload| extract_pcrs(&payload));
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

        let result = parse(&cose_bytes).and_then(|payload| extract_pcrs(&payload));
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
