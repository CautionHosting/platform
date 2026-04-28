// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result, bail};
use coset::CborSerializable;
use serde_cbor::Value as CborValue;

#[derive(Debug, Clone)]
pub struct AttestationPcrs {
    pub pcr0: String,
    pub pcr1: String,
    pub pcr2: String,
}

pub fn extract_pcrs(attestation_bytes: &[u8]) -> Result<AttestationPcrs> {
    let cose_sign1 = coset::CoseSign1::from_slice(attestation_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse COSE_Sign1: {:?}", e))?;

    let payload = cose_sign1
        .payload
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No payload in COSE_Sign1"))?;

    extract_pcrs_from_payload(payload)
}

fn extract_pcrs_from_payload(payload: &[u8]) -> Result<AttestationPcrs> {
    let attestation: CborValue =
        serde_cbor::from_slice(payload).context("Failed to parse attestation payload as CBOR")?;

    let attestation_map = match attestation {
        CborValue::Map(map) => map,
        _ => bail!("Attestation payload is not a CBOR map"),
    };

    let pcrs_key = CborValue::Text("pcrs".to_string());
    let pcrs_map = match attestation_map.get(&pcrs_key) {
        Some(CborValue::Map(map)) => map,
        _ => bail!("No PCRs found in attestation document"),
    };

    let mut pcr0 = None;
    let mut pcr1 = None;
    let mut pcr2 = None;

    for (key, value) in pcrs_map {
        let pcr_num = match key {
            CborValue::Integer(n) => *n as i64,
            _ => continue,
        };

        let pcr_hex = match value {
            CborValue::Bytes(bytes) => hex::encode(bytes),
            _ => continue,
        };

        match pcr_num {
            0 => pcr0 = Some(pcr_hex),
            1 => pcr1 = Some(pcr_hex),
            2 => pcr2 = Some(pcr_hex),
            _ => {}
        }
    }

    Ok(AttestationPcrs {
        pcr0: pcr0.context("PCR0 not found in attestation document")?,
        pcr1: pcr1.context("PCR1 not found in attestation document")?,
        pcr2: pcr2.context("PCR2 not found in attestation document")?,
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

        let result = extract_pcrs(&cose_bytes).unwrap();
        assert_eq!(result.pcr0, "aabbcc");
        assert_eq!(result.pcr1, "112233");
        assert_eq!(result.pcr2, "ddeeff");
    }

    #[test]
    fn test_extract_pcrs_missing_pcr0() {
        let cose_bytes = build_cose_sign1_with_pcrs(&[(1, &[0x11]), (2, &[0x22])]);

        let result = extract_pcrs(&cose_bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("PCR0"));
    }

    #[test]
    fn test_extract_pcrs_missing_pcr1() {
        let cose_bytes = build_cose_sign1_with_pcrs(&[(0, &[0xAA]), (2, &[0x22])]);

        let result = extract_pcrs(&cose_bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("PCR1"));
    }

    #[test]
    fn test_extract_pcrs_missing_pcr2() {
        let cose_bytes = build_cose_sign1_with_pcrs(&[(0, &[0xAA]), (1, &[0x11])]);

        let result = extract_pcrs(&cose_bytes);
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

        let result = extract_pcrs(&cose_bytes).unwrap();
        assert_eq!(result.pcr0, "aa");
        assert_eq!(result.pcr1, "bb");
        assert_eq!(result.pcr2, "cc");
    }

    #[test]
    fn test_extract_pcrs_realistic_hash_length() {
        // PCRs are SHA-384 hashes (48 bytes = 96 hex chars)
        let hash = vec![0xABu8; 48];
        let cose_bytes = build_cose_sign1_with_pcrs(&[(0, &hash), (1, &hash), (2, &hash)]);

        let result = extract_pcrs(&cose_bytes).unwrap();
        assert_eq!(result.pcr0.len(), 96);
    }

    #[test]
    fn test_extract_pcrs_invalid_cbor() {
        let result = extract_pcrs(&[0xFF, 0xFF, 0xFF]);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_pcrs_empty_input() {
        let result = extract_pcrs(&[]);
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

        let result = extract_pcrs_from_payload(&payload);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("PCRs"));
    }

    #[test]
    fn test_extract_pcrs_from_payload_not_map() {
        let payload =
            serde_cbor::to_vec(&serde_cbor::Value::Text("not a map".to_string())).unwrap();

        let result = extract_pcrs_from_payload(&payload);
        assert!(result.is_err());
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
