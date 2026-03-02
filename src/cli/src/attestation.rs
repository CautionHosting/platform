// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result, bail};
use serde_cbor::Value as CborValue;
use coset::CborSerializable;

#[derive(Debug, Clone)]
pub struct AttestationPcrs {
    pub pcr0: String,
    pub pcr1: String,
    pub pcr2: String,
}

pub fn extract_pcrs(attestation_bytes: &[u8]) -> Result<AttestationPcrs> {
    let cose_sign1 = coset::CoseSign1::from_slice(attestation_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse COSE_Sign1: {:?}", e))?;

    let payload = cose_sign1.payload.as_ref()
        .ok_or_else(|| anyhow::anyhow!("No payload in COSE_Sign1"))?;

    extract_pcrs_from_payload(payload)
}

fn extract_pcrs_from_payload(payload: &[u8]) -> Result<AttestationPcrs> {
    let attestation: CborValue = serde_cbor::from_slice(payload)
        .context("Failed to parse attestation payload as CBOR")?;

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
