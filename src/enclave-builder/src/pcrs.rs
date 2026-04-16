// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result};

use crate::{EifFile, PcrValues};

pub fn extract_pcrs_from_eif(eif: &EifFile) -> Result<PcrValues> {
    let pcrs_path = eif.path.with_extension("pcrs");

    if !pcrs_path.exists() {
        anyhow::bail!(
            "PCR file not found: {}. Make sure nitro-cli build-enclave was run successfully.",
            pcrs_path.display()
        );
    }

    let pcrs_content = std::fs::read_to_string(&pcrs_path).context("Failed to read PCR file")?;

    parse_pcrs_file(&pcrs_content)
}

pub fn parse_pcrs_file(content: &str) -> Result<PcrValues> {
    let mut pcr0 = None;
    let mut pcr1 = None;
    let mut pcr2 = None;
    let mut pcr3 = None;
    let mut pcr4 = None;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let (hash, pcr_label) = if let Some((hash, label)) = line.split_once(' ') {
            (hash.trim(), label.trim())
        } else if let Some((label, hash)) = line.split_once(':') {
            (hash.trim(), label.trim())
        } else {
            continue;
        };

        match pcr_label {
            "PCR0" => pcr0 = Some(hash.to_string()),
            "PCR1" => pcr1 = Some(hash.to_string()),
            "PCR2" => pcr2 = Some(hash.to_string()),
            "PCR3" => pcr3 = Some(hash.to_string()),
            "PCR4" => pcr4 = Some(hash.to_string()),
            _ => {}
        }
    }

    Ok(PcrValues {
        pcr0: pcr0.context("PCR0 not found in file")?,
        pcr1: pcr1.context("PCR1 not found in file")?,
        pcr2: pcr2.context("PCR2 not found in file")?,
        pcr3,
        pcr4,
    })
}

pub fn parse_attestation_document(attestation_b64: &str) -> Result<PcrValues> {
    use base64::Engine;

    let attestation_bytes = base64::engine::general_purpose::STANDARD
        .decode(attestation_b64)
        .context("Failed to decode attestation document base64")?;

    let doc: serde_cbor::Value = serde_cbor::from_slice(&attestation_bytes)
        .context("Failed to parse attestation document CBOR")?;

    let array = match doc {
        serde_cbor::Value::Array(ref arr) => arr,
        _ => anyhow::bail!("Attestation document is not a CBOR array"),
    };

    if array.len() < 3 {
        anyhow::bail!("Invalid COSE_Sign1 structure");
    }

    let payload_bytes = match &array[2] {
        serde_cbor::Value::Bytes(bytes) => bytes,
        _ => anyhow::bail!("Payload is not bytes"),
    };

    let attestation: serde_cbor::Value =
        serde_cbor::from_slice(payload_bytes).context("Failed to parse attestation payload")?;

    let attestation_map = match attestation {
        serde_cbor::Value::Map(ref map) => map,
        _ => anyhow::bail!("Attestation is not a map"),
    };

    let pcrs_key = serde_cbor::Value::Text("pcrs".to_string());
    let pcrs_map = match attestation_map.get(&pcrs_key) {
        Some(serde_cbor::Value::Map(ref map)) => map,
        _ => anyhow::bail!("No PCRs found in attestation document"),
    };

    let mut pcr_values = PcrValues {
        pcr0: String::new(),
        pcr1: String::new(),
        pcr2: String::new(),
        pcr3: None,
        pcr4: None,
    };

    for (key, value) in pcrs_map {
        let pcr_num = match key {
            serde_cbor::Value::Integer(n) => *n as i64,
            _ => continue,
        };

        let pcr_bytes = match value {
            serde_cbor::Value::Bytes(bytes) => bytes,
            _ => continue,
        };

        let pcr_hex = hex::encode(pcr_bytes);

        match pcr_num {
            0 => pcr_values.pcr0 = pcr_hex,
            1 => pcr_values.pcr1 = pcr_hex,
            2 => pcr_values.pcr2 = pcr_hex,
            3 => pcr_values.pcr3 = Some(pcr_hex),
            4 => pcr_values.pcr4 = Some(pcr_hex),
            _ => {}
        }
    }

    if pcr_values.pcr0.is_empty() || pcr_values.pcr1.is_empty() || pcr_values.pcr2.is_empty() {
        anyhow::bail!("Missing required PCRs (0, 1, or 2) in attestation document");
    }

    Ok(pcr_values)
}

pub fn is_debug_mode(pcrs: &PcrValues) -> bool {
    let is_zero = |s: &str| s.chars().all(|c| c == '0');

    is_zero(&pcrs.pcr0) || is_zero(&pcrs.pcr1) || is_zero(&pcrs.pcr2)
}

pub fn format_pcrs(pcrs: &PcrValues) -> String {
    let mut output = String::new();

    output.push_str(&format!("{} PCR0\n", pcrs.pcr0));
    output.push_str(&format!("{} PCR1\n", pcrs.pcr1));
    output.push_str(&format!("{} PCR2\n", pcrs.pcr2));

    if let Some(ref pcr3) = pcrs.pcr3 {
        output.push_str(&format!("{} PCR3\n", pcr3));
    }

    if let Some(ref pcr4) = pcrs.pcr4 {
        output.push_str(&format!("{} PCR4\n", pcr4));
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pcrs_file() {
        let content = r#"
d4f748865131ffc30929eff73c5d651dc2e6d795d8f47b3ec27208b2d293a6c040fc4db6dc44c02b8e5fc34f65b3d595 PCR0
d4f748865131ffc30929eff73c5d651dc2e6d795d8f47b3ec27208b2d293a6c040fc4db6dc44c02b8e5fc34f65b3d595 PCR1
21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a PCR2
        "#;

        let pcrs = parse_pcrs_file(content).unwrap();
        assert_eq!(
            pcrs.pcr0,
            "d4f748865131ffc30929eff73c5d651dc2e6d795d8f47b3ec27208b2d293a6c040fc4db6dc44c02b8e5fc34f65b3d595"
        );
        assert_eq!(
            pcrs.pcr2,
            "21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a"
        );
    }

    #[test]
    fn test_parse_pcrs_file_colon_format() {
        let content = r#"
PCR0:d4f748865131ffc30929eff73c5d651dc2e6d795d8f47b3ec27208b2d293a6c040fc4db6dc44c02b8e5fc34f65b3d595
PCR1:aabbccdd
PCR2:11223344
        "#;

        let pcrs = parse_pcrs_file(content).unwrap();
        assert_eq!(
            pcrs.pcr0,
            "d4f748865131ffc30929eff73c5d651dc2e6d795d8f47b3ec27208b2d293a6c040fc4db6dc44c02b8e5fc34f65b3d595"
        );
        assert_eq!(pcrs.pcr1, "aabbccdd");
        assert_eq!(pcrs.pcr2, "11223344");
    }

    #[test]
    fn test_parse_pcrs_file_with_pcr3_pcr4() {
        let content = r#"
aaa PCR0
bbb PCR1
ccc PCR2
ddd PCR3
eee PCR4
        "#;

        let pcrs = parse_pcrs_file(content).unwrap();
        assert_eq!(pcrs.pcr0, "aaa");
        assert_eq!(pcrs.pcr1, "bbb");
        assert_eq!(pcrs.pcr2, "ccc");
        assert_eq!(pcrs.pcr3, Some("ddd".to_string()));
        assert_eq!(pcrs.pcr4, Some("eee".to_string()));
    }

    #[test]
    fn test_parse_pcrs_file_missing_required() {
        let content = "aaa PCR0\nbbb PCR1\n";
        assert!(parse_pcrs_file(content).is_err()); // missing PCR2
    }

    #[test]
    fn test_parse_pcrs_file_empty() {
        assert!(parse_pcrs_file("").is_err());
    }

    #[test]
    fn test_parse_pcrs_file_ignores_blank_lines() {
        let content = "\n\naaa PCR0\n\nbbb PCR1\n\nccc PCR2\n\n";
        let pcrs = parse_pcrs_file(content).unwrap();
        assert_eq!(pcrs.pcr0, "aaa");
    }

    #[test]
    fn test_parse_pcrs_file_ignores_unknown_labels() {
        let content = "aaa PCR0\nbbb PCR1\nccc PCR2\nddd PCR99\n";
        let pcrs = parse_pcrs_file(content).unwrap();
        assert_eq!(pcrs.pcr0, "aaa");
        assert!(pcrs.pcr3.is_none());
    }

    #[test]
    fn test_is_debug_mode() {
        let production_pcrs = PcrValues {
            pcr0: "abc123".to_string(),
            pcr1: "def456".to_string(),
            pcr2: "ghi789".to_string(),
            pcr3: None,
            pcr4: None,
        };

        let debug_pcrs = PcrValues {
            pcr0: "000000000000".to_string(),
            pcr1: "000000000000".to_string(),
            pcr2: "000000000000".to_string(),
            pcr3: None,
            pcr4: None,
        };

        assert!(!is_debug_mode(&production_pcrs));
        assert!(is_debug_mode(&debug_pcrs));
    }

    #[test]
    fn test_is_debug_mode_single_zero_pcr() {
        // Any single PCR being all zeros should trigger debug mode
        let pcrs = PcrValues {
            pcr0: "000000000000".to_string(),
            pcr1: "abc123".to_string(),
            pcr2: "def456".to_string(),
            pcr3: None,
            pcr4: None,
        };
        assert!(is_debug_mode(&pcrs));

        let pcrs = PcrValues {
            pcr0: "abc123".to_string(),
            pcr1: "000000".to_string(),
            pcr2: "def456".to_string(),
            pcr3: None,
            pcr4: None,
        };
        assert!(is_debug_mode(&pcrs));
    }

    #[test]
    fn test_is_debug_mode_pcr3_pcr4_ignored() {
        // PCR3 and PCR4 being zero should not trigger debug mode
        let pcrs = PcrValues {
            pcr0: "abc123".to_string(),
            pcr1: "def456".to_string(),
            pcr2: "ghi789".to_string(),
            pcr3: Some("000000".to_string()),
            pcr4: Some("000000".to_string()),
        };
        assert!(!is_debug_mode(&pcrs));
    }

    #[test]
    fn test_format_pcrs_basic() {
        let pcrs = PcrValues {
            pcr0: "aaa".to_string(),
            pcr1: "bbb".to_string(),
            pcr2: "ccc".to_string(),
            pcr3: None,
            pcr4: None,
        };

        let output = format_pcrs(&pcrs);
        assert!(output.contains("aaa PCR0"));
        assert!(output.contains("bbb PCR1"));
        assert!(output.contains("ccc PCR2"));
        assert!(!output.contains("PCR3"));
        assert!(!output.contains("PCR4"));
    }

    #[test]
    fn test_format_pcrs_with_optional() {
        let pcrs = PcrValues {
            pcr0: "aaa".to_string(),
            pcr1: "bbb".to_string(),
            pcr2: "ccc".to_string(),
            pcr3: Some("ddd".to_string()),
            pcr4: Some("eee".to_string()),
        };

        let output = format_pcrs(&pcrs);
        assert!(output.contains("ddd PCR3"));
        assert!(output.contains("eee PCR4"));
    }

    #[test]
    fn test_format_pcrs_round_trip() {
        let pcrs = PcrValues {
            pcr0: "aaa".to_string(),
            pcr1: "bbb".to_string(),
            pcr2: "ccc".to_string(),
            pcr3: Some("ddd".to_string()),
            pcr4: Some("eee".to_string()),
        };

        let formatted = format_pcrs(&pcrs);
        let parsed = parse_pcrs_file(&formatted).unwrap();

        assert_eq!(pcrs.pcr0, parsed.pcr0);
        assert_eq!(pcrs.pcr1, parsed.pcr1);
        assert_eq!(pcrs.pcr2, parsed.pcr2);
        assert_eq!(pcrs.pcr3, parsed.pcr3);
        assert_eq!(pcrs.pcr4, parsed.pcr4);
    }
}
