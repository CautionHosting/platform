// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result, bail};
use base64::Engine;
use serde_cbor::Value as CborValue;
use coset::CborSerializable;

const AWS_NITRO_ROOT_CA_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----"#;

#[derive(Debug, Clone)]
pub struct AttestationPcrs {
    pub pcr0: String,
    pub pcr1: String,
    pub pcr2: String,
    pub pcr3: Option<String>,
    pub pcr4: Option<String>,
    pub nonce: Vec<u8>,
}

pub fn verify_attestation(attestation_b64: &str, expected_nonce: &[u8]) -> Result<AttestationPcrs> {
    let attestation_bytes = base64::engine::general_purpose::STANDARD
        .decode(attestation_b64)
        .context("Failed to decode attestation document base64")?;

    let cose_sign1: coset::CoseSign1 = coset::CoseSign1::from_slice(&attestation_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse COSE_Sign1 structure: {:?}", e))?;

    let payload = cose_sign1.payload.as_ref()
        .ok_or_else(|| anyhow::anyhow!("No payload in COSE_Sign1"))?;

    let (cert, cabundle) = extract_certificates_from_payload(payload)
        .context("Failed to extract certificates from payload")?;

    verify_certificate_chain(&cert, &cabundle)
        .context("Certificate chain verification failed")?;

    verify_cose_signature(&cose_sign1, &cert)
        .context("COSE signature verification failed")?;

    let nonce = extract_nonce(payload)
        .context("Failed to extract nonce from attestation document")?;

    if nonce != expected_nonce {
        bail!("Nonce mismatch: expected {} bytes, got {} bytes. This may indicate a replay attack!",
            expected_nonce.len(), nonce.len());
    }

    println!("✓ Nonce verified (prevents replay attacks)");

    let mut pcrs = extract_pcrs(payload)
        .context("Failed to extract PCRs from payload")?;

    pcrs.nonce = nonce;

    Ok(pcrs)
}

fn is_debug() -> bool {
    std::env::var("CAUTION_DEBUG").is_ok() || std::env::var("RUST_LOG").is_ok()
}

fn extract_certificates_from_payload(payload: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>)> {
    if is_debug() {
        println!("\n=== DEBUG: Extracting Certificates from Payload ===");
        println!("Payload length: {} bytes", payload.len());
    }

    let doc: CborValue = serde_cbor::from_slice(payload)
        .context("Failed to parse attestation payload as CBOR")?;

    let doc_map = match doc {
        CborValue::Map(ref map) => map,
        _ => bail!("Attestation payload is not a CBOR map"),
    };

    if is_debug() {
        println!("Attestation document fields:");
        for (key, _value) in doc_map {
            if let CborValue::Text(field_name) = key {
                println!("  - {}", field_name);
            }
        }
    }

    let cert_key = CborValue::Text("certificate".to_string());
    let certificate = match doc_map.get(&cert_key) {
        Some(CborValue::Bytes(cert_bytes)) => cert_bytes.clone(),
        _ => bail!("No 'certificate' field found in attestation document"),
    };

    if is_debug() {
        println!("Found certificate: {} bytes", certificate.len());
    }

    let cabundle_key = CborValue::Text("cabundle".to_string());
    let cabundle = match doc_map.get(&cabundle_key) {
        Some(CborValue::Array(certs)) => {
            let mut cert_chain = Vec::new();
            for cert_value in certs {
                if let CborValue::Bytes(cert_bytes) = cert_value {
                    cert_chain.push(cert_bytes.clone());
                }
            }
            if cert_chain.is_empty() {
                bail!("Empty cabundle in attestation document");
            }
            cert_chain
        }
        _ => bail!("No 'cabundle' field found in attestation document"),
    };

    if is_debug() {
        println!("Found CA bundle: {} certificates", cabundle.len());
        for (i, cert) in cabundle.iter().enumerate() {
            println!("  CA cert {}: {} bytes", i, cert.len());
        }
    }

    Ok((certificate, cabundle))
}

fn verify_certificate_chain(nsm_cert: &[u8], cabundle: &[Vec<u8>]) -> Result<()> {
    if is_debug() {
        println!("\n=== DEBUG: Verifying Certificate Chain ===");
        println!("NSM certificate: {} bytes", nsm_cert.len());
        println!("CA bundle: {} certificates", cabundle.len());
    }

    let root_ca_pem = pem::parse(AWS_NITRO_ROOT_CA_PEM)
        .context("Failed to parse AWS Nitro root CA PEM")?;

    if is_debug() {
        let root_ca = x509_parser::parse_x509_certificate(&root_ca_pem.contents())
            .context("Failed to parse root CA certificate")?
            .1;
        println!("Loaded AWS Nitro root CA: {}", root_ca.subject());

        let nsm_cert_parsed = x509_parser::parse_x509_certificate(nsm_cert)
            .context("Failed to parse NSM certificate")?
            .1;
        println!("NSM certificate subject: {}", nsm_cert_parsed.subject());
        println!("NSM certificate issuer: {}", nsm_cert_parsed.issuer());

        println!("\nCA Bundle certificates:");
        for (i, ca_cert_der) in cabundle.iter().enumerate() {
            if let Ok((_, ca_cert)) = x509_parser::parse_x509_certificate(ca_cert_der) {
                println!("  CA {}: {}", i, ca_cert.subject());
            }
        }
    }

    let trust_anchor = webpki::TrustAnchor::try_from_cert_der(&root_ca_pem.contents())
        .map_err(|e| anyhow::anyhow!("Failed to create trust anchor: {:?}", e))?;

    let intermediates: Vec<&[u8]> = cabundle.iter().map(|c| c.as_slice()).collect();

    if is_debug() {
        println!("\nBuilding certificate chain:");
        println!("  Trust anchor: AWS Nitro Root CA");
        println!("  Intermediates: {} certificates", intermediates.len());
        println!("  End entity: NSM certificate");
    }

    let ee_cert = webpki::EndEntityCert::try_from(nsm_cert)
        .map_err(|e| anyhow::anyhow!("Failed to parse NSM certificate as end-entity: {:?}", e))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("Failed to get current time")?
        .as_secs();
    let time = webpki::Time::from_seconds_since_unix_epoch(now);

    if is_debug() {
        println!("Verification time: {} seconds since epoch", now);
    }

    ee_cert.verify_is_valid_tls_server_cert(
        &[&webpki::ECDSA_P384_SHA384],
        &webpki::TlsServerTrustAnchors(&[trust_anchor]),
        &intermediates,
        time,
    ).map_err(|e| anyhow::anyhow!("Certificate chain verification failed: {:?}", e))?;

    println!("✓ Certificate chain verified against AWS Nitro root CA");
    println!("✓ All certificates are within validity period");

    Ok(())
}

fn verify_cose_signature(cose_sign1: &coset::CoseSign1, leaf_cert_der: &[u8]) -> Result<()> {
    if is_debug() {
        println!("\n=== DEBUG: Verifying COSE Signature ===");
    }

    let cert = x509_parser::parse_x509_certificate(leaf_cert_der)
        .context("Failed to parse certificate")?
        .1;

    let public_key_info = cert.public_key();
    let public_key_bytes = public_key_info.subject_public_key.data.as_ref(); // Raw EC point (e.g., 97 bytes for P-384)

    if is_debug() {
        println!("Public key algorithm: {:?}", public_key_info.algorithm);
        println!("Public key data length: {} bytes", public_key_bytes.len());
        println!("First bytes of public key: {:02x?}", &public_key_bytes[..public_key_bytes.len().min(20)]);
    }

    // Get the algorithm from protected headers
    let alg = cose_sign1.protected.header.alg.as_ref()
        .ok_or_else(|| anyhow::anyhow!("No algorithm specified in protected headers"))?;

    if is_debug() {
        println!("COSE algorithm: {:?}", alg);
    }

    let sig_structure = coset::sig_structure_data(
        coset::SignatureContext::CoseSign1,
        cose_sign1.protected.clone(),
        None,
        &[],
        cose_sign1.payload.as_ref().unwrap(),
    );

    if is_debug() {
        println!("Sig_structure length: {} bytes", sig_structure.len());
        println!("Signature length: {} bytes", cose_sign1.signature.len());
        println!("First bytes of signature: {:02x?}", &cose_sign1.signature[..cose_sign1.signature.len().min(20)]);
    }

    use coset::RegisteredLabelWithPrivate;
    match alg {
        RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::ES384) => {
            verify_ecdsa_signature(&sig_structure, &cose_sign1.signature, public_key_bytes, &ring::signature::ECDSA_P384_SHA384_ASN1)
                .context("ECDSA P-384 signature verification failed")?;
        }
        _ => {
            bail!("Unsupported signature algorithm: {:?}", alg);
        }
    }

    println!("✓ COSE signature verification passed");
    Ok(())
}

fn cose_signature_to_der(raw_sig: &[u8]) -> Result<Vec<u8>> {
    if raw_sig.len() != 96 {
        bail!("Invalid P-384 signature length: expected 96 bytes, got {}", raw_sig.len());
    }

    let r = &raw_sig[0..48];
    let s = &raw_sig[48..96];

    fn encode_integer(value: &[u8]) -> Vec<u8> {
        let mut result = vec![0x02];

        let needs_padding = value[0] & 0x80 != 0;

        if needs_padding {
            result.push((value.len() + 1) as u8);
            result.push(0x00);
            result.extend_from_slice(value);
        } else {
            let start = value.iter().position(|&b| b != 0).unwrap_or(value.len() - 1);
            let trimmed = &value[start..];
            result.push(trimmed.len() as u8);
            result.extend_from_slice(trimmed);
        }

        result
    }

    let r_der = encode_integer(r);
    let s_der = encode_integer(s);

    let mut der = vec![0x30];
    let content_len = r_der.len() + s_der.len();
    der.push(content_len as u8);
    der.extend_from_slice(&r_der);
    der.extend_from_slice(&s_der);

    if is_debug() {
        println!("Converted COSE signature to DER:");
        println!("  Raw length: {} bytes", raw_sig.len());
        println!("  DER length: {} bytes", der.len());
        println!("  DER: {:02x?}", &der[..der.len().min(40)]);
    }

    Ok(der)
}

fn verify_ecdsa_signature(
    message: &[u8],
    signature: &[u8],
    public_key_bytes: &[u8],
    algorithm: &'static ring::signature::EcdsaVerificationAlgorithm,
) -> Result<()> {
    let signature_der = cose_signature_to_der(signature)?;

    let public_key = ring::signature::UnparsedPublicKey::new(algorithm, public_key_bytes);

    public_key
        .verify(message, &signature_der)
        .map_err(|e| anyhow::anyhow!("ECDSA signature verification failed: {:?}", e))?;

    Ok(())
}

fn extract_pcrs(payload: &[u8]) -> Result<AttestationPcrs> {
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
    let mut pcr3 = None;
    let mut pcr4 = None;

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
            3 => pcr3 = Some(pcr_hex),
            4 => pcr4 = Some(pcr_hex),
            _ => {}
        }
    }

    Ok(AttestationPcrs {
        pcr0: pcr0.context("PCR0 not found in attestation document")?,
        pcr1: pcr1.context("PCR1 not found in attestation document")?,
        pcr2: pcr2.context("PCR2 not found in attestation document")?,
        pcr3,
        pcr4,
        nonce: Vec::new(),
    })
}

fn extract_nonce(payload: &[u8]) -> Result<Vec<u8>> {
    let attestation: CborValue = serde_cbor::from_slice(payload)
        .context("Failed to parse attestation payload as CBOR")?;

    let attestation_map = match attestation {
        CborValue::Map(ref map) => map,
        _ => bail!("Attestation payload is not a CBOR map"),
    };

    let nonce_key = CborValue::Text("nonce".to_string());
    match attestation_map.get(&nonce_key) {
        Some(CborValue::Bytes(nonce_bytes)) => {
            if is_debug() {
                println!("Extracted nonce: {} bytes", nonce_bytes.len());
            }
            Ok(nonce_bytes.clone())
        }
        Some(_) => bail!("Nonce field has wrong type (expected bytes)"),
        None => bail!("No nonce found in attestation document - attestation service must include nonce in request"),
    }
}
