//! Loopback-only certificate service for quorum integration. Never a production service.
use anyhow::{ensure, Context, Result};
use public_certificate_models::{v1, Proofed, PublicCertificateBundle, PublicCertificateRequest};
use sequoia_openpgp::{
    cert::CertBuilder,
    packet::{
        signature::{subpacket::NotationDataFlags, SignatureBuilder},
        UserID,
    },
    serialize::Serialize,
    types::SignatureType,
    Cert,
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
};

fn armor(cert: &Cert) -> Result<String> {
    let mut bytes = Vec::new();
    cert.armored().serialize(&mut bytes)?;
    Ok(String::from_utf8(bytes)?)
}

fn certificate(
    ca: &Cert,
    org: [u8; 16],
    bundle: [u8; 16],
    index: usize,
    mode: &str,
) -> Result<String> {
    let uid = UserID::from(format!("Caution public certificate index={index}"));
    let mut builder = CertBuilder::new()
        .add_userid(uid.clone())
        .add_signing_subkey()
        .add_storage_encryption_subkey();
    if mode != "ineligible" {
        builder = builder.add_authentication_subkey();
    }
    let cert = builder.generate()?.0;
    let flags = NotationDataFlags::empty().set_human_readable();
    let mut signature = SignatureBuilder::new(SignatureType::PositiveCertification).set_notation(
        "organization-id@caution.co",
        hex::encode(org),
        flags.clone(),
        true,
    )?;
    if mode != "missing-notation" {
        signature =
            signature.set_notation("bundle-id@caution.co", hex::encode(bundle), flags, true)?;
    }
    let mut signer = ca
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()?
        .into_keypair()?;
    let wrong = UserID::from("wrong signed user ID");
    let sig = signature.sign_userid_binding(
        &mut signer,
        cert.primary_key().key(),
        if mode == "bad-signature" {
            &wrong
        } else {
            &uid
        },
    )?;
    armor(&cert.insert_packets(sig)?)
}

fn serve(mut stream: TcpStream, work: &Path, ca: &Cert, wrong_ca: &Cert) -> Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut first = String::new();
    reader.read_line(&mut first)?;
    let mut length = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse()?;
            }
        }
    }
    ensure!(length <= 4096, "oversized mock request");
    let (status, body) = if first.starts_with("GET /health ") {
        (200, serde_json::json!({"status":"ready"}))
    } else if first.starts_with("GET /api/quorum-bundles ") {
        // Optional CLI display metadata is unavailable on this app-only mock.
        (404, serde_json::json!({"error":"metadata unavailable"}))
    } else if first.starts_with("GET /api/resources/quorum-test ") {
        // Only used to reach the CLI's mixed-bundle rejection; no enclave exists.
        (
            200,
            serde_json::json!({"id":"quorum-test", "state":"running", "provider_resource_id":"test", "public_ip":"127.0.0.1"}),
        )
    } else {
        ensure!(
            first.starts_with("POST /v1/public-certificates "),
            "unexpected mock path: {first}"
        );
        let mut bytes = vec![0; length];
        reader.read_exact(&mut bytes)?;
        let request: PublicCertificateRequest = serde_json::from_slice(&bytes)?;
        let request = request.to_latest();
        fs::write(work.join("certificate-request.json"), &bytes)?;
        let mode = fs::read_to_string(work.join("certificate-mode")).unwrap_or_default();
        if mode == "503" {
            (503, serde_json::json!({"error":"unavailable"}))
        } else {
            let bundle_id = *uuid::Uuid::new_v4().as_bytes();
            let signer = if mode == "wrong-ca" { wrong_ca } else { ca };
            let certificates = (0..usize::from(request.certificate_count.get()))
                .map(|index| {
                    certificate(
                        signer,
                        request.organization_id,
                        if mode == "wrong-bundle" {
                            [0; 16]
                        } else {
                            bundle_id
                        },
                        if mode == "wrong-index" {
                            index + 1
                        } else {
                            index
                        },
                        &mode,
                    )
                })
                .collect::<Result<Vec<_>>>()?;
            let mut bundle = v1::PublicCertificateBundle {
                organization_id: request.organization_id,
                bundle_id,
                certificates,
            };
            match mode.as_str() {
                "wrong-org" => bundle.organization_id = [0; 16],
                "wrong-count" => {
                    bundle.certificates.pop();
                }
                "reordered" => bundle.certificates.reverse(),
                "duplicate" if bundle.certificates.len() > 1 => {
                    bundle.certificates[1] = bundle.certificates[0].clone()
                }
                _ => {}
            }
            let data = PublicCertificateBundle::V1(bundle);
            let mut proof = Sha256::digest(serde_cbor::to_vec(&data)?).to_vec();
            if mode == "wrong-proof" {
                proof[0] ^= 1;
            }
            let response = Proofed {
                data,
                necroproof: proof,
            };
            let value = serde_json::to_value(&response)?;
            fs::write(
                work.join("certificate-response.json"),
                serde_json::to_vec(&value)?,
            )?;
            (200, value)
        }
    };
    let body = serde_json::to_vec(&body)?;
    write!(stream, "HTTP/1.1 {status} mock\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())?;
    stream.write_all(&body)?;
    Ok(())
}

fn main() -> Result<()> {
    let work = std::env::args()
        .nth(1)
        .context("temporary work directory required")?;
    let work = Path::new(&work);
    let ca = CertBuilder::new()
        .add_userid("temporary quorum test CA")
        .generate()?
        .0;
    let wrong_ca = CertBuilder::new()
        .add_userid("untrusted test CA")
        .generate()?
        .0;
    fs::write(work.join("policies/caution-ca.asc"), armor(&ca)?)?;
    let listener = TcpListener::bind(format!(
        "127.0.0.1:{}",
        fs::read_to_string(work.join("certificate.port"))?.trim()
    ))?;
    for stream in listener.incoming() {
        serve(stream?, work, &ca, &wrong_ca)?;
    }
    Ok(())
}
