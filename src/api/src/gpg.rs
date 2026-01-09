// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! GPG decryption for managed on-prem credential payloads using sequoia-openpgp.
//!
//! Env vars for the private key:
//! - CAUTION_GPG_PRIVATE_KEY: ASCII-armored or base64-encoded key content
//! - CAUTION_GPG_KEY_PATH: path to key file

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use openpgp::armor::{Kind, Reader, ReaderMode};
use openpgp::cert::prelude::*;
use openpgp::crypto::SessionKey;
use openpgp::packet::prelude::*;
use openpgp::parse::{Parse, PacketParser, PacketParserResult};
use openpgp::policy::StandardPolicy;
use openpgp::types::SymmetricAlgorithm;
use sequoia_openpgp as openpgp;
use std::io::Read;

pub fn decrypt_gpg_message(encrypted_content: &str) -> Result<String, String> {
    let trimmed = encrypted_content.trim();
    if !trimmed.starts_with("-----BEGIN PGP MESSAGE-----") {
        return Err("Content does not appear to be a GPG-encrypted message".to_string());
    }

    let key_content = get_private_key()?;
    let cert = load_cert(&key_content)?;
    let policy = StandardPolicy::new();

    let mut reader = Reader::from_reader(
        std::io::Cursor::new(trimmed),
        ReaderMode::Tolerant(Some(Kind::Message)),
    );
    let mut dearmored = Vec::new();
    reader.read_to_end(&mut dearmored)
        .map_err(|e| format!("Failed to dearmor message: {}", e))?;

    let mut ppr = PacketParser::from_bytes(&dearmored)
        .map_err(|e| format!("Failed to parse packets: {}", e))?;

    let mut session_key: Option<(SymmetricAlgorithm, SessionKey)> = None;

    // First pass: find and decrypt the session key
    while let PacketParserResult::Some(pp) = ppr {
        let (packet, next_ppr) = pp.recurse()
            .map_err(|e| format!("Failed to recurse packet: {}", e))?;

        if let Packet::PKESK(pkesk) = &packet {
            for key in cert.keys()
                .with_policy(&policy, None)
                .for_transport_encryption()
                .for_storage_encryption()
                .secret()
            {
                let mut keypair = match key.key().clone().parts_into_secret() {
                    Ok(k) => match k.into_keypair() {
                        Ok(kp) => kp,
                        Err(_) => continue,
                    },
                    Err(_) => continue,
                };

                if let Some((algo, sk)) = pkesk.decrypt(&mut keypair, None) {
                    session_key = Some((algo, sk));
                    break;
                }
            }
        }

        ppr = next_ppr;
    }

    let (algo, sk) = session_key
        .ok_or_else(|| "Could not decrypt session key with available keys".to_string())?;

    // Second pass: decrypt the actual data
    let mut ppr = PacketParser::from_bytes(&dearmored)
        .map_err(|e| format!("Failed to re-parse packets: {}", e))?;

    let mut decrypted_data = Vec::new();

    while let PacketParserResult::Some(mut pp) = ppr {
        tracing::debug!("Processing packet: {:?}", pp.packet.tag());
        match &pp.packet {
            Packet::SEIP(_) | Packet::AED(_) => {
                tracing::debug!("Decrypting SEIP/AED packet");
                pp.decrypt(algo, &sk)
                    .map_err(|e| format!("Failed to decrypt SEIP: {}", e))?;
                let (_, next_ppr) = pp.recurse()
                    .map_err(|e| format!("Failed to recurse decrypted: {}", e))?;
                ppr = next_ppr;
            }
            Packet::Literal(lit) => {
                tracing::debug!("Found literal packet, filename: {:?}", lit.filename());
                let mut body = Vec::new();
                pp.read_to_end(&mut body)
                    .map_err(|e| format!("Failed to read literal body: {}", e))?;
                tracing::debug!("Read {} bytes from literal packet", body.len());
                decrypted_data = body;
                let (_, next_ppr) = pp.recurse()
                    .map_err(|e| format!("Failed to recurse literal: {}", e))?;
                ppr = next_ppr;
            }
            Packet::CompressedData(cd) => {
                tracing::debug!("Found compressed data packet, algo: {:?}", cd.algo());
                let (_, next_ppr) = pp.recurse()
                    .map_err(|e| format!("Failed to decompress: {}", e))?;
                ppr = next_ppr;
            }
            _ => {
                tracing::debug!("Skipping packet: {:?}", pp.packet.tag());
                let (_, next_ppr) = pp.recurse()
                    .map_err(|e| format!("Failed to skip packet: {}", e))?;
                ppr = next_ppr;
            }
        }
    }

    if decrypted_data.is_empty() {
        return Err("No literal data found in decrypted message".to_string());
    }

    String::from_utf8(decrypted_data)
        .map_err(|e| format!("Decrypted content is not valid UTF-8: {}", e))
}

fn get_private_key() -> Result<String, String> {
    if let Ok(key_content) = std::env::var("CAUTION_GPG_PRIVATE_KEY") {
        if key_content.trim().starts_with("-----BEGIN PGP") {
            return Ok(key_content);
        }
        let decoded = BASE64.decode(key_content.trim())
            .map_err(|e| format!("Failed to decode base64 key: {}", e))?;
        return String::from_utf8(decoded)
            .map_err(|e| format!("Decoded key is not valid UTF-8: {}", e));
    }

    if let Ok(key_path) = std::env::var("CAUTION_GPG_KEY_PATH") {
        return std::fs::read_to_string(&key_path)
            .map_err(|e| format!("Failed to read key file {}: {}", key_path, e));
    }

    Err("No GPG private key configured. Set CAUTION_GPG_PRIVATE_KEY or CAUTION_GPG_KEY_PATH".to_string())
}

fn load_cert(key_content: &str) -> Result<Cert, String> {
    Cert::from_reader(key_content.as_bytes())
        .map_err(|e| format!("Failed to parse GPG key: {}", e))
}

pub fn is_gpg_encrypted(content: &str) -> bool {
    content.trim().starts_with("-----BEGIN PGP MESSAGE-----")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_gpg_encrypted() {
        assert!(is_gpg_encrypted("-----BEGIN PGP MESSAGE-----\nsome content\n-----END PGP MESSAGE-----"));
        assert!(is_gpg_encrypted("  -----BEGIN PGP MESSAGE-----\n"));
        assert!(!is_gpg_encrypted("{\"json\": \"data\"}"));
        assert!(!is_gpg_encrypted("plain text"));
    }
}
