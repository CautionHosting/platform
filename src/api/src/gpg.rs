// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! GPG decryption for managed on-prem credential payloads using sequoia-openpgp.
//!
//! Env vars for the private key:
//! - CAUTION_GPG_PRIVATE_KEY: ASCII-armored or base64-encoded key content
//! - CAUTION_GPG_KEY_PATH: path to key file

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use dterror::{BoxError, CtxError, Location, ResultExt};
use openpgp::armor::{Kind, Reader, ReaderMode};
use openpgp::cert::prelude::*;
use openpgp::crypto::SessionKey;
use openpgp::packet::prelude::*;
use openpgp::parse::{PacketParser, PacketParserResult, Parse};
use openpgp::policy::StandardPolicy;
use openpgp::types::SymmetricAlgorithm;
use sequoia_openpgp as openpgp;
use std::io::Read;

/// Failure modes for [`decrypt_gpg_message`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum DecryptGpgMessageError {
    #[error("content does not appear to be a GPG-encrypted message [{location}]")]
    NotGpgMessage { location: Location },

    #[error("could not load the private key [{location}]")]
    GetKey {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not parse the GPG certificate [{location}]")]
    LoadCert {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to dearmor message [{location}]")]
    Dearmor {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to parse packets [{location}]")]
    ParsePackets {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to recurse packet [{location}]")]
    Recurse {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("could not decrypt session key with available keys [{location}]")]
    SessionKey { location: Location },

    #[error("failed to decrypt SEIP/AED packet [{location}]")]
    SeipDecrypt {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to read literal body [{location}]")]
    ReadLiteral {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("no literal data found in decrypted message [{location}]")]
    NoLiteral { location: Location },

    #[error("decrypted content is not valid UTF-8 [{location}]")]
    Utf8 {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Failure modes for [`get_private_key`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum GetPrivateKeyError {
    #[error("failed to decode base64 key [{location}]")]
    Decode {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("decoded key is not valid UTF-8 [{location}]")]
    Utf8 {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to read key file {path} [{location}]")]
    ReadFile {
        #[context(borrow = str)]
        path: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error(
        "no GPG private key configured; set CAUTION_GPG_PRIVATE_KEY or CAUTION_GPG_KEY_PATH [{location}]"
    )]
    NotConfigured { location: Location },
}

/// Failure modes for [`load_cert`].
#[derive(Debug, thiserror::Error, CtxError)]
pub enum LoadCertError {
    #[error("failed to parse GPG key [{location}]")]
    Parse {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[tracing::instrument(skip_all, err)]
pub fn decrypt_gpg_message(encrypted_content: &str) -> Result<String, DecryptGpgMessageError> {
    use DecryptGpgMessageErrorCtx as Ctx;

    let trimmed = encrypted_content.trim();
    if !trimmed.starts_with("-----BEGIN PGP MESSAGE-----") {
        return Err(DecryptGpgMessageError::NotGpgMessage {
            location: std::panic::Location::caller(),
        });
    }

    let key_content = get_private_key().with_context(Ctx::get_key())?;
    let cert = load_cert(&key_content).with_context(Ctx::load_cert())?;
    let policy = StandardPolicy::new();

    let mut reader = Reader::from_reader(
        std::io::Cursor::new(trimmed),
        ReaderMode::Tolerant(Some(Kind::Message)),
    );
    let mut dearmored = Vec::new();
    reader
        .read_to_end(&mut dearmored)
        .with_context(Ctx::dearmor())?;

    let mut ppr = PacketParser::from_bytes(&dearmored).with_context(Ctx::parse_packets())?;

    let mut session_key: Option<(SymmetricAlgorithm, SessionKey)> = None;

    // First pass: find and decrypt the session key
    while let PacketParserResult::Some(pp) = ppr {
        let (packet, next_ppr) = pp.recurse().with_context(Ctx::recurse())?;

        if let Packet::PKESK(pkesk) = &packet {
            for key in cert
                .keys()
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

    let (algo, sk) = session_key.ok_or_else(|| DecryptGpgMessageError::SessionKey {
        location: std::panic::Location::caller(),
    })?;

    // Second pass: decrypt the actual data
    let mut ppr = PacketParser::from_bytes(&dearmored).with_context(Ctx::parse_packets())?;

    let mut decrypted_data = Vec::new();

    while let PacketParserResult::Some(mut pp) = ppr {
        tracing::debug!("Processing packet: {:?}", pp.packet.tag());
        match &pp.packet {
            Packet::SEIP(_) | Packet::AED(_) => {
                tracing::debug!("Decrypting SEIP/AED packet");
                pp.decrypt(algo, &sk).with_context(Ctx::seip_decrypt())?;
                let (_, next_ppr) = pp.recurse().with_context(Ctx::recurse())?;
                ppr = next_ppr;
            }
            Packet::Literal(lit) => {
                tracing::debug!("Found literal packet, filename: {:?}", lit.filename());
                let mut body = Vec::new();
                pp.read_to_end(&mut body)
                    .with_context(Ctx::read_literal())?;
                tracing::debug!("Read {} bytes from literal packet", body.len());
                decrypted_data = body;
                let (_, next_ppr) = pp.recurse().with_context(Ctx::recurse())?;
                ppr = next_ppr;
            }
            Packet::CompressedData(cd) => {
                tracing::debug!("Found compressed data packet, algo: {:?}", cd.algo());
                let (_, next_ppr) = pp.recurse().with_context(Ctx::recurse())?;
                ppr = next_ppr;
            }
            _ => {
                tracing::debug!("Skipping packet: {:?}", pp.packet.tag());
                let (_, next_ppr) = pp.recurse().with_context(Ctx::recurse())?;
                ppr = next_ppr;
            }
        }
    }

    if decrypted_data.is_empty() {
        return Err(DecryptGpgMessageError::NoLiteral {
            location: std::panic::Location::caller(),
        });
    }

    String::from_utf8(decrypted_data).with_context(Ctx::utf8())
}

#[tracing::instrument(skip_all, err)]
fn get_private_key() -> Result<String, GetPrivateKeyError> {
    use GetPrivateKeyErrorCtx as Ctx;

    if let Ok(key_content) = std::env::var("CAUTION_GPG_PRIVATE_KEY") {
        if key_content.trim().starts_with("-----BEGIN PGP") {
            return Ok(key_content);
        }
        let decoded = BASE64
            .decode(key_content.trim())
            .with_context(Ctx::decode())?;
        return String::from_utf8(decoded).with_context(Ctx::utf8());
    }

    if let Ok(key_path) = std::env::var("CAUTION_GPG_KEY_PATH") {
        return std::fs::read_to_string(&key_path).with_context(Ctx::read_file(key_path.as_str()));
    }

    Err(GetPrivateKeyError::NotConfigured {
        location: std::panic::Location::caller(),
    })
}

#[tracing::instrument(skip_all, err)]
fn load_cert(key_content: &str) -> Result<Cert, LoadCertError> {
    use LoadCertErrorCtx as Ctx;

    Cert::from_reader(key_content.as_bytes()).with_context(Ctx::parse())
}

pub fn is_gpg_encrypted(content: &str) -> bool {
    content.trim().starts_with("-----BEGIN PGP MESSAGE-----")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_gpg_encrypted() {
        assert!(is_gpg_encrypted(
            "-----BEGIN PGP MESSAGE-----\nsome content\n-----END PGP MESSAGE-----"
        ));
        assert!(is_gpg_encrypted("  -----BEGIN PGP MESSAGE-----\n"));
        assert!(!is_gpg_encrypted("{\"json\": \"data\"}"));
        assert!(!is_gpg_encrypted("plain text"));
    }
}
