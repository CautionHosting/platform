// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use sequoia_openpgp as openpgp;

use openpgp::{cert::CertParser, parse::Parse, policy::StandardPolicy, serialize::Serialize as _};

pub const PGP_PUBLIC_KEY_MAX_BYTES: usize = 64 * 1024;
pub const PGP_KEY_NAME_MAX_CHARS: usize = 255;
const PGP_PUBLIC_KEY_ARMOR_BEGIN: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
const PGP_PUBLIC_KEY_ARMOR_END: &str = "-----END PGP PUBLIC KEY BLOCK-----";
const PGP_PRIVATE_KEY_ARMOR_BEGIN: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----";

#[derive(Debug)]
pub struct ValidatedPgpPublicKey {
    armored: String,
    fingerprint: String,
}

impl ValidatedPgpPublicKey {
    pub fn armored(&self) -> &str {
        &self.armored
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

/// Leaf error for PGP public key parsing. Display is internal-only: every
/// handler that receives this type boxes it as a `#[source]` behind its own
/// fixed, generic client body.
#[derive(Debug, thiserror::Error)]
pub enum ParsePgpPublicKeyError {
    #[error("PGP public key is empty")]
    Empty { location: dterror::Location },

    #[error("PGP public key is too large (maximum {max} bytes, got {actual})")]
    TooLarge {
        max: usize,
        actual: usize,
        location: dterror::Location,
    },

    #[error("PGP public key must be an ASCII-armored public certificate")]
    InvalidArmor { location: dterror::Location },

    #[error("PGP public key is malformed")]
    Parse {
        #[source]
        source: dterror::BoxError,
        location: dterror::Location,
    },

    #[error("PGP input must contain exactly one public certificate (got {actual})")]
    CertificateCount {
        actual: usize,
        location: dterror::Location,
    },

    #[error(
        "PGP input contains private key material; export and submit only the public certificate"
    )]
    PrivateKeyMaterial { location: dterror::Location },

    #[error("PGP public certificate is not valid under the standard OpenPGP policy")]
    Policy {
        #[source]
        source: dterror::BoxError,
        location: dterror::Location,
    },

    #[error("Unable to normalize PGP public certificate")]
    Serialize {
        #[source]
        source: dterror::BoxError,
        location: dterror::Location,
    },

    #[error("Normalized PGP public certificate is not valid UTF-8")]
    Utf8 {
        #[source]
        source: dterror::BoxError,
        location: dterror::Location,
    },
}

/// Leaf error for PGP key name validation.
///
/// Location is Debug-only: the `Display` output of this type feeds client-facing
/// bodies (via `AddPgpKeyError::InvalidName`'s transparent forwarding).
#[derive(Debug, thiserror::Error)]
pub enum ValidatePgpKeyNameError {
    #[error("PGP key name must be at most {max} characters (got {actual})")]
    TooLong {
        max: usize,
        actual: usize,
        location: dterror::Location,
    },

    #[error("PGP key name cannot contain control characters")]
    ControlCharacter { location: dterror::Location },
}

#[track_caller]
pub fn parse_public_key(input: &str) -> Result<ValidatedPgpPublicKey, ParsePgpPublicKeyError> {
    let actual = input.len();

    if actual > PGP_PUBLIC_KEY_MAX_BYTES {
        return Err(ParsePgpPublicKeyError::TooLarge {
            max: PGP_PUBLIC_KEY_MAX_BYTES,
            actual,
            location: std::panic::Location::caller(),
        });
    }
    let input = input.trim();
    if input.is_empty() {
        return Err(ParsePgpPublicKeyError::Empty {
            location: std::panic::Location::caller(),
        });
    }
    if input.starts_with(PGP_PRIVATE_KEY_ARMOR_BEGIN) {
        return Err(ParsePgpPublicKeyError::PrivateKeyMaterial {
            location: std::panic::Location::caller(),
        });
    }
    if !input.starts_with(PGP_PUBLIC_KEY_ARMOR_BEGIN) || !input.ends_with(PGP_PUBLIC_KEY_ARMOR_END)
    {
        return Err(ParsePgpPublicKeyError::InvalidArmor {
            location: std::panic::Location::caller(),
        });
    }

    let parser = CertParser::from_bytes(input.as_bytes()).map_err(|source| {
        ParsePgpPublicKeyError::Parse {
            source: source.into_boxed_dyn_error(),
            location: std::panic::Location::caller(),
        }
    })?;
    let certs = parser
        .collect::<openpgp::Result<Vec<_>>>()
        .map_err(|source| ParsePgpPublicKeyError::Parse {
            source: source.into_boxed_dyn_error(),
            location: std::panic::Location::caller(),
        })?;

    if certs.len() != 1 {
        return Err(ParsePgpPublicKeyError::CertificateCount {
            actual: certs.len(),
            location: std::panic::Location::caller(),
        });
    }

    let cert =
        certs
            .into_iter()
            .next()
            .ok_or_else(|| ParsePgpPublicKeyError::CertificateCount {
                actual: 0,
                location: std::panic::Location::caller(),
            })?;

    if cert.is_tsk() {
        return Err(ParsePgpPublicKeyError::PrivateKeyMaterial {
            location: std::panic::Location::caller(),
        });
    }

    cert.with_policy(&StandardPolicy::new(), None)
        .map_err(|source| ParsePgpPublicKeyError::Policy {
            source: source.into_boxed_dyn_error(),
            location: std::panic::Location::caller(),
        })?;

    let fingerprint = cert.fingerprint().to_string();
    let mut serialized = Vec::new();
    cert.armored()
        .serialize(&mut serialized)
        .map_err(|source| ParsePgpPublicKeyError::Serialize {
            source: source.into_boxed_dyn_error(),
            location: std::panic::Location::caller(),
        })?;
    let mut armored =
        String::from_utf8(serialized).map_err(|source| ParsePgpPublicKeyError::Utf8 {
            source: Box::new(source),
            location: std::panic::Location::caller(),
        })?;
    if !armored.ends_with('\n') {
        armored.push('\n');
    }
    if armored.len() > PGP_PUBLIC_KEY_MAX_BYTES {
        return Err(ParsePgpPublicKeyError::TooLarge {
            max: PGP_PUBLIC_KEY_MAX_BYTES,
            actual: armored.len(),
            location: std::panic::Location::caller(),
        });
    }

    Ok(ValidatedPgpPublicKey {
        armored,
        fingerprint,
    })
}

#[track_caller]
pub fn validate_key_name(name: &str) -> Result<(), ValidatePgpKeyNameError> {
    let actual = name.chars().count();

    if actual > PGP_KEY_NAME_MAX_CHARS {
        return Err(ValidatePgpKeyNameError::TooLong {
            max: PGP_KEY_NAME_MAX_CHARS,
            actual,
            location: std::panic::Location::caller(),
        });
    }
    if name.chars().any(char::is_control) {
        return Err(ValidatePgpKeyNameError::ControlCharacter {
            location: std::panic::Location::caller(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openpgp::cert::prelude::CertBuilder;

    fn test_cert() -> openpgp::Cert {
        CertBuilder::new()
            .add_userid("PGP enrollment test <pgp-enrollment@example.com>")
            .add_signing_subkey()
            .generate()
            .unwrap()
            .0
    }

    fn armored_public_key(cert: &openpgp::Cert) -> String {
        let mut bytes = Vec::new();
        cert.armored().serialize(&mut bytes).unwrap();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn parses_and_normalizes_one_public_certificate() {
        let cert = test_cert();
        let key = parse_public_key(&armored_public_key(&cert)).unwrap();

        assert_eq!(key.fingerprint(), cert.fingerprint().to_string());
        assert!(key
            .armored()
            .starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assert!(key.armored().ends_with('\n'));
    }

    #[test]
    fn rejects_private_key_material() {
        let cert = test_cert();
        let mut bytes = Vec::new();
        cert.as_tsk().armored().serialize(&mut bytes).unwrap();
        let private_key = String::from_utf8(bytes).unwrap();

        assert!(matches!(
            parse_public_key(&private_key),
            Err(ParsePgpPublicKeyError::PrivateKeyMaterial { .. })
        ));
    }

    #[test]
    fn rejects_multiple_certificates() {
        let first = armored_public_key(&test_cert());
        let second = armored_public_key(&test_cert());

        assert!(matches!(
            parse_public_key(&format!("{first}{second}")),
            Err(ParsePgpPublicKeyError::CertificateCount { actual: 2, .. })
        ));
    }

    #[test]
    fn rejects_malformed_and_oversized_input() {
        assert!(matches!(
            parse_public_key("not a PGP certificate"),
            Err(ParsePgpPublicKeyError::InvalidArmor { .. })
        ));
        let with_trailing_data = format!("{}unexpected", armored_public_key(&test_cert()));
        assert!(matches!(
            parse_public_key(&with_trailing_data),
            Err(ParsePgpPublicKeyError::InvalidArmor { .. })
        ));
        assert!(matches!(
            parse_public_key(&"A".repeat(PGP_PUBLIC_KEY_MAX_BYTES + 1)),
            Err(ParsePgpPublicKeyError::TooLarge { .. })
        ));
        let padded_key = format!(
            "{}{}",
            armored_public_key(&test_cert()),
            " ".repeat(PGP_PUBLIC_KEY_MAX_BYTES)
        );
        assert!(matches!(
            parse_public_key(&padded_key),
            Err(ParsePgpPublicKeyError::TooLarge { .. })
        ));
    }

    #[test]
    fn validates_key_names() {
        assert!(validate_key_name("Work laptop").is_ok());
        assert!(matches!(
            validate_key_name("line\nbreak"),
            Err(ValidatePgpKeyNameError::ControlCharacter { .. })
        ));
        assert!(matches!(
            validate_key_name(&"x".repeat(PGP_KEY_NAME_MAX_CHARS + 1)),
            Err(ValidatePgpKeyNameError::TooLong { .. })
        ));
    }
}
