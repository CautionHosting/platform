// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use regex::Regex;
use std::sync::OnceLock;

const PASSKEY_NAME_MAX_LEN: usize = 80;
const USERNAME_MIN_LEN: usize = 3;
const USERNAME_MAX_LEN: usize = 32;
const USERNAME_PATTERN: &str = r"^[a-zA-Z0-9]([a-zA-Z0-9_-]*[a-zA-Z0-9])?$";

static USERNAME_REGEX: OnceLock<Regex> = OnceLock::new();

/// Error type returned by all validation functions in this module.
///
/// Location is Debug-only: this type's `Display` is internal; callers box it as
/// a `#[source]` and serve fixed, generic client bodies.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Invalid app ID format, expected UUID [{location}]")]
    InvalidAppId {
        #[source]
        source: dterror::BoxError,
        location: dterror::Location,
    },

    #[error("Username must be at least {min} characters")]
    UsernameTooShort {
        min: usize,
        location: dterror::Location,
    },

    #[error("Username must be at most {max} characters")]
    UsernameTooLong {
        max: usize,
        location: dterror::Location,
    },

    #[error(
        "Username must contain only letters, numbers, hyphens, and underscores, \
         and must start/end with alphanumeric"
    )]
    UsernameInvalidChars { location: dterror::Location },

    #[error("SSH public key is too short (minimum {min} characters)")]
    SshKeyTooShort {
        min: usize,
        location: dterror::Location,
    },

    #[error("SSH public key is too long (maximum {max} characters)")]
    SshKeyTooLong {
        max: usize,
        location: dterror::Location,
    },

    #[error("SSH public key must have format: <key-type> <base64-data> [comment]")]
    SshKeyMissingData { location: dterror::Location },

    #[error("Unsupported SSH key type '{key_type}'. Allowed types: {}", allowed.join(", "))]
    SshKeyUnsupportedType {
        key_type: String,
        allowed: Vec<String>,
        location: dterror::Location,
    },

    #[error("SSH public key data is not valid base64")]
    SshKeyInvalidBase64 { location: dterror::Location },

    #[error("SSH public key decoded to empty data")]
    SshKeyEmptyDecoded { location: dterror::Location },

    #[error("SSH key data is too short for key type '{key_type}'")]
    SshKeyDataTooShort {
        key_type: String,
        location: dterror::Location,
    },

    #[error("Passkey name cannot be empty")]
    PasskeyNameEmpty { location: dterror::Location },

    #[error("Passkey name must be at most {max} characters")]
    PasskeyNameTooLong {
        max: usize,
        location: dterror::Location,
    },

    #[error("Passkey name cannot contain control characters")]
    PasskeyNameControlChars { location: dterror::Location },
}

fn get_username_regex() -> &'static Regex {
    USERNAME_REGEX.get_or_init(|| Regex::new(USERNAME_PATTERN).unwrap())
}

#[track_caller]
pub fn validate_app_id(id: &str) -> Result<(), ValidationError> {
    uuid::Uuid::parse_str(id).map_err(|source| ValidationError::InvalidAppId {
        source: Box::new(source),
        location: std::panic::Location::caller(),
    })?;
    Ok(())
}

/// Validates a chosen username. Validation is case-insensitive (the pattern
/// allows both cases); the caller is responsible for normalizing to lowercase
/// before storage.
#[track_caller]
pub fn validate_username(name: &str) -> Result<(), ValidationError> {
    if name.len() < USERNAME_MIN_LEN {
        return Err(ValidationError::UsernameTooShort {
            min: USERNAME_MIN_LEN,
            location: std::panic::Location::caller(),
        });
    }
    if name.len() > USERNAME_MAX_LEN {
        return Err(ValidationError::UsernameTooLong {
            max: USERNAME_MAX_LEN,
            location: std::panic::Location::caller(),
        });
    }

    if !get_username_regex().is_match(name) {
        return Err(ValidationError::UsernameInvalidChars {
            location: std::panic::Location::caller(),
        });
    }

    Ok(())
}

#[track_caller]
pub fn validate_ssh_public_key(public_key: &str) -> Result<(), ValidationError> {
    const SSH_KEY_MIN_LEN: usize = 50;
    const SSH_KEY_MAX_LEN: usize = 2000;
    const ALLOWED_SSH_KEY_TYPES: &[&str] = &[
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "ssh-rsa",
    ];

    let key = public_key.trim();

    if key.len() < SSH_KEY_MIN_LEN {
        return Err(ValidationError::SshKeyTooShort {
            min: SSH_KEY_MIN_LEN,
            location: std::panic::Location::caller(),
        });
    }
    if key.len() > SSH_KEY_MAX_LEN {
        return Err(ValidationError::SshKeyTooLong {
            max: SSH_KEY_MAX_LEN,
            location: std::panic::Location::caller(),
        });
    }

    let parts: Vec<&str> = key.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(ValidationError::SshKeyMissingData {
            location: std::panic::Location::caller(),
        });
    }

    let key_type = parts[0];
    let key_data = parts[1];

    if !ALLOWED_SSH_KEY_TYPES.contains(&key_type) {
        return Err(ValidationError::SshKeyUnsupportedType {
            key_type: key_type.to_string(),
            allowed: ALLOWED_SSH_KEY_TYPES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            location: std::panic::Location::caller(),
        });
    }

    if !is_valid_base64(key_data) {
        return Err(ValidationError::SshKeyInvalidBase64 {
            location: std::panic::Location::caller(),
        });
    }

    let min_data_len = match key_type {
        "ssh-ed25519" => 68,
        "ssh-rsa" => 200,
        "ecdsa-sha2-nistp256" => 100,
        "ecdsa-sha2-nistp384" => 120,
        "ecdsa-sha2-nistp521" => 140,
        _ => 50,
    };

    if key_data.len() < min_data_len {
        return Err(ValidationError::SshKeyDataTooShort {
            key_type: key_type.to_string(),
            location: std::panic::Location::caller(),
        });
    }

    match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, key_data) {
        Ok(decoded) => {
            if decoded.is_empty() {
                return Err(ValidationError::SshKeyEmptyDecoded {
                    location: std::panic::Location::caller(),
                });
            }
        }
        Err(_) => {
            return Err(ValidationError::SshKeyInvalidBase64 {
                location: std::panic::Location::caller(),
            });
        }
    }

    Ok(())
}

#[track_caller]
pub fn validate_passkey_name(name: &str) -> Result<(), ValidationError> {
    let trimmed = name.trim();

    if trimmed.is_empty() {
        return Err(ValidationError::PasskeyNameEmpty {
            location: std::panic::Location::caller(),
        });
    }

    if trimmed.len() > PASSKEY_NAME_MAX_LEN {
        return Err(ValidationError::PasskeyNameTooLong {
            max: PASSKEY_NAME_MAX_LEN,
            location: std::panic::Location::caller(),
        });
    }

    if trimmed.chars().any(|c| c.is_control()) {
        return Err(ValidationError::PasskeyNameControlChars {
            location: std::panic::Location::caller(),
        });
    }

    Ok(())
}

fn is_valid_base64(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        && !s.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_app_id() {
        assert!(validate_app_id("550e8400-e29b-41d4-a716-446655440000").is_ok());
        assert!(validate_app_id("not-a-uuid").is_err());
        assert!(validate_app_id("").is_err());
        assert!(validate_app_id("550e8400e29b41d4a716446655440000").is_ok()); // no hyphens
    }

    #[test]
    fn test_ssh_key_valid_ed25519() {
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@host";
        assert!(validate_ssh_public_key(key).is_ok());
    }

    #[test]
    fn test_ssh_key_valid_with_whitespace() {
        let key = "  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@host  ";
        assert!(validate_ssh_public_key(key).is_ok());
    }

    #[test]
    fn test_ssh_key_too_short() {
        assert!(validate_ssh_public_key("ssh-ed25519 AAAA").is_err());
    }

    #[test]
    fn test_ssh_key_too_long() {
        let key = format!("ssh-ed25519 {}", "A".repeat(2000));
        assert!(validate_ssh_public_key(&key).is_err());
    }

    #[test]
    fn test_ssh_key_unsupported_type() {
        let key =
            "ssh-dss AAAAB3NzaC1kc3MAAACBAJlkjFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA user@host";
        assert!(validate_ssh_public_key(key).is_err());
    }

    #[test]
    fn test_ssh_key_missing_data() {
        assert!(validate_ssh_public_key("ssh-ed25519").is_err());
    }

    #[test]
    fn test_ssh_key_invalid_base64() {
        let key = "ssh-ed25519 not!valid@base64$$$chars user@host";
        assert!(validate_ssh_public_key(key).is_err());
    }

    #[test]
    fn test_ssh_key_no_comment() {
        let key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
        assert!(validate_ssh_public_key(key).is_ok());
    }

    #[test]
    fn test_is_valid_base64() {
        assert!(is_valid_base64("AAAA"));
        assert!(is_valid_base64("abc123+/=="));
        assert!(!is_valid_base64(""));
        assert!(!is_valid_base64("abc!"));
        assert!(!is_valid_base64("abc def"));
    }

    #[test]
    fn test_username_valid() {
        assert!(validate_username("alice").is_ok());
        assert!(validate_username("bob_1").is_ok());
        assert!(validate_username("a-b").is_ok());
        assert!(validate_username("abc").is_ok()); // 3-char min
        assert!(validate_username(&"a".repeat(32)).is_ok()); // 32-char max
    }

    #[test]
    fn test_username_invalid() {
        assert!(validate_username("ab").is_err()); // 2-char, too short
        assert!(validate_username(&"a".repeat(33)).is_err()); // 33-char, too long
        assert!(validate_username("-alice").is_err()); // leading hyphen
        assert!(validate_username("alice-").is_err()); // trailing hyphen
        assert!(validate_username("_alice").is_err()); // leading underscore
        assert!(validate_username("alice_").is_err()); // trailing underscore
        assert!(validate_username("bad name").is_err()); // space
        assert!(validate_username("bad.name").is_err()); // dot
        assert!(validate_username("café").is_err()); // non-ascii
        assert!(validate_username("").is_err()); // empty
    }

    #[test]
    fn test_validate_passkey_name() {
        assert!(validate_passkey_name("MacBook Touch ID").is_ok());
        assert!(validate_passkey_name("YubiKey NFC").is_ok());
        assert!(validate_passkey_name("").is_err());
        assert!(validate_passkey_name("   ").is_err());
        assert!(validate_passkey_name(&"a".repeat(81)).is_err());
        assert!(validate_passkey_name("bad\nname").is_err());
    }
}
