// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{bail, Result};
use regex::Regex;
use std::sync::OnceLock;

const APP_NAME_MIN_LEN: usize = 3;
const APP_NAME_MAX_LEN: usize = 63;
const APP_NAME_PATTERN: &str = r"^[a-zA-Z0-9]([a-zA-Z0-9_-]*[a-zA-Z0-9])?$";
const PASSKEY_NAME_MAX_LEN: usize = 80;

static APP_NAME_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_app_name_regex() -> &'static Regex {
    APP_NAME_REGEX.get_or_init(|| Regex::new(APP_NAME_PATTERN).unwrap())
}

pub fn validate_app_id(id: &str) -> Result<()> {
    uuid::Uuid::parse_str(id)
        .map_err(|_| anyhow::anyhow!("Invalid app ID format, expected UUID"))?;
    Ok(())
}

pub fn validate_app_name(name: &str) -> Result<()> {
    if name.len() < APP_NAME_MIN_LEN {
        bail!("App name must be at least {} characters", APP_NAME_MIN_LEN);
    }
    if name.len() > APP_NAME_MAX_LEN {
        bail!("App name must be at most {} characters", APP_NAME_MAX_LEN);
    }

    if !get_app_name_regex().is_match(name) {
        bail!("App name must contain only letters, numbers, hyphens, and underscores, and must start/end with alphanumeric");
    }

    Ok(())
}

pub fn validate_ssh_public_key(public_key: &str) -> Result<()> {
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
        bail!("SSH public key is too short (minimum {} characters)", SSH_KEY_MIN_LEN);
    }
    if key.len() > SSH_KEY_MAX_LEN {
        bail!("SSH public key is too long (maximum {} characters)", SSH_KEY_MAX_LEN);
    }

    let parts: Vec<&str> = key.split_whitespace().collect();
    if parts.len() < 2 {
        bail!("SSH public key must have format: <key-type> <base64-data> [comment]");
    }

    let key_type = parts[0];
    let key_data = parts[1];

    if !ALLOWED_SSH_KEY_TYPES.contains(&key_type) {
        bail!(
            "Unsupported SSH key type '{}'. Allowed types: {}",
            key_type,
            ALLOWED_SSH_KEY_TYPES.join(", ")
        );
    }

    if !is_valid_base64(key_data) {
        bail!("SSH public key data is not valid base64");
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
        bail!("SSH key data is too short for key type '{}'", key_type);
    }

    match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, key_data) {
        Ok(decoded) => {
            if decoded.is_empty() {
                bail!("SSH public key decoded to empty data");
            }
        }
        Err(_) => bail!("SSH public key data is not valid base64"),
    }

    Ok(())
}

pub fn validate_passkey_name(name: &str) -> Result<()> {
    let trimmed = name.trim();

    if trimmed.is_empty() {
        bail!("Passkey name cannot be empty");
    }

    if trimmed.len() > PASSKEY_NAME_MAX_LEN {
        bail!(
            "Passkey name must be at most {} characters",
            PASSKEY_NAME_MAX_LEN
        );
    }

    if trimmed.chars().any(|c| c.is_control()) {
        bail!("Passkey name cannot contain control characters");
    }

    Ok(())
}

fn is_valid_base64(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        && !s.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_name_valid() {
        assert!(validate_app_name("my-app").is_ok());
        assert!(validate_app_name("web-frontend").is_ok());
        assert!(validate_app_name("api-v2").is_ok());
        assert!(validate_app_name("test123").is_ok());
        assert!(validate_app_name("a1b").is_ok());
        assert!(validate_app_name("My-App").is_ok());
        assert!(validate_app_name("app--name").is_ok());
        assert!(validate_app_name("app_name").is_ok());
    }

    #[test]
    fn test_app_name_invalid() {
        assert!(validate_app_name("ab").is_err());
        assert!(validate_app_name("-app").is_err());
        assert!(validate_app_name("app-").is_err());
        assert!(validate_app_name("_app").is_err());
        assert!(validate_app_name("app_").is_err());
        assert!(validate_app_name("app.name").is_err());
        assert!(validate_app_name("app name").is_err());
    }

    #[test]
    fn test_app_name_boundary_lengths() {
        // Exactly min length (3)
        assert!(validate_app_name("abc").is_ok());
        // Exactly max length (63)
        assert!(validate_app_name(&"a".repeat(63)).is_ok());
        // One over max
        assert!(validate_app_name(&"a".repeat(64)).is_err());
        // One under min
        assert!(validate_app_name("ab").is_err());
        // Single char
        assert!(validate_app_name("a").is_err());
        // Empty
        assert!(validate_app_name("").is_err());
    }

    #[test]
    fn test_app_name_special_characters() {
        assert!(validate_app_name("app.name").is_err());
        assert!(validate_app_name("app name").is_err());
        assert!(validate_app_name("app@name").is_err());
        assert!(validate_app_name("app/name").is_err());
        assert!(validate_app_name("app\nname").is_err());
    }

    #[test]
    fn test_app_name_numeric_only() {
        assert!(validate_app_name("123").is_ok());
        assert!(validate_app_name("1-2-3").is_ok());
    }

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
        let key = "ssh-dss AAAAB3NzaC1kc3MAAACBAJlkjFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA user@host";
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
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
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
    fn test_validate_passkey_name() {
        assert!(validate_passkey_name("MacBook Touch ID").is_ok());
        assert!(validate_passkey_name("YubiKey NFC").is_ok());
        assert!(validate_passkey_name("").is_err());
        assert!(validate_passkey_name("   ").is_err());
        assert!(validate_passkey_name(&"a".repeat(81)).is_err());
        assert!(validate_passkey_name("bad\nname").is_err());
    }
}
