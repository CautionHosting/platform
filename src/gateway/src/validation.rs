// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{bail, Result};
use regex::Regex;
use std::sync::OnceLock;

const APP_NAME_MIN_LEN: usize = 3;
const APP_NAME_MAX_LEN: usize = 63;
const APP_NAME_PATTERN: &str = r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$";

const RESERVED_NAMES: &[&str] = &[
    "api", "gateway", "admin", "root", "system",
    "www", "mail", "smtp", "ftp", "ssh", "git",
    "aws", "amazon", "s3", "ec2", "vpc",
    "security", "auth", "login", "register",
    "metrics", "logs", "status", "health",
    "localhost", "internal", "private", "public",
];

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
        bail!("App name must contain only lowercase letters, numbers, and hyphens, and must start/end with alphanumeric");
    }

    if name.contains("--") {
        bail!("App name cannot contain consecutive hyphens");
    }

    if RESERVED_NAMES.contains(&name) {
        bail!("App name '{}' is reserved", name);
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
    }

    #[test]
    fn test_app_name_invalid() {
        assert!(validate_app_name("ab").is_err());
        assert!(validate_app_name("-app").is_err());
        assert!(validate_app_name("app-").is_err());
        assert!(validate_app_name("My-App").is_err());
        assert!(validate_app_name("app--name").is_err());
        assert!(validate_app_name("app_name").is_err());
        assert!(validate_app_name("api").is_err());
    }
}
