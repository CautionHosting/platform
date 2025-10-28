// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use regex::Regex;
use std::sync::OnceLock;
use crate::types::UserRole;
use crate::errors::{ValidationError, Span};

const APP_NAME_MIN_LEN: usize = 3;
const APP_NAME_MAX_LEN: usize = 63;
const APP_NAME_PATTERN: &str = r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$";

const ORG_NAME_MIN_LEN: usize = 2;
const ORG_NAME_MAX_LEN: usize = 100;
const ORG_NAME_PATTERN: &str = r"^[a-zA-Z0-9][a-zA-Z0-9 _-]*[a-zA-Z0-9]$";

const ORG_SLUG_MIN_LEN: usize = 3;
const ORG_SLUG_MAX_LEN: usize = 63;
const ORG_SLUG_PATTERN: &str = r"^[a-z0-9][a-z0-9-]*[a-z0-9]$";

const USERNAME_MIN_LEN: usize = 3;
const USERNAME_MAX_LEN: usize = 39;
const USERNAME_PATTERN: &str = r"^[a-zA-Z0-9][a-zA-Z0-9_-]*[a-zA-Z0-9]$";

const EMAIL_MAX_LEN: usize = 254;
const EMAIL_PATTERN: &str = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$";

const ALLOWED_SSH_KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
];

const SSH_KEY_MIN_LEN: usize = 50;
const SSH_KEY_MAX_LEN: usize = 2000;

const RESERVED_NAMES: &[&str] = &[
    "api", "gateway", "admin", "root", "system",
    "www", "mail", "smtp", "ftp", "ssh", "git",
    "aws", "amazon", "s3", "ec2", "vpc",
    "security", "auth", "login", "register",
    "metrics", "logs", "status", "health",
    "localhost", "internal", "private", "public",
];

static APP_NAME_REGEX: OnceLock<Regex> = OnceLock::new();
static ORG_NAME_REGEX: OnceLock<Regex> = OnceLock::new();
static ORG_SLUG_REGEX: OnceLock<Regex> = OnceLock::new();
static USERNAME_REGEX: OnceLock<Regex> = OnceLock::new();
static EMAIL_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_app_name_regex() -> &'static Regex {
    APP_NAME_REGEX.get_or_init(|| Regex::new(APP_NAME_PATTERN).unwrap())
}

fn get_org_name_regex() -> &'static Regex {
    ORG_NAME_REGEX.get_or_init(|| Regex::new(ORG_NAME_PATTERN).unwrap())
}

fn get_org_slug_regex() -> &'static Regex {
    ORG_SLUG_REGEX.get_or_init(|| Regex::new(ORG_SLUG_PATTERN).unwrap())
}

fn get_username_regex() -> &'static Regex {
    USERNAME_REGEX.get_or_init(|| Regex::new(USERNAME_PATTERN).unwrap())
}

fn get_email_regex() -> &'static Regex {
    EMAIL_REGEX.get_or_init(|| Regex::new(EMAIL_PATTERN).unwrap())
}

pub fn validate_app_name(name: &str) -> Result<(), ValidationError> {
    let len = name.len();

    if len < APP_NAME_MIN_LEN || len > APP_NAME_MAX_LEN {
        return Err(ValidationError::AppNameLength {
            min: APP_NAME_MIN_LEN,
            max: APP_NAME_MAX_LEN,
            actual: len,
            span: Span::new(0, len),
        });
    }

    if !get_app_name_regex().is_match(name) {
        let (pos, ch) = name
            .char_indices()
            .find(|(_, c)| !c.is_ascii_alphanumeric() && *c != '-')
            .or_else(|| {
                if name.starts_with('-') {
                    Some((0, '-'))
                } else if name.ends_with('-') {
                    Some((len - 1, '-'))
                } else {
                    Some((0, name.chars().next().unwrap_or('?')))
                }
            })
            .unwrap_or((0, '?'));

        return Err(ValidationError::AppNameInvalidChars {
            invalid_char: ch,
            span: Span::new(pos, pos + ch.len_utf8()),
        });
    }

    if let Some(pos) = name.find("--") {
        return Err(ValidationError::AppNameConsecutiveHyphens {
            span: Span::new(pos, pos + 2),
        });
    }

    if RESERVED_NAMES.contains(&name) {
        return Err(ValidationError::AppNameReserved {
            name: name.to_string(),
            span: Span::new(0, len),
        });
    }

    Ok(())
}

pub fn validate_org_name(name: &str) -> Result<(), ValidationError> {
    let len = name.len();

    if len < ORG_NAME_MIN_LEN || len > ORG_NAME_MAX_LEN {
        return Err(ValidationError::OrgNameLength {
            min: ORG_NAME_MIN_LEN,
            max: ORG_NAME_MAX_LEN,
            actual: len,
        });
    }

    if !get_org_name_regex().is_match(name) {
        return Err(ValidationError::OrgNameInvalidChars);
    }

    if name.contains("  ") {
        return Err(ValidationError::OrgNameConsecutiveSpaces);
    }

    Ok(())
}


pub fn validate_username(username: &str) -> Result<(), ValidationError> {
    let len = username.len();

    if len < USERNAME_MIN_LEN || len > USERNAME_MAX_LEN {
        return Err(ValidationError::UsernameLength {
            min: USERNAME_MIN_LEN,
            max: USERNAME_MAX_LEN,
            actual: len,
        });
    }

    if !get_username_regex().is_match(username) {
        return Err(ValidationError::UsernameInvalidChars);
    }

    if RESERVED_NAMES.contains(&username.to_lowercase().as_str()) {
        return Err(ValidationError::UsernameReserved {
            username: username.to_string(),
        });
    }

    Ok(())
}

pub fn validate_email(email: &str) -> Result<(), ValidationError> {
    let len = email.len();

    if len > EMAIL_MAX_LEN {
        return Err(ValidationError::EmailTooLong {
            max: EMAIL_MAX_LEN,
            actual: len,
        });
    }

    if !get_email_regex().is_match(email) {
        return Err(ValidationError::EmailInvalidFormat);
    }

    Ok(())
}

pub fn validate_ssh_public_key(public_key: &str) -> Result<(), ValidationError> {
    let key = public_key.trim();
    let len = key.len();

    if len < SSH_KEY_MIN_LEN {
        return Err(ValidationError::SshKeyTooShort {
            min: SSH_KEY_MIN_LEN,
            actual: len,
        });
    }

    if len > SSH_KEY_MAX_LEN {
        return Err(ValidationError::SshKeyTooLong {
            max: SSH_KEY_MAX_LEN,
            actual: len,
        });
    }

    let parts: Vec<&str> = key.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(ValidationError::SshKeyInvalidFormat {
            expected: "<key-type> <base64-data> [comment]",
        });
    }

    let key_type = parts[0];
    let key_data = parts[1];

    if !ALLOWED_SSH_KEY_TYPES.contains(&key_type) {
        return Err(ValidationError::SshKeyUnsupportedType {
            key_type: key_type.to_string(),
        });
    }

    if !is_valid_base64(key_data) {
        return Err(ValidationError::SshKeyInvalidBase64);
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
        });
    }

    match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, key_data) {
        Ok(decoded) => {
            if decoded.is_empty() {
                return Err(ValidationError::SshKeyEmptyData);
            }
        }
        Err(_) => return Err(ValidationError::SshKeyInvalidBase64),
    }

    Ok(())
}

fn is_valid_base64(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        && !s.is_empty()
}

pub fn validate_role(role: &str) -> Result<UserRole, ValidationError> {
    UserRole::from_str(role).ok_or_else(|| ValidationError::InvalidRole {
        role: role.to_string(),
    })
}

pub fn sanitize_for_terraform(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
        .replace('$', "\\$")
}

pub fn sanitize_for_shell(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.' || *c == '/')
        .collect()
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
        assert!(validate_app_name("a".repeat(64)).is_err());
    }

    #[test]
    fn test_org_name_valid() {
        assert!(validate_org_name("Acme Corp").is_ok());
        assert!(validate_org_name("My Company 2024").is_ok());
        assert!(validate_org_name("Tech_Startup").is_ok());
        assert!(validate_org_name("AB").is_ok());
    }

    #[test]
    fn test_org_name_invalid() {
        assert!(validate_org_name("A").is_err());
        assert!(validate_org_name(" Acme").is_err());
        assert!(validate_org_name("Acme!").is_err());
        assert!(validate_org_name("Acme  Corp").is_err());
    }

    #[test]
    fn test_username_valid() {
        assert!(validate_username("john_doe").is_ok());
        assert!(validate_username("user123").is_ok());
        assert!(validate_username("jane-smith").is_ok());
        assert!(validate_username("abc").is_ok());
    }

    #[test]
    fn test_username_invalid() {
        assert!(validate_username("ab").is_err());
        assert!(validate_username("_user").is_err());
        assert!(validate_username("user!").is_err());
        assert!(validate_username("admin").is_err());
    }

    #[test]
    fn test_email_valid() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("test+tag@company.co.uk").is_ok());
        assert!(validate_email("name.surname@domain.com").is_ok());
    }

    #[test]
    fn test_email_invalid() {
        assert!(validate_email("invalid").is_err());
        assert!(validate_email("@example.com").is_err());
        assert!(validate_email("user@").is_err());
        assert!(validate_email("user@com").is_err());
    }

    #[test]
    fn test_ssh_key_valid() {
        let ed25519_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@host";
        assert!(validate_ssh_public_key(ed25519_key).is_ok());
    }

    #[test]
    fn test_ssh_key_invalid() {
        assert!(validate_ssh_public_key("invalid").is_err());
        assert!(validate_ssh_public_key("ssh-ed25519").is_err());
        assert!(validate_ssh_public_key("unknown-type AAAAC3Nza...").is_err());
    }

    #[test]
    fn test_terraform_sanitization() {
        assert_eq!(
            sanitize_for_terraform("test\"value${}"),
            "test\\\"value\\${}"
        );
        assert_eq!(
            sanitize_for_terraform("line1\nline2"),
            "line1\\nline2"
        );
    }

    #[test]
    fn test_shell_sanitization() {
        assert_eq!(
            sanitize_for_shell("safe-file_name.txt"),
            "safe-file_name.txt"
        );
        assert_eq!(
            sanitize_for_shell("evil$(rm -rf /)name"),
            "evilrmrfname"
        );
    }

    #[test]
    fn test_role_validation() {
        assert_eq!(validate_role("owner").unwrap(), UserRole::Owner);
        assert_eq!(validate_role("admin").unwrap(), UserRole::Admin);
        assert_eq!(validate_role("member").unwrap(), UserRole::Member);
        assert_eq!(validate_role("viewer").unwrap(), UserRole::Viewer);
        assert!(validate_role("invalid").is_err());
        assert!(validate_role("OWNER").is_err());
    }
}
