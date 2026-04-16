// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::errors::{Span, ValidationError};
use crate::types::UserRole;
use regex::Regex;
use std::sync::OnceLock;

const APP_NAME_MIN_LEN: usize = 3;
const APP_NAME_MAX_LEN: usize = 63;
const APP_NAME_PATTERN: &str = r"^[a-zA-Z0-9]([a-zA-Z0-9_-]*[a-zA-Z0-9])?$";

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

const BRANCH_NAME_MIN_LEN: usize = 1;
const BRANCH_NAME_MAX_LEN: usize = 255;
const BRANCH_NAME_PATTERN: &str = r"^[a-zA-Z0-9][a-zA-Z0-9/_.\-]*$";

const ALLOWED_SSH_KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
];

const SSH_KEY_MIN_LEN: usize = 50;
const SSH_KEY_MAX_LEN: usize = 2000;

static APP_NAME_REGEX: OnceLock<Regex> = OnceLock::new();
static ORG_NAME_REGEX: OnceLock<Regex> = OnceLock::new();
static ORG_SLUG_REGEX: OnceLock<Regex> = OnceLock::new();
static USERNAME_REGEX: OnceLock<Regex> = OnceLock::new();
static BRANCH_NAME_REGEX: OnceLock<Regex> = OnceLock::new();
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

fn get_branch_name_regex() -> &'static Regex {
    BRANCH_NAME_REGEX.get_or_init(|| Regex::new(BRANCH_NAME_PATTERN).unwrap())
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
        let last = len - 1;
        let invalid_char = name
            .char_indices()
            .find(|&(i, c)| {
                if i == 0 || i == last {
                    !c.is_ascii_alphanumeric()
                } else {
                    !c.is_ascii_alphanumeric() && c != '-' && c != '_'
                }
            })
            .map(|(_, c)| c)
            .unwrap_or('?');
        return Err(ValidationError::AppNameInvalidChars {
            invalid_char,
            span: Span::new(0, len),
        });
    }

    Ok(())
}

pub fn validate_branch_name(name: &str) -> Result<(), ValidationError> {
    let len = name.len();

    if len < BRANCH_NAME_MIN_LEN || len > BRANCH_NAME_MAX_LEN {
        return Err(ValidationError::BranchNameLength {
            min: BRANCH_NAME_MIN_LEN,
            max: BRANCH_NAME_MAX_LEN,
            actual: len,
        });
    }

    if !get_branch_name_regex().is_match(name) {
        return Err(ValidationError::BranchNameInvalidChars);
    }

    // Reject git-unsafe patterns
    if name.contains("..") || name.contains("@{") || name.ends_with('/') || name.ends_with('.') {
        return Err(ValidationError::BranchNameInvalidChars);
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
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
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
        assert!(validate_app_name("my_app").is_ok());
        assert!(validate_app_name("web-frontend").is_ok());
        assert!(validate_app_name("web_frontend").is_ok());
        assert!(validate_app_name("api-v2").is_ok());
        assert!(validate_app_name("test123").is_ok());
        assert!(validate_app_name("a1b").is_ok());
        assert!(validate_app_name("my-app_v2").is_ok());
        assert!(validate_app_name("app--name").is_ok());
        assert!(validate_app_name("app__name").is_ok());
        assert!(validate_app_name("My-App").is_ok());
        assert!(validate_app_name("App--Name").is_ok());
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
        assert!(validate_app_name(&"a".repeat(64)).is_err());
    }

    #[test]
    fn test_app_name_boundary_lengths() {
        assert!(validate_app_name("abc").is_ok());
        assert!(validate_app_name(&"a".repeat(63)).is_ok());
        assert!(validate_app_name(&"a".repeat(64)).is_err());
        assert!(validate_app_name("ab").is_err());
        assert!(validate_app_name("").is_err());
    }

    #[test]
    fn test_app_name_error_codes() {
        match validate_app_name("ab").unwrap_err() {
            ValidationError::AppNameLength {
                min, max, actual, ..
            } => {
                assert_eq!(min, 3);
                assert_eq!(max, 63);
                assert_eq!(actual, 2);
            }
            e => panic!("Expected AppNameLength, got {:?}", e),
        }

        match validate_app_name("-app").unwrap_err() {
            ValidationError::AppNameInvalidChars { invalid_char, .. } => {
                assert_eq!(invalid_char, '-');
            }
            e => panic!("Expected AppNameInvalidChars, got {:?}", e),
        }

        match validate_app_name("app.name").unwrap_err() {
            ValidationError::AppNameInvalidChars { invalid_char, .. } => {
                assert_eq!(invalid_char, '.');
            }
            e => panic!("Expected AppNameInvalidChars, got {:?}", e),
        }
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
    fn test_org_name_boundary_lengths() {
        assert!(validate_org_name("AB").is_ok());
        assert!(validate_org_name("A").is_err());
        assert!(validate_org_name(&"A".repeat(100)).is_ok());
        assert!(validate_org_name(&"A".repeat(101)).is_err());
        assert!(validate_org_name("").is_err());
    }

    #[test]
    fn test_org_name_consecutive_spaces() {
        assert!(validate_org_name("Acme  Corp").is_err());
        assert!(validate_org_name("Acme   Corp").is_err());
        assert!(validate_org_name("Acme Corp").is_ok());
    }

    #[test]
    fn test_org_name_special_characters() {
        assert!(validate_org_name("Acme-Corp").is_ok());
        assert!(validate_org_name("Acme_Corp").is_ok());
        assert!(validate_org_name("Acme@Corp").is_err());
        assert!(validate_org_name("Acme#Corp").is_err());
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
    }

    #[test]
    fn test_username_boundary_lengths() {
        assert!(validate_username("abc").is_ok());
        assert!(validate_username("ab").is_err());
        assert!(validate_username(&"a".repeat(39)).is_ok());
        assert!(validate_username(&"a".repeat(40)).is_err());
    }

    #[test]
    fn test_username_special_chars() {
        assert!(validate_username("user.name").is_err());
        assert!(validate_username("user@name").is_err());
        assert!(validate_username("user name").is_err());
        assert!(validate_username("user-name").is_ok());
        assert!(validate_username("user_name").is_ok());
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
    fn test_email_max_length() {
        // EMAIL_MAX_LEN is 254; build an email that exceeds it
        let long_local = "a".repeat(245);
        let long_email = format!("{}@example.com", long_local);
        assert!(long_email.len() > 254);
        assert!(validate_email(&long_email).is_err());
    }

    #[test]
    fn test_email_edge_cases() {
        assert!(validate_email("a@b.co").is_ok());
        assert!(validate_email("user@sub.domain.example.com").is_ok());
        assert!(validate_email("user+tag@example.com").is_ok());
        assert!(validate_email("first.last@example.com").is_ok());
        assert!(validate_email("user@.com").is_err());
        assert!(validate_email("").is_err());
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
    fn test_ssh_key_all_types() {
        for key_type in ALLOWED_SSH_KEY_TYPES {
            // Just verify the type is accepted (data validation will fail but type check passes)
            let key = format!("{} {}", key_type, "A".repeat(300));
            let result = validate_ssh_public_key(&key);
            // Should not fail with "unsupported type"
            if let Err(e) = &result {
                assert!(
                    !matches!(e, ValidationError::SshKeyUnsupportedType { .. }),
                    "Key type {} should be supported",
                    key_type
                );
            }
        }
    }

    #[test]
    fn test_ssh_key_error_variants() {
        match validate_ssh_public_key("short").unwrap_err() {
            ValidationError::SshKeyTooShort { .. } => {}
            e => panic!("Expected SshKeyTooShort, got {:?}", e),
        }

        let long_key = format!("ssh-ed25519 {}", "A".repeat(2000));
        match validate_ssh_public_key(&long_key).unwrap_err() {
            ValidationError::SshKeyTooLong { .. } => {}
            e => panic!("Expected SshKeyTooLong, got {:?}", e),
        }
    }

    #[test]
    fn test_terraform_sanitization() {
        assert_eq!(
            sanitize_for_terraform("test\"value${}"),
            "test\\\"value\\${}"
        );
        assert_eq!(sanitize_for_terraform("line1\nline2"), "line1\\nline2");
    }

    #[test]
    fn test_terraform_sanitization_edge_cases() {
        assert_eq!(sanitize_for_terraform(""), "");
        assert_eq!(sanitize_for_terraform("plain"), "plain");
        assert_eq!(sanitize_for_terraform("tab\there"), "tab\\there");
        assert_eq!(sanitize_for_terraform("cr\rhere"), "cr\\rhere");
        assert_eq!(sanitize_for_terraform("back\\slash"), "back\\\\slash");
    }

    #[test]
    fn test_shell_sanitization() {
        assert_eq!(
            sanitize_for_shell("safe-file_name.txt"),
            "safe-file_name.txt"
        );
        // '-', '/', and alphanumeric are preserved; '$', '(', ')', ' ' are stripped
        assert_eq!(sanitize_for_shell("evil$(rm -rf /)name"), "evilrm-rf/name");
    }

    #[test]
    fn test_shell_sanitization_edge_cases() {
        assert_eq!(sanitize_for_shell(""), "");
        assert_eq!(sanitize_for_shell("abc123"), "abc123");
        assert_eq!(sanitize_for_shell("path/to/file"), "path/to/file");
        assert_eq!(sanitize_for_shell("file.tar.gz"), "file.tar.gz");
        // sanitize_for_shell allows: alphanumeric, '-', '_', '.', '/'
        assert_eq!(sanitize_for_shell("a;b|c&d"), "abcd");
        assert_eq!(sanitize_for_shell("`whoami`"), "whoami");
        assert_eq!(sanitize_for_shell("hello-world_v2.0"), "hello-world_v2.0");
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

    #[test]
    fn test_role_validation_edge_cases() {
        assert!(validate_role("").is_err());
        assert!(validate_role(" owner").is_err());
        assert!(validate_role("owner ").is_err());
        assert!(validate_role("Owner").is_err());
    }

    #[test]
    fn test_validation_error_display() {
        let err = ValidationError::AppNameLength {
            min: 3,
            max: 63,
            actual: 2,
            span: Span::new(0, 2),
        };
        assert!(err.to_string().contains("3"));
        assert!(err.to_string().contains("63"));

        let err = ValidationError::EmailInvalidFormat;
        assert!(err.to_string().contains("email"));
    }

    #[test]
    fn test_validation_error_codes() {
        let err = ValidationError::AppNameLength {
            min: 3,
            max: 63,
            actual: 2,
            span: Span::new(0, 2),
        };
        assert_eq!(err.code(), "app_name_length");

        let err = ValidationError::EmailInvalidFormat;
        assert_eq!(err.code(), "email_invalid_format");

        let err = ValidationError::SshKeyInvalidBase64;
        assert_eq!(err.code(), "ssh_key_invalid_base64");
    }
}
