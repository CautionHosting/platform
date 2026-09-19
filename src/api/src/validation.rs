// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::types::UserRole;
use regex::Regex;
use std::sync::OnceLock;

const APP_NAME_MIN_LEN: usize = 3;
const APP_NAME_MAX_LEN: usize = 63;
const APP_NAME_PATTERN: &str = r"^[a-zA-Z0-9]([a-zA-Z0-9_-]*[a-zA-Z0-9])?$";

const ORG_NAME_MIN_LEN: usize = 2;
const ORG_NAME_MAX_LEN: usize = 100;
const ORG_NAME_PATTERN: &str = r"^[a-zA-Z0-9][a-zA-Z0-9 _-]*[a-zA-Z0-9]$";

const USERNAME_MIN_LEN: usize = 3;
const USERNAME_MAX_LEN: usize = 39;
const USERNAME_PATTERN: &str = r"^[a-zA-Z0-9][a-zA-Z0-9_-]*[a-zA-Z0-9]$";

const EMAIL_MAX_LEN: usize = 254;
const EMAIL_PATTERN: &str = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$";

const BRANCH_NAME_MIN_LEN: usize = 1;
const BRANCH_NAME_MAX_LEN: usize = 255;
const BRANCH_NAME_PATTERN: &str = r"^[a-zA-Z0-9][a-zA-Z0-9/_.\-]*$";

static APP_NAME_REGEX: OnceLock<Regex> = OnceLock::new();
static ORG_NAME_REGEX: OnceLock<Regex> = OnceLock::new();
static USERNAME_REGEX: OnceLock<Regex> = OnceLock::new();
static BRANCH_NAME_REGEX: OnceLock<Regex> = OnceLock::new();
static EMAIL_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_app_name_regex() -> &'static Regex {
    APP_NAME_REGEX.get_or_init(|| Regex::new(APP_NAME_PATTERN).unwrap())
}

fn get_org_name_regex() -> &'static Regex {
    ORG_NAME_REGEX.get_or_init(|| Regex::new(ORG_NAME_PATTERN).unwrap())
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

pub use crate::errors::ValidationError;

pub fn validate_app_name(name: &str) -> Result<(), ValidationError> {
    let len = name.len();

    if !(APP_NAME_MIN_LEN..=APP_NAME_MAX_LEN).contains(&len) {
        return Err(ValidationError::AppNameLength {
            min: APP_NAME_MIN_LEN,
            max: APP_NAME_MAX_LEN,
            actual: len,
            location: std::panic::Location::caller(),
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
            location: std::panic::Location::caller(),
        });
    }

    Ok(())
}

/// Validate a resource command string. Leaf: source-less domain error.
pub fn validate_cmd(cmd: &str) -> Result<(), ValidationError> {
    if cmd.is_empty() {
        return Err(ValidationError::CmdEmpty {
            location: std::panic::Location::caller(),
        });
    }
    if cmd.len() > 1000 {
        return Err(ValidationError::CmdTooLong {
            max: 1000,
            actual: cmd.len(),
            location: std::panic::Location::caller(),
        });
    }
    Ok(())
}

pub fn validate_branch_name(name: &str) -> Result<(), ValidationError> {
    let len = name.len();

    if !(BRANCH_NAME_MIN_LEN..=BRANCH_NAME_MAX_LEN).contains(&len) {
        return Err(ValidationError::BranchNameLength {
            min: BRANCH_NAME_MIN_LEN,
            max: BRANCH_NAME_MAX_LEN,
            actual: len,
            location: std::panic::Location::caller(),
        });
    }

    if !get_branch_name_regex().is_match(name) {
        return Err(ValidationError::BranchNameInvalidChars {
            location: std::panic::Location::caller(),
        });
    }

    // Reject git-unsafe patterns
    if name.contains("..") || name.contains("@{") || name.ends_with('/') || name.ends_with('.') {
        return Err(ValidationError::BranchNameInvalidChars {
            location: std::panic::Location::caller(),
        });
    }

    Ok(())
}

pub fn validate_org_name(name: &str) -> Result<(), ValidationError> {
    let len = name.len();

    if !(ORG_NAME_MIN_LEN..=ORG_NAME_MAX_LEN).contains(&len) {
        return Err(ValidationError::OrgNameLength {
            min: ORG_NAME_MIN_LEN,
            max: ORG_NAME_MAX_LEN,
            actual: len,
            location: std::panic::Location::caller(),
        });
    }

    if !get_org_name_regex().is_match(name) {
        return Err(ValidationError::OrgNameInvalidChars {
            location: std::panic::Location::caller(),
        });
    }

    if name.contains("  ") {
        return Err(ValidationError::OrgNameConsecutiveSpaces {
            location: std::panic::Location::caller(),
        });
    }

    Ok(())
}

pub fn validate_username(username: &str) -> Result<(), ValidationError> {
    let len = username.len();

    if !(USERNAME_MIN_LEN..=USERNAME_MAX_LEN).contains(&len) {
        return Err(ValidationError::UsernameLength {
            min: USERNAME_MIN_LEN,
            max: USERNAME_MAX_LEN,
            actual: len,
            location: std::panic::Location::caller(),
        });
    }

    if !get_username_regex().is_match(username) {
        return Err(ValidationError::UsernameInvalidChars {
            location: std::panic::Location::caller(),
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
            location: std::panic::Location::caller(),
        });
    }

    if !get_email_regex().is_match(email) {
        return Err(ValidationError::EmailInvalidFormat {
            location: std::panic::Location::caller(),
        });
    }

    Ok(())
}

pub fn validate_role(role: &str) -> Result<UserRole, ValidationError> {
    UserRole::from_str(role).ok_or_else(|| ValidationError::InvalidRole {
        role: role.to_string(),
        location: std::panic::Location::caller(),
    })
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
            location: std::panic::Location::caller(),
        };
        assert!(err.to_string().contains("3"));
        assert!(err.to_string().contains("63"));

        let err = ValidationError::EmailInvalidFormat {
            location: std::panic::Location::caller(),
        };
        assert!(err.to_string().contains("email"));
    }

    #[test]
    fn test_validation_error_codes() {
        let err = ValidationError::AppNameLength {
            min: 3,
            max: 63,
            actual: 2,
            location: std::panic::Location::caller(),
        };
        assert_eq!(err.code(), "app_name_length");

        let err = ValidationError::EmailInvalidFormat {
            location: std::panic::Location::caller(),
        };
        assert_eq!(err.code(), "email_invalid_format");
    }
}
