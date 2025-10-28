// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::error::Error;
use std::fmt;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl From<(usize, usize)> for Span {
    fn from((start, end): (usize, usize)) -> Self {
        Self::new(start, end)
    }
}

#[derive(Debug)]
pub enum ValidationError {
    AppNameLength {
        min: usize,
        max: usize,
        actual: usize,
        span: Span,
    },
    AppNameReserved {
        name: String,
        span: Span,
    },
    AppNameInvalidChars {
        invalid_char: char,
        span: Span,
    },
    AppNameConsecutiveHyphens {
        span: Span,
    },

    OrgNameLength {
        min: usize,
        max: usize,
        actual: usize,
    },
    OrgNameInvalidChars,
    OrgNameConsecutiveSpaces,


    UsernameLength {
        min: usize,
        max: usize,
        actual: usize,
    },
    UsernameInvalidChars,
    UsernameReserved {
        username: String,
    },

    EmailTooLong {
        max: usize,
        actual: usize,
    },
    EmailInvalidFormat,

    SshKeyTooShort {
        min: usize,
        actual: usize,
    },
    SshKeyTooLong {
        max: usize,
        actual: usize,
    },
    SshKeyInvalidFormat {
        expected: &'static str,
    },
    SshKeyUnsupportedType {
        key_type: String,
    },
    SshKeyInvalidBase64,
    SshKeyDataTooShort {
        key_type: String,
    },
    SshKeyEmptyData,

    InvalidRole {
        role: String,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AppNameLength { min, max, actual, .. } => {
                write!(f, "app name must be between {} and {} characters (got {})", min, max, actual)
            }
            Self::AppNameReserved { name, .. } => {
                write!(f, "app name '{}' is reserved", name)
            }
            Self::AppNameInvalidChars { invalid_char, .. } => {
                write!(f, "app name contains invalid character '{}'", invalid_char)
            }
            Self::AppNameConsecutiveHyphens { .. } => {
                write!(f, "app name cannot contain consecutive hyphens")
            }

            Self::OrgNameLength { min, max, actual } => {
                write!(f, "organization name must be between {} and {} characters (got {})", min, max, actual)
            }
            Self::OrgNameInvalidChars => {
                write!(f, "organization name contains invalid characters")
            }
            Self::OrgNameConsecutiveSpaces => {
                write!(f, "organization name cannot contain consecutive spaces")
            }

            Self::UsernameLength { min, max, actual } => {
                write!(f, "username must be between {} and {} characters (got {})", min, max, actual)
            }
            Self::UsernameInvalidChars => {
                write!(f, "username contains invalid characters")
            }
            Self::UsernameReserved { username } => {
                write!(f, "username '{}' is reserved", username)
            }

            Self::EmailTooLong { max, actual } => {
                write!(f, "email address must be at most {} characters (got {})", max, actual)
            }
            Self::EmailInvalidFormat => {
                write!(f, "invalid email address format")
            }

            Self::SshKeyTooShort { min, actual } => {
                write!(f, "SSH public key is too short (minimum {} characters, got {})", min, actual)
            }
            Self::SshKeyTooLong { max, actual } => {
                write!(f, "SSH public key is too long (maximum {} characters, got {})", max, actual)
            }
            Self::SshKeyInvalidFormat { expected } => {
                write!(f, "SSH public key must have format: {}", expected)
            }
            Self::SshKeyUnsupportedType { key_type } => {
                write!(f, "unsupported SSH key type '{}'", key_type)
            }
            Self::SshKeyInvalidBase64 => {
                write!(f, "SSH key data is not valid base64")
            }
            Self::SshKeyDataTooShort { key_type } => {
                write!(f, "SSH key data is too short for key type '{}'", key_type)
            }
            Self::SshKeyEmptyData => {
                write!(f, "SSH public key decoded to empty data")
            }

            Self::InvalidRole { role } => {
                write!(f, "invalid role '{}'", role)
            }
        }
    }
}

impl Error for ValidationError {}

impl ValidationError {
    pub fn span(&self) -> Option<Span> {
        match self {
            Self::AppNameLength { span, .. } => Some(*span),
            Self::AppNameReserved { span, .. } => Some(*span),
            Self::AppNameInvalidChars { span, .. } => Some(*span),
            Self::AppNameConsecutiveHyphens { span } => Some(*span),
            _ => None,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::AppNameLength { .. } => "app_name_length",
            Self::AppNameReserved { .. } => "app_name_reserved",
            Self::AppNameInvalidChars { .. } => "app_name_invalid_chars",
            Self::AppNameConsecutiveHyphens { .. } => "app_name_consecutive_hyphens",

            Self::OrgNameLength { .. } => "org_name_length",
            Self::OrgNameInvalidChars => "org_name_invalid_chars",
            Self::OrgNameConsecutiveSpaces => "org_name_consecutive_spaces",

            Self::UsernameLength { .. } => "username_length",
            Self::UsernameInvalidChars => "username_invalid_chars",
            Self::UsernameReserved { .. } => "username_reserved",

            Self::EmailTooLong { .. } => "email_too_long",
            Self::EmailInvalidFormat => "email_invalid_format",

            Self::SshKeyTooShort { .. } => "ssh_key_too_short",
            Self::SshKeyTooLong { .. } => "ssh_key_too_long",
            Self::SshKeyInvalidFormat { .. } => "ssh_key_invalid_format",
            Self::SshKeyUnsupportedType { .. } => "ssh_key_unsupported_type",
            Self::SshKeyInvalidBase64 => "ssh_key_invalid_base64",
            Self::SshKeyDataTooShort { .. } => "ssh_key_data_too_short",
            Self::SshKeyEmptyData => "ssh_key_empty_data",

            Self::InvalidRole { .. } => "invalid_role",
        }
    }

    pub fn help(&self) -> Option<&'static str> {
        match self {
            Self::AppNameLength { .. } => Some("Choose a name with 3-63 characters"),
            Self::AppNameReserved { .. } => Some("Reserved names: api, admin, root, system, etc."),
            Self::AppNameInvalidChars { .. } => {
                Some("Use only lowercase letters, numbers, and hyphens. Must start and end with alphanumeric.")
            }
            Self::AppNameConsecutiveHyphens { .. } => {
                Some("Use single hyphens to separate words: my-app (not my--app)")
            }

            Self::OrgNameInvalidChars => {
                Some("Use only letters, numbers, spaces, hyphens, and underscores")
            }

            Self::UsernameInvalidChars => {
                Some("Use only letters, numbers, hyphens, and underscores")
            }
            Self::UsernameReserved { .. } => Some("Try a different username"),

            Self::SshKeyUnsupportedType { .. } => {
                Some("Supported types: ssh-ed25519, ssh-rsa, ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521")
            }

            Self::InvalidRole { .. } => {
                Some("Valid roles: owner, admin, member, viewer")
            }

            _ => None,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span: Option<SpanResponse>,
}

#[derive(Debug, Serialize)]
pub struct SpanResponse {
    pub start: usize,
    pub end: usize,
}

impl From<&ValidationError> for ErrorResponse {
    fn from(err: &ValidationError) -> Self {
        Self {
            error: err.to_string(),
            code: err.code().to_string(),
            help: err.help().map(String::from),
            span: err.span().map(|s| SpanResponse {
                start: s.start,
                end: s.end,
            }),
        }
    }
}

impl IntoResponse for ValidationError {
    fn into_response(self) -> Response {
        let body = Json(ErrorResponse::from(&self));
        (StatusCode::BAD_REQUEST, body).into_response()
    }
}
