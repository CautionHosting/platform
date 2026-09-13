// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
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
    AppNameInvalidChars {
        invalid_char: char,
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

    EmailTooLong {
        max: usize,
        actual: usize,
    },
    EmailInvalidFormat,

    InvalidRole {
        role: String,
    },

    BranchNameLength {
        min: usize,
        max: usize,
        actual: usize,
    },
    BranchNameInvalidChars,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AppNameLength {
                min, max, actual, ..
            } => {
                write!(
                    f,
                    "app name must be between {} and {} characters (got {})",
                    min, max, actual
                )
            }
            Self::AppNameInvalidChars { invalid_char, .. } => {
                write!(f, "app name contains invalid character '{}'", invalid_char)
            }

            Self::OrgNameLength { min, max, actual } => {
                write!(
                    f,
                    "organization name must be between {} and {} characters (got {})",
                    min, max, actual
                )
            }
            Self::OrgNameInvalidChars => {
                write!(f, "organization name contains invalid characters")
            }
            Self::OrgNameConsecutiveSpaces => {
                write!(f, "organization name cannot contain consecutive spaces")
            }

            Self::UsernameLength { min, max, actual } => {
                write!(
                    f,
                    "username must be between {} and {} characters (got {})",
                    min, max, actual
                )
            }
            Self::UsernameInvalidChars => {
                write!(f, "username contains invalid characters")
            }
            Self::EmailTooLong { max, actual } => {
                write!(
                    f,
                    "email address must be at most {} characters (got {})",
                    max, actual
                )
            }
            Self::EmailInvalidFormat => {
                write!(f, "invalid email address format")
            }

            Self::InvalidRole { role } => {
                write!(f, "invalid role '{}'", role)
            }

            Self::BranchNameLength { min, max, actual } => {
                write!(
                    f,
                    "branch name must be between {} and {} characters (got {})",
                    min, max, actual
                )
            }
            Self::BranchNameInvalidChars => {
                write!(f, "branch name contains invalid characters")
            }
        }
    }
}

impl Error for ValidationError {}

impl ValidationError {
    pub fn span(&self) -> Option<Span> {
        match self {
            Self::AppNameLength { span, .. } => Some(*span),
            Self::AppNameInvalidChars { span, .. } => Some(*span),
            _ => None,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::AppNameLength { .. } => "app_name_length",
            Self::AppNameInvalidChars { .. } => "app_name_invalid_chars",

            Self::OrgNameLength { .. } => "org_name_length",
            Self::OrgNameInvalidChars => "org_name_invalid_chars",
            Self::OrgNameConsecutiveSpaces => "org_name_consecutive_spaces",

            Self::UsernameLength { .. } => "username_length",
            Self::UsernameInvalidChars => "username_invalid_chars",

            Self::EmailTooLong { .. } => "email_too_long",
            Self::EmailInvalidFormat => "email_invalid_format",

            Self::InvalidRole { .. } => "invalid_role",

            Self::BranchNameLength { .. } => "branch_name_length",
            Self::BranchNameInvalidChars => "branch_name_invalid_chars",
        }
    }

    pub fn help(&self) -> Option<&'static str> {
        match self {
            Self::AppNameLength { .. } => Some("Choose a name with 3-63 characters"),
            Self::AppNameInvalidChars { .. } => Some(
                "Use only letters, numbers, hyphens, and underscores. Must start and end with alphanumeric.",
            ),

            Self::OrgNameInvalidChars => {
                Some("Use only letters, numbers, spaces, hyphens, and underscores")
            }

            Self::UsernameInvalidChars => {
                Some("Use only letters, numbers, hyphens, and underscores")
            }

            Self::InvalidRole { .. } => Some("Valid roles: owner, admin, member, viewer"),

            Self::BranchNameInvalidChars => Some(
                "Use only letters, numbers, slashes, underscores, dots, and hyphens. Must start with alphanumeric.",
            ),

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
