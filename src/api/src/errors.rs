// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::error::Error;
use std::fmt;
use std::panic::Location;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    #[allow(dead_code)]
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
        location: &'static Location<'static>,
    },
    AppNameInvalidChars {
        invalid_char: char,
        location: &'static Location<'static>,
    },
    /// First or last character is not alphanumeric. Distinct from
    /// `AppNameInvalidChars`: '_' and '-' are legal mid-name but not at the edge.
    AppNameInvalidBoundary {
        invalid_char: char,
        location: &'static Location<'static>,
    },

    AtLeastOneFieldRequired {
        location: &'static Location<'static>,
    },

    CmdEmpty {
        location: &'static Location<'static>,
    },
    CmdTooLong {
        max: usize,
        actual: usize,
        location: &'static Location<'static>,
    },

    OrgNameLength {
        min: usize,
        max: usize,
        actual: usize,
        location: &'static Location<'static>,
    },
    OrgNameInvalidChars {
        location: &'static Location<'static>,
    },
    OrgNameConsecutiveSpaces {
        location: &'static Location<'static>,
    },

    UsernameLength {
        min: usize,
        max: usize,
        actual: usize,
        location: &'static Location<'static>,
    },
    UsernameInvalidChars {
        location: &'static Location<'static>,
    },

    EmailTooLong {
        max: usize,
        actual: usize,
        location: &'static Location<'static>,
    },
    EmailInvalidFormat {
        location: &'static Location<'static>,
    },

    InvalidRole {
        role: String,
        location: &'static Location<'static>,
    },

    BranchNameLength {
        min: usize,
        max: usize,
        actual: usize,
        location: &'static Location<'static>,
    },
    BranchNameInvalidChars {
        location: &'static Location<'static>,
    },

    CommitShaInvalid {
        location: &'static Location<'static>,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AppNameLength {
                min, max, actual, ..
            } => write!(
                f,
                "app name must be between {} and {} characters (got {}) [{}]",
                min,
                max,
                actual,
                self.location()
            ),
            Self::AppNameInvalidChars { invalid_char, .. } => write!(
                f,
                "app name contains invalid character '{}' [{}]",
                invalid_char,
                self.location()
            ),
            Self::AppNameInvalidBoundary { invalid_char, .. } => write!(
                f,
                "app name must start and end with a letter or digit (found '{}') [{}]",
                invalid_char,
                self.location()
            ),

            Self::AtLeastOneFieldRequired { .. } => write!(
                f,
                "at least one field must be provided [{}]",
                self.location()
            ),

            Self::CmdEmpty { .. } => {
                write!(f, "command cannot be empty [{}]", self.location())
            }
            Self::CmdTooLong { max, actual, .. } => write!(
                f,
                "command must be at most {} characters (got {}) [{}]",
                max,
                actual,
                self.location()
            ),

            Self::OrgNameLength {
                min, max, actual, ..
            } => write!(
                f,
                "organization name must be between {} and {} characters (got {}) [{}]",
                min,
                max,
                actual,
                self.location()
            ),
            Self::OrgNameInvalidChars { .. } => write!(
                f,
                "organization name contains invalid characters [{}]",
                self.location()
            ),
            Self::OrgNameConsecutiveSpaces { .. } => write!(
                f,
                "organization name cannot contain consecutive spaces [{}]",
                self.location()
            ),

            Self::UsernameLength {
                min, max, actual, ..
            } => write!(
                f,
                "username must be between {} and {} characters (got {}) [{}]",
                min,
                max,
                actual,
                self.location()
            ),
            Self::UsernameInvalidChars { .. } => write!(
                f,
                "username contains invalid characters [{}]",
                self.location()
            ),

            Self::EmailTooLong { max, actual, .. } => write!(
                f,
                "email address must be at most {} characters (got {}) [{}]",
                max,
                actual,
                self.location()
            ),
            Self::EmailInvalidFormat { .. } => {
                write!(f, "invalid email address format [{}]", self.location())
            }

            Self::InvalidRole { role, .. } => {
                write!(f, "invalid role '{}' [{}]", role, self.location())
            }

            Self::BranchNameLength {
                min, max, actual, ..
            } => write!(
                f,
                "branch name must be between {} and {} characters (got {}) [{}]",
                min,
                max,
                actual,
                self.location()
            ),
            Self::BranchNameInvalidChars { .. } => write!(
                f,
                "branch name contains invalid characters [{}]",
                self.location()
            ),

            Self::CommitShaInvalid { .. } => write!(
                f,
                "invalid commit_sha: must be 40 hex characters [{}]",
                self.location()
            ),
        }
    }
}

impl Error for ValidationError {}

impl ValidationError {
    /// Location where this validation failure was constructed. Internal only:
    /// callers box this error as a `#[source]`; it never reaches a client.
    pub fn location(&self) -> &'static Location<'static> {
        match self {
            Self::AppNameLength { location, .. }
            | Self::AppNameInvalidChars { location, .. }
            | Self::AppNameInvalidBoundary { location, .. }
            | Self::AtLeastOneFieldRequired { location }
            | Self::CmdEmpty { location }
            | Self::CmdTooLong { location, .. }
            | Self::OrgNameLength { location, .. }
            | Self::OrgNameInvalidChars { location }
            | Self::OrgNameConsecutiveSpaces { location }
            | Self::UsernameLength { location, .. }
            | Self::UsernameInvalidChars { location }
            | Self::EmailTooLong { location, .. }
            | Self::EmailInvalidFormat { location }
            | Self::InvalidRole { location, .. }
            | Self::BranchNameLength { location, .. }
            | Self::BranchNameInvalidChars { location }
            | Self::CommitShaInvalid { location } => location,
        }
    }

    #[allow(dead_code)]
    pub fn code(&self) -> &'static str {
        match self {
            Self::AppNameLength { .. } => "app_name_length",
            Self::AppNameInvalidChars { .. } => "app_name_invalid_chars",
            Self::AppNameInvalidBoundary { .. } => "app_name_invalid_boundary",

            Self::AtLeastOneFieldRequired { .. } => "at_least_one_field_required",

            Self::CmdEmpty { .. } => "cmd_empty",
            Self::CmdTooLong { .. } => "cmd_too_long",

            Self::OrgNameLength { .. } => "org_name_length",
            Self::OrgNameInvalidChars { .. } => "org_name_invalid_chars",
            Self::OrgNameConsecutiveSpaces { .. } => "org_name_consecutive_spaces",

            Self::UsernameLength { .. } => "username_length",
            Self::UsernameInvalidChars { .. } => "username_invalid_chars",

            Self::EmailTooLong { .. } => "email_too_long",
            Self::EmailInvalidFormat { .. } => "email_invalid_format",

            Self::InvalidRole { .. } => "invalid_role",

            Self::BranchNameLength { .. } => "branch_name_length",
            Self::BranchNameInvalidChars { .. } => "branch_name_invalid_chars",

            Self::CommitShaInvalid { .. } => "commit_sha_invalid",
        }
    }
}
