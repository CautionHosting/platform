// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Startup validation for the AWS credentials used to provision child accounts.
//!
//! User-account provisioning no longer lives here: the default organization and
//! owner membership are now created with the user in the gateway at signup, so no
//! api request has to create one.

use dterror::Location;

/// Failure modes for [`validate_setup`] (leaf error: no underlying source).
#[derive(Debug, thiserror::Error)]
pub enum ValidateSetupError {
    #[error("AWS_ACCESS_KEY_ID environment variable not set [{location}]")]
    MissingAccessKeyId { location: Location },

    #[error("AWS_SECRET_ACCESS_KEY environment variable not set [{location}]")]
    MissingSecretAccessKey { location: Location },
}

/// Verifies the AWS credentials required for child-account provisioning are set.
#[tracing::instrument(skip_all, err)]
pub fn validate_setup() -> Result<(), ValidateSetupError> {
    if std::env::var("AWS_ACCESS_KEY_ID").is_err() {
        return Err(ValidateSetupError::MissingAccessKeyId {
            location: std::panic::Location::caller(),
        });
    }
    if std::env::var("AWS_SECRET_ACCESS_KEY").is_err() {
        return Err(ValidateSetupError::MissingSecretAccessKey {
            location: std::panic::Location::caller(),
        });
    }

    Ok(())
}
