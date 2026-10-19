// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Interface for deploying an enclave `(image, userdata)` pair to a cloud
//! platform.
//!
//! Each platform implementation (AWS today; GCP and Azure later) lives in its
//! own crate and implements [`EnclaveDeployer`]. Both the build mechanism and
//! the deploy platform consume the whole [`ConfigurationFile`], so nested
//! fields such as sizing and network policy are never passed around as loose
//! arguments.

// The `CtxError` derive generates a `{Error}Ctx` mirror type per error enum;
// the generated struct initializations trip `redundant_field_names`, and the
// lint cannot be placed on the generated items themselves.
#![allow(
    clippy::redundant_field_names,
    reason = "generated {Error}Ctx mirrors trip redundant_field_names"
)]

use caution_config::{ConfigurationFile, Platform};
use dterror::{BoxError, CtxError, Location};
use serde::{Deserialize, Serialize};

/// Result of a successful deployment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentResult {
    pub instance_id: String,
    pub public_ip: String,
    pub url: String,
    pub instance_type: Option<String>,
}

/// The `(image, userdata)` pair handed to a deploy platform.
///
/// The image is identified by a location the platform can read; user-data is the
/// template authored by the build mechanism.
#[derive(Debug, Clone)]
pub struct DeployArtifacts {
    /// Image location, e.g. `s3://bucket/key` or a local path.
    pub image_path: String,
    /// S3 object key of a pre-uploaded image, when applicable.
    pub image_s3_key: Option<String>,
    /// User-data template authored by the build mechanism.
    pub user_data: String,
}

/// Error type for [`EnclaveDeployer`] operations.
#[non_exhaustive]
#[derive(Debug, thiserror::Error, CtxError)]
pub enum DeployError {
    #[error("build mechanism '{mechanism}' cannot deploy to platform {platform:?} [{location}]")]
    UnsupportedCombination {
        mechanism: &'static str,
        platform: Platform,
        #[location]
        location: Location,
    },

    #[error(
        "configured platform {configured:?} does not match deploy platform {deployer:?} [{location}]"
    )]
    PlatformMismatch {
        configured: Platform,
        deployer: Platform,
        #[location]
        location: Location,
    },

    #[error("deployment configuration is invalid [{location}]")]
    InvalidConfiguration {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("deployment failed [{location}]")]
    Deploy {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("deployment teardown failed [{location}]")]
    Destroy {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Verify a build mechanism can produce artifacts for a deploy platform.
#[tracing::instrument(skip_all, err)]
pub fn ensure_supported(
    mechanism: &'static str,
    supported_platforms: &[Platform],
    platform: Platform,
) -> Result<(), DeployError> {
    if supported_platforms.contains(&platform) {
        Ok(())
    } else {
        Err(DeployError::UnsupportedCombination {
            mechanism,
            platform,
            location: std::panic::Location::caller(),
        })
    }
}

/// Verify the deploy platform selected for the configuration matches the
/// deployer that will run it.
///
/// A mismatch means the wrong deployer was constructed for the configuration,
/// so no build or deploy work should start.
#[tracing::instrument(skip_all, err)]
pub fn ensure_platform_match(configured: Platform, deployer: Platform) -> Result<(), DeployError> {
    if configured == deployer {
        Ok(())
    } else {
        Err(DeployError::PlatformMismatch {
            configured,
            deployer,
            location: std::panic::Location::caller(),
        })
    }
}

/// A deploy platform launches (and tears down) an enclave for a platform.
///
/// Contexts carry the non-configuration facts a platform needs (organization,
/// resource identity, credentials). They are associated types so the interface
/// stays free of any single platform's request shape.
#[async_trait::async_trait]
pub trait EnclaveDeployer: Send + Sync {
    /// Platform facts required to deploy.
    type DeployContext: Send + Sync;

    /// Platform facts required to destroy.
    type DestroyContext: Send + Sync;

    /// The platform this deployer targets.
    fn platform(&self) -> Platform;

    /// Deploy the artifacts to the platform, reading sizing and network policy
    /// from the whole configuration file.
    async fn deploy(
        &self,
        config: &ConfigurationFile,
        artifacts: &DeployArtifacts,
        ctx: &Self::DeployContext,
    ) -> Result<DeploymentResult, DeployError>;

    /// Tear down a previously deployed enclave.
    async fn destroy(&self, ctx: &Self::DestroyContext) -> Result<(), DeployError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // `Platform` has a single variant today, so only the matching case is
    // constructible. The mismatch arm guards against a second platform being
    // added without a matching deployer.
    #[test]
    fn ensure_platform_match_accepts_matching_platform() {
        assert!(ensure_platform_match(Platform::Aws, Platform::Aws).is_ok());
    }
}
