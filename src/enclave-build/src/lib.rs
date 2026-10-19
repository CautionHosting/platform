// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Interface for building an enclave image from a successfully built Docker
//! image and the whole [`ConfigurationFile`].
//!
//! Each build mechanism (Nitro today; others later) lives in its own crate and
//! implements [`ImageBuildMechanism`], producing an `(image, userdata)` pair.
//! The user-data template is owned by the mechanism; a deploy platform consumes
//! it but does not author it.

// The `CtxError` derive generates a `{Error}Ctx` mirror type per error enum;
// the generated struct initializations trip `redundant_field_names`, and the
// lint cannot be placed on the generated items themselves.
#![allow(
    clippy::redundant_field_names,
    reason = "generated {Error}Ctx mirrors trip redundant_field_names"
)]

pub mod components;
pub mod manifest;

pub use manifest::{
    AppSource, EnclaveManifest, EnclaveSource, FrameworkSource, ReadFromFileError, WriteToFileError,
};

use caution_config::ConfigurationFile;
use dterror::{BoxError, CtxError, Location};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub use caution_config::Platform;

const ENCLAVE_SOURCE_BASE: &str = "https://git.caution.co/public/enclaveos/archive";
pub const FRAMEWORK_SOURCE: &str = "https://git.caution.co/public/platform/archive/main.tar.gz";
/// Canonical archives, historical Codeberg aliases, and their GitHub mirrors.
const ARCHIVE_MIRRORS: [(&str, &str, &str); 2] = [
    (
        "https://git.caution.co/public/platform/archive/",
        "https://codeberg.org/caution/platform/archive/",
        "https://github.com/CautionHosting/platform/archive/",
    ),
    (
        "https://git.caution.co/public/enclaveos/archive/",
        "https://codeberg.org/caution/enclaveos/archive/",
        "https://github.com/CautionHosting/enclaveos/archive/",
    ),
];

pub fn enclave_source_url(commit: &str) -> String {
    format!("{}/{}.tar.gz", ENCLAVE_SOURCE_BASE, commit)
}

pub fn pin_archive_url_to_commit(url: &str, commit: &str) -> String {
    if let Some(archive_pos) = url.find("/archive/") {
        format!("{}/archive/{}.tar.gz", &url[..archive_pos], commit)
    } else {
        url.to_string()
    }
}

/// Return the canonical archive URL followed by any explicitly configured mirrors.
pub fn archive_url_candidates(url: &str) -> Vec<String> {
    let mut candidates = vec![url.to_string()];

    for (canonical, historical, mirror) in ARCHIVE_MIRRORS {
        if let Some(archive_name) = url.strip_prefix(canonical) {
            candidates.push([mirror, archive_name].concat());
        } else if let Some(archive_name) = url.strip_prefix(historical) {
            candidates.push([canonical, archive_name].concat());
            candidates.push([mirror, archive_name].concat());
        }
    }

    candidates
}

/// Classify `enclave_source` (archive URL, git URL, or local path) into the
/// matching `EnclaveSource`. `resolved_commit` is the commit already resolved
/// from the source (git rev-parse / ref lookup), if any. For a local path with
/// no resolved commit, fall back to ENCLAVEOS_COMMIT, and with neither build the
/// on-disk files directly.
pub fn classify_enclave_source(
    enclave_source: &str,
    enclave_version: &str,
    resolved_commit: Option<String>,
) -> EnclaveSource {
    if enclave_source.ends_with(".tar.gz") {
        EnclaveSource::GitArchive {
            urls: vec![enclave_source.to_string()],
            commit: resolved_commit,
        }
    } else if enclave_source.starts_with("http") || enclave_source.starts_with("git@") {
        EnclaveSource::GitRepository {
            url: enclave_source.to_string(),
            branch: enclave_version.to_string(),
            commit: resolved_commit,
        }
    } else {
        let commit = resolved_commit.or_else(|| std::env::var("ENCLAVEOS_COMMIT").ok());
        if let Some(commit) = commit {
            EnclaveSource::GitArchive {
                urls: vec![enclave_source_url(&commit)],
                commit: Some(commit),
            }
        } else {
            EnclaveSource::Local {
                path: enclave_source.to_string(),
            }
        }
    }
}

/// A built Docker image reference that a mechanism consumes as its input.
#[derive(Debug, Clone)]
pub struct UserImage {
    pub reference: String,
}

/// A built enclave image artifact.
#[derive(Debug, Clone)]
pub struct EifFile {
    pub path: PathBuf,
    pub size: u64,
    pub sha256: String,
}

/// PCR measurements over a built image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcrValues {
    pub pcr0: String,
    pub pcr1: String,
    pub pcr2: String,
    pub pcr3: Option<String>,
    pub pcr4: Option<String>,
}

/// The kind of build cache a mechanism may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildCacheType {
    Build,
    Reproduction,
}

impl BuildCacheType {
    /// Directory name used to namespace this cache kind.
    pub fn dir_name(&self) -> &'static str {
        match self {
            BuildCacheType::Build => "build",
            BuildCacheType::Reproduction => "reproductions",
        }
    }
}

/// Where a mechanism should place its build workspace.
#[derive(Debug, Clone)]
pub enum BuildWorkspace {
    /// A cache directory keyed by organization and cache key under `base_dir`.
    Cache {
        base_dir: PathBuf,
        org_id: String,
        cache_key: String,
        cache_type: BuildCacheType,
    },
    /// An explicit directory supplied by the caller.
    Directory(PathBuf),
}

/// Mechanism-independent build inputs. Everything else the mechanism needs is
/// read from the [`ConfigurationFile`].
#[derive(Debug, Clone)]
pub struct BuildInput {
    /// The successfully built application Docker image.
    pub docker_image: UserImage,
    /// Enclave source (archive URL, git URL, or local path).
    pub enclave_source: String,
    /// Enclave version (git tag, commit, or "local").
    pub enclave_version: String,
    /// Framework source URL.
    pub framework_source: String,
    /// Where the mechanism should build.
    pub workspace: BuildWorkspace,
    /// External manifest for a reproducible build, if any.
    pub manifest: Option<EnclaveManifest>,
    /// Application source provenance recorded in a generated manifest.
    pub app_source: Option<AppSource>,
    /// Free-form metadata recorded in a generated manifest.
    pub metadata: Option<String>,
    /// Prebuilt component directory, if the caller staged one.
    pub prebuilt_components: Option<PathBuf>,
    /// Whether to skip Docker cache for the image build.
    pub no_cache: bool,
}

/// The user-data template produced by a build mechanism for its platform.
#[derive(Debug, Clone)]
pub struct UserData {
    pub template: String,
}

/// The `(image, userdata)` pair plus measurements produced by a mechanism.
#[derive(Debug, Clone)]
pub struct BuildArtifacts {
    pub image: EifFile,
    pub user_data: UserData,
    pub pcrs: Option<PcrValues>,
    /// Paired TAP tunnel helper produced alongside the image, when the build
    /// enables egress.
    pub tap_framer: Option<PathBuf>,
    /// The mechanism's build workspace, exposed for inspection tooling.
    pub work_dir: PathBuf,
}

/// Error type for [`ImageBuildMechanism::build`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error, CtxError)]
pub enum ImageBuildError {
    #[error("invalid configuration for build mechanism [{location}]")]
    InvalidConfiguration {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("enclave build failed [{location}]")]
    Build {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// A build mechanism turns a built Docker image into an `(image, userdata)`
/// pair for a specific set of platforms.
#[async_trait::async_trait]
pub trait ImageBuildMechanism: Send + Sync {
    /// Stable mechanism identifier used in logs and error messages.
    fn name(&self) -> &'static str;

    /// Platforms this mechanism can produce artifacts for.
    fn supported_platforms(&self) -> &'static [Platform];

    /// Build the enclave image and user-data from the built Docker image and the
    /// whole configuration file.
    async fn build(
        &self,
        input: BuildInput,
        config: &ConfigurationFile,
    ) -> Result<BuildArtifacts, ImageBuildError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_url_candidates_adds_configured_mirrors() {
        for (canonical_prefix, historical_prefix, github_prefix) in ARCHIVE_MIRRORS {
            for archive_name in ["main.tar.gz", "abc123.tar.gz"] {
                let canonical = [canonical_prefix, archive_name].concat();
                let historical = [historical_prefix, archive_name].concat();
                let github = [github_prefix, archive_name].concat();
                assert_eq!(
                    archive_url_candidates(&canonical),
                    vec![canonical.clone(), github.clone()]
                );
                assert_eq!(
                    archive_url_candidates(&historical),
                    vec![historical, canonical, github]
                );
            }
        }
    }
}
