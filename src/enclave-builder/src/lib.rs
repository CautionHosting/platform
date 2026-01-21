// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

pub const ENCLAVE_SOURCE: &str = "https://git.distrust.co/public/enclaveos/archive/master.tar.gz";
pub const FRAMEWORK_SOURCE: &str = "https://codeberg.org/caution/platform/archive/main.tar.gz";

pub mod build;
pub mod compile;
pub mod docker;
pub mod extract;
pub mod manifest;
pub mod merge;
pub mod pcrs;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{debug, info, warn};

pub use compile::{EnclaveSourceResult, resolve_ref_to_commit};
pub use docker::{BuildConfig, build_user_image};
pub use manifest::{AppSource, EnclaveManifest, EnclaveSource, FrameworkSource};

pub use CacheType as BuildCacheType;

#[derive(Debug, Clone)]
pub struct EnclaveBuilder {
    /// Template repository URL or local path
    pub template_source: String,
    /// Template version (git tag, commit, or "local")
    pub template_version: String,
    /// Enclave source code location (git URL or local path to enclave/ directory)
    pub enclave_source: String,
    /// Enclave version (git tag, commit, or "local")
    pub enclave_version: String,
    /// Framework source URL
    pub framework_source: String,
    /// Working directory for builds
    pub work_dir: PathBuf,
    /// Whether to skip Docker cache for EIF builds
    pub no_cache: bool,
}

#[derive(Debug, Clone)]
pub struct UserImage {
    pub reference: String,
}

#[derive(Debug, Clone)]
pub struct EifFile {
    pub path: PathBuf,
    pub size: usize,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcrValues {
    pub pcr0: String,
    pub pcr1: String,
    pub pcr2: String,
    pub pcr3: Option<String>,
    pub pcr4: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Deployment {
    pub eif: EifFile,
    pub pcrs: PcrValues,
    pub image_ref: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheType {
    Build,
    Reproduction,
}

impl CacheType {
    fn dir_name(self) -> &'static str {
        match self {
            CacheType::Build => "build",
            CacheType::Reproduction => "reproductions",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EnclaveBuilderCreationError {
    #[error("cache directory not found")]
    CacheDirNotFound,

    #[error("could not remove existing working directory {path:?}")]
    CouldNotRemoveWorkDir {
        path: std::path::PathBuf,

        #[source]
        source: std::io::Error,
    },

    #[error("could not create working directory")]
    CouldNotCreateWorkDir {
        path: std::path::PathBuf,

        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug)]
pub enum CachedEifErrorKind {
    FileRead,
    HashRead,
    JsonParse,
    Metadata,
}

#[derive(Debug, thiserror::Error)]
#[error("error finding cached EIF: {kind:?} (path: {path:?})")]
pub struct CachedEifError {
    kind: CachedEifErrorKind,
    path: PathBuf,

    #[source]
    source: Box<dyn std::error::Error>,
}

#[derive(Debug)]
pub enum PcrSaveErrorKind {
    Serialize,
    Write { path: PathBuf },
}

#[derive(Debug, thiserror::Error)]
#[error("could not save PCRs to cache: {kind:?}")]
pub struct PcrSaveError {
    kind: PcrSaveErrorKind,

    #[source]
    source: Box<dyn std::error::Error>,
}

#[derive(Debug, thiserror::Error)]
#[error("could not extract user image")]
pub enum UserImageExtractError {
    SpecificFiles(#[from] extract::FileExtractError),
    WholeFilesystem(#[from] extract::ImageFilesystemExtractError),
}

// TODO: move to API
fn is_safe_cache_key_char(ch: char) -> bool {
    ch.is_alphanumeric() || ch == '-' || ch == '_'
}

fn to_safe_cache_key(input: &str, key_type: &'static str) -> String {
    if input.chars().all(is_safe_cache_key_char) {
        input.to_owned()
    } else {
        warn!(?input, key_type, "unsafe cache key");
        input
            .chars()
            .map(|c| if is_safe_cache_key_char(c) { c } else { '_' })
            .collect()
    }
}

macro_rules! to_safe_cache_key {
    ($input:ident) => {{ to_safe_cache_key($input, stringify!($input)) }};
}

impl EnclaveBuilder {
    /// Create a new [`EnclaveBuilder`] with a persistent cache directory.
    ///
    /// # Errors
    ///
    /// The function may return an error if:
    ///
    /// * A directory to store cache files could not be found
    /// * An existing working directory could not be removed
    /// * A new working directory could not be created
    #[tracing::instrument(skip(
        template_source,
        template_version,
        enclave_source,
        enclave_version,
        framework_source,
        no_cache,
        /* work_dir: if only we could skip_all */
    ))]
    pub fn new(
        template_source: impl Into<String>,
        template_version: impl Into<String>,
        enclave_source: impl Into<String>,
        enclave_version: impl Into<String>,
        framework_source: impl Into<String>,
        work_dir: impl AsRef<std::path::Path> + std::fmt::Debug,
        no_cache: bool,
    ) -> Result<Self, EnclaveBuilderCreationError> {
        let template_source = template_source.into();
        let template_version = template_version.into();
        let enclave_source = enclave_source.into();
        let enclave_version = enclave_version.into();
        let framework_source = framework_source.into();
        let work_dir = work_dir.as_ref();

        if no_cache && work_dir.exists() {
            info!(no_cache, "removing existing working directory");
            std::fs::remove_dir_all(work_dir).map_err(|source| {
                EnclaveBuilderCreationError::CouldNotRemoveWorkDir {
                    path: work_dir.to_owned(),
                    source,
                }
            })?;
        }

        debug!("creating working directory");
        std::fs::create_dir_all(work_dir).map_err(|source| {
            EnclaveBuilderCreationError::CouldNotCreateWorkDir {
                path: work_dir.to_owned(),
                source,
            }
        })?;

        info!(
            ?template_source,
            ?template_version,
            ?enclave_source,
            ?enclave_version,
            ?framework_source,
            ?no_cache,
            "created EnclaveBuilder"
        );

        Ok(Self {
            template_source,
            template_version,
            enclave_source,
            enclave_version,
            framework_source,
            work_dir: work_dir.to_owned(),
            no_cache: false,
        })
    }

    /// Get the metadata of a cached EIF.
    ///
    /// The method may return None if any cached EIF file does not exist.
    ///
    /// # Errors
    ///
    /// The method may return an error if:
    ///
    /// * The PCRs could not be read from a file
    /// * The PCRs could not be parsed
    /// * The EIF file could not have its metadata read
    /// * The EIF hash could not be read from a file
    #[tracing::instrument]
    pub fn get_cached_eif(&self) -> Result<Option<Deployment>, CachedEifError> {
        let eif_path = self.work_dir.join("enclave.eif");
        let eif_hash_path = self.work_dir.join("enclave.eif.sha256");
        let pcrs_path = self.work_dir.join("enclave.eif.pcrs");

        if !eif_path.exists() || !eif_hash_path.exists() || !pcrs_path.exists() {
            info!(?eif_path, ?eif_hash_path, ?pcrs_path, "One or more cached files didn't exist");
            return Ok(None);
        }

        let pcrs_content =
            std::fs::read_to_string(&pcrs_path).map_err(|source| CachedEifError {
                kind: CachedEifErrorKind::FileRead,
                path: pcrs_path.clone(),
                source: source.into(),
            })?;

        let pcrs: PcrValues =
            serde_json::from_str(&pcrs_content).map_err(|source| CachedEifError {
                kind: CachedEifErrorKind::JsonParse,
                path: pcrs_path.clone(),
                source: source.into(),
            })?;

        let metadata = std::fs::metadata(&eif_path).map_err(|source| CachedEifError {
            kind: CachedEifErrorKind::Metadata,
            path: eif_path.clone(),
            source: source.into(),
        })?;

        let sha256 = std::fs::read_to_string(&eif_hash_path)
            .map_err(|source| CachedEifError {
                kind: CachedEifErrorKind::HashRead,
                path: eif_hash_path.clone(),
                source: source.into(),
            })?
            .trim()
            .to_string();

        info!(?eif_path, "Found cached EIF ({} bytes)", metadata.len());

        Ok(Some(Deployment {
            eif: EifFile {
                path: eif_path,
                size: metadata.len().try_into().expect("u64 to usize"),
                sha256,
            },
            pcrs,
            image_ref: "cached".to_string(),
        }))
    }

    /// Save the PCRs to a cache
    ///
    /// # Errors
    ///
    /// The method may return an error if:
    ///
    /// * The PCRs could not be serialized
    /// * The serialized PCRs could not be written to a file
    #[tracing::instrument(skip(pcrs))]
    fn save_pcrs_to_cache(&self, pcrs: &PcrValues) -> Result<(), PcrSaveError> {
        let pcrs_path = self.work_dir.join("enclave.eif.pcrs");
        let pcrs_json = serde_json::to_string_pretty(pcrs).map_err(|source| PcrSaveError {
            kind: PcrSaveErrorKind::Serialize,
            source: source.into(),
        })?;
        std::fs::write(&pcrs_path, pcrs_json).map_err(|source| PcrSaveError {
            kind: PcrSaveErrorKind::Write {
                path: pcrs_path.clone(),
            },
            source: source.into(),
        })?;

        info!(?pcrs_path, ?pcrs, "Saved PCRs to cache");
        Ok(())
    }

    /// Extract an image into a directory.
    ///
    /// # Errors
    ///
    /// The method may return an error if:
    ///
    /// * An error was encountered when creating and exporting a container
    /// * An error was encountered when managing the exported tarball
    #[tracing::instrument(skip_all)]
    pub async fn extract_user_image(
        &self,
        image: &UserImage,
        specific_files: Option<Vec<String>>,
    ) -> Result<PathBuf, UserImageExtractError> {
        if let Some(files) = specific_files {
            info!(?files, "Extracting specific files");
            extract::extract_specific_files(&image.reference, &files, &self.work_dir)
                .await
                .map_err(Into::into)
        } else {
            info!("Extracting full filesystem");
            extract::extract_image_filesystem(&image.reference, &self.work_dir)
                .await
                .map_err(Into::into)
        }
    }

    // TODO: don't support static binary usecase, extract from a single file Docker image
    // remove this code
    #[allow(clippy::missing_errors_doc)]
    async fn extract_static_binary(&self, image: &UserImage, binary_path: &str) -> Result<PathBuf> {
        tracing::info!("Extracting static binary: {}", binary_path);
        extract::extract_static_binary(&image.reference, binary_path, &self.work_dir).await
    }

    // TODO: where is this used? eliminate dead code
    #[allow(clippy::missing_errors_doc, dead_code)]
    #[deprecated = "unused"]
    async fn build_combined_image(
        &self,
        user_fs_path: PathBuf,
        output_image_tag: &str,
    ) -> Result<String> {
        #[allow(deprecated)]
        merge::build_combined_image(
            &self.template_source,
            &self.template_version,
            user_fs_path,
            output_image_tag,
            &self.work_dir,
        )
        .await
    }

    /// Build an enclave from a local filesystem export
    #[tracing::instrument(skip_all)]
    pub async fn build_eif_native(
        &self,
        user_fs_path: &std::path::Path,
        attestation_service_path: &std::path::Path,
        init_path: &std::path::Path,
        enclave_source_path: &std::path::Path,
        output_path: PathBuf,
        run_command: Option<String>,
        manifest: Option<EnclaveManifest>,
        ports: &[u16],
        e2e: bool,
    ) -> Result<EifFile, build::EifBuildError> {
        debug!(
            ?user_fs_path,
            ?attestation_service_path,
            ?init_path,
            ?enclave_source_path,
            ?output_path,
            ?run_command,
            ?manifest,
            ?ports,
            ?e2e,
            "Building EIF from filesystem"
        );
        build::build_eif_from_filesystems(
            user_fs_path,
            attestation_service_path,
            init_path,
            enclave_source_path,
            output_path,
            &self.work_dir,
            run_command,
            manifest,
            ports,
            self.no_cache,
            e2e,
        )
        .await
    }

    pub fn extract_pcrs(&self, eif: &EifFile) -> Result<PcrValues, pcrs::PcrExtractError> {
        pcrs::extract_pcrs_from_eif(eif)
    }

    pub fn parse_attestation_pcrs(&self, attestation_b64: &str) -> Result<PcrValues> {
        pcrs::parse_attestation_document(attestation_b64)
    }

    pub fn compare_pcrs(&self, local: &PcrValues, remote: &PcrValues) -> bool {
        local.pcr0 == remote.pcr0 && local.pcr1 == remote.pcr1 && local.pcr2 == remote.pcr2
    }

    pub fn is_debug_mode(&self, pcrs: &PcrValues) -> bool {
        pcrs::is_debug_mode(pcrs)
    }

    /// Resolve framework_source archive URL to a commit SHA
    async fn resolve_framework_commit(framework_source: &str) -> Option<String> {
        tracing::info!(
            "resolve_framework_commit: framework_source={}",
            framework_source
        );

        // Extract git URL and ref from archive URL like:
        // https://codeberg.org/caution/platform/archive/main.tar.gz
        if let Some(archive_pos) = framework_source.find("/archive/") {
            let base_url = &framework_source[..archive_pos];
            let git_url = format!("{}.git", base_url);

            let after_archive = &framework_source[archive_pos + 9..];
            let ref_name = after_archive
                .trim_end_matches(".tar.gz")
                .trim_end_matches(".tar");

            tracing::info!("Extracted git_url={}, ref_name={}", git_url, ref_name);

            if !ref_name.is_empty() {
                tracing::info!("Resolving framework ref '{}' to commit SHA", ref_name);
                if let Some(sha) = compile::resolve_ref_to_commit(&git_url, ref_name).await {
                    tracing::info!("Resolved framework '{}' to commit {}", ref_name, sha);
                    return Some(sha);
                }
                tracing::warn!(
                    "Could not resolve framework ref '{}' from '{}'",
                    ref_name,
                    git_url
                );
            }
        } else {
            tracing::info!("No /archive/ found in framework_source, skipping commit resolution");
        }
        None
    }

    pub async fn build_enclave(
        &self,
        user_image: &UserImage,
        specific_files: Option<Vec<String>>,
        run_command: Option<String>,
        app_source_urls: Option<Vec<String>>,
        app_branch: Option<String>,
        app_commit: Option<String>,
        metadata: Option<String>,
        external_manifest: Option<EnclaveManifest>,
        ports: &[u16],
        e2e: bool,
    ) -> Result<Deployment> {
        if let Some(cached) = self.get_cached_eif().expect(/* XXX */ "cached EIF error") {
            tracing::info!("Using cached EIF from: {}", cached.eif.path.display());
            return Ok(cached);
        }

        tracing::info!(
            "Starting enclave build for user image: {}",
            user_image.reference
        );

        let binary_path = specific_files
            .as_ref()
            .and_then(|files| files.first().cloned());
        let run_command = run_command.or_else(|| binary_path.clone());

        tracing::info!("Extracting user image filesystem...");
        let user_fs = if let Some(ref bin_path) = binary_path {
            tracing::info!(
                "Binary path specified: {} - extracting static binary only",
                bin_path
            );
            self.extract_static_binary(user_image, bin_path).await?
        } else {
            tracing::info!("No binary path specified - extracting full filesystem");
            self.extract_user_image(user_image, None).await?
        };

        let enclave_source_result = compile::get_or_clone_enclave_source(
            &self.enclave_source,
            &self.enclave_version,
            &self.work_dir,
        )
        .await?;
        let enclave_source_path = enclave_source_result.path.clone();

        // Resolve framework_source commit
        let framework_commit = Self::resolve_framework_commit(&self.framework_source).await;

        let manifest = if let Some(ext_manifest) = external_manifest {
            tracing::info!("Using external manifest for reproducible build");
            ext_manifest
        } else {
            let enclave_src = if self.enclave_source.ends_with(".tar.gz") {
                EnclaveSource::GitArchive {
                    urls: vec![self.enclave_source.clone()],
                    commit: enclave_source_result.commit.clone(),
                }
            } else if self.enclave_source.starts_with("http")
                || self.enclave_source.starts_with("git@")
            {
                EnclaveSource::GitRepository {
                    url: self.enclave_source.clone(),
                    branch: self.enclave_version.clone(),
                    commit: enclave_source_result.commit.clone(),
                }
            } else {
                EnclaveSource::Local {
                    path: self.enclave_source.clone(),
                }
            };

            let app_src = match (app_source_urls, app_commit.clone()) {
                (Some(urls), Some(commit)) if !urls.is_empty() => Some(AppSource {
                    urls,
                    commit,
                    branch: app_branch.clone(),
                }),
                _ => None,
            };

            let framework_src = FrameworkSource::GitArchive {
                url: self.framework_source.clone(),
                commit: framework_commit.clone(),
            };

            tracing::info!(
                "Manifest source commits - enclave: {:?}, framework: {:?}, app: {:?}",
                enclave_source_result.commit,
                framework_commit,
                app_commit
            );

            EnclaveManifest::new(
                app_src,
                enclave_src,
                framework_src,
                binary_path.clone(),
                run_command.clone(),
                metadata,
            )
        };

        tracing::info!("Building EIF...");
        let eif_path = self.work_dir.join("enclave.eif");
        let dummy_path = std::path::PathBuf::from("/dev/null");
        let eif = self
            .build_eif_native(
                &user_fs,
                &dummy_path,
                &dummy_path,
                &enclave_source_path,
                eif_path,
                run_command,
                Some(manifest),
                ports,
                e2e,
            )
            .await?;

        tracing::info!("Extracting PCR values...");
        let pcrs = self
            .extract_pcrs(&eif)
            .context("Failed to extract PCR values - ensure eif_build generated .pcrs file")?;

        if let Err(e) = self.save_pcrs_to_cache(&pcrs) {
            tracing::warn!("Failed to save PCRs to cache: {}", e);
        }

        tracing::info!("Enclave build complete!");
        Ok(Deployment {
            eif,
            pcrs,
            image_ref: user_image.reference.clone(),
        })
    }

    pub async fn build_enclave_from_filesystem(
        &self,
        user_fs_path: PathBuf,
        run_command: Option<String>,
        app_source_urls: Option<Vec<String>>,
        app_branch: Option<String>,
        app_commit: Option<String>,
        metadata: Option<String>,
        external_manifest: Option<EnclaveManifest>,
        ports: &[u16],
        e2e: bool,
    ) -> Result<Deployment> {
        if let Some(cached) = self.get_cached_eif().expect(/* XXX */ "cached EIF error") {
            tracing::info!("Using cached EIF from: {}", cached.eif.path.display());
            return Ok(cached);
        }

        tracing::info!(
            "Starting enclave build from filesystem: {}",
            user_fs_path.display()
        );

        let enclave_source_result = compile::get_or_clone_enclave_source(
            &self.enclave_source,
            &self.enclave_version,
            &self.work_dir,
        )
        .await?;
        let enclave_source_path = enclave_source_result.path.clone();

        // Resolve framework_source commit
        let framework_commit = Self::resolve_framework_commit(&self.framework_source).await;

        let manifest = if let Some(ext_manifest) = external_manifest {
            tracing::info!("Using external manifest for reproducible build");
            ext_manifest
        } else {
            let enclave_src = if self.enclave_source.ends_with(".tar.gz") {
                EnclaveSource::GitArchive {
                    urls: vec![self.enclave_source.clone()],
                    commit: enclave_source_result.commit.clone(),
                }
            } else if self.enclave_source.starts_with("http")
                || self.enclave_source.starts_with("git@")
            {
                EnclaveSource::GitRepository {
                    url: self.enclave_source.clone(),
                    branch: self.enclave_version.clone(),
                    commit: enclave_source_result.commit.clone(),
                }
            } else {
                EnclaveSource::Local {
                    path: self.enclave_source.clone(),
                }
            };

            let app_src = match (app_source_urls, app_commit.clone()) {
                (Some(urls), Some(commit)) if !urls.is_empty() => Some(AppSource {
                    urls,
                    commit,
                    branch: app_branch.clone(),
                }),
                _ => None,
            };

            let framework_src = FrameworkSource::GitArchive {
                url: self.framework_source.clone(),
                commit: framework_commit.clone(),
            };

            tracing::info!(
                "Manifest source commits - enclave: {:?}, framework: {:?}, app: {:?}",
                enclave_source_result.commit,
                framework_commit,
                app_commit
            );

            EnclaveManifest::new(
                app_src,
                enclave_src,
                framework_src,
                None,
                run_command.clone(),
                metadata,
            )
        };

        tracing::info!("Building EIF...");
        let eif_path = self.work_dir.join("enclave.eif");

        let dummy_path = std::path::PathBuf::from("/dev/null");
        let eif = self
            .build_eif_native(
                &user_fs_path,
                &dummy_path,
                &dummy_path,
                &enclave_source_path,
                eif_path,
                run_command,
                Some(manifest),
                ports,
                e2e,
            )
            .await?;

        tracing::info!("Extracting PCR values...");
        let pcrs = self
            .extract_pcrs(&eif)
            .context("Failed to extract PCR values - ensure eif_build generated .pcrs file")?;

        if let Err(e) = self.save_pcrs_to_cache(&pcrs) {
            tracing::warn!("Failed to save PCRs to cache: {}", e);
        }

        tracing::info!("Enclave build complete!");
        Ok(Deployment {
            eif,
            pcrs,
            image_ref: "filesystem".to_string(),
        })
    }

    pub async fn build_enclave_auto(
        &self,
        user_image: &UserImage,
        binary_path: &str,
        run_command: Option<String>,
        app_source_urls: Option<Vec<String>>,
        app_branch: Option<String>,
        app_commit: Option<String>,
        metadata: Option<String>,
        external_manifest: Option<EnclaveManifest>,
        ports: &[u16],
        e2e: bool,
    ) -> Result<Deployment> {
        let binary_basename = std::path::Path::new(binary_path)
            .file_name()
            .and_then(|n| n.to_str())
            .context("Invalid binary path")?;

        let run_command = run_command.or_else(|| Some(binary_path.to_string()));

        let filesystem_binary = self.work_dir.join("build").join(binary_basename);

        if filesystem_binary.exists() {
            tracing::info!(
                "Found binary on filesystem: {}",
                filesystem_binary.display()
            );
            tracing::info!("Using filesystem build path (skipping Docker extraction)");

            let user_service_dir = self.work_dir.join("user-service");

            if user_service_dir.exists() {
                tokio::fs::remove_dir_all(&user_service_dir).await?;
            }

            tokio::fs::create_dir_all(&user_service_dir).await?;

            let binary_path_obj = std::path::Path::new(binary_path);
            let parent_dir = binary_path_obj
                .parent()
                .unwrap_or(std::path::Path::new("/"));
            let target_dir =
                user_service_dir.join(parent_dir.strip_prefix("/").unwrap_or(parent_dir));
            tokio::fs::create_dir_all(&target_dir).await?;

            let dest_path = target_dir.join(binary_basename);
            tokio::fs::copy(&filesystem_binary, &dest_path).await?;

            tracing::info!("Copied binary to staging: {}", dest_path.display());

            self.build_enclave_from_filesystem(
                user_service_dir,
                run_command,
                app_source_urls,
                app_branch.clone(),
                app_commit.clone(),
                metadata,
                external_manifest,
                ports,
                e2e,
            )
            .await
        } else {
            tracing::info!("Binary not found on filesystem, using Docker extraction");
            self.build_enclave(
                user_image,
                Some(vec![binary_path.to_string()]),
                run_command,
                app_source_urls,
                app_branch,
                app_commit,
                metadata,
                external_manifest,
                ports,
                e2e,
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcr_comparison() {
        let pcrs1 = PcrValues {
            pcr0: "abc123".to_string(),
            pcr1: "def456".to_string(),
            pcr2: "ghi789".to_string(),
            pcr3: None,
            pcr4: None,
        };

        let pcrs2 = pcrs1.clone();
        let pcrs3 = PcrValues {
            pcr0: "different".to_string(),
            ..pcrs1.clone()
        };

        let cache_dir = tempfile::tempdir().unwrap();

        let builder = EnclaveBuilder::new(
            "test",
            "v1",
            "./enclave",
            "local",
            "http://test",
            &cache_dir,
            false,
        )
        .unwrap();
        assert!(builder.compare_pcrs(&pcrs1, &pcrs2));
        assert!(!builder.compare_pcrs(&pcrs1, &pcrs3));
    }
}
