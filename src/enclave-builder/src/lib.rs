// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

pub const ENCLAVE_SOURCE: &str = "https://git.distrust.co/public/enclaveos/archive/master.tar.gz";
pub const FRAMEWORK_SOURCE: &str = "https://codeberg.org/caution/platform/archive/main.tar.gz";

pub mod extract;
pub mod merge;
pub mod build;
pub mod pcrs;
pub mod compile;
pub mod manifest;
pub mod docker;

use anyhow::{Context, Result};
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

pub use manifest::{EnclaveManifest, AppSource, EnclaveSource, FrameworkSource};
pub use docker::{BuildConfig, build_user_image};

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
}

#[derive(Debug, Clone)]
pub struct UserImage {
    pub reference: String,
}

#[derive(Debug, Clone)]
pub struct EifFile {
    pub path: PathBuf,
    pub size: u64,
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
    fn dir_name(&self) -> &'static str {
        match self {
            CacheType::Build => "build",
            CacheType::Reproduction => "reproductions",
        }
    }
}

impl EnclaveBuilder {
    pub fn new_with_cache(
        template_source: impl Into<String>,
        template_version: impl Into<String>,
        enclave_source: impl Into<String>,
        enclave_version: impl Into<String>,
        framework_source: impl Into<String>,
        org_id: &str,
        cache_key: &str,
        cache_type: CacheType,
        no_cache: bool,
    ) -> Result<Self> {
        let base_cache_dir = dirs::home_dir()
            .context("Failed to determine home directory")?
            .join(".cache/caution")
            .join(cache_type.dir_name());

        let safe_org_id = org_id
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect::<String>();

        let safe_cache_key = cache_key
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect::<String>();

        let work_dir = base_cache_dir.join(&safe_org_id).join(&safe_cache_key);

        if no_cache && work_dir.exists() {
            tracing::info!("no_cache=true, removing cached {:?} at: {}", cache_type, work_dir.display());
            std::fs::remove_dir_all(&work_dir)
                .context("Failed to remove cached build directory")?;
        }

        std::fs::create_dir_all(&work_dir)
            .context("Failed to create work directory")?;

        tracing::info!("{:?} cache directory: {}", cache_type, work_dir.display());

        Ok(Self {
            template_source: template_source.into(),
            template_version: template_version.into(),
            enclave_source: enclave_source.into(),
            enclave_version: enclave_version.into(),
            framework_source: framework_source.into(),
            work_dir,
        })
    }

    #[allow(deprecated)]
    pub fn new(
        template_source: impl Into<String>,
        template_version: impl Into<String>,
        enclave_source: impl Into<String>,
        enclave_version: impl Into<String>,
        framework_source: impl Into<String>,
    ) -> Result<Self> {
        let cache_dir = dirs::home_dir()
            .context("Failed to determine home directory")?
            .join(".cache/caution/build");
        std::fs::create_dir_all(&cache_dir)
            .context("Failed to create cache directory")?;

        let work_dir = tempfile::tempdir_in(&cache_dir)?.into_path();

        Ok(Self {
            template_source: template_source.into(),
            template_version: template_version.into(),
            enclave_source: enclave_source.into(),
            enclave_version: enclave_version.into(),
            framework_source: framework_source.into(),
            work_dir,
        })
    }

    pub fn with_work_dir(mut self, work_dir: PathBuf) -> Self {
        self.work_dir = work_dir;
        self
    }

    pub fn get_cached_eif(&self) -> Option<Deployment> {
        let eif_path = self.work_dir.join("enclave.eif");
        let pcrs_path = self.work_dir.join("enclave.eif.pcrs");

        if !eif_path.exists() || !pcrs_path.exists() {
            tracing::info!("No cached EIF found at: {}", eif_path.display());
            return None;
        }

        let pcrs_content = match std::fs::read_to_string(&pcrs_path) {
            Ok(content) => content,
            Err(e) => {
                tracing::warn!("Failed to read cached PCRs: {}", e);
                return None;
            }
        };

        let pcrs: PcrValues = match serde_json::from_str(&pcrs_content) {
            Ok(pcrs) => pcrs,
            Err(e) => {
                tracing::warn!("Failed to parse cached PCRs: {}", e);
                return None;
            }
        };

        let metadata = match std::fs::metadata(&eif_path) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("Failed to get EIF metadata: {}", e);
                return None;
            }
        };

        let sha256_path = self.work_dir.join("enclave.eif.sha256");
        let sha256 = std::fs::read_to_string(&sha256_path)
            .unwrap_or_else(|_| "unknown".to_string())
            .trim()
            .to_string();

        tracing::info!("Found cached EIF: {} ({} bytes)", eif_path.display(), metadata.len());

        Some(Deployment {
            eif: EifFile {
                path: eif_path,
                size: metadata.len(),
                sha256,
            },
            pcrs,
            image_ref: "cached".to_string(),
        })
    }

    fn save_pcrs_to_cache(&self, pcrs: &PcrValues) -> Result<()> {
        let pcrs_path = self.work_dir.join("enclave.eif.pcrs");
        let pcrs_json = serde_json::to_string_pretty(pcrs)
            .context("Failed to serialize PCRs")?;
        std::fs::write(&pcrs_path, pcrs_json)
            .context("Failed to write PCRs cache file")?;
        tracing::info!("Saved PCRs to cache: {}", pcrs_path.display());
        Ok(())
    }

    pub async fn extract_user_image(&self, image: &UserImage, specific_files: Option<Vec<String>>) -> Result<PathBuf> {
        if let Some(files) = specific_files {
            tracing::info!("Extracting specific files: {:?}", files);
            extract::extract_specific_files(&image.reference, &files, &self.work_dir).await
        } else {
            tracing::info!("Extracting full filesystem");
            extract::extract_image_filesystem(&image.reference, &self.work_dir).await
        }
    }

    pub async fn extract_static_binary(&self, image: &UserImage, binary_path: &str) -> Result<PathBuf> {
        tracing::info!("Extracting static binary: {}", binary_path);
        extract::extract_static_binary(&image.reference, binary_path, &self.work_dir).await
    }

    pub async fn build_combined_image(
        &self,
        user_fs_path: PathBuf,
        output_image_tag: &str,
    ) -> Result<String> {
        merge::build_combined_image(
            &self.template_source,
            &self.template_version,
            user_fs_path,
            output_image_tag,
            &self.work_dir,
        )
        .await
    }

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
    ) -> Result<EifFile> {
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
        )
        .await
    }

    pub fn extract_pcrs(&self, eif: &EifFile) -> Result<PcrValues> {
        pcrs::extract_pcrs_from_eif(eif)
    }

    pub fn parse_attestation_pcrs(&self, attestation_b64: &str) -> Result<PcrValues> {
        pcrs::parse_attestation_document(attestation_b64)
    }

    pub fn compare_pcrs(&self, local: &PcrValues, remote: &PcrValues) -> bool {
        local.pcr0 == remote.pcr0
            && local.pcr1 == remote.pcr1
            && local.pcr2 == remote.pcr2
    }

    pub fn is_debug_mode(&self, pcrs: &PcrValues) -> bool {
        pcrs::is_debug_mode(pcrs)
    }

    pub async fn build_enclave(&self, user_image: &UserImage, specific_files: Option<Vec<String>>, run_command: Option<String>, app_source_urls: Option<Vec<String>>, app_branch: Option<String>, app_commit: Option<String>, metadata: Option<String>, external_manifest: Option<EnclaveManifest>, ports: &[u16]) -> Result<Deployment> {
        if let Some(cached) = self.get_cached_eif() {
            tracing::info!("Using cached EIF from: {}", cached.eif.path.display());
            return Ok(cached);
        }

        tracing::info!("Starting enclave build for user image: {}", user_image.reference);

        let binary_path = specific_files.as_ref().and_then(|files| files.first().cloned());
        let run_command = run_command.or_else(|| binary_path.clone());

        tracing::info!("Extracting user image filesystem...");
        let user_fs = if let Some(ref bin_path) = binary_path {
            tracing::info!("Binary path specified: {} - extracting static binary only", bin_path);
            self.extract_static_binary(user_image, bin_path).await?
        } else {
            tracing::info!("No binary path specified - extracting full filesystem");
            self.extract_user_image(user_image, None).await?
        };

        let enclave_source_path = compile::get_or_clone_enclave_source(
            &self.enclave_source,
            &self.enclave_version,
            &self.work_dir,
        ).await?;

        let manifest = if let Some(ext_manifest) = external_manifest {
            tracing::info!("Using external manifest for reproducible build");
            ext_manifest
        } else {
            let enclave_src = if self.enclave_source.ends_with(".tar.gz") {
                EnclaveSource::GitArchive {
                    urls: vec![self.enclave_source.clone()],
                    commit: None,
                }
            } else if self.enclave_source.starts_with("http") || self.enclave_source.starts_with("git@") {
                EnclaveSource::GitRepository {
                    url: self.enclave_source.clone(),
                    branch: self.enclave_version.clone(),
                    commit: None,
                }
            } else {
                EnclaveSource::Local {
                    path: self.enclave_source.clone(),
                }
            };

            let app_src = match (app_source_urls, app_commit.clone()) {
                (Some(urls), Some(commit)) if !urls.is_empty() => {
                    Some(AppSource {
                        urls,
                        commit,
                        branch: app_branch.clone(),
                    })
                }
                _ => None,
            };

            let framework_src = FrameworkSource::GitArchive {
                url: self.framework_source.clone(),
            };

            EnclaveManifest::new(app_src, enclave_src, framework_src, binary_path.clone(), run_command.clone(), metadata)
        };

        tracing::info!("Building EIF...");
        let eif_path = self.work_dir.join("enclave.eif");
        let dummy_path = std::path::PathBuf::from("/dev/null");
        let eif = self.build_eif_native(
            &user_fs,
            &dummy_path,
            &dummy_path,
            &enclave_source_path,
            eif_path,
            run_command,
            Some(manifest),
            ports,
        ).await?;

        tracing::info!("Extracting PCR values...");
        let pcrs = self.extract_pcrs(&eif)
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

    pub async fn build_enclave_from_filesystem(&self, user_fs_path: PathBuf, run_command: Option<String>, app_source_urls: Option<Vec<String>>, app_branch: Option<String>, app_commit: Option<String>, metadata: Option<String>, external_manifest: Option<EnclaveManifest>, ports: &[u16]) -> Result<Deployment> {
        if let Some(cached) = self.get_cached_eif() {
            tracing::info!("Using cached EIF from: {}", cached.eif.path.display());
            return Ok(cached);
        }

        tracing::info!("Starting enclave build from filesystem: {}", user_fs_path.display());

        let enclave_source_path = compile::get_or_clone_enclave_source(
            &self.enclave_source,
            &self.enclave_version,
            &self.work_dir,
        ).await?;

        let manifest = if let Some(ext_manifest) = external_manifest {
            tracing::info!("Using external manifest for reproducible build");
            ext_manifest
        } else {
            let enclave_src = if self.enclave_source.ends_with(".tar.gz") {
                EnclaveSource::GitArchive {
                    urls: vec![self.enclave_source.clone()],
                    commit: None,
                }
            } else if self.enclave_source.starts_with("http") || self.enclave_source.starts_with("git@") {
                EnclaveSource::GitRepository {
                    url: self.enclave_source.clone(),
                    branch: self.enclave_version.clone(),
                    commit: None,
                }
            } else {
                EnclaveSource::Local {
                    path: self.enclave_source.clone(),
                }
            };

            let app_src = match (app_source_urls, app_commit.clone()) {
                (Some(urls), Some(commit)) if !urls.is_empty() => {
                    Some(AppSource {
                        urls,
                        commit,
                        branch: app_branch.clone(),
                    })
                }
                _ => None,
            };

            let framework_src = FrameworkSource::GitArchive {
                url: self.framework_source.clone(),
            };

            EnclaveManifest::new(app_src, enclave_src, framework_src, None, run_command.clone(), metadata)
        };

        tracing::info!("Building EIF...");
        let eif_path = self.work_dir.join("enclave.eif");

        let dummy_path = std::path::PathBuf::from("/dev/null");
        let eif = self.build_eif_native(
            &user_fs_path,
            &dummy_path,
            &dummy_path,
            &enclave_source_path,
            eif_path,
            run_command,
            Some(manifest),
            ports,
        ).await?;

        tracing::info!("Extracting PCR values...");
        let pcrs = self.extract_pcrs(&eif)
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

    pub async fn build_enclave_auto(&self, user_image: &UserImage, binary_path: &str, run_command: Option<String>, app_source_urls: Option<Vec<String>>, app_branch: Option<String>, app_commit: Option<String>, metadata: Option<String>, external_manifest: Option<EnclaveManifest>, ports: &[u16]) -> Result<Deployment> {
        let binary_basename = std::path::Path::new(binary_path)
            .file_name()
            .and_then(|n| n.to_str())
            .context("Invalid binary path")?;

        let run_command = run_command.or_else(|| Some(binary_path.to_string()));

        let filesystem_binary = self.work_dir.join("build").join(binary_basename);

        if filesystem_binary.exists() {
            tracing::info!("Found binary on filesystem: {}", filesystem_binary.display());
            tracing::info!("Using filesystem build path (skipping Docker extraction)");

            let user_service_dir = self.work_dir.join("user-service");

            if user_service_dir.exists() {
                tokio::fs::remove_dir_all(&user_service_dir).await?;
            }

            tokio::fs::create_dir_all(&user_service_dir).await?;

            let binary_path_obj = std::path::Path::new(binary_path);
            let parent_dir = binary_path_obj.parent().unwrap_or(std::path::Path::new("/"));
            let target_dir = user_service_dir.join(parent_dir.strip_prefix("/").unwrap_or(parent_dir));
            tokio::fs::create_dir_all(&target_dir).await?;

            let dest_path = target_dir.join(binary_basename);
            tokio::fs::copy(&filesystem_binary, &dest_path).await?;

            tracing::info!("Copied binary to staging: {}", dest_path.display());

            self.build_enclave_from_filesystem(user_service_dir, run_command, app_source_urls, app_branch.clone(), app_commit.clone(), metadata, external_manifest, ports).await
        } else {
            tracing::info!("Binary not found on filesystem, using Docker extraction");
            self.build_enclave(user_image, Some(vec![binary_path.to_string()]), run_command, app_source_urls, app_branch, app_commit, metadata, external_manifest, ports).await
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

        let builder = EnclaveBuilder::new("test", "v1", "./enclave", "local", "http://test").unwrap();
        assert!(builder.compare_pcrs(&pcrs1, &pcrs2));
        assert!(!builder.compare_pcrs(&pcrs1, &pcrs3));
    }
}
