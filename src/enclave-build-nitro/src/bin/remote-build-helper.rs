// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

// The `CtxError` derive generates a `{Error}Ctx` mirror type per error enum;
// the generated struct initializations trip `redundant_field_names`, and the
// lint cannot be placed on the generated items themselves.
#![allow(
    clippy::redundant_field_names,
    reason = "generated {Error}Ctx mirrors trip redundant_field_names"
)]

use std::path::{Path, PathBuf};

use caution_config::ConfigurationFile;
use dterror::{BoxError, CtxError, Location, ResultExt as _};
use enclave_build::{
    BuildInput, BuildWorkspace, EnclaveManifest, EnclaveSource, FrameworkSource,
    ImageBuildMechanism, UserImage,
};
use enclave_build_nitro::NitroEifMechanism;

#[derive(Debug, thiserror::Error, CtxError)]
enum RemoteBuildError {
    #[error("environment variable '{name}' is required [{location}]")]
    EnvVar {
        #[context(borrow = str)]
        name: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("failed to read configuration file {} [{location}]", path.display())]
    ReadConfig {
        #[context(borrow = Path)]
        path: PathBuf,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("failed to parse configuration file {} [{location}]", path.display())]
    ParseConfig {
        #[context(borrow = Path)]
        path: PathBuf,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("no caution.hcl or Procfile found in repository {} [{location}]", path.display())]
    NoConfigFile {
        #[context(borrow = Path)]
        path: PathBuf,
        #[location]
        location: Location,
    },
    #[error("manifest enclave_source.urls is empty [{location}]")]
    EmptyEnclaveUrls { location: Location },
    #[error("failed to create work dir {} [{location}]", path.display())]
    CreateWorkDir {
        #[context(borrow = Path)]
        path: PathBuf,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("failed to create output dir {} [{location}]", path.display())]
    CreateOutputDir {
        #[context(borrow = Path)]
        path: PathBuf,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("failed to read manifest {} [{location}]", path.display())]
    ReadManifest {
        #[context(borrow = Path)]
        path: PathBuf,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("failed to initialize enclave builder [{location}]")]
    NewBuilder {
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
    #[error("expected PCR output at {} [{location}]", path.display())]
    MissingPcrs {
        #[context(borrow = Path)]
        path: PathBuf,
        location: Location,
    },
    #[error("could not export paired TAP tunnel helper [{location}]")]
    ExportTapFramer {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("failed to copy EIF to {} [{location}]", path.display())]
    CopyEif {
        #[context(borrow = Path)]
        path: PathBuf,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("failed to copy PCRs to {} [{location}]", path.display())]
    CopyPcrs {
        #[context(borrow = Path)]
        path: PathBuf,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "True"))
        .unwrap_or(false)
}

fn env_required(name: &str) -> Result<String, RemoteBuildError> {
    use RemoteBuildErrorCtx as Ctx;
    std::env::var(name).with_context(Ctx::env_var(name))
}

/// Read the enclave configuration from the checked-out repository. The API
/// builds the manifest from the same commit, so the configuration is present in
/// the source archive the builder already extracted.
#[tracing::instrument(skip_all, err)]
async fn read_configuration(repo_dir: &Path) -> Result<ConfigurationFile, RemoteBuildError> {
    use RemoteBuildErrorCtx as Ctx;

    let hcl_path = repo_dir.join("caution.hcl");
    if hcl_path.is_file() {
        let content = tokio::fs::read_to_string(&hcl_path)
            .await
            .with_context(Ctx::read_config(&hcl_path))?;
        return ConfigurationFile::from_str(&content).with_context(Ctx::parse_config(&hcl_path));
    }

    let procfile_path = repo_dir.join("Procfile");
    if procfile_path.is_file() {
        let content = tokio::fs::read_to_string(&procfile_path)
            .await
            .with_context(Ctx::read_config(&procfile_path))?;
        return ConfigurationFile::from_procfile(&content)
            .with_context(Ctx::parse_config(&procfile_path));
    }

    Err(RemoteBuildError::NoConfigFile {
        path: repo_dir.to_path_buf(),
        location: std::panic::Location::caller(),
    })
}

fn enclave_source_from_manifest(
    manifest: &EnclaveManifest,
) -> Result<(String, String), RemoteBuildError> {
    match &manifest.enclave_source {
        EnclaveSource::GitArchive { urls, commit } => {
            let url = urls
                .first()
                .cloned()
                .ok_or_else(|| RemoteBuildError::EmptyEnclaveUrls {
                    location: std::panic::Location::caller(),
                })?;
            let pinned_url = commit
                .as_deref()
                .map(|commit| enclave_build_nitro::pin_archive_url_to_commit(&url, commit))
                .unwrap_or(url);
            let version = commit.clone().unwrap_or_else(|| "main".to_string());
            Ok((pinned_url, version))
        }
        EnclaveSource::GitRepository {
            url,
            branch,
            commit,
        } => Ok((
            url.clone(),
            commit.clone().unwrap_or_else(|| branch.clone()),
        )),
        EnclaveSource::Local { path } => Ok((path.clone(), "local".to_string())),
    }
}

fn framework_source_from_manifest(manifest: &EnclaveManifest) -> String {
    match &manifest.framework_source {
        FrameworkSource::GitArchive { url, commit } => commit
            .as_deref()
            .map(|commit| enclave_build_nitro::pin_archive_url_to_commit(url, commit))
            .unwrap_or_else(|| url.clone()),
    }
}

#[tokio::main]
async fn main() -> Result<(), RemoteBuildError> {
    use RemoteBuildErrorCtx as Ctx;

    let manifest_path = PathBuf::from(env_required("CAUTION_MANIFEST_PATH")?);
    let image_ref = env_required("CAUTION_IMAGE_REF")?;
    let work_dir = PathBuf::from(env_required("CAUTION_WORK_DIR")?);
    let output_eif = PathBuf::from(env_required("CAUTION_OUTPUT_EIF")?);
    let output_pcrs = PathBuf::from(env_required("CAUTION_OUTPUT_PCRS")?);
    let no_cache = env_flag("CAUTION_NO_CACHE");
    let repo_dir = std::env::var("CAUTION_REPO_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/build/repo"));

    tokio::fs::create_dir_all(&work_dir)
        .await
        .with_context(Ctx::create_work_dir(&work_dir))?;
    if let Some(parent) = output_eif.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(Ctx::create_output_dir(parent))?;
    }

    let manifest = EnclaveManifest::read_from_file(&manifest_path)
        .await
        .with_context(Ctx::read_manifest(&manifest_path))?;

    let config = read_configuration(&repo_dir).await?;

    let (enclave_source, enclave_version) = enclave_source_from_manifest(&manifest)?;
    let framework_source = framework_source_from_manifest(&manifest);
    let prebuilt_components = std::env::var("CAUTION_COMPONENTS_PATH")
        .ok()
        .filter(|path| !path.is_empty())
        .map(PathBuf::from);

    let input = BuildInput {
        docker_image: UserImage {
            reference: image_ref,
        },
        enclave_source,
        enclave_version,
        framework_source,
        workspace: BuildWorkspace::Directory(work_dir.clone()),
        manifest: Some(manifest),
        app_source: None,
        metadata: None,
        prebuilt_components,
        no_cache,
    };

    let artifacts = NitroEifMechanism::new()
        .build(input, &config)
        .await
        .with_context(Ctx::build())?;

    let generated_pcrs = artifacts.image.path.with_extension("pcrs");
    if !generated_pcrs.exists() {
        return Err(RemoteBuildError::MissingPcrs {
            path: generated_pcrs,
            location: std::panic::Location::caller(),
        });
    }

    tokio::fs::copy(&artifacts.image.path, &output_eif)
        .await
        .with_context(Ctx::copy_eif(&output_eif))?;
    tokio::fs::copy(&generated_pcrs, &output_pcrs)
        .await
        .with_context(Ctx::copy_pcrs(&output_pcrs))?;

    if let Some(tap_framer) = &artifacts.tap_framer {
        if tap_framer.exists() {
            let sidecar = output_eif.with_extension("tap-framer");
            tokio::fs::copy(tap_framer, &sidecar)
                .await
                .with_context(Ctx::export_tap_framer())?;
        }
    }

    println!("EIF written to {}", output_eif.display());
    println!("PCRs written to {}", output_pcrs.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enclave_archive_source_is_pinned_to_manifest_commit() {
        let manifest = EnclaveManifest::new(
            None,
            EnclaveSource::GitArchive {
                urls: vec!["https://example.com/repo/archive/main.tar.gz".to_string()],
                commit: Some("abc123".to_string()),
            },
            FrameworkSource::GitArchive {
                url: "https://example.com/framework/archive/main.tar.gz".to_string(),
                commit: None,
            },
            None,
            None,
            None,
        );

        let (url, version) = enclave_source_from_manifest(&manifest).unwrap();

        assert_eq!(url, "https://example.com/repo/archive/abc123.tar.gz");
        assert_eq!(version, "abc123");
    }

    #[test]
    fn test_framework_archive_source_is_pinned_to_manifest_commit() {
        let manifest = EnclaveManifest::new(
            None,
            EnclaveSource::Local {
                path: ".".to_string(),
            },
            FrameworkSource::GitArchive {
                url: "https://example.com/framework/archive/main.tar.gz".to_string(),
                commit: Some("def456".to_string()),
            },
            None,
            None,
            None,
        );

        assert_eq!(
            framework_source_from_manifest(&manifest),
            "https://example.com/framework/archive/def456.tar.gz"
        );
    }
}
