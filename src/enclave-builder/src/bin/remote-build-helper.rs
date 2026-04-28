// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use enclave_builder::{EnclaveBuilder, EnclaveManifest, EnclaveSource, FrameworkSource, UserImage};

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "True"))
        .unwrap_or(false)
}

fn env_required(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}

fn ports_from_env() -> Vec<u16> {
    std::env::var("CAUTION_PORTS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .filter_map(|part| {
                    let trimmed = part.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        trimmed.parse::<u16>().ok()
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn enclave_source_from_manifest(manifest: &EnclaveManifest) -> Result<(String, String)> {
    match &manifest.enclave_source {
        EnclaveSource::GitArchive { urls, commit } => {
            let url = urls
                .first()
                .cloned()
                .context("manifest enclave_source.urls is empty")?;
            let pinned_url = commit
                .as_deref()
                .map(|commit| enclave_builder::pin_archive_url_to_commit(&url, commit))
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
            .map(|commit| enclave_builder::pin_archive_url_to_commit(url, commit))
            .unwrap_or_else(|| url.clone()),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let manifest_path = PathBuf::from(env_required("CAUTION_MANIFEST_PATH")?);
    let image_ref = env_required("CAUTION_IMAGE_REF")?;
    let work_dir = PathBuf::from(env_required("CAUTION_WORK_DIR")?);
    let output_eif = PathBuf::from(env_required("CAUTION_OUTPUT_EIF")?);
    let output_pcrs = PathBuf::from(env_required("CAUTION_OUTPUT_PCRS")?);
    let e2e = env_flag("CAUTION_E2E");
    let locksmith = env_flag("CAUTION_LOCKSMITH");
    let no_cache = env_flag("CAUTION_NO_CACHE");
    let ports = ports_from_env();

    tokio::fs::create_dir_all(&work_dir)
        .await
        .with_context(|| format!("Failed to create work dir {}", work_dir.display()))?;
    if let Some(parent) = output_eif.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("Failed to create output dir {}", parent.display()))?;
    }

    let manifest = EnclaveManifest::read_from_file(&manifest_path)
        .await
        .with_context(|| format!("Failed to read manifest {}", manifest_path.display()))?;

    let (enclave_source, enclave_version) = enclave_source_from_manifest(&manifest)?;
    let framework_source = framework_source_from_manifest(&manifest);
    let app_source_urls = manifest
        .app_source
        .as_ref()
        .map(|source| source.urls.clone());
    let app_branch = manifest
        .app_source
        .as_ref()
        .and_then(|source| source.branch.clone());
    let app_commit = manifest
        .app_source
        .as_ref()
        .map(|source| source.commit.clone());
    let binary_path = manifest.binary.clone();
    let run_command = manifest.run_command.clone();
    let metadata = manifest.metadata.clone();

    let builder = EnclaveBuilder::new(enclave_source, enclave_version, framework_source)?
        .with_work_dir(work_dir.clone())
        .with_no_cache(no_cache);

    let user_image = UserImage {
        reference: image_ref,
    };
    let deployment = if let Some(binary_path) = binary_path {
        builder
            .build_enclave_auto(
                &user_image,
                &binary_path,
                run_command,
                app_source_urls,
                app_branch,
                app_commit,
                metadata,
                Some(manifest),
                &ports,
                e2e,
                locksmith,
            )
            .await?
    } else {
        builder
            .build_enclave(
                &user_image,
                None,
                run_command,
                app_source_urls,
                app_branch,
                app_commit,
                metadata,
                Some(manifest),
                &ports,
                e2e,
                locksmith,
            )
            .await?
    };

    let generated_pcrs = deployment.eif.path.with_extension("pcrs");
    if !generated_pcrs.exists() {
        bail!("Expected PCR output at {}", generated_pcrs.display());
    }

    tokio::fs::copy(&deployment.eif.path, &output_eif)
        .await
        .with_context(|| format!("Failed to copy EIF to {}", output_eif.display()))?;
    tokio::fs::copy(&generated_pcrs, &output_pcrs)
        .await
        .with_context(|| format!("Failed to copy PCRs to {}", output_pcrs.display()))?;

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
