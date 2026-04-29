// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{bail, Context, Result};
use std::path::{Component, Path};
use tokio::process::Command;

/// Configuration for building a Docker image from Procfile fields
#[derive(Debug, Clone, Default)]
pub struct BuildConfig {
    /// The `build:` field from Procfile (e.g., "docker build -f Containerfile .")
    pub build_command: Option<String>,
    /// The `containerfile:` field from Procfile (fallback if no build command)
    pub containerfile: Option<String>,
    /// The `oci_tarball:` field for containerd builds that output tarballs
    pub oci_tarball: Option<String>,
    /// Whether to skip Docker build cache (from `nocache:` field in Procfile)
    pub no_cache: bool,
}

pub fn has_explicit_build_command(build_command: Option<&str>) -> bool {
    build_command
        .map(str::trim)
        .is_some_and(|cmd| !cmd.is_empty())
}

pub fn validate_explicit_containerfile_path(containerfile: &str) -> Result<String> {
    let containerfile = containerfile.trim();
    if containerfile.is_empty() {
        bail!("Procfile field `containerfile:` cannot be empty");
    }

    let path = Path::new(containerfile);
    if path.is_absolute() {
        bail!("Procfile field `containerfile:` must be a relative path within the repository");
    }

    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        bail!("Procfile field `containerfile:` must stay within the repository");
    }

    Ok(containerfile.to_string())
}

fn resolve_build_command_with_selected_containerfile(
    build_command: Option<&str>,
    containerfile: Option<&str>,
) -> String {
    if has_explicit_build_command(build_command) {
        let cmd = build_command.expect("checked above").trim();
        tracing::info!("Using build command from Procfile: {}", cmd);
        return cmd.to_string();
    }

    let containerfile = containerfile
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Dockerfile");
    tracing::info!(
        "No explicit build command, resolving via containerfile precedence: {}",
        containerfile
    );

    format!("docker build -f {} .", containerfile)
}

/// Resolve the build command using the shared Procfile precedence:
/// 1. explicit `build:`
/// 2. explicit `containerfile:`
/// 3. `Dockerfile`
pub fn resolve_build_command(build_command: Option<&str>, containerfile: Option<&str>) -> String {
    resolve_build_command_with_selected_containerfile(build_command, containerfile)
}

/// Resolve the build command for a checked-out repository directory using the
/// shared Procfile precedence:
/// 1. explicit `build:`
/// 2. explicit `containerfile:`
/// 3. auto-detected `Containerfile`
/// 4. `Dockerfile`
pub fn resolve_build_command_in_dir(
    build_command: Option<&str>,
    containerfile: Option<&str>,
    work_dir: &Path,
) -> String {
    if has_explicit_build_command(build_command) {
        return resolve_build_command_with_selected_containerfile(build_command, None);
    }

    let containerfile = containerfile
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            work_dir
                .join("Containerfile")
                .is_file()
                .then_some("Containerfile".to_string())
        });

    resolve_build_command_with_selected_containerfile(build_command, containerfile.as_deref())
}

/// Build a Docker image from a Procfile configuration.
///
/// This function handles the full build workflow:
/// 1. Resolves the build command using `build:` -> `containerfile:` -> `Containerfile` -> `Dockerfile`
/// 2. Adds image tag to docker build commands
/// 3. Runs the build
/// 4. Optionally loads OCI tarball for containerd-style builds
///
/// Returns the image tag that was built.
pub async fn build_user_image(
    work_dir: &Path,
    image_tag: &str,
    config: &BuildConfig,
) -> Result<String> {
    tracing::info!("Building Docker image with tag: {}", image_tag);

    let containerfile = if !has_explicit_build_command(config.build_command.as_deref()) {
        match config.containerfile.as_deref() {
            Some(containerfile) => {
                let containerfile = validate_explicit_containerfile_path(containerfile)?;
                if !work_dir.join(&containerfile).is_file() {
                    bail!(
                        "Procfile field `containerfile:` points to missing file: {}",
                        containerfile
                    );
                }
                Some(containerfile)
            }
            None => None,
        }
    } else {
        None
    };

    let build_command = resolve_build_command_in_dir(
        config.build_command.as_deref(),
        containerfile.as_deref(),
        work_dir,
    );

    // Add -t <tag> and optionally --no-cache if it's a docker build command
    let build_command_with_tag = if build_command.starts_with("docker build") {
        let mut cmd = build_command.clone();

        // Add --no-cache --pull and CACHEBUST if no_cache is enabled
        if config.no_cache {
            if !cmd.contains("--no-cache") {
                cmd = cmd.replacen("docker build", "docker build --no-cache --pull", 1);
            }
            // Add cache-busting build arg with timestamp to invalidate BuildKit layer cache
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            cmd = format!("{} --build-arg CACHEBUST={}", cmd, timestamp);
        }

        // Add image tag
        if cmd.ends_with(" .") {
            cmd.replace(" .", &format!(" -t {} .", image_tag))
        } else {
            format!("{} -t {}", cmd, image_tag)
        }
    } else {
        // Non-docker build command, use as-is
        build_command.clone()
    };

    tracing::info!("Executing build command: {}", build_command_with_tag);

    // Run build command
    let output = Command::new("sh")
        .arg("-c")
        .arg(&build_command_with_tag)
        .current_dir(work_dir)
        .output()
        .await
        .context("Failed to run build command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        tracing::error!("Build failed:\nstdout: {}\nstderr: {}", stdout, stderr);
        bail!("Build command failed: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    tracing::info!("Build completed successfully");
    tracing::debug!("Build output: {}", stdout);

    // Handle OCI tarball if specified (for containerd builds)
    if let Some(oci_tarball) = &config.oci_tarball {
        let tarball_path = work_dir.join(oci_tarball);
        tracing::info!("Loading OCI tarball: {}", tarball_path.display());

        let load_output = Command::new("docker")
            .args(["load", "-i", &tarball_path.to_string_lossy()])
            .output()
            .await
            .context("Failed to load OCI tarball")?;

        if !load_output.status.success() {
            let stderr = String::from_utf8_lossy(&load_output.stderr);
            tracing::error!("Failed to load OCI tarball: {}", stderr);
            bail!("Failed to load OCI tarball: {}", stderr);
        }

        let load_stdout = String::from_utf8_lossy(&load_output.stdout);
        tracing::info!("Docker load output: {}", load_stdout);

        let loaded_image = load_stdout
            .lines()
            .find(|l| l.contains("Loaded image"))
            .and_then(|line| {
                if line.contains("Loaded image ID:") {
                    line.split("Loaded image ID:").nth(1).map(|s| s.trim())
                } else if line.contains("Loaded image:") {
                    line.split("Loaded image:").nth(1).map(|s| s.trim())
                } else {
                    None
                }
            })
            .context("Failed to parse loaded image from docker load output")?;

        tracing::info!("Loaded image: {}, tagging as: {}", loaded_image, image_tag);

        // Tag the loaded image
        let tag_output = Command::new("docker")
            .args(["tag", loaded_image, image_tag])
            .output()
            .await
            .context("Failed to tag loaded image")?;

        if !tag_output.status.success() {
            let stderr = String::from_utf8_lossy(&tag_output.stderr);
            bail!("Failed to tag image: {}", stderr);
        }
    }

    tracing::info!("Docker image built successfully: {}", image_tag);
    Ok(image_tag.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_build_config_default() {
        let config = BuildConfig::default();
        assert!(config.build_command.is_none());
        assert!(config.containerfile.is_none());
        assert!(config.oci_tarball.is_none());
    }

    #[test]
    fn test_resolve_build_command_prefers_explicit_build() {
        assert_eq!(
            resolve_build_command(
                Some("docker build -f Custom.Containerfile ."),
                Some("Ignored.Containerfile"),
            ),
            "docker build -f Custom.Containerfile ."
        );
    }

    #[test]
    fn test_resolve_build_command_prefers_explicit_containerfile() {
        assert_eq!(
            resolve_build_command(None, Some("Custom.Containerfile")),
            "docker build -f Custom.Containerfile ."
        );
    }

    #[test]
    fn test_resolve_build_command_falls_back_to_dockerfile() {
        assert_eq!(
            resolve_build_command(None, None),
            "docker build -f Dockerfile ."
        );
    }

    #[test]
    fn test_resolve_build_command_in_dir_auto_detects_containerfile_before_dockerfile() {
        let work_dir = tempdir().unwrap();
        std::fs::write(work_dir.path().join("Containerfile"), "").unwrap();
        std::fs::write(work_dir.path().join("Dockerfile"), "").unwrap();

        assert_eq!(
            resolve_build_command_in_dir(None, None, work_dir.path()),
            "docker build -f Containerfile ."
        );
    }

    #[test]
    fn test_validate_explicit_containerfile_path_rejects_absolute_paths() {
        let err = validate_explicit_containerfile_path("/tmp/Containerfile").unwrap_err();
        assert!(
            err.to_string().contains("relative path"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_validate_explicit_containerfile_path_rejects_parent_dir_traversal() {
        let err = validate_explicit_containerfile_path("../Containerfile").unwrap_err();
        assert!(
            err.to_string().contains("within the repository"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_build_user_image_rejects_missing_explicit_containerfile() {
        let work_dir = tempdir().unwrap();
        let config = BuildConfig {
            containerfile: Some("Missing.Containerfile".to_string()),
            ..BuildConfig::default()
        };

        let err = build_user_image(work_dir.path(), "test-image", &config)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("missing file"),
            "unexpected error: {err}"
        );
    }
}
