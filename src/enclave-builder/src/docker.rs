// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use dterror::ResultExt;
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

/// Error type for [`validate_explicit_containerfile_path`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ValidateExplicitContainerfilePathError {
    #[error("Procfile field `containerfile:` cannot be empty [{location}]")]
    Empty { location: dterror::Location },

    #[error("Procfile field `containerfile:` '{containerfile}' must be a relative path within the repository [{location}]")]
    Absolute {
        containerfile: String,
        location: dterror::Location,
    },

    #[error("Procfile field `containerfile:` '{containerfile}' must stay within the repository [{location}]")]
    Traversal {
        containerfile: String,
        location: dterror::Location,
    },
}

/// Error type for [`build_user_image`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error, dterror::CtxError)]
pub enum BuildUserImageError {
    #[error("invalid containerfile configuration: {reason} [{location}]")]
    ValidateContainerfile {
        reason: ValidateExplicitContainerfilePathError,
        location: dterror::Location,
    },

    #[error(
        "Procfile field `containerfile:` points to missing file: {containerfile} [{location}]"
    )]
    MissingFile {
        containerfile: String,
        location: dterror::Location,
    },

    #[error("failed to run build command [{location}]")]
    RunBuild {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("build command failed: {stderr} [{location}]")]
    BuildFailed {
        stderr: String,
        location: dterror::Location,
    },

    #[error("failed to load OCI tarball [{location}]")]
    LoadOciTarball {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to load OCI tarball: {stderr} [{location}]")]
    OciLoadFailed {
        stderr: String,
        location: dterror::Location,
    },

    #[error("failed to parse loaded image from docker load output [{location}]")]
    ParseLoadedImage { location: dterror::Location },

    #[error("failed to tag loaded image [{location}]")]
    TagImage {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to tag image: {stderr} [{location}]")]
    TagFailed {
        stderr: String,
        location: dterror::Location,
    },
}

#[tracing::instrument(skip_all, err)]
pub fn validate_explicit_containerfile_path(
    containerfile: &str,
) -> Result<String, ValidateExplicitContainerfilePathError> {
    let containerfile = containerfile.trim();
    if containerfile.is_empty() {
        return Err(ValidateExplicitContainerfilePathError::Empty {
            location: std::panic::Location::caller(),
        });
    }

    let path = Path::new(containerfile);
    if path.is_absolute() {
        return Err(ValidateExplicitContainerfilePathError::Absolute {
            containerfile: containerfile.to_string(),
            location: std::panic::Location::caller(),
        });
    }

    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(ValidateExplicitContainerfilePathError::Traversal {
            containerfile: containerfile.to_string(),
            location: std::panic::Location::caller(),
        });
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

fn augment_docker_build_command(build_command: &str, image_tag: &str, no_cache: bool) -> String {
    let mut cmd = build_command.to_string();

    if !cmd.starts_with("docker build") {
        return cmd;
    }

    // Enclave/user image builds target Linux/x86_64. Without an explicit
    // platform, Docker on Apple Silicon can select arm64 and fail to resolve
    // the pinned StageX base images needed for reproducible builds.
    if !cmd.contains("--platform") {
        cmd = cmd.replacen("docker build", "docker build --platform linux/amd64", 1);
    }

    if no_cache && !cmd.contains("--no-cache") {
        cmd = cmd.replacen("docker build", "docker build --no-cache --pull", 1);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        cmd = format!("{} --build-arg CACHEBUST={}", cmd, timestamp);
    }

    if cmd.ends_with(" .") {
        cmd.replace(" .", &format!(" -t {} .", image_tag))
    } else {
        format!("{} -t {}", cmd, image_tag)
    }
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
#[tracing::instrument(skip_all, err)]
pub async fn build_user_image(
    work_dir: &Path,
    image_tag: &str,
    config: &BuildConfig,
) -> Result<String, BuildUserImageError> {
    use BuildUserImageErrorCtx as Ctx;

    tracing::info!("Building Docker image with tag: {}", image_tag);

    let containerfile =
        if !has_explicit_build_command(config.build_command.as_deref()) {
            match config.containerfile.as_deref() {
                Some(containerfile) => {
                    let containerfile = validate_explicit_containerfile_path(containerfile)
                        .map_err(|e| BuildUserImageError::ValidateContainerfile {
                            reason: e,
                            location: std::panic::Location::caller(),
                        })?;
                    if !work_dir.join(&containerfile).is_file() {
                        return Err(BuildUserImageError::MissingFile {
                            containerfile,
                            location: std::panic::Location::caller(),
                        });
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

    let build_command_with_tag =
        augment_docker_build_command(&build_command, image_tag, config.no_cache);

    tracing::info!("Executing build command: {}", build_command_with_tag);

    // Run build command
    let output = Command::new("sh")
        .arg("-c")
        .arg(&build_command_with_tag)
        .current_dir(work_dir)
        .output()
        .await
        .with_context(Ctx::run_build())?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        tracing::error!("Build failed:\nstdout: {}\nstderr: {}", stdout, stderr);
        return Err(BuildUserImageError::BuildFailed {
            stderr: stderr.to_string(),
            location: std::panic::Location::caller(),
        });
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
            .with_context(Ctx::load_oci_tarball())?;

        if !load_output.status.success() {
            let stderr = String::from_utf8_lossy(&load_output.stderr);
            tracing::error!("Failed to load OCI tarball: {}", stderr);
            return Err(BuildUserImageError::OciLoadFailed {
                stderr: stderr.to_string(),
                location: std::panic::Location::caller(),
            });
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
            .ok_or_else(|| BuildUserImageError::ParseLoadedImage {
                location: std::panic::Location::caller(),
            })?;

        tracing::info!("Loaded image: {}, tagging as: {}", loaded_image, image_tag);

        // Tag the loaded image
        let tag_output = Command::new("docker")
            .args(["tag", loaded_image, image_tag])
            .output()
            .await
            .with_context(Ctx::tag_image())?;

        if !tag_output.status.success() {
            let stderr = String::from_utf8_lossy(&tag_output.stderr);
            return Err(BuildUserImageError::TagFailed {
                stderr: stderr.to_string(),
                location: std::panic::Location::caller(),
            });
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

    #[test]
    fn test_augment_docker_build_command_adds_linux_amd64_platform() {
        let cmd = augment_docker_build_command("docker build -f Dockerfile .", "test-image", false);
        assert_eq!(
            cmd,
            "docker build --platform linux/amd64 -f Dockerfile -t test-image ."
        );
    }

    #[test]
    fn test_augment_docker_build_command_preserves_explicit_platform() {
        let cmd = augment_docker_build_command(
            "docker build --platform linux/arm64 -f Dockerfile .",
            "test-image",
            false,
        );
        assert_eq!(
            cmd,
            "docker build --platform linux/arm64 -f Dockerfile -t test-image ."
        );
    }
}
