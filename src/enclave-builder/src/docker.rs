// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result, bail};
use std::path::Path;
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
}

/// Build a Docker image from a Procfile configuration.
///
/// This function handles the full build workflow:
/// 1. Determines the build command (from `build:` field or generates one from `containerfile:`)
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

    // Determine build command
    let build_command = match &config.build_command {
        Some(cmd) if !cmd.trim().is_empty() => {
            tracing::info!("Using build command from Procfile: {}", cmd);
            cmd.clone()
        }
        _ => {
            // Fall back to containerfile or Dockerfile
            let containerfile = config.containerfile.clone().unwrap_or_else(|| {
                if work_dir.join("Containerfile").exists() {
                    "Containerfile".to_string()
                } else {
                    "Dockerfile".to_string()
                }
            });
            tracing::info!("No build command, using containerfile: {}", containerfile);
            format!("docker build -f {} .", containerfile)
        }
    };

    // Add -t <tag> and --no-cache if it's a docker build command
    let build_command_with_tag = if build_command.starts_with("docker build") {
        let with_no_cache = if build_command.contains("--no-cache") {
            build_command.clone()
        } else {
            build_command.replacen("docker build", "docker build --no-cache", 1)
        };
        if with_no_cache.ends_with(" .") {
            with_no_cache.replace(" .", &format!(" -t {} .", image_tag))
        } else {
            format!("{} -t {}", with_no_cache, image_tag)
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

        let loaded_image = load_stdout.lines()
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

    #[test]
    fn test_build_config_default() {
        let config = BuildConfig::default();
        assert!(config.build_command.is_none());
        assert!(config.containerfile.is_none());
        assert!(config.oci_tarball.is_none());
    }
}
