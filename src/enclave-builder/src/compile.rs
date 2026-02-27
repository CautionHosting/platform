// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tokio::process::Command;
use tokio::fs;
use flate2::read::GzDecoder;
use tar::Archive;

pub struct EnclaveBinaries {
    pub bootproofd: PathBuf,
    pub init: PathBuf,
}

pub async fn compile_enclave_binaries(
    enclave_source_path: &Path,
    work_dir: &Path,
) -> Result<EnclaveBinaries> {
    tracing::info!("Compiling enclave binaries from source: {}", enclave_source_path.display());

    let build_dir = work_dir.join("enclave-build");
    fs::create_dir_all(&build_dir).await?;

    let dockerfile_content = r#"
FROM stagex/pallet-rust@sha256:9c38bf1066dd9ad1b6a6b584974dd798c2bf798985bf82e58024fbe0515592ca AS pallet-rust

FROM pallet-rust AS enclave-builder

ENV SOURCE_DATE_EPOCH=1
ENV CARGO_HOME=/usr/local/cargo
ENV RUSTFLAGS="-C codegen-units=1 -C target-feature=+crt-static -C link-arg=-Wl,--build-id=none"
ENV TARGET_ARCH="x86_64-unknown-linux-musl"

WORKDIR /build-enclave

COPY Cargo.toml Cargo.lock ./
COPY src/init/Cargo.toml ./src/init/
COPY src/aws/Cargo.toml ./src/aws/
COPY src/system/Cargo.toml ./src/system/

RUN mkdir -p src/init/src src/aws/src src/system/src && \
    echo "fn main() {}" > src/init/src/main.rs && \
    echo "pub fn dummy() {}" > src/aws/src/lib.rs && \
    echo "pub fn dummy() {}" > src/system/src/lib.rs

COPY src/init/init.rs ./src/init/init.rs
COPY src/aws/src ./src/aws/src
COPY src/system/src ./src/system/src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo fetch --locked --target $TARGET_ARCH

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build-enclave/target \
    cargo build --release --locked --target ${TARGET_ARCH} -p init \
      && install -D -m 0755 /build-enclave/target/${TARGET_ARCH}/release/init /output/init
"#;

    let dockerfile_path = build_dir.join("Dockerfile");
    fs::write(&dockerfile_path, dockerfile_content).await?;

    let output_dir = work_dir.join("enclave-binaries");
    fs::create_dir_all(&output_dir).await?;

    tracing::info!("Building and extracting enclave binaries with Docker...");
    let output = Command::new("docker")
        .args([
            "build",
            "--progress=plain",
            "--target", "enclave-builder",
            "--output", &format!("type=local,dest={}", output_dir.to_str().unwrap()),
            "-f", dockerfile_path.to_str().unwrap(),
            enclave_source_path.to_str().unwrap(),
        ])
        .output()
        .await
        .context("Failed to execute docker build")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::bail!(
            "Docker build failed:\nstdout: {}\nstderr: {}",
            stdout,
            stderr
        );
    }

    let bootproofd = output_dir.join("output").join("bootproofd");
    let init = output_dir.join("output").join("init");

    if !bootproofd.exists() {
        anyhow::bail!("bootproofd binary not found at: {}", bootproofd.display());
    }

    if !init.exists() {
        anyhow::bail!("Init binary not found at: {}", init.display());
    }

    tracing::info!("Enclave binaries compiled successfully");
    Ok(EnclaveBinaries {
        bootproofd,
        init,
    })
}

/// Result of fetching enclave source, including path and commit info
#[derive(Debug, Clone)]
pub struct EnclaveSourceResult {
    pub path: PathBuf,
    pub commit: Option<String>,
}

/// Convert archive URL to git repo URL for ls-remote
fn archive_url_to_git_url(archive_url: &str) -> Option<String> {
    if let Some(archive_pos) = archive_url.find("/archive/") {
        let base = &archive_url[..archive_pos];
        let git_url = format!("{}.git", base);
        tracing::debug!("archive_url_to_git_url: {} -> {}", archive_url, git_url);
        Some(git_url)
    } else {
        tracing::debug!("archive_url_to_git_url: {} -> None (no /archive/ found)", archive_url);
        None
    }
}

/// Extract ref name from archive URL
fn extract_ref_from_archive_url(url: &str) -> Option<String> {
    if let Some(archive_pos) = url.find("/archive/") {
        let after_archive = &url[archive_pos + 9..];
        let ref_part = if after_archive.starts_with("refs/heads/") {
            &after_archive[11..]
        } else if after_archive.starts_with("refs/tags/") {
            &after_archive[10..]
        } else {
            after_archive
        };
        let clean_ref = ref_part.trim_end_matches(".tar.gz").trim_end_matches(".tar");
        if !clean_ref.is_empty() {
            tracing::debug!("extract_ref_from_archive_url: {} -> {}", url, clean_ref);
            return Some(clean_ref.to_string());
        }
    }
    tracing::debug!("extract_ref_from_archive_url: {} -> None", url);
    None
}

/// Resolve a branch/tag name to a commit SHA using git ls-remote
pub async fn resolve_ref_to_commit(git_url: &str, ref_name: &str) -> Option<String> {
    tracing::info!("resolve_ref_to_commit: git_url={}, ref_name={}", git_url, ref_name);

    // If ref_name already looks like a commit SHA (40 hex chars), use it directly
    if ref_name.len() == 40 && ref_name.chars().all(|c| c.is_ascii_hexdigit()) {
        tracing::debug!("ref_name is already a SHA, returning as-is");
        return Some(ref_name.to_string());
    }

    // Try as branch first (refs/heads/)
    let branch_ref = format!("refs/heads/{}", ref_name);
    tracing::info!("Trying git ls-remote {} {}", git_url, branch_ref);
    match Command::new("git")
        .args(["ls-remote", git_url, &branch_ref])
        .output()
        .await
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::info!("git ls-remote (branch) status={}, stdout='{}', stderr='{}'",
                output.status, stdout.trim(), stderr.trim());

            if output.status.success() {
                if let Some(sha) = stdout.split_whitespace().next() {
                    if !sha.is_empty() {
                        tracing::info!("Resolved {} to commit {} (branch)", ref_name, sha);
                        return Some(sha.to_string());
                    }
                }
            }
        }
        Err(e) => {
            tracing::warn!("git ls-remote failed: {}", e);
        }
    }

    // Try as tag (refs/tags/)
    let tag_ref = format!("refs/tags/{}", ref_name);
    tracing::info!("Trying git ls-remote {} {}", git_url, tag_ref);
    match Command::new("git")
        .args(["ls-remote", git_url, &tag_ref])
        .output()
        .await
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::info!("git ls-remote (tag) status={}, stdout='{}', stderr='{}'",
                output.status, stdout.trim(), stderr.trim());

            if output.status.success() {
                if let Some(sha) = stdout.split_whitespace().next() {
                    if !sha.is_empty() {
                        tracing::info!("Resolved {} to commit {} (tag)", ref_name, sha);
                        return Some(sha.to_string());
                    }
                }
            }
        }
        Err(e) => {
            tracing::warn!("git ls-remote failed: {}", e);
        }
    }

    tracing::warn!("Could not resolve ref '{}' from '{}'", ref_name, git_url);
    None
}

pub async fn get_or_clone_enclave_source(
    enclave_source: &str,
    enclave_version: &str,
    work_dir: &Path,
) -> Result<EnclaveSourceResult> {
    // Check if it's an archive URL (tar.gz)
    if enclave_source.ends_with(".tar.gz") || enclave_source.ends_with(".tar") {
        tracing::info!("Downloading enclave source archive from: {}", enclave_source);

        // Try to resolve the commit SHA before downloading
        let git_url = archive_url_to_git_url(enclave_source);
        let ref_name = extract_ref_from_archive_url(enclave_source);
        tracing::info!("Enclave source URL parsing: git_url={:?}, ref_name={:?}", git_url, ref_name);

        let commit = if let (Some(git_url), Some(ref_name)) = (git_url, ref_name) {
            tracing::info!("Resolving enclave ref '{}' from '{}' to commit SHA", ref_name, git_url);
            match resolve_ref_to_commit(&git_url, &ref_name).await {
                Some(sha) => {
                    tracing::info!("Resolved enclave '{}' to commit {}", ref_name, sha);
                    Some(sha)
                }
                None => {
                    tracing::warn!("Could not resolve enclave ref '{}' from '{}' (may be private or git not available)", ref_name, git_url);
                    None
                }
            }
        } else {
            tracing::warn!("Could not extract git URL or ref from enclave source: {}", enclave_source);
            None
        };

        let download_dir = work_dir.join("enclave-source");

        // Remove existing directory if it exists
        if download_dir.exists() {
            tracing::info!("Removing existing source directory: {}", download_dir.display());
            fs::remove_dir_all(&download_dir).await?;
        }

        fs::create_dir_all(&download_dir).await?;

        // Download archive using reqwest
        tracing::info!("Downloading archive...");
        let response = reqwest::get(enclave_source)
            .await
            .context("Failed to download archive")?;

        if !response.status().is_success() {
            anyhow::bail!("Failed to download archive: HTTP {}", response.status());
        }

        let archive_bytes = response.bytes()
            .await
            .context("Failed to read archive bytes")?;

        tracing::info!("Downloaded {} bytes, extracting...", archive_bytes.len());

        // Extract tar.gz archive
        let decoder = GzDecoder::new(&archive_bytes[..]);
        let mut archive = Archive::new(decoder);

        // Extract with strip_components=1 equivalent (skip first path component)
        for entry in archive.entries().context("Failed to read archive entries")? {
            let mut entry = entry.context("Failed to read archive entry")?;
            let path = entry.path().context("Failed to get entry path")?;

            // Skip the first path component (equivalent to --strip-components=1)
            let components: Vec<_> = path.components().collect();
            if components.len() <= 1 {
                continue;  // Skip the top-level directory itself
            }

            let stripped_path: PathBuf = components[1..].iter().collect();
            let dest_path = download_dir.join(&stripped_path);

            // Create parent directories if needed
            if let Some(parent) = dest_path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
            }

            entry.unpack(&dest_path)
                .with_context(|| format!("Failed to extract: {}", stripped_path.display()))?;
        }

        tracing::info!("Enclave source extracted to: {}", download_dir.display());
        Ok(EnclaveSourceResult {
            path: download_dir,
            commit,
        })
    } else if enclave_source.starts_with("http://") || enclave_source.starts_with("https://") || enclave_source.starts_with("git@") {
        tracing::info!("Cloning enclave source from: {} (version: {})", enclave_source, enclave_version);

        let clone_dir = work_dir.join("enclave-source");

        // Remove existing clone directory if it exists
        if clone_dir.exists() {
            tracing::info!("Removing existing clone directory: {}", clone_dir.display());
            fs::remove_dir_all(&clone_dir).await?;
        }

        fs::create_dir_all(&clone_dir).await?;

        let output = Command::new("git")
            .args([
                "clone",
                "--depth", "1",
                "--branch", enclave_version,
                enclave_source,
                clone_dir.to_str().unwrap(),
            ])
            .output()
            .await
            .context("Failed to clone enclave source")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Git clone failed: {}", stderr);
        }

        // Get the commit SHA from the cloned repo
        let commit = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&clone_dir)
            .output()
            .await
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

        if let Some(ref c) = commit {
            tracing::info!("Cloned enclave source at commit: {}", c);
        }

        Ok(EnclaveSourceResult {
            path: clone_dir,
            commit,
        })
    } else {
        tracing::info!("Using local enclave source: {}", enclave_source);

        // Try to get commit from local git repo
        let commit = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(enclave_source)
            .output()
            .await
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

        if let Some(ref c) = commit {
            tracing::info!("Local enclave source at commit: {}", c);
        }

        Ok(EnclaveSourceResult {
            path: PathBuf::from(enclave_source),
            commit,
        })
    }
}
