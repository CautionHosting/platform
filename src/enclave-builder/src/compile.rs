// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tokio::process::Command;
use tokio::fs;
use flate2::read::GzDecoder;
use tar::Archive;

pub struct EnclaveBinaries {
    pub attestation_service: PathBuf,
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
COPY src/attestation-service/Cargo.toml ./src/attestation-service/
COPY src/init/Cargo.toml ./src/init/
COPY src/aws/Cargo.toml ./src/aws/
COPY src/system/Cargo.toml ./src/system/

RUN mkdir -p src/init/src src/aws/src src/system/src src/attestation-service/src && \
    echo "fn main() {}" > src/init/src/main.rs && \
    echo "pub fn dummy() {}" > src/aws/src/lib.rs && \
    echo "pub fn dummy() {}" > src/system/src/lib.rs && \
    echo "fn main() {}" > src/attestation-service/src/main.rs

COPY src/attestation-service/src ./src/attestation-service/src
COPY src/init/init.rs ./src/init/init.rs
COPY src/aws/src ./src/aws/src
COPY src/system/src ./src/system/src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo fetch --locked --target $TARGET_ARCH

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build-enclave/target \
    cargo build --release --locked --target ${TARGET_ARCH} -p attestation-service \
      && install -D -m 0755 /build-enclave/target/${TARGET_ARCH}/release/attestation-service /output/attestation-service

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

    let attestation_service = output_dir.join("output").join("attestation-service");
    let init = output_dir.join("output").join("init");

    if !attestation_service.exists() {
        anyhow::bail!("Attestation service binary not found at: {}", attestation_service.display());
    }

    if !init.exists() {
        anyhow::bail!("Init binary not found at: {}", init.display());
    }

    tracing::info!("Enclave binaries compiled successfully");
    Ok(EnclaveBinaries {
        attestation_service,
        init,
    })
}

pub async fn get_or_clone_enclave_source(
    enclave_source: &str,
    enclave_version: &str,
    work_dir: &Path,
) -> Result<PathBuf> {
    // Check if it's an archive URL (tar.gz)
    if enclave_source.ends_with(".tar.gz") || enclave_source.ends_with(".tar") {
        tracing::info!("Downloading enclave source archive from: {}", enclave_source);

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
        Ok(download_dir)
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

        Ok(clone_dir)
    } else {
        tracing::info!("Using local enclave source: {}", enclave_source);
        Ok(PathBuf::from(enclave_source))
    }
}
