// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result};
use bollard::Docker;
use bollard::container::{CreateContainerOptions, Config, DownloadFromContainerOptions};
use futures_util::stream::StreamExt;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::AsyncWriteExt;

pub async fn extract_image_filesystem(image_ref: &str, work_dir: &Path) -> Result<PathBuf> {
    tracing::info!("Extracting filesystem from image: {}", image_ref);

    let docker = Docker::connect_with_local_defaults()
        .context("Failed to connect to Docker daemon")?;

    verify_image_exists_locally(&docker, image_ref).await?;

    let container_id = create_container(&docker, image_ref).await?;

    let export_dir = work_dir.join("user-service");
    fs::create_dir_all(&export_dir).await?;

    export_container_filesystem(&docker, &container_id, &export_dir).await?;

    docker
        .remove_container(&container_id, None)
        .await
        .context("Failed to remove temporary container")?;

    tracing::info!("Extracted user filesystem to: {}", export_dir.display());
    Ok(export_dir)
}

async fn verify_image_exists_locally(docker: &Docker, image_ref: &str) -> Result<()> {
    tracing::info!("Checking if image exists locally: {}", image_ref);

    match docker.inspect_image(image_ref).await {
        Ok(_) => {
            tracing::info!("✓ Image exists locally: {}", image_ref);
            Ok(())
        }
        Err(e) => {
            tracing::error!("✗ Image not found locally: {}", image_ref);
            Err(anyhow::anyhow!(
                "Image '{}' not found locally. This image should have been built earlier in the deployment process. Error: {}",
                image_ref,
                e
            ))
        }
    }
}

async fn create_container(docker: &Docker, image_ref: &str) -> Result<String> {
    tracing::info!("Creating temporary container from image");

    let config = Config {
        image: Some(image_ref.to_string()),
        cmd: Some(vec!["/bin/true".to_string()]),
        ..Default::default()
    };

    let options = CreateContainerOptions {
        name: format!("extract-{}", uuid::Uuid::new_v4()),
        platform: None,
    };

    let response = docker
        .create_container(Some(options), config)
        .await
        .context("Failed to create container")?;

    tracing::info!("Created container: {}", response.id);
    Ok(response.id)
}

async fn export_container_filesystem(
    docker: &Docker,
    container_id: &str,
    output_dir: &Path,
) -> Result<()> {
    tracing::info!("Exporting container filesystem");

    let mut stream = docker.export_container(container_id);

    let tar_path = output_dir.parent().unwrap().join("container-export.tar");
    let mut tar_file = fs::File::create(&tar_path)
        .await
        .context("Failed to create tar file")?;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("Failed to read export stream")?;
        tar_file
            .write_all(&chunk)
            .await
            .context("Failed to write tar data")?;
    }

    tar_file.flush().await?;
    drop(tar_file);

    tracing::info!("Extracting tar archive to: {}", output_dir.display());

    let tar_file = std::fs::File::open(&tar_path).context("Failed to open tar file")?;
    let mut archive = tar::Archive::new(tar_file);

    archive
        .unpack(output_dir)
        .context("Failed to extract tar archive")?;

    fs::remove_file(&tar_path).await.ok();

    tracing::info!("Filesystem extracted successfully");
    Ok(())
}

pub async fn extract_specific_files(
    image_ref: &str,
    files: &[String],
    work_dir: &Path,
) -> Result<PathBuf> {
    tracing::info!("Extracting {} specific files from image: {}", files.len(), image_ref);

    let docker = Docker::connect_with_local_defaults()
        .context("Failed to connect to Docker daemon")?;

    verify_image_exists_locally(&docker, image_ref).await?;

    let container_id = create_container(&docker, image_ref).await?;

    let output_dir = work_dir.join("user-service");
    fs::create_dir_all(&output_dir).await?;

    for file_path in files {
        tracing::info!("Attempting to extract file: {}", file_path);

        let options = DownloadFromContainerOptions {
            path: file_path.clone(),
        };

        tracing::info!("Creating download stream for path: {}", file_path);
        let mut stream = docker.download_from_container(&container_id, Some(options));

        let tar_path = output_dir.parent().unwrap().join("file-extract.tar");
        let mut tar_file = fs::File::create(&tar_path)
            .await
            .context("Failed to create tar file")?;

        while let Some(chunk_result) = stream.next().await {
            match chunk_result {
                Ok(bytes) => {
                    tar_file
                        .write_all(&bytes)
                        .await
                        .context("Failed to write tar data")?;
                }
                Err(e) => {
                    docker.remove_container(&container_id, None).await.ok();
                    return Err(anyhow::anyhow!(
                        "Failed to download file '{}' from container: {}",
                        file_path,
                        e
                    ));
                }
            }
        }

        tar_file.flush().await?;
        drop(tar_file);

        let tar_file = std::fs::File::open(&tar_path).context("Failed to open tar file")?;
        let mut archive = tar::Archive::new(tar_file);

        archive.set_preserve_permissions(true);
        archive.set_preserve_mtime(true);
        archive.set_unpack_xattrs(true);

        archive
            .unpack(&output_dir)
            .context("Failed to extract tar archive")?;

        fs::remove_file(&tar_path).await.ok();

        tracing::info!("Successfully extracted: {}", file_path);
    }

    docker
        .remove_container(&container_id, None)
        .await
        .context("Failed to remove temporary container")?;

    tracing::info!("All files extracted to: {}", output_dir.display());
    Ok(output_dir)
}

pub async fn extract_last_layer_only(image_ref: &str, work_dir: &Path) -> Result<PathBuf> {
    tracing::info!("Extracting last layer from image: {}", image_ref);

    let docker = Docker::connect_with_local_defaults()
        .context("Failed to connect to Docker daemon")?;

    verify_image_exists_locally(&docker, image_ref).await?;

    let save_path = work_dir.join("image.tar");
    let mut stream = docker.export_image(image_ref);

    let mut save_file = fs::File::create(&save_path)
        .await
        .context("Failed to create image save file")?;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("Failed to read image stream")?;
        save_file.write_all(&chunk).await?;
    }

    save_file.flush().await?;
    drop(save_file);

    let extract_dir = work_dir.join("image-layers");
    fs::create_dir_all(&extract_dir).await?;

    let tar_file = std::fs::File::open(&save_path)?;
    let mut archive = tar::Archive::new(tar_file);
    archive.unpack(&extract_dir)?;

    let manifest_path = extract_dir.join("manifest.json");
    let manifest_data = fs::read_to_string(&manifest_path).await?;
    let manifest: Vec<serde_json::Value> = serde_json::from_str(&manifest_data)?;

    let layers = manifest[0]["Layers"]
        .as_array()
        .context("No layers found in manifest")?;

    let last_layer = layers
        .last()
        .and_then(|v| v.as_str())
        .context("Failed to get last layer")?;

    let layer_path = extract_dir.join(last_layer);
    let output_dir = work_dir.join("user-service");
    fs::create_dir_all(&output_dir).await?;

    let layer_file = std::fs::File::open(&layer_path)?;
    let mut layer_archive = tar::Archive::new(layer_file);
    layer_archive.unpack(&output_dir)?;

    fs::remove_file(&save_path).await.ok();
    fs::remove_dir_all(&extract_dir).await.ok();

    tracing::info!("Last layer extracted to: {}", output_dir.display());
    Ok(output_dir)
}
