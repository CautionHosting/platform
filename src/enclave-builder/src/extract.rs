// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result};
use bollard::Docker;
use bollard::container::{Config, CreateContainerOptions, DownloadFromContainerOptions};
use futures_util::stream::StreamExt;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info};

#[derive(Debug)]
pub enum ImageFilesystemExtractErrorKind {
    DockerConnect,
    ImageDoesNotExist,
    ContainerCreate,
    ExportDirCreate,
    ContainerFilesystemExport,
    ContainerRemove,
}

#[derive(Debug, thiserror::Error, bon::Builder)]
#[error("could not extract fs from image (ref: {image_ref}, work_dir: {work_dir:?}): {kind:?}")]
pub struct ImageFilesystemExtractError {
    #[builder(into)]
    image_ref: String,
    #[builder(into)]
    work_dir: PathBuf,
    kind: ImageFilesystemExtractErrorKind,

    #[source]
    #[builder(into)]
    source: Box<dyn std::error::Error + Send + Sync>,
}

#[tracing::instrument]
pub async fn extract_image_filesystem(
    image_ref: &str,
    work_dir: &Path,
) -> Result<PathBuf, ImageFilesystemExtractError> {
    debug!("Extracting filesystem from image");
    let error_template = ImageFilesystemExtractError::builder()
        .image_ref(image_ref)
        .work_dir(work_dir);

    let docker = match Docker::connect_with_local_defaults() {
        Ok(o) => o,
        Err(e) => {
            return Err(error_template
                .kind(ImageFilesystemExtractErrorKind::DockerConnect)
                .source(e)
                .build());
        }
    };

    if let Err(e) = verify_image_exists_locally(&docker, image_ref).await {
        return Err(error_template
            .kind(ImageFilesystemExtractErrorKind::ImageDoesNotExist)
            .source(e)
            .build());
    }

    let container_id = match create_container(&docker, image_ref).await {
        Ok(o) => o,
        Err(e) => {
            return Err(error_template
                .kind(ImageFilesystemExtractErrorKind::ContainerCreate)
                .source(e)
                .build());
        }
    };

    let export_dir = work_dir.join("user-service");
    if let Err(e) = fs::create_dir_all(&export_dir).await {
        return Err(error_template
            .kind(ImageFilesystemExtractErrorKind::ExportDirCreate)
            .source(e)
            .build());
    }

    if let Err(e) = export_container_filesystem(&docker, &container_id, &export_dir).await {
        return Err(error_template
            .kind(ImageFilesystemExtractErrorKind::ContainerFilesystemExport)
            .source(e)
            .build());
    }

    docker
        .remove_container(&container_id, None)
        .await
        .map_err(|source| {
            error_template
                .kind(ImageFilesystemExtractErrorKind::ContainerRemove)
                .source(source)
                .build()
        })?;

    info!(?export_dir, "Extracted user filesystem");
    Ok(export_dir)
}

#[derive(Debug, thiserror::Error)]
#[error("could not inspect image {image_ref}")]
pub struct ImageInspectError {
    image_ref: String,

    #[source]
    source: bollard::errors::Error,
}

async fn verify_image_exists_locally(
    docker: &Docker,
    image_ref: &str,
) -> Result<(), ImageInspectError> {
    debug!(?image_ref, "Checking if image exists locally");

    match docker.inspect_image(image_ref).await {
        Ok(_) => {
            info!(?image_ref, "Image exists locally");
            Ok(())
        }
        Err(source) => {
            error!(?image_ref, "Image not found locally");
            Err(ImageInspectError {
                image_ref: image_ref.into(),
                source,
            })
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("could not create a container from image {image_ref}")]
pub struct ContainerCreateError {
    image_ref: String,

    #[source]
    source: bollard::errors::Error,
}

#[tracing::instrument(skip(docker))]
async fn create_container(docker: &Docker, image_ref: &str) -> Result<String> {
    info!("Creating temporary container from image");

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
        .map_err(|source| ContainerCreateError {
            image_ref: image_ref.into(),
            source,
        })?;

    info!(container_id = ?response.id, "Created container");
    Ok(response.id)
}

#[derive(Debug)]
pub enum ContainerFilesystemExportErrorKind {
    TarFileCreate { path: PathBuf },
    TarFileOpen { path: PathBuf },
    TarFileCleanup { path: PathBuf },
    ChunkRead,
    ChunkWrite,
    Flush,
    TarUnpack,
}

#[derive(Debug, thiserror::Error, bon::Builder)]
#[error("could not export filesystem for container {container_id} to {output_dir:?} ({kind:?})")]
pub struct ContainerFilesystemExportError {
    #[builder(into)]
    container_id: String,
    #[builder(into)]
    output_dir: PathBuf,
    kind: ContainerFilesystemExportErrorKind,

    #[source]
    #[builder(into)]
    source: Box<dyn std::error::Error + Send + Sync>,
}

#[tracing::instrument(skip(docker))]
async fn export_container_filesystem(
    docker: &Docker,
    container_id: &str,
    output_dir: &Path,
) -> Result<(), ContainerFilesystemExportError> {
    info!("Exporting container filesystem");
    let error_template = ContainerFilesystemExportError::builder()
        .container_id(container_id)
        .output_dir(output_dir);

    let mut stream = docker.export_container(container_id);

    // TODO: share code with extract_specific_files
    // link: REUSE-CODE-01
    let tar_path = output_dir.parent().unwrap().join("container-export.tar");
    let mut tar_file = match fs::File::create(&tar_path).await {
        Ok(o) => o,
        Err(source) => {
            return Err(error_template
                .kind(ContainerFilesystemExportErrorKind::TarFileCreate { path: tar_path })
                .source(source)
                .build());
        }
    };

    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(o) => o,
            Err(source) => {
                return Err(error_template
                    .kind(ContainerFilesystemExportErrorKind::ChunkRead)
                    .source(source)
                    .build());
            }
        };
        if let Err(source) = tar_file.write_all(&chunk).await {
            return Err(error_template
                .kind(ContainerFilesystemExportErrorKind::ChunkWrite)
                .source(source)
                .build());
        }
    }

    // manual flush because no AsyncDrop
    if let Err(source) = tar_file.flush().await {
        return Err(error_template
            .kind(ContainerFilesystemExportErrorKind::Flush)
            .source(source)
            .build());
    }
    drop(tar_file);

    info!("Extracting tar archive");

    let tar_file = match std::fs::File::open(&tar_path) {
        Ok(o) => o,
        Err(source) => {
            return Err(error_template
                .kind(ContainerFilesystemExportErrorKind::TarFileOpen { path: tar_path })
                .source(source)
                .build());
        }
    };

    // TODO: move to astral-sh/tokio-tar
    // should allow for reading chunks from stream and writing to tar parser
    // maybe ref sans-io post from amos about unzipping files

    let mut archive = tar::Archive::new(tar_file);

    archive.set_preserve_permissions(true);
    archive.set_preserve_mtime(true);
    archive.set_unpack_xattrs(true);

    if let Err(source) = archive.unpack(output_dir) {
        return Err(error_template
            .kind(ContainerFilesystemExportErrorKind::TarUnpack)
            .source(source)
            .build());
    }

    if let Err(source) = fs::remove_file(&tar_path).await {
        return Err(error_template
            .kind(ContainerFilesystemExportErrorKind::TarFileCleanup { path: tar_path })
            .source(source)
            .build());
    }

    info!("Filesystem extracted successfully");
    Ok(())
}

#[derive(Debug)]
pub enum FileExtractErrorKind {
    DockerConnect,
    ContainerRemove,
    ImageFind,
    ContainerCreate,
    OutputDirCreate,
    TarFileCreate { path: PathBuf },
    TarFileOpen { path: PathBuf },
    TarFileCleanup { path: PathBuf },
    ChunkRead,
    ChunkWrite,
    Flush,
    TarUnpack,
}

#[derive(Debug, thiserror::Error, bon::Builder)]
#[error("could not extract files from image {image_ref} to path {work_dir:?} ({kind:?})")]
pub struct FileExtractError {
    #[builder(into)]
    image_ref: String,
    #[builder(into)]
    work_dir: PathBuf,
    kind: FileExtractErrorKind,

    #[source]
    #[builder(into)]
    source: Box<dyn std::error::Error + Send + Sync>,
}

#[tracing::instrument(skip(files))]
pub async fn extract_specific_files(
    image_ref: &str,
    files: &[String],
    work_dir: &Path,
) -> Result<PathBuf, FileExtractError> {
    info!(?files, "Extracting files from image");
    let error_template = FileExtractError::builder()
        .image_ref(image_ref)
        .work_dir(work_dir);

    let docker = match Docker::connect_with_local_defaults() {
        Ok(o) => o,
        Err(source) => {
            return Err(error_template
                .kind(FileExtractErrorKind::DockerConnect)
                .source(source)
                .build());
        }
    };

    if let Err(source) = verify_image_exists_locally(&docker, image_ref).await {
        return Err(error_template
            .kind(FileExtractErrorKind::ImageFind)
            .source(source)
            .build());
    };

    let container_id = match create_container(&docker, image_ref).await {
        Ok(o) => o,
        Err(source) => {
            return Err(error_template
                .kind(FileExtractErrorKind::ContainerCreate)
                .source(source)
                .build());
        }
    };

    let output_dir = work_dir.join("user-service");
    if let Err(source) = fs::create_dir_all(&output_dir).await {
        return Err(error_template
            .kind(FileExtractErrorKind::OutputDirCreate)
            .source(source)
            .build());
    }

    // TODO: reuse code from export_container_filesystem
    // link: REUSE-CODE-01
    for file_path in files {
        tracing::info!("Attempting to extract file: {}", file_path);

        let options = DownloadFromContainerOptions {
            path: file_path.clone(),
        };

        tracing::info!("Creating download stream for path: {}", file_path);
        let mut stream = docker.download_from_container(&container_id, Some(options));

        let tar_path = output_dir.parent().unwrap().join("file-extract.tar");
        let mut tar_file = match fs::File::create(&tar_path).await {
            Ok(o) => o,
            Err(source) => {
                return Err(error_template
                    .kind(FileExtractErrorKind::TarFileCreate { path: tar_path })
                    .source(source)
                    .build());
            }
        };

        while let Some(chunk_result) = stream.next().await {
            match chunk_result {
                Ok(bytes) => {
                    if let Err(source) = tar_file.write_all(&bytes).await {
                        return Err(error_template
                            .kind(FileExtractErrorKind::ChunkWrite)
                            .source(source)
                            .build());
                    }
                }
                Err(source) => {
                    docker.remove_container(&container_id, None).await.ok();
                    return Err(error_template
                        .kind(FileExtractErrorKind::ChunkRead)
                        .source(source)
                        .build());
                }
            }
        }

        // manual flush because no AsyncDrop
        if let Err(source) = tar_file.flush().await {
            return Err(error_template
                .kind(FileExtractErrorKind::Flush)
                .source(source)
                .build());
        }
        drop(tar_file);

        let tar_file = match std::fs::File::open(&tar_path) {
            Ok(o) => o,
            Err(source) => {
                return Err(error_template
                    .kind(FileExtractErrorKind::TarFileOpen { path: tar_path })
                    .source(source)
                    .build());
            }
        };
        let mut archive = tar::Archive::new(tar_file);

        archive.set_preserve_permissions(true);
        archive.set_preserve_mtime(true);
        archive.set_unpack_xattrs(true);

        if let Err(source) = archive.unpack(&output_dir) {
            return Err(error_template
                .kind(FileExtractErrorKind::TarUnpack)
                .source(source)
                .build());
        }

        if let Err(source) = fs::remove_file(&tar_path).await {
            return Err(error_template
                .kind(FileExtractErrorKind::TarFileCleanup { path: tar_path })
                .source(source)
                .build());
        }

        debug!(?tar_path, "Extracted all files from tar");
    }

    if let Err(source) = docker.remove_container(&container_id, None).await {
        return Err(error_template
            .kind(FileExtractErrorKind::ContainerRemove)
            .source(source)
            .build());
    }

    info!(?output_dir, "Successfully extracted all files");

    Ok(output_dir)
}

// TODO: Ryan's being lazy and not fixing this up yet 'cause he wants to just delete the code
#[tracing::instrument]
pub async fn extract_static_binary(
    image_ref: &str,
    binary_path: &str,
    work_dir: &Path,
) -> Result<PathBuf> {
    info!("Extracting static binary from image");

    let docker =
        Docker::connect_with_local_defaults().context("Failed to connect to Docker daemon")?;

    verify_image_exists_locally(&docker, image_ref).await?;

    let container_id = create_container(&docker, image_ref).await?;

    let output_dir = work_dir.join("user-service");
    fs::create_dir_all(&output_dir).await?;

    let options = DownloadFromContainerOptions {
        path: binary_path.to_string(),
    };

    let mut stream = docker.download_from_container(&container_id, Some(options));

    let tar_path = output_dir.parent().unwrap().join("binary-extract.tar");
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
                    "Failed to download binary '{}' from container: {}",
                    binary_path,
                    e
                ));
            }
        }
    }

    tar_file.flush().await?;
    drop(tar_file);

    let file_path_obj = std::path::Path::new(binary_path);
    let parent_dir = file_path_obj.parent().unwrap_or(std::path::Path::new("/"));
    let target_dir = output_dir.join(parent_dir.strip_prefix("/").unwrap_or(parent_dir));

    std::fs::create_dir_all(&target_dir).context("Failed to create target directory")?;

    let tar_file = std::fs::File::open(&tar_path).context("Failed to open tar file")?;
    let mut archive = tar::Archive::new(tar_file);

    archive.set_preserve_permissions(true);
    archive.set_preserve_mtime(true);
    archive.set_unpack_xattrs(true);

    archive
        .unpack(&target_dir)
        .context("Failed to extract tar archive")?;

    fs::remove_file(&tar_path).await.ok();

    let ca_cert_path = "/etc/ssl/certs/ca-certificates.crt";
    let ca_options = DownloadFromContainerOptions {
        path: ca_cert_path.to_string(),
    };

    let mut ca_stream = docker.download_from_container(&container_id, Some(ca_options));
    let ca_tar_path = output_dir.parent().unwrap().join("ca-extract.tar");

    if let Ok(mut ca_tar_file) = fs::File::create(&ca_tar_path).await {
        let mut success = true;
        while let Some(chunk_result) = ca_stream.next().await {
            match chunk_result {
                Ok(bytes) => {
                    if ca_tar_file.write_all(&bytes).await.is_err() {
                        success = false;
                        break;
                    }
                }
                Err(_) => {
                    success = false;
                    break;
                }
            }
        }

        if success {
            ca_tar_file.flush().await.ok();
            drop(ca_tar_file);

            let ca_target_dir = output_dir.join("etc/ssl/certs");
            std::fs::create_dir_all(&ca_target_dir).ok();

            if let Ok(tar_file) = std::fs::File::open(&ca_tar_path) {
                let mut archive = tar::Archive::new(tar_file);
                archive.unpack(&ca_target_dir).ok();
            }
        }
        fs::remove_file(&ca_tar_path).await.ok();
    }

    docker
        .remove_container(&container_id, None)
        .await
        .context("Failed to remove temporary container")?;

    tracing::info!("Static binary extracted to: {}", output_dir.display());
    Ok(output_dir)
}

// TODO: what's the difference between this and a container export? which is used? a last-layer
// isn't that useful compared to all layers, what if something has multiple build steps?
//
// This code doesn't appear to be used. Nuke?
#[deprecated = "unused"]
pub async fn extract_last_layer_only(image_ref: &str, work_dir: &Path) -> Result<PathBuf> {
    tracing::info!("Extracting last layer from image: {}", image_ref);

    let docker =
        Docker::connect_with_local_defaults().context("Failed to connect to Docker daemon")?;

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
