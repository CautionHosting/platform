// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use bollard::container::{Config, CreateContainerOptions, DownloadFromContainerOptions};
use bollard::Docker;
use dterror::ResultExt;
use futures_util::stream::StreamExt;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::AsyncWriteExt;

/// Error type for [`safe_unpack`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error, dterror::CtxError)]
pub enum SafeUnpackError {
    #[error("failed to read archive entries [{location}]")]
    ReadEntries {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to read archive entry [{location}]")]
    ReadEntry {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to get entry path [{location}]")]
    EntryPath {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("path traversal detected in archive entry: {entry_path} [{location}]")]
    PathTraversal {
        entry_path: String,
        location: dterror::Location,
    },

    #[error("failed to extract: {entry_path} [{location}]")]
    ExtractEntry {
        entry_path: String,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },
}

/// Error type for [`export_image_filesystem_tar`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error, dterror::CtxError)]
pub enum ExportImageFilesystemTarError {
    #[error("failed to connect to Docker daemon [{location}]")]
    ConnectDocker {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("image not found locally [{location}]")]
    VerifyImage {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to create container [{location}]")]
    CreateContainer {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to create work directory [{location}]")]
    CreateWorkDir {
        #[context(borrow = Path)]
        path: std::path::PathBuf,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to write container export [{location}]")]
    WriteExport {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to remove temporary container [{location}]")]
    RemoveContainer {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },
}

/// Error type for [`write_container_export`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error, dterror::CtxError)]
pub enum WriteContainerExportError {
    #[error("failed to create container export tar [{location}]")]
    CreateFile {
        #[context(borrow = Path)]
        path: std::path::PathBuf,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to read export stream [{location}]")]
    ReadStream {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to write tar data [{location}]")]
    WriteData {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to flush tar file [{location}]")]
    Flush {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },
}

/// Error type for [`extract_image_filesystem`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error, dterror::CtxError)]
pub enum ExtractImageFilesystemError {
    #[error("failed to connect to Docker daemon [{location}]")]
    ConnectDocker {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("image not found locally [{location}]")]
    VerifyImage {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to create container [{location}]")]
    CreateContainer {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to create export directory [{location}]")]
    CreateDir {
        #[context(borrow = Path)]
        path: std::path::PathBuf,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to export container filesystem [{location}]")]
    ExportFilesystem {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to remove temporary container [{location}]")]
    RemoveContainer {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },
}

/// Error type for [`verify_image_exists_locally`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum VerifyImageExistsLocallyError {
    #[error("image '{image_ref}' not found locally. This image should have been built earlier in the deployment process [{location}]")]
    ImageNotFound {
        image_ref: String,
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },
}

/// Error type for [`create_container`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error, dterror::CtxError)]
pub enum CreateContainerError {
    #[error("failed to create container [{location}]")]
    CreateContainer {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },
}

/// Error type for [`export_container_filesystem`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error, dterror::CtxError)]
pub enum ExportContainerFilesystemError {
    #[error("failed to create tar file [{location}]")]
    CreateFile {
        #[context(borrow = Path)]
        path: std::path::PathBuf,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to read export stream [{location}]")]
    ReadStream {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to write tar data [{location}]")]
    WriteData {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to flush tar file [{location}]")]
    Flush {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to open tar file [{location}]")]
    OpenFile {
        #[context(borrow = Path)]
        path: std::path::PathBuf,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to extract tar archive [{location}]")]
    ExtractArchive {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },
}

/// Error type for [`extract_specific_files`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error, dterror::CtxError)]
pub enum ExtractSpecificFilesError {
    #[error("failed to connect to Docker daemon [{location}]")]
    ConnectDocker {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("image not found locally [{location}]")]
    VerifyImage {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to create container [{location}]")]
    CreateContainer {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to create output directory [{location}]")]
    CreateDir {
        #[context(borrow = Path)]
        path: std::path::PathBuf,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to create tar file [{location}]")]
    CreateFile {
        #[context(borrow = Path)]
        path: std::path::PathBuf,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to write tar data [{location}]")]
    WriteData {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to flush tar file [{location}]")]
    Flush {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to open tar file [{location}]")]
    OpenFile {
        #[context(borrow = Path)]
        path: std::path::PathBuf,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to extract tar archive [{location}]")]
    ExtractArchive {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to download file '{file_path}' from container [{location}]")]
    DownloadFile {
        #[context(borrow = str)]
        file_path: String,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to remove temporary container [{location}]")]
    RemoveContainer {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },
}

/// Error type for [`extract_static_binary`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error, dterror::CtxError)]
pub enum ExtractStaticBinaryError {
    #[error("failed to connect to Docker daemon [{location}]")]
    ConnectDocker {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("image not found locally [{location}]")]
    VerifyImage {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to create container [{location}]")]
    CreateContainer {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to create output directory [{location}]")]
    CreateDir {
        #[context(borrow = Path)]
        path: std::path::PathBuf,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to create tar file [{location}]")]
    CreateFile {
        #[context(borrow = Path)]
        path: std::path::PathBuf,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to write tar data [{location}]")]
    WriteData {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to flush tar file [{location}]")]
    Flush {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to create target directory [{location}]")]
    CreateTargetDir {
        #[context(borrow = Path)]
        path: std::path::PathBuf,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to open tar file [{location}]")]
    OpenFile {
        #[context(borrow = Path)]
        path: std::path::PathBuf,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to extract tar archive [{location}]")]
    ExtractArchive {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to download binary '{binary_path}' from container [{location}]")]
    DownloadBinary {
        #[context(borrow = str)]
        binary_path: String,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to remove temporary container [{location}]")]
    RemoveContainer {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },
}

/// Error type for [`extract_last_layer_only`].
#[non_exhaustive]
#[derive(Debug, thiserror::Error, dterror::CtxError)]
pub enum ExtractLastLayerOnlyError {
    #[error("failed to connect to Docker daemon [{location}]")]
    ConnectDocker {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("image not found locally [{location}]")]
    VerifyImage {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to create image save file [{location}]")]
    CreateSaveFile {
        #[context(borrow = Path)]
        path: std::path::PathBuf,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to read image stream [{location}]")]
    ReadStream {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to write save file [{location}]")]
    WriteSaveFile {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to flush save file [{location}]")]
    FlushSaveFile {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to create extract directory [{location}]")]
    CreateDir {
        #[context(borrow = Path)]
        path: std::path::PathBuf,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to open tar file [{location}]")]
    OpenTarFile {
        #[context(borrow = Path)]
        path: std::path::PathBuf,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to extract tar archive [{location}]")]
    ExtractArchive {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to read manifest file [{location}]")]
    ReadManifest {
        #[context(borrow = Path)]
        path: std::path::PathBuf,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to parse manifest JSON [{location}]")]
    ParseManifest {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("no layers found in manifest [{location}]")]
    NoLayers { location: dterror::Location },

    #[error("failed to get last layer [{location}]")]
    LastLayer { location: dterror::Location },

    #[error("path traversal detected in manifest layer path: {layer_path} [{location}]")]
    PathTraversal {
        layer_path: String,
        location: dterror::Location,
    },

    #[error("failed to create output directory [{location}]")]
    CreateOutputDir {
        #[context(borrow = Path)]
        path: std::path::PathBuf,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to open layer file [{location}]")]
    OpenLayerFile {
        #[context(borrow = Path)]
        path: std::path::PathBuf,
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },

    #[error("failed to extract layer archive [{location}]")]
    ExtractLayer {
        #[location]
        location: dterror::Location,
        #[source]
        source: dterror::BoxError,
    },
}

/// Safely unpack a tar archive into `dest`, rejecting any entry whose path
/// contains `..` components (zip-slip / path traversal).
#[tracing::instrument(skip_all, err)]
fn safe_unpack(
    archive: &mut tar::Archive<impl std::io::Read>,
    dest: &Path,
) -> Result<(), SafeUnpackError> {
    use SafeUnpackErrorCtx as Ctx;

    for entry in archive.entries().with_context(Ctx::read_entries())? {
        let mut entry = entry.with_context(Ctx::read_entry())?;
        let path = entry.path().with_context(Ctx::entry_path())?.into_owned();

        for component in path.components() {
            if matches!(component, std::path::Component::ParentDir) {
                return Err(SafeUnpackError::PathTraversal {
                    entry_path: path.display().to_string(),
                    location: std::panic::Location::caller(),
                });
            }
        }

        entry
            .unpack_in(dest)
            .with_context(Ctx::extract_entry(path.display().to_string()))?;
    }
    Ok(())
}

/// Export the user image filesystem as a tar, WITHOUT unpacking it on the host.
///
/// The tar is handed to the EIF build context verbatim and unpacked inside the
/// Linux builder. Unpacking here instead would silently corrupt the image on a
/// case-insensitive filesystem: macOS APFS folds `Foo` and `foo` onto one inode,
/// so entries whose names differ only by case overwrite each other and simply
/// vanish from the ramdisk. That is not a cosmetic difference - it changes the
/// cpio, so PCR0/PCR1 diverge and `caution verify` reports a mismatch against a
/// deployment that is in fact byte-correct. It also fails *silently*: the export
/// succeeds, the build succeeds, and only the attestation comparison reveals it.
///
/// Observed on a stock macOS host: 9 OpenSSL man-page symlinks
/// (`OPENSSL_VERSION_*`/`OSSL_TRACE_*`, which differ from siblings only by case)
/// were lost, 11,447 entries reproduced against 11,456 deployed. PCR2 still
/// matched, because it measures the application rather than the whole image,
/// which is what makes the failure so confusing to diagnose.
///
/// See https://codeberg.org/caution/platform/issues/401.
#[tracing::instrument(skip_all, err)]
pub async fn export_image_filesystem_tar(
    image_ref: &str,
    work_dir: &Path,
) -> Result<PathBuf, ExportImageFilesystemTarError> {
    use ExportImageFilesystemTarErrorCtx as Ctx;

    tracing::info!("Exporting filesystem tar from image: {}", image_ref);

    let docker = Docker::connect_with_local_defaults().with_context(Ctx::connect_docker())?;

    verify_image_exists_locally(&docker, image_ref)
        .await
        .with_context(Ctx::verify_image())?;

    let container_id = create_container(&docker, image_ref)
        .await
        .with_context(Ctx::create_container())?;

    fs::create_dir_all(work_dir)
        .await
        .with_context(Ctx::create_work_dir(work_dir))?;
    let tar_path = work_dir.join("user-service.tar");

    let export_result = write_container_export(&docker, &container_id, &tar_path).await;

    // Remove the container even if the export failed, so a transient error does
    // not leak a container per attempt.
    let remove_result = docker
        .remove_container(&container_id, None)
        .await
        .with_context(Ctx::remove_container());

    export_result.with_context(Ctx::write_export())?;
    remove_result?;

    tracing::info!("Exported user filesystem tar to: {}", tar_path.display());
    Ok(tar_path)
}

/// Stream `docker export` straight to a file. No unpacking, no host filesystem
/// semantics applied to the contents.
#[tracing::instrument(skip_all, err)]
pub(crate) async fn write_container_export(
    docker: &Docker,
    container_id: &str,
    tar_path: &Path,
) -> Result<(), WriteContainerExportError> {
    use WriteContainerExportErrorCtx as Ctx;

    let mut stream = docker.export_container(container_id);

    let mut tar_file = fs::File::create(tar_path)
        .await
        .with_context(Ctx::create_file(tar_path))?;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.with_context(Ctx::read_stream())?;
        tar_file
            .write_all(&chunk)
            .await
            .with_context(Ctx::write_data())?;
    }

    tar_file.flush().await.with_context(Ctx::flush())?;
    Ok(())
}

#[tracing::instrument(skip_all, err)]
pub async fn extract_image_filesystem(
    image_ref: &str,
    work_dir: &Path,
) -> Result<PathBuf, ExtractImageFilesystemError> {
    use ExtractImageFilesystemErrorCtx as Ctx;

    tracing::info!("Extracting filesystem from image: {}", image_ref);

    let docker = Docker::connect_with_local_defaults().with_context(Ctx::connect_docker())?;

    verify_image_exists_locally(&docker, image_ref)
        .await
        .with_context(Ctx::verify_image())?;

    let container_id = create_container(&docker, image_ref)
        .await
        .with_context(Ctx::create_container())?;

    let export_dir = work_dir.join("user-service");
    fs::create_dir_all(&export_dir)
        .await
        .with_context(Ctx::create_dir(&export_dir))?;

    export_container_filesystem(&docker, &container_id, &export_dir)
        .await
        .with_context(Ctx::export_filesystem())?;

    docker
        .remove_container(&container_id, None)
        .await
        .with_context(Ctx::remove_container())?;

    tracing::info!("Extracted user filesystem to: {}", export_dir.display());
    Ok(export_dir)
}

#[tracing::instrument(skip_all, err)]
pub(crate) async fn verify_image_exists_locally(
    docker: &Docker,
    image_ref: &str,
) -> Result<(), VerifyImageExistsLocallyError> {
    tracing::info!("Checking if image exists locally: {}", image_ref);

    match docker.inspect_image(image_ref).await {
        Ok(_) => {
            tracing::info!("✓ Image exists locally: {}", image_ref);
            Ok(())
        }
        Err(e) => {
            tracing::error!("✗ Image not found locally: {}", image_ref);
            Err(VerifyImageExistsLocallyError::ImageNotFound {
                image_ref: image_ref.to_string(),
                location: std::panic::Location::caller(),
                source: Box::new(e),
            })
        }
    }
}

#[tracing::instrument(skip_all, err)]
pub(crate) async fn create_container(
    docker: &Docker,
    image_ref: &str,
) -> Result<String, CreateContainerError> {
    use CreateContainerErrorCtx as Ctx;

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
        .with_context(Ctx::create_container())?;

    tracing::info!("Created container: {}", response.id);
    Ok(response.id)
}

#[tracing::instrument(skip_all, err)]
pub(crate) async fn export_container_filesystem(
    docker: &Docker,
    container_id: &str,
    output_dir: &Path,
) -> Result<(), ExportContainerFilesystemError> {
    use ExportContainerFilesystemErrorCtx as Ctx;

    tracing::info!("Exporting container filesystem");

    let mut stream = docker.export_container(container_id);

    let tar_path = output_dir.parent().unwrap().join("container-export.tar");
    let mut tar_file = fs::File::create(&tar_path)
        .await
        .with_context(Ctx::create_file(&tar_path))?;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.with_context(Ctx::read_stream())?;
        tar_file
            .write_all(&chunk)
            .await
            .with_context(Ctx::write_data())?;
    }

    tar_file.flush().await.with_context(Ctx::flush())?;
    drop(tar_file);

    tracing::info!("Extracting tar archive to: {}", output_dir.display());

    let tar_file = std::fs::File::open(&tar_path).with_context(Ctx::open_file(&tar_path))?;
    let mut archive = tar::Archive::new(tar_file);

    archive.set_preserve_permissions(true);
    archive.set_preserve_mtime(true);
    archive.set_unpack_xattrs(true);

    safe_unpack(&mut archive, output_dir).with_context(Ctx::extract_archive())?;

    fs::remove_file(&tar_path).await.ok();

    tracing::info!("Filesystem extracted successfully");
    Ok(())
}

#[tracing::instrument(skip_all, err)]
pub async fn extract_specific_files(
    image_ref: &str,
    files: &[String],
    work_dir: &Path,
) -> Result<PathBuf, ExtractSpecificFilesError> {
    use ExtractSpecificFilesErrorCtx as Ctx;

    tracing::info!(
        "Extracting {} specific files from image: {}",
        files.len(),
        image_ref
    );

    let docker = Docker::connect_with_local_defaults().with_context(Ctx::connect_docker())?;

    verify_image_exists_locally(&docker, image_ref)
        .await
        .with_context(Ctx::verify_image())?;

    let container_id = create_container(&docker, image_ref)
        .await
        .with_context(Ctx::create_container())?;

    let output_dir = work_dir.join("user-service");
    fs::create_dir_all(&output_dir)
        .await
        .with_context(Ctx::create_dir(&output_dir))?;

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
            .with_context(Ctx::create_file(&tar_path))?;

        while let Some(chunk_result) = stream.next().await {
            match chunk_result {
                Ok(bytes) => {
                    tar_file
                        .write_all(&bytes)
                        .await
                        .with_context(Ctx::write_data())?;
                }
                Err(e) => {
                    docker.remove_container(&container_id, None).await.ok();
                    return Err(ExtractSpecificFilesError::DownloadFile {
                        file_path: file_path.clone(),
                        location: std::panic::Location::caller(),
                        source: Box::new(e),
                    });
                }
            }
        }

        tar_file.flush().await.with_context(Ctx::flush())?;
        drop(tar_file);

        let tar_file = std::fs::File::open(&tar_path).with_context(Ctx::open_file(&tar_path))?;
        let mut archive = tar::Archive::new(tar_file);

        archive.set_preserve_permissions(true);
        archive.set_preserve_mtime(true);
        archive.set_unpack_xattrs(true);

        safe_unpack(&mut archive, &output_dir).with_context(Ctx::extract_archive())?;

        fs::remove_file(&tar_path).await.ok();

        tracing::info!("Successfully extracted: {}", file_path);
    }

    docker
        .remove_container(&container_id, None)
        .await
        .with_context(Ctx::remove_container())?;

    tracing::info!("All files extracted to: {}", output_dir.display());
    Ok(output_dir)
}

#[tracing::instrument(skip_all, err)]
pub async fn extract_static_binary(
    image_ref: &str,
    binary_path: &str,
    work_dir: &Path,
) -> Result<PathBuf, ExtractStaticBinaryError> {
    use ExtractStaticBinaryErrorCtx as Ctx;

    tracing::info!(
        "Extracting static binary from image: {} (binary: {})",
        image_ref,
        binary_path
    );

    let docker = Docker::connect_with_local_defaults().with_context(Ctx::connect_docker())?;

    verify_image_exists_locally(&docker, image_ref)
        .await
        .with_context(Ctx::verify_image())?;

    let container_id = create_container(&docker, image_ref)
        .await
        .with_context(Ctx::create_container())?;

    let output_dir = work_dir.join("user-service");
    fs::create_dir_all(&output_dir)
        .await
        .with_context(Ctx::create_dir(&output_dir))?;

    let options = DownloadFromContainerOptions {
        path: binary_path.to_string(),
    };

    let mut stream = docker.download_from_container(&container_id, Some(options));

    let tar_path = output_dir.parent().unwrap().join("binary-extract.tar");
    let mut tar_file = fs::File::create(&tar_path)
        .await
        .with_context(Ctx::create_file(&tar_path))?;

    while let Some(chunk_result) = stream.next().await {
        match chunk_result {
            Ok(bytes) => {
                tar_file
                    .write_all(&bytes)
                    .await
                    .with_context(Ctx::write_data())?;
            }
            Err(e) => {
                docker.remove_container(&container_id, None).await.ok();
                return Err(ExtractStaticBinaryError::DownloadBinary {
                    binary_path: binary_path.to_string(),
                    location: std::panic::Location::caller(),
                    source: Box::new(e),
                });
            }
        }
    }

    tar_file.flush().await.with_context(Ctx::flush())?;
    drop(tar_file);

    let file_path_obj = std::path::Path::new(binary_path);
    let parent_dir = file_path_obj.parent().unwrap_or(std::path::Path::new("/"));
    let target_dir = output_dir.join(parent_dir.strip_prefix("/").unwrap_or(parent_dir));

    std::fs::create_dir_all(&target_dir).with_context(Ctx::create_target_dir(&target_dir))?;

    let tar_file = std::fs::File::open(&tar_path).with_context(Ctx::open_file(&tar_path))?;
    let mut archive = tar::Archive::new(tar_file);

    archive.set_preserve_permissions(true);
    archive.set_preserve_mtime(true);
    archive.set_unpack_xattrs(true);

    safe_unpack(&mut archive, &target_dir).with_context(Ctx::extract_archive())?;

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
                safe_unpack(&mut archive, &ca_target_dir).ok();
            }
        }
        fs::remove_file(&ca_tar_path).await.ok();
    }

    docker
        .remove_container(&container_id, None)
        .await
        .with_context(Ctx::remove_container())?;

    tracing::info!("Static binary extracted to: {}", output_dir.display());
    Ok(output_dir)
}

#[tracing::instrument(skip_all, err)]
pub async fn extract_last_layer_only(
    image_ref: &str,
    work_dir: &Path,
) -> Result<PathBuf, ExtractLastLayerOnlyError> {
    use ExtractLastLayerOnlyErrorCtx as Ctx;

    tracing::info!("Extracting last layer from image: {}", image_ref);

    let docker = Docker::connect_with_local_defaults().with_context(Ctx::connect_docker())?;

    verify_image_exists_locally(&docker, image_ref)
        .await
        .with_context(Ctx::verify_image())?;

    let save_path = work_dir.join("image.tar");
    let mut stream = docker.export_image(image_ref);

    let mut save_file = fs::File::create(&save_path)
        .await
        .with_context(Ctx::create_save_file(&save_path))?;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.with_context(Ctx::read_stream())?;
        save_file
            .write_all(&chunk)
            .await
            .with_context(Ctx::write_save_file())?;
    }

    save_file
        .flush()
        .await
        .with_context(Ctx::flush_save_file())?;
    drop(save_file);

    let extract_dir = work_dir.join("image-layers");
    fs::create_dir_all(&extract_dir)
        .await
        .with_context(Ctx::create_dir(&extract_dir))?;

    let tar_file = std::fs::File::open(&save_path).with_context(Ctx::open_tar_file(&save_path))?;
    let mut archive = tar::Archive::new(tar_file);
    safe_unpack(&mut archive, &extract_dir).with_context(Ctx::extract_archive())?;

    let manifest_path = extract_dir.join("manifest.json");
    let manifest_data = fs::read_to_string(&manifest_path)
        .await
        .with_context(Ctx::read_manifest(&manifest_path))?;
    let manifest: Vec<serde_json::Value> =
        serde_json::from_str(&manifest_data).with_context(Ctx::parse_manifest())?;

    let layers = match manifest[0]["Layers"].as_array() {
        Some(arr) => arr,
        None => {
            return Err(ExtractLastLayerOnlyError::NoLayers {
                location: std::panic::Location::caller(),
            });
        }
    };

    let last_layer = match layers.last().and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            return Err(ExtractLastLayerOnlyError::LastLayer {
                location: std::panic::Location::caller(),
            });
        }
    };

    // Validate manifest layer path doesn't escape extract_dir
    if std::path::Path::new(last_layer)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(ExtractLastLayerOnlyError::PathTraversal {
            layer_path: last_layer.to_string(),
            location: std::panic::Location::caller(),
        });
    }

    let layer_path = extract_dir.join(last_layer);
    let output_dir = work_dir.join("user-service");
    fs::create_dir_all(&output_dir)
        .await
        .with_context(Ctx::create_output_dir(&output_dir))?;

    let layer_file =
        std::fs::File::open(&layer_path).with_context(Ctx::open_layer_file(&layer_path))?;
    let mut layer_archive = tar::Archive::new(layer_file);
    safe_unpack(&mut layer_archive, &output_dir).with_context(Ctx::extract_layer())?;

    fs::remove_file(&save_path).await.ok();
    fs::remove_dir_all(&extract_dir).await.ok();

    tracing::info!("Last layer extracted to: {}", output_dir.display());
    Ok(output_dir)
}
