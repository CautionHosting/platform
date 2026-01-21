// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#![allow(clippy::missing_errors_doc)]

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::process::Command;
use tracing::{debug, error, info, warn};

use crate::EifFile;
use crate::manifest::EnclaveManifest;

#[derive(Debug)]
pub enum EifStageErrorKind {
    DirectoryCreate { path: PathBuf },
    RecursiveCopy { path: PathBuf },
    ManifestWrite { path: PathBuf },
    StartScriptGenerate,
    EifContainerfileGenerate,
}

#[derive(Debug, thiserror::Error, bon::Builder)]
#[error("could not stage directories for building EIF in {work_dir:?} ({kind:?})")]
pub struct EifStageError {
    #[builder(into)]
    work_dir: PathBuf,
    kind: EifStageErrorKind,

    #[source]
    #[builder(into)]
    source: Box<dyn std::error::Error + Send + Sync>,
}

/// Ensure all directories exist for creating an EIF.
#[tracing::instrument(skip_all)]
pub async fn stage_eif_components(
    user_fs_path: &Path,
    enclave_source_path: &Path,
    work_dir: &Path,
    run_command: Option<String>,
    manifest: Option<EnclaveManifest>,
    ports: &[u16],
    e2e: bool,
) -> Result<PathBuf, EifStageError> {
    debug!(
        ?user_fs_path,
        ?enclave_source_path,
        ?work_dir,
        ?run_command,
        ?manifest,
        ?ports,
        ?e2e,
        "Staging EIF components"
    );

    let stub = EifStageError::builder().work_dir(work_dir);

    let stage_dir = work_dir.join("eif-stage");
    if let Err(source) = fs::create_dir_all(&stage_dir).await {
        return Err(stub
            .kind(EifStageErrorKind::DirectoryCreate {
                path: stage_dir.into(),
            })
            .source(source)
            .build());
    }

    let app_dir = stage_dir.join("app");
    let enclave_dir = stage_dir.join("enclave");
    let output_dir = stage_dir.join("output");

    let dirs = [&app_dir, &enclave_dir, &output_dir];

    for dir in dirs {
        if let Err(source) = fs::create_dir_all(dir).await {
            return Err(stub
                .kind(EifStageErrorKind::DirectoryCreate { path: dir.clone() })
                .source(source)
                .build());
        }
    }

    info!(?user_fs_path, "Staging user application");
    if let Err(source) = copy_dir_recursive(user_fs_path, &app_dir).await {
        return Err(stub
            .kind(EifStageErrorKind::RecursiveCopy {
                path: user_fs_path.to_owned(),
            })
            .source(source)
            .build());
    }

    info!(?enclave_source_path, "Staging enclave source",);
    if let Err(source) = copy_dir_recursive(enclave_source_path, &enclave_dir).await {
        return Err(stub
            .kind(EifStageErrorKind::RecursiveCopy { path: enclave_dir })
            .source(source)
            .build());
    }

    if let Some(manifest) = manifest {
        let manifest_path = stage_dir.join("manifest.json");
        if let Err(source) = manifest.write_to_file(&manifest_path).await {
            return Err(stub
                .kind(EifStageErrorKind::ManifestWrite {
                    path: manifest_path,
                })
                .source(source)
                .build());
        }
        info!(?manifest_path, "Wrote manifest");
    }

    if let Err(source) = generate_run_sh(&stage_dir, run_command, ports, e2e).await {
        return Err(stub
            .kind(EifStageErrorKind::StartScriptGenerate)
            .source(source)
            .build());
    }

    if let Err(source) = generate_containerfile_eif(&stage_dir, e2e).await {
        return Err(stub
            .kind(EifStageErrorKind::EifContainerfileGenerate)
            .source(source)
            .build());
    }

    info!(?stage_dir, "EIF components staged successfully",);
    Ok(stage_dir)
}

#[derive(Debug, thiserror::Error)]
#[error("could not write startup script to {path:?}")]
pub struct RunShGenerateError {
    path: PathBuf,

    #[source]
    source: std::io::Error,
}

#[tracing::instrument(skip_all)]
async fn generate_run_sh(
    stage_dir: &Path,
    run_command: Option<String>,
    ports: &[u16],
    e2e: bool,
) -> Result<()> {
    debug!("Generating run.sh");

    // TODO: shlex and shescape
    let user_cmd = if let Some(cmd) = run_command {
        let escaped_cmd = cmd.replace('\'', "'\\''");
        format!("exec sh -c '{escaped_cmd}'")
    } else {
        [
            r#"echo "ERROR: No run command specified in Procfile""#,
            "exit 1",
        ]
        .join("\n")
    };

    // Generate proxies for custom user ports (in addition to the hardcoded 8080/8081/8082)
    let custom_port_proxies: String = ports
        .iter()
        .filter_map(|port| {
            if [8080u16, 8081, 8082].contains(port) {
                warn!(?port, "Found port used by EnclaveOS service");
                None
            } else {
                Some(format!(
                    "/bin/socat VSOCK-LISTEN:{port},reuseaddr,fork TCP:localhost:{port} &",
                ))
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    let custom_port_section = if custom_port_proxies.is_empty() {
        String::new()
    } else {
        format!("\necho \"Starting custom port proxies...\"\n{custom_port_proxies}\n",)
    };

    // Conditionally include STEVE (end-to-end encryption proxy)
    let steve_section = if e2e {
        [
            r#"echo "Starting STEVE (Secure Transport Encryption Via Enclave)...""#,
            "/steve &",
        ]
        .join("\n")
    } else {
        r#"echo "E2E encryption disabled, skipping STEVE""#.into()
    };

    let run_sh_content = format!(
        include_str!("templates/run.sh.tmpl"),
        user_cmd = user_cmd,
        custom_port_section = custom_port_section,
        steve_section = steve_section,
    );

    let run_sh_path = stage_dir.join("run.sh");
    fs::write(&run_sh_path, run_sh_content)
        .await
        .map_err(|source| RunShGenerateError {
            path: run_sh_path.clone(),
            source,
        })?;

    info!(?run_sh_path, "Generated run.sh");
    Ok(())
}

#[derive(Debug, thiserror::Error)]
#[error("could not write startup script to {path:?}")]
pub struct ContainerfileEifGenerateError {
    path: PathBuf,

    #[source]
    source: std::io::Error,
}

async fn generate_containerfile_eif(stage_dir: &Path, e2e: bool) -> Result<()> {
    // Conditionally include STEVE builder stage
    let steve_builder_stage = if e2e {
        include_str!("templates/Containerfile.steve.tmpl")
    } else {
        ""
    };

    let steve_copy = if e2e {
        "COPY --from=steve-builder /binaries/steve /build/binaries/steve"
    } else {
        ""
    };

    let steve_install = if e2e {
        "RUN cp /build/binaries/steve /build/initramfs/steve && chmod +x /build/initramfs/steve"
    } else {
        ""
    };

    let containerfile_content = format!(
        include_str!("templates/Containerfile.eif.tmpl"),
        steve_builder_stage = steve_builder_stage,
        steve_copy = steve_copy,
        steve_install = steve_install,
    );

    let containerfile_path = stage_dir.join("Containerfile.eif");
    fs::write(&containerfile_path, containerfile_content)
        .await
        .map_err(|source| ContainerfileEifGenerateError {
            path: containerfile_path.clone(),
            source,
        })?;

    info!(?containerfile_path, "Generated Containerfile.eif",);

    Ok(())
}

#[derive(Debug)]
pub enum EifBuildErrorKind {
    OutputDirectoryCreate { path: PathBuf },
    OutputDirectoryCanonicalize { path: PathBuf },
    StageEifComponents,
    DockerBuild,
    LogWrite { path: PathBuf },
    EifBuild { log_path: PathBuf },
    EifMissing { path: PathBuf },
    EifCopy { source: PathBuf, dest: PathBuf },
    EifRead { source: PathBuf },
}

#[derive(Debug, thiserror::Error, bon::Builder)]
#[error("could not build EIF from local filesystem export {work_dir:?} ({kind:?})")]
pub struct EifBuildError {
    #[builder(into)]
    work_dir: PathBuf,
    kind: EifBuildErrorKind,

    #[source]
    #[builder(into)]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

/// Build an EIF from a local filesystem export.
///
/// # Errors
///
/// The function may error for God knows what.
/// Look at the error type.
///
/// # Panics
///
/// Yike on a bike, it's a Panic! At The Disco
#[tracing::instrument(skip_all)]
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn build_eif_from_filesystems(
    user_fs_path: &Path,
    _attestation_service_path: &Path,
    _init_path: &Path,
    enclave_source_path: &Path,
    output_path: PathBuf,
    work_dir: &Path,
    run_command: Option<String>,
    manifest: Option<EnclaveManifest>,
    ports: &[u16],
    no_cache: bool,
    e2e: bool,
) -> Result<EifFile, EifBuildError> {
    info!("Building EIF using transparent Containerfile approach");
    let stub = EifBuildError::builder().work_dir(work_dir);

    let stage_dir = match stage_eif_components(
        user_fs_path,
        enclave_source_path,
        work_dir,
        run_command,
        manifest,
        ports,
        e2e,
    )
    .await
    {
        Ok(o) => o,
        Err(source) => {
            return Err(stub
                .kind(EifBuildErrorKind::StageEifComponents)
                .source(source)
                .build());
        }
    };

    info!("Building EIF using Docker and Containerfile.eif");
    let output_dir = stage_dir.join("output");

    if let Err(source) = fs::create_dir_all(&output_dir).await {
        return Err(stub
            .kind(EifBuildErrorKind::OutputDirectoryCreate {
                path: output_dir.clone(),
            })
            .source(source)
            .build());
    }

    let output_dir_absolute = match std::fs::canonicalize(&output_dir) {
        Ok(o) => o,
        Err(source) => {
            return Err(stub
                .kind(EifBuildErrorKind::OutputDirectoryCanonicalize {
                    path: output_dir.into(),
                })
                .source(source)
                .build());
        }
    };

    debug!(?output_dir_absolute, "Output directory (absolute)",);

    // Build docker args, conditionally adding --no-cache
    let mut docker_args = vec![
        "build".to_string(),
        "--progress=plain".to_string(),
        "--target".to_string(),
        "output".to_string(),
        "--output".to_string(),
        format!(
            "type=local,rewrite-timestamp=true,dest={}",
            output_dir_absolute.to_str().unwrap()
        ),
        "-f".to_string(),
        "Containerfile.eif".to_string(),
    ];
    if no_cache {
        docker_args.insert(1, "--no-cache".to_string());
        info!(?no_cache, "EIF build: adding --no-cache flag");
    }
    docker_args.push(".".to_string());

    debug!(?docker_args, "Running Docker build command");
    let command_result = Command::new("docker")
        .args(&docker_args)
        .env("DOCKER_BUILDKIT", "1")
        .env("SOURCE_DATE_EPOCH", "1")
        .current_dir(&stage_dir)
        .output()
        .await;
    let output = match command_result {
        Ok(o) => o,
        Err(source) => {
            return Err(stub
                .kind(EifBuildErrorKind::DockerBuild)
                .source(source)
                .build());
        }
    };

    let build_log_path = stage_dir.join("build.log");
    let mut log_content = String::new();
    log_content.push_str("=== STDOUT ===\n");
    log_content.push_str(&String::from_utf8_lossy(&output.stdout));
    log_content.push_str("\n=== STDERR ===\n");
    log_content.push_str(&String::from_utf8_lossy(&output.stderr));
    if let Err(source) = fs::write(&build_log_path, &log_content).await {
        return Err(stub
            .kind(EifBuildErrorKind::LogWrite {
                path: build_log_path,
            })
            .source(source)
            .build());
    }

    info!(?build_log_path, "Saved build log");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        eprintln!("=== Docker Build Failed ===");
        eprintln!("STDOUT:\n{}", stdout);
        eprintln!("STDERR:\n{}", stderr);
        return Err(stub
            .kind(EifBuildErrorKind::EifBuild {
                log_path: build_log_path,
            })
            .build());
    }

    info!("Docker build completed successfully");

    let built_eif = output_dir_absolute.join("enclave.eif");
    if !built_eif.exists() {
        error!(?built_eif, "EIF file not found, printing output directory");
        if output_dir_absolute.exists() {
            match std::fs::read_dir(&output_dir_absolute) {
                Ok(entries) => {
                    error!("Files in output directory:");
                    for entry in entries.flatten() {
                        error!("  - {:?}", entry.path());
                    }
                }
                Err(source) => {
                    error!("Could not read output directory: {source}");
                }
            }
        } else {
            error!(
                ?output_dir_absolute,
                "Output directory does not exist (it should!)"
            );
        }
        return Err(stub
            .kind(EifBuildErrorKind::EifMissing { path: built_eif })
            .build());
    }

    let parent_dir = output_path.parent().expect("valid parent directory");
    if let Err(source) = fs::create_dir_all(parent_dir).await {
        return Err(stub
            .kind(EifBuildErrorKind::OutputDirectoryCreate {
                path: parent_dir.into(),
            })
            .source(source)
            .build());
    }
    if let Err(source) = fs::copy(&built_eif, &output_path).await {
        return Err(stub
            .kind(EifBuildErrorKind::EifCopy {
                source: built_eif,
                dest: output_path,
            })
            .source(source)
            .build());
    }

    let built_pcrs = output_dir_absolute.join("enclave.pcrs");
    let pcrs_path = output_path.with_extension("pcrs");
    if built_pcrs.exists() {
        if let Err(source) = fs::copy(&built_pcrs, &pcrs_path).await {
            return Err(stub
                .kind(EifBuildErrorKind::EifCopy {
                    source: built_pcrs,
                    dest: pcrs_path,
                })
                .source(source)
                .build());
        }
    }

    let file_data = match fs::read(&output_path).await {
        Ok(o) => o,
        Err(source) => {
            return Err(stub
                .kind(EifBuildErrorKind::EifRead {
                    source: output_path,
                })
                .source(source)
                .build());
        }
    };

    let mut hasher = Sha256::new();
    hasher.update(&file_data);
    let hash_result = hasher.finalize();
    let sha256 = hex::encode(hash_result);

    info!(
        ?output_path,
        len = file_data.len(),
        ?sha256,
        "EIF built successfully"
    );

    tracing::info!(
        ?stage_dir,
        "Staging directory preserved (inspect Containerfile.eif to see exact build process)",
    );

    Ok(EifFile {
        path: output_path,
        size: file_data.len(),
        sha256,
    })
}

#[derive(Debug)]
pub enum PathSpec {
    None,
    Single {
        path: PathBuf,
    },
    Dual {
        source: PathBuf,
        dest: PathBuf,
    },
    Triple {
        source: PathBuf,
        dest: PathBuf,
        target: PathBuf,
    },
}

#[derive(Debug)]
pub enum RecursiveDirectoryCopyErrorKind {
    DirectoryCreate,
    DirectoryRead,
    FileCopy,
    PrefixStrip,
    LinkRead,
    LinkCreate,
}

#[derive(Debug, thiserror::Error)]
#[error("could not recursively copy: {kind:?}({path_spec:?})")]
pub struct RecursiveDirectoryCopyError {
    kind: RecursiveDirectoryCopyErrorKind,
    path_spec: PathSpec,

    #[source]
    source: Box<dyn std::error::Error + Send + Sync>,
}

async fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), RecursiveDirectoryCopyError> {
    use walkdir::WalkDir;

    if let Err(source) = fs::create_dir_all(dst).await {
        return Err(RecursiveDirectoryCopyError {
            kind: RecursiveDirectoryCopyErrorKind::DirectoryCreate,
            path_spec: PathSpec::Single { path: dst.into() },
            source: source.into(),
        });
    }

    for entry in WalkDir::new(src).follow_links(false) {
        let entry = entry.map_err(|source| RecursiveDirectoryCopyError {
            kind: RecursiveDirectoryCopyErrorKind::DirectoryRead,
            path_spec: PathSpec::None,
            source: source.into(),
        })?;
        let path = entry.path();
        let rel_path = path
            .strip_prefix(src)
            .map_err(|source| RecursiveDirectoryCopyError {
                kind: RecursiveDirectoryCopyErrorKind::PrefixStrip,
                path_spec: PathSpec::Single { path: src.into() },
                source: source.into(),
            })?;
        let dst_path = dst.join(rel_path);

        let file_type = entry.file_type();

        if file_type.is_dir() {
            fs::create_dir_all(&dst_path)
                .await
                .map_err(|source| RecursiveDirectoryCopyError {
                    kind: RecursiveDirectoryCopyErrorKind::DirectoryCreate,
                    path_spec: PathSpec::Single { path: dst_path },
                    source: source.into(),
                })?;
        } else if file_type.is_symlink() {
            if let Some(parent) = dst_path.parent() {
                fs::create_dir_all(parent)
                    .await
                    .map_err(|source| RecursiveDirectoryCopyError {
                        kind: RecursiveDirectoryCopyErrorKind::DirectoryCreate,
                        path_spec: PathSpec::Single {
                            path: dst_path.clone(),
                        },
                        source: source.into(),
                    })?;
            }
            let target =
                std::fs::read_link(path).map_err(|source| RecursiveDirectoryCopyError {
                    kind: RecursiveDirectoryCopyErrorKind::LinkRead,
                    path_spec: PathSpec::Single { path: path.into() },
                    source: source.into(),
                })?;
            // Explicitly ignoring if a file doesn't already exist.
            let _ = fs::remove_file(&dst_path).await;
            std::os::unix::fs::symlink(&target, &dst_path).map_err(|source| {
                RecursiveDirectoryCopyError {
                    kind: RecursiveDirectoryCopyErrorKind::LinkCreate,
                    path_spec: PathSpec::Triple {
                        source: path.into(),
                        dest: dst_path,
                        target: target.into(),
                    },
                    source: source.into(),
                }
            })?;
        } else {
            if let Some(parent) = dst_path.parent() {
                fs::create_dir_all(parent)
                    .await
                    .map_err(|source| RecursiveDirectoryCopyError {
                        kind: RecursiveDirectoryCopyErrorKind::DirectoryCreate,
                        path_spec: PathSpec::Single {
                            path: parent.into(),
                        },
                        source: source.into(),
                    })?;
            }

            fs::copy(path, &dst_path)
                .await
                .map_err(|source| RecursiveDirectoryCopyError {
                    kind: RecursiveDirectoryCopyErrorKind::FileCopy,
                    path_spec: PathSpec::Dual {
                        source: path.into(),
                        dest: dst_path,
                    },
                    source: source.into(),
                })?;
        }
    }

    Ok(())
}
