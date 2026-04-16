// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::process::Command;

use crate::manifest::EnclaveManifest;
use crate::EifFile;

const DEFAULT_ENCLAVEOS_COMMIT: &str = "9582e25239430070667fdd0a6b64d887f1c308df";
const DEFAULT_BOOTPROOF_COMMIT: &str = "64dae0628e58b9f898b89f9b7a404b37e2f0ca9f";
const DEFAULT_STEVE_COMMIT: &str = "ed38a190cd5d7a8f452c854e41d00ec748e172bf";
const DEFAULT_LOCKSMITH_COMMIT: &str = "d16b74c6b3fd1d1006a5b00e4d9e21a4613947a9";

pub fn resolve_enclaveos_commit() -> String {
    std::env::var("ENCLAVEOS_COMMIT").unwrap_or_else(|_| DEFAULT_ENCLAVEOS_COMMIT.to_string())
}

/// Resolve the templates directory at runtime.
///
/// Priority:
/// 1. CAUTION_TEMPLATES_DIR env var (explicit override)
/// 2. /app/templates (Docker container path)
/// 3. CARGO_MANIFEST_DIR/templates (local dev fallback)
fn resolve_templates_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("CAUTION_TEMPLATES_DIR") {
        let p = PathBuf::from(&dir);
        anyhow::ensure!(p.exists(), "CAUTION_TEMPLATES_DIR={} does not exist", dir);
        return Ok(p);
    }

    let docker_path = PathBuf::from("/app/templates");
    if docker_path.exists() {
        return Ok(docker_path);
    }

    let dev_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("templates");
    anyhow::ensure!(
        dev_path.exists(),
        "Templates directory not found. Checked CAUTION_TEMPLATES_DIR, /app/templates, and {}",
        dev_path.display()
    );
    Ok(dev_path)
}

pub async fn stage_eif_components(
    user_fs_path: &Path,
    enclave_source_path: &Path,
    work_dir: &Path,
    run_command: Option<String>,
    manifest: Option<EnclaveManifest>,
    ports: &[u16],
    e2e: bool,
    locksmith: bool,
    templates_dir: Option<&Path>,
) -> Result<PathBuf> {
    let stage_dir = work_dir.join("eif-stage");
    fs::create_dir_all(&stage_dir).await?;

    tracing::info!("Staging EIF components in: {}", stage_dir.display());

    let app_dir = stage_dir.join("app");
    let enclave_dir = stage_dir.join("enclave");
    let output_dir = stage_dir.join("output");

    fs::create_dir_all(&app_dir).await?;
    fs::create_dir_all(&enclave_dir).await?;
    fs::create_dir_all(&output_dir).await?;

    tracing::info!("Staging user application from: {}", user_fs_path.display());
    copy_dir_recursive(user_fs_path, &app_dir).await?;

    tracing::info!(
        "Staging enclave source from: {}",
        enclave_source_path.display()
    );
    copy_dir_recursive(enclave_source_path, &enclave_dir).await?;

    let enclaveos_commit = manifest
        .as_ref()
        .and_then(|m| m.enclaveos_commit.clone())
        .unwrap_or_else(resolve_enclaveos_commit);
    let bootproof_commit = manifest
        .as_ref()
        .and_then(|m| m.bootproof_commit.clone())
        .unwrap_or_else(|| {
            std::env::var("BOOTPROOF_COMMIT")
                .unwrap_or_else(|_| DEFAULT_BOOTPROOF_COMMIT.to_string())
        });
    let steve_commit = manifest
        .as_ref()
        .and_then(|m| m.steve_commit.clone())
        .unwrap_or_else(|| {
            std::env::var("STEVE_COMMIT").unwrap_or_else(|_| DEFAULT_STEVE_COMMIT.to_string())
        });
    let locksmith_commit = manifest
        .as_ref()
        .and_then(|m| m.locksmith_commit.clone())
        .unwrap_or_else(|| {
            std::env::var("LOCKSMITH_COMMIT")
                .unwrap_or_else(|_| DEFAULT_LOCKSMITH_COMMIT.to_string())
        });

    if let Some(mut manifest) = manifest {
        manifest
            .enclaveos_commit
            .get_or_insert(enclaveos_commit.clone());
        manifest
            .bootproof_commit
            .get_or_insert(bootproof_commit.clone());
        if e2e {
            manifest.steve_commit.get_or_insert(steve_commit.clone());
        }
        if locksmith {
            manifest
                .locksmith_commit
                .get_or_insert(locksmith_commit.clone());
        }
        let manifest_path = stage_dir.join("manifest.json");
        manifest
            .write_to_file(&manifest_path)
            .await
            .context("Failed to write manifest.json")?;
        tracing::info!("Wrote manifest to: {}", manifest_path.display());
    }

    // Read and render templates
    let templates_dir = match templates_dir {
        Some(dir) => dir.to_path_buf(),
        None => resolve_templates_dir()?,
    };

    let run_sh_template = templates_dir.join("run.sh.template");
    anyhow::ensure!(
        run_sh_template.exists(),
        "run.sh.template not found at {}",
        run_sh_template.display()
    );

    let containerfile_template = templates_dir.join("Containerfile.eif");
    anyhow::ensure!(
        containerfile_template.exists(),
        "Containerfile.eif template not found at {}",
        containerfile_template.display()
    );

    let run_sh_content =
        render_run_sh_template(&run_sh_template, run_command, ports, e2e, locksmith).await?;
    let containerfile_content = render_containerfile_template(
        &containerfile_template,
        e2e,
        locksmith,
        &bootproof_commit,
        &steve_commit,
        &locksmith_commit,
    )
    .await?;

    let run_sh_path = stage_dir.join("run.sh");
    fs::write(&run_sh_path, &run_sh_content).await?;
    tracing::info!("Generated run.sh at: {}", run_sh_path.display());

    let containerfile_path = stage_dir.join("Containerfile.eif");
    fs::write(&containerfile_path, &containerfile_content).await?;
    tracing::info!(
        "Generated Containerfile.eif at: {}",
        containerfile_path.display()
    );

    tracing::info!(
        "EIF components staged successfully in: {}",
        stage_dir.display()
    );
    Ok(stage_dir)
}

fn process_template_blocks(content: &str, enabled_blocks: &[&str]) -> String {
    let mut result = Vec::new();
    let mut skip = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(block_name) = trimmed.strip_prefix("# {") {
            let block_name = block_name.trim();
            if !enabled_blocks.contains(&block_name) {
                skip = true;
            }
            continue;
        }
        if trimmed.starts_with("# }") {
            skip = false;
            continue;
        }
        if !skip {
            result.push(line);
        }
    }

    let mut output = result.join("\n");
    if content.ends_with('\n') {
        output.push('\n');
    }
    output
}

async fn render_run_sh_template(
    template_path: &Path,
    run_command: Option<String>,
    ports: &[u16],
    e2e: bool,
    locksmith: bool,
) -> Result<String> {
    let template = fs::read_to_string(template_path)
        .await
        .context("Failed to read run.sh template")?;

    let mut enabled_blocks: Vec<&str> = vec![];
    if e2e {
        enabled_blocks.push("STEVE");
    }
    if locksmith {
        enabled_blocks.push("LOCKSMITH");
    }
    let processed = process_template_blocks(&template, &enabled_blocks);

    let user_cmd = if let Some(cmd) = run_command {
        let escaped_cmd = cmd.replace("'", "'\\''");
        format!("exec sh -c '{}'", escaped_cmd)
    } else {
        "echo \"ERROR: No run command specified in Procfile\"\nexit 1".to_string()
    };

    let reserved: &[(u16, &str)] = &[
        (8080, "internal enclave services"),
        (8081, "internal enclave services"),
        (8082, "bootproofd"),
        (8084, "locksmith"),
    ];
    for &(port, service) in reserved {
        if ports.contains(&port) {
            anyhow::bail!("Port {} is reserved for {}", port, service);
        }
    }

    let custom_port_proxies: String = ports
        .iter()
        .filter(|&&port| port != 8080 && port != 8081 && port != 8082 && port != 8084)
        .map(|port| {
            format!(
                "/bin/socat VSOCK-LISTEN:{},reuseaddr,fork TCP:localhost:{} &",
                port, port
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let custom_port_section = if custom_port_proxies.is_empty() {
        String::new()
    } else {
        format!(
            "\necho \"Starting custom port proxies...\"\n{}\n",
            custom_port_proxies
        )
    };

    let result = processed
        .replace("{{USER_CMD}}", &user_cmd)
        .replace("{{CUSTOM_PORT_SECTION}}", &custom_port_section);

    Ok(result)
}

async fn render_containerfile_template(
    template_path: &Path,
    e2e: bool,
    locksmith: bool,
    bootproof_commit: &str,
    steve_commit: &str,
    locksmith_commit: &str,
) -> Result<String> {
    let template = fs::read_to_string(template_path)
        .await
        .context("Failed to read Containerfile.eif template")?;

    let mut enabled_blocks: Vec<&str> = vec![];
    if e2e {
        enabled_blocks.push("STEVE");
    }
    if locksmith {
        enabled_blocks.push("LOCKSMITH");
    }
    let processed = process_template_blocks(&template, &enabled_blocks);

    Ok(processed
        .replace("{{BOOTPROOF_COMMIT}}", bootproof_commit)
        .replace("{{STEVE_COMMIT}}", steve_commit)
        .replace("{{LOCKSMITH_COMMIT}}", locksmith_commit))
}

pub async fn build_eif_from_filesystems(
    user_fs_path: &Path,
    _bootproofd_path: &Path,
    _init_path: &Path,
    enclave_source_path: &Path,
    output_path: PathBuf,
    work_dir: &Path,
    run_command: Option<String>,
    manifest: Option<EnclaveManifest>,
    ports: &[u16],
    no_cache: bool,
    e2e: bool,
    locksmith: bool,
    templates_dir: Option<&Path>,
) -> Result<EifFile> {
    tracing::info!("Building EIF using transparent Containerfile approach");

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).await?;
    }

    let stage_dir = stage_eif_components(
        user_fs_path,
        enclave_source_path,
        work_dir,
        run_command,
        manifest,
        ports,
        e2e,
        locksmith,
        templates_dir,
    )
    .await?;

    tracing::info!("Building EIF using Docker and Containerfile.eif");
    let output_dir = stage_dir.join("output");

    fs::create_dir_all(&output_dir).await?;

    let output_dir_absolute = std::fs::canonicalize(&output_dir)
        .context("Failed to get absolute path for output directory")?;

    tracing::info!(
        "Output directory (absolute): {}",
        output_dir_absolute.display()
    );
    eprintln!("Output directory: {}", output_dir_absolute.display());

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
        tracing::info!("EIF build: no_cache=true, adding --no-cache flag");
    }
    docker_args.push(".".to_string());

    let output = Command::new("docker")
        .args(&docker_args)
        .env("DOCKER_BUILDKIT", "1")
        .env("SOURCE_DATE_EPOCH", "1")
        .current_dir(&stage_dir)
        .output()
        .await
        .context("Failed to execute docker build")?;

    let build_log_path = stage_dir.join("build.log");
    let mut log_content = String::new();
    log_content.push_str("=== STDOUT ===\n");
    log_content.push_str(&String::from_utf8_lossy(&output.stdout));
    log_content.push_str("\n=== STDERR ===\n");
    log_content.push_str(&String::from_utf8_lossy(&output.stderr));
    fs::write(&build_log_path, &log_content).await?;

    tracing::info!("Build log saved to: {}", build_log_path.display());
    eprintln!("Build log saved to: {}", build_log_path.display());

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        eprintln!("=== Docker Build Failed ===");
        eprintln!("STDOUT:\n{}", stdout);
        eprintln!("STDERR:\n{}", stderr);
        anyhow::bail!(
            "Docker build failed. See {} for full output",
            build_log_path.display()
        );
    }

    tracing::info!("Docker build completed successfully");
    eprintln!("Docker build completed successfully");

    let built_eif = output_dir_absolute.join("enclave.eif");
    if !built_eif.exists() {
        eprintln!("EIF file not found at: {}", built_eif.display());
        eprintln!("Checking output directory contents...");
        if output_dir_absolute.exists() {
            match std::fs::read_dir(&output_dir_absolute) {
                Ok(entries) => {
                    eprintln!("Files in output directory:");
                    for entry in entries.flatten() {
                        eprintln!("  - {}", entry.path().display());
                    }
                }
                Err(e) => {
                    eprintln!("Could not read output directory: {}", e);
                }
            }
        } else {
            eprintln!(
                "Output directory does not exist: {}",
                output_dir_absolute.display()
            );
        }
        anyhow::bail!(
            "EIF file was not created at: {}. Check build log: {}",
            built_eif.display(),
            build_log_path.display()
        );
    }

    fs::copy(&built_eif, &output_path).await.with_context(|| {
        format!(
            "Failed to copy EIF from {} to {}",
            built_eif.display(),
            output_path.display()
        )
    })?;

    let built_pcrs = output_dir_absolute.join("enclave.pcrs");
    let pcrs_path = output_path.with_extension("pcrs");
    if built_pcrs.exists() {
        fs::copy(&built_pcrs, &pcrs_path).await.with_context(|| {
            format!(
                "Failed to copy PCRs from {} to {}",
                built_pcrs.display(),
                pcrs_path.display()
            )
        })?;
    }

    let metadata = fs::metadata(&output_path)
        .await
        .context("Failed to read EIF metadata")?;

    let file_data = fs::read(&output_path)
        .await
        .context("Failed to read EIF for hashing")?;

    let mut hasher = Sha256::new();
    hasher.update(&file_data);
    let hash_result = hasher.finalize();
    let sha256 = hex::encode(hash_result);

    tracing::info!(
        "EIF built successfully: {} ({} bytes, SHA256: {})",
        output_path.display(),
        metadata.len(),
        sha256
    );
    tracing::info!(
        "Staging directory preserved at: {} (inspect Containerfile.eif to see exact build process)",
        stage_dir.display()
    );

    Ok(EifFile {
        path: output_path,
        size: metadata.len(),
        sha256,
    })
}

async fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    use walkdir::WalkDir;

    fs::create_dir_all(dst).await?;

    for entry in WalkDir::new(src).follow_links(false) {
        let entry = entry?;
        let path = entry.path();
        let rel_path = path.strip_prefix(src)?;
        let dst_path = dst.join(rel_path);

        let file_type = entry.file_type();

        if file_type.is_dir() {
            fs::create_dir_all(&dst_path).await?;
        } else if file_type.is_symlink() {
            if let Some(parent) = dst_path.parent() {
                fs::create_dir_all(parent).await?;
            }
            let target = std::fs::read_link(path)
                .with_context(|| format!("Failed to read symlink: {}", path.display()))?;
            let _ = fs::remove_file(&dst_path).await;
            std::os::unix::fs::symlink(&target, &dst_path).with_context(|| {
                format!(
                    "Failed to create symlink:\n  link: {}\n  target: {}",
                    dst_path.display(),
                    target.display()
                )
            })?;
        } else {
            if let Some(parent) = dst_path.parent() {
                fs::create_dir_all(parent).await?;
            }

            fs::copy(path, &dst_path).await.with_context(|| {
                format!(
                    "Failed to copy file:\n  src: {}\n  dst: {}",
                    path.display(),
                    dst_path.display()
                )
            })?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_template_blocks_enabled() {
        let content = "before\n# {STEVE\nsteve content\n# }STEVE\nafter\n";
        let result = process_template_blocks(content, &["STEVE"]);
        assert_eq!(result, "before\nsteve content\nafter\n");
    }

    #[test]
    fn test_process_template_blocks_disabled() {
        let content = "before\n# {STEVE\nsteve content\n# }STEVE\nafter\n";
        let result = process_template_blocks(content, &[]);
        assert_eq!(result, "before\nafter\n");
    }

    #[test]
    fn test_process_template_blocks_no_markers() {
        let content = "line1\nline2\nline3\n";
        let result = process_template_blocks(content, &["STEVE"]);
        assert_eq!(result, "line1\nline2\nline3\n");
    }

    #[test]
    fn test_process_template_blocks_multiple_blocks() {
        let content = "start\n# {A\na content\n# }A\nmiddle\n# {B\nb content\n# }B\nend\n";
        let result = process_template_blocks(content, &["A"]);
        assert_eq!(result, "start\na content\nmiddle\nend\n");
    }

    #[test]
    fn test_process_template_blocks_preserves_blank_lines() {
        let content = "before\n\n# {STEVE\ncontent\n# }STEVE\nafter\n";
        let result = process_template_blocks(content, &[]);
        assert_eq!(result, "before\n\nafter\n");
    }

    #[test]
    fn test_process_template_blocks_multiline_enabled() {
        let content = "header\n\n# {STEVE\nline1\nline2\nline3\n# }STEVE\nfooter\n";
        let result = process_template_blocks(content, &["STEVE"]);
        assert_eq!(result, "header\n\nline1\nline2\nline3\nfooter\n");
    }

    #[test]
    fn test_process_template_blocks_all_enabled() {
        let content = "start\n# {A\na\n# }A\n# {B\nb\n# }B\nend\n";
        let result = process_template_blocks(content, &["A", "B"]);
        assert_eq!(result, "start\na\nb\nend\n");
    }

    #[test]
    fn test_process_template_blocks_locksmith_enabled() {
        let content = "before\n# {LOCKSMITH\nlocksmith content\n# }LOCKSMITH\nafter\n";
        let result = process_template_blocks(content, &["LOCKSMITH"]);
        assert_eq!(result, "before\nlocksmith content\nafter\n");
    }

    #[test]
    fn test_process_template_blocks_locksmith_disabled() {
        let content = "before\n# {LOCKSMITH\nlocksmith content\n# }LOCKSMITH\nafter\n";
        let result = process_template_blocks(content, &[]);
        assert_eq!(result, "before\nafter\n");
    }

    #[test]
    fn test_process_template_blocks_steve_and_locksmith() {
        let content =
            "start\n# {STEVE\nsteve\n# }STEVE\nmid\n# {LOCKSMITH\nlocksmith\n# }LOCKSMITH\nend\n";

        // Both enabled
        let result = process_template_blocks(content, &["STEVE", "LOCKSMITH"]);
        assert_eq!(result, "start\nsteve\nmid\nlocksmith\nend\n");

        // Only STEVE
        let result = process_template_blocks(content, &["STEVE"]);
        assert_eq!(result, "start\nsteve\nmid\nend\n");

        // Only LOCKSMITH
        let result = process_template_blocks(content, &["LOCKSMITH"]);
        assert_eq!(result, "start\nmid\nlocksmith\nend\n");

        // Neither
        let result = process_template_blocks(content, &[]);
        assert_eq!(result, "start\nmid\nend\n");
    }
}
