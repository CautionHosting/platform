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

// Kept in sync with the git clone URLs in templates/Containerfile.eif.
pub const ENCLAVEOS_REPO: &str = "https://git.distrust.co/public/enclaveos.git";
pub const BOOTPROOF_REPO: &str = "https://git.distrust.co/public/bootproof.git";
pub const STEVE_REPO: &str = "https://git.distrust.co/public/steve.git";
pub const LOCKSMITH_REPO: &str = "https://codeberg.org/caution/locksmith.git";

const RESERVED_INTERNAL_PORT_START: u16 = 49_500;
const RESERVED_INTERNAL_PORT_END: u16 = 49_600;

/// S3-backed BuildKit cache config for the EIF build. Strictly opt-in: when
/// absent, the build runs `docker build` with the embedded builder exactly as
/// before, so `caution verify` and local builds never need buildx or S3.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub s3_bucket: String,
    pub s3_region: String,
}

fn is_reserved_internal_port(port: u16) -> bool {
    (RESERVED_INTERNAL_PORT_START..=RESERVED_INTERNAL_PORT_END).contains(&port)
}

fn resolve_commit(var: &str, default: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.to_string())
}

pub fn resolve_enclaveos_commit() -> String {
    resolve_commit("ENCLAVEOS_COMMIT", DEFAULT_ENCLAVEOS_COMMIT)
}

pub fn resolve_bootproof_commit() -> String {
    resolve_commit("BOOTPROOF_COMMIT", DEFAULT_BOOTPROOF_COMMIT)
}

pub fn resolve_steve_commit() -> String {
    resolve_commit("STEVE_COMMIT", DEFAULT_STEVE_COMMIT)
}

pub fn resolve_locksmith_commit() -> String {
    resolve_commit("LOCKSMITH_COMMIT", DEFAULT_LOCKSMITH_COMMIT)
}

/// A build-input tool paired with the repo it's cloned from, so the commit and
/// its source URL can never be matched up wrong downstream.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ToolSource {
    pub commit: String,
    pub repo: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ToolCommits {
    pub enclaveos: ToolSource,
    pub bootproof: ToolSource,
    pub steve: ToolSource,
    pub locksmith: ToolSource,
}

pub fn resolve_tool_commits() -> ToolCommits {
    ToolCommits {
        enclaveos: ToolSource {
            commit: resolve_enclaveos_commit(),
            repo: ENCLAVEOS_REPO,
        },
        bootproof: ToolSource {
            commit: resolve_bootproof_commit(),
            repo: BOOTPROOF_REPO,
        },
        steve: ToolSource {
            commit: resolve_steve_commit(),
            repo: STEVE_REPO,
        },
        locksmith: ToolSource {
            commit: resolve_locksmith_commit(),
            repo: LOCKSMITH_REPO,
        },
    }
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
    http_port: Option<u16>,
    e2e: bool,
    locksmith: bool,
    e2e_cors_origins: Option<String>,
    egress: bool,
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
        .unwrap_or_else(resolve_bootproof_commit);
    let steve_commit = manifest
        .as_ref()
        .and_then(|m| m.steve_commit.clone())
        .unwrap_or_else(resolve_steve_commit);
    let locksmith_commit = manifest
        .as_ref()
        .and_then(|m| m.locksmith_commit.clone())
        .unwrap_or_else(resolve_locksmith_commit);

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
            manifest.locksmith = true;
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

    let run_sh_content = render_run_sh_template(
        &run_sh_template,
        run_command,
        ports,
        http_port,
        e2e,
        locksmith,
        e2e_cors_origins.as_deref(),
        egress,
    )
    .await?;
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
    http_port: Option<u16>,
    e2e: bool,
    locksmith: bool,
    e2e_cors_origins: Option<&str>,
    egress: bool,
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
    if egress {
        enabled_blocks.push("EGRESS");
    }
    let processed = process_template_blocks(&template, &enabled_blocks);

    let user_cmd = if let Some(cmd) = run_command {
        let escaped_cmd = cmd.replace("'", "'\\''");
        format!(
            "sh -c '{}'\nAPP_STATUS=$?\necho \"ERROR: user application exited with status ${{APP_STATUS}}\"\nexit \"${{APP_STATUS}}\"",
            escaped_cmd
        )
    } else {
        "echo \"ERROR: No run command specified in Procfile\"\nexit 1".to_string()
    };

    if let Some(port) = ports
        .iter()
        .copied()
        .find(|port| is_reserved_internal_port(*port))
    {
        anyhow::bail!(
            "Port {} is reserved for internal enclave services (reserved range: {}-{})",
            port,
            RESERVED_INTERNAL_PORT_START,
            RESERVED_INTERNAL_PORT_END
        );
    }

    let steve_app_port = if e2e {
        let port = match http_port {
            Some(port) => port,
            None if ports.len() == 1 => ports[0],
            None => anyhow::bail!(
                "e2e builds require http_port or exactly one app port so STEVE can reach the app"
            ),
        };

        if !ports.contains(&port) {
            anyhow::bail!("http_port {} must also be listed in ports", port);
        }

        port.to_string()
    } else {
        String::new()
    };

    let custom_port_proxies: String = ports
        .iter()
        .filter(|&&port| !is_reserved_internal_port(port))
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

    let cors_env = match e2e_cors_origins {
        Some(origins) => format!(
            "STEVE_CORS_ORIGINS='{}'",
            origins.replace('\'', "'\\''")
        ),
        None => String::new(),
    };

    let result = processed
        .replace("{{USER_CMD}}", &user_cmd)
        .replace("{{STEVE_APP_PORT}}", &steve_app_port)
        .replace("{{CUSTOM_PORT_SECTION}}", &custom_port_section)
        .replace("{{STEVE_CORS_ORIGINS_ENV}}", &cors_env);

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
    http_port: Option<u16>,
    no_cache: bool,
    e2e: bool,
    locksmith: bool,
    e2e_cors_origins: Option<String>,
    egress: bool,
    templates_dir: Option<&Path>,
    cache_config: Option<CacheConfig>,
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
        http_port,
        e2e,
        locksmith,
        e2e_cors_origins,
        egress,
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

    // Build docker args, conditionally adding --no-cache and S3 BuildKit cache flags
    let mut docker_args = Vec::new();
    if cache_config.is_some() {
        docker_args.push("buildx".to_string());
    }
    docker_args.push("build".to_string());
    if no_cache {
        docker_args.push("--no-cache".to_string());
        tracing::info!("EIF build: no_cache=true, adding --no-cache flag");
    }
    docker_args.push("--progress=plain".to_string());
    docker_args.push("--target".to_string());
    docker_args.push("output".to_string());
    docker_args.push("--output".to_string());
    docker_args.push(format!(
        "type=local,rewrite-timestamp=true,dest={}",
        output_dir_absolute.to_str().unwrap()
    ));
    if let Some(cache) = &cache_config {
        docker_args.push("--cache-to".to_string());
        docker_args.push(format!(
            "type=s3,region={},bucket={},prefix=buildcache/,mode=max,ignore-error=true",
            cache.s3_region, cache.s3_bucket
        ));
        if !no_cache {
            docker_args.push("--cache-from".to_string());
            docker_args.push(format!(
                "type=s3,region={},bucket={},prefix=buildcache/",
                cache.s3_region, cache.s3_bucket
            ));
        }
    }
    docker_args.push("-f".to_string());
    docker_args.push("Containerfile.eif".to_string());
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
    use std::io::Write;

    fn run_template_file() -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(
            file,
            "#!/bin/sh\n# {{STEVE\necho steve\nSTEVE_APP_UPSTREAM=\"http://127.0.0.1:{{{{STEVE_APP_PORT}}}}\"\n# }}STEVE\n{{{{CUSTOM_PORT_SECTION}}}}\n{{{{USER_CMD}}}}\n"
        )
        .unwrap();
        file
    }

    #[test]
    fn test_tool_commit_resolution() {
        // Env-var mutations are process-global; serialize on the crate-wide lock
        // so parallel tests in this binary don't see each other's temp values.
        let _guard = crate::TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for var in [
            "ENCLAVEOS_COMMIT",
            "BOOTPROOF_COMMIT",
            "STEVE_COMMIT",
            "LOCKSMITH_COMMIT",
        ] {
            std::env::remove_var(var);
        }

        // No env override -> pinned defaults, surfaced via the shared bundle.
        let defaults = resolve_tool_commits();
        assert_eq!(defaults.enclaveos.commit, DEFAULT_ENCLAVEOS_COMMIT);
        assert_eq!(defaults.bootproof.commit, DEFAULT_BOOTPROOF_COMMIT);
        assert_eq!(defaults.steve.commit, DEFAULT_STEVE_COMMIT);
        assert_eq!(defaults.locksmith.commit, DEFAULT_LOCKSMITH_COMMIT);
        // Repo URLs are paired with their commit at the source.
        assert_eq!(defaults.enclaveos.repo, ENCLAVEOS_REPO);
        assert_eq!(defaults.locksmith.repo, LOCKSMITH_REPO);

        // Env override wins (this is how the platform pins prod commits).
        std::env::set_var("BOOTPROOF_COMMIT", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        assert_eq!(
            resolve_bootproof_commit(),
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        );
        assert_eq!(
            resolve_tool_commits().bootproof.commit,
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        );
        std::env::remove_var("BOOTPROOF_COMMIT");
        assert_eq!(resolve_bootproof_commit(), DEFAULT_BOOTPROOF_COMMIT);
    }

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

    #[tokio::test]
    async fn test_render_run_sh_uses_reserved_locksmith_port() {
        let template = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("templates/run.sh.template");
        let rendered =
            render_run_sh_template(&template, Some("/app".to_string()), &[], None, false, true, None, false)
                .await
                .unwrap();

        assert!(rendered.contains("INTERNAL_LOCKSMITH_PORT=49504"));
        assert!(rendered.contains(
            "VSOCK-LISTEN:${INTERNAL_LOCKSMITH_PORT},reuseaddr,fork TCP:localhost:${INTERNAL_LOCKSMITH_PORT}"
        ));
    }

    #[tokio::test]
    async fn test_render_run_sh_uses_explicit_http_port_for_steve_upstream() {
        let template = run_template_file();
        let result = render_run_sh_template(
            template.path(),
            Some("/app/server".to_string()),
            &[3000, 9000],
            Some(3000),
            true,
            false,
            None,
            true,
        )
        .await
        .unwrap();

        assert!(result.contains("STEVE_APP_UPSTREAM=\"http://127.0.0.1:3000\""));
    }

    #[tokio::test]
    async fn test_render_run_sh_defaults_single_port_for_steve_upstream() {
        let template = run_template_file();
        let result = render_run_sh_template(
            template.path(),
            Some("/app/server".to_string()),
            &[8080],
            None,
            true,
            false,
            None,
            true,
        )
        .await
        .unwrap();

        assert!(result.contains("STEVE_APP_UPSTREAM=\"http://127.0.0.1:8080\""));
    }

    #[tokio::test]
    async fn test_render_run_sh_requires_http_port_for_multi_port_e2e() {
        let template = run_template_file();
        let err = render_run_sh_template(
            template.path(),
            Some("/app/server".to_string()),
            &[3000, 9000],
            None,
            true,
            false,
            None,
            true,
        )
        .await
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("e2e builds require http_port or exactly one app port"));
    }

    #[tokio::test]
    async fn test_render_run_sh_egress_enabled_includes_tunnel() {
        let template = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("templates/run.sh.template");
        let rendered = render_run_sh_template(
            &template, Some("/app".to_string()), &[], None, false, false, None, true,
        )
        .await
        .unwrap();
        assert!(rendered.contains("VSOCK-CONNECT:3:3"));
        assert!(rendered.contains("nameserver 10.0.100.1"));
    }

    #[tokio::test]
    async fn test_render_run_sh_egress_disabled_is_hermetic() {
        let template = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("templates/run.sh.template");
        let rendered = render_run_sh_template(
            &template, Some("/app".to_string()), &[], None, false, false, None, false,
        )
        .await
        .unwrap();
        assert!(!rendered.contains("VSOCK-CONNECT:3:3"));
        assert!(!rendered.contains("udhcpc"));
        assert!(rendered.contains("nameserver 127.0.0.1"));
    }
}
