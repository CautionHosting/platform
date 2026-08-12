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
const DEFAULT_STEVE_COMMIT: &str = "c0b8d2d62e66108689745561242972048f6cfce5";
const DEFAULT_LOCKSMITH_COMMIT: &str = "d16b74c6b3fd1d1006a5b00e4d9e21a4613947a9";

// Kept in sync with the git clone URLs in templates/Containerfile.eif.
pub const ENCLAVEOS_REPO: &str = "https://git.distrust.co/public/enclaveos.git";
pub const BOOTPROOF_REPO: &str = "https://git.distrust.co/public/bootproof.git";
pub const STEVE_REPO: &str = "https://git.distrust.co/public/steve.git";
pub const LOCKSMITH_REPO: &str = "https://codeberg.org/caution/locksmith.git";

/// STEVE's built-in default key exchange. Must match
/// `caution_config::KeyExchange::X25519.steve_env_value()`.
pub const DEFAULT_KEY_EXCHANGE: &str = "X25519";
const XWING_DRAFT10_KEY_EXCHANGE: &str = "XWING-DRAFT10";

pub fn validate_key_exchange(value: &str) -> Result<()> {
    anyhow::ensure!(
        matches!(value, DEFAULT_KEY_EXCHANGE | XWING_DRAFT10_KEY_EXCHANGE),
        "unsupported STEVE key exchange: {value}"
    );
    Ok(())
}

const RESERVED_INTERNAL_PORT_START: u16 = 49_500;
const RESERVED_INTERNAL_PORT_END: u16 = 49_600;

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
    e2e_mode: &str,
    e2e_key_exchange: &str,
    allow_plaintext_fallback: bool,
    domain: Option<&str>,
    http_upstream_protocol: &str,
    locksmith: bool,
    e2e_cors_origins: Option<String>,
    egress: bool,
    templates_dir: Option<&Path>,
) -> Result<PathBuf> {
    validate_key_exchange(e2e_key_exchange)?;

    let stage_dir = work_dir.join("eif-stage");
    fs::create_dir_all(&stage_dir).await?;

    tracing::info!("Staging EIF components in: {}", stage_dir.display());

    let app_dir = stage_dir.join("app");
    let enclave_dir = stage_dir.join("enclave");
    let output_dir = stage_dir.join("output");

    fs::create_dir_all(&app_dir).await?;
    fs::create_dir_all(&enclave_dir).await?;
    fs::create_dir_all(&output_dir).await?;

    stage_user_application(user_fs_path, &stage_dir, &app_dir).await?;

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
            manifest.steve_allow_plaintext_fallback = allow_plaintext_fallback;
        }
        manifest.steve_key_exchange =
            (e2e && e2e_key_exchange != DEFAULT_KEY_EXCHANGE).then(|| e2e_key_exchange.to_string());
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

    let caddy_certfp_template = templates_dir.join("caddy-certfp.sh");
    if e2e_mode == "tls" {
        anyhow::ensure!(
            caddy_certfp_template.exists(),
            "caddy-certfp.sh not found at {}",
            caddy_certfp_template.display()
        );
    }

    let run_sh_content = render_run_sh_template(
        &run_sh_template,
        run_command,
        ports,
        http_port,
        e2e,
        e2e_mode,
        e2e_key_exchange,
        allow_plaintext_fallback,
        domain,
        http_upstream_protocol,
        locksmith,
        e2e_cors_origins.as_deref(),
        egress,
    )
    .await?;
    let containerfile_content = render_containerfile_template(
        &containerfile_template,
        e2e,
        e2e_mode == "tls",
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

    if e2e_mode == "tls" {
        fs::copy(&caddy_certfp_template, stage_dir.join("caddy-certfp.sh")).await?;
    }

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
    e2e_mode: &str,
    e2e_key_exchange: &str,
    allow_plaintext_fallback: bool,
    domain: Option<&str>,
    http_upstream_protocol: &str,
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
    if e2e_mode == "tls" {
        enabled_blocks.push("CADDY");
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

        Some(port)
    } else {
        None
    };

    let caddy_upstream = if e2e_mode == "tls" {
        if !egress {
            anyhow::bail!("tls mode requires egress for ACME certificate issuance");
        }
        let port =
            http_port.context("tls mode requires http_port so enclave Caddy can reach the app")?;
        if !ports.contains(&port) {
            anyhow::bail!("http_port {} must also be listed in ports", port);
        }
        match http_upstream_protocol {
            "http" | "" => format!("http://127.0.0.1:{port}"),
            "h2c" => format!("h2c://127.0.0.1:{port}"),
            other => anyhow::bail!("unsupported HTTP upstream protocol {other:?}"),
        }
    } else {
        String::new()
    };

    let caddy_domain = if e2e_mode == "tls" {
        domain
            .filter(|domain| !domain.is_empty())
            .context("tls mode requires a domain for trusted TLS")?
    } else {
        ""
    };

    let custom_port_proxies: String = ports
        .iter()
        .filter(|&&port| {
            !is_reserved_internal_port(port)
                && steve_app_port != Some(port)
                && !(e2e_mode == "tls" && http_port == Some(port))
        })
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

    // Only emit the variable for non-default key exchanges: STEVE defaults to
    // X25519, so omitting it keeps run.sh (and therefore the PCRs) byte-identical
    // to deployments made before key exchange was selectable.
    let key_exchange_env = if e2e_key_exchange == DEFAULT_KEY_EXCHANGE {
        String::new()
    } else {
        format!("STEVE_KEY_EXCHANGE={} ", e2e_key_exchange)
    };

    let cors_env = match e2e_cors_origins {
        Some(origins) => format!("STEVE_CORS_ORIGINS='{}'", origins.replace('\'', "'\\''")),
        None => String::new(),
    };

    let plaintext_fallback_env = if allow_plaintext_fallback {
        "STEVE_ALLOW_PLAINTEXT_FALLBACK=true "
    } else {
        ""
    };

    let result = processed
        .replace("{{USER_CMD}}", &user_cmd)
        .replace(
            "{{STEVE_APP_PORT}}",
            &steve_app_port
                .map(|port| port.to_string())
                .unwrap_or_default(),
        )
        .replace("{{CADDY_UPSTREAM}}", &caddy_upstream)
        .replace("{{STEVE_KEY_EXCHANGE_ENV}}", &key_exchange_env)
        .replace("{{STEVE_PLAINTEXT_FALLBACK_ENV}}", plaintext_fallback_env)
        .replace("{{CADDY_DOMAIN}}", caddy_domain)
        .replace("{{CUSTOM_PORT_SECTION}}", &custom_port_section)
        .replace("{{STEVE_CORS_ORIGINS_ENV}}", &cors_env);

    Ok(result)
}

async fn render_containerfile_template(
    template_path: &Path,
    e2e: bool,
    caddy: bool,
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
    if caddy {
        enabled_blocks.push("CADDY");
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
    e2e_mode: &str,
    e2e_key_exchange: &str,
    allow_plaintext_fallback: bool,
    domain: Option<&str>,
    http_upstream_protocol: &str,
    locksmith: bool,
    e2e_cors_origins: Option<String>,
    egress: bool,
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
        http_port,
        e2e,
        e2e_mode,
        e2e_key_exchange,
        allow_plaintext_fallback,
        domain,
        http_upstream_protocol,
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

    // When the application arrived as a payload tar, hand Docker a tar context
    // on stdin with the payload expanded into app/. That keeps the application
    // filesystem off the host, where a case-insensitive volume would silently
    // drop colliding entries (issue #401), while the Containerfile still sees
    // the same `app/` it always has.
    let payload = stage_dir.join(APP_PAYLOAD_TAR);
    let context_tar = if payload.exists() {
        let stage_for_ctx = stage_dir.clone();
        // Sits beside the stage dir so it is not swept into its own context.
        let ctx_path = work_dir.join("eif-context.tar");
        let ctx_for_task = ctx_path.clone();
        tokio::task::spawn_blocking(move || write_context_tar(&stage_for_ctx, &ctx_for_task))
            .await
            .context("Build context assembly panicked")??;
        docker_args.push("-".to_string());
        Some(ctx_path)
    } else {
        docker_args.push(".".to_string());
        None
    };

    let stdin = match &context_tar {
        Some(path) => {
            let file = std::fs::File::open(path).context("Failed to open build context tar")?;
            std::process::Stdio::from(file)
        }
        None => std::process::Stdio::null(),
    };

    let output = Command::new("docker")
        .args(&docker_args)
        .env("DOCKER_BUILDKIT", "1")
        .env("SOURCE_DATE_EPOCH", "1")
        .stdin(stdin)
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

/// Name of the application payload inside the stage directory. Its presence is
/// what tells the build to assemble a tar context instead of a directory one;
/// it is never sent to Docker under this name.
pub(crate) const APP_PAYLOAD_TAR: &str = "app.tar";

/// Place the user application into the EIF build context.
///
/// Returns `true` when the application was left as a tar payload for the build
/// to stream into the context, `false` when it was staged as a directory.
///
/// The full-image path hands us the raw `docker export` tar precisely so the
/// application filesystem never round-trips through the host. Unpacking it here
/// would drop entries whose names differ only by case on a case-insensitive
/// host (macOS APFS), silently changing PCR0/PCR1 for a byte-correct deployment
/// while PCR2 continues to match. See issue #401.
///
/// The narrower extract paths (specific files, static binary) still hand us a
/// directory. They select a handful of known names where a case collision
/// cannot arise, so they keep directory staging and the previous behaviour.
async fn stage_user_application(
    user_fs_path: &Path,
    stage_dir: &Path,
    app_dir: &Path,
) -> Result<bool> {
    let is_tar = user_fs_path.is_file()
        && user_fs_path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("tar"));

    if !is_tar {
        tracing::info!("Staging user application from: {}", user_fs_path.display());
        // The payload's presence is what selects the tar path later, so one left
        // by an earlier build in the same work dir would silently win over the
        // directory we are about to stage. Clear it before, not after.
        fs::remove_file(stage_dir.join(APP_PAYLOAD_TAR)).await.ok();
        copy_dir_recursive(user_fs_path, app_dir).await?;
        return Ok(false);
    }

    tracing::info!(
        "Staging user application tar (unpacked inside the builder) from: {}",
        user_fs_path.display()
    );

    // The caller pre-creates app/; leaving an empty one behind would have COPY
    // layer it over the unpacked tree, so drop it when the tar path is taken.
    fs::remove_dir_all(app_dir).await.ok();

    fs::copy(user_fs_path, stage_dir.join(APP_PAYLOAD_TAR))
        .await
        .context("Failed to stage user application tar")?;

    Ok(true)
}

/// Strip trailing slashes and `./` so a directory entry compares equal however
/// the producing tar wrote it. `docker export` emits `home/user/.cache/`, and
/// `PathBuf` treats that as distinct from the `home/user/.cache` you get by
/// asking a child for its parent.
fn normalized(path: &Path) -> PathBuf {
    path.components().collect()
}

/// Paths the *container runtime* injects, which are not part of the image and
/// must not reach the ramdisk.
///
/// Docker Desktop on Apple Silicon runs amd64 images under Rosetta and mounts
/// its translation cache into the container, so `docker export` captures an
/// empty `<home>/.cache/rosetta` even though nothing in the image put it there.
/// A Linux builder has no such directory, so leaving it in makes every macOS
/// reproduction differ from the deployment by exactly those entries - the same
/// class of false PCR0/PCR1 mismatch as issue #401, from a different cause.
///
/// The rule is self-gating rather than name-only, because dropping image
/// content would be a far worse bug than the one it fixes. All three must hold:
/// a *directory* named `rosetta`, whose parent directory is named `.cache`, and
/// whose subtree contains nothing but directories. That is the bare mount point
/// Docker Desktop leaves behind. An image genuinely shipping a `.cache/rosetta`
/// ships something *in* it, so it is untouched; and on a Linux builder nothing
/// matches at all, which makes this a no-op for production builds.
///
/// `docker diff` cannot be used to establish provenance here - it reports no
/// changes for these containers even though the export contains the directory.
///
/// `.dockerenv` is also runtime-injected but appears on Linux builders too, so
/// it is part of what deployed enclaves actually contain and removing it would
/// break reproduction of every existing deployment. Only artifacts that differ
/// *between* hosts belong here.
fn container_runtime_artifacts(
    entries: &std::collections::BTreeMap<PathBuf, tar::EntryType>,
) -> std::collections::BTreeSet<PathBuf> {
    use std::collections::BTreeSet;

    let mut drop: BTreeSet<PathBuf> = BTreeSet::new();
    let mut emptied_caches: BTreeSet<PathBuf> = BTreeSet::new();

    let under = |root: &Path| {
        let prefix = root.to_path_buf();
        entries
            .iter()
            .filter(move |(p, _)| p.as_path() != prefix.as_path() && p.starts_with(&prefix))
    };

    for (path, entry_type) in entries {
        if !entry_type.is_dir() || path.file_name().is_none_or(|n| n != "rosetta") {
            continue;
        }
        let Some(parent) = path.parent() else { continue };
        if parent.file_name().is_none_or(|n| n != ".cache") {
            continue;
        }
        // A populated `rosetta` is the image's own; only the empty mount point
        // Docker Desktop leaves behind is an artifact.
        if under(path).any(|(_, t)| !t.is_dir()) {
            continue;
        }

        drop.insert(path.clone());
        drop.extend(under(path).map(|(p, _)| p.clone()));
        emptied_caches.insert(parent.to_path_buf());
    }

    // A `.cache` that existed only to hold the Rosetta mount point is itself an
    // artifact. Only ones we just emptied qualify - a `.cache` the image ships
    // empty is image content and must survive.
    for cache in emptied_caches {
        if !under(&cache).any(|(p, _)| !drop.contains(p)) {
            drop.insert(cache);
        }
    }

    drop
}

/// Assemble the Docker build context as a tar, expanding the application
/// payload into `app/` entries on the way through.
///
/// This exists so the application filesystem reaches Docker without ever being
/// written to the host filesystem as individual files. A directory context
/// requires the CLI to materialise every entry locally first, and on a
/// case-insensitive host (macOS APFS) siblings differing only by case collide
/// and one silently disappears - changing the cpio and therefore PCR0/PCR1
/// while PCR2 still matches, which is what makes issue #401 so hard to read.
///
/// Crucially the Containerfile is untouched: it still sees `app/` exactly as
/// before, so an enclave built by any framework version reproduces bit-for-bit.
/// Fixing this in the Containerfile instead would only help enclaves built
/// *after* the fix shipped, because a reproduction uses the framework template
/// pinned in the deployment's own manifest.
///
/// Stage files are emitted before the payload so the archive opens with a
/// short, framework-controlled name. buildx decides whether stdin is a context
/// archive or a bare Dockerfile by running a tar reader over the first 1 KiB
/// only, and a GNU/PAX extension record at the front defeats that - the context
/// is then parsed as a Dockerfile and the build dies on `unknown instruction`.
fn write_context_tar(stage_dir: &Path, context_tar: &Path) -> Result<()> {
    use walkdir::WalkDir;

    let payload = stage_dir.join(APP_PAYLOAD_TAR);
    let out = std::fs::File::create(context_tar).context("Failed to create build context tar")?;
    let mut builder = tar::Builder::new(out);
    builder.follow_symlinks(false);

    for entry in WalkDir::new(stage_dir).min_depth(1).follow_links(false) {
        let entry = entry.context("Failed to walk stage directory")?;
        let path = entry.path();
        let rel = path.strip_prefix(stage_dir)?;

        // The payload is expanded below under app/; it must not also appear
        // verbatim, or the context carries a redundant 9 MB blob.
        if rel == Path::new(APP_PAYLOAD_TAR) {
            continue;
        }

        let file_type = entry.file_type();
        if file_type.is_dir() {
            builder.append_dir(rel, path)?;
        } else if file_type.is_symlink() {
            let target = std::fs::read_link(path)
                .with_context(|| format!("Failed to read symlink: {}", path.display()))?;
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            header.set_cksum();
            builder.append_link(&mut header, rel, &target)?;
        } else {
            let mut file = std::fs::File::open(path)
                .with_context(|| format!("Failed to open: {}", path.display()))?;
            builder.append_file(rel, &mut file)?;
        }
    }

    // First pass: which entries exist and what they are, so runtime artifacts
    // can be identified by their surroundings rather than by a hardcoded path.
    let mut all_entries = std::collections::BTreeMap::new();
    {
        let payload_file = std::fs::File::open(&payload)
            .context("Failed to open staged application payload")?;
        let mut archive = tar::Archive::new(payload_file);
        for entry in archive.entries().context("Failed to read application payload")? {
            let entry = entry.context("Failed to read application payload entry")?;
            let entry_type = entry.header().entry_type();
            all_entries.insert(normalized(&entry.path()?), entry_type);
        }
    }
    let skip = container_runtime_artifacts(&all_entries);
    if !skip.is_empty() {
        tracing::info!(
            "Excluding {} container-runtime artifact(s) from the ramdisk: {:?}",
            skip.len(),
            skip
        );
    }

    // Second pass: re-emit every payload entry under app/, header intact, so
    // file type, mode, and link targets survive exactly as `docker export`
    // recorded them.
    let payload_file =
        std::fs::File::open(&payload).context("Failed to open staged application payload")?;
    let mut archive = tar::Archive::new(payload_file);
    let mut count = 0usize;
    for entry in archive.entries().context("Failed to read application payload")? {
        let mut entry = entry.context("Failed to read application payload entry")?;
        let entry_path = entry.path()?.into_owned();
        if skip.contains(&normalized(&entry_path)) {
            continue;
        }
        let mut header = entry.header().clone();
        let entry_type = header.entry_type();

        // Docker's `COPY` assigns uid/gid 0 unless told otherwise, so the
        // directory-context path this replaces produced a root-owned ramdisk
        // regardless of what the image recorded. Preserving the image's real
        // ownership here would be *more* faithful but would change PCR0/PCR1
        // for every existing deployment - e.g. an image with a `/home/user`
        // owned by 1000:1000 reproduces as 0:0 in every enclave deployed to
        // date. Match the established behaviour rather than the tar.
        header.set_uid(0);
        header.set_gid(0);
        header.set_username("")?;
        header.set_groupname("")?;

        let staged_path = Path::new("app").join(&entry_path);

        if entry_type.is_hard_link() || entry_type.is_symlink() {
            // Read the target through the entry rather than the cloned header:
            // a PAX or GNU long link target lives in a preceding extension
            // record, so the header alone carries a truncated name or none.
            let target = entry
                .link_name()
                .with_context(|| format!("Failed to read link target: {}", entry_path.display()))?
                .with_context(|| format!("Link entry has no target: {}", entry_path.display()))?
                .into_owned();

            // A hard link names another entry *within this archive*, so
            // re-rooting the entry under app/ without re-rooting its target
            // leaves it pointing at a path the context no longer contains and
            // BuildKit fails the build. A symlink is resolved inside the
            // container against what becomes the ramdisk root, so its target
            // must be left exactly as the image recorded it.
            let staged_target = if entry_type.is_hard_link() {
                Path::new("app").join(&target)
            } else {
                target
            };

            builder
                .append_link(&mut header, &staged_path, &staged_target)
                .with_context(|| {
                    format!("Failed to stage application link: {}", entry_path.display())
                })?;
        } else {
            builder
                .append_data(&mut header, &staged_path, &mut entry)
                .with_context(|| {
                    format!("Failed to stage application entry: {}", entry_path.display())
                })?;
        }
        count += 1;
    }

    builder.finish().context("Failed to finalise build context tar")?;
    tracing::info!("Build context assembled with {} application entries", count);
    Ok(())
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

    fn test_manifest() -> EnclaveManifest {
        EnclaveManifest::new(
            None,
            crate::manifest::EnclaveSource::Local {
                path: ".".to_string(),
            },
            crate::manifest::FrameworkSource::GitArchive {
                url: "https://example.com/platform/archive/main.tar.gz".to_string(),
                commit: None,
            },
            None,
            Some("/app/server".to_string()),
            None,
        )
    }

    async fn stage_test_manifest(key_exchange: &str) -> Result<EnclaveManifest> {
        let work_dir = tempfile::tempdir()?;
        let user_dir = work_dir.path().join("user");
        let enclave_dir = work_dir.path().join("enclave");
        fs::create_dir_all(&user_dir).await?;
        fs::create_dir_all(&enclave_dir).await?;

        let stage_dir = stage_eif_components(
            &user_dir,
            &enclave_dir,
            work_dir.path(),
            Some("/app/server".to_string()),
            Some(test_manifest()),
            &[8080],
            Some(8080),
            true,
            "steve",
            key_exchange,
            false,
            None,
            "http",
            false,
            None,
            false,
            None,
        )
        .await?;

        EnclaveManifest::read_from_file(&stage_dir.join("manifest.json")).await
    }

    fn run_template_file() -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(
            file,
            "#!/bin/sh\n# {{STEVE\necho steve\nSTEVE_APP_UPSTREAM=\"http://127.0.0.1:{{{{STEVE_APP_PORT}}}}\" {{{{STEVE_KEY_EXCHANGE_ENV}}}}{{{{STEVE_PLAINTEXT_FALLBACK_ENV}}}}/steve\n# }}STEVE\n{{{{CUSTOM_PORT_SECTION}}}}\n{{{{USER_CMD}}}}\n"
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

    #[tokio::test]
    async fn test_stage_manifest_records_non_default_key_exchange() {
        let manifest = stage_test_manifest(XWING_DRAFT10_KEY_EXCHANGE)
            .await
            .unwrap();

        assert_eq!(
            manifest.steve_key_exchange.as_deref(),
            Some(XWING_DRAFT10_KEY_EXCHANGE)
        );
    }

    #[tokio::test]
    async fn test_stage_manifest_omits_default_key_exchange() {
        let manifest = stage_test_manifest(DEFAULT_KEY_EXCHANGE).await.unwrap();

        assert!(manifest.steve_key_exchange.is_none());
    }

    #[tokio::test]
    async fn test_stage_rejects_invalid_key_exchange_before_generating_run_script() {
        let work_dir = tempfile::tempdir().unwrap();
        let user_dir = work_dir.path().join("user");
        let enclave_dir = work_dir.path().join("enclave");
        fs::create_dir_all(&user_dir).await.unwrap();
        fs::create_dir_all(&enclave_dir).await.unwrap();

        let err = stage_eif_components(
            &user_dir,
            &enclave_dir,
            work_dir.path(),
            Some("/app/server".to_string()),
            Some(test_manifest()),
            &[8080],
            Some(8080),
            true,
            "steve",
            "XWING-DRAFT10; touch /tmp/injected",
            false,
            None,
            "http",
            false,
            None,
            false,
            None,
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("unsupported STEVE key exchange"));
        assert!(!work_dir.path().join("eif-stage/run.sh").exists());
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
        let rendered = render_run_sh_template(
            &template,
            Some("/app".to_string()),
            &[],
            None,
            false,
            "disabled",
            "X25519",
            false,
            None,
            "http",
            true,
            None,
            false,
        )
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
            "steve",
            "XWING-DRAFT10",
            false,
            None,
            "http",
            false,
            None,
            true,
        )
        .await
        .unwrap();

        assert!(result.contains("STEVE_APP_UPSTREAM=\"http://127.0.0.1:3000\""));
        assert!(result.contains("STEVE_KEY_EXCHANGE=XWING-DRAFT10"));
        assert!(!result.contains("VSOCK-LISTEN:3000"));
        assert!(result.contains("VSOCK-LISTEN:9000"));
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
            "steve",
            "X25519",
            false,
            None,
            "http",
            false,
            None,
            true,
        )
        .await
        .unwrap();

        assert!(result.contains("STEVE_APP_UPSTREAM=\"http://127.0.0.1:8080\""));
        // The default key exchange is left implicit so run.sh stays byte-identical
        // to pre-key-exchange deployments (and their PCRs).
        assert!(!result.contains("STEVE_KEY_EXCHANGE"));
        assert!(!result.contains("STEVE_ALLOW_PLAINTEXT_FALLBACK"));
        assert!(!result.contains("VSOCK-LISTEN:8080"));
    }

    #[tokio::test]
    async fn test_render_run_sh_emits_explicit_plaintext_fallback() {
        let template = run_template_file();
        let result = render_run_sh_template(
            template.path(),
            Some("/app/server".to_string()),
            &[8080],
            Some(8080),
            true,
            "steve",
            "X25519",
            true,
            None,
            "http",
            false,
            None,
            false,
        )
        .await
        .unwrap();

        assert!(result.contains("STEVE_ALLOW_PLAINTEXT_FALLBACK=true /steve"));
        assert!(!result.contains("VSOCK-LISTEN:8080"));
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
            "steve",
            "X25519",
            false,
            None,
            "http",
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
    async fn test_render_run_sh_tls_mode_terminates_tls_in_enclave() {
        let template = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("templates/run.sh.template");
        let rendered = render_run_sh_template(
            &template,
            Some("/app/server".to_string()),
            &[8080, 9000],
            Some(8080),
            false,
            "tls",
            "X25519",
            false,
            Some("app.example.com"),
            "h2c",
            false,
            None,
            true,
        )
        .await
        .unwrap();

        assert!(rendered.contains("Starting enclave Caddy TLS ingress"));
        assert!(rendered.contains("app.example.com {"));
        assert!(rendered.contains("reverse_proxy h2c://127.0.0.1:8080"));
        assert!(rendered.contains(
            "HOME=/var/lib/caddy \\\nXDG_CONFIG_HOME=/etc \\\nXDG_DATA_HOME=/var/lib \\\n/caddy run --config /etc/caddy/Caddyfile &"
        ));
        assert!(rendered.contains("CADDY_DOMAIN=\"app.example.com\" /caddy-certfp.sh &"));
        assert!(rendered.contains("VSOCK-LISTEN:443,reuseaddr,fork TCP:127.0.0.1:443"));
        assert!(rendered.contains("VSOCK-LISTEN:9000,reuseaddr,fork TCP:localhost:9000"));
        assert!(!rendered.contains("VSOCK-LISTEN:8080"));
        assert!(!rendered.contains("on_demand"));
        assert!(!rendered.contains("Starting STEVE"));
    }

    #[tokio::test]
    async fn test_render_run_sh_tls_mode_requires_http_port() {
        let template = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("templates/run.sh.template");
        let err = render_run_sh_template(
            &template,
            Some("/app/server".to_string()),
            &[8080],
            None,
            false,
            "tls",
            "X25519",
            false,
            Some("app.example.com"),
            "http",
            false,
            None,
            true,
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("tls mode requires http_port"));
    }

    #[tokio::test]
    async fn test_render_run_sh_tls_mode_requires_domain_and_egress() {
        let template = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("templates/run.sh.template");

        let missing_domain = render_run_sh_template(
            &template,
            Some("/app/server".to_string()),
            &[8080],
            Some(8080),
            false,
            "tls",
            "X25519",
            false,
            None,
            "http",
            false,
            None,
            true,
        )
        .await
        .unwrap_err();
        assert!(missing_domain
            .to_string()
            .contains("tls mode requires a domain"));

        let missing_egress = render_run_sh_template(
            &template,
            Some("/app/server".to_string()),
            &[8080],
            Some(8080),
            false,
            "tls",
            "X25519",
            false,
            Some("app.example.com"),
            "http",
            false,
            None,
            false,
        )
        .await
        .unwrap_err();
        assert!(missing_egress
            .to_string()
            .contains("tls mode requires egress"));
    }

    #[tokio::test]
    async fn test_render_containerfile_caddy_runtime_smoke() {
        let template =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("templates/Containerfile.eif");
        let rendered = render_containerfile_template(
            &template,
            false,
            true,
            false,
            "bootproof-commit",
            "steve-commit",
            "locksmith-commit",
        )
        .await
        .unwrap();

        assert!(rendered.contains("COPY caddy-certfp.sh /build/caddy-certfp.sh"));
        assert!(rendered.contains("FROM stagex/user-caddy@sha256:"));
        assert!(rendered.contains("cp /usr/lib/libssl.so.3"));
        assert!(rendered.contains("cp /usr/lib/libcrypto.so.3"));
        assert!(rendered.contains("chroot /build/initramfs /caddy version"));
        assert!(rendered.contains("chroot /build/initramfs /usr/bin/openssl version"));
        assert!(rendered.contains("ensure_root_dir /build/initramfs/bin usr/bin"));
        assert!(rendered.contains("ensure_root_dir /build/initramfs/lib usr/lib"));
        assert!(rendered.contains("readlink -n \"$path\"; printf x"));
        assert!(!rendered.contains("COPY --from=steve-builder"));
    }

    /// Build a tar holding two entries that differ only by case. On a
    /// case-insensitive filesystem these collide the moment anything unpacks
    /// them, which is the whole of issue #401.
    fn case_colliding_tar(path: &Path) {
        let file = std::fs::File::create(path).unwrap();
        let mut builder = tar::Builder::new(file);
        for (name, body) in [("foo", b"lower" as &[u8]), ("FOO", b"upper" as &[u8])] {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, body).unwrap();
        }
        builder.finish().unwrap();
    }

    const DIR: tar::EntryType = tar::EntryType::Directory;
    const FILE: tar::EntryType = tar::EntryType::Regular;

    fn entry_map(
        entries: &[(&str, tar::EntryType)],
    ) -> std::collections::BTreeMap<PathBuf, tar::EntryType> {
        entries
            .iter()
            .map(|(p, t)| (normalized(Path::new(p)), *t))
            .collect()
    }

    /// A symlink target long enough to force the GNU/PAX long-link extension,
    /// which is stored in a record *preceding* the entry rather than in its
    /// header. Anything that clones the raw header loses it.
    fn long_link_target() -> String {
        let deep: Vec<String> = (0..20).map(|i| format!("very-long-segment-{i:02}")).collect();
        let target = format!("{}/libssl.so.3", deep.join("/"));
        assert!(target.len() > 100, "target must exceed the header field");
        target
    }

    /// A payload shaped like a real `docker export`, carrying every hazard the
    /// tar context has to survive: entries differing only by case, a hard link
    /// (a reference *within* the archive), and a symlink whose target needs a
    /// long-link record.
    fn hazard_payload_tar(path: &Path) {
        let file = std::fs::File::create(path).unwrap();
        let mut builder = tar::Builder::new(file);

        for (name, body) in [("foo", b"lower" as &[u8]), ("FOO", b"upper" as &[u8])] {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, body).unwrap();
        }

        let body = b"ELF-ish" as &[u8];
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, "usr/bin/busybox", body)
            .unwrap();

        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Link);
        header.set_size(0);
        header.set_mode(0o755);
        builder
            .append_link(&mut header, "bin/sh", "usr/bin/busybox")
            .unwrap();

        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        builder
            .append_link(&mut header, "usr/lib/libssl.so", long_link_target())
            .unwrap();

        builder.finish().unwrap();
    }

    fn tar_entry_names(path: &Path) -> Vec<String> {
        let file = std::fs::File::open(path).unwrap();
        let mut archive = tar::Archive::new(file);
        archive
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect()
    }

    /// The acceptance criterion from issue #401: an application containing both
    /// `foo` and `FOO` must reach the builder with BOTH entries intact, on any
    /// host filesystem. Staging copies the tar verbatim rather than unpacking,
    /// so this holds on case-insensitive macOS exactly as it does on Linux.
    #[tokio::test]
    async fn test_case_colliding_entries_survive_staging() {
        let tmp = tempfile::tempdir().unwrap();
        let src_tar = tmp.path().join("user-service.tar");
        case_colliding_tar(&src_tar);

        let stage_dir = tmp.path().join("eif-stage");
        let app_dir = stage_dir.join("app");
        fs::create_dir_all(&app_dir).await.unwrap();

        let staged_tar = stage_user_application(&src_tar, &stage_dir, &app_dir)
            .await
            .unwrap();
        assert!(staged_tar, "a .tar payload must take the tar path");

        let staged = stage_dir.join("app.tar");
        assert!(staged.exists(), "app.tar must be staged into the context");
        assert!(
            !app_dir.exists(),
            "app/ must not survive, or COPY would layer it over the unpacked tree"
        );

        let names = tar_entry_names(&staged);
        assert!(names.contains(&"foo".to_string()), "lost 'foo': {names:?}");
        assert!(names.contains(&"FOO".to_string()), "lost 'FOO': {names:?}");

        // Byte-identical: nothing about the payload is reinterpreted host-side.
        assert_eq!(
            std::fs::read(&src_tar).unwrap(),
            std::fs::read(&staged).unwrap()
        );
    }

    /// A directory payload keeps the previous behaviour, so the narrower
    /// extract paths are unaffected by the fix.
    #[tokio::test]
    async fn test_directory_payload_still_staged_as_app_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let src_dir = tmp.path().join("user-service");
        fs::create_dir_all(src_dir.join("bin")).await.unwrap();
        fs::write(src_dir.join("bin/app"), b"binary").await.unwrap();

        let stage_dir = tmp.path().join("eif-stage");
        let app_dir = stage_dir.join("app");
        fs::create_dir_all(&app_dir).await.unwrap();

        let staged_tar = stage_user_application(&src_dir, &stage_dir, &app_dir)
            .await
            .unwrap();
        assert!(
            !staged_tar,
            "a directory payload must keep directory staging"
        );
        assert!(app_dir.join("bin/app").exists());
        assert!(!stage_dir.join("app.tar").exists());
    }

    /// The acceptance criterion of issue #401, at the layer that now enforces
    /// it: an application containing both `foo` and `FOO` must reach Docker
    /// with BOTH entries under `app/`, on any host filesystem. The context is
    /// assembled tar-to-tar, so a case-insensitive host never gets the chance
    /// to fold them together.
    #[tokio::test]
    async fn test_context_tar_preserves_case_colliding_app_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let work_dir = tmp.path();
        let stage_dir = work_dir.join("eif-stage");
        let app_dir = stage_dir.join("app");
        fs::create_dir_all(&app_dir).await.unwrap();

        // A couple of ordinary context files alongside the payload.
        fs::write(stage_dir.join("Containerfile.eif"), b"FROM scratch\n")
            .await
            .unwrap();
        fs::create_dir_all(stage_dir.join("enclave")).await.unwrap();
        fs::write(stage_dir.join("enclave/rootfs.sh"), b"#!/bin/sh\n")
            .await
            .unwrap();

        let payload = work_dir.join("user-service.tar");
        case_colliding_tar(&payload);
        assert!(stage_user_application(&payload, &stage_dir, &app_dir)
            .await
            .unwrap());

        let context_tar = work_dir.join("eif-context.tar");
        write_context_tar(&stage_dir, &context_tar).unwrap();

        let names = tar_entry_names(&context_tar);

        // Both colliding entries present, namespaced under app/.
        assert!(
            names.contains(&"app/foo".to_string()),
            "lost app/foo: {names:?}"
        );
        assert!(
            names.contains(&"app/FOO".to_string()),
            "lost app/FOO: {names:?}"
        );

        // The rest of the context is carried through unchanged...
        assert!(names.contains(&"Containerfile.eif".to_string()));
        assert!(names.contains(&"enclave/rootfs.sh".to_string()));

        // ...and the payload blob itself is not shipped twice.
        assert!(
            !names.iter().any(|n| n == APP_PAYLOAD_TAR),
            "payload must not appear verbatim in the context: {names:?}"
        );
    }

    /// Re-rooting entries under `app/` must re-root hard-link targets with
    /// them - a hard link names another entry *inside the archive*, so a target
    /// left un-prefixed points at a path the context no longer contains and
    /// BuildKit rejects the build. Symlink targets must NOT move: they are
    /// resolved inside the container against what becomes the ramdisk root.
    /// Both are read via `Entry::link_name` so a long-link record survives.
    #[tokio::test]
    async fn test_context_tar_reroots_hard_links_and_keeps_long_symlink_targets() {
        let tmp = tempfile::tempdir().unwrap();
        let work_dir = tmp.path();
        let stage_dir = work_dir.join("eif-stage");
        let app_dir = stage_dir.join("app");
        fs::create_dir_all(&app_dir).await.unwrap();
        fs::write(stage_dir.join("Containerfile.eif"), b"FROM scratch\n")
            .await
            .unwrap();

        let payload = work_dir.join("user-service.tar");
        hazard_payload_tar(&payload);
        assert!(stage_user_application(&payload, &stage_dir, &app_dir)
            .await
            .unwrap());

        let context_tar = work_dir.join("eif-context.tar");
        write_context_tar(&stage_dir, &context_tar).unwrap();

        let mut links = std::collections::BTreeMap::new();
        let file = std::fs::File::open(&context_tar).unwrap();
        let mut archive = tar::Archive::new(file);
        for entry in archive.entries().unwrap() {
            let entry = entry.unwrap();
            let name = entry.path().unwrap().to_string_lossy().into_owned();
            if let Some(target) = entry.link_name().unwrap() {
                links.insert(
                    name,
                    (
                        entry.header().entry_type(),
                        target.to_string_lossy().into_owned(),
                    ),
                );
            }
        }

        let (kind, target) = links.get("app/bin/sh").expect("hard link lost");
        assert_eq!(*kind, tar::EntryType::Link);
        assert_eq!(
            target, "app/usr/bin/busybox",
            "hard-link target must be re-rooted alongside its entry"
        );

        let (kind, target) = links.get("app/usr/lib/libssl.so").expect("symlink lost");
        assert_eq!(*kind, tar::EntryType::Symlink);
        assert_eq!(
            target,
            &long_link_target(),
            "symlink target must survive the long-link record, unmodified"
        );
    }

    /// buildx decides whether stdin is a context archive or a bare Dockerfile
    /// by running a tar reader over only the first 1 KiB. A GNU/PAX extension
    /// record at the very front needs more than that, so the read fails and the
    /// whole context is parsed as a Dockerfile - the build then dies on
    /// "unknown instruction: ././@PaxHeader" with nothing pointing at the real
    /// cause. Stage files are written first precisely because their names are
    /// short and framework-controlled; this pins that ordering.
    #[tokio::test]
    async fn test_context_tar_opens_with_a_short_named_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let stage_dir = tmp.path().join("eif-stage");
        let app_dir = stage_dir.join("app");
        fs::create_dir_all(&app_dir).await.unwrap();
        fs::write(stage_dir.join("Containerfile.eif"), b"FROM scratch\n")
            .await
            .unwrap();

        let payload = tmp.path().join("user-service.tar");
        hazard_payload_tar(&payload);
        stage_user_application(&payload, &stage_dir, &app_dir)
            .await
            .unwrap();

        let context_tar = tmp.path().join("eif-context.tar");
        write_context_tar(&stage_dir, &context_tar).unwrap();

        let head = std::fs::read(&context_tar).unwrap();
        assert_eq!(
            &head[257..262],
            b"ustar",
            "first block must be a plain tar header, not an extension record"
        );

        let first = tar_entry_names(&context_tar).into_iter().next().unwrap();
        assert!(
            first.len() <= 100,
            "first entry must fit a tar header, or buildx misreads the context: {first}"
        );
    }

    async fn docker_available() -> bool {
        Command::new("docker")
            .arg("version")
            .output()
            .await
            .is_ok_and(|o| o.status.success())
    }

    /// The regression the tar context introduced, and the reason a unit test on
    /// the tar is not enough: a hard link references another entry *inside the
    /// archive*, so re-rooting entries under `app/` without re-rooting link
    /// targets hands BuildKit a dangling reference. Only BuildKit's own
    /// unpacker rejects it - `link ...: no such file or directory` - and it
    /// does so before the Containerfile even runs.
    ///
    /// Also covers the other two hazards end-to-end: case-colliding entries
    /// (issue #401 itself) and a symlink whose target needs a long-link record.
    /// The result is exported as a tar rather than to a directory, so the
    /// assertion is not itself subject to the case folding under test.
    ///
    /// Skipped, loudly, when Docker is unavailable.
    #[tokio::test]
    async fn test_buildkit_accepts_rerooted_hard_links_and_long_link_targets() {
        if !docker_available().await {
            eprintln!(
                "SKIP test_buildkit_accepts_rerooted_hard_links_and_long_link_targets: no docker"
            );
            return;
        }

        let tmp = tempfile::tempdir().unwrap();
        let stage_dir = tmp.path().join("eif-stage");
        let app_dir = stage_dir.join("app");
        fs::create_dir_all(&app_dir).await.unwrap();
        fs::write(
            stage_dir.join("Containerfile.eif"),
            b"FROM scratch\nCOPY app/ /app/\n",
        )
        .await
        .unwrap();

        let payload = tmp.path().join("user-service.tar");
        hazard_payload_tar(&payload);
        stage_user_application(&payload, &stage_dir, &app_dir)
            .await
            .unwrap();

        let context_tar = tmp.path().join("eif-context.tar");
        write_context_tar(&stage_dir, &context_tar).unwrap();

        let result_tar = tmp.path().join("result.tar");
        let context = std::fs::File::open(&context_tar).unwrap();
        let output = Command::new("docker")
            .args([
                "build",
                "--no-cache",
                "--progress=plain",
                "--output",
                &format!("type=tar,dest={}", result_tar.display()),
                "-f",
                "Containerfile.eif",
                "-",
            ])
            .env("DOCKER_BUILDKIT", "1")
            .stdin(std::process::Stdio::from(context))
            .current_dir(&stage_dir)
            .output()
            .await
            .unwrap();

        assert!(
            output.status.success(),
            "BuildKit rejected the context:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );

        let mut files = std::collections::BTreeMap::new();
        let file = std::fs::File::open(&result_tar).unwrap();
        let mut archive = tar::Archive::new(file);
        for entry in archive.entries().unwrap() {
            let entry = entry.unwrap();
            files.insert(
                entry.path().unwrap().to_string_lossy().into_owned(),
                (
                    entry.header().entry_type(),
                    entry
                        .link_name()
                        .unwrap()
                        .map(|t| t.to_string_lossy().into_owned()),
                ),
            );
        }

        // Issue #401's acceptance criterion, all the way through BuildKit.
        assert!(files.contains_key("app/foo"), "lost app/foo: {files:?}");
        assert!(files.contains_key("app/FOO"), "lost app/FOO: {files:?}");

        // The hard link and its target both landed, and one references the
        // other. BuildKit is free to choose which of the pair carries the data.
        let sh = files.get("app/bin/sh").expect("hard link lost");
        let busybox = files.get("app/usr/bin/busybox").expect("link target lost");
        let linked = [(sh, "app/usr/bin/busybox"), (busybox, "app/bin/sh")]
            .iter()
            .any(|((kind, target), other)| {
                *kind == tar::EntryType::Link && target.as_deref() == Some(*other)
            });
        assert!(linked, "hard link did not survive re-rooting: {files:?}");

        let (kind, target) = files.get("app/usr/lib/libssl.so").expect("symlink lost");
        assert_eq!(*kind, tar::EntryType::Symlink);
        assert_eq!(
            target.as_deref(),
            Some(long_link_target().as_str()),
            "long symlink target must survive unmodified"
        );
    }

    /// A payload left behind by an earlier build must not hijack a directory
    /// staging: the marker selects the build flow, so a stale one silently
    /// ships the previous application.
    #[tokio::test]
    async fn test_stale_payload_does_not_hijack_directory_staging() {
        let tmp = tempfile::tempdir().unwrap();
        let stage_dir = tmp.path().join("eif-stage");
        let app_dir = stage_dir.join("app");
        fs::create_dir_all(&app_dir).await.unwrap();

        // A previous run in this work dir left a payload behind.
        case_colliding_tar(&stage_dir.join(APP_PAYLOAD_TAR));

        let src_dir = tmp.path().join("user-service");
        fs::create_dir_all(src_dir.join("bin")).await.unwrap();
        fs::write(src_dir.join("bin/app"), b"binary").await.unwrap();

        let staged_tar = stage_user_application(&src_dir, &stage_dir, &app_dir)
            .await
            .unwrap();

        assert!(
            !staged_tar,
            "a directory payload must keep directory staging"
        );
        assert!(
            !stage_dir.join(APP_PAYLOAD_TAR).exists(),
            "stale payload must be cleared, or the build takes the tar path"
        );
        assert!(app_dir.join("bin/app").exists());
    }

    /// Rosetta's translation cache is created by Docker Desktop inside the
    /// container on Apple Silicon and captured by `docker export`. A Linux
    /// builder never has it, so it must be dropped or every macOS reproduction
    /// differs from the deployment by exactly these entries.
    #[test]
    fn test_rosetta_cache_is_treated_as_a_runtime_artifact() {
        // Directory entries carry the trailing slash `docker export` writes, so
        // this also pins that lookups normalise rather than compare raw.
        let entries = entry_map(&[
            ("home/", DIR),
            ("home/user/", DIR),
            ("home/user/.cache/", DIR),
            ("home/user/.cache/rosetta/", DIR),
            (".dockerenv", FILE),
            ("zero-indexer-shim", FILE),
        ]);

        let drop = container_runtime_artifacts(&entries);

        assert!(drop.contains(&PathBuf::from("home/user/.cache/rosetta")));
        // The .cache dir existed only to hold it, so it goes too.
        assert!(drop.contains(&PathBuf::from("home/user/.cache")));
        // Real image content is untouched...
        assert!(!drop.contains(&PathBuf::from("home/user")));
        assert!(!drop.contains(&PathBuf::from("zero-indexer-shim")));
        // ...and .dockerenv stays: Linux builders have it too, so deployed
        // enclaves genuinely contain it.
        assert!(!drop.contains(&PathBuf::from(".dockerenv")));
    }

    /// A `.cache` holding real application data must survive even when Rosetta
    /// also mounted into it.
    #[test]
    fn test_cache_dir_with_real_contents_is_kept() {
        let entries = entry_map(&[
            ("app/.cache/", DIR),
            ("app/.cache/rosetta/", DIR),
            ("app/.cache/real-data.bin", FILE),
        ]);

        let drop = container_runtime_artifacts(&entries);

        assert!(drop.contains(&PathBuf::from("app/.cache/rosetta")));
        assert!(!drop.contains(&PathBuf::from("app/.cache")));
        assert!(!drop.contains(&PathBuf::from("app/.cache/real-data.bin")));
    }

    /// The exclusion must not fire on image content that merely shares the
    /// name. A `rosetta` the image actually ships has something in it.
    #[test]
    fn test_populated_rosetta_dir_is_image_content() {
        let entries = entry_map(&[
            ("opt/.cache/", DIR),
            ("opt/.cache/rosetta/", DIR),
            ("opt/.cache/rosetta/translations.bin", FILE),
        ]);

        assert!(
            container_runtime_artifacts(&entries).is_empty(),
            "a populated .cache/rosetta belongs to the image"
        );
    }

    /// Only a `.cache` emptied by removing the Rosetta mount point is an
    /// artifact. One the image ships empty is image content, and dropping it
    /// would change PCR0/PCR1 for a correct deployment - the exact failure the
    /// exclusion exists to prevent.
    #[test]
    fn test_unrelated_empty_cache_dir_is_kept() {
        let entries = entry_map(&[("var/lib/app/", DIR), ("var/lib/app/.cache/", DIR)]);

        assert!(
            container_runtime_artifacts(&entries).is_empty(),
            "an empty .cache with no Rosetta mount point is image content"
        );
    }

    /// A file named `rosetta` under `.cache` is not a mount point.
    #[test]
    fn test_rosetta_file_is_not_a_mount_point() {
        let entries = entry_map(&[("home/.cache/", DIR), ("home/.cache/rosetta", FILE)]);

        assert!(container_runtime_artifacts(&entries).is_empty());
    }

    #[test]
    fn test_render_containerfile_non_caddy_excludes_caddy_artifacts() {
        let template = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("templates/Containerfile.eif"),
        )
        .unwrap();

        for enabled_blocks in [&[][..], &["STEVE"][..]] {
            let rendered = process_template_blocks(&template, enabled_blocks);
            assert!(!rendered.contains("FROM stagex/user-caddy@sha256:"));
            for applet in ["cut", "tr", "mv", "rm"] {
                assert!(!rendered.contains(&format!("ln -sf busybox {applet}")));
            }
        }
    }

    #[tokio::test]
    async fn test_render_run_sh_egress_enabled_includes_tunnel() {
        let template = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("templates/run.sh.template");
        let rendered = render_run_sh_template(
            &template,
            Some("/app".to_string()),
            &[],
            None,
            false,
            "disabled",
            "X25519",
            false,
            None,
            "http",
            false,
            None,
            true,
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
            &template,
            Some("/app".to_string()),
            &[],
            None,
            false,
            "disabled",
            "X25519",
            false,
            None,
            "http",
            false,
            None,
            false,
        )
        .await
        .unwrap();
        assert!(!rendered.contains("VSOCK-CONNECT:3:3"));
        assert!(!rendered.contains("udhcpc"));
        assert!(rendered.contains("nameserver 127.0.0.1"));
        assert!(rendered.contains(
            "# Internal service proxies use high ports so application ports like 8080 are available."
        ));
        assert!(!rendered.contains("VSOCK-LISTEN:443"));
    }
}
