// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result, bail};
use futures::StreamExt;
use russh::server::{Auth, Msg, Server, Session};
use russh::{Channel, ChannelId};
use russh_keys::PublicKeyBase64;
use russh_keys::key::{KeyPair, PublicKey};
use sqlx::PgPool;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Child;
use tokio::sync::Mutex;
use uuid::Uuid;

const POST_RECEIVE_HOOK: &str = r#"#!/bin/sh
set -eu
: "${CAUTION_PUSH_REF_LOG:?}"

while read old new ref; do
    case "$ref" in
        refs/heads/*)
            printf '%s %s %s\n' "$old" "$new" "$ref" >> "$CAUTION_PUSH_REF_LOG"
            ;;
    esac
done
"#;

const ZERO_SHA1: &str = "0000000000000000000000000000000000000000";

#[derive(Debug)]
struct PushedBranchRef {
    branch: String,
    commit_sha: String,
}

#[derive(Debug)]
enum PushedBranchSelection {
    None,
    One(PushedBranchRef),
    Multiple,
}

#[derive(Clone)]
pub struct SshServer {
    pub pool: PgPool,
    pub api_service_url: String,
    pub data_dir: String,
    pub internal_service_secret: Option<String>,
}

impl SshServer {
    pub fn new(
        pool: PgPool,
        api_service_url: String,
        data_dir: String,
        internal_service_secret: Option<String>,
    ) -> Self {
        Self {
            pool,
            api_service_url,
            data_dir,
            internal_service_secret,
        }
    }
}

pub struct SshSession {
    pool: PgPool,
    api_service_url: String,
    data_dir: String,
    internal_service_secret: Option<String>,
    ssh_fingerprint: Option<String>,
    git_processes: Arc<Mutex<HashMap<ChannelId, Child>>>,
}

impl russh::server::Server for SshServer {
    type Handler = SshSession;

    fn new_client(&mut self, _peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        tracing::debug!("New SSH client connected");
        SshSession {
            pool: self.pool.clone(),
            api_service_url: self.api_service_url.clone(),
            data_dir: self.data_dir.clone(),
            internal_service_secret: self.internal_service_secret.clone(),
            ssh_fingerprint: None,
            git_processes: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl russh::server::Handler for SshSession {
    type Error = anyhow::Error;

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        tracing::debug!("Channel opened");
        Ok(true)
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        tracing::info!("SSH public key auth attempt for user: {}", user);

        // Convert public key to OpenSSH format
        let pub_key_str = public_key.public_key_base64();
        let key_type = public_key.name();
        let full_key = format!("{} {}", key_type, pub_key_str);

        let fingerprint = match crate::db::generate_ssh_fingerprint(&full_key) {
            Ok(fp) => fp,
            Err(e) => {
                tracing::warn!("Failed to generate SSH fingerprint: {}", e);
                return Ok(Auth::Reject {
                    proceed_with_methods: None,
                });
            }
        };
        tracing::info!("Calculated fingerprint during auth: {}", fingerprint);
        tracing::debug!("Full key being checked: {}", full_key);

        // Check if this key belongs to ANY user (we'll resolve the correct user during git push
        // based on which org owns the app being pushed to)
        match crate::db::ssh_key_exists(&self.pool, &fingerprint).await {
            Ok(true) => {
                tracing::info!("SSH auth accepted for fingerprint: {}", fingerprint);
                self.ssh_fingerprint = Some(fingerprint);
                Ok(Auth::Accept)
            }
            Ok(false) => {
                tracing::warn!("SSH key not found in database");
                Ok(Auth::Reject {
                    proceed_with_methods: None,
                })
            }
            Err(e) => {
                tracing::error!("SSH auth error: {:?}", e);
                Ok(Auth::Reject {
                    proceed_with_methods: None,
                })
            }
        }
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data);
        tracing::info!("SSH exec request: {}", command);

        let fingerprint = self
            .ssh_fingerprint
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Not authenticated"))?;

        if let Some(app_id) = parse_git_receive_pack(&command) {
            tracing::info!("Git push for app: {}", app_id);

            // Resolve user_id and org_id based on the app's org and the SSH fingerprint
            let (user_id, org_id) = match crate::db::get_user_for_app_by_ssh_key(
                &self.pool,
                fingerprint,
                &app_id,
            )
            .await
            {
                Ok(Some((user_id, org_id))) => {
                    tracing::info!(
                        "Resolved user {} in org {} for app {}",
                        user_id,
                        org_id,
                        app_id
                    );

                    // Update last_used_at for this SSH key
                    if let Err(e) =
                        crate::db::update_ssh_key_last_used(&self.pool, fingerprint).await
                    {
                        tracing::warn!("Failed to update SSH key last_used_at: {:?}", e);
                    }

                    (user_id, org_id)
                }
                Ok(None) => {
                    let error_msg =
                        "Your SSH key is not registered to any user in this app's organization.\n";
                    tracing::warn!(
                        "SSH key {} not found for any user in app {}'s org",
                        fingerprint,
                        app_id
                    );
                    session.extended_data(
                        channel,
                        1,
                        format!("remote: error: {}", error_msg).into_bytes().into(),
                    );
                    session.exit_status_request(channel, 1);
                    session.close(channel);
                    return Ok(());
                }
                Err(e) => {
                    tracing::error!("Failed to resolve user for app: {:?}", e);
                    session.extended_data(
                        channel,
                        1,
                        "remote: error: Internal error, please try again later.\n"
                            .as_bytes()
                            .to_vec()
                            .into(),
                    );
                    session.exit_status_request(channel, 1);
                    session.close(channel);
                    return Ok(());
                }
            };

            match handle_git_push(
                &self.pool,
                &self.api_service_url,
                &self.data_dir,
                self.internal_service_secret.clone(),
                user_id,
                org_id,
                &app_id,
                channel,
                session,
                self.git_processes.clone(),
            )
            .await
            {
                Ok(()) => {
                    tracing::info!("Git push completed successfully");
                }
                Err(e) => {
                    tracing::error!("Git push failed: {:?}", e);
                    let error_msg = format!("remote: error: {}\n", e);
                    session.extended_data(channel, 1, error_msg.into_bytes().into());
                    session.exit_status_request(channel, 1);
                    session.close(channel);
                }
            }
        } else {
            let error = "remote: Only git-receive-pack commands are supported\n";
            session.extended_data(channel, 1, error.as_bytes().to_vec().into());
            session.exit_status_request(channel, 1);
            session.close(channel);
        }

        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut processes = self.git_processes.lock().await;
        if let Some(child) = processes.get_mut(&channel) {
            if let Some(stdin) = child.stdin.as_mut() {
                if let Err(e) = stdin.write_all(data).await {
                    tracing::error!("Failed to write to git stdin: {}", e);
                    return Err(e.into());
                }
            }
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        tracing::debug!("Channel EOF received for channel {:?}", channel);
        let mut processes = self.git_processes.lock().await;
        if let Some(child) = processes.get_mut(&channel) {
            child.stdin.take();
        }
        Ok(())
    }
}

fn parse_git_receive_pack(command: &str) -> Option<String> {
    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.len() != 2 || parts[0] != "git-receive-pack" {
        return None;
    }

    let repo_path = parts[1].trim_matches('\'').trim_matches('"');
    let app_id = repo_path.trim_start_matches('/').trim_end_matches(".git");

    if let Err(e) = crate::validation::validate_app_id(app_id) {
        tracing::warn!("Invalid app ID '{}' in git push: {}", app_id, e);
        return None;
    }

    Some(app_id.to_string())
}

fn ensure_git_repo_exists(repo_path: &str) -> Result<()> {
    use std::fs;
    use std::process::Command;

    if fs::metadata(repo_path).is_ok() {
        tracing::debug!("Git repository already exists at {}", repo_path);
        return Ok(());
    }

    tracing::info!("Initializing bare git repository at {}", repo_path);

    if let Some(parent) = std::path::Path::new(repo_path).parent() {
        fs::create_dir_all(parent).context("Failed to create git repos directory")?;
    }

    let output = Command::new("git")
        .args(&["init", "--bare", repo_path])
        .output()
        .context("Failed to execute git init")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Git init failed: {}", stderr);
    }

    Ok(())
}

fn prepare_push_ref_hook() -> Result<(tempfile::TempDir, std::path::PathBuf)> {
    use std::fs;

    let hook_dir = tempfile::Builder::new()
        .prefix("caution-push-hooks-")
        .tempdir()
        .context("Failed to create temporary git hook directory")?;
    let hook_path = hook_dir.path().join("post-receive");
    let log_path = hook_dir.path().join("pushed-refs.log");

    fs::write(&hook_path, POST_RECEIVE_HOOK).context("Failed to write post-receive hook")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(&hook_path)
            .context("Failed to stat post-receive hook")?
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&hook_path, permissions)
            .context("Failed to make post-receive hook executable")?;
    }

    Ok((hook_dir, log_path))
}

fn is_sha1_hex(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn parse_pushed_branch_ref(log_content: &str) -> Result<PushedBranchSelection> {
    let mut pushed_ref = None;

    for (line_index, line) in log_content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }

        let mut parts = line.split_whitespace();
        let _old = parts
            .next()
            .with_context(|| format!("Malformed pushed ref log line {}", line_index + 1))?;
        let new = parts
            .next()
            .with_context(|| format!("Malformed pushed ref log line {}", line_index + 1))?;
        let ref_name = parts
            .next()
            .with_context(|| format!("Malformed pushed ref log line {}", line_index + 1))?;

        if parts.next().is_some() {
            bail!("Malformed pushed ref log line {}", line_index + 1);
        }

        let Some(branch) = ref_name.strip_prefix("refs/heads/") else {
            continue;
        };

        if new == ZERO_SHA1 {
            continue;
        }

        if branch.is_empty() {
            bail!("Malformed pushed ref log line {}", line_index + 1);
        }

        if !is_sha1_hex(new) {
            bail!(
                "Invalid commit SHA in pushed ref log line {}",
                line_index + 1
            );
        }

        let next_ref = PushedBranchRef {
            branch: branch.to_string(),
            commit_sha: new.to_ascii_lowercase(),
        };
        if pushed_ref.replace(next_ref).is_some() {
            return Ok(PushedBranchSelection::Multiple);
        }
    }

    Ok(match pushed_ref {
        Some(pushed_ref) => PushedBranchSelection::One(pushed_ref),
        None => PushedBranchSelection::None,
    })
}

fn read_pushed_branch_ref(log_path: &Path) -> Result<PushedBranchSelection> {
    match std::fs::read_to_string(log_path) {
        Ok(content) => parse_pushed_branch_ref(&content),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(PushedBranchSelection::None)
        }
        Err(error) => Err(error).context("Failed to read pushed ref log"),
    }
}

fn set_repo_head(repo_path: &str, branch: &str) -> Result<()> {
    use std::process::Command;

    tracing::info!("Setting HEAD to refs/heads/{}", branch);

    let output = Command::new("git")
        .args(&[
            "--git-dir",
            repo_path,
            "symbolic-ref",
            "--",
            "HEAD",
            &format!("refs/heads/{}", branch),
        ])
        .output()
        .context("Failed to update HEAD")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::warn!("Failed to update HEAD: {}", stderr);
    } else {
        tracing::info!("Successfully set HEAD to refs/heads/{}", branch);
    }

    Ok(())
}

fn get_repo_head_branch(repo_path: &str) -> Result<Option<PushedBranchRef>> {
    use std::process::Command;

    let output = Command::new("git")
        .args(&["--git-dir", repo_path, "symbolic-ref", "--short", "HEAD"])
        .output()
        .context("Failed to read repo HEAD")?;

    if !output.status.success() {
        return Ok(None);
    }

    let branch = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if branch.is_empty() {
        return Ok(None);
    }

    let ref_name = format!("refs/heads/{}", branch);
    let output = Command::new("git")
        .args(&["--git-dir", repo_path, "rev-parse", &ref_name])
        .output()
        .context("Failed to resolve repo HEAD branch")?;

    if !output.status.success() {
        return Ok(None);
    }

    let commit_sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !is_sha1_hex(&commit_sha) {
        bail!("Repo HEAD resolved to invalid commit SHA");
    }

    Ok(Some(PushedBranchRef {
        branch,
        commit_sha: commit_sha.to_ascii_lowercase(),
    }))
}

fn resource_state_allows_noop_redeploy(state: &str) -> bool {
    matches!(state, "initialized" | "terminated" | "failed")
}

async fn handle_git_push(
    pool: &PgPool,
    api_service_url: &str,
    data_dir: &str,
    internal_service_secret: Option<String>,
    user_id: Uuid,
    org_id: Uuid,
    app_id: &str,
    channel: ChannelId,
    session: &mut Session,
    git_processes: Arc<Mutex<HashMap<ChannelId, Child>>>,
) -> Result<()> {
    let app_uuid = Uuid::parse_str(app_id).context("Invalid app ID format")?;

    let existing: Option<(String,)> = sqlx::query_as(
        "SELECT state::text FROM compute_resources
         WHERE id = $1 AND organization_id = $2",
    )
    .bind(app_uuid)
    .bind(org_id)
    .fetch_optional(pool)
    .await
    .context("Failed to check existing resource")?;

    let resource_state = match existing {
        Some((state,)) => {
            if state == "running" || state == "stopped" {
                bail!(
                    "App '{}' already exists in state '{}'. Use 'caution apps destroy {}' to destroy it first.",
                    app_id,
                    state,
                    app_id
                );
            }
            tracing::info!(
                "App '{}' exists in state '{}', allowing push",
                app_id,
                state
            );
            state
        }
        None => {
            bail!("App '{}' not found. Run 'caution init' first.", app_id);
        }
    };
    let allow_noop_redeploy = resource_state_allows_noop_redeploy(&resource_state);

    let repo_path = format!("{}/git-repos/{}.git", data_dir, app_id);
    ensure_git_repo_exists(&repo_path)?;
    let (push_hook_dir, push_ref_log_path) = prepare_push_ref_hook()?;
    let hooks_path = push_hook_dir.path().to_path_buf();

    tracing::info!("Spawning git receive-pack for {}", repo_path);

    let mut child = tokio::process::Command::new("git")
        .arg("-c")
        .arg(format!("core.hooksPath={}", hooks_path.display()))
        .arg("receive-pack")
        .arg(&repo_path)
        .env("CAUTION_PUSH_REF_LOG", &push_ref_log_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("Failed to spawn git receive-pack")?;

    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();

    {
        let mut processes = git_processes.lock().await;
        processes.insert(channel, child);
    }

    let session_handle = session.handle();

    let api_service_url = api_service_url.to_string();
    let app_id = app_id.to_string();
    let channel_id = channel;

    tokio::spawn(async move {
        let push_hook_dir = push_hook_dir;

        let stdout_task = {
            let handle = session_handle.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    match stdout.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            tracing::debug!("Git stdout: {} bytes", n);
                            if let Err(e) = handle.data(channel, buf[..n].to_vec().into()).await {
                                tracing::error!("Failed to send git stdout to SSH: {:?}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::error!("Error reading git stdout: {}", e);
                            break;
                        }
                    }
                }
            })
        };

        let stderr_task = {
            let handle = session_handle.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    match stderr.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            tracing::debug!("Git stderr: {} bytes", n);
                            if let Err(e) = handle
                                .extended_data(channel, 1, buf[..n].to_vec().into())
                                .await
                            {
                                tracing::error!("Failed to send git stderr to SSH: {:?}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::error!("Error reading git stderr: {}", e);
                            break;
                        }
                    }
                }
            })
        };

        let _ = tokio::join!(stdout_task, stderr_task);

        let exit_status = {
            let mut processes = git_processes.lock().await;
            if let Some(mut child) = processes.remove(&channel_id) {
                match child.wait().await {
                    Ok(status) => status,
                    Err(e) => {
                        tracing::error!("Failed to wait for git process: {}", e);
                        let error_msg =
                            format!("remote: error: Failed to complete git receive-pack\n");
                        let _ = session_handle
                            .extended_data(channel, 1, error_msg.into_bytes().into())
                            .await;
                        let _ = session_handle.exit_status_request(channel, 1).await;
                        let _ = session_handle.close(channel).await;
                        return;
                    }
                }
            } else {
                tracing::error!("Git process not found in map");
                return;
            }
        };

        if !exit_status.success() {
            let exit_code = exit_status.code().unwrap_or(1);
            tracing::error!("Git receive-pack failed with exit code: {}", exit_code);
            let _ = session_handle
                .exit_status_request(channel, exit_code as u32)
                .await;
            let _ = session_handle.close(channel).await;
            return;
        }

        tracing::info!("Git receive-pack completed successfully");

        let pushed_ref = match read_pushed_branch_ref(&push_ref_log_path) {
            Ok(PushedBranchSelection::One(pushed_ref)) => pushed_ref,
            Ok(PushedBranchSelection::None) if allow_noop_redeploy => {
                match get_repo_head_branch(&repo_path) {
                    Ok(Some(head_ref)) => {
                        tracing::info!(
                            "No branch refs updated; redeploying HEAD branch '{}' at {}",
                            head_ref.branch,
                            head_ref.commit_sha
                        );
                        let msg = format!(
                            "\nremote: No branch updates received; redeploying existing remote HEAD '{}' at {}.\nremote: To deploy the current checkout, push with: git push caution HEAD:{}\n",
                            head_ref.branch, head_ref.commit_sha, head_ref.branch
                        );
                        let _ = session_handle
                            .extended_data(channel, 1, msg.into_bytes().into())
                            .await;
                        head_ref
                    }
                    Ok(None) => {
                        tracing::info!(
                            "No branch refs updated and no deployable HEAD; skipping deployment"
                        );
                        let msg = "\nremote: No branch updates; skipping deployment.\n".to_string();
                        let _ = session_handle
                            .extended_data(channel, 1, msg.into_bytes().into())
                            .await;
                        let _ = session_handle.exit_status_request(channel, 0).await;
                        let _ = session_handle.close(channel).await;
                        return;
                    }
                    Err(e) => {
                        tracing::error!("Failed to resolve repo HEAD for no-op push: {}", e);
                        let msg = "remote: error: Failed to resolve deploy branch\n".to_string();
                        let _ = session_handle
                            .extended_data(channel, 1, msg.into_bytes().into())
                            .await;
                        let _ = session_handle.exit_status_request(channel, 1).await;
                        let _ = session_handle.close(channel).await;
                        return;
                    }
                }
            }
            Ok(PushedBranchSelection::None) => {
                tracing::info!("No branch refs updated; skipping deployment");
                let msg = "\nremote: No branch updates; skipping deployment.\n".to_string();
                let _ = session_handle
                    .extended_data(channel, 1, msg.into_bytes().into())
                    .await;
                let _ = session_handle.exit_status_request(channel, 0).await;
                let _ = session_handle.close(channel).await;
                return;
            }
            Ok(PushedBranchSelection::Multiple) => {
                tracing::warn!("Multiple branch refs updated; skipping deployment");
                let msg =
                    "\nremote: warning: Multiple branches updated; push one branch to deploy.\n"
                        .to_string();
                let _ = session_handle
                    .extended_data(channel, 1, msg.into_bytes().into())
                    .await;
                let _ = session_handle.exit_status_request(channel, 0).await;
                let _ = session_handle.close(channel).await;
                return;
            }
            Err(e) => {
                tracing::error!("Failed to read pushed branch refs: {}", e);
                let msg = "remote: error: Failed to read pushed refs\n".to_string();
                let _ = session_handle
                    .extended_data(channel, 1, msg.into_bytes().into())
                    .await;
                let _ = session_handle.exit_status_request(channel, 1).await;
                let _ = session_handle.close(channel).await;
                return;
            }
        };

        drop(push_hook_dir);

        if let Err(e) = set_repo_head(&repo_path, &pushed_ref.branch) {
            tracing::warn!("Failed to update repo HEAD: {}", e);
        }

        let branch = pushed_ref.branch;
        let commit_sha = pushed_ref.commit_sha;

        let deploy_ref_msg = format!(
            "\nremote: Deploying branch '{}' at {}\n",
            branch, commit_sha
        );
        let _ = session_handle
            .extended_data(channel, 1, deploy_ref_msg.into_bytes().into())
            .await;

        #[derive(serde::Serialize)]
        struct DeployRequest {
            org_id: Uuid,
            app_id: Uuid,
            branch: String,
            commit_sha: String,
        }

        let app_uuid = Uuid::parse_str(&app_id).expect("Already validated app_id");
        tracing::info!(
            "Triggering deployment for {} (branch: {}, commit: {})",
            app_id,
            branch,
            commit_sha
        );

        let client = reqwest::Client::new();
        let deploy_url = format!("{}/deploy", api_service_url);

        let mut request = client
            .post(&deploy_url)
            .header("X-Authenticated-User-ID", user_id.to_string());

        if let Some(ref secret) = internal_service_secret {
            request = request.header("X-Internal-Service-Secret", secret.clone());
        }

        let response = match request
            .json(&DeployRequest {
                org_id,
                app_id: app_uuid,
                branch: branch.clone(),
                commit_sha: commit_sha.clone(),
            })
            .timeout(std::time::Duration::from_secs(7200))
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                tracing::error!("Failed to send deployment request: {}", e);
                let error_msg =
                    "remote: error: Failed to trigger deployment, please try again later.\n"
                        .to_string();
                let _ = session_handle
                    .extended_data(channel, 1, error_msg.into_bytes().into())
                    .await;
                let _ = session_handle.exit_status_request(channel, 1).await;
                let _ = session_handle.close(channel).await;
                return;
            }
        };

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            tracing::error!("Deployment failed: {}", error_text);
            let error_msg =
                "remote: error: Deployment failed, please try again later.\n".to_string();
            let _ = session_handle
                .extended_data(channel, 1, error_msg.into_bytes().into())
                .await;
            let _ = session_handle.exit_status_request(channel, 1).await;
            let _ = session_handle.close(channel).await;
            return;
        }

        #[derive(serde::Deserialize)]
        struct DeployResponse {
            url: String,
            resource_id: String,
            public_ip: String,
            domain: Option<String>,
        }

        #[derive(serde::Deserialize)]
        struct DeployErrorResponse {
            error: String,
            #[serde(default)]
            status: Option<u16>,
        }

        // Stream the response to the SSH client with spinner animation for milestones
        let mut stream = response.bytes_stream();
        let mut last_line = String::new();
        let mut buffer = String::new();
        let mut current_milestone: Option<String> = None;
        let mut spinner_stop_tx: Option<tokio::sync::oneshot::Sender<()>> = None;
        let mut stream_reported_error = false;

        let spinner_frames = ["⣼", "⣹", "⢻", "⠿", "⡟", "⣏", "⣧", "⣶"];

        while let Some(chunk_result) = stream.next().await {
            match chunk_result {
                Ok(bytes) => {
                    let chunk_str = String::from_utf8_lossy(&bytes);
                    buffer.push_str(&chunk_str);

                    // Process complete lines
                    while let Some(newline_pos) = buffer.find('\n') {
                        let line = buffer[..newline_pos].to_string();
                        buffer = buffer[newline_pos + 1..].to_string();

                        // Check if this line is JSON (the final result)
                        if line.starts_with('{') {
                            // Stop any running spinner and mark previous milestone done
                            if let Some(tx) = spinner_stop_tx.take() {
                                let _ = tx.send(());
                            }
                            if let Some(milestone) = current_milestone.take() {
                                let done_msg = format!("\rremote: [x] {}\n", milestone);
                                let _ = session_handle
                                    .extended_data(channel, 1, done_msg.into_bytes().into())
                                    .await;
                            }
                            last_line = line;
                        } else if let Some(step_msg) = line.strip_prefix("STEP:") {
                            // New milestone starting - complete previous one first
                            if let Some(tx) = spinner_stop_tx.take() {
                                let _ = tx.send(());
                            }
                            if let Some(prev_milestone) = current_milestone.take() {
                                let done_msg = format!("\rremote: [x] {}\n", prev_milestone);
                                let _ = session_handle
                                    .extended_data(channel, 1, done_msg.into_bytes().into())
                                    .await;
                            }

                            // Extract milestone text and start spinner
                            let milestone_text = step_msg.to_string();
                            current_milestone = Some(milestone_text.clone());

                            // Start spinner for this milestone
                            let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
                            spinner_stop_tx = Some(stop_tx);

                            let session_handle_clone = session_handle.clone();
                            let milestone_for_spinner = milestone_text.clone();
                            tokio::spawn(async move {
                                let mut frame_idx = 0;
                                let mut interval =
                                    tokio::time::interval(std::time::Duration::from_millis(120));
                                interval.set_missed_tick_behavior(
                                    tokio::time::MissedTickBehavior::Skip,
                                );

                                loop {
                                    tokio::select! {
                                        _ = &mut stop_rx => break,
                                        _ = interval.tick() => {
                                            let frame_msg = format!("\rremote: {} {}", spinner_frames[frame_idx], milestone_for_spinner);
                                            let _ = session_handle_clone.extended_data(channel, 1, frame_msg.as_bytes().to_vec().into()).await;
                                            frame_idx = (frame_idx + 1) % spinner_frames.len();
                                        }
                                    }
                                }
                            });

                            // Show initial state
                            let initial_msg =
                                format!("remote: {} {}", spinner_frames[0], milestone_text);
                            let _ = session_handle
                                .extended_data(channel, 1, initial_msg.into_bytes().into())
                                .await;
                        } else if !line.is_empty() {
                            // Plain message or error - stop spinner and show
                            if let Some(tx) = spinner_stop_tx.take() {
                                let _ = tx.send(());
                            }
                            if let Some(milestone) = current_milestone.take() {
                                let done_msg = format!("\rremote: [x] {}\n", milestone);
                                let _ = session_handle
                                    .extended_data(channel, 1, done_msg.into_bytes().into())
                                    .await;
                            }
                            if line.starts_with("error:") {
                                stream_reported_error = true;
                            }
                            let msg = format!("remote: {}\n", line);
                            let _ = session_handle
                                .extended_data(channel, 1, msg.into_bytes().into())
                                .await;
                        }
                    }
                }
                Err(e) => {
                    if let Some(tx) = spinner_stop_tx.take() {
                        let _ = tx.send(());
                    }
                    tracing::error!("Error reading deployment stream: {}", e);
                    let error_msg = format!("remote: error: Stream error: {}\n", e);
                    let _ = session_handle
                        .extended_data(channel, 1, error_msg.into_bytes().into())
                        .await;
                    let _ = session_handle.exit_status_request(channel, 1).await;
                    let _ = session_handle.close(channel).await;
                    return;
                }
            }
        }

        // Handle any remaining content in buffer
        if let Some(tx) = spinner_stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(milestone) = current_milestone.take() {
            let done_msg = format!("\rremote: [x] {}\n", milestone);
            let _ = session_handle
                .extended_data(channel, 1, done_msg.into_bytes().into())
                .await;
        }
        if !buffer.is_empty() && buffer.starts_with('{') {
            last_line = buffer;
        }

        let deploy_result: DeployResponse = match serde_json::from_str(&last_line) {
            Ok(result) => result,
            Err(e) => {
                if let Ok(api_error) = serde_json::from_str::<DeployErrorResponse>(&last_line) {
                    tracing::error!(
                        "Deployment failed with API error: status={:?}, error={}",
                        api_error.status,
                        api_error.error
                    );
                    if !stream_reported_error {
                        let error_msg = format!("remote: error: {}\n", api_error.error);
                        let _ = session_handle
                            .extended_data(channel, 1, error_msg.into_bytes().into())
                            .await;
                    }
                    let _ = session_handle.exit_status_request(channel, 1).await;
                    let _ = session_handle.close(channel).await;
                    return;
                }

                tracing::error!(
                    "Failed to parse deployment response: {} (line: {})",
                    e,
                    last_line
                );
                let error_msg = format!("remote: error: Invalid deployment response\n");
                let _ = session_handle
                    .extended_data(channel, 1, error_msg.into_bytes().into())
                    .await;
                let _ = session_handle.exit_status_request(channel, 1).await;
                let _ = session_handle.close(channel).await;
                return;
            }
        };

        tracing::info!(
            "Deployment successful: {} (resource_id: {})",
            deploy_result.url,
            deploy_result.resource_id
        );

        let attestation_url = format!("{}/attestation", deploy_result.url);

        let dns_note = if let Some(ref domain) = deploy_result.domain {
            format!(
                "\nNOTE: Add a DNS A record for '{}' pointing to {}\n",
                domain, deploy_result.public_ip
            )
        } else {
            String::new()
        };

        let success_msg = format!(
            "\nApplication: {}\nAttestation: {}{}\n\nRun 'caution verify' to verify the application attestation.\n\n",
            deploy_result.url, attestation_url, dns_note
        );
        let _ = session_handle
            .extended_data(channel, 1, success_msg.into_bytes().into())
            .await;
        let _ = session_handle.exit_status_request(channel, 0).await;
        let _ = session_handle.close(channel).await;
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        PushedBranchSelection, ZERO_SHA1, parse_pushed_branch_ref,
        resource_state_allows_noop_redeploy,
    };

    const OLD_SHA: &str = "1111111111111111111111111111111111111111";
    const MAIN_SHA: &str = "2222222222222222222222222222222222222222";
    const FEATURE_SHA: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn pushed_ref_parser_keeps_branch_updates() {
        let log = format!("{OLD_SHA} {FEATURE_SHA} refs/heads/qwen2.5-model-swap\n");

        let pushed_ref = parse_pushed_branch_ref(&log).unwrap();

        let PushedBranchSelection::One(pushed_ref) = pushed_ref else {
            panic!("expected one pushed branch ref");
        };
        assert_eq!(pushed_ref.branch, "qwen2.5-model-swap");
        assert_eq!(
            pushed_ref.commit_sha,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[test]
    fn pushed_ref_parser_ignores_deleted_branches_and_tags() {
        let log = format!(
            "{OLD_SHA} {ZERO_SHA1} refs/heads/old-branch\n{OLD_SHA} {MAIN_SHA} refs/tags/v1\n"
        );

        let pushed_ref = parse_pushed_branch_ref(&log).unwrap();

        assert!(matches!(pushed_ref, PushedBranchSelection::None));
    }

    #[test]
    fn pushed_ref_selector_refuses_to_guess_multiple_branches() {
        let log = format!(
            "{OLD_SHA} {MAIN_SHA} refs/heads/main\n{OLD_SHA} {FEATURE_SHA} refs/heads/feature\n"
        );
        let pushed_ref = parse_pushed_branch_ref(&log).unwrap();

        assert!(matches!(pushed_ref, PushedBranchSelection::Multiple));
    }

    #[test]
    fn noop_redeploy_is_only_allowed_for_deployable_inactive_states() {
        assert!(resource_state_allows_noop_redeploy("initialized"));
        assert!(resource_state_allows_noop_redeploy("terminated"));
        assert!(resource_state_allows_noop_redeploy("failed"));

        assert!(!resource_state_allows_noop_redeploy("pending"));
        assert!(!resource_state_allows_noop_redeploy("running"));
        assert!(!resource_state_allows_noop_redeploy("stopped"));
    }

    #[test]
    fn repo_head_branch_resolves_current_deploy_target() {
        let repo_dir = tempfile::tempdir().unwrap();
        let repo_path = repo_dir.path().to_str().unwrap();
        let work_dir = tempfile::tempdir().unwrap();
        let work_path = work_dir.path().to_str().unwrap();

        run_git(&["init", "--bare", repo_path]);
        run_git(&["-C", work_path, "init"]);
        std::fs::write(work_dir.path().join("README.md"), "test\n").unwrap();
        run_git(&["-C", work_path, "add", "."]);
        run_git(&[
            "-C",
            work_path,
            "-c",
            "user.name=Test User",
            "-c",
            "user.email=test@example.com",
            "commit",
            "--no-gpg-sign",
            "-m",
            "initial commit",
        ]);
        let commit_sha = run_git_stdout(&["-C", work_path, "rev-parse", "HEAD"]);
        run_git(&["-C", work_path, "push", repo_path, "HEAD:refs/heads/main"]);
        run_git(&[
            "--git-dir",
            repo_path,
            "symbolic-ref",
            "--",
            "HEAD",
            "refs/heads/main",
        ]);

        let pushed_ref = super::get_repo_head_branch(repo_path).unwrap().unwrap();

        assert_eq!(pushed_ref.branch, "main");
        assert_eq!(pushed_ref.commit_sha, commit_sha);
    }

    fn run_git(args: &[&str]) {
        let output = run_git_output(args);

        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn run_git_stdout(args: &[&str]) -> String {
        let output = run_git_output(args);

        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );

        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    fn run_git_output(args: &[&str]) -> std::process::Output {
        std::process::Command::new("git")
            .args(args)
            .output()
            .unwrap()
    }
}

pub async fn run_ssh_server(
    pool: PgPool,
    api_service_url: String,
    data_dir: String,
    internal_service_secret: Option<String>,
    host_key: KeyPair,
    bind_addr: &str,
) -> Result<()> {
    let config = Arc::new(russh::server::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_secs(3),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![host_key],
        ..Default::default()
    });

    let mut server = SshServer::new(pool, api_service_url, data_dir, internal_service_secret);

    tracing::info!("Starting SSH server on {}", bind_addr);

    server.run_on_address(config, bind_addr).await?;

    Ok(())
}
