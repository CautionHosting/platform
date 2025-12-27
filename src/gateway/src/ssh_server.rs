// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::{Context, Result, bail};
use russh::server::{Auth, Msg, Session, Server};
use russh::{Channel, ChannelId};
use russh_keys::key::{KeyPair, PublicKey};
use russh_keys::PublicKeyBase64;
use sqlx::PgPool;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::Mutex;
use tokio::process::Child;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

#[derive(Clone)]
pub struct SshServer {
    pub pool: PgPool,
    pub api_service_url: String,
    pub data_dir: String,
    pub internal_service_secret: Option<String>,
}

impl SshServer {
    pub fn new(pool: PgPool, api_service_url: String, data_dir: String, internal_service_secret: Option<String>) -> Self {
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
    user_id: Option<Uuid>,
    org_id: Option<Uuid>,
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
            user_id: None,
            org_id: None,
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

        let calculated_fingerprint = crate::db::generate_ssh_fingerprint(&full_key);
        tracing::info!("Calculated fingerprint during auth: {}", calculated_fingerprint);
        tracing::debug!("Full key being checked: {}", full_key);
        match crate::db::get_user_by_ssh_key(&self.pool, &full_key).await {
            Ok(Some(user_id)) => {
                tracing::info!("SSH auth successful for user_id: {}", user_id);
                self.user_id = Some(user_id);

                match get_user_org(&self.pool, user_id).await {
                    Ok(Some(org_id)) => {
                        self.org_id = Some(org_id);
                        tracing::debug!("User {} belongs to org {}", user_id, org_id);
                        Ok(Auth::Accept)
                    }
                    Ok(None) => {
                        tracing::warn!("User {} has no organization", user_id);
                        Ok(Auth::Reject {
                            proceed_with_methods: None,
                        })
                    }
                    Err(e) => {
                        tracing::error!("Failed to get user org: {:?}", e);
                        Ok(Auth::Reject {
                            proceed_with_methods: None,
                        })
                    }
                }
            }
            Ok(None) => {
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

        let user_id = self.user_id.ok_or_else(|| anyhow::anyhow!("Not authenticated"))?;
        let org_id = self.org_id.ok_or_else(|| anyhow::anyhow!("No organization"))?;

        if let Some(app_id) = parse_git_receive_pack(&command) {
            tracing::info!("Git push for app: {}", app_id);

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
                self.git_processes.clone()
            ).await {
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
    let app_id = repo_path
        .trim_start_matches('/')
        .trim_end_matches(".git");

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
        fs::create_dir_all(parent)
            .context("Failed to create git repos directory")?;
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

fn update_repo_head(repo_path: &str) -> Result<String> {
    use std::process::Command;

    let output = Command::new("git")
        .args(&[
            "--git-dir", repo_path,
            "for-each-ref",
            "--sort=-committerdate",
            "--format=%(refname:short)",
            "refs/heads/",
            "--count=1"
        ])
        .output()
        .context("Failed to list branches")?;

    if !output.status.success() {
        tracing::debug!("No branches found yet in {}", repo_path);
        return Ok("main".to_string());
    }

    let target_branch = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if target_branch.is_empty() {
        tracing::debug!("No branches found in {}", repo_path);
        return Ok("main".to_string());
    }

    tracing::info!("Most recently updated branch: {}", target_branch);
    tracing::info!("Setting HEAD to refs/heads/{}", target_branch);

    let output = Command::new("git")
        .args(&["--git-dir", repo_path, "symbolic-ref", "HEAD", &format!("refs/heads/{}", target_branch)])
        .output()
        .context("Failed to update HEAD")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::warn!("Failed to update HEAD: {}", stderr);
    } else {
        tracing::info!("Successfully set HEAD to refs/heads/{}", target_branch);
    }

    Ok(target_branch)
}

async fn get_user_org(pool: &PgPool, user_id: Uuid) -> Result<Option<Uuid>> {
    let org_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT organization_id FROM organization_members WHERE user_id = $1 LIMIT 1"
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .context("Failed to get user org")?;

    Ok(org_id)
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
         WHERE id = $1 AND organization_id = $2"
    )
    .bind(app_uuid)
    .bind(org_id)
    .fetch_optional(pool)
    .await
    .context("Failed to check existing resource")?;

    match existing {
        Some((state,)) => {
            if state == "running" || state == "stopped" {
                bail!("App '{}' already exists in state '{}'. Use 'caution apps destroy {}' to destroy it first.", app_id, state, app_id);
            }
            tracing::info!("App '{}' exists in state '{}', allowing push", app_id, state);
        }
        None => {
            bail!("App '{}' not found. Run 'caution init' first.", app_id);
        }
    }

    let repo_path = format!("{}/git-repos/{}.git", data_dir, app_id);
    ensure_git_repo_exists(&repo_path)?;

    tracing::info!("Spawning git receive-pack for {}", repo_path);

    let mut child = tokio::process::Command::new("git")
        .arg("receive-pack")
        .arg(&repo_path)
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
                            if let Err(e) = handle.extended_data(channel, 1, buf[..n].to_vec().into()).await {
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
                        let error_msg = format!("remote: error: Failed to complete git receive-pack\n");
                        let _ = session_handle.extended_data(channel, 1, error_msg.into_bytes().into()).await;
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
            let _ = session_handle.exit_status_request(channel, exit_code as u32).await;
            let _ = session_handle.close(channel).await;
            return;
        }

        tracing::info!("Git receive-pack completed successfully");

        let branch = match update_repo_head(&repo_path) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("Failed to update repo HEAD: {}", e);
                "main".to_string()
            }
        };

        let deploy_msg = "\n";
        let _ = session_handle.extended_data(channel, 1, deploy_msg.as_bytes().to_vec().into()).await;

        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();

        let session_handle_clone = session_handle.clone();
        tokio::spawn(async move {
            let frames = ["⣼", "⣹", "⢻", "⠿", "⡟", "⣏", "⣧", "⣶"];
            let message = "Building and deploying your application";
            let mut frame_idx = 0;
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(120));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = &mut stop_rx => {
                        break;
                    }
                    _ = interval.tick() => {
                        let frame_msg = format!("\r{} {}", frames[frame_idx], message);
                        let _ = session_handle_clone.extended_data(channel, 1, frame_msg.as_bytes().to_vec().into()).await;
                        frame_idx = (frame_idx + 1) % frames.len();
                    }
                }
            }
        });

        #[derive(serde::Serialize)]
        struct DeployRequest {
            org_id: Uuid,
            app_id: Uuid,
            branch: String,
        }

        let app_uuid = Uuid::parse_str(&app_id).expect("Already validated app_id");
        tracing::info!("Triggering deployment for {} (branch: {})", app_id, branch);

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
            })
            .timeout(std::time::Duration::from_secs(7200))
            .send()
            .await
        {
            Ok(resp) => {
                let _ = stop_tx.send(());
                let _ = session_handle.extended_data(channel, 1, b"\n".to_vec().into()).await;
                resp
            }
            Err(e) => {
                let _ = stop_tx.send(());
                let _ = session_handle.extended_data(channel, 1, b"\n".to_vec().into()).await;
                tracing::error!("Failed to send deployment request: {}", e);
                let error_msg = format!("remote: error: Failed to trigger deployment: {}\n", e);
                let _ = session_handle.extended_data(channel, 1, error_msg.into_bytes().into()).await;
                let _ = session_handle.exit_status_request(channel, 1).await;
                let _ = session_handle.close(channel).await;
                return;
            }
        };

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            tracing::error!("Deployment failed: {}", error_text);
            let error_msg = format!("remote: error: Deployment failed: {}\n", error_text);
            let _ = session_handle.extended_data(channel, 1, error_msg.into_bytes().into()).await;
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

        let deploy_result: DeployResponse = match response.json().await {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Failed to parse deployment response: {}", e);
                let error_msg = format!("remote: error: Invalid deployment response\n");
                let _ = session_handle.extended_data(channel, 1, error_msg.into_bytes().into()).await;
                let _ = session_handle.exit_status_request(channel, 1).await;
                let _ = session_handle.close(channel).await;
                return;
            }
        };

        tracing::info!("Deployment successful: {} (resource_id: {})", deploy_result.url, deploy_result.resource_id);

        let attestation_url = format!("{}/attestation", deploy_result.url);

        let dns_note = if let Some(ref domain) = deploy_result.domain {
            format!("\nNOTE: Add a DNS A record for '{}' pointing to {}\n", domain, deploy_result.public_ip)
        } else {
            String::new()
        };

        let success_msg = format!(
            "\nDeployment successful!\nApplication: {}\nAttestation: {}{}\n\nRun 'caution verify' to verify the application attestation.\n\n",
            deploy_result.url,
            attestation_url,
            dns_note
        );
        let _ = session_handle.extended_data(channel, 1, success_msg.into_bytes().into()).await;
        let _ = session_handle.exit_status_request(channel, 0).await;
        let _ = session_handle.close(channel).await;
    });

    Ok(())
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
