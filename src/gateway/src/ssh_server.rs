// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use bytes::Bytes;
use dterror::{BoxError, CtxError, Location, ResultExt};
use futures::StreamExt;
use russh::keys::{PrivateKey, PublicKey, PublicKeyBase64};
use russh::server::{Auth, Msg, Server, Session};
use russh::{Channel, ChannelId};
use sqlx::PgPool;
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
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

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SshHandlerError {
    #[error("not authenticated [{location}]")]
    NotAuthenticated {
        #[location]
        location: Location,
    },

    #[error("failed to write to git stdin [{location}]")]
    StdinWrite {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("protocol error [{location}]")]
    Protocol {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl From<russh::Error> for SshHandlerError {
    fn from(e: russh::Error) -> Self {
        Self::Protocol {
            location: std::panic::Location::caller(),
            source: Box::new(e),
        }
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum EnsureGitRepoExistsError {
    #[error("Failed to create git repos directory [{location}]")]
    CreateDirectory {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Failed to execute git init [{location}]")]
    GitInitSpawn {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Git init failed: {stderr} [{location}]")]
    GitInitFailed {
        stderr: String,
        #[location]
        location: Location,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum PreparePushRefHookError {
    #[error("Failed to create temporary git hook directory [{location}]")]
    CreateTempDir {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Failed to write post-receive hook [{location}]")]
    WriteHook {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Failed to stat post-receive hook [{location}]")]
    StatHook {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("Failed to make post-receive hook executable [{location}]")]
    SetPermissions {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Error type for parsing the pushed-ref log lines. All variants are source-less
/// (leaf error), so only `thiserror::Error` is derived — no `CtxError`.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ParsePushedBranchRefError {
    #[error("Malformed pushed ref log line {line_number} [{location}]")]
    MalformedLine {
        line_number: usize,
        location: dterror::Location,
    },

    #[error("Invalid commit SHA in pushed ref log line {line_number} [{location}]")]
    InvalidSha {
        line_number: usize,
        location: dterror::Location,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ReadPushedBranchRefError {
    #[error("failed to read pushed ref log [{location}]")]
    Io {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to parse pushed ref log [{location}]")]
    Parse {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SetRepoHeadError {
    #[error("failed to update HEAD [{location}]")]
    CommandFailed {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetRepoHeadBranchError {
    #[error("failed to read repo HEAD [{location}]")]
    ReadHead {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to resolve repo HEAD branch [{location}]")]
    ResolveBranch {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("repo HEAD resolved to invalid commit SHA [{location}]")]
    InvalidSha {
        #[location]
        location: Location,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum ReserveDeploymentError {
    #[error("deployment reservation rejected: {message} [{location}]")]
    Rejected {
        message: String,
        #[location]
        location: Location,
    },

    #[error("deployment reservation request failed [{location}]")]
    Request {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl ReserveDeploymentError {
    /// The API's fixed rejection text, unless it carries terminal controls.
    pub(crate) fn client_message(&self) -> String {
        match self {
            Self::Rejected { message, .. } if !contains_non_line_terminal_control(message) => {
                message.clone()
            }
            _ => "Failed to reserve a deployment".to_string(),
        }
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum HandleGitPushError {
    #[error("invalid app ID format [{location}]")]
    InvalidAppId {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to check existing resource [{location}]")]
    QueryResource {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error(
        "App '{app_id}' is in state '{state}'. In-place redeploy is not supported. \
         `caution apps destroy {app_id}` causes downtime and temporarily withdraws managed DNS. \
         After destroy completes, redeploy the same app ID, managed hostname, and any BYOC \
         linkage with `git push caution HEAD:main` using the existing remote. \
         Do not run `caution apps create` or plain `caution init`. \
         For BYOC apps, do not run `caution teardown --byoc`. [{location}]"
    )]
    RunningApp {
        app_id: String,
        state: String,
        #[location]
        location: Location,
    },

    #[error("App '{app_id}' not found. Run 'caution init' first. [{location}]")]
    AppNotFound {
        app_id: String,
        #[location]
        location: Location,
    },

    /// `client_message` is the source's sanitized text: `CtxError` sources
    /// are boxed, so it is captured before boxing.
    #[error("deployment reservation failed [{location}]")]
    Reserve {
        client_message: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to ensure git repo exists [{location}]")]
    EnsureRepo {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to prepare push ref hook [{location}]")]
    PrepareHook {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to spawn git receive-pack [{location}]")]
    SpawnReceivePack {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl HandleGitPushError {
    /// Client-visible message for the git channel. Built from fixed literals so
    /// it never embeds the internal `[{location}]` segment or the boxed source
    /// (both are for logs only). The `RunningApp`/`AppNotFound` wording is
    /// byte-identical to HEAD's; the remaining variants use a fixed generic
    /// string because their underlying cause is now an opaque boxed source.
    pub(crate) fn client_message(&self) -> String {
        match self {
            Self::InvalidAppId { .. } => "Invalid app ID format".to_string(),
            Self::QueryResource { .. } => "Failed to check existing resource".to_string(),
            Self::RunningApp { app_id, state, .. } => {
                [
                    "App '", app_id.as_str(), "' is in state '", state.as_str(),
                    "'. In-place redeploy is not supported. `caution apps destroy ", app_id.as_str(),
                    "` causes downtime and temporarily withdraws managed DNS. After destroy completes, redeploy the same app ID, managed hostname, and any BYOC linkage with `git push caution HEAD:main` using the existing remote. Do not run `caution apps create` or plain `caution init`. For BYOC apps, do not run `caution teardown --byoc`.",
                ].concat()
            }
            Self::AppNotFound { app_id, .. } => {
                format!("App '{}' not found. Run 'caution init' first.", app_id)
            }
            Self::Reserve { client_message, .. } => client_message.clone(),
            Self::EnsureRepo { .. } => "Failed to create git repos directory".to_string(),
            Self::PrepareHook { .. } => "Failed to prepare post-receive hook".to_string(),
            Self::SpawnReceivePack { .. } => "Failed to spawn git receive-pack".to_string(),
        }
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum RunSshServerError {
    #[error("failed to start SSH server [{location}]")]
    Listen {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

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
pub(crate) struct SshServer {
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

pub(crate) struct SshSession {
    pool: PgPool,
    api_service_url: String,
    data_dir: String,
    internal_service_secret: Option<String>,
    ssh_fingerprint: Option<String>,
    git_processes: Arc<Mutex<HashMap<ChannelId, Child>>>,
    /// Set when the connection ends; see the `Drop` impl.
    session_closed: Arc<AtomicBool>,
}

/// russh drops the handler when the connection ends for any reason (client
/// disconnect, keepalive timeout, error). A vanished client sends no channel
/// EOF, and the push task's `Arc` keeps `git_processes` alive, so without this
/// `receive-pack` would block on stdin forever.
impl Drop for SshSession {
    fn drop(&mut self) {
        self.session_closed.store(true, Ordering::SeqCst);
        close_git_stdins(&self.git_processes);
    }
}

/// Closes each child's stdin, as `channel_eof` does. If the lock is held, the
/// push task is already reaping its child, and `Child::wait` closes stdin.
fn close_git_stdins<K>(git_processes: &Mutex<HashMap<K, Child>>) {
    if let Ok(mut processes) = git_processes.try_lock() {
        for child in processes.values_mut() {
            child.stdin.take();
        }
    }
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
            session_closed: Arc::new(AtomicBool::new(false)),
        }
    }

    #[tracing::instrument(skip_all)]
    fn handle_session_error(&mut self, error: SshHandlerError) {
        let (error_kind, io_kind) = match &error {
            SshHandlerError::NotAuthenticated { .. } => ("not_authenticated", None),
            SshHandlerError::StdinWrite { source, .. } => (
                "git_stdin_write",
                source
                    .downcast_ref::<std::io::Error>()
                    .map(std::io::Error::kind),
            ),
            SshHandlerError::Protocol { source, .. } => {
                match source.downcast_ref::<russh::Error>() {
                    Some(russh::Error::KeepaliveTimeout) => ("keepalive_timeout", None),
                    Some(russh::Error::InactivityTimeout) => ("inactivity_timeout", None),
                    Some(russh::Error::ConnectionTimeout) => ("connection_timeout", None),
                    Some(russh::Error::HUP) => ("peer_hangup", None),
                    Some(russh::Error::Disconnect) => ("disconnect", None),
                    Some(russh::Error::WrongChannel) => ("wrong_channel", None),
                    Some(russh::Error::IO(error)) => ("transport_io", Some(error.kind())),
                    _ => ("protocol", None),
                }
            }
        };
        tracing::warn!(error_kind, ?io_kind, "SSH session failed");
    }
}

/// Render a public key as the OpenSSH `"<type> <base64>"` line used for
/// fingerprinting during auth. Must match how keys were stored at
/// registration, otherwise lookups by fingerprint fail.
fn public_key_line(public_key: &PublicKey) -> String {
    format!(
        "{} {}",
        public_key.algorithm(),
        public_key.public_key_base64()
    )
}

/// The guidance lines a deploy failure carries, ready to print to the push.
///
/// Each line becomes one `remote: ` line: trimmed, free of terminal controls,
/// capped, and shown once, so a misconfigured or hostile response cannot flood
/// the push.
fn deploy_error_guidance(notes: &[String], warnings: &[String]) -> Vec<String> {
    /// The cap the API applies to a client message, in bytes.
    const MAX_LINE: usize = 1024;

    let mut lines: Vec<String> = Vec::new();
    for line in notes.iter().chain(warnings.iter()) {
        let line = line.trim();
        if line.is_empty()
            || line.len() > MAX_LINE
            || line.chars().any(char::is_control)
            || lines.iter().any(|seen| seen == line)
        {
            continue;
        }
        lines.push(line.to_string());
    }
    lines
}

fn deploy_progress_started_message(milestone: &str) -> String {
    format!("remote: {milestone}")
}

fn deploy_progress_finished_message(elapsed: std::time::Duration, failed: bool) -> String {
    let duration_str = if elapsed.as_secs() >= 60 {
        let mins = elapsed.as_secs() / 60;
        let secs = elapsed.as_secs() % 60;
        format!("{mins}m{secs}s")
    } else {
        format!(
            "{}.{:01}s",
            elapsed.as_secs(),
            elapsed.subsec_millis() / 100
        )
    };
    let status = if failed { "Failed" } else { "Complete!" };
    format!(" {status} ({duration_str})\n")
}

fn deploy_progress_completed_message(elapsed: std::time::Duration) -> String {
    deploy_progress_finished_message(elapsed, false)
}

fn contains_non_line_terminal_control(message: &str) -> bool {
    message.chars().any(|ch| ch.is_control() && ch != '\n')
}

impl russh::server::Handler for SshSession {
    type Error = SshHandlerError;

    #[tracing::instrument(skip_all)]
    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        tracing::debug!("Channel opened");
        Ok(true)
    }

    #[tracing::instrument(skip_all, fields(user = %user))]
    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        tracing::info!("SSH public key auth attempt for user: {}", user);

        // Convert public key to OpenSSH "<type> <base64>" form for fingerprinting.
        let full_key = public_key_line(public_key);

        let fingerprint = match crate::db::generate_ssh_fingerprint(&full_key) {
            Ok(fp) => fp,
            Err(e) => {
                tracing::warn!("Failed to generate SSH fingerprint: {}", e);
                return Ok(Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
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
                    partial_success: false,
                })
            }
            Err(e) => {
                tracing::error!("SSH auth error: {:?}", e);
                Ok(Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                })
            }
        }
    }

    #[tracing::instrument(skip_all)]
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data);
        tracing::info!("SSH exec request: {}", command);

        let fingerprint =
            self.ssh_fingerprint
                .as_ref()
                .ok_or(SshHandlerError::NotAuthenticated {
                    location: std::panic::Location::caller(),
                })?;

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
                    let _ = session.extended_data(
                        channel,
                        1,
                        Bytes::from(format!("remote: error: {}", error_msg).into_bytes()),
                    );
                    let _ = session.exit_status_request(channel, 1);
                    let _ = session.close(channel);
                    return Ok(());
                }
                Err(e) => {
                    tracing::error!("Failed to resolve user for app: {:?}", e);
                    let _ = session.extended_data(
                        channel,
                        1,
                        Bytes::from_static(
                            b"remote: error: Internal error, please try again later.\n",
                        ),
                    );
                    let _ = session.exit_status_request(channel, 1);
                    let _ = session.close(channel);
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
                self.session_closed.clone(),
            )
            .await
            {
                Ok(()) => {
                    tracing::info!("Git push completed successfully");
                }
                Err(e) => {
                    tracing::error!("Git push failed: {:?}", e);
                    let error_msg = format!("remote: error: {}\n", e.client_message());
                    let _ = session.extended_data(channel, 1, Bytes::from(error_msg.into_bytes()));
                    let _ = session.exit_status_request(channel, 1);
                    let _ = session.close(channel);
                }
            }
        } else {
            let error = "remote: Only git-receive-pack commands are supported\n";
            let _ = session.extended_data(channel, 1, Bytes::from(error.as_bytes().to_vec()));
            let _ = session.exit_status_request(channel, 1);
            let _ = session.close(channel);
        }

        Ok(())
    }

    #[tracing::instrument(skip_all)]
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
                    return Err(SshHandlerError::StdinWrite {
                        location: std::panic::Location::caller(),
                        source: Box::new(e),
                    });
                }
            }
        }
        Ok(())
    }

    #[tracing::instrument(skip_all)]
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

#[tracing::instrument(skip_all)]
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

#[tracing::instrument(skip_all)]
fn ensure_git_repo_exists(repo_path: &str) -> Result<(), EnsureGitRepoExistsError> {
    use std::fs;
    use std::process::Command;

    if fs::metadata(repo_path).is_ok() {
        tracing::debug!("Git repository already exists at {}", repo_path);
        return Ok(());
    }

    tracing::info!("Initializing bare git repository at {}", repo_path);

    if let Some(parent) = std::path::Path::new(repo_path).parent() {
        fs::create_dir_all(parent).with_context(EnsureGitRepoExistsErrorCtx::create_directory())?;
    }

    let output = Command::new("git")
        .args(["init", "--bare", repo_path])
        .output()
        .with_context(EnsureGitRepoExistsErrorCtx::git_init_spawn())?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(EnsureGitRepoExistsError::GitInitFailed {
            stderr,
            location: std::panic::Location::caller(),
        });
    }

    Ok(())
}

fn prepare_push_ref_hook(
) -> Result<(tempfile::TempDir, std::path::PathBuf), PreparePushRefHookError> {
    use std::fs;
    use PreparePushRefHookErrorCtx as Ctx;

    let hook_dir = tempfile::Builder::new()
        .prefix("caution-push-hooks-")
        .tempdir()
        .with_context(Ctx::create_temp_dir())?;
    let hook_path = hook_dir.path().join("post-receive");
    let log_path = hook_dir.path().join("pushed-refs.log");

    fs::write(&hook_path, POST_RECEIVE_HOOK).with_context(Ctx::write_hook())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(&hook_path)
            .with_context(Ctx::stat_hook())?
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&hook_path, permissions).with_context(Ctx::set_permissions())?;
    }

    Ok((hook_dir, log_path))
}

fn is_sha1_hex(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn parse_pushed_branch_ref(
    log_content: &str,
) -> Result<PushedBranchSelection, ParsePushedBranchRefError> {
    let mut pushed_ref = None;

    for (line_index, line) in log_content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }

        let mut parts = line.split_whitespace();
        let _old = parts
            .next()
            .ok_or_else(|| ParsePushedBranchRefError::MalformedLine {
                line_number: line_index + 1,
                location: std::panic::Location::caller(),
            })?;
        let new = parts
            .next()
            .ok_or_else(|| ParsePushedBranchRefError::MalformedLine {
                line_number: line_index + 1,
                location: std::panic::Location::caller(),
            })?;
        let ref_name = parts
            .next()
            .ok_or_else(|| ParsePushedBranchRefError::MalformedLine {
                line_number: line_index + 1,
                location: std::panic::Location::caller(),
            })?;

        if parts.next().is_some() {
            return Err(ParsePushedBranchRefError::MalformedLine {
                line_number: line_index + 1,
                location: std::panic::Location::caller(),
            });
        }

        let Some(branch) = ref_name.strip_prefix("refs/heads/") else {
            continue;
        };

        if new == ZERO_SHA1 {
            continue;
        }

        if branch.is_empty() {
            return Err(ParsePushedBranchRefError::MalformedLine {
                line_number: line_index + 1,
                location: std::panic::Location::caller(),
            });
        }

        if !is_sha1_hex(new) {
            return Err(ParsePushedBranchRefError::InvalidSha {
                line_number: line_index + 1,
                location: std::panic::Location::caller(),
            });
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

fn read_pushed_branch_ref(
    log_path: &Path,
) -> Result<PushedBranchSelection, ReadPushedBranchRefError> {
    match std::fs::read_to_string(log_path) {
        Ok(content) => {
            parse_pushed_branch_ref(&content).map_err(|e| ReadPushedBranchRefError::Parse {
                location: std::panic::Location::caller(),
                source: Box::new(e),
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(PushedBranchSelection::None)
        }
        Err(error) => Err(ReadPushedBranchRefError::Io {
            location: std::panic::Location::caller(),
            source: Box::new(error),
        }),
    }
}

#[tracing::instrument(skip_all)]
fn set_repo_head(repo_path: &str, branch: &str) -> Result<(), SetRepoHeadError> {
    use std::process::Command;
    use SetRepoHeadErrorCtx as Ctx;

    tracing::info!("Setting HEAD to refs/heads/{}", branch);

    let output = Command::new("git")
        .args([
            "--git-dir",
            repo_path,
            "symbolic-ref",
            "--",
            "HEAD",
            &format!("refs/heads/{}", branch),
        ])
        .output()
        .with_context(Ctx::command_failed())?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::warn!("Failed to update HEAD: {}", stderr);
    } else {
        tracing::info!("Successfully set HEAD to refs/heads/{}", branch);
    }

    Ok(())
}

#[tracing::instrument(skip_all)]
fn get_repo_head_branch(
    repo_path: &str,
) -> Result<Option<PushedBranchRef>, GetRepoHeadBranchError> {
    use std::process::Command;
    use GetRepoHeadBranchErrorCtx as Ctx;

    let output = Command::new("git")
        .args(["--git-dir", repo_path, "symbolic-ref", "--short", "HEAD"])
        .output()
        .with_context(Ctx::read_head())?;

    if !output.status.success() {
        return Ok(None);
    }

    let branch = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if branch.is_empty() {
        return Ok(None);
    }

    let ref_name = format!("refs/heads/{}", branch);
    let output = Command::new("git")
        .args(["--git-dir", repo_path, "rev-parse", &ref_name])
        .output()
        .with_context(Ctx::resolve_branch())?;

    if !output.status.success() {
        return Ok(None);
    }

    let commit_sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !is_sha1_hex(&commit_sha) {
        return Err(GetRepoHeadBranchError::InvalidSha {
            location: std::panic::Location::caller(),
        });
    }

    Ok(Some(PushedBranchRef {
        branch,
        commit_sha: commit_sha.to_ascii_lowercase(),
    }))
}

fn resource_state_allows_noop_redeploy(state: &str) -> bool {
    matches!(state, "initialized" | "terminated" | "failed")
}

/// Shown once the push is durably accepted: after `receive-pack`, before
/// `/deploy`. If `/deploy` fails the reservation is released and the ID can 404.
fn accepted_message(deployment_id: Uuid) -> String {
    format!(
        "remote: Deployment {deployment_id} accepted. Disconnecting does not cancel it.\nremote: Follow it with: caution apps get -d {deployment_id}\n"
    )
}

/// Shown when the `/deploy` stream breaks after the push was accepted.
fn interrupted_message(deployment_id: Option<Uuid>, error: &dyn std::fmt::Display) -> String {
    match deployment_id {
        Some(id) => format!(
            "remote: error: The API connection was lost during this deploy (it may have restarted); deployment {id} was abandoned and is cleaned up automatically. Push again.\n"
        ),
        None => format!("remote: error: Stream error: {error}\n"),
    }
}

fn candidate_success_message(
    deployment_id: Uuid,
    live: Option<Uuid>,
    url: &str,
    tls_after_switch: bool,
) -> String {
    let deployment_id = deployment_id.to_string();
    let tls_line = if tls_after_switch {
        [
            "Application TLS: this deployment obtains its certificate after caution apps switch -d ",
            deployment_id.as_str(),
            ".\n",
        ]
        .concat()
    } else {
        String::new()
    };
    let live_line = live
        .map(|id| ["Live deployment: ", &id.to_string(), " (unchanged)\n"].concat())
        .unwrap_or_default();
    [
        "\nCandidate deployment: ",
        deployment_id.as_str(),
        "\nCandidate endpoint: ",
        url,
        "\n",
        live_line.as_str(),
        tls_line.as_str(),
        "\nNext:\n  caution verify -d ",
        deployment_id.as_str(),
        "\n  caution apps switch -d ",
        deployment_id.as_str(),
        "\n\n",
    ]
    .concat()
}

/// Bounds the reservation call: the push waits on it before `receive-pack`.
const RESERVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Reserves the app's deployment slot (`POST /internal/apps/{id}/deployments/reserve`).
async fn reserve_deployment(
    http: &reqwest::Client,
    api_service_url: &str,
    internal_service_secret: Option<&str>,
    app_id: Uuid,
    org_id: Uuid,
    user_id: Uuid,
) -> Result<Uuid, ReserveDeploymentError> {
    use ReserveDeploymentErrorCtx as Ctx;

    #[derive(serde::Deserialize)]
    struct Reserved {
        deployment_id: Uuid,
    }
    #[derive(serde::Deserialize)]
    struct Rejected {
        error: String,
    }

    let mut request = http
        .post(format!(
            "{api_service_url}/internal/apps/{app_id}/deployments/reserve"
        ))
        .timeout(RESERVE_TIMEOUT)
        .json(&serde_json::json!({ "org_id": org_id, "user_id": user_id }));
    if let Some(secret) = internal_service_secret {
        request = request.header("X-Internal-Service-Secret", secret);
    }
    let response = request.send().await.with_context(Ctx::request())?;
    if response.status().is_success() {
        let reserved: Reserved = response.json().await.with_context(Ctx::request())?;
        return Ok(reserved.deployment_id);
    }
    let message = response
        .json::<Rejected>()
        .await
        .map(|body| body.error)
        .unwrap_or_else(|_| "Failed to reserve a deployment".to_string());
    Err(ReserveDeploymentError::Rejected {
        message,
        location: std::panic::Location::caller(),
    })
}

/// Best effort: an unreleased reservation expires and reconciliation deletes
/// it. The API deletes only `reserved` rows, so this never touches a
/// deployment that `/deploy` already claimed.
async fn release_deployment_reservation(
    http: &reqwest::Client,
    api_service_url: &str,
    internal_service_secret: Option<&str>,
    deployment_id: Option<Uuid>,
) {
    let Some(deployment_id) = deployment_id else {
        return;
    };
    let mut request = http.delete(format!(
        "{api_service_url}/internal/deployments/{deployment_id}/reservation"
    ));
    if let Some(secret) = internal_service_secret {
        request = request.header("X-Internal-Service-Secret", secret);
    }
    match request.send().await {
        Ok(response) if response.status().is_success() => {}
        Ok(response) => {
            tracing::warn!(deployment_id = %deployment_id, status = %response.status(), "failed to release deployment reservation");
        }
        Err(error) => {
            tracing::warn!(deployment_id = %deployment_id, error = %error, "failed to release deployment reservation");
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip_all, fields(user_id = %user_id, org_id = %org_id, app_id = %app_id))]
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
    session_closed: Arc<AtomicBool>,
) -> Result<(), HandleGitPushError> {
    use HandleGitPushErrorCtx as Ctx;

    let app_uuid = Uuid::parse_str(app_id).with_context(Ctx::invalid_app_id())?;

    let existing: Option<(String, String, bool)> = sqlx::query_as(
        "SELECT state::text, lifecycle, live_deployment_id IS NULL FROM compute_resources
         WHERE id = $1 AND organization_id = $2",
    )
    .bind(app_uuid)
    .bind(org_id)
    .fetch_optional(pool)
    .await
    .with_context(Ctx::query_resource())?;

    let http = reqwest::Client::new();
    let (allow_noop_redeploy, reservation) = match existing {
        Some((_, lifecycle, nothing_live)) if lifecycle == "deployments" => {
            // `reserve` refuses a state that cannot take a push (409) under
            // the app lock, before `receive-pack` runs.
            let deployment_id = match reserve_deployment(
                &http,
                api_service_url,
                internal_service_secret.as_deref(),
                app_uuid,
                org_id,
                user_id,
            )
            .await
            {
                Ok(deployment_id) => deployment_id,
                Err(source) => {
                    let client_message = source.client_message();
                    return Err(source).with_context(Ctx::reserve(client_message));
                }
            };
            // An unchanged ref rebuilds HEAD only while nothing is live;
            // with a live deployment it creates no deployment.
            (nothing_live, Some(deployment_id))
        }
        Some((state, _, _)) => {
            if state == "running" || state == "stopped" {
                return Err(HandleGitPushError::RunningApp {
                    app_id: app_id.to_string(),
                    state,
                    location: std::panic::Location::caller(),
                });
            }
            tracing::info!(
                "App '{}' exists in state '{}', allowing push",
                app_id,
                state
            );
            (resource_state_allows_noop_redeploy(&state), None)
        }
        None => {
            return Err(HandleGitPushError::AppNotFound {
                app_id: app_id.to_string(),
                location: std::panic::Location::caller(),
            });
        }
    };
    // No-op for Legacy (`reservation` is None).
    let release_reservation = || {
        release_deployment_reservation(
            &http,
            api_service_url,
            internal_service_secret.as_deref(),
            reservation,
        )
    };

    let repo_path = format!("{}/git-repos/{}.git", data_dir, app_id);
    if let Err(source) = ensure_git_repo_exists(&repo_path) {
        release_reservation().await;
        return Err(source).with_context(Ctx::ensure_repo());
    }
    let (push_hook_dir, push_ref_log_path) = match prepare_push_ref_hook() {
        Ok(hook) => hook,
        Err(source) => {
            release_reservation().await;
            return Err(source).with_context(Ctx::prepare_hook());
        }
    };
    let hooks_path = push_hook_dir.path().to_path_buf();

    tracing::info!("Spawning git receive-pack for {}", repo_path);

    let mut child = match tokio::process::Command::new("git")
        .arg("-c")
        .arg(format!("core.hooksPath={}", hooks_path.display()))
        .arg("receive-pack")
        .arg(&repo_path)
        .env("CAUTION_PUSH_REF_LOG", &push_ref_log_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(source) => {
            release_reservation().await;
            return Err(source).with_context(Ctx::spawn_receive_pack());
        }
    };

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
        // Every failed exit releases the reservation; this is a no-op once
        // the API has claimed it.
        let release_reservation = || {
            release_deployment_reservation(
                &http,
                &api_service_url,
                internal_service_secret.as_deref(),
                reservation,
            )
        };

        let stdout_task = {
            let handle = session_handle.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    match stdout.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            tracing::debug!("Git stdout: {} bytes", n);
                            if let Err(e) = handle
                                .data(channel, Bytes::copy_from_slice(&buf[..n]))
                                .await
                            {
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
                                .extended_data(channel, 1, Bytes::copy_from_slice(&buf[..n]))
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
                        drop(processes);
                        release_reservation().await;
                        let error_msg = "remote: error: Failed to complete git receive-pack\n";
                        let _ = session_handle
                            .extended_data(channel, 1, Bytes::from(error_msg))
                            .await;
                        let _ = session_handle.exit_status_request(channel, 1).await;
                        let _ = session_handle.close(channel).await;
                        return;
                    }
                }
            } else {
                tracing::error!("Git process not found in map");
                drop(processes);
                release_reservation().await;
                return;
            }
        };

        if !exit_status.success() {
            let exit_code = exit_status.code().unwrap_or(1);
            tracing::error!("Git receive-pack failed with exit code: {}", exit_code);
            release_reservation().await;
            let _ = session_handle
                .exit_status_request(channel, exit_code as u32)
                .await;
            let _ = session_handle.close(channel).await;
            return;
        }

        tracing::info!("Git receive-pack completed successfully");

        let pushed_ref = match read_pushed_branch_ref(&push_ref_log_path) {
            Ok(PushedBranchSelection::One(pushed_ref)) => pushed_ref,
            // A client that vanished mid-pack leaves receive-pack exiting 0
            // with no ref updated: that is not a request to redeploy HEAD.
            Ok(PushedBranchSelection::None)
                if allow_noop_redeploy && !session_closed.load(Ordering::SeqCst) =>
            {
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
                            .extended_data(channel, 1, Bytes::from(msg.into_bytes()))
                            .await;
                        head_ref
                    }
                    Ok(None) => {
                        tracing::info!(
                            "No branch refs updated and no deployable HEAD; skipping deployment"
                        );
                        release_reservation().await;
                        let msg = "\nremote: No branch updates; skipping deployment.\n".to_string();
                        let _ = session_handle
                            .extended_data(channel, 1, Bytes::from(msg.into_bytes()))
                            .await;
                        let _ = session_handle.exit_status_request(channel, 0).await;
                        let _ = session_handle.close(channel).await;
                        return;
                    }
                    Err(e) => {
                        tracing::error!("Failed to resolve repo HEAD for no-op push: {}", e);
                        release_reservation().await;
                        let msg = "remote: error: Failed to resolve deploy branch\n".to_string();
                        let _ = session_handle
                            .extended_data(channel, 1, Bytes::from(msg.into_bytes()))
                            .await;
                        let _ = session_handle.exit_status_request(channel, 1).await;
                        let _ = session_handle.close(channel).await;
                        return;
                    }
                }
            }
            Ok(PushedBranchSelection::None) => {
                tracing::info!("No branch refs updated; skipping deployment");
                release_reservation().await;
                let msg = "\nremote: No branch updates; skipping deployment.\n".to_string();
                let _ = session_handle
                    .extended_data(channel, 1, Bytes::from(msg.into_bytes()))
                    .await;
                let _ = session_handle.exit_status_request(channel, 0).await;
                let _ = session_handle.close(channel).await;
                return;
            }
            Ok(PushedBranchSelection::Multiple) => {
                tracing::warn!("Multiple branch refs updated; skipping deployment");
                release_reservation().await;
                let msg =
                    "\nremote: warning: Multiple branches updated; push one branch to deploy.\n"
                        .to_string();
                let _ = session_handle
                    .extended_data(channel, 1, Bytes::from(msg.into_bytes()))
                    .await;
                let _ = session_handle.exit_status_request(channel, 0).await;
                let _ = session_handle.close(channel).await;
                return;
            }
            Err(e) => {
                tracing::error!("Failed to read pushed branch refs: {}", e);
                release_reservation().await;
                let msg = "remote: error: Failed to read pushed refs\n".to_string();
                let _ = session_handle
                    .extended_data(channel, 1, Bytes::from(msg.into_bytes()))
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
            .extended_data(channel, 1, Bytes::from(deploy_ref_msg.into_bytes()))
            .await;
        if let Some(deployment_id) = reservation {
            let _ = session_handle
                .extended_data(
                    channel,
                    1,
                    Bytes::from(accepted_message(deployment_id).into_bytes()),
                )
                .await;
        }

        #[derive(serde::Serialize)]
        struct DeployRequest {
            org_id: Uuid,
            app_id: Uuid,
            branch: String,
            commit_sha: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            deployment_id: Option<Uuid>,
        }

        let app_uuid = Uuid::parse_str(&app_id).expect("Already validated app_id");
        tracing::info!(
            "Triggering deployment for {} (branch: {}, commit: {})",
            app_id,
            branch,
            commit_sha
        );

        let deploy_url = format!("{}/deploy", api_service_url);

        let mut request = http
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
                deployment_id: reservation,
            })
            .timeout(std::time::Duration::from_secs(7200))
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                tracing::error!("Failed to send deployment request: {}", e);
                release_reservation().await;
                let error_msg =
                    "remote: error: Failed to trigger deployment, please try again later.\n"
                        .to_string();
                let _ = session_handle
                    .extended_data(channel, 1, Bytes::from(error_msg.into_bytes()))
                    .await;
                let _ = session_handle.exit_status_request(channel, 1).await;
                let _ = session_handle.close(channel).await;
                return;
            }
        };

        if !response.status().is_success() {
            let status = response.status();
            let mut message = "Deployment failed, please try again later.".to_string();
            let mut guidance = Vec::new();
            if status.is_client_error() {
                tracing::warn!(%status, "Deployment rejected");
                if let Ok(rejection) = response.json::<DeployErrorResponse>().await {
                    if !rejection.error.is_empty()
                        && rejection.error.len() <= 1024
                        && !rejection.error.chars().any(char::is_control)
                    {
                        message = rejection.error;
                    }
                    guidance = deploy_error_guidance(&rejection.notes, &rejection.warnings);
                }
            } else {
                tracing::error!(%status, "Deployment failed");
            }
            release_reservation().await;
            let mut error_msg = format!("remote: error: {message}\n");
            for line in &guidance {
                error_msg.push_str(&format!("remote: {line}\n"));
            }
            let _ = session_handle
                .extended_data(channel, 1, Bytes::from(error_msg.into_bytes()))
                .await;
            let _ = session_handle.exit_status_request(channel, 1).await;
            let _ = session_handle.close(channel).await;
            return;
        }

        #[derive(serde::Deserialize)]
        struct DeployResponse {
            url: String,
            resource_id: String,
            #[serde(rename = "public_ip")]
            _public_ip: String,
            domain: Option<String>,
            #[serde(default)]
            managed_hostname: Option<String>,
            #[serde(default)]
            dns_status: Option<String>,
            #[serde(default)]
            dns_error: Option<String>,
            #[serde(default)]
            deployment_id: Option<Uuid>,
            #[serde(default)]
            role: Option<String>,
            #[serde(default)]
            live_deployment_id: Option<Uuid>,
            #[serde(default)]
            tls_after_switch: bool,
        }

        #[derive(serde::Deserialize)]
        struct DeployErrorResponse {
            error: String,
            #[serde(default)]
            status: Option<u16>,
            /// Guidance the API attaches to the failure: what to do about it.
            #[serde(default)]
            notes: Vec<String>,
            #[serde(default)]
            warnings: Vec<String>,
        }

        // Stream line-oriented deployment progress to the SSH client. Keep this
        // output free of carriage returns and other terminal controls so Git can
        // pass it through in versions that reject non-color terminal escapes.
        let mut stream = response.bytes_stream();
        let mut last_line = String::new();
        let mut buffer = String::new();
        let mut current_milestone: Option<(String, Instant)> = None;
        let mut stream_reported_error = false;

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
                            if let Some((_milestone, start_time)) = current_milestone.take() {
                                let elapsed = start_time.elapsed();
                                let done_msg = deploy_progress_completed_message(elapsed);
                                if !done_msg.is_empty() {
                                    let _ = session_handle
                                        .extended_data(
                                            channel,
                                            1,
                                            Bytes::from(done_msg.into_bytes()),
                                        )
                                        .await;
                                }
                            }
                            last_line = line;
                        } else if let Some(step_msg) = line.strip_prefix("STEP:") {
                            if let Some((_prev_milestone, start_time)) = current_milestone.take() {
                                let elapsed = start_time.elapsed();
                                let done_msg = deploy_progress_completed_message(elapsed);
                                if !done_msg.is_empty() {
                                    let _ = session_handle
                                        .extended_data(
                                            channel,
                                            1,
                                            Bytes::from(done_msg.into_bytes()),
                                        )
                                        .await;
                                }
                            }

                            let milestone_text = step_msg.to_string();
                            let step_msg = deploy_progress_started_message(&milestone_text);
                            let _ = session_handle
                                .extended_data(channel, 1, Bytes::from(step_msg.into_bytes()))
                                .await;
                            current_milestone = Some((milestone_text, Instant::now()));
                        } else if !line.is_empty() {
                            let failed = line.starts_with("error:");
                            if let Some((_milestone, start_time)) = current_milestone.take() {
                                let elapsed = start_time.elapsed();
                                let done_msg = deploy_progress_finished_message(elapsed, failed);
                                if !done_msg.is_empty() {
                                    let _ = session_handle
                                        .extended_data(
                                            channel,
                                            1,
                                            Bytes::from(done_msg.into_bytes()),
                                        )
                                        .await;
                                }
                            }
                            if line.starts_with("error:") {
                                stream_reported_error = true;
                            }
                            let msg = format!("remote: {}\n", line);
                            let _ = session_handle
                                .extended_data(channel, 1, Bytes::from(msg.into_bytes()))
                                .await;
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Error reading deployment stream: {}", e);
                    let error_msg = interrupted_message(reservation, &e);
                    let _ = session_handle
                        .extended_data(channel, 1, Bytes::from(error_msg.into_bytes()))
                        .await;
                    // No-op once the API claimed the reservation. After the
                    // message: the API may be unreachable and the client has no timeout.
                    release_reservation().await;
                    let _ = session_handle.exit_status_request(channel, 1).await;
                    let _ = session_handle.close(channel).await;
                    return;
                }
            }
        }

        // Handle any remaining content in buffer
        if let Some((_milestone, start_time)) = current_milestone.take() {
            let elapsed = start_time.elapsed();
            let done_msg = deploy_progress_completed_message(elapsed);
            if !done_msg.is_empty() {
                let _ = session_handle
                    .extended_data(channel, 1, Bytes::from(done_msg.into_bytes()))
                    .await;
            }
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
                    // A failure before the API claimed the reservation would
                    // keep the app busy until it expires; after the claim this
                    // is a no-op (only `reserved` rows are released).
                    release_reservation().await;
                    // The stream reported the message as a progress line; the
                    // guidance is new, so print it either way.
                    let mut output = String::new();
                    if !stream_reported_error {
                        output.push_str(&format!("remote: error: {}\n", api_error.error));
                    }
                    for line in deploy_error_guidance(&api_error.notes, &api_error.warnings) {
                        output.push_str(&format!("remote: {line}\n"));
                    }
                    if !output.is_empty() {
                        let _ = session_handle
                            .extended_data(channel, 1, Bytes::from(output.into_bytes()))
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
                let error_msg = "remote: error: Invalid deployment response\n";
                let _ = session_handle
                    .extended_data(channel, 1, Bytes::from(error_msg))
                    .await;
                // No-op once the API claimed the reservation. After the
                // message: the API may be unreachable and the client has no timeout.
                release_reservation().await;
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

        let dns_note = managed_dns_note(
            deploy_result.managed_hostname.as_deref(),
            deploy_result.dns_status.as_deref(),
            deploy_result.dns_error.as_deref(),
            deploy_result.domain.as_deref(),
        );

        let success_msg = match (deploy_result.role.as_deref(), deploy_result.deployment_id) {
            (Some("candidate"), Some(deployment_id)) => candidate_success_message(
                deployment_id,
                deploy_result.live_deployment_id,
                &deploy_result.url,
                deploy_result.tls_after_switch,
            ),
            (_, deployment_id) => {
                let deployment_line = deployment_id
                    .map(|id| ["\nDeployment: ", &id.to_string(), " (live)"].concat())
                    .unwrap_or_default();
                let tls_line = match deployment_id {
                    Some(id) if deploy_result.tls_after_switch => [
                        "\nApplication TLS verification pending: the certificate is issued now that this deployment is live. Run caution verify -d ",
                        &id.to_string(),
                        " once HTTPS answers.",
                    ]
                    .concat(),
                    _ => String::new(),
                };
                format!(
                    "\nApplication: {}\nAttestation: {}{}{}{}\n\nRun 'caution verify' to verify the application attestation against this checkout.\n\n",
                    deploy_result.url, attestation_url, deployment_line, tls_line, dns_note
                )
            }
        };
        let _ = session_handle
            .extended_data(channel, 1, Bytes::from(success_msg.into_bytes()))
            .await;
        let _ = session_handle.exit_status_request(channel, 0).await;
        let _ = session_handle.close(channel).await;
    });

    Ok(())
}

fn managed_dns_note(
    hostname: Option<&str>,
    status: Option<&str>,
    error: Option<&str>,
    domain: Option<&str>,
) -> String {
    let Some(hostname) = hostname else {
        return String::new();
    };
    let mut note = ["\nDNS target: ", hostname, "\n"].concat();
    if let Some(status) = status {
        note.push_str("Managed DNS: ");
        note.push_str(status);
        note.push('\n');
    }
    if let Some(error) = error {
        note.push_str("Managed DNS retry error: ");
        note.push_str(error);
        note.push('\n');
    }
    if let Some(domain) = domain {
        note.push_str("Create a CNAME for ");
        note.push_str(domain);
        note.push_str(" pointing to ");
        note.push_str(hostname);
        note.push('\n');
    }
    note
}

/// Build the SSH server config.
///
/// The default `Preferred` algorithm set leads with the post-quantum
/// `mlkem768x25519-sha256` key exchange, so clients (incl. recent OpenSSH)
/// negotiate a PQ kex and avoid "store now, decrypt later" warnings. We rely
/// on that default rather than hand-rolling a kex list so we stay current as
/// russh adds algorithms.
fn ssh_server_config(host_key: PrivateKey) -> russh::server::Config {
    russh::server::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        // Keep silent deploy phases alive without writing into Git's output channel.
        keepalive_interval: Some(std::time::Duration::from_secs(30)),
        keepalive_max: 3,
        auth_rejection_time: std::time::Duration::from_secs(3),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![host_key],
        ..Default::default()
    }
}

#[tracing::instrument(skip_all, fields(bind_addr = %bind_addr))]
pub async fn run_ssh_server(
    pool: PgPool,
    api_service_url: String,
    data_dir: String,
    internal_service_secret: Option<String>,
    host_key: PrivateKey,
    bind_addr: &str,
) -> Result<(), RunSshServerError> {
    use RunSshServerErrorCtx as Ctx;

    let config = Arc::new(ssh_server_config(host_key));

    let mut server = SshServer::new(pool, api_service_url, data_dir, internal_service_secret);

    tracing::info!("Starting SSH server on {}", bind_addr);

    server
        .run_on_address(config, bind_addr)
        .await
        .with_context(Ctx::listen())?;

    Ok(())
}

#[cfg(test)]
#[path = "ssh_server_connection_tests.rs"]
mod connection_tests;

#[cfg(test)]
mod tests {
    use super::{
        contains_non_line_terminal_control, deploy_error_guidance,
        deploy_progress_completed_message, deploy_progress_finished_message,
        deploy_progress_started_message, managed_dns_note, parse_pushed_branch_ref,
        resource_state_allows_noop_redeploy, PushedBranchSelection, ZERO_SHA1,
    };

    const OLD_SHA: &str = "1111111111111111111111111111111111111111";
    const MAIN_SHA: &str = "2222222222222222222222222222222222222222";
    const FEATURE_SHA: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn deploy_guidance_uses_managed_cname_target() {
        let note = managed_dns_note(
            Some("123e4567-e89b-12d3-a456-426614174000.apps.caution.sh"),
            Some("ready"),
            None,
            Some("app.example.com"),
        );
        assert!(note.contains("DNS target: 123e4567-e89b-12d3-a456-426614174000.apps.caution.sh"));
        assert!(note.contains("Create a CNAME for app.example.com pointing to"));
        assert!(!note.contains("DNS A record"));
        assert!(!note.contains("https://123e4567"));
    }

    #[test]
    fn deploy_error_guidance_keeps_one_clean_line_per_guidance() {
        let notes = vec![
            "  Purchase credits in Settings.  ".to_string(),
            // A repeated line is shown once.
            "Purchase credits in Settings.".to_string(),
            // A control character would break the line-oriented push output.
            "line\nbreak".to_string(),
            String::new(),
            "x".repeat(1025),
        ];
        let warnings = vec!["Nothing was stored.".to_string()];

        assert_eq!(
            deploy_error_guidance(&notes, &warnings),
            vec![
                "Purchase credits in Settings.".to_string(),
                "Nothing was stored.".to_string()
            ]
        );
    }

    #[test]
    fn deploy_progress_messages_are_git_safe_line_output() {
        // Started message should have no newline (cursor stays on same line)
        // Note: The "..." is already part of the milestone text from the source
        let started_msg = deploy_progress_started_message("Building enclave...");
        assert!(
            started_msg.starts_with("remote: "),
            "git progress should remain remote-prefixed: {started_msg:?}"
        );
        assert!(
            !started_msg.contains('\n'),
            "started message should NOT end with newline: {started_msg:?}"
        );
        assert!(
            !contains_non_line_terminal_control(&started_msg),
            "git progress must not contain carriage returns or terminal escape controls: {started_msg:?}"
        );

        // Completed message includes duration and ends with newline
        let elapsed = std::time::Duration::from_secs(2) + std::time::Duration::from_millis(300);
        let completed_msg = deploy_progress_completed_message(elapsed);
        assert!(
            completed_msg.contains("Complete!"),
            "completed message should contain 'Complete!': {completed_msg:?}"
        );
        assert!(
            completed_msg.contains("(2.3s)"),
            "completed message should include duration: {completed_msg:?}"
        );
        assert!(
            completed_msg.ends_with('\n'),
            "completed message should end with newline: {completed_msg:?}"
        );
    }

    #[test]
    fn deploy_progress_duration_format_minutes_and_seconds() {
        // Under 1 minute: format as seconds
        let msg = deploy_progress_completed_message(std::time::Duration::from_secs(45));
        assert!(msg.contains("(45.0s)"));

        // Over 1 minute: format as minutes and seconds
        let msg = deploy_progress_completed_message(std::time::Duration::from_secs(125));
        assert!(msg.contains("(2m5s)"));

        // Zero duration
        let msg = deploy_progress_completed_message(std::time::Duration::from_millis(100));
        assert!(msg.contains("(0.1s)"));
    }

    #[test]
    fn failed_deploy_progress_is_terminal_and_not_complete() {
        let msg = deploy_progress_finished_message(std::time::Duration::from_secs(125), true);
        assert_eq!(msg, " Failed (2m5s)\n");
        assert!(!msg.contains("Complete"));
    }

    #[test]
    fn public_key_line_fingerprints_to_openssh_value() {
        use russh::keys::PublicKey;

        // Same key/fingerprint as the golden vector in db::tests, verified with
        // `ssh-keygen -lf`. This exercises the real auth extraction path:
        // parse a key the way russh hands it to us, build the line, fingerprint.
        let pubkey = "ssh-ed25519 \
            AAAAC3NzaC1lZDI1NTE5AAAAIMBnPZP2DQ1v1MC9AQKLsNo0M649c6MVmz9O+P9UiBrT \
            test@example.com";
        let key = PublicKey::from_openssh(pubkey).unwrap();

        let line = super::public_key_line(&key);
        assert_eq!(
            line,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMBnPZP2DQ1v1MC9AQKLsNo0M649c6MVmz9O+P9UiBrT"
        );

        let fingerprint = crate::db::generate_ssh_fingerprint(&line).unwrap();
        assert_eq!(fingerprint, "vO7cKxkbEOoI4Qix7nsJMasdWsJHDFVfgXsKQrA0DhM");
    }

    #[test]
    fn ssh_config_offers_and_prefers_post_quantum_kex() {
        use russh::keys::{Algorithm, PrivateKey};

        let host_key = PrivateKey::random(&mut rand010::rng(), Algorithm::Ed25519).unwrap();
        let config = super::ssh_server_config(host_key);

        // The PQ hybrid kex must be offered...
        assert!(
            config
                .preferred
                .kex
                .contains(&russh::kex::MLKEM768X25519_SHA256),
            "server must offer the post-quantum mlkem768x25519-sha256 key exchange"
        );

        // ...and preferred over the classical algorithms, so a PQ-capable
        // client negotiates it instead of falling back to e.g. curve25519.
        assert_eq!(
            config.preferred.kex.first(),
            Some(&russh::kex::MLKEM768X25519_SHA256),
            "post-quantum kex must be the highest-priority algorithm"
        );
    }

    #[test]
    fn ssh_config_keeps_long_deploy_connections_alive() {
        use russh::keys::{Algorithm, PrivateKey};

        let host_key = PrivateKey::random(&mut rand010::rng(), Algorithm::Ed25519).unwrap();
        let config = super::ssh_server_config(host_key);

        assert_eq!(
            config.keepalive_interval,
            Some(std::time::Duration::from_secs(30))
        );
        assert_eq!(config.keepalive_max, 3);
    }

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
    fn running_app_error_preserves_identity_instructions() {
        let err = super::HandleGitPushError::RunningApp {
            app_id: "my-app".into(),
            state: "running".into(),
            location: std::panic::Location::caller(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("caution apps destroy my-app"),
            "must contain the destroy instruction: {msg}"
        );
        assert!(
            msg.contains("git push caution HEAD:main"),
            "must contain the redeploy instruction: {msg}"
        );
        assert!(
            msg.contains("Do not run `caution apps create`"),
            "must warn against creating a new app: {msg}"
        );
    }

    #[test]
    fn running_app_client_message_ignores_brackets_in_data() {
        // Regression: the channel writer used to strip the location suffix via
        // `to_string().rsplit_once(" [")`, which truncated at the LAST bracket.
        // A resource id containing " [" broke that. client_message() must return
        // the full guidance regardless of brackets in the interpolated data, and
        // must never leak the internal location segment.
        let err = super::HandleGitPushError::RunningApp {
            app_id: "weird [id]".into(),
            state: "run [ning]".into(),
            location: std::panic::Location::caller(),
        };
        let msg = err.client_message();
        assert_eq!(
            msg,
            "App 'weird [id]' is in state 'run [ning]'. In-place redeploy is not supported. \
             `caution apps destroy weird [id]` causes downtime and temporarily withdraws managed DNS. \
             After destroy completes, redeploy the same app ID, managed hostname, and any BYOC \
             linkage with `git push caution HEAD:main` using the existing remote. Do not run \
             `caution apps create` or plain `caution init`. For BYOC apps, do not run \
             `caution teardown --byoc`.",
            "client message must equal the fixed guidance with no location leak: {msg}"
        );
    }

    #[test]
    fn ensure_repo_client_message_is_fixed_and_location_free() {
        let err = super::HandleGitPushError::EnsureRepo {
            location: std::panic::Location::caller(),
            source: Box::new(std::io::Error::other("boom [detail]")),
        };
        assert_eq!(err.client_message(), "Failed to create git repos directory");
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

    #[test]
    fn candidate_success_message_points_at_next_commands() {
        let d1 = uuid::Uuid::from_u128(1);
        let d2 = uuid::Uuid::from_u128(2);
        let message = super::candidate_success_message(d2, Some(d1), "http://203.0.113.9", false);
        assert!(message.contains(&format!("Candidate deployment: {d2}")));
        assert!(message.contains(&format!("Live deployment: {d1} (unchanged)")));
        assert!(message.contains(&format!("caution verify -d {d2}")));
        assert!(message.contains(&format!("caution apps switch -d {d2}")));
        assert!(!super::contains_non_line_terminal_control(&message));
    }

    #[test]
    fn candidate_success_message_discloses_pending_tls() {
        let d2 = uuid::Uuid::from_u128(2);
        let message = super::candidate_success_message(d2, None, "http://203.0.113.9", true);
        assert!(message.contains(&format!(
            "Application TLS: this deployment obtains its certificate after caution apps switch -d {d2}."
        )));
        let message = super::candidate_success_message(d2, None, "http://203.0.113.9", false);
        assert!(!message.contains("Application TLS"));
    }

    #[test]
    fn accepted_message_names_the_deployment_and_follow_up() {
        let id = uuid::Uuid::from_u128(7);
        let message = super::accepted_message(id);
        assert!(message.contains(&format!(
            "Deployment {id} accepted. Disconnecting does not cancel it."
        )));
        assert!(message.contains(&format!("Follow it with: caution apps get -d {id}")));
        assert!(!super::contains_non_line_terminal_control(&message));
    }

    #[test]
    fn interrupted_message_names_the_abandoned_deployment_or_keeps_the_stream_error() {
        let id = uuid::Uuid::from_u128(7);
        let message = super::interrupted_message(Some(id), &"connection reset");
        assert!(message.contains(&format!("deployment {id} was abandoned")));
        assert!(message.contains("it may have restarted"));
        assert!(!message.contains("connection reset"));
        assert!(!super::contains_non_line_terminal_control(&message));
        // A Legacy push has no reservation to name.
        assert_eq!(
            super::interrupted_message(None, &"connection reset"),
            "remote: error: Stream error: connection reset\n"
        );
    }

    #[tokio::test]
    async fn closing_git_stdins_ends_a_receive_pack_blocked_on_stdin() {
        // Stands in for `git receive-pack` waiting on a client that vanished.
        let child = tokio::process::Command::new("cat")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let processes = tokio::sync::Mutex::new(std::collections::HashMap::from([(1u32, child)]));

        super::close_git_stdins(&processes);

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            // `try_wait`, unlike `wait`, does not close stdin itself.
            if let Some(status) = processes
                .lock()
                .await
                .get_mut(&1)
                .unwrap()
                .try_wait()
                .unwrap()
            {
                assert!(status.success());
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "child still blocked on stdin"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn dropping_a_session_marks_it_closed() {
        use russh::server::Server as _;

        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://user:pass@localhost/nonexistent")
            .unwrap();
        let mut server = super::SshServer::new(pool, String::new(), String::new(), None);
        let session = server.new_client(None);
        let closed = session.session_closed.clone();
        assert!(!closed.load(std::sync::atomic::Ordering::SeqCst));
        drop(session);
        assert!(closed.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn reservation_rejection_text_is_sanitized() {
        let ok = super::ReserveDeploymentError::Rejected {
            message: "Candidate limit reached (3 / 3).".to_string(),
            location: std::panic::Location::caller(),
        };
        assert_eq!(ok.client_message(), "Candidate limit reached (3 / 3).");
        let hostile = super::ReserveDeploymentError::Rejected {
            message: "bad\x1b[2Jtext".to_string(),
            location: std::panic::Location::caller(),
        };
        assert_eq!(hostile.client_message(), "Failed to reserve a deployment");
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
