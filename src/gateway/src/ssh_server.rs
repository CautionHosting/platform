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

    #[error("failed to write to git stdin [{location:?}]")]
    StdinWrite {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("protocol error [{location:?}]")]
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
    #[error("failed to create git repos directory [{location:?}]")]
    CreateDirectory {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to execute git init [{location:?}]")]
    GitInitSpawn {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("git init failed [{location:?}]")]
    GitInitFailed {
        stderr: String,
        #[location]
        location: Location,
    },
}

impl EnsureGitRepoExistsError {
    /// Returns the client-visible error message matching HEAD's anyhow Display
    /// output (the outermost `.context()` string or `bail!` message).
    fn client_message(&self) -> String {
        match self {
            Self::CreateDirectory { .. } => "Failed to create git repos directory".to_string(),
            Self::GitInitSpawn { .. } => "Failed to execute git init".to_string(),
            Self::GitInitFailed { stderr, .. } => {
                format!("Git init failed: {}", stderr)
            }
        }
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum PreparePushRefHookError {
    #[error("failed to create temporary git hook directory [{location:?}]")]
    CreateTempDir {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to write post-receive hook [{location:?}]")]
    WriteHook {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to stat post-receive hook [{location:?}]")]
    StatHook {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to make post-receive hook executable [{location:?}]")]
    SetPermissions {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl PreparePushRefHookError {
    /// Returns the client-visible error message matching HEAD's anyhow Display
    /// output (the `.context()` string for each failure path).
    fn client_message(&self) -> String {
        match self {
            Self::CreateTempDir { .. } => {
                "Failed to create temporary git hook directory".to_string()
            }
            Self::WriteHook { .. } => "Failed to write post-receive hook".to_string(),
            Self::StatHook { .. } => "Failed to stat post-receive hook".to_string(),
            Self::SetPermissions { .. } => {
                "Failed to make post-receive hook executable".to_string()
            }
        }
    }
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
    #[error("failed to read pushed ref log [{location:?}]")]
    Io {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to parse pushed ref log [{location:?}]")]
    Parse {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SetRepoHeadError {
    #[error("failed to update HEAD [{location:?}]")]
    CommandFailed {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum GetRepoHeadBranchError {
    #[error("failed to read repo HEAD [{location:?}]")]
    ReadHead {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to resolve repo HEAD branch [{location:?}]")]
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
pub(crate) enum HandleGitPushError {
    #[error("invalid app ID format [{location:?}]")]
    InvalidAppId {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },

    #[error("failed to check existing resource [{location:?}]")]
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

    /// Typed inner errors as unmarked fields: these feed `client_message()`
    /// directly (documented deviation, same pattern as `PasskeyError::Auth`).
    #[error("failed to ensure git repo exists [{location}]")]
    EnsureRepo {
        #[location]
        location: Location,
        source: EnsureGitRepoExistsError,
    },

    #[error("failed to prepare push ref hook [{location}]")]
    PrepareHook {
        #[location]
        location: Location,
        source: PreparePushRefHookError,
    },

    #[error("failed to spawn git receive-pack [{location:?}]")]
    SpawnReceivePack {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl HandleGitPushError {
    /// Returns the client-visible error message without the internal `[{location}]`
    /// suffix. Byte-identical to what HEAD's `bail!`/`.context(...)` produced via
    /// anyhow's Display (which only shows the outermost context string). For
    /// EnsureRepo and PrepareHook, this delegates to the inner error's own
    /// `client_message()` since at HEAD those propagated their specific message
    /// directly (no call-site `.context()` was added).
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
            Self::EnsureRepo { source, .. } => source.client_message(),
            Self::PrepareHook { source, .. } => source.client_message(),
            Self::SpawnReceivePack { .. } => "Failed to spawn git receive-pack".to_string(),
        }
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum RunSshServerError {
    #[error("failed to start SSH server [{location:?}]")]
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

#[cfg(test)]
fn contains_non_line_terminal_control(message: &str) -> bool {
    message.chars().any(|ch| ch.is_control() && ch != '\n')
}

impl russh::server::Handler for SshSession {
    type Error = SshHandlerError;

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

#[allow(clippy::too_many_arguments)]
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
) -> Result<(), HandleGitPushError> {
    use HandleGitPushErrorCtx as Ctx;

    let app_uuid = Uuid::parse_str(app_id).with_context(Ctx::invalid_app_id())?;

    let existing: Option<(String,)> = sqlx::query_as(
        "SELECT state::text FROM compute_resources
         WHERE id = $1 AND organization_id = $2",
    )
    .bind(app_uuid)
    .bind(org_id)
    .fetch_optional(pool)
    .await
    .with_context(Ctx::query_resource())?;

    let resource_state = match existing {
        Some((state,)) => {
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
            state
        }
        None => {
            return Err(HandleGitPushError::AppNotFound {
                app_id: app_id.to_string(),
                location: std::panic::Location::caller(),
            });
        }
    };
    let allow_noop_redeploy = resource_state_allows_noop_redeploy(&resource_state);

    let repo_path = format!("{}/git-repos/{}.git", data_dir, app_id);
    ensure_git_repo_exists(&repo_path).map_err(|source| HandleGitPushError::EnsureRepo {
        location: std::panic::Location::caller(),
        source,
    })?;
    let (push_hook_dir, push_ref_log_path) =
        prepare_push_ref_hook().map_err(|source| HandleGitPushError::PrepareHook {
            location: std::panic::Location::caller(),
            source,
        })?;
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
        .with_context(Ctx::spawn_receive_pack())?;

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
                            .extended_data(channel, 1, Bytes::from(msg.into_bytes()))
                            .await;
                        head_ref
                    }
                    Ok(None) => {
                        tracing::info!(
                            "No branch refs updated and no deployable HEAD; skipping deployment"
                        );
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
                    .extended_data(channel, 1, Bytes::from(error_msg.into_bytes()))
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
        }

        #[derive(serde::Deserialize)]
        struct DeployErrorResponse {
            error: String,
            #[serde(default)]
            status: Option<u16>,
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
                    let error_msg = format!("remote: error: Stream error: {}\n", e);
                    let _ = session_handle
                        .extended_data(channel, 1, Bytes::from(error_msg.into_bytes()))
                        .await;
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
                    if !stream_reported_error {
                        let error_msg = format!("remote: error: {}\n", api_error.error);
                        let _ = session_handle
                            .extended_data(channel, 1, Bytes::from(error_msg.into_bytes()))
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

        let success_msg = format!(
            "\nApplication: {}\nAttestation: {}{}\n\nRun 'caution verify' to verify the application attestation against this checkout.\n\n",
            deploy_result.url, attestation_url, dns_note
        );
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
mod tests {
    use super::{
        contains_non_line_terminal_control, deploy_progress_completed_message,
        deploy_progress_finished_message, deploy_progress_started_message, managed_dns_note,
        parse_pushed_branch_ref, resource_state_allows_noop_redeploy, PushedBranchSelection,
        ZERO_SHA1,
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
