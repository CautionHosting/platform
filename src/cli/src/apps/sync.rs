// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::process::{Command, Output};

use dterror::{BoxError, CtxError, Location, ResultExt};

use super::crud::extract_resource_id_from_git_url;
use crate::{ApiClient, output};

/// Which `git` invocation in [`run`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyncGitErrorKind {
    /// Verify the checkout is a worktree and locate the current directory in it.
    VerifyWorktree,
    /// List existing remotes.
    ListRemotes,
    /// Create the canonical remote.
    AddRemote,
    /// Read the remote URLs in the local config file.
    ReadRemote,
    /// Read the remote URLs from every config scope, following includes.
    ReadEffectiveRemote,
    /// Repair the fetch URL.
    ConfigureRemote,
    /// Drop explicit push URLs so pushes follow the fetch URL.
    ClearPushUrl,
}

impl std::fmt::Display for SyncGitErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let command = match self {
            Self::VerifyWorktree => "git rev-parse --show-toplevel --show-prefix",
            Self::ListRemotes => "git remote",
            Self::AddRemote => "git remote add caution <url>",
            Self::ReadRemote => {
                "git config --local --show-origin --get-regexp ^remote\\.caution\\.(push)?url$"
            }
            Self::ReadEffectiveRemote => {
                "git config --show-origin --get-regexp ^remote\\.caution\\.(push)?url$"
            }
            Self::ConfigureRemote => "git config --local --replace-all remote.caution.url <url>",
            Self::ClearPushUrl => "git config --local --unset-all remote.caution.pushurl",
        };
        f.write_str(command)
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SyncError {
    #[error("failed to run `{kind}` [{location}]")]
    RunGit {
        kind: SyncGitErrorKind,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("`{kind}` failed: {message} [{location}]")]
    GitFailed {
        kind: SyncGitErrorKind,
        message: String,
        #[location]
        location: Location,
    },
    #[error(
        "run apps sync from the repository root, not {prefix}; checkout link was not changed [{location}]"
    )]
    NotRepoRoot {
        prefix: String,
        #[location]
        location: Location,
    },
    #[error("unable to verify app {app_id}; checkout link was not changed [{location}]")]
    FetchApp {
        app_id: String,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error(
        "API returned app {actual} instead of {expected}; checkout link was not changed [{location}]"
    )]
    IdMismatch {
        expected: String,
        actual: String,
        #[location]
        location: Location,
    },
    #[error(
        "API returned no valid Caution Git URL for app {app_id}; checkout link was not changed [{location}]"
    )]
    InvalidGitUrl {
        app_id: String,
        #[location]
        location: Location,
    },
    #[error(
        "git remote 'caution' has URLs set outside the repository's local config that sync does not manage: {entries}; remove them and retry. Checkout link was not changed [{location}]"
    )]
    InheritedRemoteUrl {
        entries: String,
        #[location]
        location: Location,
    },
    #[error(
        "Git remote was updated but deployment info could not be saved; retry apps sync after fixing the local file error [{location}]"
    )]
    SaveDeployment {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

/// Restore the current checkout's app identity and canonical fetch/push remote.
#[tracing::instrument(skip_all, err)]
pub(crate) async fn run(client: &ApiClient, id: uuid::Uuid) -> Result<(), SyncError> {
    use SyncErrorCtx as Ctx;

    let worktree = git(
        SyncGitErrorKind::VerifyWorktree,
        &["rev-parse", "--show-toplevel", "--show-prefix"],
    )?;
    // `.caution/` is read from the current directory but the remote is repository-wide,
    // so syncing from a subdirectory would leave the root linked to another app.
    let prefix = String::from_utf8_lossy(&worktree.stdout)
        .lines()
        .nth(1)
        .unwrap_or_default()
        .to_string();
    if !prefix.is_empty() {
        return Err(SyncError::NotRepoRoot {
            prefix,
            location: std::panic::Location::caller(),
        });
    }
    // Lines are `<origin>\t<key> <url>`; exit 1: no URL keys set.
    let url_keys = r"^remote\.caution\.(push)?url$";
    let local = git_allowing(
        SyncGitErrorKind::ReadRemote,
        &[
            "config",
            "--local",
            "--show-origin",
            "--get-regexp",
            url_keys,
        ],
        &[1],
    )?;
    let effective = git_allowing(
        SyncGitErrorKind::ReadEffectiveRemote,
        &["config", "--show-origin", "--get-regexp", url_keys],
        &[1],
    )?;
    let local = String::from_utf8_lossy(&local.stdout);
    let effective = String::from_utf8_lossy(&effective.stdout);
    let local: Vec<_> = local.lines().filter_map(parse_config_entry).collect();
    // Global, system, and included entries survive the local rewrite below and would
    // keep fetching or pushing to whatever they name, even after a later relink.
    let inherited: Vec<String> = effective
        .lines()
        .filter_map(parse_config_entry)
        .filter(|(origin, _, _)| !local.iter().any(|(local, _, _)| local == origin))
        .map(|(origin, entry, _)| format!("{entry} ({origin})"))
        .collect();
    if !inherited.is_empty() {
        return Err(SyncError::InheritedRemoteUrl {
            entries: inherited.join(", "),
            location: std::panic::Location::caller(),
        });
    }

    let id = id.to_string();
    let app = client
        .fetch_app(&id)
        .await
        .with_context(Ctx::fetch_app(&id))?;
    if app.id != id {
        return Err(SyncError::IdMismatch {
            expected: id,
            actual: app.id,
            location: std::panic::Location::caller(),
        });
    }
    if extract_resource_id_from_git_url(&app.git_url).as_deref() != Some(id.as_str()) {
        return Err(SyncError::InvalidGitUrl {
            app_id: id,
            location: std::panic::Location::caller(),
        });
    }

    let mut replaced: Vec<&str> = local
        .iter()
        .map(|(_, _, url)| *url)
        .filter(|url| *url != app.git_url)
        .collect();
    replaced.sort_unstable();
    replaced.dedup();
    for url in replaced {
        output::warning(format!(
            "Replacing git remote 'caution' URL {url} with {}",
            app.git_url
        ));
    }

    let remotes = git(SyncGitErrorKind::ListRemotes, &["remote"])?;
    if !String::from_utf8_lossy(&remotes.stdout)
        .lines()
        .any(|name| name == "caution")
    {
        git(
            SyncGitErrorKind::AddRemote,
            &["remote", "add", "caution", &app.git_url],
        )?;
    }
    git(
        SyncGitErrorKind::ConfigureRemote,
        &[
            "config",
            "--local",
            "--replace-all",
            "remote.caution.url",
            &app.git_url,
        ],
    )?;
    // A pinned pushurl would survive later `git remote set-url caution` relinks and keep
    // pushing to the old app. Exit 5: no pushurl was set.
    git_allowing(
        SyncGitErrorKind::ClearPushUrl,
        &["config", "--local", "--unset-all", "remote.caution.pushurl"],
        &[5],
    )?;
    client
        .save_deployment(&id)
        .with_context(Ctx::save_deployment())?;
    output::success(format!("Synced app {id} to .caution/deployment.json"));
    output::status(format!("Git remote 'caution': {}", app.git_url));
    Ok(())
}

/// Split a `git config --show-origin --get-regexp` line into origin, `<key> <url>`, and URL.
fn parse_config_entry(line: &str) -> Option<(&str, &str, &str)> {
    let (origin, entry) = line.split_once('\t')?;
    let (_, url) = entry.split_once(' ')?;
    Some((origin, entry, url))
}

fn git(kind: SyncGitErrorKind, args: &[&str]) -> Result<Output, SyncError> {
    git_allowing(kind, args, &[])
}

/// Run `git`, also treating the listed exit codes as success.
#[tracing::instrument(skip_all, err)]
fn git_allowing(
    kind: SyncGitErrorKind,
    args: &[&str],
    allowed_codes: &[i32],
) -> Result<Output, SyncError> {
    use SyncErrorCtx as Ctx;

    let output = Command::new("git")
        .args(args)
        .output()
        .with_context(Ctx::run_git(kind))?;
    if !output.status.success()
        && !output
            .status
            .code()
            .is_some_and(|code| allowed_codes.contains(&code))
    {
        return Err(SyncError::GitFailed {
            kind,
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            location: std::panic::Location::caller(),
        });
    }
    Ok(output)
}
