// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::process::{Command, Output};

use dterror::{BoxError, CtxError, Location, ResultExt};

use super::crud::extract_resource_id_from_git_url;
use crate::{ApiClient, output};

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum SyncError {
    #[error("failed to run git [{location}]")]
    RunGit {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("git command failed: {message} [{location}]")]
    GitFailed {
        message: String,
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

    git(&["rev-parse", "--show-toplevel"])?;
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

    let remotes = git(&["remote"])?;
    if !String::from_utf8_lossy(&remotes.stdout)
        .lines()
        .any(|name| name == "caution")
    {
        git(&["remote", "add", "caution", &app.git_url])?;
    }
    for key in ["remote.caution.url", "remote.caution.pushurl"] {
        git(&["config", "--local", "--replace-all", key, &app.git_url])?;
    }
    client
        .save_deployment(&id)
        .with_context(Ctx::save_deployment())?;
    output::success(format!("Synced app {id} to .caution/deployment.json"));
    output::status(format!("Git remote 'caution': {}", app.git_url));
    Ok(())
}

#[tracing::instrument(skip_all, err)]
fn git(args: &[&str]) -> Result<Output, SyncError> {
    use SyncErrorCtx as Ctx;

    let output = Command::new("git")
        .args(args)
        .output()
        .with_context(Ctx::run_git())?;
    if !output.status.success() {
        return Err(SyncError::GitFailed {
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            location: std::panic::Location::caller(),
        });
    }
    Ok(output)
}
