// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use tokio::task::JoinHandle;

use crate::{
    aws::{self, AwsSnapshot, LoadSnapshotError},
    db::Database,
    state::{AppState, AwsLoadMode},
};

pub(super) struct PendingAwsLoad {
    mode: AwsLoadMode,
    task: JoinHandle<Result<AwsSnapshot, LoadSnapshotError>>,
}

impl PendingAwsLoad {
    pub(super) fn start(database: Database, state: &mut AppState, mode: AwsLoadMode) -> Self {
        state.begin_aws_load(mode);
        Self {
            mode,
            task: tokio::spawn(async move { aws::load_snapshot(&database).await }),
        }
    }

    pub(super) fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    pub(super) async fn finish(self, state: &mut AppState) {
        let mode = self.mode;
        state.finish_aws_load();
        match self.task.await {
            Ok(Ok(snapshot)) => apply(state, mode, snapshot),
            Ok(Err(error)) => fail(state, mode, super::error_message(&error)),
            Err(error) => {
                state.set_error(super::error_message(&error));
                state.should_quit = true;
            }
        }
    }

    pub(super) fn cancel(self, state: &mut AppState, notify: bool) {
        self.task.abort();
        state.finish_aws_load();
        if notify {
            state.set_status("AWS load canceled");
        }
    }
}

fn apply(state: &mut AppState, mode: AwsLoadMode, snapshot: AwsSnapshot) {
    match mode {
        AwsLoadMode::Open => state.open_aws_overview(snapshot),
        AwsLoadMode::Refresh => {
            let snapshot = match state.aws_cache.as_ref() {
                Some(previous) => previous.merge_refresh(snapshot),
                None => snapshot,
            };
            state.replace_aws(snapshot);
        }
    }
}

fn fail(state: &mut AppState, mode: AwsLoadMode, message: String) {
    if mode == AwsLoadMode::Refresh
        && let Some(mut snapshot) = state.aws_cache.clone()
    {
        snapshot.mark_stale("refresh failed; previous data retained");
        state.replace_aws(snapshot);
    }
    state.set_error(message);
}

#[cfg(test)]
mod tests {
    use std::io;

    use tokio::task::JoinHandle;

    use super::PendingAwsLoad;
    use crate::{
        aws::{AwsSnapshot, LoadSnapshotError},
        state::{AppState, AwsLoadMode, Screen},
        tui::tests::aws_snapshot,
    };

    #[tokio::test]
    async fn completed_open_applies_the_snapshot() {
        let snapshot = aws_snapshot(Vec::new());
        let task = tokio::spawn(async move { Ok::<_, LoadSnapshotError>(snapshot) });
        let mut state = AppState::new();
        state.begin_aws_load(AwsLoadMode::Open);

        PendingAwsLoad {
            mode: AwsLoadMode::Open,
            task,
        }
        .finish(&mut state)
        .await;

        assert!(matches!(state.current.screen, Screen::AwsOverview(_)));
        assert_eq!(state.aws_loading, None);
    }

    #[tokio::test]
    async fn failed_refresh_keeps_previous_data_and_marks_it_stale() {
        let snapshot = aws_snapshot(Vec::new());
        let mut state = AppState::new();
        state.open_aws_overview(snapshot);
        state.begin_aws_load(AwsLoadMode::Refresh);
        let task = tokio::spawn(async { Err(load_error("AWS request failed")) });

        PendingAwsLoad {
            mode: AwsLoadMode::Refresh,
            task,
        }
        .finish(&mut state)
        .await;

        assert_eq!(state.aws_loading, None);
        assert_eq!(state.aws_cache.as_ref().unwrap().metadata.status, "stale");
        assert!(
            state
                .current
                .status
                .as_ref()
                .unwrap()
                .text
                .contains("AWS request failed")
        );
    }

    #[tokio::test]
    async fn failed_initial_load_stays_home_and_shows_the_error() {
        let mut state = AppState::new();
        state.begin_aws_load(AwsLoadMode::Open);
        let task = tokio::spawn(async { Err(load_error("initial AWS request failed")) });

        PendingAwsLoad {
            mode: AwsLoadMode::Open,
            task,
        }
        .finish(&mut state)
        .await;

        assert_eq!(state.aws_loading, None);
        assert!(matches!(state.current.screen, Screen::Home));
        assert!(
            state
                .current
                .status
                .as_ref()
                .unwrap()
                .text
                .contains("initial AWS request failed")
        );
    }

    #[tokio::test]
    async fn cancellation_clears_loading_without_changing_screen() {
        let task: JoinHandle<Result<AwsSnapshot, LoadSnapshotError>> =
            tokio::spawn(std::future::pending());
        let mut state = AppState::new();
        state.begin_aws_load(AwsLoadMode::Open);

        PendingAwsLoad {
            mode: AwsLoadMode::Open,
            task,
        }
        .cancel(&mut state, true);

        assert_eq!(state.aws_loading, None);
        assert!(matches!(state.current.screen, Screen::Home));
        assert_eq!(state.current.status.unwrap().text, "AWS load canceled");
    }

    fn load_error(message: &str) -> LoadSnapshotError {
        LoadSnapshotError::Database {
            location: std::panic::Location::caller(),
            source: Box::new(io::Error::other(message)),
        }
    }
}
