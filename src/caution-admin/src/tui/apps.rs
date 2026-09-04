// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::{
    db::Database,
    model::{AppFilter, Build, ResourceSummary, SortColumn},
    state::{AppState, Screen},
};

use super::{TUI_PAGE_SIZE, error_message};

pub(super) async fn open_apps(database: &Database, state: &mut AppState) {
    let filter = AppFilter::Current;
    let sort = SortColumn::Details;
    match database.browse_apps(filter, 0, TUI_PAGE_SIZE, sort).await {
        Ok(result) => state.open_apps(filter, result, sort),
        Err(error) => state.set_error(error_message(&error)),
    }
}

pub(super) async fn cycle_filter(database: &Database, state: &mut AppState) {
    let Screen::Apps { filter, .. } = state.current.screen else {
        return;
    };
    let sort = state.current.sort.unwrap_or(SortColumn::Details);
    reload_apps(database, state, filter.next(), 0, sort, true).await;
}

pub(super) async fn reload_apps(
    database: &Database,
    state: &mut AppState,
    filter: AppFilter,
    offset: u32,
    sort: SortColumn,
    reset_selection: bool,
) {
    match database
        .browse_apps(filter, offset, TUI_PAGE_SIZE, sort)
        .await
    {
        Ok(result) => state.replace_apps(filter, result, sort, reset_selection),
        Err(error) => state.set_error(error_message(&error)),
    }
}

pub(super) async fn open_build_history(
    database: &Database,
    state: &mut AppState,
    app: ResourceSummary,
) {
    match database.list_builds(app.id, 0, TUI_PAGE_SIZE).await {
        Ok(page) => state.open_build_history(app, page),
        Err(error) => state.set_error(error_message(&error)),
    }
}

pub(super) async fn reload_builds(
    database: &Database,
    state: &mut AppState,
    app: &ResourceSummary,
    offset: u32,
    reset_selection: bool,
) {
    match database.list_builds(app.id, offset, TUI_PAGE_SIZE).await {
        Ok(page) => state.replace_builds(page, reset_selection),
        Err(error) => state.set_error(error_message(&error)),
    }
}

pub(super) fn open_build(state: &mut AppState, build: Build) {
    let Screen::BuildHistory { app } = state.current.screen.clone() else {
        state.set_error("build is unavailable from this screen");
        return;
    };
    state.open_build(app, build);
}

pub(super) async fn refresh_build(
    database: &Database,
    state: &mut AppState,
    app: ResourceSummary,
    build: Build,
) {
    match database.show_build(app.id, build.id).await {
        Ok(build) => state.replace_build(app, build),
        Err(error) => state.set_error(error_message(&error)),
    }
}
