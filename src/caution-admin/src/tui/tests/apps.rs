// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use chrono::{TimeZone, Utc};
use uuid::Uuid;

use super::{resource, screen_text};
use crate::{
    model::{AppCounts, AppFilter, AppPage, Build, Page, ResourceKind, SortColumn},
    state::AppState,
};

fn build(status: &str) -> Build {
    Build {
        id: Uuid::from_u128(42),
        status: status.to_string(),
        commit_sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
        builder_instance_id: Some("i-0123456789abcdef0".to_string()),
        builder_instance_type: Some("m5.xlarge".to_string()),
        started_at: Some(Utc.with_ymd_and_hms(2026, 9, 2, 10, 1, 0).unwrap()),
        completed_at: Some(Utc.with_ymd_and_hms(2026, 9, 2, 10, 4, 0).unwrap()),
        created_at: Utc.with_ymd_and_hms(2026, 9, 2, 10, 0, 0).unwrap(),
    }
}

#[test]
fn app_browse_separates_counts_from_selectable_resources() {
    let mut state = AppState::new();
    state.open_apps(
        AppFilter::Current,
        AppPage {
            page: Page {
                items: vec![resource(ResourceKind::App, "api").summary()],
                offset: 0,
                limit: 50,
                has_more: false,
            },
            counts: AppCounts {
                current: 1,
                failed: 2,
                historical: 3,
                total: 6,
            },
        },
        SortColumn::Details,
    );

    let text = screen_text(&mut state);
    assert!(text.contains("App status"));
    assert!(text.contains("Current 1 · Failed 2 · Historical 3 · Total 6"));
    assert!(text.contains("Browse Apps · Current"));
    assert!(text.contains("f filter"));
    assert_eq!(state.current.rows.len(), 1);
}

#[test]
fn build_list_and_detail_are_clear_and_terminal_safe() {
    let app = resource(ResourceKind::App, "api").summary();
    let item = build("failed");
    let mut state = AppState::new();
    state.open_build_history(
        app.clone(),
        Page {
            items: vec![item.clone()],
            offset: 50,
            limit: 50,
            has_more: false,
        },
    );
    let text = screen_text(&mut state);
    assert!(text.contains("Builds · newest first · Page 2 · rows 51–51"));
    assert!(text.contains("STATUS"));
    assert!(text.contains("COMMIT"));
    assert!(text.contains("FAILURE"));
    assert!(text.contains("FAILED"));
    assert!(text.contains("Build failed"));

    state.open_build(app, item);
    let text = screen_text(&mut state);
    for label in [
        "Status:",
        "App:",
        "Commit:",
        "Builder instance:",
        "Builder type:",
        "Created:",
        "Started:",
        "Completed:",
        "Failure:",
    ] {
        assert!(text.contains(label), "missing {label}\n{text}");
    }
    assert!(text.contains("Build failed; inspect API/builder logs"));
}

#[test]
fn timeout_builds_use_a_coarse_failure_summary() {
    let app = resource(ResourceKind::App, "api").summary();
    let mut state = AppState::new();
    state.open_build(app, build("timeout"));

    let text = screen_text(&mut state);
    assert!(text.contains("Build timed out"));
}
