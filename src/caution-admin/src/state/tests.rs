// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use uuid::Uuid;

use super::{AppState, Row, Screen};
use crate::model::{
    Field, Page, RelatedResource, Relation, RelationSummary, Resource, ResourceKind,
    ResourceSummary, SortColumn,
};

fn page(items: Vec<ResourceSummary>) -> Page<ResourceSummary> {
    Page {
        items,
        offset: 0,
        limit: 50,
        has_more: false,
    }
}

fn summary(label: &str) -> ResourceSummary {
    ResourceSummary {
        kind: ResourceKind::User,
        id: Uuid::nil(),
        label: label.to_string(),
        context: None,
    }
}

fn resource(kind: ResourceKind, label: &str) -> Resource {
    Resource {
        kind,
        id: Uuid::nil(),
        label: label.to_string(),
        fields: vec![Field {
            label: "Status",
            value: "active".to_string(),
        }],
    }
}

#[test]
fn back_restores_query_rows_and_selection() {
    let mut state = AppState::new();
    state.current.query = "alice".to_string();
    state.current.selected = 2;
    let previous = state.current.clone();
    state.open_search("alice".to_string(), None, page(vec![summary("alice")]));
    assert!(matches!(state.current.screen, Screen::Search { .. }));
    assert!(state.back());
    assert_eq!(state.current, previous);
}

#[test]
fn selection_is_clamped_at_both_ends() {
    let mut state = AppState::new();
    state.select_previous();
    for _ in 0..10 {
        state.select_next();
    }
    assert_eq!(state.current.selected, 3);
}

#[test]
fn result_pages_keep_navigation_metadata() {
    let mut state = AppState::new();
    state.open_search(
        "alice".to_string(),
        None,
        Page {
            items: vec![summary("alice")],
            offset: 0,
            limit: 50,
            has_more: true,
        },
    );
    let first = state.current.page.expect("page metadata");
    assert_eq!(first.page_number(), 1);
    assert!(first.has_more);
    assert_eq!(state.current.sort, Some(SortColumn::Details));

    state.replace_resources(
        Page {
            items: vec![summary("alice")],
            offset: 50,
            limit: 50,
            has_more: false,
        },
        SortColumn::Name,
        true,
    );
    let second = state.current.page.expect("second page metadata");
    assert_eq!(second.page_number(), 2);
    assert_eq!((second.first_row(), second.last_row()), (51, 51));
    assert_eq!(state.current.sort, Some(SortColumn::Name));
}

#[test]
fn refresh_keeps_the_selected_resource_identity() {
    let mut first = summary("first");
    first.id = Uuid::from_u128(1);
    let mut selected = summary("selected");
    selected.id = Uuid::from_u128(2);
    let mut state = AppState::new();
    state.open_search(
        String::new(),
        Some(ResourceKind::User),
        page(vec![first.clone(), selected.clone()]),
    );
    state.current.selected = 1;
    selected.label = "renamed".to_string();
    selected.context = Some("inactive".to_string());

    state.replace_resources(page(vec![selected, first]), SortColumn::Details, false);

    assert!(matches!(
        state.selected_row(),
        Some(Row::Resource(resource)) if resource.id == Uuid::from_u128(2)
    ));
}

#[test]
fn query_editing_is_limited_to_input_mode() {
    let mut state = AppState::new();
    state.begin_search();
    state.insert_query_char('a');
    assert_eq!(state.current.query, "a");
    state.open_search("alice".to_string(), None, page(vec![summary("alice")]));
    state.insert_query_char('b');
    assert_eq!(state.current.query, "alice");
}

#[test]
fn canceling_global_search_restores_the_previous_screen() {
    let mut state = AppState::new();
    state.open_search("alice".to_string(), None, page(vec![summary("alice")]));
    let previous = state.current.clone();

    state.begin_search();
    state.insert_query_char('x');
    state.cancel_input();

    assert_eq!(state.current, previous);
}

#[test]
fn home_contains_resource_roots_and_aws() {
    let state = AppState::new();
    assert_eq!(state.current.rows.len(), 4);
    assert!(
        state
            .current
            .rows
            .iter()
            .take(3)
            .all(|row| matches!(row, Row::Browse(_)))
    );
    assert!(matches!(state.current.rows.last(), Some(Row::AwsRoot)));
}

#[test]
fn breadcrumbs_follow_relationships_and_back() {
    let mut state = AppState::new();
    let user = resource(ResourceKind::User, "alice");
    let app = resource(ResourceKind::App, "api");
    state.open_search("alice".to_string(), None, page(vec![user.summary()]));
    state.open_resource(
        user.clone(),
        vec![RelationSummary {
            relation: Relation::UserApps,
            count: 1,
        }],
    );
    state.open_related(
        user,
        Relation::UserApps,
        Page {
            items: vec![RelatedResource {
                resource: app.summary(),
                role: Some("owner".to_string()),
                via: None,
            }],
            offset: 0,
            limit: 50,
            has_more: false,
        },
    );
    state.open_resource(app, Vec::new());
    assert_eq!(
        state.breadcrumbs(),
        [
            "Search “alice”",
            "User alice",
            "Apps via organizations",
            "App api"
        ]
    );
    assert!(state.back());
    assert_eq!(
        state.breadcrumbs(),
        ["Search “alice”", "User alice", "Apps via organizations"]
    );
}
