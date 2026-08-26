// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::io;

use dterror::ResultExt as _;
use ratatui::{Terminal, backend::TestBackend};
use uuid::Uuid;

use super::render::{breadcrumb_text, detail_line, details_line, status_style};
use super::{
    RunTuiError, RunTuiErrorCtx, RunTuiStage, error_message, leave_alternate_screen, render,
};
use crate::{
    model::{
        Field, Page, RelatedResource, Relation, RelationSummary, Resource, ResourceKind,
        ResourceSummary,
    },
    state::AppState,
};

fn screen_lines(state: &mut AppState) -> Vec<String> {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).expect("test terminal");
    terminal
        .draw(|frame| render(frame, state, Some("0123456789abcdef")))
        .expect("render screen");
    terminal
        .backend()
        .buffer()
        .content
        .chunks(80)
        .map(|row| row.iter().map(|cell| cell.symbol()).collect())
        .collect()
}

fn screen_text(state: &mut AppState) -> String {
    screen_lines(state).join("\n")
}

fn user() -> Resource {
    Resource {
        kind: ResourceKind::User,
        id: Uuid::nil(),
        label: "alice".to_string(),
        fields: vec![Field {
            label: "Email",
            value: "alice@example.com".to_string(),
        }],
    }
}

fn organization() -> Resource {
    Resource {
        kind: ResourceKind::Organization,
        id: Uuid::nil(),
        label: "Alice Labs".to_string(),
        fields: vec![
            Field {
                label: "Status",
                value: "active".to_string(),
            },
            Field {
                label: "Credit balance",
                value: "$80.00".to_string(),
            },
            Field {
                label: "Credit state",
                value: "warning · dunning warning sent".to_string(),
            },
            Field {
                label: "BYOC plan",
                value: "3 Enclaves".to_string(),
            },
            Field {
                label: "Subscription status",
                value: "active".to_string(),
            },
            Field {
                label: "Billing source",
                value: "Credits".to_string(),
            },
            Field {
                label: "BYOC capacity",
                value: "1 / 2 used".to_string(),
            },
            Field {
                label: "Pending change",
                value: "A deliberately long pending subscription change that must be truncated"
                    .to_string(),
            },
            Field {
                label: "Created",
                value: "2026-08-25T10:00:00Z".to_string(),
            },
            Field {
                label: "Updated",
                value: "2026-08-26T10:00:00Z".to_string(),
            },
        ],
    }
}

fn app() -> Resource {
    Resource {
        kind: ResourceKind::App,
        id: Uuid::nil(),
        label: "alice-api".to_string(),
        fields: vec![
            Field {
                label: "State",
                value: "running".to_string(),
            },
            Field {
                label: "Organization",
                value: "Alice Labs".to_string(),
            },
            Field {
                label: "Mode",
                value: "BYOC".to_string(),
            },
            Field {
                label: "Provider",
                value:
                    "AWS · a deliberately long provider account name that cannot fit · EC2 Instance"
                        .to_string(),
            },
            Field {
                label: "Provider resource",
                value: "i-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string(),
            },
            Field {
                label: "Region",
                value: "eu-central-1".to_string(),
            },
            Field {
                label: "Public IP",
                value: "203.0.113.10".to_string(),
            },
            Field {
                label: "Domain",
                value: "a-deliberately-long-managed-application-domain.example.caution.co"
                    .to_string(),
            },
            Field {
                label: "DNS",
                value: "ready".to_string(),
            },
            Field {
                label: "Destroyed",
                value: "—".to_string(),
            },
            Field {
                label: "Created",
                value: "2026-08-25T10:00:00Z".to_string(),
            },
            Field {
                label: "Updated",
                value: "2026-08-26T10:00:00Z".to_string(),
            },
        ],
    }
}

#[test]
fn home_screen_renders_at_standard_terminal_size() {
    let mut state = AppState::new();
    let lines = screen_lines(&mut state);
    assert!(lines[0].starts_with("┌ CAUTION ADMIN · DEVELOPMENT"));
    assert!(lines[1].starts_with("│ Home"));
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("┌ Find user, organization, app, email, or UUID "))
    );
    assert!(lines.iter().any(|line| line.starts_with("┌ Browse all ")));

    let users = lines
        .iter()
        .position(|line| line.contains("Users"))
        .expect("users row");
    let organizations = lines
        .iter()
        .position(|line| line.contains("Organizations"))
        .expect("organizations row");
    let apps = lines
        .iter()
        .position(|line| line.contains("Apps"))
        .expect("apps row");
    assert!(lines[users].starts_with("│ > Users"));
    assert_eq!(organizations, users + 1);
    assert_eq!(apps, organizations + 1);
}

#[test]
fn resource_and_relationship_screens_render() {
    let mut state = AppState::new();
    state.open_search("alice".to_string(), None, vec![user().summary()]);
    let text = screen_text(&mut state);
    assert!(text.contains("Search “alice”"));
    assert!(text.contains("alice"));

    state.open_resource(
        user(),
        vec![RelationSummary {
            relation: Relation::UserApps,
            count: 2,
        }],
    );
    let text = screen_text(&mut state);
    assert!(text.contains("alice@example.com"));
    assert!(text.contains("Apps via organizations"));
    assert!(text.contains("┌ USER · alice "));
    assert!(text.contains("┌ Relationships "));

    state.open_related(
        user(),
        Relation::UserApps,
        Page {
            items: vec![RelatedResource {
                resource: ResourceSummary {
                    kind: ResourceKind::App,
                    id: Uuid::nil(),
                    label: "alice-api".to_string(),
                    context: Some("running".to_string()),
                },
                role: Some("owner".to_string()),
                via: None,
            }],
            offset: 0,
            limit: 50,
            has_more: false,
        },
    );
    let text = screen_text(&mut state);
    assert!(text.contains("alice-api"));
    assert!(text.contains("role: owner"));
}

#[test]
fn empty_error_and_help_states_render() {
    let mut state = AppState::new();
    state.open_search("nobody".to_string(), None, Vec::new());
    state.set_status("database query failed");
    let text = screen_text(&mut state);
    assert!(text.contains("No results"));
    assert!(text.contains("database query failed"));

    state.show_help = true;
    let text = screen_text(&mut state);
    assert!(text.contains("read-only development pilot"));
    assert!(text.contains("┌ Help "));
}

#[test]
fn resource_screens_fit_at_standard_terminal_size() {
    for resource in [user(), organization(), app()] {
        let expect_ellipsis = resource.kind != ResourceKind::User;
        let mut state = AppState::new();
        state.open_resource(
            resource,
            vec![RelationSummary {
                relation: Relation::AppOrganization,
                count: 1,
            }],
        );
        let text = screen_text(&mut state);
        assert!(text.contains("2026-08-26T10:00:00Z") || text.contains("alice@example.com"));
        assert!(text.contains("q quit"));
        if expect_ellipsis {
            assert!(text.contains('…'));
        }
    }
}

#[test]
fn breadcrumbs_and_statuses_have_clear_terminal_styles() {
    let mut state = AppState::new();
    state.open_search("alice".to_string(), None, vec![user().summary()]);
    assert_eq!(breadcrumb_text(&state, 80), "Search “alice”");
    assert_eq!(
        status_style("running").fg,
        Some(ratatui::style::Color::Green)
    );
    assert_eq!(
        status_style("pending").fg,
        Some(ratatui::style::Color::Yellow)
    );
    assert_eq!(
        status_style("terminated").fg,
        Some(ratatui::style::Color::Red)
    );

    let details = details_line("active · alice@example.com · role: owner".to_string());
    assert_eq!(
        details.spans[0].style.fg,
        Some(ratatui::style::Color::Green)
    );
    assert_eq!(details.spans[1].style.fg, None);
    assert_eq!(details.spans[2].style.fg, None);

    let detail = detail_line("Credit state", "suspended · dunning suspended".to_string());
    assert_eq!(detail.spans[1].style.fg, Some(ratatui::style::Color::Red));
    assert_eq!(detail.spans[2].style.fg, None);
    assert_eq!(detail.spans[3].style.fg, None);
}

#[test]
fn terminal_cleanup_emits_restore_commands() {
    let mut output = Vec::new();
    leave_alternate_screen(&mut output).expect("restore terminal commands");
    assert!(!output.is_empty());
}

#[test]
fn terminal_errors_show_their_actionable_cause() {
    let error: RunTuiError = Err::<(), _>(io::Error::other("draw failed"))
        .with_context(RunTuiErrorCtx::new(RunTuiStage::Draw))
        .expect_err("terminal draw must fail");

    assert_eq!(
        error_message(&error),
        "terminal explorer failed while drawing the screen: draw failed"
    );
}
