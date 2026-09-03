// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use drift_detector::drift::DriftSeverity;
use ratatui::{Terminal, backend::TestBackend};
use uuid::Uuid;

use super::render::{
    breadcrumb_text, detail_line, details_line, render, selection_style, status_style,
    terminal_text,
};
use crate::{
    aws::{
        AwsAction, AwsDisplayRow, AwsFinding, AwsHost, AwsHostPlatform, AwsOverviewMetadata,
        AwsSection, AwsSnapshot, FindingKind,
    },
    model::{
        Field, Page, Relation, RelationSummary, Resource, ResourceKind, ResourceSummary, SortColumn,
    },
    state::{AppState, Row, Screen, StatusLevel},
};

mod findings;
mod interaction;

fn lines_at(state: &mut AppState, width: u16, height: u16, sha: Option<&str>) -> Vec<String> {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test terminal");
    terminal
        .draw(|frame| render(frame, state, sha))
        .expect("render");
    terminal
        .backend()
        .buffer()
        .content
        .chunks(usize::from(width))
        .map(|row| row.iter().map(|cell| cell.symbol()).collect())
        .collect()
}

fn screen_text(state: &mut AppState) -> String {
    lines_at(state, 80, 24, Some("0123456789abcdef")).join("\n")
}

fn page(items: Vec<ResourceSummary>) -> Page<ResourceSummary> {
    Page {
        items,
        offset: 0,
        limit: 50,
        has_more: false,
    }
}

fn resource(kind: ResourceKind, label: &str) -> Resource {
    Resource {
        kind,
        id: Uuid::nil(),
        label: label.to_string(),
        fields: vec![
            Field {
                label: "Name",
                value: label.to_string(),
            },
            Field {
                label: "State",
                value: "running".to_string(),
            },
            Field {
                label: "Organization",
                value: "Acme".to_string(),
            },
            Field {
                label: "Provider",
                value: "AWS".to_string(),
            },
            Field {
                label: "Created",
                value: "2026-09-02T10:00:00Z".to_string(),
            },
        ],
    }
}

pub(super) fn aws_snapshot(findings: Vec<AwsFinding>) -> AwsSnapshot {
    AwsSnapshot {
        metadata: AwsOverviewMetadata {
            account: "123456789012".to_string(),
            principal: "caution-platform".to_string(),
            regions: "17 scanned · 7 with resources · 0 partial failures".to_string(),
            updated: "2026-09-02T10:00:00Z · r refresh".to_string(),
            status: "complete".to_string(),
        },
        overview: AwsSection::ALL
            .into_iter()
            .map(|section| AwsDisplayRow {
                kind: "AWS".to_string(),
                name: format!("{} (0)", section.label()),
                details: "active · available".to_string(),
                action: AwsAction::Section(section),
            })
            .collect(),
        app_hosts: vec![AwsDisplayRow {
            kind: "HOST".to_string(),
            name: "api".to_string(),
            details: "running · AWS host · Platform running".to_string(),
            action: AwsAction::Host("i-api".to_string()),
        }],
        builders: Vec::new(),
        hosts: vec![AwsHost {
            account: Some("123456789012".to_string()),
            instance: crate::aws::AwsInstance {
                instance_id: "i-api".to_string(),
                region: "us-west-2".to_string(),
                availability_zone: Some("us-west-2a".to_string()),
                launch_time_epoch_secs: Some(1_788_000_000),
                instance_type: Some("m6i.xlarge".to_string()),
                state: "running".to_string(),
                public_ip: Some("203.0.113.1".to_string()),
                private_ip: Some("10.0.0.1".to_string()),
                vpc_id: Some("vpc-1".to_string()),
                subnet_id: Some("subnet-1".to_string()),
                tags: std::collections::HashMap::from([
                    ("ManagedBy".to_string(), "caution+tofu".to_string()),
                    ("ResourceId".to_string(), Uuid::nil().to_string()),
                    ("ConfigDomain".to_string(), "api.example".to_string()),
                ]),
            },
            platform: Some(AwsHostPlatform {
                resource: resource(ResourceKind::App, "api").summary(),
                state: "running".to_string(),
                expected_host: Some("i-api".to_string()),
                account: Some("123456789012".to_string()),
                relation: "exact instance ID".to_string(),
            }),
        }],
        storage: Vec::new(),
        findings,
        costs: vec![
            AwsDisplayRow {
                kind: "MTD".to_string(),
                name: "Month to date".to_string(),
                details: "active · USD 10.00".to_string(),
                action: AwsAction::None,
            },
            AwsDisplayRow {
                kind: "SERVICE".to_string(),
                name: "EC2".to_string(),
                details: "active · USD 8.00".to_string(),
                action: AwsAction::None,
            },
        ],
        byoc: vec![AwsDisplayRow {
            kind: "ORGANIZATION".to_string(),
            name: "Acme".to_string(),
            details: "active · deployable · Growth".to_string(),
            action: AwsAction::Resource(resource(ResourceKind::Organization, "Acme").summary()),
        }],
        stale_reason: None,
        identity_available: true,
        inventory_available: true,
        inventory_complete: true,
        costs_available: true,
    }
}

fn finding(resources: Vec<ResourceSummary>) -> AwsFinding {
    AwsFinding {
        severity: DriftSeverity::Critical,
        kind: FindingKind::ExpectedHostAbsent,
        subject: "api".to_string(),
        platform: "running · expected EC2 i-api".to_string(),
        aws: "expected EC2 absent from complete region scan".to_string(),
        scope: None,
        host_id: None,
        resources,
    }
}

#[test]
fn home_search_resource_and_relationship_screens_render_at_80_by_24() {
    let mut state = AppState::new();
    assert!(screen_text(&mut state).contains("Browse all"));
    state.open_search(
        "api".to_string(),
        None,
        page(vec![resource(ResourceKind::App, "api").summary()]),
    );
    assert!(screen_text(&mut state).contains("┌ Resources "));
    state.open_resource(
        resource(ResourceKind::App, "api"),
        vec![RelationSummary {
            relation: Relation::AppOrganization,
            count: 1,
        }],
    );
    let text = screen_text(&mut state);
    assert!(text.contains("APP · api · RUNNING"));
    assert!(text.contains("Relationships"));
}

#[test]
fn resource_pages_show_range_and_active_sort_column() {
    let mut state = AppState::new();
    state.open_search(
        String::new(),
        Some(ResourceKind::App),
        Page {
            items: vec![resource(ResourceKind::App, "api").summary()],
            offset: 50,
            limit: 50,
            has_more: false,
        },
    );
    let text = screen_text(&mut state);
    assert!(text.contains("Page 2 · rows 51–51"));
    assert!(text.contains("DETAILS ↑"));
    assert!(text.contains("p/PgUp prev"));

    state.current.sort_rows(SortColumn::Name);
    assert!(screen_text(&mut state).contains("NAME ↑"));
}

#[test]
fn aws_loading_is_visible_without_replacing_the_current_screen() {
    let mut state = AppState::new();
    state.begin_aws_load(crate::state::AwsLoadMode::Open);

    let text = screen_text(&mut state);

    assert!(matches!(state.current.screen, Screen::Home));
    assert!(text.contains("Loading AWS snapshot"));
    assert!(text.contains("Backspace cancel"));
}

#[test]
fn opening_a_sorted_aws_section_selects_its_first_row() {
    let mut snapshot = aws_snapshot(Vec::new());
    snapshot.app_hosts = vec![
        AwsDisplayRow {
            kind: "HOST".to_string(),
            name: "stopped".to_string(),
            details: "stopped · AWS host".to_string(),
            action: AwsAction::None,
        },
        AwsDisplayRow {
            kind: "HOST".to_string(),
            name: "running".to_string(),
            details: "running · AWS host".to_string(),
            action: AwsAction::None,
        },
    ];
    let mut state = AppState::new();
    state.open_aws_overview(snapshot);
    state.open_aws_section(AwsSection::AppHosts);

    assert_eq!(state.current.selected, 0);
    assert!(matches!(state.selected_row(), Some(Row::Aws(row)) if row.name == "running"));
}

#[test]
fn finding_sort_defaults_to_critical_first() {
    let critical = finding(Vec::new());
    let mut warning = critical.clone();
    warning.severity = DriftSeverity::Warning;
    warning.subject = "warning".to_string();
    let mut state = AppState::new();
    state.open_aws_overview(aws_snapshot(vec![warning, critical]));
    state.open_aws_section(AwsSection::Findings);
    assert!(matches!(
        state.current.rows.first(),
        Some(Row::AwsFinding(finding)) if finding.severity == DriftSeverity::Critical
    ));
    assert!(screen_text(&mut state).contains("LEVEL ↑"));
}

#[test]
fn aws_sections_use_section_specific_panels_and_tables() {
    let mut snapshot = aws_snapshot(Vec::new());
    snapshot.app_hosts.insert(
        0,
        AwsDisplayRow {
            kind: "HOST".to_string(),
            name: "stopped".to_string(),
            details: "stopped · AWS host · Platform stopped".to_string(),
            action: AwsAction::Host("i-stopped".to_string()),
        },
    );
    let mut state = AppState::new();
    state.open_aws_overview(snapshot);
    let text = screen_text(&mut state);
    assert!(text.contains("AWS · 123456789012 · COMPLETE"));
    assert!(text.contains("┌ Sections "));
    assert!(!text.contains("ACCOUNT"));

    state.open_aws_section(AwsSection::AppHosts);
    assert!(screen_text(&mut state).contains("┌ AWS resources "));
    assert!(matches!(
        state.current.rows.first(),
        Some(Row::Aws(row)) if row.details.starts_with("running")
    ));
    assert!(state.back());
    state.open_aws_section(AwsSection::Costs);
    let text = screen_text(&mut state);
    assert!(text.contains("Cost summary"));
    assert!(text.contains("Cost breakdown"));
    assert_eq!(
        state.current.rows.len(),
        1,
        "MTD is panel metadata, not a row"
    );
    assert!(state.back());
    state.open_aws_section(AwsSection::Byoc);
    let text = screen_text(&mut state);
    assert!(text.contains("BYOC scope"));
    assert!(text.contains("Organizations"));
}

#[test]
fn findings_have_a_dedicated_list_and_detail_screen() {
    let linked = resource(ResourceKind::App, "api").summary();
    let organization = resource(ResourceKind::Organization, "Acme").summary();
    let item = finding(vec![linked.clone(), organization.clone()]);
    let mut state = AppState::new();
    state.open_aws_overview(aws_snapshot(vec![item.clone()]));
    state.open_aws_section(AwsSection::Findings);
    let text = screen_text(&mut state);
    assert!(text.contains("Reconciliation summary"));
    assert!(text.contains("Findings: 1 critical · 0 warning"));
    assert!(text.contains("LEVEL"));
    assert!(text.contains("ISSUE"));
    assert!(text.contains("SUBJECT"));
    assert!(text.contains("App expects EC2; none observed"));
    assert!(!text.contains("PLATFORM → AWS"));
    assert!(!text.contains("running · expected EC2 i-api"));
    assert!(matches!(state.selected_row(), Some(Row::AwsFinding(_))));
    state.open_aws_finding(item);
    let text = screen_text(&mut state);
    assert!(text.contains("Platform expected:"));
    assert!(text.contains("AWS observed:"));
    assert!(text.contains("Next step:"));
    assert!(text.contains("┌ Platform resources "));
    assert_eq!(state.current.rows.len(), 2);
    assert!(matches!(state.selected_row(), Some(Row::Resource(resource)) if resource == &linked));
    assert!(
        state
            .current
            .rows
            .iter()
            .any(|row| matches!(row, Row::Resource(resource) if resource == &organization))
    );
}

#[test]
fn aws_only_finding_says_there_is_no_linked_resource() {
    let item = finding(Vec::new());
    let mut state = AppState::new();
    state.open_aws_overview(aws_snapshot(vec![item.clone()]));
    state.open_aws_section(AwsSection::Findings);
    state.open_aws_finding(item);
    assert!(screen_text(&mut state).contains("No linked Platform resource"));
    assert!(state.current.rows.is_empty());
}

#[test]
fn findings_and_host_rows_open_operational_host_details() {
    let linked = resource(ResourceKind::App, "api").summary();
    let mut item = finding(vec![linked]);
    item.kind = FindingKind::StateMismatch;
    item.host_id = Some("i-api".to_string());
    item.aws = "stopped EC2 i-api in us-west-2".to_string();
    item.scope = Some("Platform account 999999999999 · scanned account 123456789012".to_string());
    let snapshot = aws_snapshot(vec![item.clone()]);
    let host = snapshot.hosts[0].clone();
    let mut state = AppState::new();
    state.open_aws_overview(snapshot);
    state.open_aws_section(AwsSection::Findings);
    state.open_aws_finding(item);

    let text = screen_text(&mut state);
    assert!(text.contains("Platform expected:"));
    assert!(text.contains("AWS observed:"));
    assert!(text.contains("Scope:"));
    assert!(text.contains("AWS resource"));
    assert!(matches!(state.selected_row(), Some(Row::AwsHost(_))));

    state.open_aws_host(host);
    let text = screen_text(&mut state);
    for label in [
        "State:",
        "Account:",
        "Location:",
        "Launched:",
        "IPs:",
        "Network:",
        "ManagedBy:",
        "ResourceId:",
        "Platform:",
        "Finding:",
    ] {
        assert!(text.contains(label), "missing {label}\n{text}");
    }
    assert!(text.contains("Platform resources"));
    assert!(matches!(state.current.screen, Screen::AwsHost(_)));
}

#[test]
fn refresh_of_a_disappeared_host_returns_to_the_host_list() {
    let snapshot = aws_snapshot(Vec::new());
    let host = snapshot.hosts[0].clone();
    let mut state = AppState::new();
    state.open_aws_overview(snapshot);
    state.open_aws_section(AwsSection::AppHosts);
    state.open_aws_host(host);

    let mut refreshed = aws_snapshot(Vec::new());
    refreshed.hosts.clear();
    refreshed.app_hosts.clear();
    state.replace_aws(refreshed);

    assert!(matches!(
        state.current.screen,
        Screen::AwsSection(AwsSection::AppHosts)
    ));
    assert_eq!(
        state
            .current
            .status
            .as_ref()
            .map(|status| status.text.as_str()),
        Some("AWS host no longer present")
    );
}

#[test]
fn partial_and_stale_quality_are_explicit() {
    let mut snapshot = aws_snapshot(vec![finding(Vec::new())]);
    snapshot.inventory_complete = false;
    snapshot.metadata.status = "partial".to_string();
    snapshot.overview[3].name = "Findings (1+)".to_string();
    let mut state = AppState::new();
    state.open_aws_overview(snapshot.clone());
    assert!(screen_text(&mut state).contains("PARTIAL"));
    state.open_aws_section(AwsSection::Findings);
    assert!(screen_text(&mut state).contains("Partial; absence findings suppressed"));
    assert!(state.back());
    snapshot.mark_stale("refresh failed");
    state.replace_aws(snapshot);
    assert!(screen_text(&mut state).contains("STALE"));
}

#[test]
fn refresh_without_identity_keeps_the_consistent_previous_findings() {
    let item = finding(Vec::new());
    let previous = aws_snapshot(vec![item.clone()]);
    let mut refresh = aws_snapshot(Vec::new());
    refresh.identity_available = false;
    refresh.metadata.account = "Unavailable".to_string();
    refresh.app_hosts.clear();
    let merged = previous.merge_refresh(refresh);
    assert_eq!(merged.findings, vec![item]);
    assert_eq!(merged.app_hosts.len(), 1);
    assert_eq!(merged.metadata.account, "123456789012");
    assert_eq!(merged.metadata.status, "stale");
}

#[test]
fn statuses_and_terminal_text_are_safe_and_unambiguous() {
    assert_eq!(selection_style().fg, None);
    assert_eq!(
        selection_style().bg,
        Some(ratatui::style::Color::Rgb(36, 40, 52))
    );
    assert_eq!(
        status_style("complete").fg,
        Some(ratatui::style::Color::Green)
    );
    assert_eq!(
        status_style("partial").fg,
        Some(ratatui::style::Color::Yellow)
    );
    assert_eq!(
        status_style("initialized").fg,
        Some(ratatui::style::Color::Yellow)
    );
    let details = details_line("active · alice@example.com".to_string());
    assert_eq!(
        details.spans[0].style.fg,
        Some(ratatui::style::Color::Green)
    );
    assert_eq!(details.spans[2].style.fg, None);
    let byoc = detail_line(
        "BYOC state",
        "inactive · subscription cannot deploy".to_string(),
    );
    assert_eq!(byoc.spans[1].style.fg, Some(ratatui::style::Color::Red));
    assert_eq!(
        terminal_text("safe 日本語\u{1b}[31m\u{202e}spoof\n"),
        "safe 日本語\\u{1b}[31m\\u{202e}spoof\\n"
    );
}

#[test]
fn breadcrumbs_use_display_width_and_multibyte_sha_is_safe() {
    let mut state = AppState::new();
    state.open_search(
        "日本語組織テスト日本語組織テスト".to_string(),
        None,
        page(Vec::new()),
    );
    for width in [20_u16, 40, 80] {
        let text = breadcrumb_text(&state, width);
        assert!(ratatui::text::Span::raw(text).width() <= usize::from(width.saturating_sub(3)));
    }
    assert!(lines_at(&mut state, 80, 24, Some("aaaaaaaé0123"))[0].contains("aaaaaaaé"));
}

#[test]
fn typed_status_levels_render_without_string_matching() {
    let mut state = AppState::new();
    state.set_status("informational");
    assert_eq!(
        state.current.status.as_ref().unwrap().level,
        StatusLevel::Info
    );
    state.set_warning("warning");
    assert_eq!(
        state.current.status.as_ref().unwrap().level,
        StatusLevel::Warning
    );
    state.set_error("error");
    assert_eq!(
        state.current.status.as_ref().unwrap().level,
        StatusLevel::Error
    );
}

#[test]
fn every_screen_renders_at_small_terminal_sizes() {
    for (width, height) in [(80_u16, 24_u16), (40, 10), (20, 6), (10, 4), (1, 1)] {
        let mut state = AppState::new();
        state.open_resource(resource(ResourceKind::App, "api"), Vec::new());
        assert_eq!(
            lines_at(&mut state, width, height, None).len(),
            usize::from(height)
        );
    }
}

#[test]
fn back_restores_findings_selection() {
    let item = finding(Vec::new());
    let mut state = AppState::new();
    state.open_aws_overview(aws_snapshot(vec![item.clone()]));
    state.open_aws_section(AwsSection::Findings);
    let previous = state.current.clone();
    state.open_aws_finding(item);
    assert!(matches!(state.current.screen, Screen::AwsFinding(_)));
    assert!(state.back());
    assert_eq!(state.current, previous);
}
