// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use drift_detector::drift::DriftSeverity;
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Padding, Paragraph, Row as TableRow, Table, TableState},
};

use crate::{
    aws::{AwsDisplayRow, AwsFinding, AwsHost, AwsOverviewMetadata, AwsSection},
    model::ResourceSummary,
    state::{AppState, Row},
};

use super::{
    detail_line, details_line, render_resource_table, selection_style, status_style, table_header,
    terminal_text, truncate_detail_value,
};

pub(super) fn render_overview(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &mut AppState,
    metadata: AwsOverviewMetadata,
) {
    let title = overview_title(&metadata);
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(4)])
        .split(area);
    let detail_width = usize::from(areas[0].width.saturating_sub(3));
    let lines = [
        ("Principal", metadata.principal),
        ("Regions", metadata.regions),
        ("Updated", metadata.updated),
    ]
    .into_iter()
    .map(|(label, value)| {
        detail_line(
            label,
            truncate_detail_value(label, &terminal_text(&value), detail_width),
        )
    })
    .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(lines).block(panel(title)), areas[0]);
    render_resource_table(frame, areas[1], state, Some(" Sections "));
}

pub(super) fn render_section(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &mut AppState,
    section: AwsSection,
) {
    match section {
        AwsSection::Findings => render_findings(frame, area, state),
        AwsSection::Costs => render_costs(frame, area, state),
        AwsSection::Byoc => render_byoc(frame, area, state),
        AwsSection::AppHosts | AwsSection::Builders | AwsSection::Storage => {
            render_resource_table(frame, area, state, Some(" AWS resources "));
        }
    }
}

pub(super) fn render_finding(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &mut AppState,
    finding: AwsFinding,
) {
    let detail_height = if finding.scope.is_some() { 9 } else { 8 };
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(detail_height),
            Constraint::Length(4),
            Constraint::Min(4),
        ])
        .split(area);
    let level = finding.severity.to_string();
    let detail_width = usize::from(areas[0].width.saturating_sub(3));
    let mut lines = vec![
        detail_line("Level", level),
        detail_line(
            "Subject",
            truncate_detail_value("Subject", &terminal_text(&finding.subject), detail_width),
        ),
        detail_line(
            "Platform expected",
            truncate_detail_value(
                "Platform expected",
                &terminal_text(&finding.platform),
                detail_width,
            ),
        ),
        detail_line(
            "AWS observed",
            truncate_detail_value("AWS observed", &terminal_text(&finding.aws), detail_width),
        ),
    ];
    if let Some(scope) = &finding.scope {
        lines.push(detail_line(
            "Scope",
            truncate_detail_value("Scope", &terminal_text(scope), detail_width),
        ));
    }
    lines.push(detail_line(
        "Next step",
        truncate_detail_value("Next step", finding.kind.next_step(), detail_width),
    ));
    frame.render_widget(
        Paragraph::new(lines).block(panel(Line::from(format!(" {} ", finding.kind.label())))),
        areas[0],
    );
    render_finding_host(frame, areas[1], state, &finding);
    if finding.resources.is_empty() {
        frame.render_widget(
            Paragraph::new("No linked Platform resource")
                .alignment(Alignment::Center)
                .block(panel(Line::from(" Platform resources "))),
            areas[2],
        );
    } else {
        let offset = usize::from(matches!(state.current.rows.first(), Some(Row::AwsHost(_))));
        render_platform_resources(frame, areas[2], state, offset, &finding.resources);
    }
}

fn render_finding_host(frame: &mut Frame<'_>, area: Rect, state: &AppState, finding: &AwsFinding) {
    let host = finding.host_id.as_deref().and_then(|id| {
        state
            .aws_cache
            .as_ref()?
            .hosts
            .iter()
            .find(|host| host.instance.instance_id == id)
    });
    let Some(host) = host else {
        frame.render_widget(
            Paragraph::new(if finding.host_id.is_some() {
                "AWS host unavailable in current snapshot"
            } else {
                "Expected EC2 was not observed"
            })
            .alignment(Alignment::Center)
            .block(panel(Line::from(" AWS resource "))),
            area,
        );
        return;
    };
    let rows = vec![TableRow::new([
        Cell::from("HOST").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from(terminal_text(&host.instance.instance_id)),
        Cell::from(details_line(format!(
            "{} · {} · {}",
            host.instance.state,
            host.instance
                .instance_type
                .as_deref()
                .unwrap_or("unknown type"),
            host.instance.region
        ))),
    ])];
    let table = standard_table(rows, " AWS resource ");
    let selected = matches!(state.current.rows.first(), Some(Row::AwsHost(_)))
        .then_some(state.current.selected)
        .filter(|selected| *selected == 0);
    let mut table_state = TableState::default().with_selected(selected);
    frame.render_stateful_widget(table, area, &mut table_state);
}

fn render_platform_resources(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &AppState,
    offset: usize,
    resources: &[ResourceSummary],
) {
    let rows = resources
        .iter()
        .map(|resource| {
            TableRow::new([
                Cell::from(resource.kind.singular().to_ascii_uppercase()).style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Cell::from(terminal_text(&resource.label)),
                Cell::from(details_line(resource.context.clone().unwrap_or_default())),
            ])
        })
        .collect();
    let table = standard_table(rows, " Platform resources ");
    let selected = state.current.selected.checked_sub(offset);
    let mut table_state = TableState::default().with_selected(selected);
    frame.render_stateful_widget(table, area, &mut table_state);
}

fn standard_table(rows: Vec<TableRow<'static>>, title: &'static str) -> Table<'static> {
    Table::new(
        rows,
        [
            Constraint::Length(14),
            Constraint::Percentage(38),
            Constraint::Fill(1),
        ],
    )
    .header(
        TableRow::new(["TYPE", "NAME", "DETAILS"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(panel(Line::from(title)))
    .row_highlight_style(selection_style())
    .highlight_symbol("> ")
}

pub(super) fn render_host(frame: &mut Frame<'_>, area: Rect, state: &mut AppState, host: AwsHost) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(14), Constraint::Min(4)])
        .split(area);
    let width = usize::from(areas[0].width.saturating_sub(3));
    let value = |label, value: String| {
        detail_line(
            label,
            truncate_detail_value(label, &terminal_text(&value), width),
        )
    };
    let instance = &host.instance;
    let launched = instance
        .launch_time_epoch_secs
        .and_then(|seconds| chrono::DateTime::from_timestamp(seconds, 0))
        .map_or_else(
            || "—".to_string(),
            |time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        );
    let tags = ["ConfigDomain", "org_id", "BuildId", "Name"]
        .into_iter()
        .filter_map(|key| instance.tags.get(key).map(|entry| format!("{key}={entry}")))
        .collect::<Vec<_>>()
        .join(" · ");
    let platform = host.platform.as_ref().map_or_else(
        || "unlinked".to_string(),
        |platform| {
            let account = platform
                .account
                .as_deref()
                .map_or(String::new(), |account| format!(" · account {account}"));
            format!(
                "{} {} · {} · expected {} · via {}{}",
                platform.resource.kind.singular(),
                platform.resource.label,
                platform.state,
                platform.expected_host.as_deref().unwrap_or("none"),
                platform.relation,
                account,
            )
        },
    );
    let finding = state
        .aws_cache
        .as_ref()
        .into_iter()
        .flat_map(|snapshot| &snapshot.findings)
        .filter(|finding| finding.host_id.as_deref() == Some(&instance.instance_id))
        .map(|finding| format!("{} {}", finding.severity, finding.kind.label()))
        .collect::<Vec<_>>()
        .join(" · ");
    let lines = vec![
        value("State", instance.state.clone()),
        value(
            "Account",
            host.account
                .clone()
                .unwrap_or_else(|| "unavailable".to_string()),
        ),
        value(
            "Location",
            format!(
                "{} · {}",
                instance.region,
                instance
                    .availability_zone
                    .as_deref()
                    .unwrap_or("unknown AZ")
            ),
        ),
        value(
            "Type",
            instance
                .instance_type
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
        ),
        value("Launched", launched),
        value(
            "IPs",
            format!(
                "public {} · private {}",
                instance.public_ip.as_deref().unwrap_or("—"),
                instance.private_ip.as_deref().unwrap_or("—")
            ),
        ),
        value(
            "Network",
            format!(
                "VPC {} · subnet {}",
                instance.vpc_id.as_deref().unwrap_or("—"),
                instance.subnet_id.as_deref().unwrap_or("—")
            ),
        ),
        value(
            "ManagedBy",
            instance
                .tags
                .get("ManagedBy")
                .cloned()
                .unwrap_or_else(|| "—".to_string()),
        ),
        value(
            "ResourceId",
            instance
                .tags
                .get("ResourceId")
                .or_else(|| instance.tags.get("caution:resource_id"))
                .cloned()
                .unwrap_or_else(|| "—".to_string()),
        ),
        value(
            "Tags",
            if tags.is_empty() {
                "—".to_string()
            } else {
                tags
            },
        ),
        value("Platform", platform),
        value(
            "Finding",
            if finding.is_empty() {
                "none".to_string()
            } else {
                finding
            },
        ),
    ];
    let title = Line::from(format!(
        " AWS HOST · {} · {} ",
        terminal_text(&instance.instance_id),
        terminal_text(&instance.state.to_ascii_uppercase())
    ));
    frame.render_widget(Paragraph::new(lines).block(panel(title)), areas[0]);
    if state.current.rows.is_empty() {
        frame.render_widget(
            Paragraph::new("No linked Platform resource")
                .alignment(Alignment::Center)
                .block(panel(Line::from(" Platform resources "))),
            areas[1],
        );
    } else {
        render_resource_table(frame, areas[1], state, Some(" Platform resources "));
    }
}

fn render_findings(frame: &mut Frame<'_>, area: Rect, state: &mut AppState) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(4)])
        .split(area);
    let snapshot = state.aws_cache.as_ref();
    let findings = snapshot.map_or(&[][..], |snapshot| snapshot.findings.as_slice());
    let critical = findings
        .iter()
        .filter(|finding| finding.severity == DriftSeverity::Critical)
        .count();
    let warning = findings.len().saturating_sub(critical);
    let inventory_available = snapshot.is_some_and(|snapshot| snapshot.inventory_available);
    let findings_summary = if inventory_available {
        format!("{critical} critical · {warning} warning")
    } else {
        "Unavailable".to_string()
    };
    let coverage = snapshot.map_or("Not scanned", |snapshot| {
        if !snapshot.inventory_available {
            "Not scanned"
        } else if snapshot.inventory_complete {
            "Complete"
        } else {
            "Partial; absence findings suppressed in failed regions"
        }
    });
    frame.render_widget(
        Paragraph::new(vec![
            detail_line("Findings", findings_summary),
            detail_line("Coverage", coverage.to_string()),
        ])
        .block(panel(Line::from(" Reconciliation summary "))),
        areas[0],
    );
    if !inventory_available {
        frame.render_widget(
            Paragraph::new("Findings unavailable because AWS inventory was not scanned")
                .alignment(Alignment::Center)
                .block(panel(Line::from(" Findings "))),
            areas[1],
        );
        return;
    }
    if state.current.rows.is_empty() {
        frame.render_widget(
            Paragraph::new("No findings")
                .alignment(Alignment::Center)
                .block(panel(Line::from(" Findings "))),
            areas[1],
        );
        return;
    }
    let rows = state
        .current
        .rows
        .iter()
        .filter_map(|row| match row {
            Row::AwsFinding(finding) => Some(finding_row(finding)),
            _ => None,
        })
        .collect::<Vec<_>>();
    let table = Table::new(
        rows,
        [
            Constraint::Length(11),
            Constraint::Length(34),
            Constraint::Fill(1),
        ],
    )
    .header(table_header(state, ["LEVEL", "ISSUE", "SUBJECT"]))
    .block(panel(Line::from(" Findings ")))
    .row_highlight_style(selection_style())
    .highlight_symbol("> ");
    let mut table_state = TableState::default().with_selected(Some(state.current.selected));
    frame.render_stateful_widget(table, areas[1], &mut table_state);
}

fn render_costs(frame: &mut Frame<'_>, area: Rect, state: &mut AppState) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(4)])
        .split(area);
    let costs = state
        .aws_cache
        .as_ref()
        .map(|snapshot| snapshot.costs.as_slice())
        .unwrap_or_default();
    let value = |kind: &str| {
        costs
            .iter()
            .find(|row| row.kind == kind)
            .map(|row| terminal_text(&row.details))
            .unwrap_or_else(|| "unavailable".to_string())
    };
    frame.render_widget(
        Paragraph::new(vec![
            detail_line("Month to date", value("MTD")),
            detail_line("Projected month end", value("FORECAST")),
        ])
        .block(panel(Line::from(" Cost summary "))),
        areas[0],
    );
    render_resource_table(frame, areas[1], state, Some(" Cost breakdown "));
}

fn render_byoc(frame: &mut Frame<'_>, area: Rect, state: &mut AppState) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(4)])
        .split(area);
    frame.render_widget(
        Paragraph::new(vec![
            detail_line("Scope", "Platform subscriptions only".to_string()),
            detail_line("Customer AWS", "not queried".to_string()),
        ])
        .block(panel(Line::from(" BYOC scope "))),
        areas[0],
    );
    render_resource_table(frame, areas[1], state, Some(" Organizations "));
}

fn panel(title: Line<'static>) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .padding(Padding::left(1))
        .title(title)
}

fn overview_title(metadata: &AwsOverviewMetadata) -> Line<'static> {
    Line::from(vec![
        Span::raw(" "),
        Span::styled(
            "AWS",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" · "),
        Span::styled(
            terminal_text(&metadata.account),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(" · "),
        Span::styled(
            metadata.status.to_ascii_uppercase(),
            status_style(&metadata.status),
        ),
        Span::raw(" "),
    ])
}

pub(super) fn table_row(row: &AwsDisplayRow) -> TableRow<'static> {
    TableRow::new([
        Cell::from(terminal_text(&row.kind)).style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from(terminal_text(&row.name)),
        Cell::from(details_line(row.details.clone())),
    ])
}

pub(super) fn finding_row(finding: &AwsFinding) -> TableRow<'static> {
    let severity = finding.severity.to_string();
    TableRow::new([
        Cell::from(severity.clone()).style(status_style(match finding.severity {
            DriftSeverity::Critical => "failed",
            DriftSeverity::Warning => "warning",
            DriftSeverity::Info => "active",
        })),
        Cell::from(finding.kind.label()),
        Cell::from(terminal_text(&finding.subject)),
    ])
}
