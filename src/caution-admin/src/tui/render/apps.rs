// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Padding, Paragraph, Row as TableRow, Table, TableState},
};

use crate::{
    model::{AppCounts, AppFilter, Build, ResourceSummary, timestamp},
    state::{AppState, Row},
};

use super::{detail_line, selection_style, status_style, terminal_text};

pub(super) fn render_app_browse(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &mut AppState,
    filter: AppFilter,
    counts: AppCounts,
) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(4)])
        .split(area);
    let entries = [
        (AppFilter::Current, counts.current),
        (AppFilter::Failed, counts.failed),
        (AppFilter::Historical, counts.historical),
        (AppFilter::All, counts.total),
    ];
    let mut spans = Vec::new();
    for (index, (entry, count)) in entries.into_iter().enumerate() {
        if index > 0 {
            spans.push(Span::raw(" · "));
        }
        let label = if entry == AppFilter::All {
            "Total"
        } else {
            entry.label()
        };
        let style = if entry == filter {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        spans.push(Span::styled(format!("{label} {count}"), style));
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans)).block(
            Block::default()
                .borders(Borders::ALL)
                .padding(Padding::left(1))
                .title(" App status "),
        ),
        areas[0],
    );
    super::render_resource_table(frame, areas[1], state, Some(" Apps "));
}

pub(super) fn render_build_history(frame: &mut Frame<'_>, area: Rect, state: &mut AppState) {
    let title = state.current.page.map_or_else(
        || " Builds · newest first ".to_string(),
        |page| {
            format!(
                " Builds · newest first · Page {} · rows {}–{} ",
                page.page_number(),
                page.first_row(),
                page.last_row()
            )
        },
    );
    let block = Block::default()
        .borders(Borders::ALL)
        .padding(Padding::left(1))
        .title(title);
    if state.current.rows.is_empty() {
        frame.render_widget(
            Paragraph::new("No build history")
                .alignment(ratatui::layout::Alignment::Center)
                .block(block),
            area,
        );
        return;
    }

    let details_width = usize::from(area.width.saturating_sub(34));
    let rows = state.current.rows.iter().filter_map(|row| {
        let Row::Build(build) = row else {
            return None;
        };
        Some(TableRow::new([
            Cell::from(build.status.to_ascii_uppercase()).style(status_style(&build.status)),
            Cell::from(terminal_text(&build.short_commit())),
            Cell::from(build_list_details(build, details_width)),
        ]))
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(12),
            Constraint::Length(14),
            Constraint::Fill(1),
        ],
    )
    .header(
        TableRow::new(["STATUS", "COMMIT", "CREATED · BUILDER / FAILURE"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(block)
    .highlight_symbol("> ")
    .row_highlight_style(selection_style());
    let mut table_state = TableState::default().with_selected(Some(state.current.selected));
    frame.render_stateful_widget(table, area, &mut table_state);
}

pub(super) fn render_build(frame: &mut Frame<'_>, area: Rect, app: ResourceSummary, build: Build) {
    let width = usize::from(area.width.saturating_sub(3));
    let mut lines = vec![
        detail_line("ID", truncate_value(&build.id.to_string(), width, "ID")),
        detail_line(
            "App",
            truncate_value(&terminal_text(&app.label), width, "App"),
        ),
        status_line(&build.status),
        detail_line(
            "Commit",
            truncate_value(&terminal_text(&build.commit_sha), width, "Commit"),
        ),
        detail_line(
            "Builder instance",
            truncate_value(
                &optional_text(build.builder_instance_id.as_deref()),
                width,
                "Builder instance",
            ),
        ),
        detail_line(
            "Builder type",
            truncate_value(
                &optional_text(build.builder_instance_type.as_deref()),
                width,
                "Builder type",
            ),
        ),
        detail_line("Created", timestamp(build.created_at)),
        detail_line("Started", optional_timestamp(build.started_at)),
        detail_line("Completed", optional_timestamp(build.completed_at)),
    ];
    if let Some(summary) = build.failure_summary() {
        lines.push(detail_line(
            "Failure",
            truncate_value(summary, width, "Failure"),
        ));
    }

    let title = Line::from(vec![
        Span::styled(
            " BUILD ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("· "),
        Span::styled(
            terminal_text(&build.short_commit()),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(" · "),
        Span::styled(
            build.status.to_ascii_uppercase(),
            status_style(&build.status),
        ),
        Span::raw(" "),
    ]);
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .padding(Padding::left(1))
                .title(title),
        ),
        area,
    );
}

fn build_list_details(build: &Build, width: usize) -> String {
    let detail = if let Some(summary) = build.failure_summary() {
        format!("{} · {summary}", timestamp(build.created_at))
    } else {
        let builder = build
            .builder_instance_id
            .as_deref()
            .map(terminal_text)
            .unwrap_or_else(|| "no builder".to_string());
        format!("{} · {builder}", timestamp(build.created_at))
    };
    truncate_display(&detail, width)
}

fn status_line(status: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled("Status: ", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(terminal_text(status), status_style(status)),
    ])
}

fn optional_text(value: Option<&str>) -> String {
    value.map(terminal_text).unwrap_or_else(|| "—".to_string())
}

fn optional_timestamp(value: Option<DateTime<Utc>>) -> String {
    value.map(timestamp).unwrap_or_else(|| "—".to_string())
}

fn truncate_value(value: &str, line_width: usize, label: &str) -> String {
    let prefix_width = Span::raw(format!("{label}: ")).width();
    truncate_display(value, line_width.saturating_sub(prefix_width))
}

fn truncate_display(value: &str, width: usize) -> String {
    if Span::raw(value).width() <= width {
        return value.to_string();
    }
    if width == 0 {
        return String::new();
    }
    let available = width.saturating_sub(Span::raw("…").width());
    let mut output = String::new();
    let mut used = 0;
    for character in value.chars() {
        let character_width = Span::raw(character.to_string()).width();
        if used + character_width > available {
            break;
        }
        output.push(character);
        used += character_width;
    }
    output.push('…');
    output
}

#[cfg(test)]
mod tests {
    use super::truncate_display;

    #[test]
    fn build_values_are_display_truncated() {
        assert_eq!(truncate_display("日本語abc", 5), "日本…");
    }
}
