// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Padding, Paragraph},
    widgets::{Cell, Row as TableRow},
};

use crate::{
    aws::{AwsDisplayRow, AwsOverviewMetadata},
    state::AppState,
};

use super::{
    detail_line, details_line, render_resource_table, status_style, truncate_detail_value,
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
    .map(|(label, value)| detail_line(label, truncate_detail_value(label, &value, detail_width)))
    .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .padding(Padding::left(1))
                .title(title),
        ),
        areas[0],
    );
    render_resource_table(frame, areas[1], state, Some(" Resources "));
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
            metadata.account.clone(),
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
        Cell::from(row.kind.clone()).style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from(row.name.clone()),
        Cell::from(details_line(row.details.clone())),
    ])
}
