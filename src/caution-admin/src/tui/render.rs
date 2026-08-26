// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Cell, Clear, List, ListItem, ListState, Padding, Paragraph,
        Row as TableRow, Table, TableState, Wrap,
    },
};

use crate::{
    model::{ResourceKind, ResourceSummary},
    state::{AppState, Row, Screen},
};

pub fn render(frame: &mut Frame<'_>, state: &mut AppState, platform_sha: Option<&str>) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(2),
        ])
        .split(frame.area());

    render_header(frame, areas[0], state, platform_sha);
    match &state.current.screen {
        Screen::Home => render_home(frame, areas[1], state),
        Screen::Search { .. } | Screen::Related { .. } => {
            render_resource_table(frame, areas[1], state)
        }
        Screen::Resource(resource) => render_resource(frame, areas[1], state, resource.clone()),
    }
    render_footer(frame, areas[2], state);

    if state.show_help {
        render_help(frame);
    }
}

fn render_header(frame: &mut Frame<'_>, area: Rect, state: &AppState, platform_sha: Option<&str>) {
    let mut title = " CAUTION ADMIN · DEVELOPMENT".to_string();
    if let Some(sha) = platform_sha.filter(|sha| !sha.is_empty()) {
        title.push_str(" · ");
        title.push_str(&sha[..sha.len().min(8)]);
    }
    title.push(' ');
    let block = Block::default()
        .borders(Borders::ALL)
        .padding(Padding::left(1))
        .title(Span::styled(
            title,
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ));
    frame.render_widget(
        Paragraph::new(breadcrumb_text(state, area.width))
            .style(Style::default().fg(Color::Cyan))
            .block(block),
        area,
    );
}

pub(super) fn breadcrumb_text(state: &AppState, width: u16) -> String {
    let segments = state.breadcrumbs();
    let available = usize::from(width.saturating_sub(3));
    let joined = segments.join(" › ");
    if joined.chars().count() <= available {
        return joined;
    }

    let current = segments.last().map(String::as_str).unwrap_or("Home");
    let prefix = "… › ";
    let remaining = available.saturating_sub(prefix.chars().count());
    let mut shortened = current
        .chars()
        .take(remaining.saturating_sub(1))
        .collect::<String>();
    if shortened.chars().count() < current.chars().count() && remaining > 0 {
        shortened.push('…');
    }
    [prefix, &shortened].concat()
}

fn render_home(frame: &mut Frame<'_>, area: Rect, state: &mut AppState) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(4)])
        .split(area);
    let mut query = state.current.query.clone();
    if state.current.input_mode {
        query.push('▏');
    } else if query.is_empty() {
        query.push_str("Press / to search");
    }
    frame.render_widget(
        Paragraph::new(query).block(
            Block::default()
                .borders(Borders::ALL)
                .padding(Padding::left(1))
                .title(" Find user, organization, app, email, or UUID "),
        ),
        areas[0],
    );

    let items = ResourceKind::ALL
        .into_iter()
        .map(|kind| ListItem::new(kind.plural()))
        .collect::<Vec<_>>();
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .padding(Padding::left(1))
                .title(" Browse all "),
        )
        .highlight_symbol("> ")
        .highlight_style(selection_style());
    let mut list_state = ListState::default().with_selected(Some(state.current.selected));
    frame.render_stateful_widget(list, areas[1], &mut list_state);
}

fn render_resource_table(frame: &mut Frame<'_>, area: Rect, state: &mut AppState) {
    if state.current.rows.is_empty() {
        frame.render_widget(
            Paragraph::new("No results")
                .alignment(Alignment::Center)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .padding(Padding::left(1)),
                ),
            area,
        );
        return;
    }

    let rows = state
        .current
        .rows
        .iter()
        .filter_map(table_row)
        .collect::<Vec<_>>();
    let table = Table::new(
        rows,
        [
            Constraint::Length(14),
            Constraint::Percentage(38),
            Constraint::Percentage(62),
        ],
    )
    .header(
        TableRow::new(["TYPE", "NAME", "DETAILS"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .padding(Padding::left(1)),
    )
    .row_highlight_style(selection_style())
    .highlight_symbol("> ");
    let mut table_state = TableState::default().with_selected(Some(state.current.selected));
    frame.render_stateful_widget(table, area, &mut table_state);
}

fn table_row(row: &Row) -> Option<TableRow<'static>> {
    match row {
        Row::Resource(resource) => Some(summary_row(resource, None, None)),
        Row::Related(related) => Some(summary_row(
            &related.resource,
            related.role.as_deref(),
            related.via.as_ref(),
        )),
        Row::Browse(_) | Row::Relation(_) => None,
    }
}

fn summary_row(
    resource: &ResourceSummary,
    role: Option<&str>,
    via: Option<&ResourceSummary>,
) -> TableRow<'static> {
    let mut context = resource.context.clone().unwrap_or_default();
    if let Some(role) = role {
        if !context.is_empty() {
            context.push_str(" · ");
        }
        context.push_str("role: ");
        context.push_str(role);
    }
    if let Some(via) = via {
        if !context.is_empty() {
            context.push_str(" · ");
        }
        context.push_str("via ");
        context.push_str(&via.label);
    }
    TableRow::new([
        Cell::from(resource.kind.singular().to_ascii_uppercase()).style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from(resource.label.clone()),
        Cell::from(details_line(context)),
    ])
}

pub(super) fn details_line(details: String) -> Line<'static> {
    Line::from(status_spans(details))
}

fn status_spans(value: String) -> Vec<Span<'static>> {
    if let Some(index) = value.find(" · ") {
        let status = value[..index].to_string();
        let rest = value[index + " · ".len()..].to_string();
        vec![
            Span::styled(status.clone(), status_style(&status)),
            Span::raw(" · "),
            Span::raw(rest),
        ]
    } else {
        let style = status_style(&value);
        vec![Span::styled(value, style)]
    }
}

fn render_resource(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &mut AppState,
    resource: crate::model::Resource,
) {
    let visible_fields = resource
        .fields
        .iter()
        .filter(|field| !matches!(field.label, "Name" | "Username" | "State" | "Status"))
        .collect::<Vec<_>>();
    let detail_height = (visible_fields.len() as u16 + 4).min(area.height.saturating_sub(4));
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(detail_height), Constraint::Min(4)])
        .split(area);

    let mut lines = vec![Line::from(vec![
        Span::styled("ID: ", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(
            resource.id.to_string(),
            Style::default().fg(Color::DarkGray),
        ),
    ])];
    let detail_width = usize::from(areas[0].width.saturating_sub(3));
    lines.extend(visible_fields.into_iter().map(|field| {
        detail_line(
            field.label,
            truncate_detail_value(field.label, &field.value, detail_width),
        )
    }));
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .padding(Padding::left(1))
                .title(resource_title(&resource)),
        ),
        areas[0],
    );

    let rows = state
        .current
        .rows
        .iter()
        .filter_map(|row| match row {
            Row::Relation(relation) => Some(TableRow::new([
                Cell::from(relation.relation.label()),
                Cell::from(relation.count.to_string()),
            ])),
            _ => None,
        })
        .collect::<Vec<_>>();
    let table = Table::new(rows, [Constraint::Min(12), Constraint::Length(8)])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .padding(Padding::left(1))
                .title(" Relationships "),
        )
        .highlight_symbol("> ")
        .row_highlight_style(selection_style());
    let mut table_state = TableState::default().with_selected(Some(state.current.selected));
    frame.render_stateful_widget(table, areas[1], &mut table_state);
}

pub(super) fn detail_line(label: &'static str, value: String) -> Line<'static> {
    let value_style = match label {
        "Credit balance" if value.starts_with('-') => Style::default().fg(Color::Red),
        "Credit balance" => Style::default().fg(Color::Green),
        "Pending change" => Style::default().fg(Color::Yellow),
        _ if value == "—" => Style::default().fg(Color::DarkGray),
        _ => Style::default(),
    };
    let mut spans = vec![Span::styled(
        [label, ": "].concat(),
        Style::default().add_modifier(Modifier::BOLD),
    )];
    if matches!(label, "Credit state" | "Subscription status" | "DNS") {
        spans.extend(status_spans(value));
    } else {
        spans.push(Span::styled(value, value_style));
    }
    Line::from(spans)
}

fn truncate_detail_value(label: &str, value: &str, line_width: usize) -> String {
    let prefix_width = Span::raw([label, ": "].concat()).width();
    let available = line_width.saturating_sub(prefix_width);
    if Span::raw(value).width() <= available {
        return value.to_string();
    }

    let ellipsis = "…";
    let ellipsis_width = Span::raw(ellipsis).width();
    if available < ellipsis_width {
        return String::new();
    }

    let mut truncated = String::new();
    let mut width = 0;
    for character in value.chars() {
        let character = character.to_string();
        let character_width = Span::raw(character.as_str()).width();
        if width + character_width + ellipsis_width > available {
            break;
        }
        truncated.push_str(&character);
        width += character_width;
    }
    truncated.push_str(ellipsis);
    truncated
}

fn resource_title(resource: &crate::model::Resource) -> Line<'static> {
    let status = resource
        .fields
        .iter()
        .find(|field| matches!(field.label, "State" | "Status"))
        .map(|field| field.value.as_str());
    let mut spans = vec![
        Span::raw(" "),
        Span::styled(
            resource.kind.singular().to_ascii_uppercase(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" · "),
        Span::styled(
            resource.label.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
    ];
    if let Some(status) = status {
        spans.push(Span::raw(" · "));
        spans.push(Span::styled(
            status.to_ascii_uppercase(),
            status_style(status),
        ));
    }
    spans.push(Span::raw(" "));
    Line::from(spans)
}

fn selection_style() -> Style {
    Style::default()
        .fg(Color::Black)
        .bg(Color::Cyan)
        .add_modifier(Modifier::BOLD)
}

pub(super) fn status_style(value: &str) -> Style {
    let token = value
        .split(|character: char| character.is_whitespace() || character == '·')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let color = match token.as_str() {
        "active" | "running" | "ready" | "validated" | "clear" => Some(Color::Green),
        "pending" | "trialing" | "past_due" | "paused" | "stopped" | "terminating" | "reserved"
        | "publishing" | "withdrawing" | "warning" | "reminder" => Some(Color::Yellow),
        "inactive" | "failed" | "terminated" | "suspended" | "canceled" | "invalid" => {
            Some(Color::Red)
        }
        _ => None,
    };
    color.map_or_else(Style::default, |color| Style::default().fg(color))
}

fn render_footer(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let (text, style) = if let Some(status) = &state.current.status {
        (status.clone(), Style::default().fg(Color::Red))
    } else if state.current.input_mode {
        (
            "Type query · Enter search · Esc cancel · Backspace delete".to_string(),
            Style::default(),
        )
    } else {
        (
            "↑↓/jk move · Enter open · Bksp back · / search · r refresh · ? help · q quit"
                .to_string(),
            Style::default(),
        )
    };
    frame.render_widget(Paragraph::new(text).style(style), area);
}

fn render_help(frame: &mut Frame<'_>) {
    let area = centered_rect(70, 60, frame.area());
    frame.render_widget(Clear, area);
    let help = Paragraph::new(vec![
        Line::from("This is a read-only development pilot."),
        Line::from(""),
        Line::from("/          Search users, organizations, and apps"),
        Line::from("↑↓ or j/k  Move selection"),
        Line::from("Enter      Open a resource or follow a relationship"),
        Line::from("Backspace  Return to the exact previous screen"),
        Line::from("r          Refresh the current screen"),
        Line::from("q          Quit"),
        Line::from(""),
        Line::from("Press ?, Esc, or Enter to close this help."),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .padding(Padding::left(1))
            .title(" Help "),
    )
    .wrap(Wrap { trim: false });
    frame.render_widget(help, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}
