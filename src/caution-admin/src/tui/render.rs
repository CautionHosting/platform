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
    model::{ResourceSummary, SortColumn},
    state::{AppState, AwsLoadMode, Row, Screen},
};

pub(super) use crate::terminal::terminal_text;

mod aws;
mod footer;

pub fn render(frame: &mut Frame<'_>, state: &mut AppState, platform_sha: Option<&str>) {
    let footer_height = footer::height(state, frame.area().width);
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(footer_height),
        ])
        .split(frame.area());

    render_header(frame, areas[0], state, platform_sha);
    match &state.current.screen {
        Screen::Home => render_home(frame, areas[1], state),
        Screen::Search { .. } | Screen::Related { .. } => {
            render_resource_table(frame, areas[1], state, Some(" Resources "));
        }
        Screen::AwsSection(section) => aws::render_section(frame, areas[1], state, *section),
        Screen::AwsOverview(metadata) => {
            aws::render_overview(frame, areas[1], state, metadata.clone());
        }
        Screen::AwsFinding(finding) => {
            aws::render_finding(frame, areas[1], state, finding.clone());
        }
        Screen::AwsHost(host) => aws::render_host(frame, areas[1], state, host.as_ref().clone()),
        Screen::Resource(resource) => render_resource(frame, areas[1], state, resource.clone()),
    }
    footer::render(frame, areas[2], state);

    if state.aws_loading.is_some() {
        render_aws_loading(frame, state);
    } else if state.show_help {
        render_help(frame);
    }
}

fn render_aws_loading(frame: &mut Frame<'_>, state: &AppState) {
    const SPINNER: [&str; 4] = ["⠋", "⠙", "⠹", "⠸"];
    let area = centered_rect(48, 20, frame.area());
    let action = match state.aws_loading {
        Some(AwsLoadMode::Open) => "Loading AWS snapshot",
        Some(AwsLoadMode::Refresh) => "Refreshing AWS snapshot",
        None => return,
    };
    let text = format!(
        "{} {action}…",
        SPINNER[state.aws_loading_frame % SPINNER.len()]
    );
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(text)
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL).title(" AWS ")),
        area,
    );
}

fn render_header(frame: &mut Frame<'_>, area: Rect, state: &AppState, platform_sha: Option<&str>) {
    let mut title = " CAUTION ADMIN · DEVELOPMENT".to_string();
    if let Some(sha) = platform_sha.filter(|sha| !sha.is_empty()) {
        title.push_str(" · ");
        title.extend(terminal_text(sha).chars().take(8));
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
    let joined = terminal_text(&segments.join(" › "));
    if Span::raw(&joined).width() <= available {
        return joined;
    }

    let current = terminal_text(segments.last().map(String::as_str).unwrap_or("Home"));
    let prefix = "… › ";
    let remaining = available.saturating_sub(Span::raw(prefix).width());
    let ellipsis_width = Span::raw("…").width();
    let mut shortened = String::new();
    let mut used = 0;
    for character in current.chars() {
        let character_width = Span::raw(character.to_string().as_str()).width();
        if used + character_width + ellipsis_width > remaining {
            break;
        }
        shortened.push(character);
        used += character_width;
    }
    if shortened.chars().count() < current.chars().count() && remaining >= ellipsis_width {
        shortened.push('…');
    }
    [prefix, &shortened].concat()
}

fn render_home(frame: &mut Frame<'_>, area: Rect, state: &mut AppState) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(4)])
        .split(area);
    let mut query = terminal_text(&state.current.query);
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

    let items = state
        .current
        .rows
        .iter()
        .filter_map(|row| match row {
            Row::Browse(kind) => Some(ListItem::new(kind.plural())),
            Row::AwsRoot => Some(ListItem::new("AWS")),
            _ => None,
        })
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

pub(super) fn render_resource_table(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &mut AppState,
    title: Option<&'static str>,
) {
    let mut block = Block::default()
        .borders(Borders::ALL)
        .padding(Padding::left(1));
    if let Some(title) = title {
        block = block.title(table_title(state, title));
    }
    if state.current.rows.is_empty() {
        frame.render_widget(
            Paragraph::new("No results")
                .alignment(Alignment::Center)
                .block(block),
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
            Constraint::Fill(1),
        ],
    )
    .header(table_header(state, ["TYPE", "NAME", "DETAILS"]))
    .block(block)
    .row_highlight_style(selection_style())
    .highlight_symbol("> ");
    let mut table_state = TableState::default().with_selected(Some(state.current.selected));
    frame.render_stateful_widget(table, area, &mut table_state);
}

fn table_title(state: &AppState, title: &str) -> Line<'static> {
    let title = title.trim();
    let text = state.current.page.map_or_else(
        || format!(" {title} "),
        |page| {
            format!(
                " {title} · Page {} · rows {}–{} ",
                page.page_number(),
                page.first_row(),
                page.last_row()
            )
        },
    );
    Line::from(text)
}

pub(super) fn table_header(state: &AppState, labels: [&'static str; 3]) -> TableRow<'static> {
    let columns = [SortColumn::Type, SortColumn::Name, SortColumn::Details];
    TableRow::new(labels.into_iter().zip(columns).map(|(label, column)| {
        let active = state.current.sort == Some(column);
        let text = if active {
            format!("{label} ↑")
        } else {
            label.to_string()
        };
        let style = Style::default().add_modifier(Modifier::BOLD).fg(if active {
            Color::Cyan
        } else {
            Color::Reset
        });
        Cell::from(text).style(style)
    }))
}

fn table_row(row: &Row) -> Option<TableRow<'static>> {
    match row {
        Row::Resource(resource) => Some(summary_row(resource, None, None)),
        Row::Related(related) => Some(summary_row(
            &related.resource,
            related.role.as_deref(),
            related.via.as_ref(),
        )),
        Row::Aws(row) => Some(aws::table_row(row)),
        Row::AwsFinding(finding) => Some(aws::finding_row(finding)),
        Row::AwsHost(_) | Row::Browse(_) | Row::AwsRoot | Row::Relation(_) => None,
    }
}

fn summary_row(
    resource: &ResourceSummary,
    role: Option<&str>,
    via: Option<&ResourceSummary>,
) -> TableRow<'static> {
    let mut context = terminal_text(resource.context.as_deref().unwrap_or(""));
    if let Some(role) = role {
        if !context.is_empty() {
            context.push_str(" · ");
        }
        context.push_str("role: ");
        context.push_str(&terminal_text(role));
    }
    if let Some(via) = via {
        if !context.is_empty() {
            context.push_str(" · ");
        }
        context.push_str("via ");
        context.push_str(&terminal_text(&via.label));
    }
    TableRow::new([
        Cell::from(resource.kind.singular().to_ascii_uppercase()).style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from(terminal_text(&resource.label)),
        Cell::from(details_line(context)),
    ])
}

pub(super) fn details_line(details: String) -> Line<'static> {
    Line::from(status_spans(terminal_text(&details)))
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
    let field_lines = u16::try_from(visible_fields.len()).unwrap_or(u16::MAX);
    let detail_height = field_lines
        .saturating_add(4)
        .min(area.height.saturating_sub(4));
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(detail_height), Constraint::Min(4)])
        .split(area);

    let mut lines = vec![Line::from(vec![
        Span::styled("ID: ", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(
            terminal_text(&resource.id.to_string()),
            Style::default().fg(Color::DarkGray),
        ),
    ])];
    let detail_width = usize::from(areas[0].width.saturating_sub(3));
    lines.extend(visible_fields.into_iter().map(|field| {
        detail_line(
            field.label,
            truncate_detail_value(field.label, &terminal_text(&field.value), detail_width),
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
    if matches!(
        label,
        "Credit state" | "Subscription status" | "BYOC state" | "DNS" | "Level"
    ) {
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
    let status = resource.status();
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
            terminal_text(&resource.label),
            Style::default().add_modifier(Modifier::BOLD),
        ),
    ];
    if let Some(status) = status {
        spans.push(Span::raw(" · "));
        spans.push(Span::styled(
            terminal_text(&status.to_ascii_uppercase()),
            status_style(status),
        ));
    }
    spans.push(Span::raw(" "));
    Line::from(spans)
}

pub(super) fn selection_style() -> Style {
    Style::default()
        .bg(Color::Rgb(36, 40, 52))
        .add_modifier(Modifier::BOLD)
}

pub(super) fn status_style(value: &str) -> Style {
    let token = value
        .split(|character: char| character.is_whitespace() || character == '·')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let color = match token.as_str() {
        "active" | "running" | "ready" | "validated" | "clear" | "complete" => Some(Color::Green),
        "pending" | "initialized" | "trialing" | "past_due" | "paused" | "stopped"
        | "terminating" | "reserved" | "publishing" | "withdrawing" | "warning" | "reminder"
        | "stale" | "partial" => Some(Color::Yellow),
        "inactive" | "failed" | "terminated" | "suspended" | "canceled" | "invalid"
        | "critical" => Some(Color::Red),
        _ => None,
    };
    color.map_or_else(Style::default, |color| Style::default().fg(color))
}

/// Help overlay body. Kept as data so a test can assert each line fits.
/// Width of the help overlay as a percentage of the terminal width.
pub(super) const HELP_WIDTH_PERCENT: u16 = 70;

pub(super) const HELP_LINES: &[&str] = &[
    "This is a read-only development pilot.",
    "",
    "/          Search users, organizations, and apps",
    "↑↓ or j/k  Move selection",
    "Enter      Open a resource or follow a relationship",
    "s          Sort by the next table column",
    "n/PgDn     Next page",
    "p/PgUp     Previous page",
    "Backspace  Return to the previous screen",
    "           (deletes a character while searching)",
    "r          Refresh the current screen",
    "q          Quit",
    "",
    "Press ?, Esc, or Enter to close this help.",
];

fn render_help(frame: &mut Frame<'_>) {
    let area = centered_rect(HELP_WIDTH_PERCENT, 60, frame.area());
    frame.render_widget(Clear, area);
    let help = Paragraph::new(
        HELP_LINES
            .iter()
            .map(|line| Line::from(*line))
            .collect::<Vec<_>>(),
    )
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
