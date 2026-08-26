// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::{error::Error, fmt, io, time::Duration};

use crossterm::{
    cursor::{Hide, Show},
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use dterror::{FromContext, ResultExt as _};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Cell, Clear, List, ListItem, ListState, Padding, Paragraph,
        Row as TableRow, Table, TableState, Wrap,
    },
};

use crate::{
    db::Database,
    model::{ResourceKind, ResourceSummary},
    state::{AppState, Row, Screen},
};

const TUI_PAGE_SIZE: u32 = 50;

pub async fn run(database: Database, platform_sha: Option<String>) -> Result<(), RunTuiError> {
    use RunTuiErrorCtx as Ctx;

    let mut session = TerminalSession::new().with_context(Ctx::new(RunTuiStage::Initialize))?;
    let mut state = AppState::new();

    while !state.should_quit {
        session
            .terminal
            .draw(|frame| render(frame, &mut state, platform_sha.as_deref()))
            .with_context(Ctx::new(RunTuiStage::Draw))?;

        if event::poll(Duration::from_millis(250)).with_context(Ctx::new(RunTuiStage::Poll))?
            && let Event::Key(key) = event::read().with_context(Ctx::new(RunTuiStage::ReadEvent))?
            && key.kind == KeyEventKind::Press
        {
            handle_key(&database, &mut state, key).await;
        }
    }

    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunTuiStage {
    Initialize,
    Draw,
    Poll,
    ReadEvent,
}

impl fmt::Display for RunTuiStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Initialize => "initializing the terminal",
            Self::Draw => "drawing the screen",
            Self::Poll => "polling for input",
            Self::ReadEvent => "reading terminal input",
        })
    }
}

#[derive(Debug, thiserror::Error, FromContext)]
#[error("terminal explorer failed while {stage}")]
pub struct RunTuiError {
    stage: RunTuiStage,
    #[source]
    source: Box<dyn Error + Send + Sync + 'static>,
}

async fn handle_key(database: &Database, state: &mut AppState, key: KeyEvent) {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        state.should_quit = true;
        return;
    }

    if state.show_help {
        if matches!(key.code, KeyCode::Char('?') | KeyCode::Esc | KeyCode::Enter) {
            state.show_help = false;
        }
        return;
    }

    if state.current.input_mode {
        match key.code {
            KeyCode::Enter => run_search(database, state).await,
            KeyCode::Backspace => {
                state.delete_query_char();
            }
            KeyCode::Esc => state.cancel_input(),
            KeyCode::Char(character) => state.insert_query_char(character),
            _ => {}
        }
        return;
    }

    match key.code {
        KeyCode::Char('q') => state.should_quit = true,
        KeyCode::Char('?') => state.show_help = true,
        KeyCode::Char('/') => state.begin_search(),
        KeyCode::Char('r') => refresh(database, state).await,
        KeyCode::Down | KeyCode::Char('j') => state.select_next(),
        KeyCode::Up | KeyCode::Char('k') => state.select_previous(),
        KeyCode::Enter => open_selected(database, state).await,
        KeyCode::Backspace | KeyCode::Left => {
            state.back();
        }
        _ => {}
    }
}

fn error_message(error: &dyn Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

async fn run_search(database: &Database, state: &mut AppState) {
    let query = state.current.query.trim().to_string();
    if query.is_empty() {
        state.cancel_input();
        return;
    }

    match database.search(&query).await {
        Ok(resources) => state.open_search(query, None, resources),
        Err(error) => state.set_status(error_message(&error)),
    }
}

async fn open_selected(database: &Database, state: &mut AppState) {
    let selected = state.selected_row().cloned();
    match selected {
        Some(Row::Browse(kind)) => match database.list(kind, 0, TUI_PAGE_SIZE).await {
            Ok(page) => state.open_search(String::new(), Some(kind), page.items),
            Err(error) => state.set_status(error_message(&error)),
        },
        Some(Row::Resource(summary)) => open_resource(database, state, summary).await,
        Some(Row::Related(related)) => open_resource(database, state, related.resource).await,
        Some(Row::Relation(relation)) => {
            let Screen::Resource(source) = state.current.screen.clone() else {
                state.set_status("relationship is unavailable from this screen");
                return;
            };
            match database
                .follow(source.reference(), relation.relation, 0, TUI_PAGE_SIZE)
                .await
            {
                Ok(page) => state.open_related(source, relation.relation, page),
                Err(error) => state.set_status(error_message(&error)),
            }
        }
        None => state.set_status("nothing to open"),
    }
}

async fn open_resource(database: &Database, state: &mut AppState, summary: ResourceSummary) {
    match database.show(summary.reference()).await {
        Ok(resource) => match database.relation_summaries(resource.reference()).await {
            Ok(relations) => state.open_resource(resource, relations),
            Err(error) => state.set_status(error_message(&error)),
        },
        Err(error) => state.set_status(error_message(&error)),
    }
}

async fn refresh(database: &Database, state: &mut AppState) {
    let screen = state.current.screen.clone();
    match screen {
        Screen::Home => {}
        Screen::Search {
            query: _,
            kind: Some(kind),
        } => match database.list(kind, 0, TUI_PAGE_SIZE).await {
            Ok(page) => state.replace_resources(page.items),
            Err(error) => state.set_status(error_message(&error)),
        },
        Screen::Search { query, kind: None } => match database.search(&query).await {
            Ok(resources) => state.replace_resources(resources),
            Err(error) => state.set_status(error_message(&error)),
        },
        Screen::Resource(resource) => match database.show(resource.reference()).await {
            Ok(resource) => match database.relation_summaries(resource.reference()).await {
                Ok(relations) => state.replace_resource(resource, relations),
                Err(error) => state.set_status(error_message(&error)),
            },
            Err(error) => state.set_status(error_message(&error)),
        },
        Screen::Related { source, relation } => match database
            .follow(source.reference(), relation, 0, TUI_PAGE_SIZE)
            .await
        {
            Ok(page) => state.replace_related(page),
            Err(error) => state.set_status(error_message(&error)),
        },
    }
}

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

fn breadcrumb_text(state: &AppState, width: u16) -> String {
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

fn details_line(details: String) -> Line<'static> {
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

fn detail_line(label: &'static str, value: String) -> Line<'static> {
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

fn status_style(value: &str) -> Style {
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

struct TerminalSession {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl TerminalSession {
    fn new() -> Result<Self, NewTerminalSessionError> {
        use NewTerminalSessionErrorCtx as Ctx;

        enable_raw_mode().with_context(Ctx::new(NewTerminalSessionStage::EnableRawMode))?;
        let mut stdout = io::stdout();
        if let Err(error) = execute!(stdout, EnterAlternateScreen, Hide) {
            let _ = disable_raw_mode();
            let _ = leave_alternate_screen(&mut stdout);
            return Err(error)
                .with_context(Ctx::new(NewTerminalSessionStage::EnterAlternateScreen));
        }
        let terminal = match Terminal::new(CrosstermBackend::new(stdout)) {
            Ok(terminal) => terminal,
            Err(error) => {
                let _ = disable_raw_mode();
                let mut stdout = io::stdout();
                let _ = leave_alternate_screen(&mut stdout);
                return Err(error).with_context(Ctx::new(NewTerminalSessionStage::CreateTerminal));
            }
        };
        Ok(Self { terminal })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NewTerminalSessionStage {
    EnableRawMode,
    EnterAlternateScreen,
    CreateTerminal,
}

impl fmt::Display for NewTerminalSessionStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EnableRawMode => "enabling raw mode",
            Self::EnterAlternateScreen => "entering the alternate screen",
            Self::CreateTerminal => "creating the terminal backend",
        })
    }
}

#[derive(Debug, thiserror::Error, FromContext)]
#[error("terminal initialization failed while {stage}")]
struct NewTerminalSessionError {
    stage: NewTerminalSessionStage,
    #[source]
    source: Box<dyn Error + Send + Sync + 'static>,
}

fn leave_alternate_screen(output: &mut impl io::Write) -> Result<(), LeaveAlternateScreenError> {
    execute!(output, LeaveAlternateScreen, Show).map_err(LeaveAlternateScreenError)
}

#[derive(Debug, thiserror::Error)]
#[error("failed to leave the alternate terminal screen")]
struct LeaveAlternateScreenError(#[source] io::Error);

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = leave_alternate_screen(self.terminal.backend_mut());
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use dterror::ResultExt as _;
    use ratatui::{Terminal, backend::TestBackend};
    use uuid::Uuid;

    use super::{
        RunTuiError, RunTuiErrorCtx, RunTuiStage, breadcrumb_text, details_line, error_message,
        leave_alternate_screen, render, status_style,
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
                    value: "AWS · a deliberately long provider account name that cannot fit · EC2 Instance"
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

        let detail =
            super::detail_line("Credit state", "suspended · dunning suspended".to_string());
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
}
