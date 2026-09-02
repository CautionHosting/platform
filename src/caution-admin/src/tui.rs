// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::{error::Error, fmt, io, time::Duration};

use crossterm::{
    cursor::{Hide, Show},
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use dterror::{BoxError, CtxError, Location, ResultExt as _};
use ratatui::{Terminal, backend::CrosstermBackend};

use crate::{
    aws::{self, AwsAction},
    db::Database,
    model::ResourceSummary,
    state::{AppState, Row, Screen},
};

mod render;

pub use render::render;

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

#[derive(Debug, thiserror::Error, CtxError)]
#[error("terminal explorer failed while {stage} [{location:?}]")]
pub struct RunTuiError {
    stage: RunTuiStage,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
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
        Some(Row::AwsRoot) => open_aws(database, state).await,
        Some(Row::Aws(row)) => match row.action {
            AwsAction::Section(section) => state.open_aws_section(section),
            AwsAction::Resource(summary) => open_resource(database, state, summary).await,
            AwsAction::None => state.set_status("this AWS row is informational"),
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

async fn open_aws(database: &Database, state: &mut AppState) {
    if let Some(snapshot) = state.aws_cache.clone() {
        state.open_aws_overview(snapshot);
        return;
    }
    match aws::load_snapshot(database).await {
        Ok(snapshot) => state.open_aws_overview(snapshot),
        Err(error) => state.set_status(error_message(&error)),
    }
}

async fn refresh(database: &Database, state: &mut AppState) {
    let screen = state.current.screen.clone();
    match screen {
        Screen::Home => {}
        Screen::AwsOverview(_) | Screen::AwsSection(_) => {
            match aws::load_snapshot(database).await {
                Ok(snapshot) => {
                    let snapshot = state
                        .aws_cache
                        .as_ref()
                        .map_or(snapshot.clone(), |previous| {
                            previous.merge_refresh(snapshot)
                        });
                    state.replace_aws(snapshot);
                }
                Err(error) => {
                    let message = error_message(&error);
                    if let Some(mut snapshot) = state.aws_cache.clone() {
                        snapshot.mark_stale("refresh failed; previous data retained");
                        state.replace_aws(snapshot);
                    }
                    state.set_status(message);
                }
            }
        }
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

#[derive(Debug, thiserror::Error, CtxError)]
#[error("terminal initialization failed while {stage} [{location:?}]")]
struct NewTerminalSessionError {
    stage: NewTerminalSessionStage,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

fn leave_alternate_screen(output: &mut impl io::Write) -> Result<(), LeaveAlternateScreenError> {
    use LeaveAlternateScreenErrorCtx as Ctx;

    execute!(output, LeaveAlternateScreen, Show).with_context(Ctx::execute())
}

#[derive(Debug, thiserror::Error, CtxError)]
enum LeaveAlternateScreenError {
    #[error("failed to leave the alternate terminal screen [{location:?}]")]
    Execute {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = leave_alternate_screen(self.terminal.backend_mut());
    }
}

#[cfg(test)]
mod tests;
