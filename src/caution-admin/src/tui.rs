// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::{
    error::Error,
    fmt, io,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use crossterm::{
    cursor::{Hide, Show},
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use dterror::{BoxError, CtxError, Location, ResultExt as _};
use ratatui::{Terminal, backend::CrosstermBackend};

use crate::{
    aws::AwsAction,
    db::Database,
    model::{ResourceKind, ResourceSummary, SortColumn},
    state::{AppState, AwsLoadMode, Row, Screen},
};

mod apps;
mod aws_load;
mod render;

use aws_load::PendingAwsLoad;

pub use render::render;

const TUI_PAGE_SIZE: u32 = 50;
static TUI_ACTIVE: AtomicBool = AtomicBool::new(false);

pub async fn run(database: Database, platform_sha: Option<String>) -> Result<(), RunTuiError> {
    use RunTuiErrorCtx as Ctx;

    let mut session = TerminalSession::new().with_context(Ctx::new(RunTuiStage::Initialize))?;
    let mut state = AppState::new();
    let mut aws_load = None;

    while !state.should_quit {
        if aws_load.as_ref().is_some_and(PendingAwsLoad::is_finished)
            && let Some(load) = aws_load.take()
        {
            load.finish(&mut state).await;
            if state.should_quit {
                break;
            }
        }
        session
            .terminal
            .draw(|frame| render(frame, &mut state, platform_sha.as_deref()))
            .with_context(Ctx::new(RunTuiStage::Draw))?;

        if event::poll(Duration::from_millis(250)).with_context(Ctx::new(RunTuiStage::Poll))?
            && let Event::Key(key) = event::read().with_context(Ctx::new(RunTuiStage::ReadEvent))?
            && key.kind == KeyEventKind::Press
        {
            if state.aws_loading.is_some() {
                if loading_key(&mut state, key)
                    && let Some(load) = aws_load.take()
                {
                    let notify = !state.should_quit;
                    load.cancel(&mut state, notify);
                }
            } else if let Some(mode) = handle_key(&database, &mut state, key).await {
                aws_load = Some(PendingAwsLoad::start(database.clone(), &mut state, mode));
            }
        }
        state.advance_aws_loading();
    }

    if let Some(load) = aws_load {
        load.cancel(&mut state, false);
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

async fn handle_key(
    database: &Database,
    state: &mut AppState,
    key: KeyEvent,
) -> Option<AwsLoadMode> {
    match classify_key(state, key) {
        KeyOutcome::Handled => None,
        KeyOutcome::Search => {
            run_search(database, state).await;
            None
        }
        KeyOutcome::Refresh => refresh(database, state).await,
        KeyOutcome::Open => open_selected(database, state).await,
        KeyOutcome::Page(direction) => {
            change_page(database, state, direction).await;
            None
        }
        KeyOutcome::Sort => {
            sort_current(database, state).await;
            None
        }
        KeyOutcome::Filter => {
            apps::cycle_filter(database, state).await;
            None
        }
    }
}

fn loading_key(state: &mut AppState, key: KeyEvent) -> bool {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        state.should_quit = true;
        return true;
    }
    if is_chord(key) {
        return false;
    }
    match key.code {
        KeyCode::Char('q') => {
            state.should_quit = true;
            true
        }
        KeyCode::Backspace | KeyCode::Left => true,
        _ => false,
    }
}

/// What a key press needs from the database, if anything.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyOutcome {
    /// Fully applied to [`AppState`]; no query required.
    Handled,
    Search,
    Refresh,
    Open,
    Page(PageDirection),
    Sort,
    Filter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PageDirection {
    Previous,
    Next,
}

/// Apply every effect a key has on [`AppState`] and report the query it needs.
///
/// Split out from [`handle_key`] so the key map is testable without a database.
fn classify_key(state: &mut AppState, key: KeyEvent) -> KeyOutcome {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        state.should_quit = true;
        return KeyOutcome::Handled;
    }

    if state.show_help {
        if matches!(key.code, KeyCode::Char('?') | KeyCode::Esc | KeyCode::Enter) {
            state.show_help = false;
        }
        return KeyOutcome::Handled;
    }

    if state.current.input_mode {
        if is_chord(key) {
            // Ctrl-u clears the line in every readline-style prompt.
            if key.code == KeyCode::Char('u') {
                state.current.query.clear();
            }
            return KeyOutcome::Handled;
        }
        match key.code {
            KeyCode::Enter => return KeyOutcome::Search,
            KeyCode::Backspace => {
                state.delete_query_char();
            }
            KeyCode::Esc => state.cancel_input(),
            KeyCode::Char(character) => state.insert_query_char(character),
            _ => {}
        }
        return KeyOutcome::Handled;
    }

    if is_chord(key) {
        return KeyOutcome::Handled;
    }

    match key.code {
        KeyCode::Char('q') => state.should_quit = true,
        KeyCode::Char('?') => state.show_help = true,
        KeyCode::Char('/') => state.begin_search(),
        KeyCode::Char('r') => return KeyOutcome::Refresh,
        KeyCode::Char('s') => return KeyOutcome::Sort,
        KeyCode::Char('f') if matches!(state.current.screen, Screen::Apps { .. }) => {
            return KeyOutcome::Filter;
        }
        KeyCode::Char('n') | KeyCode::PageDown => {
            return KeyOutcome::Page(PageDirection::Next);
        }
        KeyCode::Char('p') | KeyCode::PageUp => {
            return KeyOutcome::Page(PageDirection::Previous);
        }
        KeyCode::Down | KeyCode::Char('j') => state.select_next(),
        KeyCode::Up | KeyCode::Char('k') => state.select_previous(),
        KeyCode::Enter => return KeyOutcome::Open,
        KeyCode::Backspace | KeyCode::Left => back_or_notify(state),
        _ => {}
    }
    KeyOutcome::Handled
}

/// Whether a key event is a Ctrl or Alt chord rather than typed text.
///
/// Matching on [`KeyCode::Char`] alone treats `Ctrl-u` as the letter `u`, so
/// chords leaked into the search query and fired navigation commands: `Ctrl-j`
/// (which many terminals send for Enter) moved the selection instead.
/// `SHIFT` is deliberately allowed, because terminals set it for capitals.
fn is_chord(key: KeyEvent) -> bool {
    key.modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SUPER)
}

/// Going back from the root is a no-op, so say so rather than ignoring the key.
fn back_or_notify(state: &mut AppState) {
    if !state.back() {
        state.set_status("already at the top level; press q to quit");
    }
}

fn error_message(error: &dyn Error) -> String {
    let message = error.to_string();
    let mut source = error.source();
    let mut root = None;
    while let Some(cause) = source {
        root = Some(cause.to_string());
        source = cause.source();
    }
    root.filter(|root| !message.contains(root))
        .map_or(message.clone(), |root| format!("{message}: {root}"))
}

async fn run_search(database: &Database, state: &mut AppState) {
    let query = state.current.query.trim().to_string();
    if query.is_empty() {
        state.cancel_input();
        return;
    }

    match database
        .search(&query, 0, TUI_PAGE_SIZE, Some(SortColumn::Details))
        .await
    {
        Ok(page) => state.open_search(query, None, page),
        Err(error) => state.set_error(error_message(&error)),
    }
}

async fn open_selected(database: &Database, state: &mut AppState) -> Option<AwsLoadMode> {
    let selected = state.selected_row().cloned();
    match selected {
        Some(Row::Browse(ResourceKind::App)) => apps::open_apps(database, state).await,
        Some(Row::Browse(kind)) => match database
            .list(kind, 0, TUI_PAGE_SIZE, Some(SortColumn::Details))
            .await
        {
            Ok(page) => state.open_search(String::new(), Some(kind), page),
            Err(error) => state.set_error(error_message(&error)),
        },
        Some(Row::AwsRoot) => return open_aws(state),
        Some(Row::Aws(row)) => match row.action {
            AwsAction::Section(section) => state.open_aws_section(section),
            AwsAction::Host(instance_id) => open_aws_host(state, &instance_id),
            AwsAction::Resource(summary) => open_resource(database, state, summary).await,
            AwsAction::None => state.set_status("No linked Platform resource"),
        },
        Some(Row::AwsFinding(finding)) => state.open_aws_finding(finding),
        Some(Row::AwsHost(host)) => state.open_aws_host(*host),
        Some(Row::BuildHistory(app)) => apps::open_build_history(database, state, app).await,
        Some(Row::Build(build)) => apps::open_build(state, build),
        Some(Row::Resource(summary)) => open_resource(database, state, summary).await,
        Some(Row::Related(related)) => open_resource(database, state, related.resource).await,
        Some(Row::Relation(relation)) => {
            let Screen::Resource(source) = state.current.screen.clone() else {
                state.set_error("relationship is unavailable from this screen");
                return None;
            };
            match database
                .follow(
                    source.reference(),
                    relation.relation,
                    0,
                    TUI_PAGE_SIZE,
                    Some(SortColumn::Details),
                )
                .await
            {
                Ok(page) => state.open_related(source, relation.relation, page),
                Err(error) => state.set_error(error_message(&error)),
            }
        }
        None => state.set_status("nothing to open"),
    }
    None
}

fn open_aws_host(state: &mut AppState, instance_id: &str) {
    if let Some(host) = state.aws_host(instance_id) {
        state.open_aws_host(host);
    } else {
        state.set_status("AWS host no longer present; press r to refresh");
    }
}

async fn open_resource(database: &Database, state: &mut AppState, summary: ResourceSummary) {
    match database.show(summary.reference()).await {
        Ok(resource) => match database.relation_summaries(resource.reference()).await {
            Ok(relations) => state.open_resource(resource, relations),
            Err(error) => state.set_error(error_message(&error)),
        },
        Err(error) => state.set_error(error_message(&error)),
    }
}

fn open_aws(state: &mut AppState) -> Option<AwsLoadMode> {
    if let Some(snapshot) = state.aws_cache.clone() {
        state.open_aws_overview(snapshot);
        return None;
    }
    Some(AwsLoadMode::Open)
}

async fn refresh(database: &Database, state: &mut AppState) -> Option<AwsLoadMode> {
    let screen = state.current.screen.clone();
    match screen {
        Screen::Home => {}
        Screen::AwsOverview(_)
        | Screen::AwsSection(_)
        | Screen::AwsFinding(_)
        | Screen::AwsHost(_) => return Some(AwsLoadMode::Refresh),
        Screen::Apps { filter, .. } => {
            let offset = state.current.page.map_or(0, |page| page.offset);
            let sort = state.current.sort.unwrap_or(SortColumn::Details);
            apps::reload_apps(database, state, filter, offset, sort, false).await;
        }
        Screen::BuildHistory { app } => {
            let offset = state.current.page.map_or(0, |page| page.offset);
            apps::reload_builds(database, state, &app, offset, false).await;
        }
        Screen::Build { app, build } => {
            apps::refresh_build(database, state, app, build).await;
        }
        Screen::Search { .. } | Screen::Related { .. } => {
            let page = state.current.page;
            let sort = state.current.sort;
            if let (Some(page), Some(sort)) = (page, sort) {
                load_table_page(database, state, page.offset, sort, false).await;
            }
        }
        Screen::Resource(resource) => match database.show(resource.reference()).await {
            Ok(resource) => match database.relation_summaries(resource.reference()).await {
                Ok(relations) => state.replace_resource(resource, relations),
                Err(error) => state.set_error(error_message(&error)),
            },
            Err(error) => state.set_error(error_message(&error)),
        },
    }
    None
}

async fn change_page(database: &Database, state: &mut AppState, direction: PageDirection) {
    let Some(page) = state.current.page else {
        state.set_status("this view is not paginated");
        return;
    };
    let offset = match direction {
        PageDirection::Previous if page.has_previous() => page.offset.saturating_sub(page.limit),
        PageDirection::Next if page.has_more => page.offset.saturating_add(page.limit),
        PageDirection::Previous => {
            state.set_status("already on the first page");
            return;
        }
        PageDirection::Next => {
            state.set_status("already on the last page");
            return;
        }
    };
    if let Screen::BuildHistory { app } = state.current.screen.clone() {
        apps::reload_builds(database, state, &app, offset, true).await;
        return;
    }
    let Some(sort) = state.current.sort else {
        return;
    };
    load_table_page(database, state, offset, sort, true).await;
}

async fn sort_current(database: &Database, state: &mut AppState) {
    let Some(sort) = state.current.next_sort() else {
        state.set_status("this view has a fixed order");
        return;
    };
    if matches!(
        state.current.screen,
        Screen::Apps { .. } | Screen::Search { .. } | Screen::Related { .. }
    ) {
        load_table_page(database, state, 0, sort, true).await;
    } else {
        state.current.sort_rows(sort);
        state.current.status = None;
    }
}

async fn load_table_page(
    database: &Database,
    state: &mut AppState,
    offset: u32,
    sort: SortColumn,
    reset_selection: bool,
) {
    match state.current.screen.clone() {
        Screen::Apps { filter, .. } => {
            apps::reload_apps(database, state, filter, offset, sort, reset_selection).await;
        }
        Screen::Search {
            query: _,
            kind: Some(kind),
        } => match database.list(kind, offset, TUI_PAGE_SIZE, Some(sort)).await {
            Ok(page) => state.replace_resources(page, sort, reset_selection),
            Err(error) => state.set_error(error_message(&error)),
        },
        Screen::Search { query, kind: None } => match database
            .search(&query, offset, TUI_PAGE_SIZE, Some(sort))
            .await
        {
            Ok(page) => state.replace_resources(page, sort, reset_selection),
            Err(error) => state.set_error(error_message(&error)),
        },
        Screen::Related { source, relation } => match database
            .follow(
                source.reference(),
                relation,
                offset,
                TUI_PAGE_SIZE,
                Some(sort),
            )
            .await
        {
            Ok(page) => state.replace_related(page, sort, reset_selection),
            Err(error) => state.set_error(error_message(&error)),
        },
        _ => state.set_status("this view is not paginated"),
    }
}

struct TerminalSession {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl TerminalSession {
    fn new() -> Result<Self, NewTerminalSessionError> {
        use NewTerminalSessionErrorCtx as Ctx;

        install_panic_hook();
        enable_raw_mode().with_context(Ctx::new(NewTerminalSessionStage::EnableRawMode))?;
        let mut stdout = io::stdout();
        if let Err(error) = execute!(stdout, EnterAlternateScreen, Hide) {
            let _ = disable_raw_mode();
            let _ = leave_alternate_screen(&mut stdout);
            return Err(error)
                .with_context(Ctx::new(NewTerminalSessionStage::EnterAlternateScreen));
        }
        TUI_ACTIVE.store(true, Ordering::Release);
        let terminal = match Terminal::new(CrosstermBackend::new(stdout)) {
            Ok(terminal) => terminal,
            Err(error) => {
                restore_terminal_if_active();
                return Err(error).with_context(Ctx::new(NewTerminalSessionStage::CreateTerminal));
            }
        };
        Ok(Self { terminal })
    }
}

/// Restore the terminal before a panic message is printed.
///
/// The default hook writes to the alternate screen, which `Drop` then tears
/// down, so the operator was left with a dead terminal and no explanation of
/// why. Restoring first means the message lands on the normal screen.
fn install_panic_hook() {
    static HOOK: std::sync::Once = std::sync::Once::new();

    HOOK.call_once(|| {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_terminal_if_active();
            default_hook(info);
        }));
    });
}

/// Return the terminal to its normal screen and input mode.
fn restore_terminal_if_active() {
    if TUI_ACTIVE.swap(false, Ordering::AcqRel) {
        let _ = disable_raw_mode();
        let _ = leave_alternate_screen(&mut io::stdout());
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
        if TUI_ACTIVE.swap(false, Ordering::AcqRel) {
            let _ = disable_raw_mode();
            let _ = leave_alternate_screen(self.terminal.backend_mut());
        }
    }
}

#[cfg(test)]
mod tests;
