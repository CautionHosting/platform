// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::io;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use dterror::ResultExt as _;

use super::super::{
    KeyOutcome, PageDirection, RunTuiError, RunTuiErrorCtx, RunTuiStage, TUI_ACTIVE, classify_key,
    error_message, install_panic_hook, leave_alternate_screen, restore_terminal_if_active,
};
use crate::state::AppState;

fn press(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}
fn chord(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::CONTROL)
}

#[test]
fn terminal_cleanup_emits_restore_commands() {
    let mut output = Vec::new();
    leave_alternate_screen(&mut output).expect("restore terminal commands");
    assert!(!output.is_empty());
}

#[test]
fn panic_restoration_is_inactive_outside_a_tui() {
    install_panic_hook();
    TUI_ACTIVE.store(false, std::sync::atomic::Ordering::Release);
    restore_terminal_if_active();
    assert!(!TUI_ACTIVE.load(std::sync::atomic::Ordering::Acquire));
}

#[test]
fn terminal_errors_keep_the_root_cause() {
    let error: RunTuiError = Err::<(), _>(io::Error::other("draw failed"))
        .with_context(RunTuiErrorCtx::new(RunTuiStage::Draw))
        .expect_err("terminal draw must fail");
    let message = error_message(&error);
    assert!(message.starts_with("terminal explorer failed while drawing the screen ["));
    assert!(message.ends_with(": draw failed"));
}

#[test]
fn control_chords_do_not_type_or_navigate() {
    let mut state = AppState::new();
    assert_eq!(
        classify_key(&mut state, press(KeyCode::Char('/'))),
        KeyOutcome::Handled
    );
    for character in ['a', 'l', 'i'] {
        classify_key(&mut state, press(KeyCode::Char(character)));
    }
    classify_key(&mut state, chord(KeyCode::Char('w')));
    assert_eq!(state.current.query, "ali");
    classify_key(&mut state, chord(KeyCode::Char('u')));
    assert!(state.current.query.is_empty());
    state.cancel_input();
    assert_eq!(
        classify_key(&mut state, chord(KeyCode::Char('j'))),
        KeyOutcome::Handled
    );
    assert_eq!(state.current.selected, 0);
    assert_eq!(
        classify_key(&mut state, chord(KeyCode::Char('r'))),
        KeyOutcome::Handled
    );
    assert_eq!(
        classify_key(&mut state, press(KeyCode::Char('r'))),
        KeyOutcome::Refresh
    );
}

#[test]
fn ctrl_c_quits_from_every_mode() {
    for prepare in [0_u8, 1, 2] {
        let mut state = AppState::new();
        if prepare == 1 {
            state.show_help = true;
        }
        if prepare == 2 {
            state.begin_search();
        }
        classify_key(&mut state, chord(KeyCode::Char('c')));
        assert!(state.should_quit);
    }
}

#[test]
fn table_shortcuts_request_sorting_and_pages() {
    let mut state = AppState::new();
    assert_eq!(
        classify_key(&mut state, press(KeyCode::Char('s'))),
        KeyOutcome::Sort
    );
    assert_eq!(
        classify_key(&mut state, press(KeyCode::Char('n'))),
        KeyOutcome::Page(PageDirection::Next)
    );
    assert_eq!(
        classify_key(&mut state, press(KeyCode::PageUp)),
        KeyOutcome::Page(PageDirection::Previous)
    );
}

#[test]
fn help_lines_fit_at_eighty_columns() {
    const OVERLAY: u16 = 80 * super::super::render::HELP_WIDTH_PERCENT / 100;
    let inner = usize::from(OVERLAY.saturating_sub(3));
    for line in super::super::render::HELP_LINES {
        assert!(ratatui::text::Span::raw(*line).width() <= inner, "{line:?}");
    }
}
