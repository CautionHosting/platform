// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::Span,
    widgets::{Paragraph, Wrap},
};

use crate::{
    aws::AwsAction,
    state::{AppState, Row, StatusLevel},
};

use super::terminal_text;

pub(super) fn height(state: &AppState, width: u16) -> u16 {
    const MAX_HEIGHT: u16 = 5;
    let text = state
        .current
        .status
        .as_ref()
        .map_or_else(|| actions(state), |status| status.text.clone());
    u16::try_from(wrapped_line_count(&terminal_text(&text), width.max(1)))
        .unwrap_or(MAX_HEIGHT)
        .clamp(1, MAX_HEIGHT)
}

pub(super) fn render(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let (text, style) = if let Some(status) = &state.current.status {
        (terminal_text(&status.text), status_style(status.level))
    } else if state.current.input_mode {
        (
            "Type query · Enter search · Esc cancel · Backspace delete".to_string(),
            Style::default(),
        )
    } else {
        (actions(state), Style::default())
    };
    let lines = u16::try_from(wrapped_line_count(&text, area.width.max(1))).unwrap_or(u16::MAX);
    let scroll = if matches!(
        state.current.status.as_ref().map(|status| status.level),
        Some(StatusLevel::Error)
    ) {
        lines.saturating_sub(area.height)
    } else {
        0
    };
    frame.render_widget(
        Paragraph::new(text)
            .style(style)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        area,
    );
}

fn status_style(level: StatusLevel) -> Style {
    Style::default().fg(match level {
        StatusLevel::Info => Color::Cyan,
        StatusLevel::Warning => Color::Yellow,
        StatusLevel::Error => Color::Red,
    })
}

fn actions(state: &AppState) -> String {
    let can_open = match state.selected_row() {
        Some(Row::Aws(row)) => !matches!(row.action, AwsAction::None),
        Some(
            Row::Browse(_)
            | Row::AwsRoot
            | Row::Resource(_)
            | Row::Relation(_)
            | Row::Related(_)
            | Row::AwsFinding(_)
            | Row::AwsHost(_),
        ) => true,
        None => false,
    };
    let mut actions = vec!["↑↓/jk move"];
    if can_open {
        actions.push("Enter open");
    }
    if !state.current.sort_columns().is_empty() {
        actions.push("s sort");
    }
    if let Some(page) = state.current.page {
        if page.has_previous() {
            actions.push("p/PgUp prev");
        }
        if page.has_more {
            actions.push("n/PgDn next");
        }
    }
    actions.extend(["Bksp back", "/ search", "r refresh", "? help", "q quit"]);
    actions.join(" · ")
}

fn wrapped_line_count(text: &str, width: u16) -> usize {
    let width = usize::from(width);
    let mut rows = 1;
    let mut used = 0;
    for word in text.split_whitespace() {
        let word_width = Span::raw(word).width();
        let needed = if used == 0 {
            word_width
        } else {
            used + 1 + word_width
        };
        if needed > width && used > 0 {
            rows += 1;
            used = word_width;
        } else {
            used = needed;
        }
        while used > width {
            rows += 1;
            used -= width;
        }
    }
    rows
}
