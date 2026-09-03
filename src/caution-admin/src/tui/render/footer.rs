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
    let (text, _) = content(state);
    u16::try_from(wrapped_line_count(&terminal_text(&text), width.max(1)))
        .unwrap_or(MAX_HEIGHT)
        .clamp(1, MAX_HEIGHT)
}

pub(super) fn render(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let (text, style) = content(state);
    let text = terminal_text(&text);
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

fn content(state: &AppState) -> (String, Style) {
    if let Some(status) = &state.current.status {
        (status.text.clone(), status_style(status.level))
    } else if state.aws_loading.is_some() {
        (
            "AWS request in progress · Backspace cancel · q quit".to_string(),
            Style::default().fg(Color::Cyan),
        )
    } else if state.current.input_mode {
        (
            "Type query · Enter search · Esc cancel · Backspace delete".to_string(),
            Style::default(),
        )
    } else {
        (actions(state), Style::default())
    }
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

#[cfg(test)]
mod tests {
    use super::{content, height, wrapped_line_count};
    use crate::state::AppState;

    #[test]
    fn input_footer_height_measures_the_rendered_hint() {
        let mut state = AppState::new();
        state.begin_search();
        let width = 20;
        let (text, _) = content(&state);

        assert_eq!(
            usize::from(height(&state, width)),
            wrapped_line_count(&text, width)
        );
    }
}
