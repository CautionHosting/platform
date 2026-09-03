// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Interactive prompt helpers for CLI user input.
//!
//! Prompt labels are written to stderr to avoid contaminating piped stdout.

use std::io::{self, Write};
use std::str::FromStr;

/// Print the prompt label to stderr and flush.
fn write_prompt(label: &str) -> io::Result<()> {
    io::stderr().write_all(label.as_bytes())?;
    io::stderr().flush()?;
    Ok(())
}

/// Prompt for a non-empty line of text.
///
/// Re-prompts with the same label if the user provides only whitespace.
/// Returns an error on EOF (e.g. piped input).
pub fn text(prompt: &str) -> io::Result<String> {
    loop {
        write_prompt(prompt)?;
        let mut input = String::new();
        let n = io::stdin().read_line(&mut input)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"));
        }
        let trimmed = input.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
        // Re-prompt on empty input (don't print retry message — just loop)
    }
}

/// Prompt for a value, returning a default on bare Enter.
///
/// Use this for prompts that display a default value (e.g. `"Port [22]: "`).
/// Pressing Enter returns the provided default. If the user enters text, it is
/// parsed as `T` via `FromStr`. Returns an error on EOF or parse failure.
pub fn text_or_default<T: FromStr>(prompt: &str, default: T) -> io::Result<T> {
    write_prompt(prompt)?;
    let mut input = String::new();
    let n = io::stdin().read_line(&mut input)?;
    if n == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"));
    }
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(default);
    }
    trimmed
        .parse::<T>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid input"))
}

/// Prompt for a y/N confirmation. Returns true only for "y" or "Y".
/// Returns an error on EOF.
pub fn confirm(label: &str) -> io::Result<bool> {
    write_prompt(label)?;
    let mut input = String::new();
    let n = io::stdin().read_line(&mut input)?;
    if n == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"));
    }
    Ok(input.trim() == "y" || input.trim() == "Y")
}

/// Read a password-like value without echo.
///
/// Both the label and the (echo-suppressed) read go to the controlling
/// terminal — `/dev/tty` on unix — not to stdin/stderr. Writing the label
/// anywhere else would hide it whenever stderr is redirected, leaving the
/// command blocked on a terminal read with nothing on screen to explain why.
pub fn password(prompt: &str) -> io::Result<String> {
    rpassword::prompt_password(prompt).map_err(io::Error::other)
}

/// Prompt for a numeric selection from a list of items.
///
/// Writes the prompt label (e.g. `"Enter selection (0-2): "`) to stderr,
/// reads a usize from stdin, and returns it. The caller is responsible for
/// displaying the list and validating the range. Returns an error on EOF.
pub fn select(prompt: &str) -> io::Result<usize> {
    write_prompt(prompt)?;
    let mut input = String::new();
    let n = io::stdin().read_line(&mut input)?;
    if n == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"));
    }
    input
        .trim()
        .parse::<usize>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}
