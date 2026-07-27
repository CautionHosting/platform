// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Interactive prompt helpers for CLI user input.
//!
//! Prompt labels are written to stderr to avoid contaminating piped stdout.

use std::io::{self, Write};

/// Print the prompt label to stderr and flush.
fn write_prompt(label: &str) -> io::Result<()> {
    io::stderr().write_all(label.as_bytes())?;
    io::stderr().flush()?;
    Ok(())
}

/// Prompt for a non-empty line of text.
///
/// Re-prompts with the same label if the user provides only whitespace.
pub fn text(prompt: &str) -> io::Result<String> {
    loop {
        write_prompt(prompt)?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let trimmed = input.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
        // Re-prompt on empty input (don't print retry message — just loop)
    }
}

/// Prompt for a y/N confirmation. Returns true only for "y" or "Y".
pub fn confirm(label: &str) -> io::Result<bool> {
    write_prompt(label)?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim() == "y" || input.trim() == "Y")
}

/// Read a password-like value without echo.
///
/// Writes the prompt label to stderr, then reads from stdin with echo suppressed.
pub fn password(prompt: &str) -> io::Result<String> {
    write_prompt(prompt)?;
    rpassword::read_password().map_err(|e| io::Error::new(io::ErrorKind::Other, e))
}

/// Prompt for a numeric selection from a list of items.
///
/// Writes the prompt label (e.g. `"Enter selection (0-2): "`) to stderr,
/// reads a usize from stdin, and returns it. The caller is responsible for
/// displaying the list and validating the range.
pub fn select(prompt: &str) -> io::Result<usize> {
    write_prompt(prompt)?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    input
        .trim()
        .parse::<usize>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}
