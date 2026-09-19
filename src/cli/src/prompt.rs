// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Interactive prompt helpers for CLI user input.
//!
//! Prompt labels are written to stderr to avoid contaminating piped stdout.

use dterror::BoxError;
use std::io::Write;
use std::str::FromStr;

/// Leaf error for the prompt helpers. Plain `thiserror` (no `CtxError` derive:
/// there is no context field beyond location); callers box it as the
/// `#[source]` of their own typed error at the call site.
#[derive(Debug, thiserror::Error)]
pub enum PromptError {
    #[error("failed to write prompt label [{location}]")]
    WritePrompt {
        #[source]
        source: BoxError,
        location: dterror::Location,
    },

    #[error("no input available (EOF) [{location}]")]
    Eof { location: dterror::Location },

    #[error("failed to read prompt input [{location}]")]
    ReadInput {
        #[source]
        source: BoxError,
        location: dterror::Location,
    },

    #[error("invalid prompt input [{location}]")]
    Parse {
        #[source]
        source: BoxError,
        location: dterror::Location,
    },
}

/// Print the prompt label to stderr and flush.
fn write_prompt(label: &str) -> Result<(), PromptError> {
    let mut stderr = std::io::stderr().lock();
    stderr
        .write_all(label.as_bytes())
        .map_err(|source| PromptError::WritePrompt {
            source: Box::new(source),
            location: std::panic::Location::caller(),
        })?;
    stderr.flush().map_err(|source| PromptError::WritePrompt {
        source: Box::new(source),
        location: std::panic::Location::caller(),
    })?;
    Ok(())
}

/// Read one line from stdin. Returns `Err(Eof)` on EOF (e.g. piped input).
fn read_line() -> Result<String, PromptError> {
    let mut input = String::new();
    let n = std::io::stdin()
        .read_line(&mut input)
        .map_err(|source| PromptError::ReadInput {
            source: Box::new(source),
            location: std::panic::Location::caller(),
        })?;
    if n == 0 {
        return Err(PromptError::Eof {
            location: std::panic::Location::caller(),
        });
    }
    Ok(input)
}

/// Prompt for a non-empty line of text.
///
/// Re-prompts with the same label if the user provides only whitespace.
/// Returns an error on EOF (e.g. piped input).
pub fn text(prompt: &str) -> Result<String, PromptError> {
    loop {
        write_prompt(prompt)?;
        let input = read_line()?;
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
pub fn text_or_default<T: FromStr>(prompt: &str, default: T) -> Result<T, PromptError>
where
    <T as FromStr>::Err: std::error::Error + Send + Sync + 'static,
{
    write_prompt(prompt)?;
    let input = read_line()?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(default);
    }
    trimmed.parse::<T>().map_err(|source| PromptError::Parse {
        source: Box::new(source),
        location: std::panic::Location::caller(),
    })
}

/// Prompt for a y/N confirmation. Returns true only for "y" or "Y".
/// Returns an error on EOF.
pub fn confirm(label: &str) -> Result<bool, PromptError> {
    write_prompt(label)?;
    let input = read_line()?;
    Ok(input.trim() == "y" || input.trim() == "Y")
}

/// Read a password-like value without echo.
///
/// Writes the prompt label to stderr, then reads from stdin with echo suppressed.
pub fn password(prompt: &str) -> Result<String, PromptError> {
    write_prompt(prompt)?;
    rpassword::read_password().map_err(|source| PromptError::ReadInput {
        source: Box::new(source),
        location: std::panic::Location::caller(),
    })
}

/// Prompt for a numeric selection from a list of items.
///
/// Writes the prompt label (e.g. `"Enter selection (0-2): "`) to stderr,
/// reads a usize from stdin, and returns it. The caller is responsible for
/// displaying the list and validating the range. Returns an error on EOF.
pub fn select(prompt: &str) -> Result<usize, PromptError> {
    write_prompt(prompt)?;
    let input = read_line()?;
    let trimmed = input.trim();
    trimmed
        .parse::<usize>()
        .map_err(|source| PromptError::Parse {
            source: Box::new(source),
            location: std::panic::Location::caller(),
        })
}
