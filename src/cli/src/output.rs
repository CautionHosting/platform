// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Standardized CLI output API.
//!
//! All human-facing content routes to stderr; machine-readable data goes to stdout.

use indicatif::{ProgressBar, ProgressStyle};
use std::io::{self, IsTerminal, Write};

/// Print a status message to stderr (informational progress).
pub fn status(msg: impl std::fmt::Display) {
    eprintln!("{msg}");
}

/// Print a success confirmation to stderr.
pub fn success(msg: impl std::fmt::Display) {
    eprintln!("{msg}");
}

/// Print a warning message to stderr.
pub fn warning(msg: impl std::fmt::Display) {
    eprintln!("{msg}");
}

/// Print an error message to stderr (used only in the binary entrypoint).
pub fn error(msg: impl std::fmt::Display) {
    eprintln!("{msg}");
}

/// Write a verbose diagnostic message to stderr when `enabled` is true.
///
/// This is the centralized path for all `[VERBOSE]` output. When `enabled` is
/// false, this function is a no-op. The `[VERBOSE]` prefix is applied here so
/// that all verbose output flows through a single function.
pub fn verbose(enabled: bool, msg: impl std::fmt::Display) {
    if enabled {
        eprintln!("[VERBOSE] {msg}");
    }
}

/// Write machine-readable data directly to stdout.
///
/// Piped consumers receive complete output without UI contamination.
pub fn data(msg: impl std::fmt::Display) -> io::Result<()> {
    let msg = format!("{msg}");
    io::stdout().write_all(msg.as_bytes())?;
    Ok(())
}

/// Write a line of machine-readable data to stdout.
pub fn data_ln(msg: impl std::fmt::Display) -> io::Result<()> {
    let msg = format!("{msg}\n");
    io::stdout().write_all(msg.as_bytes())?;
    Ok(())
}

/// Print a section header for data display to stderr.
///
/// Use this for headers in list views (e.g. "SSH Keys:", "Apps:") so they
/// don't leak into piped stdout.
pub fn data_header(msg: impl std::fmt::Display) {
    eprintln!("{msg}");
}

/// Returns true if stderr is connected to a terminal.
pub fn is_tty() -> bool {
    io::stderr().is_terminal()
}

/// Returns true if stdout is connected to a terminal.
pub fn is_tty_stdout() -> bool {
    io::stdout().is_terminal()
}

// ---------------------------------------------------------------------------

/// Tick style for animated spinners.
#[derive(Debug, Clone, Copy)]
pub enum SpinnerStyle {
    /// For waiting on security key tap (arrows moving left to right)
    KeyTap,
    /// For general waiting/processing (spinning braille)
    Processing,
}

/// An animated spinner backed by indicatif's ProgressBar.
///
/// Automatically suppressed when not attached to a terminal. Calls to `finish()`
/// clear the line; if dropped without calling `finish()`, it still cleans up.
pub struct Spinner {
    pb: Option<ProgressBar>,
}

impl Spinner {
    /// Create a new spinner with the given message and style.
    ///
    /// When not on a terminal, creates a no-op progress bar that produces no output.
    pub fn new(msg: &str, style: SpinnerStyle) -> Self {
        let pb = ProgressBar::new(0);

        if is_tty() {
            match style {
                SpinnerStyle::KeyTap => {
                    pb.set_style(
                        ProgressStyle::default_spinner()
                            .tick_strings(&["▹▹▹", "▸▹▹", "▹▸▹", "▹▹▸"])
                            .template("{spinner} {msg}")
                            .unwrap(),
                    );
                }
                SpinnerStyle::Processing => {
                    pb.set_style(
                        ProgressStyle::default_spinner()
                            .tick_strings(&["⣼", "⣹", "⢻", "⠿", "⡟", "⣏", "⣧", "⣶"])
                            .template("{spinner} {msg}")
                            .unwrap(),
                    );
                }
            }
            pb.enable_steady_tick(std::time::Duration::from_millis(120));
        }

        pb.set_message(msg.to_string());

        Self { pb: Some(pb) }
    }

    /// Update the spinner message mid-flight.
    pub fn set_message(&self, msg: &str) {
        if let Some(ref pb) = self.pb {
            pb.set_message(msg.to_string());
        }
    }

    /// Stop the spinner and clear its line from the terminal.
    ///
    /// Use this before printing other output (prompts, error messages) so the
    /// spinner text doesn't linger on screen.
    pub fn abandon(&mut self) {
        if let Some(pb) = self.pb.take() {
            pb.finish_and_clear();
        }
    }

    /// Finish the spinner, clearing its line from the terminal.
    ///
    /// This method consumes the Spinner so it can only be called once.
    pub fn finish(mut self) {
        if let Some(pb) = self.pb.take() {
            pb.finish_and_clear();
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        // Safety net: if neither abandon() nor finish() was called, clean up.
        // In practice this path is rarely hit since callers explicitly clear
        // the spinner before printing other output.
        if let Some(pb) = self.pb.take() {
            pb.finish_and_clear();
        }
    }
}
