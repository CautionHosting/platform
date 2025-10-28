// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::io::{self, Write};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::Duration;

/// Loader style for different use cases
pub enum LoaderStyle {
    /// For waiting on security key tap (arrows moving left to right)
    KeyTap,
    /// For general waiting/processing (spinning braille)
    Processing,
}

/// A CLI loader that displays an animated pattern
/// while a long-running operation is in progress.
pub struct Loader {
    running: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Loader {
    /// Create a new loader with a custom message and style
    pub fn new(message: &str, style: LoaderStyle) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();
        let message = message.to_string();

        let handle = thread::spawn(move || {
            let frames = match style {
                LoaderStyle::KeyTap => vec![
                    "▹▹▹", "▸▹▹", "▹▸▹", "▹▹▸"
                ],
                LoaderStyle::Processing => vec![
                    "⣼", "⣹", "⢻", "⠿", "⡟", "⣏", "⣧", "⣶"
                ],
            };

            let mut frame_idx = 0;
            let mut stdout = io::stdout();

            // Hide cursor
            print!("\x1B[?25l");
            let _ = stdout.flush();

            while running_clone.load(Ordering::Relaxed) {
                // Clear the current line and move to beginning
                print!("\r\x1B[K{} {}", frames[frame_idx], message);
                let _ = stdout.flush();

                frame_idx = (frame_idx + 1) % frames.len();
                thread::sleep(Duration::from_millis(120));
            }

            // Clear the loader output
            print!("\r\x1B[K");

            // Show cursor
            print!("\x1B[?25h");
            let _ = stdout.flush();
        });

        Self {
            running,
            handle: Some(handle),
        }
    }

    /// Stop the loader animation
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Loader {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Helper function to run a closure with a loader
pub fn with_loader<F, T>(message: &str, style: LoaderStyle, f: F) -> T
where
    F: FnOnce() -> T,
{
    let mut loader = Loader::new(message, style);
    let result = f();
    loader.stop();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loader_creation() {
        let mut loader = Loader::new("Testing", LoaderStyle::Processing);
        thread::sleep(Duration::from_millis(500));
        loader.stop();
    }

    #[test]
    fn test_with_loader() {
        let result = with_loader("Processing", LoaderStyle::Processing, || {
            thread::sleep(Duration::from_millis(500));
            42
        });
        assert_eq!(result, 42);
    }
}
