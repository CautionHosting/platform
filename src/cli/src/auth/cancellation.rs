//! Cooperative cancellation for native recovery approval and its terminal input.
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    terminal,
};
use std::{
    io::{self, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use zeroize::Zeroizing;

#[derive(Clone, Default)]
pub(crate) struct Cancellation(Arc<AtomicBool>);

impl Cancellation {
    pub(crate) fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub(crate) fn check(&self) -> io::Result<()> {
        if self.0.load(Ordering::Acquire) {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "native approval cancelled",
            ))
        } else {
            Ok(())
        }
    }

    pub(crate) fn password(&self, label: &str) -> io::Result<String> {
        self.line(label, true)
    }

    pub(crate) fn selection(&self, label: &str) -> io::Result<usize> {
        self.line(label, false)?
            .trim()
            .parse()
            .map_err(io::Error::other)
    }

    fn line(&self, label: &str, hidden: bool) -> io::Result<String> {
        self.check()?;
        let mut terminal = RawMode::enter()?;
        // Echo must already be disabled when the caller sees the prompt.
        let result = (|| {
            let mut output = io::stderr();
            output.write_all(label.as_bytes())?;
            output.flush()?;
            let mut input = Zeroizing::new(String::new());
            loop {
                self.check()?;
                if !event::poll(Duration::from_millis(100))? {
                    continue;
                }
                self.check()?;
                let Event::Key(key) = event::read()? else {
                    continue;
                };
                if key.kind == KeyEventKind::Release {
                    continue;
                }
                let previous_len = input.chars().count();
                match (key.code, key.modifiers.contains(KeyModifiers::CONTROL)) {
                    (KeyCode::Char('c'), true) => {
                        self.cancel();
                        self.check()?;
                    }
                    (KeyCode::Char('d'), true) if input.is_empty() => {
                        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "end of input"));
                    }
                    (KeyCode::Char('u'), true) => input.clear(),
                    (KeyCode::Char('w'), true) => {
                        while input.ends_with(char::is_whitespace) {
                            input.pop();
                        }
                        while !input.is_empty() && !input.ends_with(char::is_whitespace) {
                            input.pop();
                        }
                    }
                    (KeyCode::Backspace, _) | (KeyCode::Char('h'), true) => {
                        input.pop();
                    }
                    (KeyCode::Enter, _) | (KeyCode::Char('j'), true) => {
                        self.check()?;
                        return Ok(std::mem::take(&mut *input));
                    }
                    (KeyCode::Char(c), false)
                        if !c.is_control() && (hidden || c.is_ascii_digit()) =>
                    {
                        input.push(c);
                        if !hidden {
                            write!(output, "{c}")?;
                        }
                    }
                    _ => {}
                }
                if !hidden {
                    for _ in input.chars().count()..previous_len {
                        output.write_all(b"\x08 \x08")?;
                    }
                    output.flush()?;
                }
            }
        })();
        terminal.restore()?;
        writeln!(io::stderr())?;
        result
    }
}

struct RawMode(bool);
impl RawMode {
    fn enter() -> io::Result<Self> {
        let already_raw = terminal::is_raw_mode_enabled()?;
        terminal::enable_raw_mode()?;
        Ok(Self(!already_raw))
    }

    fn restore(&mut self) -> io::Result<()> {
        if self.0 {
            terminal::disable_raw_mode()?;
            self.0 = false;
        }
        Ok(())
    }
}
impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}
