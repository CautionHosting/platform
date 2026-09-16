//! App name rules, shared by the CLI and the API.
//!
//! These lived only in the API, so the CLI hand-rolled a looser check and could
//! derive a default name from the working directory that the server always
//! rejected (a leading `_`, for instance, is legal mid-name but not at the edge).

use std::fmt;

pub const MIN_LEN: usize = 3;
pub const MAX_LEN: usize = 63;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppNameError {
    Length {
        actual: usize,
    },
    /// First or last character is not ASCII-alphanumeric.
    Boundary {
        ch: char,
    },
    /// Character is illegal in any position.
    InvalidChar {
        ch: char,
    },
}

impl fmt::Display for AppNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { actual } => write!(
                f,
                "app name must be between {} and {} characters (got {})",
                MIN_LEN, MAX_LEN, actual
            ),
            Self::Boundary { ch } => write!(
                f,
                "app name must start and end with a letter or digit (found '{}')",
                ch
            ),
            Self::InvalidChar { ch } => {
                write!(f, "app name contains invalid character '{}'", ch)
            }
        }
    }
}

impl std::error::Error for AppNameError {}

fn is_body(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// Equivalent to `^[a-zA-Z0-9]([a-zA-Z0-9_-]*[a-zA-Z0-9])?$` plus the length bounds.
pub fn validate(name: &str) -> Result<(), AppNameError> {
    let len = name.len();
    if !(MIN_LEN..=MAX_LEN).contains(&len) {
        return Err(AppNameError::Length { actual: len });
    }

    // An illegal character is the more specific complaint when a name breaks
    // both rules, so report it before the boundary violation.
    if let Some(ch) = name.chars().find(|c| !is_body(*c)) {
        return Err(AppNameError::InvalidChar { ch });
    }

    let mut chars = name.chars();
    let first = chars.next().expect("non-empty: length checked above");
    if !first.is_ascii_alphanumeric() {
        return Err(AppNameError::Boundary { ch: first });
    }
    let last = chars
        .next_back()
        .expect("len >= MIN_LEN, so at least 2 chars");
    if !last.is_ascii_alphanumeric() {
        return Err(AppNameError::Boundary { ch: last });
    }

    Ok(())
}

/// Coerce an arbitrary string (typically a directory name) into a valid app name.
/// Legal underscores are kept; anything illegal becomes a hyphen, and runs of
/// hyphens collapse so a stripped character does not double one up.
///
/// Returns `None` when nothing usable survives; callers pick their own fallback.
pub fn sanitize(raw: &str) -> Option<String> {
    let mut out = String::with_capacity(raw.len());
    for c in raw.to_lowercase().chars() {
        let c = if is_body(c) { c } else { '-' };
        if c == '-' && out.ends_with('-') {
            continue;
        }
        out.push(c);
    }

    // Trim to the outermost alphanumerics: the boundary rule allows nothing else.
    let start = out.find(|c: char| c.is_ascii_alphanumeric())?;
    let end = out
        .rfind(|c: char| c.is_ascii_alphanumeric())
        .expect("a start was found, so there is a last one too");
    out.truncate(end + 1);
    out.drain(..start);

    // Truncating can expose a trailing '-' or '_'.
    out.truncate(MAX_LEN);
    while out
        .chars()
        .next_back()
        .is_some_and(|c| !c.is_ascii_alphanumeric())
    {
        out.pop();
    }

    (out.len() >= MIN_LEN).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_names() {
        for name in [
            "my-app",
            "my_app",
            "my-app_v2",
            "app--name",
            "app__name",
            "My-App",
            "api-v2",
            "a1b",
            &"a".repeat(MAX_LEN),
        ] {
            assert!(validate(name).is_ok(), "expected {name:?} to be valid");
        }
    }

    #[test]
    fn rejects_out_of_range_lengths() {
        assert_eq!(validate(""), Err(AppNameError::Length { actual: 0 }));
        assert_eq!(validate("ab"), Err(AppNameError::Length { actual: 2 }));
        assert_eq!(
            validate(&"a".repeat(MAX_LEN + 1)),
            Err(AppNameError::Length {
                actual: MAX_LEN + 1
            })
        );
    }

    #[test]
    fn rejects_non_alphanumeric_boundaries() {
        // The bug this module exists for: '_' is legal mid-name, not at the edge.
        assert_eq!(
            validate("_dummy_locksmith_test_app"),
            Err(AppNameError::Boundary { ch: '_' })
        );
        assert_eq!(validate("app_"), Err(AppNameError::Boundary { ch: '_' }));
        assert_eq!(validate("-app"), Err(AppNameError::Boundary { ch: '-' }));
        assert_eq!(validate("app-"), Err(AppNameError::Boundary { ch: '-' }));
    }

    #[test]
    fn rejects_illegal_characters_before_boundary_violations() {
        assert_eq!(
            validate("app.name"),
            Err(AppNameError::InvalidChar { ch: '.' })
        );
        assert_eq!(
            validate("app name"),
            Err(AppNameError::InvalidChar { ch: ' ' })
        );
        // Broken on both counts: the illegal character wins.
        assert_eq!(
            validate("_app.name"),
            Err(AppNameError::InvalidChar { ch: '.' })
        );
        assert_eq!(
            validate("café-svc"),
            Err(AppNameError::InvalidChar { ch: 'é' })
        );
    }

    #[test]
    fn sanitizes_directory_names() {
        assert_eq!(
            sanitize("_dummy_locksmith_test_app").as_deref(),
            Some("dummy_locksmith_test_app")
        );
        assert_eq!(sanitize("_pgp_test_keys").as_deref(), Some("pgp_test_keys"));
        assert_eq!(sanitize("My App").as_deref(), Some("my-app"));
        assert_eq!(sanitize("café-svc").as_deref(), Some("caf-svc"));
        assert_eq!(sanitize("already-valid").as_deref(), Some("already-valid"));
        assert_eq!(sanitize("  spaced  out  ").as_deref(), Some("spaced-out"));
    }

    #[test]
    fn sanitize_gives_up_when_nothing_usable_survives() {
        assert_eq!(sanitize(""), None);
        assert_eq!(sanitize("ab"), None);
        assert_eq!(sanitize("__"), None);
        assert_eq!(sanitize("///"), None);
    }

    #[test]
    fn sanitize_truncates_without_leaving_a_bad_boundary() {
        let long = format!("{}--tail", "a".repeat(MAX_LEN - 1));
        let out = sanitize(&long).expect("long name should survive");
        assert_eq!(out, "a".repeat(MAX_LEN - 1));
        assert!(validate(&out).is_ok());
    }

    #[test]
    fn sanitize_output_always_validates() {
        for raw in [
            "_dummy_locksmith_test_app",
            "My App",
            "café-svc",
            "---x---",
            "a_b",
            "  spaced  out  ",
            "ÜBER_APP",
            &"x".repeat(200),
            &format!("{}_", "y".repeat(MAX_LEN)),
        ] {
            match sanitize(raw) {
                Some(name) => assert!(
                    validate(&name).is_ok(),
                    "sanitize({raw:?}) produced invalid {name:?}"
                ),
                None => {}
            }
        }
    }
}
