// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Resolve the name for a newly created app.
//!
//! The CLI has two creation entry points, `caution init` and
//! `caution apps create`, and both must derive a name the same way. An explicit
//! `--name` is validated and never rewritten; a name derived from the working
//! directory is sanitized, since the user never typed it. Both go through the
//! same rule the API enforces, so the CLI cannot post a name the server rejects.

use caution_config::app_name::{self, AppNameError};

/// Resolve the app name to create.
///
/// An explicit `--name` is validated and returned unchanged; without one, the
/// current directory's name is sanitized into a valid name, falling back to
/// `app` when nothing usable survives.
pub(crate) fn resolve(name: Option<String>) -> Result<String, AppNameError> {
    match name {
        Some(explicit) => validate_explicit(explicit),
        None => Ok(std::env::current_dir()
            .ok()
            .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
            .and_then(|dir| app_name::sanitize(&dir))
            .unwrap_or_else(|| "app".to_string())),
    }
}

/// Validate an explicit, user-typed name without rewriting it.
fn validate_explicit(name: String) -> Result<String, AppNameError> {
    app_name::validate(&name).map(|()| name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_name_is_kept_verbatim_when_valid() {
        assert_eq!(resolve(Some("My-App".to_string())).unwrap(), "My-App");
        assert_eq!(resolve(Some("my_app".to_string())).unwrap(), "my_app");
    }

    #[test]
    fn explicit_name_is_never_rewritten() {
        // A sanitizer would turn this into `_my.app` -> `my-app`; an explicit
        // name must surface the error instead.
        assert!(resolve(Some("_my.app".to_string())).is_err());
    }
}
