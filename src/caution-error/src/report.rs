// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Structured, actionable error reports.
//!
//! An error surfaces two kinds of guidance to the client: [`Note`]s and
//! [`Warning`]s. An error owns them as `&[Note]` / `&[Warning]` in the provider
//! API, so the derive can expose a `Vec<Note>` / `Vec<Warning>` field, and a
//! report reads them off each error in the chain:
//!
//! ```rust
//! use caution_error::{ErrorReport, Note, ProviderError, Request, request_ref};
//!
//! #[derive(Debug)]
//! struct Busy {
//!     notes: Vec<Note>,
//! }
//!
//! impl std::fmt::Display for Busy {
//!     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//!         f.write_str("the device is busy")
//!     }
//! }
//!
//! impl std::error::Error for Busy {}
//!
//! impl ProviderError for Busy {
//!     fn provide<'a>(&'a self, request: &mut Request<'a>) {
//!         request.provide_ref::<[Note]>(&self.notes);
//!     }
//! }
//!
//! let error = Busy { notes: vec![Note("retry in a few seconds".to_string())] };
//! let report = ErrorReport::from_error(&error);
//! assert_eq!(report.error, "the device is busy");
//! assert_eq!(report.errors[0].notes[0].0, "retry in a few seconds");
//! ```
//!
//! The report is a wire contract shared by the API and the gateway. `error`
//! repeats the first chain entry so older clients that read a flat `error`
//! string keep working while others read `errors`.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{ProviderError, request_ref};

/// The client-facing location type carried by an error.
///
/// This matches `dterror::Location` (`&'static std::panic::Location<'static>`).
/// Errors expose it through the provider API; use [`location`] to read it.
pub type Location = std::panic::Location<'static>;

/// A piece of guidance that helps a client resolve an error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Note(pub String);

impl fmt::Display for Note {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A caution that a client may want to take into account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Warning(pub String);

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One error in the chain, as reported to a client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// The error's [`Display`](std::fmt::Display) output.
    pub error: String,

    /// Guidance provided by this error, in order.
    pub notes: Vec<Note>,

    /// Warnings provided by this error, in order.
    pub warnings: Vec<Warning>,
}

/// The full error report: the root message plus every error in the chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorReport {
    /// The root error's [`Display`](std::fmt::Display) output.
    ///
    /// This repeats `errors[0].error`. Clients that only read a flat `error`
    /// string keep working.
    pub error: String,

    /// One entry per error in the chain, root first.
    pub errors: Vec<ErrorResponse>,
}

impl ErrorReport {
    /// Builds a report from an error and its chain.
    ///
    /// The chain is walked through
    /// [`provider_source`](ProviderError::provider_source) first, so typed
    /// sources are reached, and through [`std::error::Error::source`] for a
    /// source that is not itself a [`ProviderError`]. A boxed source still
    /// appears (with no notes or warnings).
    #[must_use]
    pub fn from_error(error: &dyn ProviderError) -> Self {
        Self {
            error: error.to_string(),
            errors: chain(error),
        }
    }
}

/// Builds a report from an error and its chain. See [`ErrorReport::from_error`].
#[must_use]
pub fn report(error: &dyn ProviderError) -> ErrorReport {
    ErrorReport::from_error(error)
}

/// Returns the client-facing location an error provides, when it provides one.
///
/// A `#[provide(location)]` field is exposed by `#[derive(ProviderError)]`.
#[must_use]
pub fn location(error: &dyn ProviderError) -> Option<&Location> {
    request_ref::<Location>(error)
}

/// Bounds a pathological source chain. Real chains are a few links deep.
const MAX_CHAIN_LINKS: usize = 64;

/// Walks the error chain and builds one [`ErrorResponse`] per link.
fn chain(root: &dyn ProviderError) -> Vec<ErrorResponse> {
    let mut responses = Vec::new();
    let mut provider: Option<&dyn ProviderError> = Some(root);
    let mut error: &(dyn std::error::Error + 'static) = root;

    for _ in 0..MAX_CHAIN_LINKS {
        responses.push(ErrorResponse {
            error: error.to_string(),
            notes: slice_copy(provider.and_then(|p| request_ref::<[Note]>(p))),
            warnings: slice_copy(provider.and_then(|p| request_ref::<[Warning]>(p))),
        });

        if let Some(next) = provider.and_then(|p| p.provider_source()) {
            let upcast: &(dyn std::error::Error + 'static) = next;
            error = upcast;
            provider = Some(next);
            continue;
        }

        match std::error::Error::source(error) {
            Some(source) => {
                error = source;
                provider = None;
            }
            None => break,
        }
    }

    responses
}

/// Copies a provided slice into an owned vector.
fn slice_copy<T: Clone>(slice: Option<&[T]>) -> Vec<T> {
    slice.map(<[T]>::to_vec).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{ErrorReport, Note, Warning};
    use crate::{ProviderError, Request, request_ref};

    #[derive(Debug)]
    struct Root {
        notes: Vec<Note>,
        warnings: Vec<Warning>,
        source: Inner,
    }

    #[derive(Debug)]
    struct Inner {
        notes: Vec<Note>,
    }

    #[derive(Debug)]
    struct Boxed;

    impl std::fmt::Display for Root {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("root failed")
        }
    }

    impl std::fmt::Display for Inner {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("inner failed")
        }
    }

    impl std::fmt::Display for Boxed {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("boxed failed")
        }
    }

    impl std::error::Error for Root {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.source)
        }
    }

    impl std::error::Error for Inner {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&Boxed)
        }
    }

    impl std::error::Error for Boxed {}

    impl ProviderError for Root {
        fn provide<'a>(&'a self, request: &mut Request<'a>) {
            request.provide_ref::<[Note]>(&self.notes);
            request.provide_ref::<[Warning]>(&self.warnings);
        }

        fn provider_source(&self) -> Option<&(dyn ProviderError + 'static)> {
            Some(&self.source)
        }
    }

    impl ProviderError for Inner {
        fn provide<'a>(&'a self, request: &mut Request<'a>) {
            request.provide_ref::<[Note]>(&self.notes);
        }
    }

    #[test]
    fn report_covers_provider_and_boxed_links() {
        let error = Root {
            notes: vec![Note("root note".to_string())],
            warnings: vec![Warning("root warning".to_string())],
            source: Inner {
                notes: vec![Note("inner note".to_string())],
            },
        };

        let report = ErrorReport::from_error(&error);

        assert_eq!(report.error, "root failed");
        assert_eq!(report.errors.len(), 3, "typed source then boxed source");

        assert_eq!(report.errors[0].error, "root failed");
        assert_eq!(report.errors[0].notes[0].0, "root note");
        assert_eq!(report.errors[0].warnings[0].0, "root warning");

        assert_eq!(report.errors[1].error, "inner failed");
        assert_eq!(report.errors[1].notes[0].0, "inner note");
        assert!(report.errors[1].warnings.is_empty());

        assert_eq!(report.errors[2].error, "boxed failed");
        assert!(report.errors[2].notes.is_empty());
    }

    #[test]
    fn notes_and_warnings_are_bare_json_strings() {
        let report = ErrorReport {
            error: "boom".to_string(),
            errors: vec![super::ErrorResponse {
                error: "boom".to_string(),
                notes: vec![Note("do x".to_string())],
                warnings: vec![Warning("careful".to_string())],
            }],
        };

        let json = serde_json::to_value(&report).expect("serializes");
        assert_eq!(json["error"], "boom");
        assert_eq!(json["errors"][0]["notes"][0], "do x");
        assert_eq!(json["errors"][0]["warnings"][0], "careful");
    }

    #[test]
    fn location_is_read_from_the_provider_api() {
        #[derive(Debug)]
        struct Located;

        impl std::fmt::Display for Located {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("located")
            }
        }

        impl std::error::Error for Located {}

        #[track_caller]
        fn site() -> &'static std::panic::Location<'static> {
            std::panic::Location::caller()
        }

        impl ProviderError for Located {
            fn provide<'a>(&'a self, request: &mut Request<'a>) {
                request.provide_ref::<super::Location>(site());
            }
        }

        let located = super::location(&Located).expect("location provided");
        assert!(located.file().ends_with("report.rs"));
        assert!(request_ref::<super::Location>(&Located).is_some());
    }
}
