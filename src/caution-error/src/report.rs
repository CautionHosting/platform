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
//! let error = Busy { notes: vec![Note::from("retry in a few seconds")] };
//! let report = ErrorReport::from_error(&error);
//! assert_eq!(report.error, "the device is busy");
//! assert_eq!(report.errors[0].notes[0].0, "retry in a few seconds");
//! ```
//!
//! The report is a wire contract shared by the API and the gateway. `error`
//! repeats the first chain entry so older clients that read a flat `error`
//! string keep working while others read `errors`.

use std::borrow::Cow;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{ProviderError, request_ref, request_value};

/// A piece of guidance that helps a client resolve an error.
///
/// Use it when the client can change the outcome: it names the next step, so
/// the next attempt can succeed. See
/// [choosing between a Note and a Warning](crate#choosing-between-a-note-and-a-warning).
///
/// Holds a [`Cow`] so a fixed message can borrow a `'static` literal and a
/// computed message can own its string. [`From<&'static str>`](From) and
/// `From<String>` let a `dterror` context field be built from a literal:
/// `Ctx::new("retry shortly")`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Note(pub Cow<'static, str>);

impl Note {
    /// Builds a note from anything that becomes a `Cow<'static, str>`.
    #[must_use]
    pub fn new(message: impl Into<Cow<'static, str>>) -> Self {
        Self(message.into())
    }

    /// Builds a note from a `'static` literal.
    ///
    /// This is `const` (unlike [`From::from`]), so it can build a `static`
    /// slice of notes: `static NOTES: &[Note] = &[Note::from_static("…")];`.
    #[must_use]
    pub const fn from_static(message: &'static str) -> Self {
        Self(Cow::Borrowed(message))
    }
}

impl fmt::Display for Note {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&'static str> for Note {
    fn from(message: &'static str) -> Self {
        Self(Cow::Borrowed(message))
    }
}

impl From<String> for Note {
    fn from(message: String) -> Self {
        Self(Cow::Owned(message))
    }
}

impl From<Cow<'static, str>> for Note {
    fn from(message: Cow<'static, str>) -> Self {
        Self(message)
    }
}

/// A caution that a client may want to take into account.
///
/// Use it for a consequence the client cannot change but should weigh: a cost,
/// a risk, or a property of the result. See
/// [choosing between a Note and a Warning](crate#choosing-between-a-note-and-a-warning).
///
/// Holds a [`Cow`] for the same reason as [`Note`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Warning(pub Cow<'static, str>);

impl Warning {
    /// Builds a warning from anything that becomes a `Cow<'static, str>`.
    #[must_use]
    pub fn new(message: impl Into<Cow<'static, str>>) -> Self {
        Self(message.into())
    }

    /// Builds a warning from a `'static` literal. See [`Note::from_static`].
    #[must_use]
    pub const fn from_static(message: &'static str) -> Self {
        Self(Cow::Borrowed(message))
    }
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&'static str> for Warning {
    fn from(message: &'static str) -> Self {
        Self(Cow::Borrowed(message))
    }
}

impl From<String> for Warning {
    fn from(message: String) -> Self {
        Self(Cow::Owned(message))
    }
}

impl From<Cow<'static, str>> for Warning {
    fn from(message: Cow<'static, str>) -> Self {
        Self(message)
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
    ///
    /// A link that provides [`Opaque`] and every source below it are dropped, so
    /// the report never carries them. When the root itself is [`Opaque`] no link
    /// remains and the report is empty; use [`ErrorReport::from_error_with`] to
    /// supply the client-safe message for that case.
    #[must_use]
    pub fn from_error(error: &dyn ProviderError) -> Self {
        Self::walk(error, None)
    }

    /// Builds a report from an error and its chain, using `fallback` as the
    /// client message when no non-[`Opaque`] link remains.
    ///
    /// A root error that provides [`Opaque`] is dropped along with its chain, so
    /// `fallback` is what the client sees. See [`ErrorReport::from_error`].
    #[must_use]
    pub fn from_error_with(error: &dyn ProviderError, fallback: impl Into<String>) -> Self {
        Self::walk(error, Some(fallback.into()))
    }

    /// Walks the chain, substituting `fallback` for a report that is otherwise
    /// empty.
    fn walk(error: &dyn ProviderError, fallback: Option<String>) -> Self {
        let errors = responses(error);
        match errors.first() {
            Some(first) => Self {
                error: first.error.clone(),
                errors,
            },
            None => match fallback {
                Some(message) => Self::opaque(message),
                None => Self {
                    error: String::new(),
                    errors,
                },
            },
        }
    }

    /// Builds a report that carries only a client-safe message and no chain.
    ///
    /// Use it for a failure whose detail must not leave the server: the message
    /// is all the client sees, while the full error still reaches logs, the
    /// journal and Sentry. `errors` holds one link mirroring the message, so a
    /// client that reads either field sees the same text.
    #[must_use]
    pub fn opaque(message: impl Into<String>) -> Self {
        let error = message.into();
        Self {
            errors: vec![ErrorResponse {
                error: error.clone(),
                notes: Vec::new(),
                warnings: Vec::new(),
            }],
            error,
        }
    }
}

/// A marker a link provides when the failure, and every source below it, must
/// not reach a client.
///
/// [`ErrorReport::from_error`] stops at the first link that provides it, dropping
/// that link and the rest of the chain; a root that provides it is dropped too.
/// Logs, the journal and Sentry read the error directly and still see everything.
///
/// Provide it by value, because it is a `Copy` unit type:
///
/// ```rust
/// use caution_error::{ErrorReport, Opaque, ProviderError, Request};
///
/// #[derive(Debug)]
/// struct Refused;
///
/// impl std::fmt::Display for Refused {
///     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
///         f.write_str("a database detail the client must not see")
///     }
/// }
///
/// impl std::error::Error for Refused {}
///
/// impl ProviderError for Refused {
///     fn provide<'a>(&'a self, request: &mut Request<'a>) {
///         request.provide_value(Opaque);
///     }
/// }
///
/// let report = ErrorReport::from_error_with(&Refused, "internal error");
/// assert_eq!(report.error, "internal error");
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Opaque;

/// Whether a link asks that it and every source below it be withheld.
fn is_opaque(error: &dyn ProviderError) -> bool {
    request_value::<Opaque>(error).is_some()
}

/// Builds a report from an error and its chain. See [`ErrorReport::from_error`].
#[must_use]
pub fn report(error: &dyn ProviderError) -> ErrorReport {
    ErrorReport::from_error(error)
}

/// Returns the call site an error provides, when it provides one.
///
/// A field marked `#[provide]` (`dterror::Location` is `Copy`) is stored by
/// value, so this returns the `'static` reference itself.
#[must_use]
pub fn location(error: &dyn ProviderError) -> Option<&'static std::panic::Location<'static>> {
    request_value::<&'static std::panic::Location<'static>>(error)
}

/// Collects the [`Note`]s an error provides.
///
/// An error may provide a slice (`provide_ref::<[Note]>`, as the derive does for
/// a `Vec<Note>` field), a single value (`provide_value(Note)`), or a single
/// reference (`provide_ref::<Note>`, as the derive does for `#[provide(ref = Note)]`).
/// A slice wins, then a value, then a reference.
#[must_use]
pub fn notes(error: &dyn ProviderError) -> Vec<Note> {
    if let Some(slice) = request_ref::<[Note]>(error) {
        return slice.to_vec();
    }
    if let Some(note) = request_value::<Note>(error) {
        return vec![note];
    }
    if let Some(note) = request_ref::<Note>(error) {
        return vec![note.clone()];
    }
    Vec::new()
}

/// Collects the [`Warning`]s an error provides. See [`notes`] for the shapes.
#[must_use]
pub fn warnings(error: &dyn ProviderError) -> Vec<Warning> {
    if let Some(slice) = request_ref::<[Warning]>(error) {
        return slice.to_vec();
    }
    if let Some(warning) = request_value::<Warning>(error) {
        return vec![warning];
    }
    if let Some(warning) = request_ref::<Warning>(error) {
        return vec![warning.clone()];
    }
    Vec::new()
}

/// Bounds a pathological source chain. Real chains are a few links deep.
const MAX_CHAIN_LINKS: usize = 64;

/// Iterates an error chain: the root, then [`provider_source`] links (typed
/// sources), then [`std::error::Error::source`] links (a source that is not a
/// [`ProviderError`], such as a boxed error).
///
/// [`provider_source`]: ProviderError::provider_source
#[must_use]
pub fn chain(root: &dyn ProviderError) -> Chain<'_> {
    let error: &(dyn std::error::Error + 'static) = root;
    Chain {
        provider: Some(root),
        error: Some(error),
        remaining: MAX_CHAIN_LINKS,
    }
}

/// One link in an error [`chain`].
#[derive(Clone, Copy)]
pub struct ErrorNode<'a> {
    error: &'a (dyn std::error::Error + 'static),
    provider: Option<&'a dyn ProviderError>,
}

impl<'a> ErrorNode<'a> {
    /// The error, for `Display` and `source`.
    #[must_use]
    pub fn error(&self) -> &'a (dyn std::error::Error + 'static) {
        self.error
    }

    /// The error as a [`ProviderError`], when it is one.
    #[must_use]
    pub fn provider(&self) -> Option<&'a dyn ProviderError> {
        self.provider
    }

    /// The call site this link provides, when it provides one. See [`location`].
    #[must_use]
    pub fn location(&self) -> Option<&'static std::panic::Location<'static>> {
        self.provider.and_then(location)
    }
}

/// Iterator over an error chain, produced by [`chain`].
pub struct Chain<'a> {
    provider: Option<&'a dyn ProviderError>,
    error: Option<&'a (dyn std::error::Error + 'static)>,
    remaining: usize,
}

impl<'a> Iterator for Chain<'a> {
    type Item = ErrorNode<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let error = self.error?;
        if self.remaining == 0 {
            self.error = None;
            return None;
        }
        self.remaining -= 1;

        let provider = self.provider;
        match provider.and_then(|p| p.provider_source()) {
            Some(next) => {
                let upcast: &(dyn std::error::Error + 'static) = next;
                self.error = Some(upcast);
                self.provider = Some(next);
            }
            None => {
                self.error = std::error::Error::source(error);
                self.provider = None;
            }
        }

        Some(ErrorNode { error, provider })
    }
}

/// Builds one [`ErrorResponse`] per link of the chain, stopping before the first
/// link that provides [`Opaque`].
fn responses(root: &dyn ProviderError) -> Vec<ErrorResponse> {
    let mut responses = Vec::new();
    for node in chain(root) {
        let (notes, warnings) = match node.provider() {
            Some(provider) if is_opaque(provider) => break,
            Some(provider) => (notes(provider), warnings(provider)),
            None => (Vec::new(), Vec::new()),
        };
        responses.push(ErrorResponse {
            error: node.error().to_string(),
            notes,
            warnings,
        });
    }
    responses
}

#[cfg(test)]
mod tests {
    use super::{ErrorReport, Note, Warning};
    use crate::{ProviderError, Request};
    use std::fmt;

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
            notes: vec![Note::from("root note")],
            warnings: vec![Warning::from("root warning")],
            source: Inner {
                notes: vec![Note::from("inner note")],
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
    fn an_opaque_root_is_withheld() {
        #[derive(Debug)]
        struct Internal {
            source: Boxed,
        }

        impl fmt::Display for Internal {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a database detail the client must not see")
            }
        }

        impl std::error::Error for Internal {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.source)
            }
        }

        impl ProviderError for Internal {
            fn provide<'a>(&'a self, request: &mut Request<'a>) {
                request.provide_value(crate::Opaque);
            }
        }

        let error = Internal { source: Boxed };

        let report = ErrorReport::from_error_with(&error, "internal error");
        assert_eq!(report.error, "internal error");
        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.errors[0].error, "internal error");

        assert!(
            ErrorReport::from_error(&error).errors.is_empty(),
            "the root is dropped, leaving no link",
        );
    }

    #[test]
    fn an_opaque_source_is_withheld_with_everything_below_it() {
        #[derive(Debug)]
        struct Safe {
            notes: Vec<Note>,
            inner: Confidential,
        }

        #[derive(Debug)]
        struct Confidential {
            notes: Vec<Note>,
            source: Secret,
        }

        #[derive(Debug)]
        struct Secret;

        impl fmt::Display for Safe {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("safe failed")
            }
        }

        impl fmt::Display for Confidential {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a secret the client must not see")
            }
        }

        impl fmt::Display for Secret {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a deeper secret")
            }
        }

        impl std::error::Error for Safe {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.inner)
            }
        }

        impl std::error::Error for Confidential {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.source)
            }
        }

        impl std::error::Error for Secret {}

        impl ProviderError for Safe {
            fn provide<'a>(&'a self, request: &mut Request<'a>) {
                request.provide_ref::<[Note]>(&self.notes);
            }

            fn provider_source(&self) -> Option<&(dyn ProviderError + 'static)> {
                Some(&self.inner)
            }
        }

        impl ProviderError for Confidential {
            fn provide<'a>(&'a self, request: &mut Request<'a>) {
                request.provide_value(crate::Opaque);
                request.provide_ref::<[Note]>(&self.notes);
            }

            fn provider_source(&self) -> Option<&(dyn ProviderError + 'static)> {
                Some(&self.source)
            }
        }

        impl ProviderError for Secret {}

        let error = Safe {
            notes: vec![Note::from("root note")],
            inner: Confidential {
                notes: vec![Note::from("secret note")],
                source: Secret,
            },
        };

        let report = ErrorReport::from_error_with(&error, "internal error");
        assert_eq!(report.error, "safe failed");
        assert_eq!(report.errors.len(), 1, "the opaque link and below are gone");
        assert_eq!(report.errors[0].error, "safe failed");
        assert_eq!(report.errors[0].notes[0].0, "root note");
    }

    #[test]
    fn notes_and_warnings_are_bare_json_strings() {
        let report = ErrorReport {
            error: "boom".to_string(),
            errors: vec![super::ErrorResponse {
                error: "boom".to_string(),
                notes: vec![Note::from("do x")],
                warnings: vec![Warning::from("careful")],
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
                request.provide_value(site());
            }
        }

        let located = super::location(&Located).expect("location provided");
        assert!(located.file().ends_with("report.rs"));
    }

    #[test]
    fn note_and_warning_borrow_literals_and_own_strings() {
        use std::borrow::Cow;

        assert!(matches!(
            Note::from("static"),
            Note(Cow::Borrowed("static"))
        ));
        assert!(matches!(
            Note::from(String::from("owned")),
            Note(Cow::Owned(_))
        ));
        assert!(matches!(
            Warning::from("static"),
            Warning(Cow::Borrowed("static"))
        ));
        assert_eq!(Note::new("built").0, "built");
    }

    #[test]
    fn from_static_is_const_constructible() {
        static NOTES: &[Note] = &[Note::from_static("static note")];
        static WARNINGS: &[Warning] = &[Warning::from_static("static warning")];

        assert_eq!(NOTES[0].0, "static note");
        assert_eq!(WARNINGS[0].0, "static warning");
    }

    #[test]
    fn notes_and_warnings_read_a_slice_or_a_single_value() {
        use crate::{ProviderError, Request};

        #[derive(Debug)]
        struct WithSlice {
            notes: Vec<Note>,
            warnings: Vec<Warning>,
        }

        impl std::fmt::Display for WithSlice {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("with slice")
            }
        }

        impl std::error::Error for WithSlice {}

        impl ProviderError for WithSlice {
            fn provide<'a>(&'a self, request: &mut Request<'a>) {
                request.provide_ref::<[Note]>(&self.notes);
                request.provide_ref::<[Warning]>(&self.warnings);
            }
        }

        #[derive(Debug)]
        struct WithSingle;

        impl std::fmt::Display for WithSingle {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("with single")
            }
        }

        impl std::error::Error for WithSingle {}

        impl ProviderError for WithSingle {
            fn provide<'a>(&'a self, request: &mut Request<'a>) {
                request.provide_value(Note::from("single note"));
                request.provide_value(Warning::from("single warning"));
            }
        }

        let slice = WithSlice {
            notes: vec![Note::from("one"), Note::from("two")],
            warnings: vec![Warning::from("careful")],
        };
        assert_eq!(
            super::notes(&slice),
            vec![Note::from("one"), Note::from("two")]
        );
        assert_eq!(super::warnings(&slice), vec![Warning::from("careful")]);

        assert_eq!(super::notes(&WithSingle), vec![Note::from("single note")]);
        assert_eq!(
            super::warnings(&WithSingle),
            vec![Warning::from("single warning")]
        );

        #[derive(Debug)]
        struct WithRef {
            note: Note,
        }

        impl std::fmt::Display for WithRef {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("with ref")
            }
        }

        impl std::error::Error for WithRef {}

        impl ProviderError for WithRef {
            fn provide<'a>(&'a self, request: &mut Request<'a>) {
                request.provide_ref::<Note>(&self.note);
            }
        }

        let reference = WithRef {
            note: Note::from("ref note"),
        };
        assert_eq!(super::notes(&reference), vec![Note::from("ref note")]);
    }

    #[test]
    fn report_round_trips_through_json() {
        let report = ErrorReport {
            error: "boom".to_string(),
            errors: vec![super::ErrorResponse {
                error: "boom".to_string(),
                notes: vec![Note::from("do x")],
                warnings: vec![Warning::from("careful")],
            }],
        };

        let json = serde_json::to_string(&report).expect("serializes");
        let back: ErrorReport = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, report);
    }
}
