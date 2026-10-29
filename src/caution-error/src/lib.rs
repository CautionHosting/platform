// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! A stable, object-safe provider API for errors.
//!
//! The standard library exposes *generic member access* for errors through
//! [`std::error::Error::provide`] and [`core::error::request_ref`] /
//! [`core::error::request_value`]. That API lets an error expose extra context
//! (a backtrace, a request id, a location) keyed by type, without adding a
//! method per concrete type. It is gated behind the unstable
//! `error_generic_member_access` feature, so it cannot be used on a stable
//! toolchain.
//!
//! This crate implements the same mechanism in stable Rust. The [`Request`]
//! type, its `provide_value` / `provide_ref` family, and the
//! [`request_ref`] / [`request_value`] free functions behave like their
//! standard-library counterparts; call sites migrate by changing the import
//! path.
//!
//! The [`ProviderError`] trait ties it together. It has the same bounds the platform
//! uses everywhere else — `std::error::Error + Send + Sync + 'static` — so every
//! method already on [`std::error::Error`] (`source`, `Display`, `Debug`) stays
//! available through the supertrait bound. On top of that it adds a single
//! [`ProviderError::provide`] hook with an empty default, so a type only implements
//! it when it has context to offer.
//!
//! [`request_ref`] and [`request_value`] ask one error. When context lives in a
//! typed source field, wire [`ProviderError::provider_source`] to widen that
//! field to `&dyn ProviderError`; [`request_ref_in_chain`] and
//! [`request_value_in_chain`] then walk the whole source chain.
//!
//! # Derive
//!
//! `#[derive(ProviderError)]` writes the `provide` impl. Only fields marked
//! `#[provide]` are exposed: plain `#[provide]` provides the field's value (the
//! field must be `Copy`), and `#[provide(ref = T)]` provides a reference to `T`.
//! The derive does not touch `std::error::Error`, so it composes with `thiserror`
//! and therefore with `dterror`:
//!
//! ```rust
//! use caution_error::{ProviderError, request_ref};
//!
//! #[derive(Debug, thiserror::Error, ProviderError)]
//! #[error("upstream returned {status}")]
//! struct UpstreamError {
//!     #[provide(ref = String)]
//!     request_id: String,
//!     status: u16,
//! }
//!
//! let err = UpstreamError { request_id: "req-7".into(), status: 503 };
//! assert_eq!(request_ref::<String>(&err).map(String::as_str), Some("req-7"));
//! assert!(request_ref::<u16>(&err).is_none(), "only #[provide] fields are exposed");
//! ```
//!
//! A field marked `#[source]` (or `#[from]`) wires
//! [`ProviderError::provider_source`] automatically. The source type does not
//! have to implement the trait: the derive probes it at compile time, so a typed
//! source is chained and anything else (for example a `Box<dyn Error + Send +
//! Sync>`) safely yields `None`:
//!
//! ```rust
//! use caution_error::{ProviderError, Request, request_ref_in_chain};
//!
//! #[derive(Debug, thiserror::Error, ProviderError)]
//! #[error("read failed")]
//! struct ReadError {
//!     #[source]
//!     cause: Inner,
//! }
//!
//! #[derive(Debug, thiserror::Error, ProviderError)]
//! #[error("no such device")]
//! struct Inner {
//!     #[provide(ref = String)]
//!     device: String,
//! }
//!
//! let err = ReadError { cause: Inner { device: "nvme0".into() } };
//! assert_eq!(request_ref_in_chain::<String>(&err).map(String::as_str), Some("nvme0"));
//! ```
//!
//! # Choosing between a Note and a Warning
//!
//! An error can carry two kinds of guidance for the client: [`Note`]s and
//! [`Warning`]s. Both are read from the provider API and rendered in a report.
//! Guidance says what the client can do about the failure; the message and the
//! chain already say what failed, so guidance never restates them. The test
//! that separates the two types is *agency*: can the client change the outcome?
//!
//! - A [`Note`] says how to change it, so the next attempt can succeed. "Link a
//!   cloud provider account in Settings at …", "Wait for the deployment to
//!   finish", "Fetch the branch head, then push the commit you intend to deploy
//!   again".
//! - A [`Warning`] says what to weigh when the client cannot change it: a cost,
//!   a risk, or a property of the result. "Existing connections may close and
//!   HTTPS can be unavailable until the certificate is issued", "The payload
//!   imports as unverified metadata only".
//!
//! What belongs to neither: a restatement of the failure (the message has it),
//! and an outcome the failure is named for (a destroy that found nothing to
//! delete says so in its message). An outcome the client must weigh, such as
//! money still being spent, is a warning; an outcome attached to an instruction
//! folds into the note.
//!
//! Craft:
//!
//! - One idea per item. An item that also states an outcome is two items.
//! - Imperative for notes, declarative for warnings, so a reader knows which
//!   kind they have before parsing it.
//! - Name the concrete thing: a command in backticks, a field, a setting, a URL.
//!   "`caution apps get -d <id>` shows its state" beats "inspect it".
//! - Keep notes to one to three items, most preferred first.
//! - Keep warnings rare: a warning on an error that fires constantly is noise.
//! - Advice carries its condition. "Retry once other candidates are cleaned up"
//!   is a note; "retry later" is not.
//! - Guidance reaches clients, so no secrets, no values from another tenant, and
//!   no `[{location}]`-style internals.
//! - When the message is a code the client keys on (an HTTP body of
//!   `{"error": "insufficient_balance"}`), the code stays the message and the
//!   human sentence becomes a note.
//!
//! Put guidance on the error that knows the reason, not on the wrapper that
//! boxes it. Every link carries its own, so a wrapper's note and its source's
//! note both arrive; a client that renders them shows each unique line once.
//!
//! # Example
//!
//! ```rust
//! use caution_error::{request_ref, request_value, Request, ProviderError};
//! use std::fmt;
//!
//! #[derive(Debug)]
//! struct RequestId(u64);
//!
//! #[derive(Debug)]
//! struct UpstreamError {
//!     request_id: RequestId,
//!     status: u16,
//! }
//!
//! impl fmt::Display for UpstreamError {
//!     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//!         write!(f, "upstream returned {}", self.status)
//!     }
//! }
//!
//! impl std::error::Error for UpstreamError {}
//!
//! impl ProviderError for UpstreamError {
//!     fn provide<'a>(&'a self, request: &mut Request<'a>) {
//!         request.provide_ref::<RequestId>(&self.request_id);
//!         request.provide_value::<u16>(self.status);
//!     }
//! }
//!
//! let err = UpstreamError { request_id: RequestId(42), status: 503 };
//! assert_eq!(request_ref::<RequestId>(&err).map(|id| id.0), Some(42));
//! assert_eq!(request_value::<u16>(&err), Some(503));
//! assert!(request_ref::<String>(&err).is_none());
//! ```

mod error;
mod report;
mod request;

#[doc(hidden)]
pub mod __private;

pub use error::ProviderError;
pub use report::{
    Chain, ErrorNode, ErrorReport, ErrorResponse, Note, Warning, chain, location, notes, report,
    warnings,
};
pub use request::{
    Request, request_ref, request_ref_in_chain, request_value, request_value_in_chain,
};

/// Derives [`ProviderError`] for a struct or enum.
///
/// Emits only the `ProviderError` implementation. Fields marked `#[provide]` are
/// exposed (by value, or as a reference with `#[provide(ref = T)]`); nothing else
/// is provided. The derive never implements `std::error::Error`, so it composes
/// with `thiserror` and `dterror`.
pub use caution_error_derive::ProviderError;
