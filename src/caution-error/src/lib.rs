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
mod request;

pub use error::ProviderError;
pub use request::{
    Request, request_ref, request_ref_in_chain, request_value, request_value_in_chain,
};
