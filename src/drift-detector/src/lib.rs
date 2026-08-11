// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! # Drift Detector
//!
//! This crate detects drift between the expected state stored in the database
//! and the actual state of AWS resources.
//!
//! ## Overview
//!
//! The drift detector works by:
//! 1. Reading expected resource state from the database (`db` module)
//! 2. Querying actual AWS resource state (`aws` module)
//! 3. Comparing the two states and reporting differences
//!
//! ## Module Structure
//!
//! - `db`: Database access layer for reading expected state
//! - `aws`: AWS API client for querying actual state
//! - `drift`: Core drift detection logic comparing db vs aws state
//!
//! ## Error Handling
//!
//! Each fallible module exposes a `thiserror`-based error enum:
//!
//! - [`db::DbError`]: database query failures, carrying the organization and/or
//!   resource identifiers involved
//! - [`aws::AwsError`]: AWS API call failures, carrying the queried region

#![warn(missing_docs)]
#![warn(missing_debug_implementations)]

pub mod aws;
pub mod db;
pub mod drift;

pub use aws::AwsError;
pub use db::DbError;
