// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Organization access tokens (see docs/access-tokens-bible.md).
//!
//! Management handlers are owner-only and run on the RBAC-gated
//! `resource_routes` group; the gateway authenticates the tokens themselves.

pub(crate) mod handlers;

#[cfg(test)]
mod db_tests;
