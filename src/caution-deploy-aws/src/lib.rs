// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! AWS deploy platform for Nitro Enclaves.
//!
//! Owns the Nitro/AWS OpenTofu deployment code, the EC2/ASG clients, and the
//! network-policy renderer that the deploy path uses.

// The `CtxError` derive generates a `{Error}Ctx` mirror type per error enum;
// the generated struct initializations trip `redundant_field_names`, and the
// lint cannot be placed on the generated items themselves.
#![allow(
    clippy::redundant_field_names,
    reason = "generated {Error}Ctx mirrors trip redundant_field_names"
)]

pub mod deployment;
pub mod ec2;
pub mod network_policy;
