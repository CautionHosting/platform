// SPDX-FileCopyrightText: 2025 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Inventory of the RBAC-protected (organization-scoped) routes.
//!
//! The role editor builds its route table from this. The list is maintained
//! alongside the `resource_routes` group in `main.rs`; see the "route/rule
//! drift" item in `docs/rbac-spec.md` for the plan to keep them in step.

use axum::Json;
use serde::Serialize;

/// Method + route template pairs registered in `resource_routes`, plus this
/// `GET /routes` endpoint itself.
pub(crate) const RESOURCE_ROUTES: &[(&str, &str)] = &[
    ("GET", "/users/me"),
    ("PATCH", "/users/me"),
    ("DELETE", "/users/me"),
    ("GET", "/organizations/{id}"),
    ("PATCH", "/organizations/{id}"),
    ("DELETE", "/organizations/{id}"),
    ("GET", "/organizations/{id}/settings"),
    ("PATCH", "/organizations/{id}/settings"),
    ("GET", "/organizations/{id}/members"),
    ("POST", "/organizations/{id}/members"),
    ("GET", "/organizations/{id}/invitations"),
    ("POST", "/organizations/{id}/invitations"),
    ("DELETE", "/organizations/{id}/invitations/{invitation_id}"),
    ("PATCH", "/organizations/{id}/members/{user_id}"),
    ("DELETE", "/organizations/{id}/members/{user_id}"),
    ("POST", "/organizations/{id}/fully-managed/waitlist"),
    ("GET", "/organizations/{id}/roles"),
    ("POST", "/organizations/{id}/roles"),
    ("GET", "/organizations/{id}/roles/{role_id}"),
    ("PUT", "/organizations/{id}/roles/{role_id}"),
    ("DELETE", "/organizations/{id}/roles/{role_id}"),
    ("GET", "/organizations/{id}/roles/{role_id}/rules"),
    ("POST", "/organizations/{id}/roles/{role_id}/rules"),
    ("GET", "/organizations/{id}/roles/{role_id}/rules/{rule_id}"),
    (
        "PATCH",
        "/organizations/{id}/roles/{role_id}/rules/{rule_id}",
    ),
    (
        "DELETE",
        "/organizations/{id}/roles/{role_id}/rules/{rule_id}",
    ),
    ("GET", "/organizations/{id}/members/{user_id}/roles"),
    ("POST", "/organizations/{id}/members/{user_id}/roles"),
    (
        "DELETE",
        "/organizations/{id}/members/{user_id}/roles/{role_id}",
    ),
    ("POST", "/resources"),
    ("GET", "/resources"),
    ("GET", "/resources/{id}"),
    ("PATCH", "/resources/{id}"),
    ("DELETE", "/resources/{id}"),
    ("GET", "/resources/{id}/deployments"),
    ("GET", "/resources/{id}/deployments/{deployment_id}"),
    ("DELETE", "/resources/{id}/deployments/{deployment_id}"),
    ("GET", "/resources/{id}/history"),
    ("GET", "/deployments/{id}"),
    ("POST", "/resources/{id}/deployments/{deployment_id}/switch"),
    ("POST", "/resources/{id}/attestation"),
    ("GET", "/resources/{id}/builder-config"),
    ("PUT", "/resources/{id}/builder-config"),
    ("GET", "/resources/{id}/eif/download"),
    ("POST", "/resources/managed-onprem"),
    ("POST", "/deploy"),
    ("GET", "/credentials"),
    ("POST", "/credentials"),
    ("GET", "/credentials/{id}"),
    ("DELETE", "/credentials/{id}"),
    ("POST", "/credentials/{id}/default"),
    ("GET", "/quorum-bundles"),
    ("POST", "/quorum-bundles"),
    ("POST", "/quorum-bundles/from-org-users"),
    ("GET", "/quorum-bundles/participants"),
    ("GET", "/quorum-bundles/{id}"),
    ("PATCH", "/quorum-bundles/{id}"),
    ("DELETE", "/quorum-bundles/{id}"),
    ("GET", "/secrets-bundles"),
    ("POST", "/secrets-bundles"),
    ("GET", "/secrets-bundles/{id}"),
    ("PATCH", "/secrets-bundles/{id}"),
    ("DELETE", "/secrets-bundles/{id}"),
    ("GET", "/billing/usage"),
    ("GET", "/billing/invoices"),
    ("GET", "/billing/payment-methods"),
    ("DELETE", "/billing/payment-methods/{id}"),
    ("POST", "/billing/payment-methods/{id}/set-primary"),
    ("GET", "/billing/paddle/client-token"),
    ("POST", "/billing/paddle/transaction-completed"),
    ("GET", "/billing/credits/balance"),
    ("GET", "/billing/credits/packages"),
    ("POST", "/billing/credits/purchase"),
    ("GET", "/billing/credits/ledger"),
    ("POST", "/billing/credits/redeem"),
    ("GET", "/billing/subscription/tiers"),
    ("GET", "/billing/subscription"),
    ("POST", "/billing/subscription/checkout"),
    ("POST", "/billing/subscription/subscribe"),
    ("POST", "/billing/subscription/change-tier"),
    ("POST", "/billing/subscription/cancel"),
    ("GET", "/routes"),
];

#[derive(Debug, Serialize)]
pub(crate) struct RouteEntry {
    pub(crate) method: &'static str,
    pub(crate) path: &'static str,
}

/// Returns the route inventory the role editor builds its table from. Static
/// data, so this needs no database access; the route is still behind
/// auth/onboarding/RBAC like the rest of the group.
#[tracing::instrument(skip_all)]
pub(crate) async fn list_routes() -> Json<Vec<RouteEntry>> {
    Json(
        RESOURCE_ROUTES
            .iter()
            .map(|(method, path)| RouteEntry { method, path })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_entries_are_well_formed() {
        assert!(!RESOURCE_ROUTES.is_empty());
        for (method, path) in RESOURCE_ROUTES {
            assert!(
                ["GET", "POST", "PUT", "PATCH", "DELETE"].contains(method),
                "unexpected method {method}"
            );
            assert!(path.starts_with('/'), "unexpected path {path}");
        }
        assert!(
            RESOURCE_ROUTES
                .iter()
                .any(|(method, path)| *method == "GET" && *path == "/routes")
        );
    }
}
