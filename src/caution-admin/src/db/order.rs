// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use crate::model::{Relation, ResourceKind, SortColumn};

// These are compile-time allowlisted SQL fragments. No operator input is ever
// interpolated into an ORDER BY clause.
pub(super) const fn search(sort: Option<SortColumn>) -> &'static str {
    match sort {
        None => "created_at DESC, id",
        Some(SortColumn::Type) => "kind, created_at DESC, id",
        Some(SortColumn::Name) => "lower(label), label, kind, id",
        Some(SortColumn::Details) => {
            "status_rank, lower(context), context, created_at DESC, kind, id"
        }
    }
}

pub(super) const fn list(kind: ResourceKind, sort: Option<SortColumn>) -> &'static str {
    match (kind, sort) {
        (ResourceKind::User, None | Some(SortColumn::Type)) => "created_at DESC, id",
        (ResourceKind::User, Some(SortColumn::Name)) => "lower(username::text), username::text, id",
        (ResourceKind::User, Some(SortColumn::Details)) => {
            "CASE WHEN is_active THEN 0 ELSE 1 END, lower(COALESCE(email, 'no email')), username::text, id"
        }
        (ResourceKind::Organization, None | Some(SortColumn::Type)) => "o.created_at DESC, o.id",
        (ResourceKind::Organization, Some(SortColumn::Name)) => {
            "lower(o.name::text), o.name::text, o.id"
        }
        (ResourceKind::Organization, Some(SortColumn::Details)) => {
            "CASE WHEN o.is_active THEN 0 ELSE 1 END, context, o.name::text, o.id"
        }
        (ResourceKind::App, None | Some(SortColumn::Type)) => "cr.created_at DESC, cr.id",
        (ResourceKind::App, Some(SortColumn::Name)) => {
            "lower(COALESCE(cr.resource_name, '(unnamed app)')), COALESCE(cr.resource_name, '(unnamed app)'), cr.id"
        }
        (ResourceKind::App, Some(SortColumn::Details)) => {
            "CASE cr.state::text WHEN 'running' THEN 0 WHEN 'pending' THEN 1 WHEN 'initialized' THEN 2 WHEN 'stopped' THEN 3 WHEN 'terminating' THEN 4 WHEN 'failed' THEN 5 WHEN 'terminated' THEN 6 ELSE 7 END, lower(o.name::text), o.name::text, cr.created_at DESC, cr.id"
        }
    }
}

pub(super) const fn relation(relation: Relation, sort: Option<SortColumn>) -> &'static str {
    match (relation, sort) {
        (Relation::UserOrganization, None | Some(SortColumn::Type)) => {
            " ORDER BY om.created_at, om.id"
        }
        (Relation::UserOrganization, Some(SortColumn::Name)) => {
            " ORDER BY lower(o.name::text), o.name::text, o.id"
        }
        (Relation::UserOrganization, Some(SortColumn::Details)) => {
            " ORDER BY CASE WHEN o.is_active THEN 0 ELSE 1 END, om.role::text, lower(o.name::text), o.id"
        }
        (Relation::UserApps, None | Some(SortColumn::Type)) => {
            " ORDER BY cr.created_at DESC, cr.id"
        }
        (Relation::UserApps, Some(SortColumn::Name)) => {
            " ORDER BY lower(COALESCE(cr.resource_name, '(unnamed app)')), COALESCE(cr.resource_name, '(unnamed app)'), cr.id"
        }
        (Relation::UserApps, Some(SortColumn::Details)) => {
            " ORDER BY CASE cr.state::text WHEN 'running' THEN 0 WHEN 'pending' THEN 1 WHEN 'initialized' THEN 2 WHEN 'stopped' THEN 3 WHEN 'terminating' THEN 4 WHEN 'failed' THEN 5 WHEN 'terminated' THEN 6 ELSE 7 END, om.role::text, lower(o.name::text), cr.created_at DESC, cr.id"
        }
        (Relation::OrganizationUsers, None | Some(SortColumn::Type)) => {
            " ORDER BY om.role, u.username, u.id"
        }
        (Relation::OrganizationUsers, Some(SortColumn::Name)) => {
            " ORDER BY lower(u.username::text), u.username::text, u.id"
        }
        (Relation::OrganizationUsers, Some(SortColumn::Details)) => {
            " ORDER BY CASE WHEN u.is_active THEN 0 ELSE 1 END, om.role::text, lower(COALESCE(u.email, 'no email')), u.username::text, u.id"
        }
        (Relation::OrganizationApps, None | Some(SortColumn::Type)) => {
            " ORDER BY cr.created_at DESC, cr.id"
        }
        (Relation::OrganizationApps, Some(SortColumn::Name)) => {
            " ORDER BY lower(COALESCE(cr.resource_name, '(unnamed app)')), COALESCE(cr.resource_name, '(unnamed app)'), cr.id"
        }
        (Relation::OrganizationApps, Some(SortColumn::Details)) => {
            " ORDER BY CASE cr.state::text WHEN 'running' THEN 0 WHEN 'pending' THEN 1 WHEN 'initialized' THEN 2 WHEN 'stopped' THEN 3 WHEN 'terminating' THEN 4 WHEN 'failed' THEN 5 WHEN 'terminated' THEN 6 ELSE 7 END, cr.created_at DESC, cr.id"
        }
        (Relation::AppOrganization, None) => "",
        (Relation::AppOrganization, Some(SortColumn::Type)) => " ORDER BY o.id",
        (Relation::AppOrganization, Some(SortColumn::Name)) => {
            " ORDER BY lower(o.name::text), o.name::text, o.id"
        }
        (Relation::AppOrganization, Some(SortColumn::Details)) => {
            " ORDER BY CASE WHEN o.is_active THEN 0 ELSE 1 END, lower(o.name::text), o.id"
        }
        (Relation::AppUsers, None | Some(SortColumn::Type)) => {
            " ORDER BY om.role, u.username, u.id"
        }
        (Relation::AppUsers, Some(SortColumn::Name)) => {
            " ORDER BY lower(u.username::text), u.username::text, u.id"
        }
        (Relation::AppUsers, Some(SortColumn::Details)) => {
            " ORDER BY CASE WHEN u.is_active THEN 0 ELSE 1 END, om.role::text, lower(COALESCE(u.email, 'no email')), u.username::text, u.id"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{list, relation, search};
    use crate::model::{Relation, ResourceKind, SortColumn};

    #[test]
    fn default_orders_remain_unchanged() {
        assert_eq!(search(None), "created_at DESC, id");
        assert_eq!(list(ResourceKind::App, None), "cr.created_at DESC, cr.id");
        assert_eq!(relation(Relation::AppOrganization, None), "");
    }

    #[test]
    fn app_details_order_is_semantic_and_stable() {
        let order = list(ResourceKind::App, Some(SortColumn::Details));
        for state in [
            "running",
            "pending",
            "initialized",
            "stopped",
            "terminating",
            "failed",
            "terminated",
        ] {
            assert!(order.contains(state));
        }
        assert!(order.ends_with("cr.created_at DESC, cr.id"));
        assert!(
            relation(Relation::OrganizationApps, Some(SortColumn::Details))
                .contains("WHEN 'running' THEN 0")
        );
    }
}
