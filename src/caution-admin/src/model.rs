// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::{fmt, str::FromStr};

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ResourceKind {
    User,
    Organization,
    App,
}

impl ResourceKind {
    pub const ALL: [Self; 3] = [Self::User, Self::Organization, Self::App];

    pub const fn singular(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Organization => "organization",
            Self::App => "app",
        }
    }

    pub const fn plural(self) -> &'static str {
        match self {
            Self::User => "Users",
            Self::Organization => "Organizations",
            Self::App => "Apps",
        }
    }
}

impl fmt::Display for ResourceKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.singular())
    }
}

impl FromStr for ResourceKind {
    type Err = ParseResourceKindError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "user" | "users" => Ok(Self::User),
            "organization" | "organizations" | "org" | "orgs" => Ok(Self::Organization),
            "app" | "apps" | "application" | "applications" => Ok(Self::App),
            _ => Err(ParseResourceKindError(value.to_string())),
        }
    }
}

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
#[error("unknown resource kind `{0}`; expected user, organization, or app")]
pub struct ParseResourceKindError(String);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Relation {
    UserOrganization,
    UserApps,
    OrganizationUsers,
    OrganizationApps,
    AppOrganization,
    AppUsers,
}

impl Relation {
    pub const fn source_kind(self) -> ResourceKind {
        match self {
            Self::UserOrganization | Self::UserApps => ResourceKind::User,
            Self::OrganizationUsers | Self::OrganizationApps => ResourceKind::Organization,
            Self::AppOrganization | Self::AppUsers => ResourceKind::App,
        }
    }

    pub const fn target_kind(self) -> ResourceKind {
        match self {
            Self::UserOrganization | Self::AppOrganization => ResourceKind::Organization,
            Self::UserApps | Self::OrganizationApps => ResourceKind::App,
            Self::OrganizationUsers | Self::AppUsers => ResourceKind::User,
        }
    }

    pub const fn key(self) -> &'static str {
        match self {
            Self::UserOrganization | Self::AppOrganization => "organization",
            Self::UserApps | Self::OrganizationApps => "apps",
            Self::OrganizationUsers | Self::AppUsers => "users",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::UserOrganization => "Organizations",
            Self::UserApps => "Apps via organizations",
            Self::OrganizationUsers => "Members",
            Self::OrganizationApps => "Apps",
            Self::AppOrganization => "Organization",
            Self::AppUsers => "Users via organization",
        }
    }

    pub const fn for_kind(kind: ResourceKind) -> [Self; 2] {
        match kind {
            ResourceKind::User => [Self::UserOrganization, Self::UserApps],
            ResourceKind::Organization => [Self::OrganizationUsers, Self::OrganizationApps],
            ResourceKind::App => [Self::AppOrganization, Self::AppUsers],
        }
    }

    pub fn parse(kind: ResourceKind, value: &str) -> Result<Self, ParseRelationError> {
        let normalized = value.to_ascii_lowercase();
        Self::for_kind(kind)
            .into_iter()
            .find(|relation| {
                relation.key() == normalized
                    || (relation.key() == "organization"
                        && matches!(normalized.as_str(), "org" | "organizations" | "orgs"))
                    || (relation.key() == "apps"
                        && matches!(normalized.as_str(), "app" | "application" | "applications"))
                    || (relation.key() == "users" && normalized == "user")
            })
            .ok_or_else(|| ParseRelationError {
                kind,
                value: value.to_string(),
            })
    }
}

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
#[error("unknown relation `{value}` for {kind}; expected {expected}", expected = expected_relations(*kind))]
pub struct ParseRelationError {
    kind: ResourceKind,
    value: String,
}

fn expected_relations(kind: ResourceKind) -> String {
    Relation::for_kind(kind).map(Relation::key).join(" or ")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ResourceRef {
    pub kind: ResourceKind,
    pub id: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResourceSummary {
    pub kind: ResourceKind,
    pub id: Uuid,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

impl ResourceSummary {
    pub const fn reference(&self) -> ResourceRef {
        ResourceRef {
            kind: self.kind,
            id: self.id,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Field {
    pub label: &'static str,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Resource {
    pub kind: ResourceKind,
    pub id: Uuid,
    pub label: String,
    pub fields: Vec<Field>,
}

impl Resource {
    pub const fn reference(&self) -> ResourceRef {
        ResourceRef {
            kind: self.kind,
            id: self.id,
        }
    }

    pub fn summary(&self) -> ResourceSummary {
        ResourceSummary {
            kind: self.kind,
            id: self.id,
            label: self.label.clone(),
            context: self
                .fields
                .iter()
                .find(|field| matches!(field.label, "Email" | "State" | "Status"))
                .map(|field| field.value.clone()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RelatedResource {
    #[serde(flatten)]
    pub resource: ResourceSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<ResourceSummary>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RelationSummary {
    pub relation: Relation,
    pub count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub offset: u32,
    pub limit: u32,
    pub has_more: bool,
}

impl<T> Page<T> {
    pub fn from_extra(mut items: Vec<T>, offset: u32, limit: u32) -> Self {
        let has_more = items.len() > limit as usize;
        if has_more {
            items.truncate(limit as usize);
        }
        Self {
            items,
            offset,
            limit,
            has_more,
        }
    }
}

pub fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::{Relation, ResourceKind};

    #[test]
    fn resource_kind_accepts_product_and_plural_names() {
        assert_eq!("users".parse(), Ok(ResourceKind::User));
        assert_eq!("org".parse(), Ok(ResourceKind::Organization));
        assert_eq!("applications".parse(), Ok(ResourceKind::App));
    }

    #[test]
    fn relations_are_scoped_to_the_source_kind() {
        assert_eq!(
            Relation::parse(ResourceKind::User, "apps"),
            Ok(Relation::UserApps)
        );
        assert_eq!(
            Relation::parse(ResourceKind::App, "users"),
            Ok(Relation::AppUsers)
        );
        assert!(Relation::parse(ResourceKind::User, "users").is_err());
    }

    #[test]
    fn every_kind_exposes_two_relationships() {
        for kind in ResourceKind::ALL {
            let relations = Relation::for_kind(kind);
            assert!(
                relations
                    .iter()
                    .all(|relation| relation.source_kind() == kind)
            );
        }
    }
}
