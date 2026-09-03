// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use dterror::{BoxError, CtxError, Location, ResultExt as _};
use sqlx::FromRow;
use uuid::Uuid;

use super::{Database, order, validate_page};
use crate::model::{
    Page, RelatedResource, Relation, RelationSummary, ResourceKind, ResourceRef, ResourceSummary,
    SortColumn,
};

impl Database {
    pub async fn relation_summaries(
        &self,
        reference: ResourceRef,
    ) -> Result<Vec<RelationSummary>, RelationSummariesError> {
        use RelationSummariesErrorCtx as Ctx;

        let counts = match reference.kind {
            ResourceKind::User => {
                let (organizations, apps): (i64, i64) = sqlx::query_as(
                    "SELECT
                         (SELECT COUNT(*) FROM organization_members om WHERE om.user_id = $1),
                         (SELECT COUNT(*)
                          FROM compute_resources cr
                          JOIN organization_members om ON om.organization_id = cr.organization_id
                          WHERE om.user_id = $1)",
                )
                .bind(reference.id)
                .fetch_one(&self.pool)
                .await
                .with_context(Ctx::new(reference.kind, reference.id))?;
                [
                    (Relation::UserOrganization, organizations),
                    (Relation::UserApps, apps),
                ]
            }
            ResourceKind::Organization => {
                let (users, apps): (i64, i64) = sqlx::query_as(
                    "SELECT
                         (SELECT COUNT(*) FROM organization_members om WHERE om.organization_id = $1),
                         (SELECT COUNT(*) FROM compute_resources cr WHERE cr.organization_id = $1)",
                )
                .bind(reference.id)
                .fetch_one(&self.pool)
                .await
                .with_context(Ctx::new(reference.kind, reference.id))?;
                [
                    (Relation::OrganizationUsers, users),
                    (Relation::OrganizationApps, apps),
                ]
            }
            ResourceKind::App => {
                let (organization, users): (i64, i64) = sqlx::query_as(
                    "SELECT
                         (SELECT COUNT(*) FROM compute_resources cr WHERE cr.id = $1),
                         (SELECT COUNT(*)
                          FROM organization_members om
                          JOIN compute_resources cr ON cr.organization_id = om.organization_id
                          WHERE cr.id = $1)",
                )
                .bind(reference.id)
                .fetch_one(&self.pool)
                .await
                .with_context(Ctx::new(reference.kind, reference.id))?;
                [
                    (Relation::AppOrganization, organization),
                    (Relation::AppUsers, users),
                ]
            }
        };
        Ok(counts
            .into_iter()
            .map(|(relation, count)| RelationSummary {
                relation,
                count: count.try_into().unwrap_or(0),
            })
            .collect())
    }

    pub async fn follow(
        &self,
        source: ResourceRef,
        relation: Relation,
        offset: u32,
        limit: u32,
        sort: Option<SortColumn>,
    ) -> Result<Page<RelatedResource>, FollowError> {
        use FollowErrorCtx as Ctx;

        if relation.source_kind() != source.kind {
            return Err(FollowError::RelationSourceMismatch {
                relation,
                kind: source.kind,
                location: std::panic::Location::caller(),
            });
        }
        validate_page(limit).with_context(Ctx::new(
            source.kind,
            source.id,
            relation,
            "validating pagination",
        ))?;
        if !self.resource_exists(source).await.with_context(Ctx::new(
            source.kind,
            source.id,
            relation,
            "checking the source resource",
        ))? {
            return Err(FollowError::SourceNotFound {
                kind: source.kind,
                id: source.id,
                location: std::panic::Location::caller(),
            });
        }
        let fetch_limit = i64::from(limit) + 1;
        let offset_value = i64::from(offset);
        let order = order::relation(relation, sort);

        let rows = match relation {
            Relation::UserOrganization => {
                let sql = format!(
                    "SELECT o.id,
                            o.name::text AS label,
                            CASE WHEN o.is_active THEN 'active' ELSE 'inactive' END::text AS context,
                            om.role::text AS role,
                            NULL::uuid AS via_id,
                            NULL::text AS via_label
                     FROM organization_members om
                     JOIN organizations o ON o.id = om.organization_id
                     WHERE om.user_id = $1{order}
                     LIMIT $2 OFFSET $3"
                );
                sqlx::query_as::<_, RelatedRow>(&sql)
                    .bind(source.id)
                    .bind(fetch_limit)
                    .bind(offset_value)
                    .fetch_all(&self.pool)
                    .await
                    .with_context(Ctx::new(
                        source.kind,
                        source.id,
                        relation,
                        "querying PostgreSQL",
                    ))?
            }
            Relation::UserApps => {
                let sql = format!(
                    "SELECT cr.id,
                            COALESCE(cr.resource_name, '(unnamed app)')::text AS label,
                            cr.state::text AS context,
                            om.role::text AS role,
                            o.id AS via_id,
                            o.name::text AS via_label
                     FROM organization_members om
                     JOIN organizations o ON o.id = om.organization_id
                     JOIN compute_resources cr ON cr.organization_id = o.id
                     WHERE om.user_id = $1{order}
                     LIMIT $2 OFFSET $3"
                );
                sqlx::query_as::<_, RelatedRow>(&sql)
                    .bind(source.id)
                    .bind(fetch_limit)
                    .bind(offset_value)
                    .fetch_all(&self.pool)
                    .await
                    .with_context(Ctx::new(
                        source.kind,
                        source.id,
                        relation,
                        "querying PostgreSQL",
                    ))?
            }
            Relation::OrganizationUsers => {
                let sql = format!(
                    "SELECT u.id,
                            u.username::text AS label,
                            (CASE WHEN u.is_active THEN 'active' ELSE 'inactive' END ||
                             ' · ' || COALESCE(u.email, 'no email'))::text AS context,
                            om.role::text AS role,
                            NULL::uuid AS via_id,
                            NULL::text AS via_label
                     FROM organization_members om
                     JOIN users u ON u.id = om.user_id
                     WHERE om.organization_id = $1{order}
                     LIMIT $2 OFFSET $3"
                );
                sqlx::query_as::<_, RelatedRow>(&sql)
                    .bind(source.id)
                    .bind(fetch_limit)
                    .bind(offset_value)
                    .fetch_all(&self.pool)
                    .await
                    .with_context(Ctx::new(
                        source.kind,
                        source.id,
                        relation,
                        "querying PostgreSQL",
                    ))?
            }
            Relation::OrganizationApps => {
                let sql = format!(
                    "SELECT cr.id,
                            COALESCE(cr.resource_name, '(unnamed app)')::text AS label,
                            cr.state::text AS context,
                            NULL::text AS role,
                            NULL::uuid AS via_id,
                            NULL::text AS via_label
                     FROM compute_resources cr
                     WHERE cr.organization_id = $1{order}
                     LIMIT $2 OFFSET $3"
                );
                sqlx::query_as::<_, RelatedRow>(&sql)
                    .bind(source.id)
                    .bind(fetch_limit)
                    .bind(offset_value)
                    .fetch_all(&self.pool)
                    .await
                    .with_context(Ctx::new(
                        source.kind,
                        source.id,
                        relation,
                        "querying PostgreSQL",
                    ))?
            }
            Relation::AppOrganization => {
                let sql = format!(
                    "SELECT o.id,
                            o.name::text AS label,
                            CASE WHEN o.is_active THEN 'active' ELSE 'inactive' END::text AS context,
                            NULL::text AS role,
                            NULL::uuid AS via_id,
                            NULL::text AS via_label
                     FROM compute_resources cr
                     JOIN organizations o ON o.id = cr.organization_id
                     WHERE cr.id = $1{order}
                     LIMIT $2 OFFSET $3"
                );
                sqlx::query_as::<_, RelatedRow>(&sql)
                    .bind(source.id)
                    .bind(fetch_limit)
                    .bind(offset_value)
                    .fetch_all(&self.pool)
                    .await
                    .with_context(Ctx::new(
                        source.kind,
                        source.id,
                        relation,
                        "querying PostgreSQL",
                    ))?
            }
            Relation::AppUsers => {
                let sql = format!(
                    "SELECT u.id,
                            u.username::text AS label,
                            (CASE WHEN u.is_active THEN 'active' ELSE 'inactive' END ||
                             ' · ' || COALESCE(u.email, 'no email'))::text AS context,
                            om.role::text AS role,
                            o.id AS via_id,
                            o.name::text AS via_label
                     FROM compute_resources cr
                     JOIN organizations o ON o.id = cr.organization_id
                     JOIN organization_members om ON om.organization_id = o.id
                     JOIN users u ON u.id = om.user_id
                     WHERE cr.id = $1{order}
                     LIMIT $2 OFFSET $3"
                );
                sqlx::query_as::<_, RelatedRow>(&sql)
                    .bind(source.id)
                    .bind(fetch_limit)
                    .bind(offset_value)
                    .fetch_all(&self.pool)
                    .await
                    .with_context(Ctx::new(
                        source.kind,
                        source.id,
                        relation,
                        "querying PostgreSQL",
                    ))?
            }
        };

        let target_kind = relation.target_kind();
        let via_kind = matches!(relation, Relation::UserApps | Relation::AppUsers)
            .then_some(ResourceKind::Organization);
        let items = rows
            .into_iter()
            .map(|row| row.into_related(target_kind, via_kind))
            .collect();
        Ok(Page::from_extra(items, offset, limit))
    }

    async fn resource_exists(&self, reference: ResourceRef) -> Result<bool, ResourceExistsError> {
        use ResourceExistsErrorCtx as Ctx;

        let query = match reference.kind {
            ResourceKind::User => {
                sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)")
            }
            ResourceKind::Organization => sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM organizations WHERE id = $1)",
            ),
            ResourceKind::App => sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM compute_resources WHERE id = $1)",
            ),
        };
        query
            .bind(reference.id)
            .fetch_one(&self.pool)
            .await
            .with_context(Ctx::new(reference.kind, reference.id))
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("failed to load relationships for {kind} {id} [{location:?}]")]
pub struct RelationSummariesError {
    kind: ResourceKind,
    id: Uuid,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

#[derive(Debug, thiserror::Error, CtxError)]
pub enum FollowError {
    #[context(constructor = "new")]
    #[error("failed to follow {relation:?} from {kind} {id} while {operation} [{location:?}]")]
    Operation {
        kind: ResourceKind,
        id: Uuid,
        relation: Relation,
        operation: &'static str,
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("relation {relation:?} cannot be followed from {kind} [{location:?}]")]
    RelationSourceMismatch {
        relation: Relation,
        kind: ResourceKind,
        #[location]
        location: Location,
    },
    #[error("{kind} {id} was not found [{location:?}]")]
    SourceNotFound {
        kind: ResourceKind,
        id: Uuid,
        #[location]
        location: Location,
    },
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("failed to check whether {kind} {id} exists [{location:?}]")]
struct ResourceExistsError {
    kind: ResourceKind,
    id: Uuid,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

#[derive(FromRow)]
struct RelatedRow {
    id: Uuid,
    label: String,
    context: Option<String>,
    role: Option<String>,
    via_id: Option<Uuid>,
    via_label: Option<String>,
}

impl RelatedRow {
    fn into_related(self, kind: ResourceKind, via_kind: Option<ResourceKind>) -> RelatedResource {
        let via = match (via_kind, self.via_id, self.via_label) {
            (Some(kind), Some(id), Some(label)) => Some(ResourceSummary {
                kind,
                id,
                label,
                context: None,
            }),
            _ => None,
        };
        RelatedResource {
            resource: ResourceSummary {
                kind,
                id: self.id,
                label: self.label,
                context: self.context,
            },
            role: self.role,
            via,
        }
    }
}
