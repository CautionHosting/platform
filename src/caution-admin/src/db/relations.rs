// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use std::error::Error;

use dterror::{FromContext, ResultExt as _};
use sqlx::FromRow;
use uuid::Uuid;

use super::{Database, ResourceNotFoundError, validate_page};
use crate::model::{
    Page, RelatedResource, Relation, RelationSummary, ResourceKind, ResourceRef, ResourceSummary,
};

impl Database {
    pub async fn relation_summaries(
        &self,
        reference: ResourceRef,
    ) -> Result<Vec<RelationSummary>, RelationSummariesError> {
        use RelationSummariesErrorCtx as Ctx;

        let counts: (i64, i64) = match reference.kind {
            ResourceKind::User => {
                sqlx::query_as(
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
                .with_context(Ctx::new(reference.kind, reference.id))?
            }
            ResourceKind::Organization => {
                sqlx::query_as(
                    "SELECT
                         (SELECT COUNT(*) FROM organization_members om WHERE om.organization_id = $1),
                         (SELECT COUNT(*) FROM compute_resources cr WHERE cr.organization_id = $1)",
                )
                .bind(reference.id)
                .fetch_one(&self.pool)
                .await
                .with_context(Ctx::new(reference.kind, reference.id))?
            }
            ResourceKind::App => {
                sqlx::query_as(
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
                .with_context(Ctx::new(reference.kind, reference.id))?
            }
        };
        let relations = Relation::for_kind(reference.kind);
        Ok(vec![
            RelationSummary {
                relation: relations[0],
                count: counts.0.try_into().unwrap_or(0),
            },
            RelationSummary {
                relation: relations[1],
                count: counts.1.try_into().unwrap_or(0),
            },
        ])
    }

    pub async fn follow(
        &self,
        source: ResourceRef,
        relation: Relation,
        offset: u32,
        limit: u32,
    ) -> Result<Page<RelatedResource>, FollowError> {
        use FollowErrorCtx as Ctx;

        if relation.source_kind() != source.kind {
            return Err(RelationSourceMismatchError {
                relation,
                kind: source.kind,
            })
            .with_context(Ctx::new(
                source.kind,
                source.id,
                relation,
                "validating the relationship",
            ));
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
            return Err(ResourceNotFoundError {
                kind: source.kind,
                id: source.id,
            })
            .with_context(Ctx::new(
                source.kind,
                source.id,
                relation,
                "checking the source resource",
            ));
        }
        let fetch_limit = i64::from(limit) + 1;
        let offset_value = i64::from(offset);

        let rows = match relation {
            Relation::UserOrganization => {
                sqlx::query_as::<_, RelatedRow>(
                    "SELECT o.id,
                            o.name::text AS label,
                            CASE WHEN o.is_active THEN 'active' ELSE 'inactive' END::text AS context,
                            om.role::text AS role,
                            NULL::uuid AS via_id,
                            NULL::text AS via_label
                     FROM organization_members om
                     JOIN organizations o ON o.id = om.organization_id
                     WHERE om.user_id = $1
                     ORDER BY om.created_at, om.id
                     LIMIT $2 OFFSET $3",
                )
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
                sqlx::query_as::<_, RelatedRow>(
                    "SELECT cr.id,
                            COALESCE(cr.resource_name, '(unnamed app)')::text AS label,
                            cr.state::text AS context,
                            om.role::text AS role,
                            o.id AS via_id,
                            o.name::text AS via_label
                     FROM organization_members om
                     JOIN organizations o ON o.id = om.organization_id
                     JOIN compute_resources cr ON cr.organization_id = o.id
                     WHERE om.user_id = $1
                     ORDER BY cr.created_at DESC, cr.id
                     LIMIT $2 OFFSET $3",
                )
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
                sqlx::query_as::<_, RelatedRow>(
                    "SELECT u.id,
                            u.username::text AS label,
                            (CASE WHEN u.is_active THEN 'active' ELSE 'inactive' END ||
                             ' · ' || COALESCE(u.email, 'no email'))::text AS context,
                            om.role::text AS role,
                            NULL::uuid AS via_id,
                            NULL::text AS via_label
                     FROM organization_members om
                     JOIN users u ON u.id = om.user_id
                     WHERE om.organization_id = $1
                     ORDER BY om.role, u.username, u.id
                     LIMIT $2 OFFSET $3",
                )
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
                sqlx::query_as::<_, RelatedRow>(
                    "SELECT cr.id,
                            COALESCE(cr.resource_name, '(unnamed app)')::text AS label,
                            cr.state::text AS context,
                            NULL::text AS role,
                            NULL::uuid AS via_id,
                            NULL::text AS via_label
                     FROM compute_resources cr
                     WHERE cr.organization_id = $1
                     ORDER BY cr.created_at DESC, cr.id
                     LIMIT $2 OFFSET $3",
                )
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
                sqlx::query_as::<_, RelatedRow>(
                    "SELECT o.id,
                            o.name::text AS label,
                            CASE WHEN o.is_active THEN 'active' ELSE 'inactive' END::text AS context,
                            NULL::text AS role,
                            NULL::uuid AS via_id,
                            NULL::text AS via_label
                     FROM compute_resources cr
                     JOIN organizations o ON o.id = cr.organization_id
                     WHERE cr.id = $1
                     LIMIT $2 OFFSET $3",
                )
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
                sqlx::query_as::<_, RelatedRow>(
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
                     WHERE cr.id = $1
                     ORDER BY om.role, u.username, u.id
                     LIMIT $2 OFFSET $3",
                )
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

#[derive(Debug, thiserror::Error, FromContext)]
#[error("failed to load relationships for {kind} {id}")]
pub struct RelationSummariesError {
    kind: ResourceKind,
    id: Uuid,
    #[source]
    source: Box<dyn Error + Send + Sync + 'static>,
}

#[derive(Debug, thiserror::Error, FromContext)]
#[error("failed to follow {relation:?} from {kind} {id} while {operation}")]
pub struct FollowError {
    kind: ResourceKind,
    id: Uuid,
    relation: Relation,
    operation: &'static str,
    #[source]
    source: Box<dyn Error + Send + Sync + 'static>,
}

#[derive(Debug, thiserror::Error, FromContext)]
#[error("failed to check whether {kind} {id} exists")]
struct ResourceExistsError {
    kind: ResourceKind,
    id: Uuid,
    #[source]
    source: Box<dyn Error + Send + Sync + 'static>,
}

#[derive(Debug, thiserror::Error)]
#[error("relation {relation:?} cannot be followed from {kind}")]
struct RelationSourceMismatchError {
    relation: Relation,
    kind: ResourceKind,
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
