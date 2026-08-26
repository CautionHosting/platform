// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool, postgres::PgPoolOptions};
use uuid::Uuid;

use crate::model::{
    Field, Page, RelatedResource, Relation, RelationSummary, Resource, ResourceKind, ResourceRef,
    ResourceSummary, timestamp,
};

const MAX_PAGE_SIZE: u32 = 200;
const SEARCH_LIMIT: i64 = 50;

#[derive(Clone)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    pub async fn connect_read_only(database_url: &str) -> Result<Self, DatabaseError> {
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .after_connect(|connection, _metadata| {
                Box::pin(async move {
                    sqlx::query("SET application_name = 'caution-admin'")
                        .execute(&mut *connection)
                        .await?;
                    sqlx::query("SET default_transaction_read_only = on")
                        .execute(&mut *connection)
                        .await?;
                    sqlx::query("SET statement_timeout = '10s'")
                        .execute(&mut *connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(database_url)
            .await
            .map_err(DatabaseError::Connect)?;

        let read_only: String = sqlx::query_scalar("SHOW default_transaction_read_only")
            .fetch_one(&pool)
            .await?;
        if read_only != "on" {
            return Err(DatabaseError::ReadWriteSession);
        }

        Ok(Self { pool })
    }

    pub async fn search(&self, query: &str) -> Result<Vec<ResourceSummary>, DatabaseError> {
        let (pattern, exact) = search_parameters(query)?;

        let rows = sqlx::query_as::<_, SummaryRow>(
            "SELECT kind, id, label, context
             FROM (
                 SELECT 'user'::text AS kind,
                        u.id,
                        u.username::text AS label,
                        (CASE WHEN u.is_active THEN 'active' ELSE 'inactive' END ||
                         ' · ' || COALESCE(u.email, 'no email'))::text AS context,
                        u.created_at
                 FROM users u
                 WHERE u.username ILIKE $1 OR u.email ILIKE $1 OR u.id::text = $2
                 UNION ALL
                 SELECT 'organization'::text AS kind,
                        o.id,
                        o.name::text AS label,
                        (CASE WHEN o.is_active THEN 'active' ELSE 'inactive' END ||
                         ' · ' ||
                         (SELECT COUNT(*) FROM compute_resources cr WHERE cr.organization_id = o.id)::text ||
                         ' apps')::text AS context,
                        o.created_at
                 FROM organizations o
                 WHERE o.name ILIKE $1 OR o.id::text = $2
                 UNION ALL
                 SELECT 'app'::text AS kind,
                        cr.id,
                        COALESCE(cr.resource_name, '(unnamed app)')::text AS label,
                        (cr.state::text || ' · ' || o.name)::text AS context,
                        cr.created_at
                 FROM compute_resources cr
                 JOIN organizations o ON o.id = cr.organization_id
                 WHERE cr.resource_name ILIKE $1 OR cr.id::text = $2
             ) resources
             ORDER BY created_at DESC, id
             LIMIT $3",
        )
        .bind(pattern)
        .bind(exact)
        .bind(SEARCH_LIMIT)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    pub async fn list(
        &self,
        kind: ResourceKind,
        offset: u32,
        limit: u32,
    ) -> Result<Page<ResourceSummary>, DatabaseError> {
        validate_page(limit)?;
        let fetch_limit = i64::from(limit) + 1;
        let offset = i64::from(offset);

        let rows = match kind {
            ResourceKind::User => {
                sqlx::query_as::<_, SummaryRow>(
                    "SELECT 'user'::text AS kind,
                            id,
                            username::text AS label,
                            (CASE WHEN is_active THEN 'active' ELSE 'inactive' END ||
                             ' · ' || COALESCE(email, 'no email'))::text AS context
                     FROM users
                     ORDER BY created_at DESC, id
                     LIMIT $1 OFFSET $2",
                )
                .bind(fetch_limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await?
            }
            ResourceKind::Organization => {
                sqlx::query_as::<_, SummaryRow>(
                    "SELECT 'organization'::text AS kind,
                            o.id,
                            o.name::text AS label,
                            (CASE WHEN o.is_active THEN 'active' ELSE 'inactive' END ||
                             ' · ' ||
                             (SELECT COUNT(*) FROM compute_resources cr WHERE cr.organization_id = o.id)::text ||
                             ' apps')::text AS context
                     FROM organizations o
                     ORDER BY o.created_at DESC, o.id
                     LIMIT $1 OFFSET $2",
                )
                .bind(fetch_limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await?
            }
            ResourceKind::App => {
                sqlx::query_as::<_, SummaryRow>(
                    "SELECT 'app'::text AS kind,
                            cr.id,
                            COALESCE(cr.resource_name, '(unnamed app)')::text AS label,
                            (cr.state::text || ' · ' || o.name)::text AS context
                     FROM compute_resources cr
                     JOIN organizations o ON o.id = cr.organization_id
                     ORDER BY cr.created_at DESC, cr.id
                     LIMIT $1 OFFSET $2",
                )
                .bind(fetch_limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await?
            }
        };

        let items = rows
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Page::from_extra(items, offset as u32, limit))
    }

    pub async fn show(&self, reference: ResourceRef) -> Result<Resource, DatabaseError> {
        match reference.kind {
            ResourceKind::User => self.show_user(reference.id).await,
            ResourceKind::Organization => self.show_organization(reference.id).await,
            ResourceKind::App => self.show_app(reference.id).await,
        }
    }

    pub async fn relation_summaries(
        &self,
        reference: ResourceRef,
    ) -> Result<Vec<RelationSummary>, DatabaseError> {
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
                .await?
            }
            ResourceKind::Organization => {
                sqlx::query_as(
                    "SELECT
                         (SELECT COUNT(*) FROM organization_members om WHERE om.organization_id = $1),
                         (SELECT COUNT(*) FROM compute_resources cr WHERE cr.organization_id = $1)",
                )
                .bind(reference.id)
                .fetch_one(&self.pool)
                .await?
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
                .await?
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
    ) -> Result<Page<RelatedResource>, DatabaseError> {
        if relation.source_kind() != source.kind {
            return Err(DatabaseError::RelationSourceMismatch {
                relation,
                kind: source.kind,
            });
        }
        validate_page(limit)?;
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
                .await?
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
                .await?
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
                .await?
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
                .await?
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
                .await?
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
                .await?
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

    async fn show_user(&self, id: Uuid) -> Result<Resource, DatabaseError> {
        let row = sqlx::query_as::<_, UserRow>(
            "SELECT id, username, email, is_active, created_at, updated_at
             FROM users
             WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DatabaseError::NotFound {
            kind: ResourceKind::User,
            id,
        })?;

        Ok(row.into_resource())
    }

    async fn show_organization(&self, id: Uuid) -> Result<Resource, DatabaseError> {
        let row = sqlx::query_as::<_, OrganizationRow>(
            "SELECT o.id,
                    o.name,
                    o.is_active,
                    o.credit_suspended_at,
                    o.dunning_stage,
                    (COALESCE(clb.credit_cents, 0) - COALESCE(dlb.debit_cents, 0))::bigint
                        AS credit_balance_cents,
                    s.tier AS subscription_tier,
                    s.status AS subscription_status,
                    s.billing_source,
                    s.max_apps AS subscription_max_apps,
                    s.pending_tier,
                    s.pending_max_apps,
                    (SELECT COUNT(*)
                     FROM compute_resources cr
                     JOIN cloud_credentials cc ON cc.resource_id = cr.id
                     WHERE cr.organization_id = o.id
                       AND cc.managed_on_prem = true
                       AND cr.destroyed_at IS NULL
                       AND cr.state NOT IN ('terminated', 'failed')) AS allocated_byoc_apps,
                    o.created_at,
                    o.updated_at
             FROM organizations o
             LEFT JOIN credit_ledger_balances clb ON clb.organization_id = o.id
             LEFT JOIN debit_ledger_balances dlb ON dlb.organization_id = o.id
             LEFT JOIN subscriptions s
                    ON s.organization_id = o.id AND s.status <> 'canceled'
             WHERE o.id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DatabaseError::NotFound {
            kind: ResourceKind::Organization,
            id,
        })?;

        Ok(row.into_resource())
    }

    async fn show_app(&self, id: Uuid) -> Result<Resource, DatabaseError> {
        let row = sqlx::query_as::<_, AppRow>(
            "SELECT cr.id,
                    cr.resource_name,
                    cr.state::text AS state,
                    o.name::text AS organization_name,
                    EXISTS (
                        SELECT 1
                        FROM cloud_credentials cc
                        WHERE cc.resource_id = cr.id AND cc.managed_on_prem = true
                    ) AS managed_on_prem,
                    p.provider_type::text AS provider,
                    pa.account_name::text AS provider_account,
                    rt.display_name::text AS resource_type,
                    cr.provider_resource_id,
                    cr.region,
                    cr.public_ip,
                    cr.configuration->>'domain' AS domain,
                    cr.dns_status,
                    cr.dns_error,
                    cr.destroyed_at,
                    cr.created_at,
                    cr.updated_at
             FROM compute_resources cr
             JOIN organizations o ON o.id = cr.organization_id
             JOIN provider_accounts pa ON pa.id = cr.provider_account_id
             JOIN providers p ON p.id = pa.provider_id
             JOIN resource_types rt ON rt.id = cr.resource_type_id
             WHERE cr.id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DatabaseError::NotFound {
            kind: ResourceKind::App,
            id,
        })?;

        Ok(row.into_resource())
    }
}

fn search_parameters(query: &str) -> Result<(String, String), DatabaseError> {
    let exact = query.trim().to_string();
    if exact.len() < 2 && Uuid::parse_str(&exact).is_err() {
        return Err(DatabaseError::SearchTooShort);
    }
    Ok((["%", &exact, "%"].concat(), exact))
}

fn validate_page(limit: u32) -> Result<(), DatabaseError> {
    if (1..=MAX_PAGE_SIZE).contains(&limit) {
        Ok(())
    } else {
        Err(DatabaseError::InvalidLimit {
            limit,
            max: MAX_PAGE_SIZE,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("failed to connect to PostgreSQL")]
    Connect(#[source] sqlx::Error),
    #[error("PostgreSQL connection is not read-only")]
    ReadWriteSession,
    #[error("search requires at least two characters or an exact UUID")]
    SearchTooShort,
    #[error("{kind} {id} was not found")]
    NotFound { kind: ResourceKind, id: Uuid },
    #[error("relation {relation:?} cannot be followed from {kind}")]
    RelationSourceMismatch {
        relation: Relation,
        kind: ResourceKind,
    },
    #[error("limit must be between 1 and {max}, got {limit}")]
    InvalidLimit { limit: u32, max: u32 },
    #[error("database query failed")]
    Query(#[from] sqlx::Error),
    #[error("database returned an unknown resource kind `{0}`")]
    UnknownResourceKind(String),
}

#[derive(FromRow)]
struct SummaryRow {
    kind: String,
    id: Uuid,
    label: String,
    context: Option<String>,
}

impl TryFrom<SummaryRow> for ResourceSummary {
    type Error = DatabaseError;

    fn try_from(row: SummaryRow) -> Result<Self, Self::Error> {
        let kind = row
            .kind
            .parse()
            .map_err(|_| DatabaseError::UnknownResourceKind(row.kind))?;
        Ok(Self {
            kind,
            id: row.id,
            label: row.label,
            context: row.context,
        })
    }
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

#[derive(FromRow)]
struct UserRow {
    id: Uuid,
    username: String,
    email: Option<String>,
    is_active: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl UserRow {
    fn into_resource(self) -> Resource {
        Resource {
            kind: ResourceKind::User,
            id: self.id,
            label: self.username.clone(),
            fields: vec![
                Field {
                    label: "Username",
                    value: self.username,
                },
                Field {
                    label: "Email",
                    value: optional(self.email),
                },
                Field {
                    label: "Status",
                    value: status(self.is_active),
                },
                Field {
                    label: "Created",
                    value: timestamp(self.created_at),
                },
                Field {
                    label: "Updated",
                    value: timestamp(self.updated_at),
                },
            ],
        }
    }
}

#[derive(FromRow)]
struct OrganizationRow {
    id: Uuid,
    name: String,
    is_active: bool,
    credit_suspended_at: Option<DateTime<Utc>>,
    dunning_stage: String,
    credit_balance_cents: i64,
    subscription_tier: Option<String>,
    subscription_status: Option<String>,
    billing_source: Option<String>,
    subscription_max_apps: Option<i32>,
    pending_tier: Option<String>,
    pending_max_apps: Option<i32>,
    allocated_byoc_apps: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl OrganizationRow {
    fn into_resource(self) -> Resource {
        let mut fields = vec![
            Field {
                label: "Name",
                value: self.name.clone(),
            },
            Field {
                label: "Status",
                value: status(self.is_active),
            },
            Field {
                label: "Credit balance",
                value: money(self.credit_balance_cents),
            },
            Field {
                label: "Credit state",
                value: credit_state(self.credit_suspended_at, &self.dunning_stage),
            },
            Field {
                label: "BYOC plan",
                value: self
                    .subscription_tier
                    .as_deref()
                    .map(tier_name)
                    .unwrap_or_else(|| "—".to_string()),
            },
            Field {
                label: "Subscription status",
                value: optional(self.subscription_status),
            },
            Field {
                label: "Billing source",
                value: self
                    .billing_source
                    .as_deref()
                    .map(billing_source)
                    .unwrap_or_else(|| "—".to_string()),
            },
            Field {
                label: "BYOC capacity",
                value: byoc_capacity(
                    self.allocated_byoc_apps,
                    self.subscription_max_apps,
                    self.pending_max_apps,
                ),
            },
        ];
        if self.pending_tier.is_some() || self.pending_max_apps.is_some() {
            fields.push(Field {
                label: "Pending change",
                value: pending_change(self.pending_tier.as_deref(), self.pending_max_apps),
            });
        }
        fields.extend([
            Field {
                label: "Created",
                value: timestamp(self.created_at),
            },
            Field {
                label: "Updated",
                value: timestamp(self.updated_at),
            },
        ]);

        Resource {
            kind: ResourceKind::Organization,
            id: self.id,
            label: self.name,
            fields,
        }
    }
}

#[derive(FromRow)]
struct AppRow {
    id: Uuid,
    resource_name: Option<String>,
    state: String,
    organization_name: String,
    managed_on_prem: bool,
    provider: String,
    provider_account: String,
    resource_type: String,
    provider_resource_id: String,
    region: Option<String>,
    public_ip: Option<String>,
    domain: Option<String>,
    dns_status: String,
    dns_error: Option<String>,
    destroyed_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl AppRow {
    fn into_resource(self) -> Resource {
        let label = self
            .resource_name
            .clone()
            .unwrap_or_else(|| "(unnamed app)".to_string());
        let mut provider = self.provider.to_ascii_uppercase();
        provider.push_str(" · ");
        provider.push_str(&self.provider_account);
        provider.push_str(" · ");
        provider.push_str(&self.resource_type);
        let mut dns = self.dns_status;
        if let Some(error) = self.dns_error {
            dns.push_str(" · ");
            dns.push_str(&error);
        }
        Resource {
            kind: ResourceKind::App,
            id: self.id,
            label,
            fields: vec![
                Field {
                    label: "Name",
                    value: optional(self.resource_name),
                },
                Field {
                    label: "State",
                    value: self.state,
                },
                Field {
                    label: "Organization",
                    value: self.organization_name,
                },
                Field {
                    label: "Mode",
                    value: deployment_mode(self.managed_on_prem).to_string(),
                },
                Field {
                    label: "Provider",
                    value: provider,
                },
                Field {
                    label: "Provider resource",
                    value: self.provider_resource_id,
                },
                Field {
                    label: "Region",
                    value: optional(self.region),
                },
                Field {
                    label: "Public IP",
                    value: optional(self.public_ip),
                },
                Field {
                    label: "Domain",
                    value: optional(self.domain),
                },
                Field {
                    label: "DNS",
                    value: dns,
                },
                Field {
                    label: "Destroyed",
                    value: self
                        .destroyed_at
                        .map(timestamp)
                        .unwrap_or_else(|| "—".to_string()),
                },
                Field {
                    label: "Created",
                    value: timestamp(self.created_at),
                },
                Field {
                    label: "Updated",
                    value: timestamp(self.updated_at),
                },
            ],
        }
    }
}

fn optional(value: Option<String>) -> String {
    value.unwrap_or_else(|| "—".to_string())
}

fn status(active: bool) -> String {
    if active { "active" } else { "inactive" }.to_string()
}

fn money(cents: i64) -> String {
    let magnitude = cents.unsigned_abs();
    let mut value = String::new();
    if cents < 0 {
        value.push('-');
    }
    value.push('$');
    value.push_str(&(magnitude / 100).to_string());
    value.push('.');
    let remainder = magnitude % 100;
    if remainder < 10 {
        value.push('0');
    }
    value.push_str(&remainder.to_string());
    value
}

fn credit_state(suspended_at: Option<DateTime<Utc>>, dunning_stage: &str) -> String {
    let mut value = suspended_at.map_or_else(
        || "clear".to_string(),
        |suspended_at| ["suspended since ", &timestamp(suspended_at)].concat(),
    );
    if dunning_stage != "none" {
        value.push_str(" · dunning ");
        value.push_str(&dunning_stage.replace('_', " "));
    }
    value
}

fn tier_name(tier: &str) -> String {
    tier.split('_')
        .map(|word| {
            let mut characters = word.chars();
            characters.next().map_or_else(String::new, |first| {
                first.to_uppercase().to_string() + characters.as_str()
            })
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn billing_source(source: &str) -> String {
    match source {
        "legacy_credits" => "Credits".to_string(),
        "paddle" => "Paddle".to_string(),
        "enterprise" => "Enterprise".to_string(),
        other => other.replace('_', " "),
    }
}

fn byoc_capacity(allocated: i64, maximum: Option<i32>, pending: Option<i32>) -> String {
    let Some(maximum) = maximum else {
        return "—".to_string();
    };
    let effective = pending.map_or(maximum, |pending| pending.min(maximum));
    let mut value = allocated.to_string();
    value.push_str(" / ");
    value.push_str(&effective.to_string());
    value.push_str(" used");
    value
}

fn pending_change(tier: Option<&str>, limit: Option<i32>) -> String {
    let mut value = tier
        .map(tier_name)
        .unwrap_or_else(|| "plan unchanged".to_string());
    if let Some(limit) = limit {
        value.push_str(" · ");
        value.push_str(&limit.to_string());
        value.push_str(" apps");
    }
    value
}

const fn deployment_mode(managed_on_prem: bool) -> &'static str {
    if managed_on_prem {
        "BYOC"
    } else {
        "Fully managed"
    }
}

#[cfg(test)]
mod tests {
    use super::{byoc_capacity, deployment_mode, money, search_parameters, tier_name};
    use crate::model::Page;

    #[test]
    fn search_parameters_trim_and_bound_queries() {
        assert_eq!(
            search_parameters("  alice@example.com ").expect("valid search"),
            (
                "%alice@example.com%".to_string(),
                "alice@example.com".to_string()
            )
        );
        assert!(search_parameters("a").is_err());
    }

    #[test]
    fn page_discards_the_extra_probe_row() {
        let page = Page::from_extra(vec![1, 2, 3], 10, 2);
        assert_eq!(page.items, vec![1, 2]);
        assert!(page.has_more);
        assert_eq!(page.offset, 10);
    }

    #[test]
    fn billing_and_mode_summaries_use_operator_terms() {
        assert_eq!(money(8_000), "$80.00");
        assert_eq!(money(-125), "-$1.25");
        assert_eq!(tier_name("3_enclaves"), "3 Enclaves");
        assert_eq!(byoc_capacity(1, Some(3), Some(2)), "1 / 2 used");
        assert_eq!(byoc_capacity(0, None, None), "—");
        assert_eq!(deployment_mode(true), "BYOC");
        assert_eq!(deployment_mode(false), "Fully managed");
    }
}
