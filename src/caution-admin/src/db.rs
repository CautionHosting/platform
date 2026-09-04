// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use dterror::{BoxError, CtxError, Location, ResultExt as _};
use sqlx::{PgPool, postgres::PgPoolOptions};
use uuid::Uuid;

use crate::model::{Page, Resource, ResourceKind, ResourceRef, ResourceSummary, SortColumn};

mod apps;
pub(crate) mod aws;
mod builds;
mod order;
mod relations;
mod rows;

pub use relations::{
    FollowError, FollowErrorCtx, RelationSummariesError, RelationSummariesErrorCtx,
};
use rows::{AppRow, OrganizationRow, SummaryRow, UserRow};
pub(crate) use rows::{billing_source, byoc_capacity, byoc_state, pending_change, tier_name};

const MAX_PAGE_SIZE: u32 = 200;

#[derive(Clone)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    /// The resource search query.
    ///
    /// A raw string literal on purpose: `ESCAPE '\'` written in a normal Rust
    /// literal is an escaped quote, so PostgreSQL would receive `ESCAPE ''`
    /// and every wildcard escape would silently stop working.
    const SEARCH_SQL: &'static str = r"SELECT kind, id, label, context
             FROM (
                 SELECT 'user'::text AS kind,
                        u.id,
                        u.username::text AS label,
                        (CASE WHEN u.is_active THEN 'active' ELSE 'inactive' END ||
                         ' · ' || COALESCE(u.email, 'no email'))::text AS context,
                        CASE WHEN u.is_active THEN 0 ELSE 1 END AS status_rank,
                        u.created_at
                 FROM users u
                 WHERE u.username ILIKE $1 ESCAPE '\'
                    OR u.email ILIKE $1 ESCAPE '\'
                    OR u.id::text = $2
                 UNION ALL
                 SELECT 'organization'::text AS kind,
                        o.id,
                        o.name::text AS label,
                        (CASE WHEN o.is_active THEN 'active' ELSE 'inactive' END ||
                         ' · ' ||
                         (SELECT COUNT(*) FROM compute_resources cr WHERE cr.organization_id = o.id)::text ||
                         ' apps')::text AS context,
                        CASE WHEN o.is_active THEN 0 ELSE 1 END AS status_rank,
                        o.created_at
                 FROM organizations o
                 WHERE o.name ILIKE $1 ESCAPE '\' OR o.id::text = $2
                 UNION ALL
                 SELECT 'app'::text AS kind,
                        cr.id,
                        COALESCE(cr.resource_name, '(unnamed app)')::text AS label,
                        (cr.state::text || ' · ' || o.name)::text AS context,
                        CASE cr.state::text
                            WHEN 'running' THEN 0
                            WHEN 'pending' THEN 1
                            WHEN 'initialized' THEN 2
                            WHEN 'stopped' THEN 3
                            WHEN 'terminating' THEN 4
                            WHEN 'failed' THEN 5
                            WHEN 'terminated' THEN 6
                            ELSE 7
                        END AS status_rank,
                        cr.created_at
                 FROM compute_resources cr
                 JOIN organizations o ON o.id = cr.organization_id
                 WHERE cr.resource_name ILIKE $1 ESCAPE '\' OR cr.id::text = $2
             ) resources";

    pub async fn connect_read_only(database_url: &str) -> Result<Self, ConnectReadOnlyError> {
        use ConnectReadOnlyErrorCtx as Ctx;

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
            .with_context(Ctx::new("connecting and configuring the pool"))?;

        let read_only: String = sqlx::query_scalar("SHOW default_transaction_read_only")
            .fetch_one(&pool)
            .await
            .with_context(Ctx::new("verifying read-only mode"))?;
        if read_only != "on" {
            return Err(ConnectReadOnlyError {
                operation: "verifying read-only mode: PostgreSQL connection is not read-only",
                location: std::panic::Location::caller(),
                source: None,
            });
        }

        Ok(Self { pool })
    }

    /// Search across users, organizations, and apps.
    ///
    /// Returns one globally sorted page of matching resources.
    pub async fn search(
        &self,
        query: &str,
        offset: u32,
        limit: u32,
        sort: Option<SortColumn>,
    ) -> Result<Page<ResourceSummary>, SearchError> {
        use SearchErrorCtx as Ctx;

        validate_page(limit).with_context(Ctx::new("validating pagination"))?;
        let (pattern, exact) =
            search_parameters(query).with_context(Ctx::new("validating the search query"))?;
        let sql = format!(
            "{} ORDER BY {} LIMIT $3 OFFSET $4",
            Self::SEARCH_SQL,
            order::search(sort)
        );

        let rows = sqlx::query_as::<_, SummaryRow>(&sql)
            .bind(pattern)
            .bind(exact)
            .bind(i64::from(limit) + 1)
            .bind(i64::from(offset))
            .fetch_all(&self.pool)
            .await
            .with_context(Ctx::new("querying PostgreSQL"))?;

        let items = rows
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .with_context(Ctx::new("decoding search results"))?;
        Ok(Page::from_extra(items, offset, limit))
    }

    pub async fn list(
        &self,
        kind: ResourceKind,
        offset: u32,
        limit: u32,
        sort: Option<SortColumn>,
    ) -> Result<Page<ResourceSummary>, ListError> {
        use ListErrorCtx as Ctx;

        validate_page(limit).with_context(Ctx::new(kind, "validating pagination"))?;
        let fetch_limit = i64::from(limit) + 1;
        let offset = i64::from(offset);
        let ordering = order::list(kind, sort);

        let rows = match kind {
            ResourceKind::User => {
                let sql = format!(
                    "SELECT 'user'::text AS kind,
                            id,
                            username::text AS label,
                            (CASE WHEN is_active THEN 'active' ELSE 'inactive' END ||
                             ' · ' || COALESCE(email, 'no email'))::text AS context
                     FROM users
                     ORDER BY {ordering}
                     LIMIT $1 OFFSET $2"
                );
                sqlx::query_as::<_, SummaryRow>(&sql)
                    .bind(fetch_limit)
                    .bind(offset)
                    .fetch_all(&self.pool)
                    .await
                    .with_context(Ctx::new(kind, "querying PostgreSQL"))?
            }
            ResourceKind::Organization => {
                let sql = format!(
                    "SELECT 'organization'::text AS kind,
                            o.id,
                            o.name::text AS label,
                            (CASE WHEN o.is_active THEN 'active' ELSE 'inactive' END ||
                             ' · ' ||
                             (SELECT COUNT(*) FROM compute_resources cr WHERE cr.organization_id = o.id)::text ||
                             ' apps')::text AS context
                     FROM organizations o
                     ORDER BY {ordering}
                     LIMIT $1 OFFSET $2"
                );
                sqlx::query_as::<_, SummaryRow>(&sql)
                    .bind(fetch_limit)
                    .bind(offset)
                    .fetch_all(&self.pool)
                    .await
                    .with_context(Ctx::new(kind, "querying PostgreSQL"))?
            }
            ResourceKind::App => {
                let sql = format!(
                    "SELECT 'app'::text AS kind,
                            cr.id,
                            COALESCE(cr.resource_name, '(unnamed app)')::text AS label,
                            (cr.state::text || ' · ' || o.name)::text AS context
                     FROM compute_resources cr
                     JOIN organizations o ON o.id = cr.organization_id
                     ORDER BY {ordering}
                     LIMIT $1 OFFSET $2"
                );
                sqlx::query_as::<_, SummaryRow>(&sql)
                    .bind(fetch_limit)
                    .bind(offset)
                    .fetch_all(&self.pool)
                    .await
                    .with_context(Ctx::new(kind, "querying PostgreSQL"))?
            }
        };

        let items = rows
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .with_context(Ctx::new(kind, "decoding database rows"))?;
        Ok(Page::from_extra(items, offset as u32, limit))
    }

    pub async fn show(&self, reference: ResourceRef) -> Result<Resource, ShowError> {
        use ShowErrorCtx as Ctx;

        match reference.kind {
            ResourceKind::User => self
                .show_user(reference.id)
                .await
                .with_context(Ctx::new(reference.kind, reference.id)),
            ResourceKind::Organization => self
                .show_organization(reference.id)
                .await
                .with_context(Ctx::new(reference.kind, reference.id)),
            ResourceKind::App => self
                .show_app(reference.id)
                .await
                .with_context(Ctx::new(reference.kind, reference.id)),
        }
    }

    async fn show_user(&self, id: Uuid) -> Result<Resource, ShowUserError> {
        use ShowUserErrorCtx as Ctx;

        let row = sqlx::query_as::<_, UserRow>(
            "SELECT id, username, email, is_active, created_at, updated_at
             FROM users
             WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .with_context(Ctx::new(id, "querying PostgreSQL"))?;
        let Some(row) = row else {
            return Err(ShowUserError {
                id,
                operation: "the user was not found",
                location: std::panic::Location::caller(),
                source: None,
            });
        };

        Ok(row.into_resource())
    }

    async fn show_organization(&self, id: Uuid) -> Result<Resource, ShowOrganizationError> {
        use ShowOrganizationErrorCtx as Ctx;

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
                    s.catalog_valid,
                    s.enterprise_expires_at,
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
        .await
        .with_context(Ctx::new(id, "querying PostgreSQL"))?;
        let Some(row) = row else {
            return Err(ShowOrganizationError {
                id,
                operation: "the organization was not found",
                location: std::panic::Location::caller(),
                source: None,
            });
        };

        Ok(row.into_resource())
    }

    async fn show_app(&self, id: Uuid) -> Result<Resource, ShowAppError> {
        use ShowAppErrorCtx as Ctx;

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
        .await
        .with_context(Ctx::new(id, "querying PostgreSQL"))?;
        let Some(row) = row else {
            return Err(ShowAppError {
                id,
                operation: "the app was not found",
                location: std::panic::Location::caller(),
                source: None,
            });
        };

        Ok(row.into_resource())
    }
}

fn search_parameters(query: &str) -> Result<(String, String), SearchParametersError> {
    let exact = query.trim().to_string();
    let parsed_uuid = Uuid::parse_str(&exact);
    if exact.chars().count() < 2 && parsed_uuid.is_err() {
        return Err(SearchParametersError {
            location: std::panic::Location::caller(),
        });
    }
    let canonical = parsed_uuid.map_or_else(|_| exact.clone(), |id| id.to_string());
    Ok((["%", &escape_like(&exact), "%"].concat(), canonical))
}

/// Escape `LIKE`/`ILIKE` metacharacters so operator input stays a literal
/// substring match. Without this, the two-character query `%%` becomes the
/// match-everything pattern `%%%` and returns every user with their email.
fn escape_like(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(character, '\\' | '%' | '_') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

fn validate_page(limit: u32) -> Result<(), ValidatePageError> {
    if (1..=MAX_PAGE_SIZE).contains(&limit) {
        Ok(())
    } else {
        Err(ValidatePageError {
            limit,
            max: MAX_PAGE_SIZE,
            location: std::panic::Location::caller(),
        })
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("failed to establish a read-only PostgreSQL session while {operation} [{location:?}]")]
pub struct ConnectReadOnlyError {
    operation: &'static str,
    #[location]
    location: Location,
    #[source]
    #[context(option)]
    source: Option<BoxError>,
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("resource search failed while {operation} [{location:?}]")]
pub struct SearchError {
    operation: &'static str,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("failed to list {kind} resources while {operation} [{location:?}]")]
pub struct ListError {
    kind: ResourceKind,
    operation: &'static str,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("failed to show {kind} {id} [{location:?}]")]
pub struct ShowError {
    kind: ResourceKind,
    id: Uuid,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("failed to load user {id} while {operation} [{location:?}]")]
struct ShowUserError {
    id: Uuid,
    operation: &'static str,
    #[location]
    location: Location,
    #[source]
    #[context(option)]
    source: Option<BoxError>,
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("failed to load organization {id} while {operation} [{location:?}]")]
struct ShowOrganizationError {
    id: Uuid,
    operation: &'static str,
    #[location]
    location: Location,
    #[source]
    #[context(option)]
    source: Option<BoxError>,
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("failed to load app {id} while {operation} [{location:?}]")]
struct ShowAppError {
    id: Uuid,
    operation: &'static str,
    #[location]
    location: Location,
    #[source]
    #[context(option)]
    source: Option<BoxError>,
}

#[derive(Debug, thiserror::Error)]
#[error("search requires at least two characters or an exact UUID [{location:?}]")]
struct SearchParametersError {
    location: Location,
}

#[derive(Debug, thiserror::Error)]
#[error("limit must be between 1 and {max}, got {limit} [{location:?}]")]
struct ValidatePageError {
    limit: u32,
    max: u32,
    location: Location,
}

#[cfg(test)]
mod tests {
    use super::{Database, search_parameters};
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
        assert!(
            search_parameters("é").is_err(),
            "the minimum length must count characters, not bytes"
        );
        assert_eq!(
            search_parameters("40000000-0000-0000-0000-0000000000AB").expect("uppercase UUID"),
            (
                "%40000000-0000-0000-0000-0000000000AB%".to_string(),
                "40000000-0000-0000-0000-0000000000ab".to_string(),
            )
        );
        let message = search_parameters("a")
            .expect_err("short search must fail")
            .to_string();
        assert!(message.starts_with("search requires at least two characters or an exact UUID ["));
        assert!(message.contains("src/caution-admin/src/db.rs"));
    }

    #[test]
    fn search_patterns_escape_like_wildcards() {
        // `%%` used to become the match-everything pattern `%%%`, which
        // returned every user together with their email address.
        assert_eq!(
            search_parameters("%%").expect("valid search").0,
            "%\\%\\%%".to_string()
        );
        assert_eq!(
            search_parameters("a_c").expect("valid search").0,
            "%a\\_c%".to_string()
        );
        assert_eq!(
            search_parameters("back\\slash").expect("valid search").0,
            "%back\\\\slash%".to_string()
        );
    }

    #[test]
    fn search_sql_escape_clause_survives_rust_string_escaping() {
        // `"ESCAPE '\'"` in a normal Rust literal is an escaped quote, so
        // PostgreSQL receives `ESCAPE ''` and every escape stops working. The
        // query must be a raw string; assert on the SQL actually sent.
        let sql = Database::SEARCH_SQL;
        assert!(
            sql.contains("ESCAPE '\\'"),
            "the ESCAPE clause must reach SQL as a single backslash"
        );
        assert!(
            !sql.contains("ESCAPE ''"),
            "an empty ESCAPE clause silently disables wildcard escaping"
        );
        assert_eq!(
            sql.matches("ILIKE $1").count(),
            sql.matches("ILIKE $1 ESCAPE").count(),
            "every ILIKE must carry the ESCAPE clause"
        );
    }

    #[test]
    fn page_discards_the_extra_probe_row() {
        let page = Page::from_extra(vec![1, 2, 3], 10, 2);
        assert_eq!(page.items, vec![1, 2]);
        assert!(page.has_more);
        assert_eq!(page.offset, 10);
    }
}
