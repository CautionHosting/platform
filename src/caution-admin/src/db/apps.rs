// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use dterror::{BoxError, CtxError, Location, ResultExt as _};
use sqlx::FromRow;

use super::{Database, SummaryRow, order, validate_page};
use crate::model::{AppCounts, AppFilter, AppPage, Page, ResourceKind, SortColumn};

impl Database {
    pub(crate) async fn browse_apps(
        &self,
        filter: AppFilter,
        offset: u32,
        limit: u32,
        sort: SortColumn,
    ) -> Result<AppPage, BrowseAppsError> {
        use BrowseAppsErrorCtx as Ctx;

        validate_page(limit).with_context(Ctx::new(filter, "validating pagination"))?;

        let counts = sqlx::query_as::<_, AppCountRow>(
            "SELECT COUNT(*) FILTER (
                        WHERE destroyed_at IS NULL
                          AND state::text NOT IN ('failed', 'terminated')
                    )::bigint AS current,
                    COUNT(*) FILTER (
                        WHERE destroyed_at IS NULL AND state::text = 'failed'
                    )::bigint AS failed,
                    COUNT(*) FILTER (
                        WHERE destroyed_at IS NOT NULL OR state::text = 'terminated'
                    )::bigint AS historical,
                    COUNT(*)::bigint AS total
             FROM compute_resources",
        )
        .fetch_one(&self.pool)
        .await
        .with_context(Ctx::new(filter, "counting apps"))?;
        let counts = AppCounts {
            current: counts
                .current
                .try_into()
                .with_context(Ctx::new(filter, "decoding the current-app count"))?,
            failed: counts
                .failed
                .try_into()
                .with_context(Ctx::new(filter, "decoding the failed-app count"))?,
            historical: counts
                .historical
                .try_into()
                .with_context(Ctx::new(filter, "decoding the historical-app count"))?,
            total: counts
                .total
                .try_into()
                .with_context(Ctx::new(filter, "decoding the total app count"))?,
        };

        let sql = format!(
            "SELECT 'app'::text AS kind,
                    cr.id,
                    COALESCE(cr.resource_name, '(unnamed app)')::text AS label,
                    (cr.state::text || ' · ' || o.name)::text AS context
             FROM compute_resources cr
             JOIN organizations o ON o.id = cr.organization_id
             WHERE {}
             ORDER BY {}
             LIMIT $1 OFFSET $2",
            filter_predicate(filter),
            order::list(ResourceKind::App, Some(sort)),
        );
        let rows = sqlx::query_as::<_, SummaryRow>(&sql)
            .bind(i64::from(limit) + 1)
            .bind(i64::from(offset))
            .fetch_all(&self.pool)
            .await
            .with_context(Ctx::new(filter, "querying PostgreSQL"))?;
        let items = rows
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .with_context(Ctx::new(filter, "decoding app rows"))?;

        Ok(AppPage {
            page: Page::from_extra(items, offset, limit),
            counts,
        })
    }
}

const fn filter_predicate(filter: AppFilter) -> &'static str {
    match filter {
        AppFilter::Current => {
            "cr.destroyed_at IS NULL AND cr.state::text NOT IN ('failed', 'terminated')"
        }
        AppFilter::Failed => "cr.destroyed_at IS NULL AND cr.state::text = 'failed'",
        AppFilter::Historical => "(cr.destroyed_at IS NOT NULL OR cr.state::text = 'terminated')",
        AppFilter::All => "TRUE",
    }
}

#[derive(FromRow)]
struct AppCountRow {
    current: i64,
    failed: i64,
    historical: i64,
    total: i64,
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("failed to browse {filter} apps while {operation} [{location:?}]")]
pub(crate) struct BrowseAppsError {
    filter: AppFilter,
    operation: &'static str,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

#[cfg(test)]
mod tests {
    use super::filter_predicate;
    use crate::model::AppFilter;

    #[test]
    fn app_filters_are_mutually_exclusive() {
        assert!(filter_predicate(AppFilter::Current).contains("NOT IN ('failed', 'terminated')"));
        assert!(filter_predicate(AppFilter::Failed).contains("state::text = 'failed'"));
        assert!(filter_predicate(AppFilter::Historical).contains("destroyed_at IS NOT NULL"));
        assert_eq!(filter_predicate(AppFilter::All), "TRUE");
    }
}
