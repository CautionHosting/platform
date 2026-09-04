// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use dterror::{BoxError, CtxError, Location, ResultExt as _};
use sqlx::FromRow;
use uuid::Uuid;

use super::{Database, validate_page};
use crate::model::{Build, Page};

impl Database {
    pub(crate) async fn list_builds(
        &self,
        app_id: Uuid,
        offset: u32,
        limit: u32,
    ) -> Result<Page<Build>, ListBuildsError> {
        use ListBuildsErrorCtx as Ctx;

        validate_page(limit).with_context(Ctx::new(app_id, "validating pagination"))?;
        let rows = sqlx::query_as::<_, BuildRow>(
            "SELECT id, status, commit_sha, builder_instance_id, builder_instance_type,
                    started_at, completed_at, created_at
             FROM eif_builds
             WHERE app_id = $1
             ORDER BY created_at DESC, id DESC
             LIMIT $2 OFFSET $3",
        )
        .bind(app_id)
        .bind(i64::from(limit) + 1)
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .with_context(Ctx::new(app_id, "querying PostgreSQL"))?;

        Ok(Page::from_extra(
            rows.into_iter().map(BuildRow::into_build).collect(),
            offset,
            limit,
        ))
    }

    pub(crate) async fn show_build(
        &self,
        app_id: Uuid,
        build_id: Uuid,
    ) -> Result<Build, ShowBuildError> {
        use ShowBuildErrorCtx as Ctx;

        let row = sqlx::query_as::<_, BuildRow>(
            "SELECT id, status, commit_sha, builder_instance_id, builder_instance_type,
                    started_at, completed_at, created_at
             FROM eif_builds
             WHERE app_id = $1 AND id = $2",
        )
        .bind(app_id)
        .bind(build_id)
        .fetch_optional(&self.pool)
        .await
        .with_context(Ctx::new(app_id, build_id, "querying PostgreSQL"))?;
        let Some(row) = row else {
            return Err(ShowBuildError {
                app_id,
                build_id,
                operation: "the build was not found",
                location: std::panic::Location::caller(),
                source: None,
            });
        };
        Ok(row.into_build())
    }
}

#[derive(FromRow)]
struct BuildRow {
    id: Uuid,
    status: String,
    commit_sha: String,
    builder_instance_id: Option<String>,
    builder_instance_type: Option<String>,
    started_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl BuildRow {
    fn into_build(self) -> Build {
        Build {
            id: self.id,
            status: self.status,
            commit_sha: self.commit_sha,
            builder_instance_id: self.builder_instance_id,
            builder_instance_type: self.builder_instance_type,
            started_at: self.started_at,
            completed_at: self.completed_at,
            created_at: self.created_at,
        }
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("failed to list builds for app {app_id} while {operation} [{location:?}]")]
pub(crate) struct ListBuildsError {
    app_id: Uuid,
    operation: &'static str,
    #[location]
    location: Location,
    #[source]
    source: BoxError,
}

#[derive(Debug, thiserror::Error, CtxError)]
#[error("failed to show build {build_id} for app {app_id} while {operation} [{location:?}]")]
pub(crate) struct ShowBuildError {
    app_id: Uuid,
    build_id: Uuid,
    operation: &'static str,
    #[location]
    location: Location,
    #[source]
    #[context(option)]
    source: Option<BoxError>,
}
