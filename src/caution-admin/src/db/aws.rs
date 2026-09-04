// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use chrono::{DateTime, Utc};
use dterror::{BoxError, CtxError, Location, ResultExt as _};
use sqlx::FromRow;
use uuid::Uuid;

use super::Database;

#[derive(Clone, Debug, Eq, FromRow, PartialEq)]
pub(crate) struct AwsAppRow {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub organization_name: String,
    pub name: String,
    pub state: String,
    pub aws_account_id: String,
    pub provider_resource_id: String,
    pub region: Option<String>,
    pub public_ip: Option<String>,
    pub managed_on_prem: bool,
    pub destroyed: bool,
}

#[derive(Clone, Debug, Eq, FromRow, PartialEq)]
pub(crate) struct AwsBuildRow {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub organization_name: String,
    pub app_id: Option<Uuid>,
    pub app_name: Option<String>,
    pub builder_instance_id: Option<String>,
    pub status: String,
}

#[derive(Clone, Debug, Eq, FromRow, PartialEq)]
pub(crate) struct ByocSubscriptionRow {
    pub organization_id: Uuid,
    pub organization_name: String,
    pub organization_active: bool,
    pub tier: String,
    pub status: String,
    pub billing_source: String,
    pub catalog_valid: bool,
    pub enterprise_expires_at: Option<DateTime<Utc>>,
    pub max_apps: i32,
    pub pending_tier: Option<String>,
    pub pending_max_apps: Option<i32>,
    pub allocated_apps: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AwsDatabaseState {
    pub apps: Vec<AwsAppRow>,
    pub builds: Vec<AwsBuildRow>,
    pub byoc: Vec<ByocSubscriptionRow>,
}

impl Database {
    pub(crate) async fn load_aws_state(&self) -> Result<AwsDatabaseState, LoadAwsStateError> {
        use LoadAwsStateErrorCtx as Ctx;

        let apps = sqlx::query_as::<_, AwsAppRow>(
            "SELECT cr.id,
                    cr.organization_id,
                    o.name::text AS organization_name,
                    COALESCE(cr.resource_name, '(unnamed app)')::text AS name,
                    cr.state::text AS state,
                    pa.external_account_id::text AS aws_account_id,
                    cr.provider_resource_id::text AS provider_resource_id,
                    cr.region::text AS region,
                    cr.public_ip::text AS public_ip,
                    EXISTS (
                        SELECT 1 FROM cloud_credentials cc
                        WHERE cc.resource_id = cr.id AND cc.managed_on_prem = true
                    ) AS managed_on_prem,
                    cr.destroyed_at IS NOT NULL AS destroyed
             FROM compute_resources cr
             JOIN organizations o ON o.id = cr.organization_id
             JOIN provider_accounts pa ON pa.id = cr.provider_account_id
             JOIN providers p ON p.id = pa.provider_id
             WHERE p.provider_type::text = 'aws'
             ORDER BY cr.created_at DESC, cr.id",
        )
        .fetch_all(&self.pool)
        .await
        .with_context(Ctx::apps())?;

        let builds = sqlx::query_as::<_, AwsBuildRow>(
            "SELECT eb.id,
                    eb.organization_id,
                    o.name::text AS organization_name,
                    eb.app_id,
                    cr.resource_name::text AS app_name,
                    eb.builder_instance_id::text AS builder_instance_id,
                    eb.status::text AS status
             FROM eif_builds eb
             JOIN organizations o ON o.id = eb.organization_id
             LEFT JOIN compute_resources cr ON cr.id = eb.app_id
             WHERE eb.status IN ('pending', 'building', 'uploading')
                OR (eb.builder_instance_id IS NOT NULL
                    AND eb.created_at >= NOW() - INTERVAL '7 days')
             ORDER BY eb.created_at DESC, eb.id",
        )
        .fetch_all(&self.pool)
        .await
        .with_context(Ctx::builds())?;

        let byoc = sqlx::query_as::<_, ByocSubscriptionRow>(
            "SELECT s.organization_id,
                    o.name::text AS organization_name,
                    o.is_active AS organization_active,
                    s.tier,
                    s.status,
                    s.billing_source,
                    s.catalog_valid,
                    s.enterprise_expires_at,
                    s.max_apps,
                    s.pending_tier,
                    s.pending_max_apps,
                    (SELECT COUNT(*)
                     FROM compute_resources cr
                     JOIN cloud_credentials cc ON cc.resource_id = cr.id
                     WHERE cr.organization_id = s.organization_id
                       AND cc.managed_on_prem = true
                       AND cr.destroyed_at IS NULL
                       AND cr.state NOT IN ('terminated', 'failed')) AS allocated_apps
             FROM subscriptions s
             JOIN organizations o ON o.id = s.organization_id
             WHERE s.status <> 'canceled'
             ORDER BY o.name, s.id",
        )
        .fetch_all(&self.pool)
        .await
        .with_context(Ctx::byoc())?;

        Ok(AwsDatabaseState { apps, builds, byoc })
    }
}

#[derive(Debug, thiserror::Error, CtxError)]
pub(crate) enum LoadAwsStateError {
    #[error("failed to load AWS app declarations [{location:?}]")]
    Apps {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("failed to load AWS builder declarations [{location:?}]")]
    Builds {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
    #[error("failed to load BYOC subscriptions [{location:?}]")]
    Byoc {
        #[location]
        location: Location,
        #[source]
        source: BoxError,
    },
}

#[cfg(test)]
mod tests {
    use sqlx::PgPool;
    use uuid::Uuid;

    use super::Database;
    use crate::model::{AppFilter, Relation, ResourceKind, ResourceRef, SortColumn};

    #[tokio::test]
    #[ignore = "requires a migrated PostgreSQL test database"]
    async fn database_projection_includes_apps_builds_and_current_byoc_subscriptions() {
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
        let writer = PgPool::connect(&database_url).await.expect("writable pool");
        let user_id = Uuid::new_v4();
        let organization_id = Uuid::new_v4();
        let unused_organization_id = Uuid::new_v4();
        let canceled_organization_id = Uuid::new_v4();
        let account_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();
        let stopped_app_id = Uuid::new_v4();
        let failed_app_id = Uuid::new_v4();
        let terminated_app_id = Uuid::new_v4();
        let destroyed_app_id = Uuid::new_v4();
        let build_id = Uuid::new_v4();
        let recent_build_id = Uuid::new_v4();
        let old_build_id = Uuid::new_v4();

        sqlx::query("INSERT INTO users (id, username) VALUES ($1, $2)")
            .bind(user_id)
            .bind(format!("aws-projection-{user_id}"))
            .execute(&writer)
            .await
            .expect("user fixture");
        sqlx::query(
            "INSERT INTO organizations (id, name) VALUES
                ($1, 'AWS projection test'),
                ($2, 'Unused BYOC subscription'),
                ($3, 'Canceled BYOC subscription')",
        )
        .bind(organization_id)
        .bind(unused_organization_id)
        .bind(canceled_organization_id)
        .execute(&writer)
        .await
        .expect("organization fixtures");
        sqlx::query(
            "INSERT INTO organization_members (organization_id, user_id, role)
             VALUES ($1, $2, 'owner')",
        )
        .bind(organization_id)
        .bind(user_id)
        .execute(&writer)
        .await
        .expect("membership fixture");
        sqlx::query(
            "INSERT INTO subscriptions
                (user_id, organization_id, tier, max_vcpus, max_apps,
                 price_cents_per_cycle, current_period_end, next_billing_at,
                 status, pending_tier, pending_max_apps)
             VALUES
                ($1, $2, 'growth', 4, 5, 0, NOW() + INTERVAL '1 month',
                 NOW() + INTERVAL '1 month', 'active', 'scale', 3),
                ($1, $3, 'starter', 2, 2, 0, NOW() + INTERVAL '1 month',
                 NOW() + INTERVAL '1 month', 'active', NULL, NULL),
                ($1, $4, 'starter', 2, 2, 0, NOW(), NOW(), 'canceled', NULL, NULL)",
        )
        .bind(user_id)
        .bind(organization_id)
        .bind(unused_organization_id)
        .bind(canceled_organization_id)
        .execute(&writer)
        .await
        .expect("subscription fixtures");
        sqlx::query(
            "INSERT INTO provider_accounts
                (id, organization_id, provider_id, external_account_id, account_name)
             SELECT $1, $2, id, 'aws-projection', 'AWS projection'
             FROM providers WHERE provider_type::text = 'aws'",
        )
        .bind(account_id)
        .bind(organization_id)
        .execute(&writer)
        .await
        .expect("provider fixture");
        sqlx::query(
            "INSERT INTO compute_resources
                (id, organization_id, provider_account_id, resource_type_id,
                 provider_resource_id, resource_name, state, region)
             SELECT $1, $2, $3, rt.id, 'i-projection', 'paging-app-running',
                    'running', 'us-west-2'
             FROM resource_types rt
             JOIN providers p ON p.id = rt.provider_id
             WHERE p.provider_type::text = 'aws' AND rt.type_code = 'ec2-instance'",
        )
        .bind(app_id)
        .bind(organization_id)
        .bind(account_id)
        .execute(&writer)
        .await
        .expect("app fixture");
        sqlx::query(
            "INSERT INTO compute_resources
                (id, organization_id, provider_account_id, resource_type_id,
                 provider_resource_id, resource_name, state, region)
             SELECT $1, $2, $3, rt.id, 'i-projection-stopped', 'paging-app-stopped',
                    'stopped', 'us-west-2'
             FROM resource_types rt
             JOIN providers p ON p.id = rt.provider_id
             WHERE p.provider_type::text = 'aws' AND rt.type_code = 'ec2-instance'",
        )
        .bind(stopped_app_id)
        .bind(organization_id)
        .bind(account_id)
        .execute(&writer)
        .await
        .expect("stopped app fixture");
        sqlx::query(
            "INSERT INTO compute_resources
                (id, organization_id, provider_account_id, resource_type_id,
                 provider_resource_id, resource_name, state, region, destroyed_at)
             SELECT fixture.id, $1, $2, rt.id, fixture.host, fixture.name,
                    fixture.state::resource_state, 'us-west-2', fixture.destroyed_at
             FROM resource_types rt
             JOIN providers p ON p.id = rt.provider_id
             CROSS JOIN (VALUES
                ($3::uuid, 'i-projection-failed', 'filter-app-failed', 'failed', NULL::timestamptz),
                ($4::uuid, 'i-projection-terminated', 'filter-app-terminated', 'terminated', NOW()),
                ($5::uuid, 'i-projection-destroyed', 'filter-app-destroyed', 'pending', NOW())
             ) AS fixture(id, host, name, state, destroyed_at)
             WHERE p.provider_type::text = 'aws' AND rt.type_code = 'ec2-instance'",
        )
        .bind(organization_id)
        .bind(account_id)
        .bind(failed_app_id)
        .bind(terminated_app_id)
        .bind(destroyed_app_id)
        .execute(&writer)
        .await
        .expect("filtered app fixtures");
        sqlx::query(
            "INSERT INTO eif_builds
                (id, organization_id, app_id, commit_sha, procfile_hash, cache_key,
                 builder_instance_id, status, error_message, created_at)
             VALUES
                ($1, $2, $3, 'commit', 'procfile', 'cache-active',
                 'i-builder-active', 'building', NULL, NOW() - INTERVAL '30 days'),
                ($4, $2, $3, 'commit', 'procfile', 'cache-recent',
                 'i-builder-recent', 'failed',
                 'never-display-build-error s3://private/cache-key=secret',
                 NOW() - INTERVAL '1 day'),
                ($5, $2, $3, 'commit', 'procfile', 'cache-old',
                 'i-builder-old', 'completed', NULL, NOW() - INTERVAL '60 days')",
        )
        .bind(build_id)
        .bind(organization_id)
        .bind(app_id)
        .bind(recent_build_id)
        .bind(old_build_id)
        .execute(&writer)
        .await
        .expect("build fixture");
        sqlx::query(
            "INSERT INTO cloud_credentials
                (organization_id, resource_id, platform, identifier, secrets_encrypted,
                 config, managed_on_prem)
             VALUES ($1, $2, 'aws', 'redacted', $3,
                     '{\"aws_account_id\":\"123456789012\",\"aws_region\":\"us-west-2\",\"deployment_id\":\"dep-1\",\"asg_name\":\"asg-1\",\"sentinel_secret\":\"never-select\"}'::jsonb,
                     true)",
        )
        .bind(organization_id)
        .bind(app_id)
        .bind(Vec::<u8>::new())
        .execute(&writer)
        .await
        .expect("BYOC fixture");

        let database = Database::connect_read_only(&database_url)
            .await
            .expect("read-only database");
        let state = database.load_aws_state().await.expect("AWS projection");
        assert!(state.apps.iter().any(|app| app.id == app_id
            && app.managed_on_prem
            && app.aws_account_id == "aws-projection"));
        assert!(state.builds.iter().any(|build| build.id == build_id));
        assert!(state.builds.iter().any(|build| build.id == recent_build_id));
        assert!(state.builds.iter().all(|build| build.id != old_build_id));

        let current = database
            .browse_apps(AppFilter::Current, 0, 200, SortColumn::Details)
            .await
            .expect("current apps");
        assert!(current.page.items.iter().any(|app| app.id == app_id));
        assert!(
            current
                .page
                .items
                .iter()
                .any(|app| app.id == stopped_app_id)
        );
        assert!(
            current.page.items.iter().all(|app| ![
                failed_app_id,
                terminated_app_id,
                destroyed_app_id
            ]
            .contains(&app.id))
        );
        assert_eq!(
            current.counts.total,
            current.counts.current + current.counts.failed + current.counts.historical
        );
        let failed = database
            .browse_apps(AppFilter::Failed, 0, 200, SortColumn::Details)
            .await
            .expect("failed apps");
        assert!(failed.page.items.iter().any(|app| app.id == failed_app_id));
        let historical = database
            .browse_apps(AppFilter::Historical, 0, 200, SortColumn::Details)
            .await
            .expect("historical apps");
        assert!(
            historical
                .page
                .items
                .iter()
                .any(|app| app.id == terminated_app_id)
        );
        assert!(
            historical
                .page
                .items
                .iter()
                .any(|app| app.id == destroyed_app_id)
        );

        let first_builds = database
            .list_builds(app_id, 0, 2)
            .await
            .expect("first build page");
        assert_eq!(first_builds.items[0].id, recent_build_id);
        assert_eq!(
            first_builds.items[0].failure_summary(),
            Some("Build failed; inspect API/builder logs")
        );
        assert!(!format!("{:?}", first_builds.items[0]).contains("never-display-build-error"));
        assert_eq!(first_builds.items[1].id, build_id);
        assert!(first_builds.has_more);
        let last_builds = database
            .list_builds(app_id, 2, 2)
            .await
            .expect("last build page");
        assert_eq!(last_builds.items[0].id, old_build_id);
        assert!(!last_builds.has_more);
        assert_eq!(
            database
                .show_build(app_id, recent_build_id)
                .await
                .expect("build detail")
                .commit_sha,
            "commit"
        );
        assert!(
            database
                .show_build(stopped_app_id, recent_build_id)
                .await
                .is_err()
        );

        let apps = database
            .list(ResourceKind::App, 0, 1, Some(SortColumn::Details))
            .await
            .expect("sorted app page");
        assert_eq!(apps.items[0].id, app_id);
        assert!(apps.has_more);
        let search = database
            .search("paging-app-", 1, 1, Some(SortColumn::Details))
            .await
            .expect("second sorted search page");
        assert_eq!(search.items[0].id, stopped_app_id);
        let related = database
            .follow(
                ResourceRef {
                    kind: ResourceKind::Organization,
                    id: organization_id,
                },
                Relation::OrganizationApps,
                0,
                1,
                Some(SortColumn::Details),
            )
            .await
            .expect("sorted related app page");
        assert_eq!(related.items[0].resource.id, app_id);
        assert!(related.has_more);
        let relations = database
            .relation_summaries(ResourceRef {
                kind: ResourceKind::Organization,
                id: organization_id,
            })
            .await
            .expect("relationship counts");
        assert_eq!(
            relations,
            [
                crate::model::RelationSummary {
                    relation: Relation::OrganizationUsers,
                    count: 1,
                },
                crate::model::RelationSummary {
                    relation: Relation::OrganizationApps,
                    count: 5,
                },
            ]
        );
        let byoc = state
            .byoc
            .iter()
            .find(|row| row.organization_id == organization_id)
            .expect("BYOC subscription row");
        assert_eq!(byoc.allocated_apps, 1);
        assert_eq!(byoc.max_apps, 5);
        assert_eq!(byoc.pending_max_apps, Some(3));
        assert!(byoc.catalog_valid);
        assert_eq!(byoc.enterprise_expires_at, None);
        assert!(
            state
                .byoc
                .iter()
                .any(|row| row.organization_id == unused_organization_id)
        );
        assert!(
            state
                .byoc
                .iter()
                .all(|row| row.organization_id != canceled_organization_id)
        );

        sqlx::query("DELETE FROM eif_builds WHERE id = ANY($1)")
            .bind(vec![build_id, recent_build_id, old_build_id])
            .execute(&writer)
            .await
            .expect("delete build fixture");
        sqlx::query("DELETE FROM cloud_credentials WHERE resource_id = $1")
            .bind(app_id)
            .execute(&writer)
            .await
            .expect("delete BYOC fixture");
        sqlx::query("DELETE FROM subscriptions WHERE user_id = $1")
            .bind(user_id)
            .execute(&writer)
            .await
            .expect("delete subscription fixtures");
        sqlx::query("DELETE FROM compute_resources WHERE id = ANY($1)")
            .bind(vec![
                app_id,
                stopped_app_id,
                failed_app_id,
                terminated_app_id,
                destroyed_app_id,
            ])
            .execute(&writer)
            .await
            .expect("delete app fixture");
        sqlx::query("DELETE FROM provider_accounts WHERE id = $1")
            .bind(account_id)
            .execute(&writer)
            .await
            .expect("delete provider fixture");
        sqlx::query("DELETE FROM organizations WHERE id = ANY($1)")
            .bind(vec![
                organization_id,
                unused_organization_id,
                canceled_organization_id,
            ])
            .execute(&writer)
            .await
            .expect("delete organization fixtures");
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&writer)
            .await
            .expect("delete user fixture");
    }
}
