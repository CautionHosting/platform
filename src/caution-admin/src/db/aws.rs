// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

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
                OR eb.builder_instance_id IS NOT NULL
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
        let build_id = Uuid::new_v4();

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
             SELECT $1, $2, $3, rt.id, 'i-projection', 'projection-app',
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
            "INSERT INTO eif_builds
                (id, organization_id, app_id, commit_sha, procfile_hash, cache_key,
                 builder_instance_id, status)
             VALUES ($1, $2, $3, 'commit', 'procfile', 'cache', 'i-builder', 'building')",
        )
        .bind(build_id)
        .bind(organization_id)
        .bind(app_id)
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
        assert!(
            state
                .apps
                .iter()
                .any(|app| app.id == app_id && app.managed_on_prem)
        );
        assert!(state.builds.iter().any(|build| build.id == build_id));
        let byoc = state
            .byoc
            .iter()
            .find(|row| row.organization_id == organization_id)
            .expect("BYOC subscription row");
        assert_eq!(byoc.allocated_apps, 1);
        assert_eq!(byoc.max_apps, 5);
        assert_eq!(byoc.pending_max_apps, Some(3));
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

        sqlx::query("DELETE FROM eif_builds WHERE id = $1")
            .bind(build_id)
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
        sqlx::query("DELETE FROM compute_resources WHERE id = $1")
            .bind(app_id)
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
