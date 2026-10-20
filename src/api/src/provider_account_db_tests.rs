// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Database-backed concurrency checks for [`get_or_create_provider_account`]:
//! run `bash tests/e2e/test_app_deployments_db.sh` (isolated PostgreSQL).
//!
//! Provisioning a provider account happens lazily on first use, so two parallel
//! first requests for a brand-new organization must not collide on
//! `provider_accounts_unique`.

use crate::get_or_create_provider_account;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::Barrier;
use uuid::Uuid;

const CALLERS: usize = 4;

async fn test_pool() -> PgPool {
    let url = std::env::var("APP_DEPLOYMENTS_TEST_DATABASE_URL")
        .expect("use the isolated api database test runner");
    let parsed = url::Url::parse(&url).unwrap();
    assert_eq!(parsed.host_str(), Some("127.0.0.1"));
    assert_eq!(parsed.path(), "/caution_app_deployments_test");
    PgPool::connect(&url).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run bash tests/e2e/test_app_deployments_db.sh (isolated PostgreSQL)"]
async fn concurrent_provider_account_creation_is_idempotent() {
    let pool = Arc::new(test_pool().await);

    let user: Uuid = sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(format!("provider-test-{}", Uuid::new_v4()))
        .fetch_one(&*pool)
        .await
        .unwrap();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name) VALUES ('provider test') RETURNING id",
    )
    .fetch_one(&*pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO organization_members (organization_id, user_id, role)
         VALUES ($1, $2, 'owner')",
    )
    .bind(org)
    .bind(user)
    .execute(&*pool)
    .await
    .unwrap();

    // Release every caller at once so they race on the first insert rather than
    // running one after another.
    let barrier = Arc::new(Barrier::new(CALLERS));
    let mut handles = Vec::with_capacity(CALLERS);
    for _ in 0..CALLERS {
        let pool = Arc::clone(&pool);
        let barrier = Arc::clone(&barrier);
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            get_or_create_provider_account(&pool, org).await
        }));
    }

    let mut ids = Vec::with_capacity(CALLERS);
    for handle in handles {
        ids.push(
            handle
                .await
                .expect("task panicked")
                .expect("provider account creation failed"),
        );
    }
    assert!(
        ids.iter().all(|id| *id == ids[0]),
        "concurrent callers must observe the same provider account, got {ids:?}"
    );

    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM provider_accounts WHERE organization_id = $1")
            .bind(org)
            .fetch_one(&*pool)
            .await
            .unwrap();
    assert_eq!(count, 1, "exactly one provider account row must exist");

    Arc::try_unwrap(pool).expect("sole owner").close().await;
}
