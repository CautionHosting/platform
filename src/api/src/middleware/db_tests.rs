// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Database-backed checks for [`ensure_user_has_org`] against the fully migrated
//! API schema: run `bash tests/e2e/test_app_deployments_db.sh`, which provides the
//! isolated PostgreSQL database these tests share.
//!
//! Organizations are created with the user in the gateway at signup, so the
//! middleware must pass a user that has one and fail a user that does not.

use super::*;

async fn test_pool() -> PgPool {
    let url = std::env::var("APP_DEPLOYMENTS_TEST_DATABASE_URL")
        .expect("use the isolated api database test runner");
    let parsed = url::Url::parse(&url).unwrap();
    assert_eq!(parsed.host_str(), Some("127.0.0.1"));
    assert_eq!(parsed.path(), "/caution_app_deployments_test");
    PgPool::connect(&url).await.unwrap()
}

/// Inserts a user with a unique username, optionally fully onboarded.
async fn create_user(pool: &PgPool, onboarded: bool) -> Uuid {
    let username = format!("middleware-test-{}", Uuid::new_v4());
    sqlx::query_scalar(
        "INSERT INTO users (username, email_verified_at, payment_method_added_at)
         VALUES ($1,
                 CASE WHEN $2 THEN NOW() ELSE NULL END,
                 CASE WHEN $2 THEN NOW() ELSE NULL END)
         RETURNING id",
    )
    .bind(username)
    .bind(onboarded)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "run bash tests/e2e/test_app_deployments_db.sh (isolated PostgreSQL)"]
async fn onboarded_user_with_an_organization_passes() {
    let pool = test_pool().await;
    let user = create_user(&pool, true).await;

    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name) VALUES ('middleware test') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO organization_members (organization_id, user_id, role)
         VALUES ($1, $2, 'owner')",
    )
    .bind(org)
    .bind(user)
    .execute(&pool)
    .await
    .unwrap();

    ensure_user_has_org(&pool, user)
        .await
        .expect("a user with an organization must pass");

    pool.close().await;
}

#[tokio::test]
#[ignore = "run bash tests/e2e/test_app_deployments_db.sh (isolated PostgreSQL)"]
async fn onboarded_user_without_an_organization_is_rejected() {
    let pool = test_pool().await;
    let user = create_user(&pool, true).await;

    let error = ensure_user_has_org(&pool, user)
        .await
        .expect_err("a user without an organization must be rejected");

    assert!(
        matches!(error, EnsureUserHasOrgError::MissingOrganization { .. }),
        "expected MissingOrganization, got {error:?}"
    );

    pool.close().await;
}

#[tokio::test]
#[ignore = "run bash tests/e2e/test_app_deployments_db.sh (isolated PostgreSQL)"]
async fn user_that_has_not_onboarded_is_rejected() {
    let pool = test_pool().await;
    let user = create_user(&pool, false).await;

    // The user has an organization (created at signup) but has not onboarded.
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name) VALUES ('middleware test') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO organization_members (organization_id, user_id, role)
         VALUES ($1, $2, 'owner')",
    )
    .bind(org)
    .bind(user)
    .execute(&pool)
    .await
    .unwrap();

    let error = ensure_user_has_org(&pool, user)
        .await
        .expect_err("a user that has not onboarded must be rejected");

    assert!(
        matches!(error, EnsureUserHasOrgError::NotOnboarded { .. }),
        "expected NotOnboarded, got {error:?}"
    );

    pool.close().await;
}
