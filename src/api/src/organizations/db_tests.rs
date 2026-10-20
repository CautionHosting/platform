// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Database-backed checks for [`create_organization_for_user`] against the fully
//! migrated API schema: run `bash tests/e2e/test_app_deployments_db.sh`, which
//! provides the isolated PostgreSQL database these tests share.
//!
//! The gateway creates a user's organization at signup, but a user can also be
//! left without one after being removed from their last organization. That state
//! has to be recoverable, so the creation path must accept a user with no
//! membership, and it must not hand out a second organization to a user who
//! already has one.

use super::*;

async fn test_pool() -> PgPool {
    let url = std::env::var("APP_DEPLOYMENTS_TEST_DATABASE_URL")
        .expect("use the isolated api database test runner");
    let parsed = url::Url::parse(&url).unwrap();
    assert_eq!(parsed.host_str(), Some("127.0.0.1"));
    assert_eq!(parsed.path(), "/caution_app_deployments_test");
    PgPool::connect(&url).await.unwrap()
}

/// Inserts a fully onboarded user who belongs to no organization.
async fn create_org_less_user(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO users (username, email_verified_at, payment_method_added_at)
         VALUES ($1, NOW(), NOW())
         RETURNING id",
    )
    .bind(format!("organization-create-test-{}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn membership(pool: &PgPool, user_id: Uuid) -> Option<(Uuid, String)> {
    sqlx::query_as(
        "SELECT organization_id, role::text
         FROM organization_members
         WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "run bash tests/e2e/test_app_deployments_db.sh (isolated PostgreSQL)"]
async fn a_user_without_an_organization_can_create_one() {
    let pool = test_pool().await;
    let user = create_org_less_user(&pool).await;

    let org = create_organization_for_user(&pool, user, "Recovered Organization")
        .await
        .expect("an org-less user must be able to create an organization");

    assert_eq!(org.name, "Recovered Organization");
    assert!(org.is_active, "a newly created organization must be active");

    let (member_org, role) = membership(&pool, user)
        .await
        .expect("the creator must end up in the new organization");
    assert_eq!(member_org, org.id);
    assert_eq!(role, "owner");

    // The middleware's organization contract accepts the user again, which is
    // the state every other organization-scoped route requires.
    crate::middleware::ensure_user_has_org(&pool, user)
        .await
        .expect("the middleware must accept the user once the organization exists");

    pool.close().await;
}

#[tokio::test]
#[ignore = "run bash tests/e2e/test_app_deployments_db.sh (isolated PostgreSQL)"]
async fn a_user_who_already_belongs_to_an_organization_is_refused() {
    let pool = test_pool().await;
    let user = create_org_less_user(&pool).await;

    let first = create_organization_for_user(&pool, user, "First Organization")
        .await
        .expect("the first organization must be created");

    let error = create_organization_for_user(&pool, user, "Second Organization")
        .await
        .expect_err("a user may belong to exactly one organization");

    assert!(
        matches!(error, CreateOrganizationError::AlreadyMember { user_id, .. } if user_id == user),
        "expected AlreadyMember, got {error:?}"
    );

    let (member_org, _role) = membership(&pool, user).await.unwrap();
    assert_eq!(
        member_org, first.id,
        "the refused call must not move the user to another organization"
    );

    let organizations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM organizations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        organizations, 1,
        "the refused call must not commit an extra organization"
    );

    pool.close().await;
}
