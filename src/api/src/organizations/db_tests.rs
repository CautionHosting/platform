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
//!
//! These tests share one database with every other database-backed test in the
//! runner, so they only ever assert on rows they created themselves.

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

/// A name no other test or earlier run can have used.
fn organization_name(label: &str) -> String {
    format!("{label} {}", Uuid::new_v4())
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

async fn organizations_named(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM organizations WHERE name = $1")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "run bash tests/e2e/test_app_deployments_db.sh (isolated PostgreSQL)"]
async fn a_user_without_an_organization_can_create_one() {
    let pool = test_pool().await;
    let user = create_org_less_user(&pool).await;
    let name = organization_name("Recovered Organization");

    let org = create_organization_for_user(&pool, user, &name)
        .await
        .expect("an org-less user must be able to create an organization");

    assert_eq!(org.name, name);
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
    let first_name = organization_name("First Organization");
    let refused_name = organization_name("Refused Organization");

    let first = create_organization_for_user(&pool, user, &first_name)
        .await
        .expect("the first organization must be created");

    let error = create_organization_for_user(&pool, user, &refused_name)
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
    assert_eq!(
        organizations_named(&pool, &refused_name).await,
        0,
        "the refused call must not commit an organization"
    );

    pool.close().await;
}

/// Adds a new user to `org_id` with `role`, returning the user's id.
async fn add_member_with_role(pool: &PgPool, org_id: Uuid, role: &str) -> Uuid {
    let user = create_org_less_user(pool).await;
    sqlx::query(
        "INSERT INTO organization_members (organization_id, user_id, role)
         VALUES ($1, $2, $3::user_role)",
    )
    .bind(org_id)
    .bind(user)
    .bind(role)
    .execute(pool)
    .await
    .unwrap();
    user
}

/// Runs [`guard_member_change`] in its own transaction and rolls it back, so
/// the organization lock is released and nothing is written.
async fn guard(
    pool: &PgPool,
    org_id: Uuid,
    caller: Uuid,
    target: Uuid,
    new_role: Option<types::UserRole>,
) -> Option<MemberRefusal> {
    let mut tx = pool.begin().await.unwrap();
    let refusal = guard_member_change(&mut tx, org_id, caller, target, new_role)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    refusal
}

#[tokio::test]
#[ignore = "run bash tests/e2e/test_app_deployments_db.sh (isolated PostgreSQL)"]
async fn the_last_owner_can_neither_be_demoted_nor_removed() {
    use types::UserRole::Admin;

    let pool = test_pool().await;
    let owner = create_org_less_user(&pool).await;
    let org = create_organization_for_user(&pool, owner, &organization_name("Sole Owner"))
        .await
        .unwrap();

    assert_eq!(
        guard(&pool, org.id, owner, owner, Some(Admin)).await,
        Some(MemberRefusal::LastOwner)
    );
    assert_eq!(
        guard(&pool, org.id, owner, owner, None).await,
        Some(MemberRefusal::LastOwner)
    );

    // With a second owner, either owner may step down.
    let second_owner = add_member_with_role(&pool, org.id, "owner").await;
    assert_eq!(guard(&pool, org.id, owner, owner, Some(Admin)).await, None);
    assert_eq!(guard(&pool, org.id, owner, second_owner, None).await, None);

    pool.close().await;
}

#[tokio::test]
#[ignore = "run bash tests/e2e/test_app_deployments_db.sh (isolated PostgreSQL)"]
async fn an_admin_cannot_create_change_or_remove_owners() {
    use types::UserRole::{Member, Owner, Viewer};

    let pool = test_pool().await;
    let owner = create_org_less_user(&pool).await;
    let org = create_organization_for_user(&pool, owner, &organization_name("Admin Limits"))
        .await
        .unwrap();
    let admin = add_member_with_role(&pool, org.id, "admin").await;
    let member = add_member_with_role(&pool, org.id, "member").await;

    // Self-promotion, demoting the owner and removing the owner are refused.
    assert_eq!(
        guard(&pool, org.id, admin, admin, Some(Owner)).await,
        Some(MemberRefusal::OwnerOnly)
    );
    assert_eq!(
        guard(&pool, org.id, admin, owner, Some(Member)).await,
        Some(MemberRefusal::OwnerOnly)
    );
    assert_eq!(
        guard(&pool, org.id, admin, owner, None).await,
        Some(MemberRefusal::OwnerOnly)
    );

    // Managing non-owners still works.
    assert_eq!(
        guard(&pool, org.id, admin, member, Some(Viewer)).await,
        None
    );
    assert_eq!(guard(&pool, org.id, admin, member, None).await, None);

    // A plain member is not a manager, and a stranger is not a member.
    assert_eq!(
        guard(&pool, org.id, member, admin, None).await,
        Some(MemberRefusal::NotManager)
    );
    let stranger = create_org_less_user(&pool).await;
    assert_eq!(
        guard(&pool, org.id, owner, stranger, None).await,
        Some(MemberRefusal::NotMember)
    );

    pool.close().await;
}
