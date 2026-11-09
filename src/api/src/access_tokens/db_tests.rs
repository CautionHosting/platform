// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Database-backed checks for the organization access token schema
//! (`migrations/064_organization_access_tokens.sql`): run
//! `bash tests/e2e/test_app_deployments_db.sh`, which provides the isolated
//! PostgreSQL database these tests share.

use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

async fn test_pool() -> PgPool {
    let url = std::env::var("APP_DEPLOYMENTS_TEST_DATABASE_URL")
        .expect("use the isolated api database test runner");
    let parsed = url::Url::parse(&url).unwrap();
    assert_eq!(parsed.host_str(), Some("127.0.0.1"));
    assert_eq!(parsed.path(), "/caution_app_deployments_test");
    PgPool::connect(&url).await.unwrap()
}

async fn create_org(pool: &PgPool) -> Uuid {
    sqlx::query_scalar("INSERT INTO organizations (name) VALUES ($1) RETURNING id")
        .bind(format!("access-token test {}", Uuid::new_v4()))
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn create_role(pool: &PgPool, org: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO rbac_roles (organization_id, name) VALUES ($1, $2) RETURNING id",
    )
    .bind(org)
    .bind(format!("role-{}", Uuid::new_v4()))
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn create_token(pool: &PgPool, org: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO organization_access_tokens (organization_id, token_hash, name)
         VALUES ($1, $2, 'test token') RETURNING id",
    )
    .bind(org)
    .bind(hex::encode(Sha256::digest(Uuid::new_v4().as_bytes())))
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "run bash tests/e2e/test_app_deployments_db.sh (isolated PostgreSQL)"]
async fn token_hash_is_unique() {
    let pool = test_pool().await;
    let org = create_org(&pool).await;
    let hash = hex::encode(Sha256::digest(b"duplicate"));

    let insert = || {
        sqlx::query(
            "INSERT INTO organization_access_tokens (organization_id, token_hash, name)
             VALUES ($1, $2, 'dup')",
        )
        .bind(org)
        .bind(hash.clone())
        .execute(&pool)
    };

    insert().await.expect("first insert is fine");
    assert!(
        insert().await.is_err(),
        "duplicate token_hash must be rejected"
    );

    pool.close().await;
}

#[tokio::test]
#[ignore = "run bash tests/e2e/test_app_deployments_db.sh (isolated PostgreSQL)"]
async fn token_role_must_be_in_the_same_organization() {
    let pool = test_pool().await;
    let org = create_org(&pool).await;
    let other_org = create_org(&pool).await;
    let token = create_token(&pool, org).await;
    let foreign_role = create_role(&pool, other_org).await;

    let result = sqlx::query(
        "INSERT INTO organization_access_token_roles (organization_id, token_id, role_id)
         VALUES ($1, $2, $3)",
    )
    .bind(org)
    .bind(token)
    .bind(foreign_role)
    .execute(&pool)
    .await;
    assert!(
        result.is_err(),
        "a role from another organization must not attach"
    );

    pool.close().await;
}

#[tokio::test]
#[ignore = "run bash tests/e2e/test_app_deployments_db.sh (isolated PostgreSQL)"]
async fn deleting_a_token_cascades_its_roles() {
    let pool = test_pool().await;
    let org = create_org(&pool).await;
    let token = create_token(&pool, org).await;
    let role = create_role(&pool, org).await;

    sqlx::query(
        "INSERT INTO organization_access_token_roles (organization_id, token_id, role_id)
         VALUES ($1, $2, $3)",
    )
    .bind(org)
    .bind(token)
    .bind(role)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query("DELETE FROM organization_access_tokens WHERE id = $1")
        .bind(token)
        .execute(&pool)
        .await
        .unwrap();

    let remaining: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM organization_access_token_roles WHERE token_id = $1",
    )
    .bind(token)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(remaining, 0, "token deletion must cascade to its role rows");

    pool.close().await;
}
