// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::*;

const MIGRATION: &str = include_str!("../../../api/migrations/053_passkey_last_used.sql");

async fn fixture(pool: &PgPool) -> Uuid {
    // Minimal pre-migration schema; each sqlx test owns a disposable database.
    sqlx::raw_sql(
        "CREATE TABLE fido2_credentials (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID NOT NULL,
            credential_id BYTEA UNIQUE NOT NULL, name TEXT, transport JSONB,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
         CREATE TABLE signed_request_audit (
            user_id UUID, credential_id BYTEA, verified_at TIMESTAMPTZ);
         CREATE TABLE auth_sessions (
            session_id TEXT PRIMARY KEY, credential_id BYTEA,
            created_at TIMESTAMPTZ, expires_at TIMESTAMPTZ, last_used_at TIMESTAMPTZ);
         CREATE TABLE qr_login_tokens (expires_at TIMESTAMPTZ);
         CREATE TABLE qr_sign_tokens (expires_at TIMESTAMPTZ);",
    )
    .execute(pool)
    .await
    .unwrap();
    let user = Uuid::new_v4();
    for credential in [b"first".as_slice(), b"second"] {
        sqlx::query("INSERT INTO fido2_credentials (user_id, credential_id) VALUES ($1, $2)")
            .bind(user)
            .bind(credential)
            .execute(pool)
            .await
            .unwrap();
    }
    user
}

async fn usage(pool: &PgPool, user: Uuid, credential: &[u8]) -> Option<OffsetDateTime> {
    get_user_credential_by_credential_id(pool, user, credential)
        .await
        .unwrap()
        .unwrap()
        .last_used_at
}

#[sqlx::test(migrations = false)]
#[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
async fn backfill_only_uses_matching_verification_evidence(pool: PgPool) {
    let user = fixture(&pool).await;
    let earlier = OffsetDateTime::now_utc() - time::Duration::days(3);
    let latest = earlier + time::Duration::days(1);
    for (owner, timestamp) in [
        (user, earlier),
        (user, latest),
        (Uuid::new_v4(), OffsetDateTime::now_utc()),
    ] {
        sqlx::query("INSERT INTO signed_request_audit VALUES ($1, $2, $3)")
            .bind(owner)
            .bind(b"first".as_slice())
            .bind(timestamp)
            .execute(&pool)
            .await
            .unwrap();
    }
    create_auth_session(
        &pool,
        "recent",
        b"second",
        OffsetDateTime::now_utc() + time::Duration::hours(1),
    )
    .await
    .unwrap();
    sqlx::raw_sql(MIGRATION).execute(&pool).await.unwrap();
    // Postgres stores microseconds rather than nanoseconds.
    assert_eq!(
        usage(&pool, user, b"first").await.unwrap().unix_timestamp(),
        latest.unix_timestamp()
    );
    assert_eq!(usage(&pool, user, b"second").await, None);
    record_credential_use(&pool, user, b"first").await.unwrap();
    let recorded = usage(&pool, user, b"first").await;
    sqlx::raw_sql(MIGRATION).execute(&pool).await.unwrap();
    assert_eq!(usage(&pool, user, b"first").await, recorded);
}

#[sqlx::test(migrations = false)]
#[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
async fn verification_survives_sessions_and_only_updates_its_credential(pool: PgPool) {
    let user = fixture(&pool).await;
    sqlx::raw_sql(MIGRATION).execute(&pool).await.unwrap();
    create_auth_session(
        &pool,
        "active",
        b"first",
        OffsetDateTime::now_utc() + time::Duration::hours(1),
    )
    .await
    .unwrap();
    validate_auth_session(&pool, "active").await.unwrap();
    assert_eq!(usage(&pool, user, b"first").await, None);
    record_credential_use(&pool, user, b"first").await.unwrap();
    let recorded = usage(&pool, user, b"first").await;
    assert!(recorded.is_some());
    validate_auth_session(&pool, "active").await.unwrap();
    assert_eq!(usage(&pool, user, b"first").await, recorded);
    delete_auth_session(&pool, "active").await.unwrap();
    create_auth_session(
        &pool,
        "expired",
        b"first",
        OffsetDateTime::now_utc() - time::Duration::hours(1),
    )
    .await
    .unwrap();
    run_cleanups(&pool).await;
    assert_eq!(usage(&pool, user, b"first").await, recorded);
    assert_eq!(usage(&pool, user, b"second").await, None);
    let listed = list_user_credentials(&pool, user).await.unwrap();
    assert_eq!(
        listed
            .iter()
            .find(|c| c.credential_id == b"first")
            .unwrap()
            .last_used_at,
        recorded
    );
}

#[sqlx::test(migrations = false)]
#[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
async fn usage_is_monotonic_and_write_errors_propagate(pool: PgPool) {
    let user = fixture(&pool).await;
    sqlx::raw_sql(MIGRATION).execute(&pool).await.unwrap();
    // Exercise concurrent writers against a stored timestamp ahead of NOW().
    sqlx::query("UPDATE fido2_credentials SET last_used_at = NOW() + INTERVAL '1 hour' WHERE credential_id = $1")
        .bind(b"first".as_slice()).execute(&pool).await.unwrap();
    let recorded = usage(&pool, user, b"first").await;
    let (a, b) = tokio::join!(
        record_credential_use(&pool, user, b"first"),
        record_credential_use(&pool, user, b"first")
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(usage(&pool, user, b"first").await, recorded);
    assert!(record_credential_use(&pool, Uuid::new_v4(), b"first")
        .await
        .is_err());
    assert!(record_credential_use(&pool, user, b"missing")
        .await
        .is_err());
    sqlx::raw_sql("CREATE FUNCTION reject_usage() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test write failure'; END $$;
        CREATE TRIGGER reject_usage BEFORE UPDATE ON fido2_credentials FOR EACH ROW EXECUTE FUNCTION reject_usage();")
        .execute(&pool).await.unwrap();
    assert!(record_credential_use(&pool, user, b"second").await.is_err());
    assert_eq!(usage(&pool, user, b"second").await, None);
}
