// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use super::*;

const MIGRATION: &str = include_str!("../../../api/migrations/060_dbsc.sql");
const RAW: &str = "raw-session-id";
const TOKEN: &str = "bound-token";
const CHALLENGE: &str = "challenge-1";
const DBSC_ID: &str = "dbsc-id-1";
const PUBLIC_KEY: &[u8] = b"sec1-point";

fn in_minutes(minutes: i64) -> OffsetDateTime {
    OffsetDateTime::now_utc() + time::Duration::minutes(minutes)
}

/// Minimal `auth_sessions` (as in `passkey_usage_tests.rs`) plus `060_dbsc.sql`,
/// holding one live, unbound session `RAW`. Each sqlx test owns a disposable
/// database.
async fn fixture(pool: &PgPool) -> Uuid {
    sqlx::raw_sql(
        "CREATE TABLE auth_sessions (
            session_id TEXT PRIMARY KEY, credential_id BYTEA,
            user_id UUID NOT NULL,
            created_at TIMESTAMPTZ, expires_at TIMESTAMPTZ, last_used_at TIMESTAMPTZ);",
    )
    .execute(pool)
    .await
    .unwrap();
    // Applied twice: the deploy runner re-applies every migration file.
    for _ in 0..2 {
        sqlx::raw_sql(MIGRATION).execute(pool).await.unwrap();
    }
    let user = Uuid::new_v4();
    create_auth_session(pool, RAW, b"cred", user, in_minutes(60))
        .await
        .unwrap();
    user
}

/// Issue `CHALLENGE` on `RAW`, then bind it to `token`.
async fn bind(pool: &PgPool, token: &str, token_expires_at: OffsetDateTime) -> bool {
    set_dbsc_challenge(pool, RAW, CHALLENGE, in_minutes(5))
        .await
        .unwrap();
    bind_dbsc_session(
        pool,
        RAW,
        CHALLENGE,
        DBSC_ID,
        PUBLIC_KEY,
        &hash_bound_token(token),
        token_expires_at,
    )
    .await
    .unwrap()
}

async fn resolve(pool: &PgPool, token: &str) -> Option<ValidatedSession> {
    validate_auth_session(pool, token).await.unwrap()
}

#[test]
fn bound_token_hash_is_sha256_of_token_bytes() {
    assert_eq!(
        hex::encode(hash_bound_token("abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[sqlx::test(migrations = false)]
#[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
async fn unbound_session_id_resolves(pool: PgPool) {
    let user = fixture(&pool).await;
    // Login stores a challenge on every session; a client that never registers
    // (Firefox, Safari, the CLI) must keep resolving by its raw id.
    set_dbsc_challenge(&pool, RAW, CHALLENGE, in_minutes(5))
        .await
        .unwrap();
    let v = resolve(&pool, RAW).await.unwrap();
    assert_eq!(v.session_id, RAW);
    assert_eq!(v.credential_id, b"cred");
    assert_eq!(v.user_id, user);
}

#[sqlx::test(migrations = false)]
#[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
async fn bound_session_rejects_raw_session_id(pool: PgPool) {
    fixture(&pool).await;
    assert!(bind(&pool, TOKEN, in_minutes(10)).await);
    assert!(resolve(&pool, RAW).await.is_none());
}

#[sqlx::test(migrations = false)]
#[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
async fn bound_token_resolves_to_canonical_session_id(pool: PgPool) {
    let user = fixture(&pool).await;
    assert!(bind(&pool, TOKEN, in_minutes(10)).await);
    sqlx::query("UPDATE auth_sessions SET last_used_at = NOW() - INTERVAL '1 hour'")
        .execute(&pool)
        .await
        .unwrap();
    let v = resolve(&pool, TOKEN).await.unwrap();
    assert_eq!(v.session_id, RAW);
    assert_eq!(v.credential_id, b"cred");
    assert_eq!(v.user_id, user);
    // The last_used_at touch follows the canonical id, not the presented token.
    let touched: bool = sqlx::query_scalar(
        "SELECT last_used_at > NOW() - INTERVAL '1 minute' FROM auth_sessions WHERE session_id = $1",
    )
    .bind(RAW)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(touched);
}

#[sqlx::test(migrations = false)]
#[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
async fn expired_bound_token_rejected(pool: PgPool) {
    fixture(&pool).await;
    assert!(bind(&pool, TOKEN, in_minutes(-1)).await);
    assert!(resolve(&pool, TOKEN).await.is_none());
    assert!(resolve(&pool, RAW).await.is_none());
}

#[sqlx::test(migrations = false)]
#[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
async fn expired_session_rejects_bound_token(pool: PgPool) {
    fixture(&pool).await;
    assert!(bind(&pool, TOKEN, in_minutes(10)).await);
    sqlx::query("UPDATE auth_sessions SET expires_at = NOW() - INTERVAL '1 minute'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(resolve(&pool, TOKEN).await.is_none());
}

#[sqlx::test(migrations = false)]
#[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
async fn bind_is_single_shot(pool: PgPool) {
    fixture(&pool).await;
    assert!(bind(&pool, TOKEN, in_minutes(10)).await);
    let bound = get_dbsc_session_by_session_id(&pool, RAW)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bound.dbsc_id.as_deref(), Some(DBSC_ID));
    assert_eq!(bound.dbsc_public_key.as_deref(), Some(PUBLIC_KEY));
    assert_eq!(bound.dbsc_challenge, None);
    assert_eq!(bound.dbsc_challenge_expires_at, None);
    assert!(bound.expires_at > in_minutes(59));

    set_dbsc_challenge(&pool, RAW, "challenge-2", in_minutes(5))
        .await
        .unwrap();
    assert!(!bind_dbsc_session(
        &pool,
        RAW,
        "challenge-2",
        "dbsc-id-2",
        b"other-key",
        &hash_bound_token("other-token"),
        in_minutes(10),
    )
    .await
    .unwrap());
    let still = get_dbsc_session_by_dbsc_id(&pool, DBSC_ID)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(still.session_id, RAW);
    assert_eq!(still.dbsc_public_key.as_deref(), Some(PUBLIC_KEY));
    assert!(resolve(&pool, "other-token").await.is_none());
    assert!(resolve(&pool, TOKEN).await.is_some());
}

#[sqlx::test(migrations = false)]
#[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
async fn bind_rejects_wrong_or_expired_challenge(pool: PgPool) {
    fixture(&pool).await;
    let hash = hash_bound_token(TOKEN);

    set_dbsc_challenge(&pool, RAW, CHALLENGE, in_minutes(5))
        .await
        .unwrap();
    assert!(!bind_dbsc_session(
        &pool,
        RAW,
        "wrong",
        DBSC_ID,
        PUBLIC_KEY,
        &hash,
        in_minutes(10)
    )
    .await
    .unwrap());

    set_dbsc_challenge(&pool, RAW, CHALLENGE, in_minutes(-1))
        .await
        .unwrap();
    assert!(!bind_dbsc_session(
        &pool,
        RAW,
        CHALLENGE,
        DBSC_ID,
        PUBLIC_KEY,
        &hash,
        in_minutes(10)
    )
    .await
    .unwrap());

    // Both failures left the session unbound.
    assert_eq!(resolve(&pool, RAW).await.unwrap().session_id, RAW);
    assert!(resolve(&pool, TOKEN).await.is_none());
    assert!(get_dbsc_session_by_dbsc_id(&pool, DBSC_ID)
        .await
        .unwrap()
        .is_none());
}

#[sqlx::test(migrations = false)]
#[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
async fn rotate_requires_current_challenge(pool: PgPool) {
    fixture(&pool).await;
    assert!(bind(&pool, TOKEN, in_minutes(10)).await);
    let new_hash = hash_bound_token("token-2");

    // The binding consumed CHALLENGE.
    assert!(
        !rotate_bound_token(&pool, DBSC_ID, CHALLENGE, &new_hash, in_minutes(10))
            .await
            .unwrap()
    );

    set_dbsc_challenge(&pool, RAW, "challenge-2", in_minutes(5))
        .await
        .unwrap();
    assert!(
        rotate_bound_token(&pool, DBSC_ID, "challenge-2", &new_hash, in_minutes(10))
            .await
            .unwrap()
    );
    assert!(resolve(&pool, TOKEN).await.is_none());
    assert_eq!(resolve(&pool, "token-2").await.unwrap().session_id, RAW);

    let rotated = get_dbsc_session_by_dbsc_id(&pool, DBSC_ID)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rotated.dbsc_challenge, None);
    assert_eq!(rotated.dbsc_challenge_expires_at, None);
    // Single-use: the same challenge cannot rotate twice.
    assert!(!rotate_bound_token(
        &pool,
        DBSC_ID,
        "challenge-2",
        &hash_bound_token("token-3"),
        in_minutes(10)
    )
    .await
    .unwrap());
}

#[sqlx::test(migrations = false)]
#[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
async fn delete_by_bound_token_removes_session(pool: PgPool) {
    fixture(&pool).await;
    assert!(bind(&pool, TOKEN, in_minutes(10)).await);
    delete_auth_session(&pool, TOKEN).await.unwrap();
    assert!(get_dbsc_session_by_session_id(&pool, RAW)
        .await
        .unwrap()
        .is_none());
    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM auth_sessions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining, 0);
}

#[sqlx::test(migrations = false)]
#[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
async fn delete_by_raw_id_spares_bound_session(pool: PgPool) {
    fixture(&pool).await;
    assert!(bind(&pool, TOKEN, in_minutes(10)).await);
    // A stale raw id (public /auth/logout) must not log out a bound session.
    delete_auth_session(&pool, RAW).await.unwrap();
    assert!(get_dbsc_session_by_session_id(&pool, RAW)
        .await
        .unwrap()
        .is_some());
    assert_eq!(resolve(&pool, TOKEN).await.unwrap().session_id, RAW);
}

#[sqlx::test(migrations = false)]
#[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
async fn delete_by_expired_bound_token_removes_session(pool: PgPool) {
    fixture(&pool).await;
    // An expired token still deletes the row so it cannot be refreshed back.
    assert!(bind(&pool, TOKEN, in_minutes(-1)).await);
    delete_auth_session(&pool, TOKEN).await.unwrap();
    assert!(get_dbsc_session_by_session_id(&pool, RAW)
        .await
        .unwrap()
        .is_none());
}
