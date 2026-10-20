// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! User creation is org-agnostic; the signup route composes it with organization
//! creation for non-org-bound users, while invitations join an existing org.

use super::*;

/// Minimal pre-existing schema; each `sqlx::test` owns a disposable database.
///
/// This hand-rolled schema can drift from the migrations, so it deliberately
/// covers only `create_user`/`create_default_organization`/invitation logic.
/// Real-schema coverage of the signup route lives in the e2e suite
/// (`test_happy_path.sh` via `create_e2e_user`, and `test_webauthn_roundtrip.sh`
/// via the register route).
async fn fixture(pool: &PgPool) -> Uuid {
    sqlx::raw_sql(
        "CREATE TABLE beta_codes (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            used_at TIMESTAMPTZ,
            expires_at TIMESTAMPTZ);
         CREATE TABLE users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            fido2_user_handle BYTEA UNIQUE,
            username TEXT NOT NULL UNIQUE,
            email TEXT,
            beta_code_id UUID,
            email_verified_at TIMESTAMPTZ,
            payment_method_added_at TIMESTAMPTZ,
            username_is_placeholder BOOLEAN NOT NULL DEFAULT true);
         CREATE TABLE legal_documents (
            id UUID NOT NULL,
            document_type TEXT NOT NULL,
            version TEXT NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT false,
            requires_blocking_reacceptance BOOLEAN NOT NULL DEFAULT false);
         CREATE TABLE user_legal_events (
            user_id UUID, legal_document_id UUID, document_type TEXT,
            document_version TEXT, event_type TEXT, event_source TEXT,
            occurred_at TIMESTAMPTZ, ip_address INET, user_agent TEXT);
         CREATE TYPE user_role AS ENUM ('owner', 'admin', 'member', 'viewer');
         CREATE TABLE organizations (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name TEXT NOT NULL);
         CREATE TABLE organization_members (
            organization_id UUID NOT NULL REFERENCES organizations(id),
            user_id UUID NOT NULL REFERENCES users(id),
            role user_role NOT NULL,
            invited_by UUID REFERENCES users(id),
            UNIQUE (user_id));
         CREATE TABLE organization_invitations (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            organization_id UUID NOT NULL REFERENCES organizations(id),
            email TEXT NOT NULL,
            role user_role NOT NULL DEFAULT 'owner',
            token_hash TEXT NOT NULL UNIQUE,
            invited_by UUID REFERENCES users(id),
            accepted_by UUID REFERENCES users(id),
            expires_at TIMESTAMPTZ NOT NULL,
            accepted_at TIMESTAMPTZ,
            revoked_at TIMESTAMPTZ);",
    )
    .execute(pool)
    .await
    .unwrap();

    let alpha_code_id = Uuid::new_v4();
    sqlx::query("INSERT INTO beta_codes (id) VALUES ($1)")
        .bind(alpha_code_id)
        .execute(pool)
        .await
        .unwrap();
    alpha_code_id
}

fn legal() -> SignupLegalContext {
    SignupLegalContext {
        ip_address: None,
        user_agent: None,
    }
}

async fn membership_count(pool: &PgPool, user_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM organization_members WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = false)]
#[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
async fn create_user_alone_does_not_create_an_organization(pool: PgPool) {
    let alpha_code_id = fixture(&pool).await;

    let mut tx = pool.begin().await.unwrap();
    let user = create_user(
        &mut tx,
        b"org-test-handle",
        alpha_code_id,
        "organization-test-user",
        &legal(),
    )
    .await
    .expect("create_user should succeed");
    tx.commit().await.unwrap();

    assert_eq!(
        membership_count(&pool, user).await,
        0,
        "user creation must not create an organization on its own"
    );
}

#[sqlx::test(migrations = false)]
#[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
async fn non_org_bound_registration_creates_exactly_one_owner_organization(pool: PgPool) {
    let alpha_code_id = fixture(&pool).await;

    // Mirrors the signup route: user creation and organization creation share
    // one transaction.
    let mut tx = pool.begin().await.unwrap();
    let user = create_user(
        &mut tx,
        b"org-test-handle",
        alpha_code_id,
        "organization-test-user",
        &legal(),
    )
    .await
    .expect("create_user should succeed");
    create_default_organization(&mut tx, user)
        .await
        .expect("organization creation should succeed");
    tx.commit().await.unwrap();

    let memberships: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT organization_id, role::text FROM organization_members WHERE user_id = $1",
    )
    .bind(user)
    .fetch_all(&pool)
    .await
    .unwrap();

    assert_eq!(
        memberships.len(),
        1,
        "a non-org-bound signup must create exactly one organization membership"
    );
    assert_eq!(memberships[0].1, "owner");

    let name: String = sqlx::query_scalar("SELECT name FROM organizations WHERE id = $1")
        .bind(memberships[0].0)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(name, DEFAULT_ORGANIZATION_NAME);
}

#[sqlx::test(migrations = false)]
#[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
async fn invited_registration_joins_the_invited_organization_only(pool: PgPool) {
    fixture(&pool).await;

    let inviter: Uuid =
        sqlx::query_scalar("INSERT INTO users (username) VALUES ('inviter') RETURNING id")
            .fetch_one(&pool)
            .await
            .unwrap();
    let invited_org: Uuid =
        sqlx::query_scalar("INSERT INTO organizations (name) VALUES ('invited org') RETURNING id")
            .fetch_one(&pool)
            .await
            .unwrap();
    let invitation_id: Uuid = sqlx::query_scalar(
        "INSERT INTO organization_invitations (organization_id, email, token_hash, invited_by, expires_at)
         VALUES ($1, 'invitee@example.com', 'invite-token-hash', $2, NOW() + INTERVAL '1 day')
         RETURNING id",
    )
    .bind(invited_org)
    .bind(inviter)
    .fetch_one(&pool)
    .await
    .unwrap();

    let user = accept_invitation_and_create_user(
        &pool,
        invitation_id,
        "invite-token-hash",
        b"invite-handle",
        "invitee",
        &legal(),
    )
    .await
    .expect("accepting the invitation should succeed");

    let memberships: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT organization_id, role::text FROM organization_members WHERE user_id = $1",
    )
    .bind(user)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        memberships.len(),
        1,
        "an invited user must belong to exactly one organization"
    );
    assert_eq!(
        memberships[0].0, invited_org,
        "an invited user must join the inviting organization, not a new one"
    );

    let personal_orgs: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM organizations WHERE name = $1")
            .bind(DEFAULT_ORGANIZATION_NAME)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        personal_orgs, 0,
        "an invited user must not get a personal organization"
    );

    let accepted: bool = sqlx::query_scalar(
        "SELECT accepted_at IS NOT NULL FROM organization_invitations WHERE id = $1",
    )
    .bind(invitation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(accepted, "the invitation must be marked accepted");
}

#[sqlx::test(migrations = false)]
#[ignore = "requires DATABASE_URL pointing to disposable Postgres"]
async fn failed_signup_rolls_back_user_and_alpha_code(pool: PgPool) {
    let alpha_code_id = fixture(&pool).await;

    sqlx::query("INSERT INTO users (username) VALUES ('taken')")
        .execute(&pool)
        .await
        .unwrap();

    // The signup route owns this transaction; a failure must roll everything
    // back (no user, no consumed alpha code).
    let mut tx = pool.begin().await.unwrap();
    let error = create_user(&mut tx, b"handle", alpha_code_id, "taken", &legal())
        .await
        .expect_err("a duplicate username must fail");
    assert!(
        matches!(error.kind, DbErrorKind::UsernameTaken),
        "expected UsernameTaken, got {:?}",
        error.kind
    );
    tx.rollback().await.unwrap();

    let used: Option<OffsetDateTime> =
        sqlx::query_scalar("SELECT used_at FROM beta_codes WHERE id = $1")
            .bind(alpha_code_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        used.is_none(),
        "the alpha code must not be consumed when signup rolls back"
    );

    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username = 'taken'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(users, 1, "no second user row must exist after the rollback");
}
