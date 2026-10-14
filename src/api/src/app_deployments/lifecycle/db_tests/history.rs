// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Database-backed tests of deployment history, signed switch links and app summaries.

use super::*;
use crate::app_deployments::events::{self, NewOperation, Operation, Outcome};
use crate::app_deployments::switch::signed_switch_request;

#[tokio::test]
#[ignore = "run bash tests/e2e/test_app_deployments_db.sh (isolated PostgreSQL)"]
async fn history() {
    let pool = test_pool().await;
    switch_requires_the_callers_pending_signed_request(&pool).await;
    rejected_switches_keep_their_signed_request_link(&pool).await;
    the_switch_handler_records_only_signed_switches(&pool).await;
    interrupted_operations_are_settled_by_reconciliation(&pool).await;
    destroy_records_the_operation_with_its_claim(&pool).await;
    pool.close().await;
}

/// A pending WebAuthn audit row as the gateway writes it before the handler runs.
async fn signed_request(pool: &PgPool, user: Uuid, method: &str, path: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO signed_request_audit
             (user_id, credential_id, credential_public_key, relying_party_id, request_method,
              request_path, request_body_sha256, request_body_size_bytes, challenge_id,
              authentication_state, assertion, authorization_flow)
         VALUES ($1, '\\x01', '\\x01', 'localhost', $2, $3, repeat('0', 64), 0,
                 gen_random_uuid(), '\\x01', '\\x01', 'direct')
         RETURNING id",
    )
    .bind(user)
    .bind(method)
    .bind(path)
    .fetch_one(pool)
    .await
    .unwrap()
}

fn signed(user: Uuid, signed_request_id: Option<Uuid>) -> crate::AuthContext {
    crate::AuthContext {
        user_id: user,
        auth_method: Some("passkey"),
        signed_request_id,
    }
}

async fn latest_outcome(pool: &PgPool, operation_id: Uuid) -> String {
    sqlx::query_scalar(
        "SELECT outcome FROM deployment_events WHERE operation_id = $1 ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .bind(operation_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn switch_requires_the_callers_pending_signed_request(pool: &PgPool) {
    let f = fixture(pool, "running").await;
    let path = format!("/resources/{}/deployments/{}/switch", f.app, f.target);
    let own = signed_request(pool, f.user, "POST", &path).await;
    assert_eq!(
        signed_switch_request(pool, &signed(f.user, Some(own)), f.app, f.target)
            .await
            .unwrap(),
        own
    );
    // Another member's proof, another path, another method, a completed request
    // or no proof at all is refused.
    let other_user = member(pool, f.org).await;
    let theirs = signed_request(pool, other_user, "POST", &path).await;
    let other_path = signed_request(
        pool,
        f.user,
        "POST",
        &format!("/resources/{}/deployments/{}/switch", f.app, Uuid::new_v4()),
    )
    .await;
    let get = signed_request(pool, f.user, "GET", &path).await;
    let done = signed_request(pool, f.user, "POST", &path).await;
    sqlx::query(
        "UPDATE signed_request_audit SET response_status = 200, completed_at = NOW() WHERE id = $1",
    )
    .bind(done)
    .execute(pool)
    .await
    .unwrap();
    for id in [
        Some(theirs),
        Some(other_path),
        Some(get),
        Some(done),
        Some(Uuid::new_v4()),
        None,
    ] {
        assert!(matches!(
            signed_switch_request(pool, &signed(f.user, id), f.app, f.target).await,
            Err(SwitchError::Unsigned { .. })
        ));
    }
}

/// Covers what the recorder stores for a rejected switch; which errors become
/// `rejected` is pinned by `switch.rs`'s `moved_nothing_is_true_only_before_the_address_moves`.
async fn rejected_switches_keep_their_signed_request_link(pool: &PgPool) {
    let f = fixture(pool, "running").await;
    let path = format!("/resources/{}/deployments/{}/switch", f.app, f.target);
    let id = signed_request(pool, f.user, "POST", &path).await;
    let auth = signed(f.user, Some(id));
    let operation = events::begin(
        pool,
        NewOperation {
            org_id: f.org,
            app_id: f.app,
            operation: Operation::Switch,
            actor: &auth,
            previous_deployment_id: None,
            target_deployment_id: Some(f.target),
            signed_request_id: Some(id),
        },
    )
    .await
    .unwrap();
    events::finish(
        pool,
        operation,
        Outcome::Rejected,
        Some("The live deployment changed; review and confirm again."),
    )
    .await;
    let (method, link): (Option<String>, Option<Uuid>) = sqlx::query_as(
        "SELECT auth_method, signed_request_id FROM deployment_events WHERE operation_id = $1 AND outcome = 'requested'",
    )
    .bind(operation)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!((method.as_deref(), link), (Some("passkey"), Some(id)));
    assert_eq!(latest_outcome(pool, operation).await, "rejected");
}

/// The real handler: an unsigned switch writes nothing; a stale signed one is
/// refused before any AWS call and answered `rejected`, linked to its proof.
async fn the_switch_handler_records_only_signed_switches(pool: &PgPool) {
    let state = test_state(pool, "/nonexistent");
    let f = fixture(pool, "running").await;
    let path = format!("/resources/{}/deployments/{}/switch", f.app, f.target);
    let id = signed_request(pool, f.user, "POST", &path).await;
    let call = |auth| {
        crate::app_deployments::switch::switch_handler(
            axum::extract::State(state.clone()),
            axum::Extension(auth),
            axum::extract::Path((f.app, f.target)),
            axum::Json(switch_request(Some(Uuid::new_v4()))),
        )
    };
    let unsigned = call(crate::AuthContext::session(f.user)).await;
    assert_eq!(unsigned.into_response().status(), StatusCode::FORBIDDEN);
    let recorded = |app| {
        sqlx::query_as::<_, (String, Option<Uuid>, Option<String>)>(
            "SELECT outcome, signed_request_id, error FROM deployment_events
             WHERE app_id = $1 ORDER BY created_at, id",
        )
        .bind(app)
        .fetch_all(pool)
    };
    assert!(recorded(f.app).await.unwrap().is_empty());

    let stale = call(signed(f.user, Some(id))).await;
    assert_eq!(stale.into_response().status(), StatusCode::CONFLICT);
    let stale_message = "The live deployment changed; review and confirm again.";
    assert_eq!(
        recorded(f.app).await.unwrap(),
        [
            ("requested".to_string(), Some(id), None),
            (
                "rejected".to_string(),
                None,
                Some(stale_message.to_string())
            ),
        ]
    );
}

async fn interrupted_operations_are_settled_by_reconciliation(pool: &PgPool) {
    let f = fixture(pool, "running").await;
    let auth = crate::AuthContext::session(f.user);
    let request = |operation, target| NewOperation {
        org_id: f.org,
        app_id: f.app,
        operation,
        actor: &auth,
        previous_deployment_id: None,
        target_deployment_id: target,
        signed_request_id: None,
    };
    let moved = events::begin(pool, request(Operation::Switch, Some(f.target)))
        .await
        .unwrap();
    let unmoved = events::begin(pool, request(Operation::Switch, Some(Uuid::new_v4())))
        .await
        .unwrap();
    let released = events::begin(pool, request(Operation::Switch, Some(f.target)))
        .await
        .unwrap();
    let destroying = deployment(pool, f.org, f.app, "destroying", Some("i-gone")).await;
    let in_flight = events::begin(
        pool,
        request(Operation::DeploymentDestroy, Some(destroying)),
    )
    .await
    .unwrap();
    let current = events::begin(pool, request(Operation::Switch, Some(f.target)))
        .await
        .unwrap();
    // A restart: these belong to a process that is gone; one more was released
    // by this process after a failure that may have moved the address.
    sqlx::query("UPDATE deployment_events SET owner_process_id = gen_random_uuid() WHERE operation_id = ANY($1)")
        .bind(vec![moved, unmoved, in_flight]).execute(pool).await.unwrap();
    events::release(pool, released).await;
    // Live repair confirmed the target holds the EIP.
    events::settle_switches(pool, f.app, Some(f.target)).await;
    events::settle_interrupted(pool).await.unwrap();
    assert_eq!(latest_outcome(pool, moved).await, "observed");
    assert_eq!(latest_outcome(pool, released).await, "observed");
    assert_eq!(latest_outcome(pool, unmoved).await, "failed");
    assert_eq!(
        latest_outcome(pool, in_flight).await,
        "requested",
        "still being destroyed"
    );
    assert_eq!(
        latest_outcome(pool, current).await,
        "requested",
        "this process finishes its own"
    );
    // Settling is idempotent.
    events::settle_switches(pool, f.app, Some(f.target)).await;
    events::settle_interrupted(pool).await.unwrap();
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM deployment_events WHERE operation_id = $1")
            .bind(moved)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(rows, 2);
}

async fn destroy_records_the_operation_with_its_claim(pool: &PgPool) {
    let f = fixture(pool, "running").await;
    let candidate = deployment(pool, f.org, f.app, "running", Some("i-candidate")).await;
    let backend = FakeBackend::holding(None);
    let auth = crate::AuthContext::session(f.user);
    let (target, operation) = destroy::begin_destroy(pool, &backend, &auth, f.app, candidate)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(target.deployment_id, candidate);
    let (method, recorded_target): (Option<String>, Option<Uuid>) = sqlx::query_as(
        "SELECT auth_method, target_deployment_id FROM deployment_events WHERE operation_id = $1",
    )
    .bind(operation)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        (method.as_deref(), recorded_target),
        (Some("session"), Some(candidate))
    );
    // Another app's deployment ID is refused before anything is recorded.
    let foreign = fixture(pool, "running").await;
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deployment_events")
        .fetch_one(pool)
        .await
        .unwrap();
    assert!(matches!(
        destroy::begin_destroy(pool, &backend, &auth, f.app, foreign.target).await,
        Err(DestroyError::NotFound { .. })
    ));
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deployment_events")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(before, after);
}
