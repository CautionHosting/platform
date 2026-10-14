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
    let state = test_state(&pool, "/nonexistent");
    switch_requires_the_callers_pending_signed_request(&pool).await;
    rejected_switches_keep_their_signed_request_link(&pool).await;
    the_switch_handler_records_only_signed_switches(&pool).await;
    interrupted_operations_are_settled_by_reconciliation(&pool).await;
    destroy_records_the_operation_with_its_claim(&pool).await;
    summaries_count_candidates_like_admission(&pool).await;
    app_responses_carry_the_summary(&state).await;
    deployment_views_carry_retained_and_cost(&state).await;
    history_is_tenant_scoped_and_paged(&pool).await;
    history_never_shows_another_apps_deployment(&pool).await;
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

async fn summaries_count_candidates_like_admission(pool: &PgPool) {
    let f = fixture(pool, "running").await; // target = live
    let live = f.target;
    set_live(pool, f.app, live).await;
    sqlx::query("UPDATE compute_resources SET state = 'running' WHERE id = $1")
        .bind(f.app)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("UPDATE app_deployments SET commit_sha = 'ff43fef0' WHERE id = $1")
        .bind(live)
        .execute(pool)
        .await
        .unwrap();
    deployment(pool, f.org, f.app, "running", Some("i-b")).await;
    let cleaned = deployment(pool, f.org, f.app, "failed", None).await;
    set_outcome(pool, cleaned, Some("provisioning"), true).await;
    let uncleaned = deployment(pool, f.org, f.app, "failed", Some("i-c")).await;
    set_outcome(pool, uncleaned, Some("provisioning"), false).await;
    let summaries = crate::app_deployments::summary::summaries(pool, &[f.app])
        .await
        .unwrap();
    let summary = &summaries[&f.app];
    assert_eq!(summary.summary_state, "running");
    assert!(summary.active);
    assert_eq!(summary.live_commit_sha.as_deref(), Some("ff43fef0"));
    // Same predicate as admission::reserve: running B and uncleaned C count; the cleaned failure does not.
    assert_eq!(summary.candidates, Some(2));

    // No live deployment: one unselected Running deployment is `starting` (the reconciler
    // activates it); two are never guessed between and are `unavailable`.
    let app = deployments_app(pool, f.org).await;
    assert_eq!(summary_of(pool, app).await, "initialized");
    deployment(pool, f.org, app, "running", Some("i-one")).await;
    assert_eq!(summary_of(pool, app).await, "starting");
    deployment(pool, f.org, app, "running", Some("i-two")).await;
    assert_eq!(summary_of(pool, app).await, "unavailable");
}

async fn summary_of(pool: &PgPool, app: Uuid) -> String {
    crate::app_deployments::summary::summaries(pool, &[app])
        .await
        .unwrap()[&app]
        .summary_state
        .clone()
}

/// The summary fields reach `GET /resources` and `GET /resources/{id}`; a Legacy app keeps its state.
async fn app_responses_carry_the_summary(state: &Arc<AppState>) {
    use crate::resources::{get_resource, list_resources};
    use axum::extract::{Path, State};

    let pool = &state.db;
    let f = fixture(pool, "running").await;
    set_live(pool, f.app, f.target).await;
    sqlx::query("UPDATE app_deployments SET commit_sha = 'ff43fef0' WHERE id = $1")
        .bind(f.target)
        .execute(pool)
        .await
        .unwrap();
    deployment(pool, f.org, f.app, "running", Some("i-b")).await;
    let legacy = deployments_app(pool, f.org).await;
    sqlx::query(
        "UPDATE compute_resources
         SET lifecycle = 'legacy', configuration = '{\"commit_sha\": \"04fa2381\"}' WHERE id = $1",
    )
    .bind(legacy)
    .execute(pool)
    .await
    .unwrap();
    let auth = || axum::Extension(crate::AuthContext::session(f.user));

    let limit = crate::app_deployments::max_candidates_per_app();
    let check = |view: &serde_json::Value| {
        assert_eq!(view["summary_state"], "running");
        assert_eq!(view["active"], true);
        assert_eq!(view["live_commit_sha"], "ff43fef0");
        assert_eq!(view["candidates"], 1);
        assert_eq!(view["candidate_limit"], limit);
    };
    check(
        &get_resource(State(state.clone()), auth(), Path(f.app))
            .await
            .unwrap()
            .0,
    );
    let listed = list_resources(State(state.clone()), auth())
        .await
        .unwrap()
        .0;
    check(
        listed
            .iter()
            .find(|view| view["id"] == f.app.to_string())
            .unwrap(),
    );
    for view in [
        get_resource(State(state.clone()), auth(), Path(legacy))
            .await
            .unwrap()
            .0,
        listed
            .iter()
            .find(|view| view["id"] == legacy.to_string())
            .unwrap()
            .clone(),
    ] {
        assert_eq!(
            view["summary_state"], "initialized",
            "Legacy keeps its state"
        );
        assert_eq!(view["active"], true);
        assert_eq!(view["live_commit_sha"], "04fa2381");
        assert!(view["candidates"].is_null() && view["candidate_limit"].is_null());
    }
}

/// `DeploymentView` carries retained, region, enclave size, cost and cleanup/destroy times;
/// `?retained=1` returns only retained rows, and the default list stays unfiltered.
async fn deployment_views_carry_retained_and_cost(state: &Arc<AppState>) {
    use crate::app_deployments::handlers::{ListQuery, list_handler, query_rows};
    use axum::extract::{Path, Query, State};

    let pool = &state.db;
    let f = fixture(pool, "running").await;
    sqlx::query(
        "UPDATE app_deployments SET instance_id = 'i-live', instance_type = 'm5.xlarge',
         configuration = '{\"cpus\": 2, \"memory_mb\": 4096}' WHERE id = $1",
    )
    .bind(f.target)
    .execute(pool)
    .await
    .unwrap();
    set_live(pool, f.app, f.target).await;
    let lost = deployment(pool, f.org, f.app, "failed", Some("i-lost")).await;
    set_outcome(pool, lost, Some("runtime_lost"), false).await;
    let gone = deployment(pool, f.org, f.app, "failed", None).await;
    set_outcome(pool, gone, Some("provisioning"), true).await;

    let views: HashMap<Uuid, serde_json::Value> = query_rows(pool, f.user, Some(f.app), None)
        .await
        .unwrap()
        .into_iter()
        .map(|mut row| {
            row.hourly_usd = Some(0.192); // as `load_views` derives it from the pricing config
            (row.id, serde_json::to_value(row.into_view(None)).unwrap())
        })
        .collect();
    let live = &views[&f.target];
    assert_eq!(live["retained"], true);
    assert_eq!(live["region"], "us-east-1");
    assert_eq!(
        (
            live["enclave_cpus"].as_u64(),
            live["enclave_memory_mb"].as_u64()
        ),
        (Some(2), Some(4096))
    );
    assert_eq!(live["estimated_monthly_usd"], 140.16);
    assert!(live["cleaned_up_at"].is_null() && live["destroyed_at"].is_null());
    // Lost: keeps its slot, bills nothing. Cleaned up: not retained.
    assert_eq!(views[&lost]["retained"], true);
    assert!(views[&lost]["estimated_monthly_usd"].is_null());
    assert_eq!(views[&gone]["retained"], false);
    assert!(views[&gone]["estimated_monthly_usd"].is_null());
    assert!(!views[&gone]["cleaned_up_at"].is_null());

    let ids = |retained: Option<u8>| {
        let (state, auth) = (
            state.clone(),
            axum::Extension(crate::AuthContext::session(f.user)),
        );
        async move {
            let mut ids: Vec<Uuid> = list_handler(
                State(state),
                auth,
                Path(f.app),
                Query(ListQuery { retained }),
            )
            .await
            .unwrap()
            .0
            .iter()
            .map(|view| view.id)
            .collect();
            ids.sort();
            ids
        }
    };
    let mut every = vec![f.target, lost, gone];
    every.sort();
    let mut kept = vec![f.target, lost];
    kept.sort();
    assert_eq!(ids(None).await, every, "unfiltered by default");
    assert_eq!(ids(Some(1)).await, kept);
}

async fn history_is_tenant_scoped_and_paged(pool: &PgPool) {
    let f = fixture(pool, "running").await;
    let failed = deployment(pool, f.org, f.app, "failed", None).await;
    sqlx::query(
        "UPDATE app_deployments SET failed_at = NOW() - INTERVAL '1 hour',
             error = 'tofu apply failed', commit_sha = 'b6e8c92' WHERE id = $1",
    )
    .bind(failed)
    .execute(pool)
    .await
    .unwrap();
    let auth = crate::AuthContext::session(f.user);
    for _ in 0..3 {
        let operation = events::begin(
            pool,
            NewOperation {
                org_id: f.org,
                app_id: f.app,
                operation: Operation::DeploymentDestroy,
                actor: &auth,
                previous_deployment_id: None,
                target_deployment_id: Some(f.target),
                signed_request_id: None,
            },
        )
        .await
        .unwrap();
        events::finish(pool, operation, Outcome::Succeeded, None).await;
    }
    let page =
        |cursor| crate::app_deployments::history::history_page(pool, f.user, f.app, cursor, 2);
    let first = page(None).await.unwrap().unwrap();
    assert_eq!(first.entries.len(), 2);
    assert!(first.entries.iter().all(|entry| entry.kind == "operation"
        && entry.outcome == "succeeded"
        && entry.auth_method.as_deref() == Some("session")
        && entry.completed_at.is_some()));
    assert!(first.next.is_some());
    let second = page(first.next).await.unwrap().unwrap();
    assert_eq!(second.entries.len(), 2);
    let all: std::collections::HashSet<Uuid> = first
        .entries
        .iter()
        .chain(&second.entries)
        .map(|entry| entry.id)
        .collect();
    assert_eq!(all.len(), 4, "pages neither overlap nor skip");
    assert_eq!(second.entries[1].kind, "attempt");
    assert_eq!(
        second.entries[1].error.as_deref(),
        Some("tofu apply failed")
    );
    assert!(second.next.is_none());
    // A non-member sees nothing, not even that the app exists.
    let stranger = member(pool, organization(pool).await).await;
    assert!(
        crate::app_deployments::history::history_page(pool, stranger, f.app, None, 20)
            .await
            .unwrap()
            .is_none()
    );
}

async fn history_never_shows_another_apps_deployment(pool: &PgPool) {
    let f = fixture(pool, "running").await;
    let other = fixture(pool, "running").await;
    sqlx::query(
        "UPDATE app_deployments SET commit_sha = 'secret0', commit_subject = 'other tenant' WHERE id = $1",
    )
    .bind(other.target)
    .execute(pool)
    .await
    .unwrap();
    // Even a row naming a foreign deployment (none is written today) reveals nothing about it:
    // neither its commit nor its ID.
    let auth = crate::AuthContext::session(f.user);
    let foreign = events::begin(
        pool,
        NewOperation {
            org_id: f.org,
            app_id: f.app,
            operation: Operation::Switch,
            actor: &auth,
            previous_deployment_id: Some(other.target),
            target_deployment_id: Some(other.target),
            signed_request_id: None,
        },
    )
    .await
    .unwrap();
    let own = events::begin(
        pool,
        NewOperation {
            org_id: f.org,
            app_id: f.app,
            operation: Operation::DeploymentDestroy,
            actor: &auth,
            previous_deployment_id: None,
            target_deployment_id: Some(f.target),
            signed_request_id: None,
        },
    )
    .await
    .unwrap();
    let page = crate::app_deployments::history::history_page(pool, f.user, f.app, None, 20)
        .await
        .unwrap()
        .unwrap();
    let entry = |id: Uuid| page.entries.iter().find(|entry| entry.id == id).unwrap();
    let foreign = entry(foreign);
    assert!(foreign.target_deployment_id.is_none() && foreign.previous_deployment_id.is_none());
    assert!(foreign.commit_sha.is_none() && foreign.commit_subject.is_none());
    // The join is not simply dropped: an own-app target is named.
    assert_eq!(entry(own).target_deployment_id, Some(f.target));
}
