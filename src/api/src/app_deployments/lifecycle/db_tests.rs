// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Database-backed concurrency regressions for [`complete_running`], the
//! deployment switch and destruction: run
//! `bash tests/e2e/test_app_deployments_db.sh` (isolated PostgreSQL).

use super::*;
use crate::app_deployments::admission::ReserveError;
use crate::app_deployments::destroy::{
    self, DestroyAllError, DestroyBackend, DestroyError, DestroyRejection, begin_destroy,
    complete_destroy_with, destroy_all_for_app_with,
};
use crate::app_deployments::switch::{
    SwitchError, SwitchRejection, SwitchRequest, SwitchResponse, commit_switch,
};
use crate::managed_dns::BeginTerminationError;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinHandle;

const EIP: &str = "198.51.100.7";

async fn test_pool() -> PgPool {
    let url = std::env::var("APP_DEPLOYMENTS_TEST_DATABASE_URL")
        .expect("use the isolated app deployments database test runner");
    let parsed = url::Url::parse(&url).unwrap();
    assert_eq!(parsed.host_str(), Some("127.0.0.1"));
    assert_eq!(parsed.path(), "/caution_app_deployments_test");
    PgPool::connect(&url).await.unwrap()
}

#[tokio::test]
#[ignore = "run bash tests/e2e/test_app_deployments_db.sh (isolated PostgreSQL)"]
async fn complete_running_concurrency() {
    let pool = test_pool().await;

    first_running_deployment_goes_live(&pool).await;
    running_deployment_stays_candidate_while_another_is_live(&pool).await;
    suspended_app_rejects_before_running(&pool).await;
    failed_address_move_keeps_running_without_pointer(&pool).await;
    for rival in [Rival::TerminateApp, Rival::DestroyTarget, Rival::Switch] {
        rival_wins_between_running_and_activation(&pool, rival).await;
    }
    deployment_destruction_waits_and_sees_the_live_target(&pool).await;
    app_destruction_waits_then_tears_down(&pool).await;
    interrupted_activation_keeps_running_for_reconciliation(&pool).await;
    pool.close().await;
}

/// The EC2 response to the EIP move, controlled by the test.
#[derive(Clone, Copy, PartialEq)]
enum Response {
    Move,
    /// Moves, then waits for `release` with the activation transaction open.
    MoveAndPause,
    Fail,
}

struct ControlledMover {
    response: Response,
    calls: AtomicUsize,
    /// The `expected_holder` of each move.
    expected: Mutex<Vec<Option<String>>>,
    /// Instance holding the EIP.
    holder: Mutex<Option<String>>,
    reached: Notify,
    release: Semaphore,
}

impl ControlledMover {
    fn new(response: Response) -> Arc<Self> {
        Self::holding(response, None)
    }

    fn holding(response: Response, holder: Option<&str>) -> Arc<Self> {
        Arc::new(Self {
            response,
            calls: AtomicUsize::new(0),
            expected: Mutex::new(Vec::new()),
            holder: Mutex::new(holder.map(str::to_string)),
            reached: Notify::new(),
            release: Semaphore::new(0),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn expected(&self) -> Vec<Option<String>> {
        self.expected.lock().unwrap().clone()
    }

    fn holder(&self) -> Option<String> {
        self.holder.lock().unwrap().clone()
    }
}

impl AppAddressMover for ControlledMover {
    /// Mirrors `Ec2Client::move_app_address`: succeeds at the target, refuses
    /// any holder but the expected one.
    async fn move_address(
        &self,
        _resource_id: &str,
        target: &str,
        expected_holder: Option<&str>,
    ) -> Result<String, ec2::MoveAppAddressError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.expected
            .lock()
            .unwrap()
            .push(expected_holder.map(str::to_string));
        let holder = self.holder();
        if self.response == Response::Fail
            || (holder.as_deref() != Some(target) && holder.as_deref() != expected_holder)
        {
            return Err(ec2::MoveAppAddressError::HolderMismatch {
                expected: expected_holder.map(str::to_string),
                actual: holder.or(Some("i-elsewhere".to_string())),
                location: std::panic::Location::caller(),
            });
        }
        *self.holder.lock().unwrap() = Some(target.to_string());
        if self.response == Response::MoveAndPause {
            self.reached.notify_one();
            self.release.acquire().await.unwrap().forget();
        }
        Ok(EIP.to_string())
    }

    async fn describe_address(
        &self,
        _resource_id: &str,
    ) -> Result<ec2::AppAddress, ec2::DescribeAppAddressError> {
        Ok(ec2::AppAddress {
            allocation_id: "eipalloc-test".to_string(),
            public_ip: EIP.to_string(),
            instance_id: self.holder(),
        })
    }
}

/// The EIP holder and OpenTofu outcome a destroy sees, controlled by the test.
struct FakeBackend {
    holder: Option<String>,
    fail: AtomicBool,
    /// Deployments whose state destroy ran, in order.
    destroyed: Mutex<Vec<Uuid>>,
}

impl FakeBackend {
    fn holding(holder: Option<&str>) -> Self {
        Self {
            holder: holder.map(str::to_string),
            fail: AtomicBool::new(false),
            destroyed: Mutex::new(Vec::new()),
        }
    }

    fn destroyed(&self) -> Vec<Uuid> {
        self.destroyed.lock().unwrap().clone()
    }
}

impl DestroyBackend for FakeBackend {
    async fn address_holder(
        &self,
        _app_id: Uuid,
        _region: &str,
    ) -> Result<Option<String>, ec2::DescribeAppAddressError> {
        Ok(self.holder.clone())
    }

    async fn destroy_state(
        &self,
        _org_id: Uuid,
        _app_id: Uuid,
        deployment_id: Uuid,
        _region: &str,
    ) -> Result<(), deployment::DestroyDeploymentStateError> {
        self.destroyed.lock().unwrap().push(deployment_id);
        if self.fail.load(Ordering::SeqCst) {
            return Err(deployment::DestroyDeploymentStateError::TofuDestroy {
                location: std::panic::Location::caller(),
                source: "tofu destroy failed".into(),
            });
        }
        Ok(())
    }
}

/// A concurrent operation that commits under the app lock, as switch and
/// destruction do.
#[derive(Clone, Copy, Debug)]
enum Rival {
    TerminateApp,
    DestroyTarget,
    Switch,
}

#[derive(Clone, Copy)]
struct Fixture {
    org: Uuid,
    app: Uuid,
    /// An org member, allowed to switch.
    user: Uuid,
    target: Uuid,
}

/// A deployments app whose first push recorded its region.
async fn fixture(pool: &PgPool, target_status: &str) -> Fixture {
    let org = organization(pool).await;
    let app = deployments_app(pool, org).await;
    sqlx::query("UPDATE compute_resources SET region = 'us-east-1' WHERE id = $1")
        .bind(app)
        .execute(pool)
        .await
        .unwrap();
    let user = member(pool, org).await;
    let target = deployment(pool, org, app, target_status, None).await;
    Fixture {
        org,
        app,
        user,
        target,
    }
}

/// An organization with an active AWS provider account.
async fn organization(pool: &PgPool) -> Uuid {
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations(name) VALUES ('app deployments test') RETURNING id",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO provider_accounts(organization_id, provider_id, external_account_id, account_name)
         SELECT $1, id, '123456789012', 'test' FROM providers WHERE provider_type = 'aws'",
    )
    .bind(org)
    .execute(pool)
    .await
    .unwrap();
    org
}

async fn deployments_app(pool: &PgPool, org: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO compute_resources
             (organization_id, provider_account_id, resource_type_id, provider_resource_id,
              resource_name, state, lifecycle)
         SELECT $1, pa.id, rt.id, $2, 'bg-' || $2, 'initialized', 'deployments'
         FROM provider_accounts pa, resource_types rt
         WHERE pa.organization_id = $1 AND rt.type_code = 'ec2-instance'
         LIMIT 1
         RETURNING id",
    )
    .bind(org)
    .bind(Uuid::new_v4().to_string())
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn deployment(
    pool: &PgPool,
    org: Uuid,
    app: Uuid,
    status: &str,
    instance_id: Option<&str>,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO app_deployments
             (app_id, organization_id, status, owner_process_id, instance_id, region, state_key)
         VALUES ($1, $2, $3, $4, $5, 'us-east-1', 'state-key')
         RETURNING id",
    )
    .bind(app)
    .bind(org)
    .bind(status)
    .bind(*PROCESS_ID)
    .bind(instance_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

fn running(id: Uuid) -> RunningDeployment {
    RunningDeployment {
        id,
        instance_id: format!("i-{}", &id.simple().to_string()[..12]),
        instance_type: Some("m5.xlarge".to_string()),
        region: "us-east-1".to_string(),
        configuration: serde_json::json!({ "commit_sha": "0123abcd" }),
    }
}

fn spawn_activation(
    pool: &PgPool,
    mover: &Arc<ControlledMover>,
    app: Uuid,
    deployment: RunningDeployment,
) -> JoinHandle<Result<Activation, CompleteRunningError>> {
    let (pool, mover) = (pool.clone(), mover.clone());
    tokio::spawn(async move { complete_running_with(&pool, true, &*mover, app, &deployment).await })
}

struct AppRow {
    live: Option<Uuid>,
    state: String,
    public_ip: Option<String>,
    region: Option<String>,
    provider_resource_id: String,
    dns_status: String,
    commit_sha: Option<String>,
}

async fn app_row(pool: &PgPool, app: Uuid) -> AppRow {
    let (live, state, public_ip, region, provider_resource_id, dns_status, commit_sha) =
        sqlx::query_as(
            "SELECT live_deployment_id, state::text, public_ip, region, provider_resource_id,
                    dns_status, configuration->>'commit_sha'
             FROM compute_resources WHERE id = $1",
        )
        .bind(app)
        .fetch_one(pool)
        .await
        .unwrap();
    AppRow {
        live,
        state,
        public_ip,
        region,
        provider_resource_id,
        dns_status,
        commit_sha,
    }
}

/// `(status, activated, cleaned up)` of a deployment.
async fn deployment_row(pool: &PgPool, id: Uuid) -> (String, bool, bool) {
    sqlx::query_as(
        "SELECT status, activated_at IS NOT NULL, cleaned_up_at IS NOT NULL
         FROM app_deployments WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn hold_app_lock(pool: &PgPool, app: Uuid) -> Transaction<'static, Postgres> {
    let mut tx = pool.begin().await.unwrap();
    lock_app_operations(&mut tx, app).await.unwrap();
    tx
}

/// Waits until `count` sessions of this database wait on a lock (the app
/// advisory lock or a row lock).
async fn wait_for_lock_waiters(pool: &PgPool, count: i64) {
    for _ in 0..500 {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_stat_activity
             WHERE datname = current_database() AND wait_event_type = 'Lock'",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        if waiting >= count {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("expected {count} lock waiters");
}

fn switch_request(expected_live_deployment_id: Option<Uuid>) -> SwitchRequest {
    SwitchRequest {
        expected_live_deployment_id,
        acknowledged_verification: true,
    }
}

/// The switch after its unlocked validation and health check.
fn spawn_switch(
    pool: &PgPool,
    mover: &Arc<ControlledMover>,
    f: &Fixture,
    target: Uuid,
    expected: Option<Uuid>,
) -> JoinHandle<Result<SwitchResponse, SwitchError>> {
    let (pool, mover, user, app) = (pool.clone(), mover.clone(), f.user, f.app);
    tokio::spawn(async move {
        commit_switch(
            &pool,
            true,
            &*mover,
            user,
            app,
            target,
            &switch_request(expected),
        )
        .await
    })
}

async fn run_rival(pool: PgPool, f: Fixture, other: Uuid, kind: Rival) {
    match kind {
        // The teardown entry point, which takes the app lock itself.
        Rival::TerminateApp => {
            managed_dns::begin_termination(&pool, f.app).await.unwrap();
        }
        // The locked phase of deployment destruction.
        Rival::DestroyTarget => {
            let backend = FakeBackend::holding(None);
            begin_destroy(&pool, &backend, f.user, f.app, f.target)
                .await
                .unwrap()
                .unwrap();
        }
        // The real switch, which takes the app lock itself.
        Rival::Switch => {
            let mover = ControlledMover::new(Response::Move);
            let request = switch_request(None);
            let switched = commit_switch(&pool, true, &*mover, f.user, f.app, other, &request)
                .await
                .unwrap();
            assert_eq!(switched.live_deployment_id, other);
        }
    }
}

async fn first_running_deployment_goes_live(pool: &PgPool) {
    let f = fixture(pool, "provisioning").await;
    let mover = ControlledMover::new(Response::Move);
    let deployment = running(f.target);
    let activation = complete_running_with(pool, true, &*mover, f.app, &deployment)
        .await
        .unwrap();

    assert_eq!(activation.role, Role::Live);
    assert_eq!(activation.live_deployment_id, Some(f.target));
    assert_eq!(activation.eip_public_ip.as_deref(), Some(EIP));
    assert_eq!(activation.dns.unwrap().status, "publishing");
    assert_eq!(mover.calls(), 1);
    // Activation never takes the EIP from a holder.
    assert_eq!(mover.expected(), vec![None]);
    assert_eq!(mover.holder(), Some(deployment.instance_id.clone()));
    let app = app_row(pool, f.app).await;
    assert_eq!(app.live, Some(f.target));
    assert_eq!(app.state, "running");
    assert_eq!(app.public_ip.as_deref(), Some(EIP));
    assert_eq!(app.region.as_deref(), Some("us-east-1"));
    assert_eq!(app.provider_resource_id, deployment.instance_id);
    assert_eq!(app.dns_status, "publishing");
    assert_eq!(app.commit_sha.as_deref(), Some("0123abcd"));
    assert_eq!(
        deployment_row(pool, f.target).await,
        ("running".to_string(), true, false)
    );
}

async fn running_deployment_stays_candidate_while_another_is_live(pool: &PgPool) {
    let f = fixture(pool, "provisioning").await;
    let live = deployment(pool, f.org, f.app, "running", Some("i-live")).await;
    sqlx::query(
        "UPDATE compute_resources SET live_deployment_id = $2, state = 'running' WHERE id = $1",
    )
    .bind(f.app)
    .bind(live)
    .execute(pool)
    .await
    .unwrap();
    let mover = ControlledMover::new(Response::Move);
    let activation = complete_running_with(pool, true, &*mover, f.app, &running(f.target))
        .await
        .unwrap();

    assert_eq!(activation.role, Role::Candidate);
    assert_eq!(activation.live_deployment_id, Some(live));
    assert!(activation.eip_public_ip.is_none());
    assert_eq!(mover.calls(), 0);
    assert_eq!(app_row(pool, f.app).await.live, Some(live));
    assert_eq!(
        deployment_row(pool, f.target).await,
        ("running".to_string(), false, false)
    );
}

async fn suspended_app_rejects_before_running(pool: &PgPool) {
    let f = fixture(pool, "provisioning").await;
    sqlx::query("UPDATE compute_resources SET state = 'stopped' WHERE id = $1")
        .bind(f.app)
        .execute(pool)
        .await
        .unwrap();
    let mover = ControlledMover::new(Response::Move);
    let error = complete_running_with(pool, true, &*mover, f.app, &running(f.target))
        .await
        .err()
        .unwrap();

    assert!(
        matches!(error, CompleteRunningError::AppNotActive { ref state, .. } if state == "stopped")
    );
    assert_eq!(mover.calls(), 0);
    // Still unfinished, so failure cleanup (`fail_attempt`) destroys it.
    assert_eq!(
        deployment_row(pool, f.target).await,
        ("provisioning".to_string(), false, false)
    );
}

async fn failed_address_move_keeps_running_without_pointer(pool: &PgPool) {
    let f = fixture(pool, "provisioning").await;
    let mover = ControlledMover::new(Response::Fail);
    let error = complete_running_with(pool, true, &*mover, f.app, &running(f.target))
        .await
        .err()
        .unwrap();

    assert!(matches!(error, CompleteRunningError::AttachAddress { .. }));
    assert_eq!(mover.calls(), 1);
    let app = app_row(pool, f.app).await;
    assert_eq!(app.live, None);
    assert_eq!(app.state, "initialized");
    assert_eq!(app.public_ip, None);
    assert_eq!(
        deployment_row(pool, f.target).await,
        ("running".to_string(), false, false)
    );
}

/// Pauses activation between the Running commit and its second app lock: the
/// rival queues on the app lock behind the first transaction, so it commits
/// before activation reacquires the lock.
async fn rival_wins_between_running_and_activation(pool: &PgPool, kind: Rival) {
    let f = fixture(pool, "provisioning").await;
    let other = deployment(pool, f.org, f.app, "running", Some("i-other")).await;
    let mover = ControlledMover::new(Response::Move);

    let holder = hold_app_lock(pool, f.app).await;
    let activation = spawn_activation(pool, &mover, f.app, running(f.target));
    wait_for_lock_waiters(pool, 1).await;
    let rival = tokio::spawn(run_rival(pool.clone(), f, other, kind));
    wait_for_lock_waiters(pool, 2).await;
    holder.commit().await.unwrap();
    let result = activation.await.unwrap();
    rival.await.unwrap();

    assert_eq!(
        mover.calls(),
        0,
        "{kind:?}: activation must not move the EIP"
    );
    let app = app_row(pool, f.app).await;
    let (status, activated, _) = deployment_row(pool, f.target).await;
    assert!(!activated, "{kind:?}");
    match kind {
        Rival::TerminateApp => {
            assert!(matches!(
                result,
                Err(CompleteRunningError::AppNotActive { ref state, .. }) if state == "terminating"
            ));
            assert_eq!(app.live, None);
            assert_eq!(app.public_ip, None);
            assert_eq!(status, "running");
        }
        Rival::DestroyTarget => {
            assert!(matches!(
                result,
                Err(CompleteRunningError::OwnershipLost { .. })
            ));
            assert_eq!(app.live, None);
            assert_eq!(app.public_ip, None);
            assert_eq!(status, "destroying");
        }
        Rival::Switch => {
            let activation = result.unwrap();
            assert_eq!(activation.role, Role::Candidate);
            assert_eq!(activation.live_deployment_id, Some(other));
            assert_eq!(app.live, Some(other), "the switch's selection is kept");
            assert_eq!(app.public_ip.as_deref(), Some(EIP));
            assert_eq!(app.provider_resource_id, "i-other");
            assert_eq!(status, "running");
        }
    }
}

async fn deployment_destruction_waits_and_sees_the_live_target(pool: &PgPool) {
    let f = fixture(pool, "provisioning").await;
    let mover = ControlledMover::new(Response::MoveAndPause);
    let activation = spawn_activation(pool, &mover, f.app, running(f.target));
    mover.reached.notified().await;

    // Deployment destruction takes the app lock, then reads the live pointer.
    let destruction = {
        let pool = pool.clone();
        tokio::spawn(async move {
            let backend = FakeBackend::holding(None);
            begin_destroy(&pool, &backend, f.user, f.app, f.target).await
        })
    };
    wait_for_lock_waiters(pool, 1).await;
    assert!(!destruction.is_finished());
    mover.release.add_permits(1);

    assert_eq!(activation.await.unwrap().unwrap().role, Role::Live);
    // The committed pointer names the target, so destruction rejects it.
    assert!(matches!(
        destruction.await.unwrap(),
        Err(DestroyError::Rejected {
            rejection: DestroyRejection::Live,
            ..
        })
    ));
    assert_eq!(
        deployment_row(pool, f.target).await,
        ("running".to_string(), true, false)
    );
}

async fn app_destruction_waits_then_tears_down(pool: &PgPool) {
    let f = fixture(pool, "provisioning").await;
    let mover = ControlledMover::new(Response::MoveAndPause);
    let activation = spawn_activation(pool, &mover, f.app, running(f.target));
    mover.reached.notified().await;

    let termination = {
        let pool = pool.clone();
        tokio::spawn(async move { managed_dns::begin_termination(&pool, f.app).await })
    };
    wait_for_lock_waiters(pool, 1).await;
    assert!(!termination.is_finished());
    mover.release.add_permits(1);

    assert_eq!(activation.await.unwrap().unwrap().role, Role::Live);
    termination.await.unwrap().unwrap();
    let app = app_row(pool, f.app).await;
    assert_eq!(app.state, "terminating");
    // Only app teardown clears the pointer.
    assert_eq!(app.live, Some(f.target));
}

async fn interrupted_activation_keeps_running_for_reconciliation(pool: &PgPool) {
    let f = fixture(pool, "provisioning").await;
    let deployment = running(f.target);
    let instance_id = deployment.instance_id.clone();
    let mover = ControlledMover::new(Response::MoveAndPause);
    let activation = spawn_activation(pool, &mover, f.app, deployment);
    mover.reached.notified().await;
    // The API dies after the EIP moved, before the second commit.
    activation.abort();
    assert!(matches!(activation.await, Err(error) if error.is_cancelled()));

    // The dropped transaction rolls back and frees the app lock.
    let tx = tokio::time::timeout(Duration::from_secs(10), hold_app_lock(pool, f.app))
        .await
        .expect("the interrupted activation released the app lock");
    tx.rollback().await.unwrap();

    // Durable Running, owned and not cleaned up: failure cleanup and the
    // abandoned-work sweep select only `building`/`provisioning`, so nothing
    // destroys it. Reconciliation sees its instance holding the EIP with no
    // live pointer and records it live (`LiveRepair::RecordLive`).
    assert_eq!(mover.holder(), Some(instance_id.clone()));
    assert_eq!(
        deployment_row(pool, f.target).await,
        ("running".to_string(), false, false)
    );
    let (owner, recorded_instance): (Option<Uuid>, Option<String>) =
        sqlx::query_as("SELECT owner_process_id, instance_id FROM app_deployments WHERE id = $1")
            .bind(f.target)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(owner, Some(*PROCESS_ID));
    assert_eq!(recorded_instance, Some(instance_id));
    let app = app_row(pool, f.app).await;
    assert_eq!(app.live, None);
    assert_eq!(app.state, "initialized");
    assert_eq!(app.public_ip, None);
}

#[tokio::test]
#[ignore = "run bash tests/e2e/test_app_deployments_db.sh (isolated PostgreSQL)"]
async fn switch_concurrency() {
    let pool = test_pool().await;

    first_switch_projects_the_app(&pool).await;
    stale_expectation_is_rejected(&pool).await;
    concurrent_switches_serialise(&pool).await;
    lost_live_runtime_switches_from_an_unassigned_address(&pool).await;
    pool.close().await;
}

/// `live` serves through the app EIP with published DNS.
async fn serve(pool: &PgPool, app: Uuid, live: Uuid) {
    sqlx::query(
        "UPDATE compute_resources
         SET live_deployment_id = $2, state = 'running', public_ip = $3, dns_status = 'ready'
         WHERE id = $1",
    )
    .bind(app)
    .bind(live)
    .bind(EIP)
    .execute(pool)
    .await
    .unwrap();
}

/// A Running deployment that is not live after a failed first activation.
async fn first_switch_projects_the_app(pool: &PgPool) {
    let f = fixture(pool, "running").await;
    sqlx::query(
        "UPDATE app_deployments SET instance_id = 'i-first',
                configuration = '{\"commit_sha\": \"0123abcd\"}'
         WHERE id = $1",
    )
    .bind(f.target)
    .execute(pool)
    .await
    .unwrap();
    let mover = ControlledMover::new(Response::Move);
    let switched = spawn_switch(pool, &mover, &f, f.target, None)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(switched.live_deployment_id, f.target);
    assert_eq!(switched.previous_live_deployment_id, None);
    assert_eq!(switched.stable_ip, EIP);
    // With nothing live, only an unassigned address may move.
    assert_eq!(mover.expected(), vec![None]);
    assert_eq!(mover.holder().as_deref(), Some("i-first"));
    let app = app_row(pool, f.app).await;
    assert_eq!(app.live, Some(f.target));
    assert_eq!(app.state, "running");
    assert_eq!(app.public_ip.as_deref(), Some(EIP));
    assert_eq!(app.region.as_deref(), Some("us-east-1"));
    assert_eq!(app.provider_resource_id, "i-first");
    assert_eq!(app.dns_status, "publishing");
    assert_eq!(app.commit_sha.as_deref(), Some("0123abcd"));
    assert_eq!(
        deployment_row(pool, f.target).await,
        ("running".to_string(), true, false)
    );

    // Selecting the live deployment again is a no-op.
    let again = spawn_switch(pool, &mover, &f, f.target, Some(f.target))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(again.previous_live_deployment_id, None);
    assert_eq!(mover.calls(), 1);
}

async fn stale_expectation_is_rejected(pool: &PgPool) {
    let f = fixture(pool, "running").await;
    let live = deployment(pool, f.org, f.app, "running", Some("i-live")).await;
    sqlx::query("UPDATE app_deployments SET instance_id = 'i-target' WHERE id = $1")
        .bind(f.target)
        .execute(pool)
        .await
        .unwrap();
    serve(pool, f.app, live).await;
    let mover = ControlledMover::holding(Response::Move, Some("i-live"));
    // Confirmed while nothing was live.
    let error = spawn_switch(pool, &mover, &f, f.target, None)
        .await
        .unwrap()
        .unwrap_err();

    assert!(matches!(
        error,
        SwitchError::Rejected {
            rejection: SwitchRejection::Stale,
            ..
        }
    ));
    assert_eq!(mover.calls(), 0);
    assert_eq!(mover.holder().as_deref(), Some("i-live"));
    assert_eq!(app_row(pool, f.app).await.live, Some(live));
}

/// Two switches confirmed against the same live deployment: the second waits
/// on the app lock, then fails its expectation.
async fn concurrent_switches_serialise(pool: &PgPool) {
    let f = fixture(pool, "running").await;
    let live = deployment(pool, f.org, f.app, "running", Some("i-live")).await;
    let rival = deployment(pool, f.org, f.app, "running", Some("i-rival")).await;
    sqlx::query("UPDATE app_deployments SET instance_id = 'i-target' WHERE id = $1")
        .bind(f.target)
        .execute(pool)
        .await
        .unwrap();
    serve(pool, f.app, live).await;
    let mover = ControlledMover::holding(Response::MoveAndPause, Some("i-live"));

    let first = spawn_switch(pool, &mover, &f, f.target, Some(live));
    mover.reached.notified().await;
    let second = spawn_switch(pool, &mover, &f, rival, Some(live));
    wait_for_lock_waiters(pool, 1).await;
    assert!(!second.is_finished());
    mover.release.add_permits(1);

    let switched = first.await.unwrap().unwrap();
    assert_eq!(switched.previous_live_deployment_id, Some(live));
    assert!(matches!(
        second.await.unwrap(),
        Err(SwitchError::Rejected {
            rejection: SwitchRejection::Stale,
            ..
        })
    ));
    assert_eq!(mover.calls(), 1);
    assert_eq!(mover.expected(), vec![Some("i-live".to_string())]);
    assert_eq!(mover.holder().as_deref(), Some("i-target"));
    let app = app_row(pool, f.app).await;
    assert_eq!(app.live, Some(f.target));
    assert_eq!(app.provider_resource_id, "i-target");
    // The stable EIP keeps its published record.
    assert_eq!(app.dns_status, "ready");
    // The previous live deployment is retained as a candidate.
    assert_eq!(
        deployment_row(pool, live).await,
        ("running".to_string(), false, false)
    );
}

/// Host failure: the live instance terminated and released the EIP.
async fn lost_live_runtime_switches_from_an_unassigned_address(pool: &PgPool) {
    let f = fixture(pool, "running").await;
    let live = deployment(pool, f.org, f.app, "running", Some("i-dead")).await;
    sqlx::query("UPDATE app_deployments SET instance_id = 'i-target' WHERE id = $1")
        .bind(f.target)
        .execute(pool)
        .await
        .unwrap();
    serve(pool, f.app, live).await;
    let mover = ControlledMover::new(Response::Move);

    // Until reconciliation confirms the loss, an unassigned EIP is unexpected.
    let error = spawn_switch(pool, &mover, &f, f.target, Some(live))
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(error, SwitchError::AssociationMismatch { .. }));
    assert_eq!(app_row(pool, f.app).await.live, Some(live));

    sqlx::query(
        "UPDATE app_deployments SET status = 'failed', failure_kind = 'runtime_lost'
         WHERE id = $1",
    )
    .bind(live)
    .execute(pool)
    .await
    .unwrap();
    let switched = spawn_switch(pool, &mover, &f, f.target, Some(live))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(switched.previous_live_deployment_id, Some(live));
    assert_eq!(mover.expected(), vec![Some("i-dead".to_string()), None]);
    assert_eq!(mover.holder().as_deref(), Some("i-target"));
    assert_eq!(app_row(pool, f.app).await.live, Some(f.target));
}

#[tokio::test]
#[ignore = "run bash tests/e2e/test_app_deployments_db.sh (isolated PostgreSQL)"]
async fn destruction() {
    let pool = test_pool().await;
    let state = test_state(&pool, "/nonexistent");

    live_deployment_is_never_destroyed(&state).await;
    active_operations_are_not_destroyed(&pool).await;
    failed_destroy_stays_metered_until_a_retry_succeeds(&state).await;
    app_destroy_waits_for_deployment_operations(&state).await;
    termination_serialises_with_reserve(&pool).await;
    app_teardown_destroys_every_deployment(&state).await;
    pool.close().await;
}

/// An instance ID unique to the deployment (meters are keyed by instance).
fn instance(deployment: Uuid) -> String {
    format!("i-{}", &deployment.simple().to_string()[..12])
}

async fn set_instance(pool: &PgPool, deployment: Uuid) -> String {
    let instance_id = instance(deployment);
    sqlx::query("UPDATE app_deployments SET instance_id = $2 WHERE id = $1")
        .bind(deployment)
        .bind(&instance_id)
        .execute(pool)
        .await
        .unwrap();
    instance_id
}

/// Starts metering the deployment's instance, as `complete_running` does.
async fn meter(pool: &PgPool, org: Uuid, deployment: Uuid, instance_id: &str) {
    sqlx::query(
        "INSERT INTO tracked_resources (resource_id, organization_id, provider, deployment_id)
         VALUES ($1, $2, 'aws', $3)",
    )
    .bind(instance_id)
    .bind(org)
    .bind(deployment)
    .execute(pool)
    .await
    .unwrap();
}

async fn metered(pool: &PgPool, instance_id: &str) -> bool {
    sqlx::query_scalar("SELECT status = 'running' FROM tracked_resources WHERE resource_id = $1")
        .bind(instance_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// `(status, cleaned up, destroyed)` of a deployment.
async fn destroy_row(pool: &PgPool, id: Uuid) -> (String, bool, bool) {
    sqlx::query_as(
        "SELECT status, cleaned_up_at IS NOT NULL, destroyed_at IS NOT NULL
         FROM app_deployments WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// The endpoint takes no force flag (the handler extracts none); `--force`
/// exists only on app destroy, which first takes the app to `terminating`.
async fn live_deployment_is_never_destroyed(state: &Arc<AppState>) {
    let pool = &state.db;
    let f = fixture(pool, "running").await;
    let live_instance = set_instance(pool, f.target).await;
    serve(pool, f.app, f.target).await;
    let backend = FakeBackend::holding(Some(&live_instance));

    // The real handler refuses before any AWS or OpenTofu call.
    let response = destroy::destroy_handler(
        axum::extract::State(state.clone()),
        axum::Extension(crate::AuthContext { user_id: f.user }),
        axum::extract::Path((f.app, f.target)),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    // Nor after its runtime was lost: a dead live instance stays selected.
    for (status, failure_kind) in [("running", None), ("failed", Some("runtime_lost"))] {
        sqlx::query("UPDATE app_deployments SET status = $2, failure_kind = $3 WHERE id = $1")
            .bind(f.target)
            .bind(status)
            .bind(failure_kind)
            .execute(pool)
            .await
            .unwrap();
        let result = begin_destroy(pool, &backend, f.user, f.app, f.target).await;
        assert!(
            matches!(
                result,
                Err(DestroyError::Rejected {
                    rejection: DestroyRejection::Live,
                    ..
                })
            ),
            "{status}"
        );
        assert_eq!(
            result.unwrap_err().into_response().status(),
            StatusCode::CONFLICT
        );
    }

    // After an interrupted switch the pointer lags: the EIP holder is kept.
    let holder = deployment(pool, f.org, f.app, "running", None).await;
    let holder_instance = set_instance(pool, holder).await;
    let backend = FakeBackend::holding(Some(&holder_instance));
    let error = begin_destroy(pool, &backend, f.user, f.app, holder)
        .await
        .unwrap_err();
    assert!(matches!(error, DestroyError::HoldsAddress { .. }));
    assert_eq!(error.into_response().status(), StatusCode::CONFLICT);

    assert_eq!(status(pool, f.target).await.as_deref(), Some("failed"));
    assert_eq!(status(pool, holder).await.as_deref(), Some("running"));
    assert!(backend.destroyed().is_empty());
    assert_eq!(app_row(pool, f.app).await.live, Some(f.target));
}

async fn active_operations_are_not_destroyed(pool: &PgPool) {
    for busy in ["reserved", "building", "provisioning", "destroying"] {
        let f = fixture(pool, busy).await;
        let backend = FakeBackend::holding(None);
        let result = begin_destroy(pool, &backend, f.user, f.app, f.target).await;
        assert!(
            matches!(
                result,
                Err(DestroyError::Rejected {
                    rejection: DestroyRejection::Busy,
                    ..
                })
            ),
            "{busy}"
        );
        assert_eq!(
            result.unwrap_err().into_response().status(),
            StatusCode::CONFLICT
        );
        assert_eq!(status(pool, f.target).await.as_deref(), Some(busy));
    }
}

async fn failed_destroy_stays_metered_until_a_retry_succeeds(state: &AppState) {
    let pool = &state.db;
    let f = fixture(pool, "running").await;
    let live = deployment(pool, f.org, f.app, "running", Some("i-live")).await;
    serve(pool, f.app, live).await;
    let instance_id = set_instance(pool, f.target).await;
    meter(pool, f.org, f.target, &instance_id).await;
    let backend = FakeBackend::holding(Some("i-live"));

    let outsider = member(pool, organization(pool).await).await;
    let error = begin_destroy(pool, &backend, outsider, f.app, f.target)
        .await
        .unwrap_err();
    assert!(matches!(error, DestroyError::NotFound { .. }));

    backend.fail.store(true, Ordering::SeqCst);
    let target = begin_destroy(pool, &backend, f.user, f.app, f.target)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status(pool, f.target).await.as_deref(), Some("destroying"));
    assert_eq!(target.instance_id.as_deref(), Some(instance_id.as_str()));
    complete_destroy_with(state, &backend, &target)
        .await
        .unwrap_err();
    // Still counted and billed: the instance may still run.
    assert_eq!(
        destroy_row(pool, f.target).await,
        ("failed".to_string(), false, false)
    );
    assert!(metered(pool, &instance_id).await);

    backend.fail.store(false, Ordering::SeqCst);
    let target = begin_destroy(pool, &backend, f.user, f.app, f.target)
        .await
        .unwrap()
        .unwrap();
    complete_destroy_with(state, &backend, &target)
        .await
        .unwrap();
    assert_eq!(
        destroy_row(pool, f.target).await,
        ("destroyed".to_string(), true, true)
    );
    assert!(!metered(pool, &instance_id).await);

    // Idempotent: nothing left to destroy.
    assert!(
        begin_destroy(pool, &backend, f.user, f.app, f.target)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(backend.destroyed(), vec![f.target, f.target]);
    assert_eq!(app_row(pool, f.app).await.live, Some(live));
}

/// Every app destroy path goes through `begin_termination`.
async fn app_destroy_waits_for_deployment_operations(state: &Arc<AppState>) {
    let pool = &state.db;
    let f = fixture(pool, "building").await;
    let live = deployment(pool, f.org, f.app, "running", Some("i-live")).await;
    serve(pool, f.app, live).await;
    for force in [false, true] {
        let response = crate::resources::delete_resource(
            axum::extract::State(state.clone()),
            axum::Extension(crate::AuthContext { user_id: f.user }),
            axum::extract::Path(f.app),
            axum::extract::Query(crate::resources::DeleteResourceQuery { force }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT, "force={force}");
    }
    assert_eq!(app_row(pool, f.app).await.state, "running");

    // A finished attempt no longer blocks.
    sqlx::query(
        "UPDATE app_deployments SET status = 'failed', cleaned_up_at = NOW() WHERE id = $1",
    )
    .bind(f.target)
    .execute(pool)
    .await
    .unwrap();
    managed_dns::begin_termination(pool, f.app).await.unwrap();
    assert_eq!(app_row(pool, f.app).await.state, "terminating");

    // An unexpired reservation blocks; an expired one does not.
    let f = fixture(pool, "reserved").await;
    for (expires_in, blocks) in [("30 minutes", true), ("-1 minute", false)] {
        sqlx::query(
            "UPDATE app_deployments SET reservation_expires_at = NOW() + $2::interval WHERE id = $1",
        )
        .bind(f.target)
        .bind(expires_in)
        .execute(pool)
        .await
        .unwrap();
        let result = managed_dns::begin_termination(pool, f.app).await;
        assert_eq!(
            matches!(result, Err(BeginTerminationError::Deploying { .. })),
            blocks,
            "{expires_in}"
        );
    }

    // The guard is gated on the lifecycle: Legacy is unaffected.
    let f = fixture(pool, "building").await;
    sqlx::query("UPDATE compute_resources SET lifecycle = 'legacy' WHERE id = $1")
        .bind(f.app)
        .execute(pool)
        .await
        .unwrap();
    managed_dns::begin_termination(pool, f.app).await.unwrap();
}

/// `begin_termination` and `reserve` serialise on the app lock.
async fn termination_serialises_with_reserve(pool: &PgPool) {
    let f = fixture(pool, "running").await;

    // A reservation committed while termination waits is seen: reserve's
    // critical section (app lock, app row, reservation) in one transaction.
    let mut reserving = hold_app_lock(pool, f.app).await;
    sqlx::query("SELECT 1 FROM compute_resources WHERE id = $1 FOR UPDATE")
        .bind(f.app)
        .execute(&mut *reserving)
        .await
        .unwrap();
    let reserved: Uuid = sqlx::query_scalar(
        "INSERT INTO app_deployments (app_id, organization_id, reservation_expires_at)
         VALUES ($1, $2, NOW() + INTERVAL '30 minutes')
         RETURNING id",
    )
    .bind(f.app)
    .bind(f.org)
    .fetch_one(&mut *reserving)
    .await
    .unwrap();
    let termination = {
        let pool = pool.clone();
        tokio::spawn(async move { managed_dns::begin_termination(&pool, f.app).await })
    };
    wait_for_lock_waiters(pool, 1).await;
    assert!(!termination.is_finished());
    reserving.commit().await.unwrap();
    assert!(matches!(
        termination.await.unwrap(),
        Err(BeginTerminationError::Deploying { .. })
    ));
    assert_eq!(app_row(pool, f.app).await.state, "initialized");

    // A reservation queued behind termination is refused.
    admission::release_reservation(pool, reserved, Some(f.app))
        .await
        .unwrap();
    let holder = hold_app_lock(pool, f.app).await;
    let termination = {
        let pool = pool.clone();
        tokio::spawn(async move { managed_dns::begin_termination(&pool, f.app).await })
    };
    wait_for_lock_waiters(pool, 1).await;
    let reservation = {
        let pool = pool.clone();
        tokio::spawn(async move { admission::reserve(&pool, f.org, f.app, f.user).await })
    };
    wait_for_lock_waiters(pool, 2).await;
    holder.commit().await.unwrap();
    termination.await.unwrap().unwrap();
    assert!(matches!(
        reservation.await.unwrap(),
        Err(ReserveError::NotPushable { ref state, .. }) if state == "terminating"
    ));
}

async fn app_teardown_destroys_every_deployment(state: &AppState) {
    let pool = &state.db;
    let f = fixture(pool, "running").await;
    let live = deployment(pool, f.org, f.app, "running", None).await;
    let live_instance = set_instance(pool, live).await;
    serve(pool, f.app, live).await;
    let candidate_instance = set_instance(pool, f.target).await;
    for (deployment, instance_id) in [(live, &live_instance), (f.target, &candidate_instance)] {
        meter(pool, f.org, deployment, instance_id).await;
    }
    let cleaned = deployment(pool, f.org, f.app, "failed", None).await;
    sqlx::query("UPDATE app_deployments SET cleaned_up_at = NOW() WHERE id = $1")
        .bind(cleaned)
        .execute(pool)
        .await
        .unwrap();
    let expired = deployment(pool, f.org, f.app, "reserved", None).await;
    sqlx::query(
        "UPDATE app_deployments SET reservation_expires_at = NOW() - INTERVAL '1 minute'
         WHERE id = $1",
    )
    .bind(expired)
    .execute(pool)
    .await
    .unwrap();
    managed_dns::begin_termination(pool, f.app).await.unwrap();

    // Every deployment is attempted, the live one included; a cleaned-up
    // failure has no state left.
    let backend = FakeBackend::holding(Some(&live_instance));
    backend.fail.store(true, Ordering::SeqCst);
    let error = destroy_all_for_app_with(state, &backend, f.org, f.app)
        .await
        .unwrap_err();
    assert!(matches!(error, DestroyAllError::Destroy { .. }));
    let mut attempted = backend.destroyed();
    attempted.sort();
    let mut expected = vec![live, f.target];
    expected.sort();
    assert_eq!(attempted, expected);
    assert_eq!(status(pool, expired).await, None);
    for id in [live, f.target] {
        assert_eq!(
            destroy_row(pool, id).await,
            ("failed".to_string(), false, false)
        );
    }
    // A failed teardown keeps them billed; a forced one stops every meter.
    assert!(metered(pool, &live_instance).await);
    assert!(metered(pool, &candidate_instance).await);
    destroy::stop_remaining_meters(state, f.app).await;
    assert!(!metered(pool, &live_instance).await);
    assert!(!metered(pool, &candidate_instance).await);

    backend.fail.store(false, Ordering::SeqCst);
    destroy_all_for_app_with(state, &backend, f.org, f.app)
        .await
        .unwrap();
    for id in [live, f.target, cleaned] {
        assert_eq!(
            destroy_row(pool, id).await,
            ("destroyed".to_string(), true, true)
        );
    }
    assert_eq!(backend.destroyed().len(), 4);

    // A build this process runs is never destroyed underneath OpenTofu.
    let building = deployment(pool, f.org, f.app, "building", None).await;
    let error = destroy_all_for_app_with(state, &backend, f.org, f.app)
        .await
        .unwrap_err();
    assert!(matches!(error, DestroyAllError::Busy { .. }));
    assert_eq!(status(pool, building).await.as_deref(), Some("building"));
}

/// `/deploy` takes the deployment ID from its body, so a failed request may
/// release or fail a deployment only as far as it proved it may.
#[tokio::test]
#[ignore = "run bash tests/e2e/test_app_deployments_db.sh (isolated PostgreSQL)"]
async fn deploy_error_recovery_touches_only_its_own_progress() {
    assert!(
        std::env::var("PLATFORM_GIT_SHA").is_ok(),
        "the runner sets PLATFORM_GIT_SHA so deploys get past the framework check"
    );
    let pool = test_pool().await;
    let data_dir = tempfile::TempDir::new().unwrap();
    let state = test_state(&pool, data_dir.path().to_str().unwrap());

    let victim_org = organization(&pool).await;
    let victim = member(&pool, victim_org).await;
    let org = organization(&pool).await;
    let user = member(&pool, org).await;
    sqlx::query(
        "INSERT INTO credit_ledger (organization_id, delta_cents, entry_type, description)
         VALUES ($1, 10000, 'code_redemption', 'app deployments test')",
    )
    .bind(org)
    .execute(&pool)
    .await
    .unwrap();

    // A non-member naming another org's reservation and in-flight attempt.
    let app = deployments_app(&pool, victim_org).await;
    let reserved = admission::reserve(&pool, victim_org, app, victim)
        .await
        .unwrap();
    let body = deploy(&state, user, victim_org, app, reserved).await;
    assert!(
        body.contains("User does not belong to this organization"),
        "{body}"
    );
    assert_eq!(status(&pool, reserved).await.as_deref(), Some("reserved"));
    let app = deployments_app(&pool, victim_org).await;
    let in_flight = building(&pool, victim_org, app).await;
    let body = deploy(&state, user, victim_org, app, in_flight).await;
    assert!(
        body.contains("User does not belong to this organization"),
        "{body}"
    );
    assert_eq!(status(&pool, in_flight).await.as_deref(), Some("building"));

    // A member replaying its own in-flight attempt loses the claim: the first
    // request keeps its deployment.
    let app = deployments_app(&pool, org).await;
    git_repo(data_dir.path(), app);
    let in_flight = building(&pool, org, app).await;
    let body = deploy(&state, user, org, app, in_flight).await;
    assert!(body.contains("reservation expired"), "{body}");
    assert_eq!(status(&pool, in_flight).await.as_deref(), Some("building"));

    // Another app's reservation is neither claimed nor released.
    let other_app = deployments_app(&pool, org).await;
    let foreign = admission::reserve(&pool, org, other_app, user)
        .await
        .unwrap();
    let app = deployments_app(&pool, org).await;
    git_repo(data_dir.path(), app);
    let body = deploy(&state, user, org, app, foreign).await;
    assert!(body.contains("reservation expired"), "{body}");
    assert_eq!(status(&pool, foreign).await.as_deref(), Some("reserved"));

    // Rejected before its claim (no repository): the app's own slot is freed.
    let app = deployments_app(&pool, org).await;
    let own = admission::reserve(&pool, org, app, user).await.unwrap();
    let body = deploy(&state, user, org, app, own).await;
    assert!(body.contains("Failed to get commit SHA"), "{body}");
    assert_eq!(status(&pool, own).await, None);

    // Claimed, then failed (no caution.hcl or Procfile): the attempt is failed.
    let app = deployments_app(&pool, org).await;
    git_repo(data_dir.path(), app);
    let claimed = admission::reserve(&pool, org, app, user).await.unwrap();
    let body = deploy(&state, user, org, app, claimed).await;
    assert!(body.contains("internal error"), "{body}");
    let (status, failure_kind, cleaned_up): (String, Option<String>, bool) = sqlx::query_as(
        "SELECT status, failure_kind, cleaned_up_at IS NOT NULL FROM app_deployments WHERE id = $1",
    )
    .bind(claimed)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        (status.as_str(), failure_kind.as_deref(), cleaned_up),
        ("failed", Some("provisioning"), true)
    );
    pool.close().await;
}

fn test_state(pool: &PgPool, data_dir: &str) -> std::sync::Arc<AppState> {
    Arc::new(AppState {
        db: pool.clone(),
        database_url: String::new(),
        teardown_slots: Arc::new(Semaphore::new(1)),
        git_hostname: "git.test".to_string(),
        git_ssh_port: None,
        data_dir: data_dir.to_string(),
        encryptor: None,
        internal_service_secret: None,
        paddle_client_token: None,
        paddle_setup_price_id: None,
        paddle_credits_price_ids: [None, None, None],
        paddle_api_url: String::new(),
        paddle_api_key: None,
        pricing: crate::PricingConfig {
            compute_margin_percent: 0.0,
            subscription_tiers: caution_config::pricing::DuplicateCheckedTiers(Default::default()),
            credit_packages: Default::default(),
            paddle_catalog: None,
        },
        builder_config: crate::builder::BuilderConfig {
            ami_id: String::new(),
            security_group_id: String::new(),
            subnet_id: String::new(),
            instance_profile: String::new(),
            region: "us-west-2".to_string(),
            timeout_secs: 1,
            eif_s3_bucket: String::new(),
            git_hostname: String::new(),
            additional_instance_tags: Vec::new(),
        },
        builder_sizes: crate::builder::BuilderSizesConfig {
            builder_sizes: Vec::new(),
            max_resources_per_org: 100,
        },
        eif_download_cache: crate::eif_download::EifDownloadCache::new(data_dir, 1),
        managed_dns: None,
    })
}

async fn member(pool: &PgPool, org: Uuid) -> Uuid {
    let user = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id, username) VALUES ($1, $2)")
        .bind(user)
        .bind(user.to_string())
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO organization_members(organization_id, user_id) VALUES ($1, $2)")
        .bind(org)
        .bind(user)
        .execute(pool)
        .await
        .unwrap();
    user
}

/// An attempt another request claimed and is building (nothing provisioned).
async fn building(pool: &PgPool, org: Uuid, app: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO app_deployments (app_id, organization_id, status, owner_process_id)
         VALUES ($1, $2, 'building', $3)
         RETURNING id",
    )
    .bind(app)
    .bind(org)
    .bind(*PROCESS_ID)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn status(pool: &PgPool, deployment: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT status FROM app_deployments WHERE id = $1")
        .bind(deployment)
        .fetch_optional(pool)
        .await
        .unwrap()
}

/// The app's bare repository with one empty commit on `main`.
fn git_repo(data_dir: &std::path::Path, app: Uuid) {
    let work = data_dir.join(format!("work-{app}"));
    let bare = data_dir.join(format!("git-repos/{app}.git"));
    let git = |args: &[&std::ffi::OsStr]| {
        let status = std::process::Command::new("git")
            .args(["-c", "user.name=test", "-c", "user.email=test@example.com"])
            .args(["-c", "commit.gpgsign=false"])
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    };
    git(&[
        "init".as_ref(),
        "-q".as_ref(),
        "-b".as_ref(),
        "main".as_ref(),
        work.as_os_str(),
    ]);
    git(&[
        "-C".as_ref(),
        work.as_os_str(),
        "commit".as_ref(),
        "-q".as_ref(),
        "--allow-empty".as_ref(),
        "--no-verify".as_ref(),
        "-m".as_ref(),
        "init".as_ref(),
    ]);
    git(&[
        "clone".as_ref(),
        "-q".as_ref(),
        "--bare".as_ref(),
        work.as_os_str(),
        bare.as_os_str(),
    ]);
}

/// Posts `/deploy` and returns the streamed body once the request settled.
async fn deploy(
    state: &Arc<AppState>,
    user: Uuid,
    org: Uuid,
    app: Uuid,
    deployment_id: Uuid,
) -> String {
    let response = crate::deploy_handler(
        axum::extract::State(state.clone()),
        axum::Extension(crate::AuthContext { user_id: user }),
        crate::validated_types::Validated(crate::validated_types::DeployRequest {
            org_id: org,
            app_id: app,
            branch: "main".to_string(),
            commit_sha: None,
            builder_size: None,
            deployment_id: Some(deployment_id),
        }),
    )
    .await;
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(body.to_vec()).unwrap()
}
