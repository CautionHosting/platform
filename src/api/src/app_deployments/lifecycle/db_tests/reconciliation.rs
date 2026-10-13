// SPDX-FileCopyrightText: 2026 Caution SEZC
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Database-backed tests of the deployments reconciler.

use super::*;
use crate::app_deployments::reconcile::{
    DeploymentsApp, ReconcileBackend, expire_reservations, reconcile_with, recover_abandoned,
    repair_live,
};
use std::collections::HashMap;

#[tokio::test]
#[ignore = "run bash tests/e2e/test_app_deployments_db.sh (isolated PostgreSQL)"]
async fn reconciliation() {
    let pool = test_pool().await;
    let state = test_state(&pool, "/nonexistent");

    expired_reservations_are_released(&state).await;
    abandoned_attempts_are_failed_and_cleaned_up(&state).await;
    settled_work_is_not_adopted(&state).await;
    interrupted_destroy_is_rerun_until_it_succeeds(&state).await;
    abandoned_cleanup_is_unlocked_and_retried(&state).await;
    failed_destroy_of_a_lost_runtime_is_retried(&state).await;
    cleanup_spares_in_flight_destroys(&state).await;
    stale_own_destroy_is_unlocked_and_rerun(&state).await;
    abandoned_apply_leftovers_are_swept(&state).await;
    failure_without_state_is_recorded_cleaned_up(&state).await;
    running_teardown_defers_adoption(&state).await;
    interrupted_switch_records_the_holder_live(&state).await;
    interrupted_activation_records_the_holder_live(&state).await;
    single_running_deployment_is_activated(&state).await;
    several_running_deployments_are_never_guessed(&state).await;
    unassociated_or_unknown_holder_is_only_reported(&state).await;
    lost_runtime_is_marked_and_keeps_the_pointer(&state).await;
    concurrent_selection_is_not_reverted(&state).await;
    pool.close().await;
}

/// EC2, S3 and OpenTofu as reconciliation sees them, controlled by the test.
/// Anything not configured fails, so a pass never changes another test's app.
#[derive(Default)]
struct FakeAws {
    /// The app EIP holder by app (`None`: unassociated).
    addresses: Mutex<HashMap<Uuid, Option<String>>>,
    /// The EC2 state by instance (`None`: not found).
    runtimes: Mutex<HashMap<String, Option<&'static str>>>,
    attached: Mutex<Vec<String>>,
    /// State lock deletions and destroys, in order.
    calls: Mutex<Vec<Call>>,
    fail_destroy: AtomicBool,
    ec2: FakeEc2,
}

#[derive(Clone, Debug, PartialEq)]
enum Call {
    Unlock(String),
    Destroy(Uuid),
}

impl FakeAws {
    fn address(self, app: Uuid, holder: Option<&str>) -> Self {
        self.addresses
            .lock()
            .unwrap()
            .insert(app, holder.map(str::to_string));
        self
    }

    fn runtime(self, instance_id: &str, state: Option<&'static str>) -> Self {
        self.runtimes
            .lock()
            .unwrap()
            .insert(instance_id.to_string(), state);
        self
    }

    fn holder(&self, app: Uuid) -> Option<String> {
        self.addresses.lock().unwrap()[&app].clone()
    }

    fn attached(&self) -> Vec<String> {
        self.attached.lock().unwrap().clone()
    }

    fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    fn cleared_locks(&self) -> Vec<String> {
        self.calls()
            .into_iter()
            .filter_map(|call| match call {
                Call::Unlock(state_key) => Some(state_key),
                Call::Destroy(_) => None,
            })
            .collect()
    }

    fn destroyed(&self) -> Vec<Uuid> {
        self.calls()
            .into_iter()
            .filter_map(|call| match call {
                Call::Destroy(id) => Some(id),
                Call::Unlock(_) => None,
            })
            .collect()
    }

    /// The lock deletions and destroys of one deployment, in order.
    fn calls_for(&self, id: Uuid, state_key: &str) -> Vec<Call> {
        self.calls()
            .into_iter()
            .filter(|call| match call {
                Call::Unlock(key) => key == state_key,
                Call::Destroy(destroyed) => *destroyed == id,
            })
            .collect()
    }
}

impl DestroyBackend for FakeAws {
    async fn address_holder(
        &self,
        app_id: Uuid,
        region: &str,
    ) -> Result<Option<String>, ec2::DescribeAppAddressError> {
        self.app_address(app_id, region)
            .await
            .map(|address| address.instance_id)
    }

    async fn destroy_state(
        &self,
        _org_id: Uuid,
        _app_id: Uuid,
        deployment_id: Uuid,
        _region: &str,
    ) -> Result<(), deployment::DestroyDeploymentStateError> {
        self.calls
            .lock()
            .unwrap()
            .push(Call::Destroy(deployment_id));
        if self.fail_destroy.load(Ordering::SeqCst) {
            return Err(deployment::DestroyDeploymentStateError::TofuDestroy {
                location: std::panic::Location::caller(),
                source: "tofu destroy failed".into(),
            });
        }
        Ok(())
    }

    async fn clear_state_lock(
        &self,
        state_key: &str,
    ) -> Result<(), deployment::ClearStateLockError> {
        self.calls
            .lock()
            .unwrap()
            .push(Call::Unlock(state_key.to_string()));
        Ok(())
    }

    async fn tagged_instances(
        &self,
        _app_id: Uuid,
        _deployment_id: Uuid,
        _region: &str,
    ) -> Result<Vec<ec2::Instance>, ec2::DescribeInstancesError> {
        Ok(self.ec2.tagged_instances())
    }

    async fn terminate_instances(
        &self,
        _region: &str,
        instance_ids: &[String],
    ) -> Result<(), ec2::TerminateInstancesError> {
        self.ec2.terminate(instance_ids);
        Ok(())
    }

    async fn tagged_security_groups(
        &self,
        _app_id: Uuid,
        _deployment_id: Uuid,
        _region: &str,
    ) -> Result<Vec<ec2::SecurityGroup>, ec2::DescribeSecurityGroupsError> {
        Ok(self.ec2.tagged_groups())
    }

    async fn delete_security_group(
        &self,
        _region: &str,
        group_id: &str,
    ) -> Result<(), ec2::DeleteSecurityGroupError> {
        self.ec2.delete_group(group_id)
    }
}

impl ReconcileBackend for FakeAws {
    async fn app_address(
        &self,
        app_id: Uuid,
        _region: &str,
    ) -> Result<ec2::AppAddress, ec2::DescribeAppAddressError> {
        let Some(holder) = self.addresses.lock().unwrap().get(&app_id).cloned() else {
            return Err(ec2::DescribeAppAddressError::DescribeAddresses {
                location: std::panic::Location::caller(),
                source: "unknown app".into(),
            });
        };
        Ok(ec2::AppAddress {
            allocation_id: "eipalloc-test".to_string(),
            public_ip: EIP.to_string(),
            instance_id: holder,
        })
    }

    /// Mirrors `Ec2Client::move_app_address` without an expected holder.
    async fn attach_address(
        &self,
        app_id: Uuid,
        _region: &str,
        instance_id: &str,
    ) -> Result<String, ec2::MoveAppAddressError> {
        let mut addresses = self.addresses.lock().unwrap();
        let holder = addresses.get_mut(&app_id).unwrap();
        if holder
            .as_deref()
            .is_some_and(|holder| holder != instance_id)
        {
            return Err(ec2::MoveAppAddressError::HolderMismatch {
                expected: None,
                actual: holder.clone(),
                location: std::panic::Location::caller(),
            });
        }
        *holder = Some(instance_id.to_string());
        self.attached.lock().unwrap().push(instance_id.to_string());
        Ok(EIP.to_string())
    }

    async fn instance_runtime(
        &self,
        _region: &str,
        instance_id: &str,
    ) -> Result<Option<ec2::InstanceRuntime>, ec2::DescribeInstanceRuntimeError> {
        let Some(state) = self.runtimes.lock().unwrap().get(instance_id).copied() else {
            return Err(ec2::DescribeInstanceRuntimeError::Request {
                location: std::panic::Location::caller(),
                source: "unknown instance".into(),
            });
        };
        Ok(state.map(|state| ec2::InstanceRuntime {
            state: state.to_string(),
            public_ip: None,
        }))
    }
}

/// Hands the deployment to a process that died, with its own state key.
async fn abandon(pool: &PgPool, id: Uuid) -> String {
    let state_key = format!("state-{id}");
    sqlx::query("UPDATE app_deployments SET owner_process_id = $2, state_key = $3 WHERE id = $1")
        .bind(id)
        .bind(Uuid::new_v4())
        .bind(&state_key)
        .execute(pool)
        .await
        .unwrap();
    state_key
}

/// Gives a deployment of this process its own state key.
async fn own_state_key(pool: &PgPool, id: Uuid) -> String {
    let state_key = format!("state-{id}");
    sqlx::query("UPDATE app_deployments SET state_key = $2 WHERE id = $1")
        .bind(id)
        .bind(&state_key)
        .execute(pool)
        .await
        .unwrap();
    state_key
}

/// Moves the deployment's last update past the cleanup grace (its
/// `updated_at` trigger is off for this transaction only).
async fn age(pool: &PgPool, id: Uuid) {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE app_deployments SET updated_at = NOW() - INTERVAL '23 minutes' WHERE id = $1",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

async fn owner(pool: &PgPool, id: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT owner_process_id FROM app_deployments WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// `(status, failure kind, error)` of a deployment.
async fn failure(pool: &PgPool, id: Uuid) -> (String, Option<String>, Option<String>) {
    sqlx::query_as("SELECT status, failure_kind, error FROM app_deployments WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn update(pool: &PgPool, sql: &str, id: Uuid) {
    sqlx::query(sql).bind(id).execute(pool).await.unwrap();
}

/// A deployments app whose network (and Elastic IP) exists, with a Running
/// target deployment.
async fn networked(pool: &PgPool) -> (Fixture, String) {
    let f = fixture(pool, "running").await;
    update(
        pool,
        "UPDATE compute_resources SET app_network = '{}'::jsonb WHERE id = $1",
        f.app,
    )
    .await;
    update(
        pool,
        "UPDATE app_deployments SET configuration = '{\"commit_sha\": \"0123abcd\"}' WHERE id = $1",
        f.target,
    )
    .await;
    let instance_id = set_instance(pool, f.target).await;
    (f, instance_id)
}

async fn expired_reservations_are_released(state: &AppState) {
    let pool = &state.db;
    let expired = fixture(pool, "reserved").await;
    let fresh = fixture(pool, "reserved").await;
    for (f, expires_in) in [(expired, "-1 minute"), (fresh, "30 minutes")] {
        sqlx::query(
            "UPDATE app_deployments SET reservation_expires_at = NOW() + $2::interval WHERE id = $1",
        )
        .bind(f.target)
        .bind(expires_in)
        .execute(pool)
        .await
        .unwrap();
    }
    assert!(expire_reservations(pool).await.unwrap() >= 1);
    assert_eq!(status(pool, expired.target).await, None);
    assert_eq!(
        status(pool, fresh.target).await.as_deref(),
        Some("reserved")
    );

    // The pass itself releases them too.
    update(
        pool,
        "UPDATE app_deployments SET reservation_expires_at = NOW() - INTERVAL '1 minute'
         WHERE id = $1",
        fresh.target,
    )
    .await;
    reconcile_with(state, &FakeAws::default()).await;
    assert_eq!(status(pool, fresh.target).await, None);
}

async fn abandoned_attempts_are_failed_and_cleaned_up(state: &AppState) {
    let pool = &state.db;
    // Nothing provisioned yet.
    let building = fixture(pool, "building").await;
    abandon(pool, building.target).await;
    update(
        pool,
        "UPDATE app_deployments SET state_key = NULL, region = NULL WHERE id = $1",
        building.target,
    )
    .await;
    // Its instance launched and metered before the process died.
    let provisioning = fixture(pool, "provisioning").await;
    let state_key = abandon(pool, provisioning.target).await;
    let instance_id = set_instance(pool, provisioning.target).await;
    meter(pool, provisioning.org, provisioning.target, &instance_id).await;
    // This process's own OpenTofu may still run: never adopted.
    let own = fixture(pool, "provisioning").await;
    let own_state_key = format!("state-{}", own.target);
    sqlx::query("UPDATE app_deployments SET state_key = $2 WHERE id = $1")
        .bind(own.target)
        .bind(&own_state_key)
        .execute(pool)
        .await
        .unwrap();

    let aws = FakeAws::default();
    reconcile_with(state, &aws).await;

    for f in [building, provisioning] {
        assert_eq!(
            failure(pool, f.target).await,
            (
                "failed".to_string(),
                Some("provisioning".to_string()),
                Some("abandoned by an API restart".to_string())
            )
        );
        assert!(deployment_row(pool, f.target).await.2, "cleaned up");
        assert_eq!(owner(pool, f.target).await, Some(*PROCESS_ID));
    }
    assert!(aws.cleared_locks().contains(&state_key));
    assert!(aws.destroyed().contains(&provisioning.target));
    assert!(!aws.destroyed().contains(&building.target));
    assert!(!metered(pool, &instance_id).await);

    assert_eq!(
        status(pool, own.target).await.as_deref(),
        Some("provisioning")
    );
    assert!(!aws.cleared_locks().contains(&own_state_key));
    assert!(!aws.destroyed().contains(&own.target));
}

/// A row settled after the pass listed it is re-checked when adopted.
async fn settled_work_is_not_adopted(state: &AppState) {
    let pool = &state.db;
    let f = fixture(pool, "provisioning").await;
    let state_key = abandon(pool, f.target).await;
    let dead_owner = owner(pool, f.target).await;
    update(
        pool,
        "UPDATE app_deployments SET status = 'failed', failure_kind = 'provisioning',
                cleaned_up_at = NOW()
         WHERE id = $1",
        f.target,
    )
    .await;

    let aws = FakeAws::default();
    recover_abandoned(state, &aws, f.app, f.target)
        .await
        .unwrap();
    assert_eq!(owner(pool, f.target).await, dead_owner);
    assert!(!aws.cleared_locks().contains(&state_key));
    assert!(aws.destroyed().is_empty());
}

async fn interrupted_destroy_is_rerun_until_it_succeeds(state: &AppState) {
    let pool = &state.db;
    let f = fixture(pool, "destroying").await;
    let live = deployment(pool, f.org, f.app, "running", Some("i-live")).await;
    serve(pool, f.app, live).await;
    let state_key = abandon(pool, f.target).await;
    let instance_id = set_instance(pool, f.target).await;
    meter(pool, f.org, f.target, &instance_id).await;

    // The re-run fails: still counted and billed, now owned by this process.
    let aws = FakeAws::default();
    aws.fail_destroy.store(true, Ordering::SeqCst);
    reconcile_with(state, &aws).await;
    assert!(aws.cleared_locks().contains(&state_key));
    assert_eq!(
        destroy_row(pool, f.target).await,
        ("failed".to_string(), false, false)
    );
    assert_eq!(owner(pool, f.target).await, Some(*PROCESS_ID));
    assert!(metered(pool, &instance_id).await);

    // The unfinished cleanup is retried on the next pass, after deleting the
    // lock a run killed by its timeout would have left.
    let aws = FakeAws::default();
    reconcile_with(state, &aws).await;
    assert_eq!(
        aws.calls_for(f.target, &state_key),
        vec![Call::Unlock(state_key.clone()), Call::Destroy(f.target)]
    );
    assert_eq!(
        destroy_row(pool, f.target).await,
        ("failed".to_string(), true, false)
    );
    assert!(!metered(pool, &instance_id).await);

    // A re-run that succeeds records the destruction.
    let g = fixture(pool, "destroying").await;
    let instance_id = set_instance(pool, g.target).await;
    meter(pool, g.org, g.target, &instance_id).await;
    abandon(pool, g.target).await;
    reconcile_with(state, &FakeAws::default()).await;
    assert_eq!(
        destroy_row(pool, g.target).await,
        ("destroyed".to_string(), true, true)
    );
    assert!(!metered(pool, &instance_id).await);
    assert_eq!(app_row(pool, f.app).await.live, Some(live));
}

/// A cleanup that died with its process left a stale state lock.
async fn abandoned_cleanup_is_unlocked_and_retried(state: &AppState) {
    let pool = &state.db;
    let f = fixture(pool, "failed").await;
    update(
        pool,
        "UPDATE app_deployments SET failure_kind = 'provisioning' WHERE id = $1",
        f.target,
    )
    .await;
    let state_key = abandon(pool, f.target).await;
    let instance_id = set_instance(pool, f.target).await;
    meter(pool, f.org, f.target, &instance_id).await;
    // A lost runtime keeps its state until `destroy -d`.
    let lost = deployment(pool, f.org, f.app, "failed", None).await;
    update(
        pool,
        "UPDATE app_deployments SET failure_kind = 'runtime_lost' WHERE id = $1",
        lost,
    )
    .await;
    let lost_state_key = abandon(pool, lost).await;

    let aws = FakeAws::default();
    reconcile_with(state, &aws).await;
    assert!(aws.cleared_locks().contains(&state_key));
    assert_eq!(owner(pool, f.target).await, Some(*PROCESS_ID));
    assert!(aws.destroyed().contains(&f.target));
    assert_eq!(
        destroy_row(pool, f.target).await,
        ("failed".to_string(), true, false)
    );
    assert!(!metered(pool, &instance_id).await);

    assert!(!aws.cleared_locks().contains(&lost_state_key));
    assert!(!aws.destroyed().contains(&lost));
    assert!(!deployment_row(pool, lost).await.2);

    // App teardown, under its lock, unlocks the state of every dead owner
    // before destroying it: the lost runtime and an interrupted `destroy -d`
    // of one. This process's own deployment is destroyed without unlocking.
    // A deployment destroy now blocks termination, so the leftover of one is
    // seeded after it.
    managed_dns::begin_termination(pool, f.app).await.unwrap();
    let destroying = deployment(pool, f.org, f.app, "destroying", None).await;
    update(
        pool,
        "UPDATE app_deployments SET failure_kind = 'runtime_lost' WHERE id = $1",
        destroying,
    )
    .await;
    let destroying_state_key = abandon(pool, destroying).await;
    let own = deployment(pool, f.org, f.app, "running", None).await;
    let aws = FakeAws::default();
    destroy_all_for_app_with(state, &aws, f.org, f.app)
        .await
        .unwrap();
    assert_eq!(
        aws.calls(),
        vec![
            Call::Unlock(lost_state_key),
            Call::Destroy(lost),
            Call::Unlock(destroying_state_key),
            Call::Destroy(destroying),
            Call::Destroy(own),
        ]
    );
    for id in [f.target, lost, destroying, own] {
        assert_eq!(
            destroy_row(pool, id).await,
            ("destroyed".to_string(), true, true)
        );
    }

    // A failed live deployment (app teardown failed) is unlocked, never cleaned up.
    let g = fixture(pool, "failed").await;
    update(
        pool,
        "UPDATE app_deployments SET failure_kind = 'provisioning' WHERE id = $1",
        g.target,
    )
    .await;
    let state_key = abandon(pool, g.target).await;
    set_live(pool, g.app, g.target).await;
    let aws = FakeAws::default();
    reconcile_with(state, &aws).await;
    assert!(aws.cleared_locks().contains(&state_key));
    assert!(!aws.destroyed().contains(&g.target));
    assert!(!deployment_row(pool, g.target).await.2);
}

/// A failed `destroy -d` of a lost runtime is owed cleanup like a failed
/// attempt: reconciliation retries it, which clears its stale state lock.
async fn failed_destroy_of_a_lost_runtime_is_retried(state: &AppState) {
    let pool = &state.db;
    let f = fixture(pool, "failed").await;
    let live = deployment(pool, f.org, f.app, "running", Some("i-live")).await;
    serve(pool, f.app, live).await;
    let state_key = own_state_key(pool, f.target).await;
    set_instance(pool, f.target).await;
    update(
        pool,
        "UPDATE app_deployments
         SET failure_kind = 'runtime_lost', failed_at = NOW() - INTERVAL '23 minutes'
         WHERE id = $1",
        f.target,
    )
    .await;

    let aws = FakeAws::default().address(f.app, Some("i-live"));
    aws.fail_destroy.store(true, Ordering::SeqCst);
    let target = begin_destroy(pool, &aws, f.user, f.app, f.target)
        .await
        .unwrap()
        .unwrap();
    complete_destroy_with(state, &aws, &target)
        .await
        .unwrap_err();
    assert_eq!(
        failure(pool, f.target).await,
        (
            "failed".to_string(),
            Some("provisioning".to_string()),
            Some("destroy failed; retry".to_string())
        )
    );

    let aws = FakeAws::default();
    reconcile_with(state, &aws).await;
    assert_eq!(
        aws.calls_for(f.target, &state_key),
        vec![Call::Unlock(state_key), Call::Destroy(f.target)]
    );
    assert_eq!(
        destroy_row(pool, f.target).await,
        ("failed".to_string(), true, false)
    );
    assert_eq!(app_row(pool, f.app).await.live, Some(live));
}

/// `fail_attempt` marks a failure before its own destroy runs; an app teardown
/// destroys the state itself. Neither lock is touched until the retry.
async fn cleanup_spares_in_flight_destroys(state: &AppState) {
    let pool = &state.db;
    let f = fixture(pool, "failed").await;
    let state_key = own_state_key(pool, f.target).await;
    update(
        pool,
        "UPDATE app_deployments SET failure_kind = 'provisioning', failed_at = NOW()
         WHERE id = $1",
        f.target,
    )
    .await;
    let aws = FakeAws::default();
    reconcile_with(state, &aws).await;
    assert!(aws.calls_for(f.target, &state_key).is_empty());

    update(
        pool,
        "UPDATE app_deployments SET failed_at = NOW() - INTERVAL '23 minutes' WHERE id = $1",
        f.target,
    )
    .await;
    let mut teardown = pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(hashtextextended($1, 1))")
        .bind(f.app.to_string())
        .execute(&mut *teardown)
        .await
        .unwrap();
    reconcile_with(state, &aws).await;
    assert!(aws.calls_for(f.target, &state_key).is_empty());
    assert!(!deployment_row(pool, f.target).await.2);

    sqlx::query("SELECT pg_advisory_unlock(hashtextextended($1, 1))")
        .bind(f.app.to_string())
        .execute(&mut *teardown)
        .await
        .unwrap();
    drop(teardown);
    // Past the grace its own OpenTofu was killed: its lock is stale.
    reconcile_with(state, &aws).await;
    assert_eq!(
        aws.calls_for(f.target, &state_key),
        vec![Call::Unlock(state_key), Call::Destroy(f.target)]
    );
    assert!(deployment_row(pool, f.target).await.2);
}

/// A deployment destroy of this process still `destroying` past the grace
/// (its task died or its last write failed) is unlocked and re-run.
async fn stale_own_destroy_is_unlocked_and_rerun(state: &AppState) {
    let pool = &state.db;
    let f = fixture(pool, "destroying").await;
    let state_key = own_state_key(pool, f.target).await;
    let instance_id = set_instance(pool, f.target).await;
    meter(pool, f.org, f.target, &instance_id).await;

    // Within the grace its OpenTofu may still run.
    let aws = FakeAws::default();
    reconcile_with(state, &aws).await;
    assert!(aws.calls_for(f.target, &state_key).is_empty());
    assert_eq!(status(pool, f.target).await.as_deref(), Some("destroying"));
    assert!(metered(pool, &instance_id).await);

    age(pool, f.target).await;
    reconcile_with(state, &aws).await;
    assert_eq!(
        aws.calls_for(f.target, &state_key),
        vec![Call::Unlock(state_key), Call::Destroy(f.target)]
    );
    assert_eq!(owner(pool, f.target).await, Some(*PROCESS_ID));
    assert_eq!(
        destroy_row(pool, f.target).await,
        ("destroyed".to_string(), true, true)
    );
    assert!(!metered(pool, &instance_id).await);
}

/// An API restart during `tofu apply` can leave an instance and security group
/// the state never recorded. Failure cleanup terminates them by their tags,
/// sparing everything else, and completes only once they are gone.
async fn abandoned_apply_leftovers_are_swept(state: &AppState) {
    let pool = &state.db;
    let f = fixture(pool, "provisioning").await;
    let state_key = abandon(pool, f.target).await;
    let instance_id = set_instance(pool, f.target).await;
    meter(pool, f.org, f.target, &instance_id).await;
    let (app, target) = (f.app.to_string(), f.target.to_string());
    let both = [
        ("ResourceId", app.as_str()),
        ("DeploymentId", target.as_str()),
    ];
    let aws = FakeAws::default();
    aws.ec2.instance("i-unrecorded", &both, "pending");
    aws.ec2.instance(
        "i-other-deployment",
        &[
            ("ResourceId", &app),
            ("DeploymentId", &Uuid::new_v4().to_string()),
        ],
        "running",
    );
    aws.ec2.group("sg-unrecorded", &both);

    // Every deployment of the pass is swept against these: only the target's
    // own leftover is terminated.
    reconcile_with(state, &aws).await;
    assert_eq!(failure(pool, f.target).await.0, "failed");
    assert_eq!(aws.ec2.terminated(), vec!["i-unrecorded".to_string()]);
    assert!(aws.ec2.deleted_groups().is_empty());
    assert!(!deployment_row(pool, f.target).await.2);
    assert!(metered(pool, &instance_id).await);

    // Terminated, and past the grace: the retry completes the cleanup.
    aws.ec2.finish_terminations();
    update(
        pool,
        "UPDATE app_deployments SET failed_at = NOW() - INTERVAL '23 minutes' WHERE id = $1",
        f.target,
    )
    .await;
    reconcile_with(state, &aws).await;
    assert_eq!(
        aws.calls_for(f.target, &state_key),
        vec![
            Call::Unlock(state_key.clone()),
            Call::Destroy(f.target),
            Call::Unlock(state_key),
            Call::Destroy(f.target),
        ]
    );
    assert_eq!(aws.ec2.terminated(), vec!["i-unrecorded".to_string()]);
    assert_eq!(aws.ec2.deleted_groups(), vec!["sg-unrecorded".to_string()]);
    assert!(deployment_row(pool, f.target).await.2);
    assert!(!metered(pool, &instance_id).await);
}

/// `fail_attempt` died between marking an attempt that provisioned nothing
/// failed and recording its cleanup.
async fn failure_without_state_is_recorded_cleaned_up(state: &AppState) {
    let pool = &state.db;
    let f = fixture(pool, "failed").await;
    abandon(pool, f.target).await;
    update(
        pool,
        "UPDATE app_deployments
         SET failure_kind = 'provisioning', state_key = NULL, region = NULL
         WHERE id = $1",
        f.target,
    )
    .await;
    let aws = FakeAws::default();
    reconcile_with(state, &aws).await;
    assert!(deployment_row(pool, f.target).await.2);
    assert!(!aws.destroyed().contains(&f.target));
}

/// App teardown may be destroying the state: its lock is never deleted.
async fn running_teardown_defers_adoption(state: &AppState) {
    let pool = &state.db;
    let f = fixture(pool, "destroying").await;
    let state_key = abandon(pool, f.target).await;
    let dead_owner = owner(pool, f.target).await;
    let failed = deployment(pool, f.org, f.app, "failed", None).await;
    update(
        pool,
        "UPDATE app_deployments SET failure_kind = 'provisioning' WHERE id = $1",
        failed,
    )
    .await;
    let failed_state_key = abandon(pool, failed).await;
    let mut teardown = pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(hashtextextended($1, 1))")
        .bind(f.app.to_string())
        .execute(&mut *teardown)
        .await
        .unwrap();

    // Neither adopted nor, while possibly locked, cleaned up.
    let aws = FakeAws::default();
    reconcile_with(state, &aws).await;
    for (id, key) in [(f.target, &state_key), (failed, &failed_state_key)] {
        assert!(!aws.cleared_locks().contains(key));
        assert!(!aws.destroyed().contains(&id));
    }
    assert_eq!(owner(pool, f.target).await, dead_owner);
    assert_eq!(status(pool, f.target).await.as_deref(), Some("destroying"));

    sqlx::query("SELECT pg_advisory_unlock(hashtextextended($1, 1))")
        .bind(f.app.to_string())
        .execute(&mut *teardown)
        .await
        .unwrap();
    drop(teardown);
    reconcile_with(state, &aws).await;
    assert!(aws.cleared_locks().contains(&state_key));
    assert!(aws.cleared_locks().contains(&failed_state_key));
    assert_eq!(status(pool, f.target).await.as_deref(), Some("destroyed"));
    assert!(deployment_row(pool, failed).await.2);
}

async fn interrupted_switch_records_the_holder_live(state: &AppState) {
    let pool = &state.db;
    let (f, target_instance) = networked(pool).await;
    let live = deployment(pool, f.org, f.app, "running", None).await;
    let live_instance = set_instance(pool, live).await;
    serve(pool, f.app, live).await;
    let aws = FakeAws::default()
        .address(f.app, Some(&target_instance))
        .runtime(&live_instance, Some("running"))
        .runtime(&target_instance, Some("running"));

    reconcile_with(state, &aws).await;
    let app = app_row(pool, f.app).await;
    assert_eq!(app.live, Some(f.target));
    assert_eq!(app.provider_resource_id, target_instance);
    assert_eq!(app.public_ip.as_deref(), Some(EIP));
    assert_eq!(app.commit_sha.as_deref(), Some("0123abcd"));
    assert_eq!(
        deployment_row(pool, f.target).await,
        ("running".to_string(), true, false)
    );
    // The previous live deployment is retained as a candidate.
    assert_eq!(status(pool, live).await.as_deref(), Some("running"));
    assert!(aws.attached().is_empty());
}

async fn interrupted_activation_records_the_holder_live(state: &AppState) {
    let pool = &state.db;
    let (f, instance_id) = networked(pool).await;
    let aws = FakeAws::default()
        .address(f.app, Some(&instance_id))
        .runtime(&instance_id, Some("running"));

    reconcile_with(state, &aws).await;
    let app = app_row(pool, f.app).await;
    assert_eq!(app.live, Some(f.target));
    assert_eq!(app.state, "running");
    assert_eq!(app.public_ip.as_deref(), Some(EIP));
    assert_eq!(app.region.as_deref(), Some("us-east-1"));
    assert_eq!(app.provider_resource_id, instance_id);
    assert_eq!(app.commit_sha.as_deref(), Some("0123abcd"));
    assert_eq!(
        deployment_row(pool, f.target).await,
        ("running".to_string(), true, false)
    );
    assert!(aws.attached().is_empty());
}

/// Activation interrupted before the EIP moved.
async fn single_running_deployment_is_activated(state: &AppState) {
    let pool = &state.db;
    let (f, instance_id) = networked(pool).await;
    let aws = FakeAws::default()
        .address(f.app, None)
        .runtime(&instance_id, Some("running"));

    reconcile_with(state, &aws).await;
    assert_eq!(aws.attached(), vec![instance_id.clone()]);
    assert_eq!(aws.holder(f.app), Some(instance_id.clone()));
    let app = app_row(pool, f.app).await;
    assert_eq!(app.live, Some(f.target));
    assert_eq!(app.state, "running");
    assert_eq!(app.public_ip.as_deref(), Some(EIP));
    assert_eq!(app.provider_resource_id, instance_id);

    // Settled: the next pass changes nothing.
    reconcile_with(state, &aws).await;
    assert_eq!(aws.attached().len(), 1);
}

async fn several_running_deployments_are_never_guessed(state: &AppState) {
    let pool = &state.db;
    let (f, instance_id) = networked(pool).await;
    let other = deployment(pool, f.org, f.app, "running", None).await;
    let other_instance = set_instance(pool, other).await;
    let aws = FakeAws::default()
        .address(f.app, None)
        .runtime(&instance_id, Some("running"))
        .runtime(&other_instance, Some("running"));

    reconcile_with(state, &aws).await;
    assert!(aws.attached().is_empty());
    let app = app_row(pool, f.app).await;
    assert_eq!(app.live, None);
    assert_eq!(app.state, "initialized");
    assert_eq!(app.public_ip, None);
    for id in [f.target, other] {
        assert_eq!(
            deployment_row(pool, id).await,
            ("running".to_string(), false, false)
        );
    }
}

async fn unassociated_or_unknown_holder_is_only_reported(state: &AppState) {
    let pool = &state.db;
    // A live pointer with an unassociated EIP.
    let (f, instance_id) = networked(pool).await;
    serve(pool, f.app, f.target).await;
    let aws = FakeAws::default()
        .address(f.app, None)
        .runtime(&instance_id, Some("running"));
    reconcile_with(state, &aws).await;
    assert!(aws.attached().is_empty());
    assert_eq!(aws.holder(f.app), None);
    let app = app_row(pool, f.app).await;
    assert_eq!(app.live, Some(f.target));
    assert_eq!(app.public_ip.as_deref(), Some(EIP));
    assert_eq!(app.dns_status, "ready");
    assert_eq!(
        deployment_row(pool, f.target).await,
        ("running".to_string(), false, false)
    );

    // An EIP held by an instance of no Running deployment, nothing live.
    let (f, instance_id) = networked(pool).await;
    let aws = FakeAws::default()
        .address(f.app, Some("i-unknown"))
        .runtime(&instance_id, Some("running"));
    reconcile_with(state, &aws).await;
    assert!(aws.attached().is_empty());
    assert_eq!(aws.holder(f.app).as_deref(), Some("i-unknown"));
    assert_eq!(app_row(pool, f.app).await.live, None);
}

async fn lost_runtime_is_marked_and_keeps_the_pointer(state: &AppState) {
    let pool = &state.db;
    let (f, live_instance) = networked(pool).await;
    serve(pool, f.app, f.target).await;
    meter(pool, f.org, f.target, &live_instance).await;
    let mut candidates = Vec::new();
    for _ in 0..4 {
        let id = deployment(pool, f.org, f.app, "running", None).await;
        let instance_id = set_instance(pool, id).await;
        meter(pool, f.org, id, &instance_id).await;
        candidates.push((id, instance_id));
    }
    let [shutting_down, stopped, healthy, unreadable] = [0, 1, 2, 3].map(|i| &candidates[i]);
    // The terminated live instance released the EIP; EC2 no longer knows it.
    // An unreadable runtime is never taken for a lost one.
    let aws = FakeAws::default()
        .address(f.app, None)
        .runtime(&live_instance, None)
        .runtime(&shutting_down.1, Some("shutting-down"))
        .runtime(&stopped.1, Some("stopped"))
        .runtime(&healthy.1, Some("running"));

    reconcile_with(state, &aws).await;
    for (id, instance_id) in [
        (f.target, &live_instance),
        (shutting_down.0, &shutting_down.1),
    ] {
        assert_eq!(
            failure(pool, id).await,
            (
                "failed".to_string(),
                Some("runtime_lost".to_string()),
                Some("instance terminated".to_string())
            )
        );
        assert!(!metered(pool, instance_id).await);
    }
    for (id, instance_id) in [stopped, healthy, unreadable] {
        assert_eq!(status(pool, *id).await.as_deref(), Some("running"));
        assert!(metered(pool, instance_id).await);
    }
    // The dead live deployment stays selected, for a recovery switch.
    let app = app_row(pool, f.app).await;
    assert_eq!(app.live, Some(f.target));
    assert_eq!(app.state, "running");
    assert_eq!(app.public_ip.as_deref(), Some(EIP));
    assert!(aws.attached().is_empty());

    // Its state stays until `destroy -d`.
    reconcile_with(state, &aws).await;
    assert!(!aws.destroyed().contains(&f.target));
    assert!(!deployment_row(pool, f.target).await.2);
}

/// A switch or activation that commits after the pass read the app wins.
async fn concurrent_selection_is_not_reverted(state: &AppState) {
    let pool = &state.db;
    let (f, instance_id) = networked(pool).await;
    let other = deployment(pool, f.org, f.app, "running", None).await;
    let other_instance = set_instance(pool, other).await;
    let running = [
        (f.target, instance_id.clone()),
        (other, other_instance.clone()),
    ];
    let unselected = DeploymentsApp {
        id: f.app,
        region: "us-east-1".to_string(),
        live_deployment_id: None,
    };

    // Read before a switch to `other` committed: the EIP still at the target.
    serve(pool, f.app, other).await;
    let aws = FakeAws::default().address(f.app, Some(&instance_id));
    repair_live(state, &aws, &unselected, &running)
        .await
        .unwrap();
    assert_eq!(app_row(pool, f.app).await.live, Some(other));
    assert!(!deployment_row(pool, f.target).await.1);

    // Activation decided, then a selection commits while the pass waits for
    // the app lock: the EIP never moves.
    let (g, g_instance) = networked(pool).await;
    let unselected = DeploymentsApp {
        id: g.app,
        ..unselected
    };
    let aws = Arc::new(FakeAws::default().address(g.app, None));
    let mut selection = hold_app_lock(pool, g.app).await;
    let repair = {
        let (state, aws) = (test_state(pool, "/nonexistent"), aws.clone());
        tokio::spawn(async move {
            repair_live(&state, &*aws, &unselected, &[(g.target, g_instance)]).await
        })
    };
    wait_for_lock_waiters(pool, 1).await;
    sqlx::query("UPDATE compute_resources SET live_deployment_id = $2 WHERE id = $1")
        .bind(g.app)
        .bind(g.target)
        .execute(&mut *selection)
        .await
        .unwrap();
    selection.commit().await.unwrap();
    repair.await.unwrap().unwrap();
    assert!(aws.attached().is_empty());
    assert_eq!(aws.holder(g.app), None);
    assert!(!deployment_row(pool, g.target).await.1);
}
