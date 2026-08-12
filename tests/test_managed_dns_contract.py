from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_route53_policy_is_scoped_to_managed_a_records():
    bootstrap = (ROOT / "infra-bootstrap" / "main.tf").read_text()

    assert 'Action   = "route53:ChangeResourceRecordSets"' in bootstrap
    assert 'Resource = aws_route53_zone.apps.arn' in bootstrap
    assert '"route53:ChangeResourceRecordSetsRecordTypes" = ["A"]' in bootstrap
    assert (
        '"route53:ChangeResourceRecordSetsActions"     = ["UPSERT", "DELETE"]'
        in bootstrap
    )
    assert (
        '"route53:ChangeResourceRecordSetsNormalizedRecordNames" = '
        '["*.apps.caution.sh"]' in bootstrap
    )
    assert 'Action   = "route53:ListResourceRecordSets"' in bootstrap
    assert 'Action   = "route53:GetChange"' in bootstrap
    assert 'Resource = "arn:aws:route53:::change/*"' in bootstrap
    assert "route53:GetHostedZone" not in bootstrap


def test_managed_zone_has_protected_sixty_second_negative_cache_ttl():
    bootstrap = (ROOT / "infra-bootstrap" / "main.tf").read_text()

    assert 'name          = "apps.caution.sh"' in bootstrap
    assert 'resource "aws_route53_record" "apps_soa"' in bootstrap
    assert "ttl             = 60" in bootstrap
    assert "1209600 60" in bootstrap
    assert bootstrap.count("prevent_destroy = true") >= 2


def test_pending_deploy_updates_are_attempt_owned():
    migration = (
        ROOT / "src" / "api" / "migrations" / "052_deploy_attempt_ownership.sql"
    ).read_text()
    api = (ROOT / "src" / "api" / "src" / "main.rs").read_text()
    lost_finalization = api.split(
        "let Some((initial_dns_status, initial_dns_error)) = resource_update else", 1
    )[1]
    lost_finalization = lost_finalization.split(
        "if let Err(e) = crate::metering::upsert_tracked_resource", 1
    )[0]

    assert "ADD COLUMN IF NOT EXISTS deploy_attempt_id UUID" in migration
    assert "state = 'pending' AND deploy_attempt_id = $4" in api
    assert "AND deploy_attempt_id = $5" in api
    assert "AND deploy_attempt_id = $9" in api
    assert "SET state = $1, deploy_attempt_id = NULL" in api
    assert "fully_managed_capacity::release_reservation" in lost_finalization
    assert "recover_deploy_failure" in lost_finalization
    assert "Deployment completed after the app lifecycle changed" in lost_finalization


def test_failed_deploy_rollback_uses_owned_guarded_teardown():
    api = (ROOT / "src" / "api" / "src" / "main.rs").read_text()
    managed_dns = (ROOT / "src" / "api" / "src" / "managed_dns.rs").read_text()
    resources = (ROOT / "src" / "api" / "src" / "resources.rs").read_text()
    recovery = api.split("async fn recover_deploy_failure", 1)[1]
    recovery = recovery.split("async fn restore_pending_deploy_rejection", 1)[0]

    assert "begin_owned_deploy_rollback" in recovery
    assert "resources::destroy_resource_by_id" in recovery
    assert "state = 'pending' AND deploy_attempt_id = $4" in managed_dns
    assert "state = 'terminating' AND deploy_attempt_id = $3" in managed_dns
    assert "WHEN deploy_attempt_id IS NULL THEN 'terminated'::resource_state" in resources
    assert "ELSE 'failed'::resource_state" in resources
    assert "public_ip = NULL, region = NULL, deploy_attempt_id = NULL" in resources


def test_teardown_uses_a_bounded_dedicated_session_lock():
    api = (ROOT / "src" / "api" / "src" / "main.rs").read_text()
    resources = (ROOT / "src" / "api" / "src" / "resources.rs").read_text()
    destroy = resources.split("pub(crate) async fn destroy_resource_by_id", 1)[1]
    destroy = destroy.split("async fn destroy_credentials", 1)[0]

    assert "const TEARDOWN_CONCURRENCY: usize = 2" in api
    assert "Semaphore::new(TEARDOWN_CONCURRENCY)" in api
    assert "PgConnection::connect(&state.database_url)" in destroy
    assert destroy.index("teardown_slots") < destroy.index("ensure_safe_to_release")
    assert "pg_advisory_lock(hashtextextended($1, 1))" in destroy
    assert "pg_advisory_unlock(hashtextextended($1, 1))" in destroy
    assert "pg_advisory_xact_lock(hashtextextended($1, 0))" in (
        ROOT / "src" / "api" / "src" / "managed_dns.rs"
    ).read_text()
    assert "locked_transaction" not in destroy


def test_teardown_and_dns_reconciliation_are_independent():
    api = (ROOT / "src" / "api" / "src" / "main.rs").read_text()
    startup = api.split("let state = Arc::new(AppState", 1)[1]

    assert "async fn reconcile_terminating_resources" in api
    assert "async fn reconcile_managed_dns" in api
    assert startup.index("reconcile_terminating_resources") < startup.index(
        "if let Some(managed_dns)"
    )
    assert "MissedTickBehavior::Skip" in startup


def test_deploy_reporting_does_not_depend_on_post_commit_dns_reads():
    api = (ROOT / "src" / "api" / "src" / "main.rs").read_text()
    managed_dns = (ROOT / "src" / "api" / "src" / "managed_dns.rs").read_text()
    deploy_finalize = api.split("let resource_update = sqlx::query_as", 1)[1]
    deploy_finalize = deploy_finalize.split("async fn reconcile_terminating_resources", 1)[0]
    publish = managed_dns.split("pub(crate) async fn publish_resource", 1)[1]
    publish = publish.split("async fn publish_once", 1)[0]

    assert "RETURNING dns_status, dns_error" in deploy_finalize
    assert "managed_dns::dns_snapshot" not in deploy_finalize
    assert "return Ok(DnsSnapshot" in publish
    assert "dns_snapshot(pool, resource_id)" not in publish


def test_unsuspend_compensates_failed_readiness_without_publishing_dns():
    suspension = (ROOT / "src" / "api" / "src" / "suspension.rs").read_text()
    unsuspend = suspension.split("pub async fn unsuspend_org_resources", 1)[1]
    unsuspend = unsuspend.split("fn instance_lookup_filters", 1)[0]

    assert "started_instance_ids" in unsuspend
    assert ".stop_instances(&started_instance_ids)" in unsuspend
    assert "degraded_readiness_error.is_none()" in unsuspend
    assert "recording app as running and metered" in unsuspend
    assert "WHEN $6::text IS NOT NULL THEN $6" in unsuspend


def test_owned_tombstone_delete_is_idempotent_and_unknown_ids_stay_hidden():
    resources = (ROOT / "src" / "api" / "src" / "resources.rs").read_text()
    delete = resources.split("pub async fn delete_resource", 1)[1]
    delete = delete.split("pub(crate) async fn destroy_resource_by_id", 1)[0]

    assert "cr.destroyed_at IS NOT NULL" in delete
    assert delete.count("StatusCode::NO_CONTENT") >= 2
    assert "StatusCode::NOT_FOUND, \"App not found\"" in delete
    assert 'message == "resource is deploying"' in delete
    assert "state = 'terminating' AND deploy_attempt_id IS NOT NULL" in delete
