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
    lost_finalization = api.split("if resource_update.rows_affected() == 0", 1)[1]
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


def test_teardown_uses_a_bounded_dedicated_session_lock():
    api = (ROOT / "src" / "api" / "src" / "main.rs").read_text()
    resources = (ROOT / "src" / "api" / "src" / "resources.rs").read_text()
    destroy = resources.split("pub(crate) async fn destroy_resource_by_id", 1)[1]
    destroy = destroy.split("async fn destroy_credentials", 1)[0]

    assert "const TEARDOWN_CONCURRENCY: usize = 2" in api
    assert "Semaphore::new(TEARDOWN_CONCURRENCY)" in api
    assert "PgConnection::connect(&state.database_url)" in destroy
    assert "pg_advisory_lock(hashtextextended($1, 0))" in destroy
    assert "pg_advisory_unlock(hashtextextended($1, 0))" in destroy
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
