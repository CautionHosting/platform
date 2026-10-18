"""Offline source contracts; these do not exercise SQL, AWS, or HTTP at runtime."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


def _match(source, pattern, contract):
    match = re.search(pattern, source, re.MULTILINE | re.DOTALL)
    assert match is not None, contract
    return match


def _rust_item(source, declaration):
    """Scope a rustfmt-formatted item without depending on its return type.

    The closing brace has the declaration's indentation, unlike nested blocks
    and braces inside format strings. Fail explicitly if either boundary moves.
    """
    start = _match(
        source,
        rf"^(?P<indent>[ \t]*)(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?{declaration}\b",
        f"missing Rust item: {declaration}",
    )
    rest = source[start.end():]
    end = _match(rest, rf"^{start['indent']}\}}", f"unclosed Rust item: {declaration}")
    return source[start.start():start.end() + end.end()]


def _assert_infallible_reporting(source):
    # Ignore diagnostics and comments (which may contain '?' or debug formats).
    code = re.sub(r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*.*?\*/', "", source, flags=re.DOTALL)
    assert "?" not in code, "DNS reporting must not propagate errors after commit"
    assert not re.search(r"\b(?:return\s+)?Err\s*\(", code), "DNS reporting must succeed"
    assert not re.search(r"\.(?:unwrap|expect)\s*\(", code), "DNS reporting must not panic"


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
        '["*.${var.apps_dns_zone_name}"]' in bootstrap
    )
    assert 'Action   = "route53:ListResourceRecordSets"' in bootstrap
    assert 'Action   = "route53:GetChange"' in bootstrap
    assert 'Resource = "arn:aws:route53:::change/*"' in bootstrap
    assert "route53:GetHostedZone" not in bootstrap


def test_managed_zone_has_protected_sixty_second_negative_cache_ttl():
    bootstrap = (ROOT / "infra-bootstrap" / "main.tf").read_text()
    variables = (ROOT / "infra-bootstrap" / "variables.tf").read_text()

    assert "name          = var.apps_dns_zone_name" in bootstrap
    assert 'default     = "apps.caution.sh"' in variables
    assert 'output "apps_dns_zone_name"' in bootstrap
    assert 'resource "aws_route53_record" "apps_soa"' in bootstrap
    assert "ttl             = 60" in bootstrap
    assert "1209600 60" in bootstrap
    assert bootstrap.count("prevent_destroy = true") >= 2


def test_bootstrap_preserves_operational_platform_credentials():
    bootstrap = (ROOT / "infra-bootstrap" / "main.tf").read_text()
    variables = (ROOT / "infra-bootstrap" / "variables.tf").read_text()

    assert 'variable "create_platform_access_key"' in variables
    assert 'default     = false' in variables
    assert "count = var.create_platform_access_key ? 1 : 0" in bootstrap
    assert "ignore_changes = [tags]" in bootstrap
    assert "try(aws_iam_access_key.platform[0].id, null)" in bootstrap
    entrypoint = (ROOT / "infra-bootstrap" / "entrypoint.sh").read_text()
    _match(
        entrypoint,
        r'"\$TF_CMD"\s+output\s+-json\s*>\s*"\$OUTPUTS_TMP"',
        "read all outputs: Terraform may omit a null optional access key",
    )
    assert "jq -r '.aws_access_key_id.value // empty'" in entrypoint
    key_reads = _match(
        entrypoint,
        r'if \[\[ -n "\$PLATFORM_ACCESS_KEY_ID" \]\]; then(?P<body>.*?)^fi',
        "only retrieve credentials when a platform key was created",
    )['body']
    for output in ("aws_access_key_id", "aws_secret_access_key"):
        command = f'"$TF_CMD" output -raw {output}'
        assert command in key_reads
        assert entrypoint.count(command) == 1, "no unconditional credential reads"


def test_pending_deploy_updates_are_attempt_owned():
    migration = (
        ROOT / "src" / "api" / "migrations" / "052_deploy_attempt_ownership.sql"
    ).read_text()
    api = (ROOT / "src" / "api" / "src" / "main.rs").read_text()
    deploy = _rust_item(api, r"fn\s+deploy_logic")
    recovery = _rust_item(api, r"fn\s+recover_deploy_failure")
    handler = _rust_item(api, r"fn\s+deploy_handler")
    lost_finalization = _match(
        deploy,
        r"let Some\(\(initial_dns_status, initial_dns_error\)\)\s*=\s*"
        r"resource_update\??\s+else\s*\{(?P<body>.*?)^    \};",
        "finalization must reject an update that lost attempt ownership",
    )['body']

    assert "ADD COLUMN IF NOT EXISTS deploy_attempt_id UUID" in migration
    assert "state = 'pending' AND deploy_attempt_id = $4" in recovery
    assert "AND deploy_attempt_id = $5" in handler
    assert "AND deploy_attempt_id = $9" in deploy
    assert "SET state = $1, deploy_attempt_id = NULL" in recovery
    assert "fully_managed_capacity::release_reservation" in lost_finalization
    assert ".recover_failure(" in lost_finalization
    assert "DeployLogicError::PublishConflict" in lost_finalization
    assert "return Err(error)" in lost_finalization
    target_recovery = _rust_item(
        _rust_item(api, r"impl\s+DeployTarget"), r"fn\s+recover_failure"
    )
    _match(
        target_recovery,
        r"Self::Legacy\s*\{[^}]*\}\s*=>\s*\{\s*"
        r"if let Err\(recover_error\) = recover_deploy_failure\(\s*"
        r"state,\s*org_id,\s*resource_id,\s*deploy_attempt_id,",
        "legacy conflicts must recover using their own attempt id",
    )
    _match(
        _rust_item(api, r"impl\s+DeployLogicError"),
        r'DeployLogicError::PublishConflict\s*\{[^}]*\}\s*=>\s*\(\s*'
        r'StatusCode::CONFLICT,\s*'
        r'"Deployment completed after the app lifecycle changed; refusing to publish it"',
        "lost ownership must retain the conflict response, not report success",
    )


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


def test_dns_reconciliation_only_retries_publishing_rows():
    api = (ROOT / "src" / "api" / "src" / "main.rs").read_text()
    reconcile = api.split("async fn reconcile_managed_dns", 1)[1]
    reconcile = reconcile.split("#[tokio::main]", 1)[0]

    assert "dns_status = 'publishing'" in reconcile
    assert "publish_resource(&db, resource_id)" in reconcile
    assert "dns_status = 'reserved'" not in reconcile
    assert "wait_for_health" not in reconcile
    assert "wait_for_attestation_health" not in reconcile
    assert "mark_publishing" not in reconcile


def test_deploy_reporting_does_not_depend_on_post_commit_dns_reads():
    api = (ROOT / "src" / "api" / "src" / "main.rs").read_text()
    managed_dns = (ROOT / "src" / "api" / "src" / "managed_dns.rs").read_text()
    deploy = _rust_item(api, r"fn\s+deploy_logic")
    deploy_finalize = deploy[_match(
        deploy, r"\blet\s+resource_update\b", "legacy deployment finalization is required"
    ).start():]
    publish = _rust_item(managed_dns, r"fn\s+publish_resource")
    publish_once = _rust_item(managed_dns, r"fn\s+publish_once")
    publish_report = _rust_item(api, r"fn\s+publish_managed_dns")

    assert "RETURNING dns_status, dns_error" in deploy_finalize
    assert "dns_snapshot" not in deploy_finalize
    _match(
        deploy_finalize,
        r"let initial_dns\s*=\s*managed_dns::DnsSnapshot\s*\{\s*"
        r"status: initial_dns_status,\s*error: initial_dns_error,?\s*\};\s*"
        r"let dns\s*=\s*publish_managed_dns\(&state, &tx, resource_id, initial_dns\)\.await;",
        "report the snapshot returned by the guarded update, not a subsequent read",
    )
    assert "dns_status: dns.status" in deploy_finalize
    assert "dns_error: dns.error" in deploy_finalize
    _assert_infallible_reporting(deploy_finalize[deploy_finalize.index("let initial_dns"):])

    assert "dns_snapshot" not in publish_report
    assert "-> managed_dns::DnsSnapshot" in publish_report
    _match(
        publish_report,
        r'if initial_dns.status != "publishing"\s*\{\s*return initial_dns;',
        "do not publish or overwrite an unchanged snapshot",
    )
    _match(
        publish_report,
        r"let Some\(managed_dns\) = state.managed_dns.as_ref\(\) else\s*\{\s*return initial_dns;",
        "disabled managed DNS must preserve the snapshot",
    )
    assert "managed_dns.publish_resource(&state.db, resource_id).await" in publish_report
    assert "Ok(dns) => dns" in publish_report
    publication_error = _match(
        publish_report, r"Err\(error\) =>\s*\{(?P<body>.*?)^        \}",
        "publication failure must be captured in the response snapshot",
    )['body']
    assert "status: initial_dns.status" in publication_error
    assert "error: Some(managed_dns::sanitize_error(&error))" in publication_error
    _assert_infallible_reporting(publication_error)

    ready = _match(
        publish, r"Ok\(PublishProgress::Ready\) =>\s*\{(?P<body>.*?)^                \}",
        "successful publication must return a constructed ready snapshot",
    )['body']
    assert "return Ok(DnsSnapshot" in ready
    assert 'status: "ready".to_string()' in ready
    assert "error: None" in ready
    assert "dns_snapshot" not in publish
    _assert_infallible_reporting(ready)
    _match(
        publish_once,
        r"SET dns_status = 'ready'.*?tx\.commit\(\)\.await\.with_context\(Ctx::commit\(\)\)\?;\s*"
        r"return Ok\(PublishProgress::Ready\);",
        "return Ready directly after the publication transaction commits",
    )


def test_candidate_dns_reporting_keeps_post_commit_read_failures_nonfatal():
    api = (ROOT / "src" / "api" / "src" / "main.rs").read_text()
    lifecycle = (ROOT / "src" / "api" / "src" / "app_deployments" / "lifecycle.rs").read_text()
    deploy = _rust_item(api, r"fn\s+deploy_logic")
    candidate = _match(
        deploy,
        r"if let DeployTarget::Candidate\s*\{ deployment_id \} = deploy_target\s*\{"
        r"(?P<body>.*?)^    \}",
        "candidate deployments need their own reporting contract",
    )['body']
    committed = candidate[_match(
        candidate, r"let activation\s*=\s*activation\?;", "activation must complete before reporting"
    ).end():]
    _assert_infallible_reporting(committed)
    _match(
        committed,
        r"\(Role::Live, Some\(initial_dns\)\) =>\s*\{\s*"
        r"publish_managed_dns\(&state, &tx, resource_id, initial_dns\)\.await\s*\}",
        "a newly live deployment must publish the transaction's snapshot",
    )
    _match(
        committed,
        r"_ => managed_dns::dns_snapshot\(&state.db, resource_id\)\s*\.await\s*"
        r"\.unwrap_or_else\(\|error\|\s*\{.*?managed_dns::DnsSnapshot\s*\{\s*"
        r'status: "unknown".to_string\(\),\s*error: None,?\s*\}',
        "non-live candidate DNS lookup failures must fall back to unknown, not fail deployment",
    )
    assert "return Ok(DeployResponse" in committed
    assert "dns_status: dns.status" in committed
    assert "dns_error: dns.error" in committed

    projection = _rust_item(lifecycle, r"fn\s+project_live")
    activation = _rust_item(lifecycle, r"fn\s+complete_running_with")
    assert "RETURNING cr.dns_status, cr.dns_error" in projection
    assert "Ok(managed_dns::DnsSnapshot { status, error })" in projection
    assert "dns_snapshot" not in projection
    assert "dns_snapshot" not in activation
    _match(
        activation,
        r"let dns = project_live\(\s*&mut tx,.*?"
        r"tx\.commit\(\)\.await\.with_context\(Ctx::database\(\)\)\?;\s*"
        r"Ok\(Activation\s*\{\s*role: Role::Live,\s*"
        r"live_deployment_id: Some\(deployment.id\),\s*dns: Some\(dns\),",
        "live activation must carry the transaction's DNS snapshot across commit",
    )


def test_unsuspend_compensates_failed_readiness_without_publishing_dns():
    suspension = (ROOT / "src" / "api" / "src" / "suspension.rs").read_text()
    unsuspend = suspension.split("pub async fn unsuspend_org_resources", 1)[1]
    unsuspend = unsuspend.split("fn instance_lookup_filters", 1)[0]

    assert "started_instance_ids" in unsuspend
    assert ".stop_instances(&started_instance_ids)" in unsuspend
    assert "degraded_readiness_error.is_none()" in unsuspend
    assert "recording app as running and metered" in unsuspend
    assert "WHEN $6::text IS NOT NULL THEN $6" in unsuspend


def test_health_poller_timeout_reports_health_endpoint():
    api = (ROOT / "src" / "api" / "src" / "main.rs").read_text()
    health = _rust_item(api, r"fn\s+wait_for_health")
    _match(
        health,
        r"if start.elapsed\(\) >= timeout\s*\{\s*"
        r"return Err\(WaitForHealthError::HealthTimeout\s*\{\s*timeout_secs,",
        "the health poller must return the health-specific timeout with its duration",
    )
    assert "WaitForHealthError::AttestationTimeout" not in health
    client_message = _rust_item(
        _rust_item(api, r"impl\s+WaitForHealthError"), r"fn\s+client_message"
    )
    health_message = _match(
        client_message,
        r"Self::HealthTimeout\s*\{[^}]*\}\s*=>\s*\{(?P<body>.*?)^            \}",
        "health timeout must have a dedicated client message",
    )['body']
    _match(
        health_message,
        r'format!\(\s*"Health endpoint did not become healthy within \{\} seconds",\s*'
        r'timeout_secs\s*\)',
        "preserve the health endpoint timeout wording and duration without locations",
    )
    assert "Attestation endpoint" not in health_message


def test_owned_tombstone_delete_is_idempotent_and_unknown_ids_stay_hidden():
    resources = (ROOT / "src" / "api" / "src" / "resources.rs").read_text()
    delete = _rust_item(resources, r"fn\s+delete_resource")
    response = _rust_item(resources, r"impl\s+IntoResponse\s+for\s+DeleteResourceError")

    assert "cr.destroyed_at IS NOT NULL" in delete
    assert "INNER JOIN organization_members om ON cr.organization_id = om.organization_id" in delete
    assert "WHERE cr.id = $1 AND om.user_id = $2" in delete
    assert ".bind(auth.user_id)" in delete
    missing = _match(
        delete,
        r"let Some\([^\n]+\) = resource else\s*\{(?P<body>.*?)^    \};",
        "absent and inaccessible IDs must share the same not-found branch",
    )
    assert "return Err(DeleteResourceError::NotFound" in missing['body']
    tombstone = _match(
        delete, r"if destroyed\s*\{\s*return Ok\(StatusCode::NO_CONTENT\);\s*\}",
        "an owned tombstone must delete idempotently",
    )
    assert missing.end() < tombstone.start() < delete.index('"UPDATE compute_resources')
    assert delete.count("StatusCode::NO_CONTENT") >= 2
    assert "state = 'terminating' AND deploy_attempt_id IS NOT NULL" in delete
    for kind, variant in (("Deploying", "Deploying"), ("Gone", "AlreadyGone")):
        _match(
            delete,
            rf"DestroyResourceByIdErrorKind::{kind}\s*=>\s*\{{\s*"
            rf"return Err\(DeleteResourceError::{variant}\b",
            f"destroy failure {kind} must retain its typed response",
        )
    for variant in ("NotFound", "AlreadyGone"):
        _match(
            response,
            rf'DeleteResourceError::{variant}\s*\{{[^}}]*\}}\s*=>\s*'
            r'\(StatusCode::NOT_FOUND, "app not found"\)',
            "unknown and inaccessible IDs must retain the same generic 404 body",
        )
    _match(
        response,
        r'DeleteResourceError::Deploying\s*\{[^}]*\}\s*=>\s*\{\s*'
        r'\(StatusCode::CONFLICT, "resource is deploying"\)',
        "an in-flight deployment must still prevent deletion with 409",
    )
    assert "sentry_middleware::error_response(status, body, self)" in response


if __name__ == "__main__":
    import unittest

    suite = unittest.TestSuite(
        unittest.FunctionTestCase(test)
        for name, test in list(globals().items())
        if name.startswith("test_") and callable(test)
    )
    if not suite.countTestCases():
        raise SystemExit("No managed DNS contract tests found")
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
