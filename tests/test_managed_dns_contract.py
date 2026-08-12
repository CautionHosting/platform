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
