#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Caution-Commercial
"""Offline negative controls for the actual shell acceptance blocks (not live E2Es)."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SCRIPTS = ("test_happy_path.sh", "test_byoc.sh")
SUCCESS = "Base Nitro attestation and expected PCR0/1/2 verified\nAttestation verification PASSED"


def section(script, start, end):
    text = (HERE / script).read_text()
    return text[text.index(start):text.index(end, text.index(start))]


class AcceptanceContracts(unittest.TestCase):
    def run_block(self, block, **values):
        # Only the acceptance block executes; no live gateway, Docker or AWS calls.
        with tempfile.TemporaryDirectory() as directory:
            cli = Path(directory) / "caution"
            cli.write_text('#!/bin/bash\nprintf "%s\\n" "$FAKE_OUTPUT"\nexit "$FAKE_STATUS"\n')
            cli.chmod(0o700)
            env = {**os.environ, "CAUTION_BIN": str(cli), "GATEWAY_URL": "http://example.invalid",
                   "APP_IP": "192.0.2.1", "RESOURCE_ID": "resource-123",
                   "FAKE_OUTPUT": SUCCESS, "FAKE_STATUS": "0", **values}
            functions = '''set -euo pipefail
log() { :; }
step_fail() { printf 'FAIL: %s\n' "$*"; exit 1; }
step_warn() { printf 'WARN: %s\n' "$*"; }
step_pass() { printf 'PASS: %s\n' "$*"; }
docker() { printf '%s' "$APP_IP"; }
curl() {
    local fail=false arg
    for arg in "$@"; do
        case "$arg" in
            --fail) fail=true;;
            --*) ;;
            -*) case "$arg" in *f*) fail=true;; esac;;
        esac
    done
    if [ "${FAKE_HTTP_STATUS:-200}" -ge 400 ] && [ "$fail" = true ]; then
        return 22
    fi
    printf '%s' "${FAKE_HTTP_BODY:-}"
}
sleep() { :; }
'''
            return subprocess.run(["bash", "-c", functions + block], env=env, cwd=directory,
                                  text=True, capture_output=True, timeout=5)

    def verify_block(self, script):
        end = "# ── Step 10:" if script == SCRIPTS[0] else "# ── Step 9:"
        return section(script, 'log "Running caution verify..."', end)

    def test_full_verification_passes(self):
        for script in SCRIPTS:
            with self.subTest(script=script):
                result = self.run_block(self.verify_block(script))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("PASS:", result.stdout)

    def test_verification_failures_cannot_be_warnings(self):
        for script in SCRIPTS:
            for output in ("PCR0: MISMATCH\nPCR1: MISMATCH\nPCR2: match",
                           "PCR0: match\nPCR1: match\nPCR2: match\nAttestation verification FAILED",
                           "does not include a manifest", "private code", "connection refused", SUCCESS):
                with self.subTest(script=script, output=output):
                    result = self.run_block(self.verify_block(script), FAKE_STATUS="1", FAKE_OUTPUT=output)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertNotIn("WARN:", result.stdout)

    def test_zero_exit_without_verification_evidence_is_rejected(self):
        for script in SCRIPTS:
            for output in ("", *SUCCESS.splitlines()):
                with self.subTest(script=script, output=output):
                    result = self.run_block(self.verify_block(script), FAKE_OUTPUT=output)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_unexpected_or_missing_http_body_is_rejected(self):
        block = section(SCRIPTS[0], '    # This fixture has raw ingress only;', '# ── Step 9:')
        # The selected region ends the enclosing APP_IP condition.
        block = 'if [ -n "$APP_IP" ]; then\n' + block
        for body in ("", "unrelated service"):
            with self.subTest(body=body):
                result = self.run_block(block, FAKE_HTTP_BODY=body)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn("WARN:", result.stdout)
        result = self.run_block(block, FAKE_HTTP_BODY="Hello from Caution.co! Deployment successful!")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_http_error_with_success_body_requires_curl_fail_flag(self):
        block = section(SCRIPTS[0], '    # This fixture has raw ingress only;', '# ── Step 9:')
        block = 'if [ -n "$APP_IP" ]; then\n' + block
        body = 'Hello from Caution.co! Deployment successful!'
        for status in ('404', '500', '503'):
            with self.subTest(status=status):
                result = self.run_block(block, FAKE_HTTP_BODY=body, FAKE_HTTP_STATUS=status)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn('PASS:', result.stdout)
        without_fail = block.replace('curl -fsS', 'curl -sS')
        self.assertNotEqual(without_fail, block, 'negative control must remove curl -f')
        result = self.run_block(without_fail, FAKE_HTTP_BODY=body, FAKE_HTTP_STATUS='500')
        self.assertEqual(result.returncode, 0, 'control must expose missing curl -f')


class ByocConfigurationContracts(unittest.TestCase):
    def test_dns_target_must_match_resource_and_configured_suffix_exactly(self):
        block = section("test_byoc.sh", 'if ! echo "$INIT_OUTPUT" | grep -Eq "Deployment target:',
                        "# Verify git remote was set")
        resource = "123e4567-e89b-12d3-a456-426614174000"
        with tempfile.TemporaryDirectory() as directory:
            deployment = Path(directory) / ".caution"
            deployment.mkdir()
            (deployment / "deployment.json").write_text('{"resource_id":"' + resource + '"}')
            expected = resource + ".apps.example.test"
            for hostname in (expected, expected + ".evil.test", "wrong.apps.example.test",
                             resource + ".apps.caution.sh", resource + ".appsXexampleXtest"):
                with self.subTest(hostname=hostname):
                    env = {**os.environ, "ONPREM_TEST_REGION": "us-east-1",
                           "APPS_DNS_SUFFIX": "apps.example.test",
                           "INIT_OUTPUT": "Deployment target: capacity=BYOC, aws_account=123456789012, region=us-east-1\nDNS target: " + hostname}
                    result = subprocess.run(["bash", "-c", 'set -euo pipefail\nstep_fail() { exit 1; }\n' + block],
                                            cwd=directory, env=env, capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode == 0, hostname == expected, result.stdout + result.stderr)

    def test_suffix_precedence_normalization_and_no_dotenv_execution(self):
        helper = HERE / "lib" / "config.sh"
        self.assertTrue(helper.is_file(), "BYOC needs a side-effect-free suffix resolver")
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            config = home / ".config" / "caution"
            config.mkdir(parents=True)
            marker = home / "should-not-exist"
            env_file = config / ".env"
            env_file.write_text(f'AWS_PROFILE=wrong\nGATEWAY_URL=wrong\ntouch {marker}\n'
                                'CAUTION_APPS_DNS_SUFFIX= Apps.Example.Test... \n')
            env = {k: v for k, v in os.environ.items() if k != "CAUTION_APPS_DNS_SUFFIX"}
            env.update(HOME=directory, AWS_PROFILE="isolated", GATEWAY_URL="http://isolated.invalid")
            command = 'set -euo pipefail; source "$1"; resolve_apps_dns_suffix; printf "%s\\n" "$AWS_PROFILE" "$GATEWAY_URL"'
            for value, expected in ((None, "apps.example.test"), (" Explicit.Example.TEST. ", "explicit.example.test")):
                with self.subTest(value=value):
                    selected = dict(env)
                    if value is not None:
                        selected["CAUTION_APPS_DNS_SUFFIX"] = value
                    result = subprocess.run(["bash", "-c", command, "bash", str(helper)], env=selected,
                                            text=True, capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.splitlines(), [expected, "isolated", "http://isolated.invalid"])
                    self.assertFalse(marker.exists())
            env_file.unlink()
            result = subprocess.run(["bash", "-c", command, "bash", str(helper)], env=env,
                                    text=True, capture_output=True, timeout=5)
            self.assertEqual(result.stdout.splitlines()[0], "apps.caution.sh")
            for invalid in ("", "localhost", "bad..example", "-bad.example", "bad_.example", "a" * 64 + ".test"):
                with self.subTest(invalid=invalid):
                    result = subprocess.run(["bash", "-c", command, "bash", str(helper)],
                                            env={**env, "CAUTION_APPS_DNS_SUFFIX": invalid},
                                            text=True, capture_output=True, timeout=5)
                    self.assertNotEqual(result.returncode, 0)


class BillingConfigurationContracts(unittest.TestCase):
    def run_catalog_preflight(self, block, fixture, wrong="none", failure="mismatch"):
        import io
        import json
        import tarfile

        expected = json.loads(fixture.read_text())
        with tempfile.TemporaryDirectory() as directory:
            for service in ("api", "metering"):
                # Different formatting/key order must still compare equal.
                catalog = json.dumps(dict(reversed(list(expected.items())))).encode()
                if service == wrong:
                    catalog = {"mismatch": b'{"compute_margin_percent":80}',
                               "malformed": b'{"broken":', "empty": b'',
                               "trailing_garbage": catalog + b'not-json'}.get(failure, catalog)
                archive = io.BytesIO()
                with tarfile.open(fileobj=archive, mode="w") as stream:
                    member = tarfile.TarInfo("prices.json")
                    member.size = len(catalog)
                    stream.addfile(member, io.BytesIO(catalog))
                data = archive.getvalue()
                if service == wrong and failure == "truncated_archive":
                    # JSON is complete, but tar must still report a read error.
                    data = data[:512 + len(catalog)]
                if service == wrong and failure == "invalid_archive":
                    data = b'not a tar archive'
                (Path(directory) / (service + ".tar")).write_bytes(data)
            docker = '''
# Only host tools run here; the fake images have neither a shell nor cat.
docker() {
    if [ "$1" = exec ]; then
        printf '%s' 'OCI runtime exec failed: exec: "cat": executable file not found'
        return 127
    fi
    [ "$#" = 3 ] && [ "$1" = cp ] && [ "$3" = - ] || return 99
    case "$2" in
        api:/app/prices.json) service=api;;
        metering:/app/prices.json) service=metering;;
        *) return 99;;
    esac
    if [ "$service" = "$WRONG_SERVICE" ] && [ "$FAILURE" = unreadable ]; then
        printf '%s\\n' 'Error: could not read /app/prices.json' >&2
        return 1
    fi
    cat "$ARCHIVES/$service.tar" || return 1
    if [ "$service" = "$WRONG_SERVICE" ] && [ "$FAILURE" = copy_failed ]; then
        return 1
    fi
}
'''
            return subprocess.run(["bash", "-c", docker + block],
                                  env={**os.environ, "ARCHIVES": directory,
                                       "WRONG_SERVICE": wrong, "FAILURE": failure},
                                  text=True, capture_output=True, timeout=5)

    def test_billing_suites_check_catalog_before_mutating_state(self):
        for script, fixture in (("test_billing.sh", "prices-billing.json"),
                                ("test_paddle_subscriptions.sh", "prices-paddle-subscriptions.json")):
            prefix = (HERE / script).read_text().split("GATEWAY_URL=", 1)[0]
            prefix = prefix.replace('$(dirname "${BASH_SOURCE[0]}")', str(HERE))
            for wrong in ("none", "api", "metering"):
                with self.subTest(script=script, wrong=wrong):
                    result = self.run_catalog_preflight(prefix, HERE / "fixtures" / fixture, wrong)
                    self.assertEqual(result.returncode == 0, wrong == "none", result.stderr)
                    if wrong != "none":
                        self.assertIn(wrong + " pricing must match", result.stderr)

    def test_make_pins_billing_fixture_and_both_services_mount_prices(self):
        root = HERE.parent.parent
        # Even recursive Make recipes cannot execute with this shell. Inspect
        # the actual expanded recipes without builds, services, or providers.
        def recipe(target):
            result = subprocess.run(["make", "--no-print-directory", "-n", target,
                                     "SHELL=/bin/true", "PRICES_FILE=/operator/prices.json"],
                                    cwd=root, env={**os.environ, "PWD": str(root)},
                                    text=True, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout
        fixture = str(root / "tests/e2e/fixtures/prices-billing.json")
        self.assertIn('PRICES_FILE="' + fixture + '"', recipe("test-e2e-billing"))
        for target in ("run-api-test", "run-metering-test"):
            self.assertIn('-v "/operator/prices.json:/app/prices.json:ro"', recipe(target))
        self.assertIn("prices-paddle-subscriptions.json", recipe("test-e2e-paddle-subscriptions"))

    def test_billing_catalog_preflight_rejects_either_wrong_service(self):
        fixture = HERE / "fixtures" / "prices-billing.json"
        block = f'''set -euo pipefail
source "{HERE / 'lib/config.sh'}"
require_prices_fixture "{fixture}" api metering
'''
        for wrong in ("none", "api", "metering"):
            with self.subTest(wrong=wrong):
                result = self.run_catalog_preflight(block, fixture, wrong)
                self.assertEqual(result.returncode == 0, wrong == "none", result.stderr)
                if wrong != "none":
                    self.assertIn(wrong + " pricing must match", result.stderr)
                    self.assertIn("Make target", result.stderr)

    def test_billing_catalog_preflight_rejects_read_errors_for_either_service(self):
        fixture = HERE / "fixtures" / "prices-billing.json"
        for pipefail in ("off", "on"):
            block = f'''set -eu
set {'-o' if pipefail == 'on' else '+o'} pipefail
source "{HERE / 'lib/config.sh'}"
require_prices_fixture "{fixture}" api metering
'''
            for service in ("api", "metering"):
                for failure in ("unreadable", "copy_failed", "invalid_archive",
                                "truncated_archive", "malformed", "trailing_garbage", "empty"):
                    with self.subTest(pipefail=pipefail, service=service, failure=failure):
                        result = self.run_catalog_preflight(block, fixture, service, failure)
                        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertIn(service + " pricing must match", result.stderr)

    def test_billing_catalog_preflight_rejects_invalid_reference_fixture(self):
        fixture = HERE / "fixtures" / "prices-billing.json"
        with tempfile.TemporaryDirectory() as directory:
            reference = Path(directory) / "prices.json"
            for content in (None, "", '{"broken":'):
                with self.subTest(content=content):
                    if content is not None:
                        reference.write_text(content)
                    block = f'''set -euo pipefail
source "{HERE / 'lib/config.sh'}"
require_prices_fixture "{reference}" api
'''
                    result = self.run_catalog_preflight(block, fixture, "api", "empty")
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_projection_oracle_covers_nonzero_fallback_margin(self):
        import json
        fixture = HERE / "fixtures" / "prices-billing.json"
        self.assertTrue(fixture.is_file(), "Billing needs its own deterministic pricing fixture")
        self.assertEqual(json.loads(fixture.read_text())["compute_margin_percent"], 25)
        block = section("test_billing.sh", "EXPECTED_PROJECTION=$(", "# ── Step 37:")
        with tempfile.TemporaryDirectory() as directory:
            # Evaluate the real SQL's arithmetic locally, fixing only its month
            # duration. This is not a PostgreSQL/API integration test.
            docker = Path(directory) / "docker"
            docker.write_text('''#!/usr/bin/env python3
import re, sqlite3, sys
query = re.sub(r"EXTRACT\\(EPOCH FROM \\(.*\\)\\)", "744 * 3600", sys.argv[-1], flags=re.S)
print(sqlite3.connect(":memory:").execute(query).fetchone()[0])
''')
            docker.chmod(0o700)
            functions = '''set -euo pipefail
step_fail() { printf '%s\\n' "$*"; exit 1; }
step_pass() { :; }
curl() { printf '%s' "$RESPONSE"; }
'''
            # 31 days: $2 actual + 744h * ($0.50 ledger + $0.24 fallback).
            # Negative controls omit margin, double it, or include extra runners.
            for projected in (552.56, 516.848, 597.2, 731.12):
                with self.subTest(projected=projected):
                    env = {**os.environ, "PATH": directory + os.pathsep + os.environ["PATH"],
                           "TEST_DB_HOST": "unused", "GATEWAY_URL": "unused", "SESSION_ID": "unused",
                           "RESPONSE": json.dumps({"total_cost": 2, "projected_cost": projected})}
                    result = subprocess.run(["bash", "-c", functions + block], env=env,
                                            text=True, capture_output=True, timeout=5)
                    self.assertEqual(result.returncode == 0, projected == 552.56, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
