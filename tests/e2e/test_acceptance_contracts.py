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
curl() { printf '%s' "${FAKE_HTTP_BODY:-}"; }
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

    def test_live_keymaker_requires_explicit_opt_in(self):
        block = section("test_secret_new.sh", 'if [ -z "${KEYMAKER_URL:-}" ]; then', "WORK_DIR=$(mktemp -d)")
        for keymaker, opt_in, expected in (("http://example.invalid", "", 2),
                                          ("", "1", 2),
                                          ("http://example.invalid", "1", 0)):
            with self.subTest(keymaker=keymaker, opt_in=opt_in):
                result = self.run_block(block, KEYMAKER_URL=keymaker, ALLOW_LIVE_KEYMAKER_E2E=opt_in)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)

    def test_secret_new_failed_assertion_cannot_exit_successfully(self):
        block = section("test_secret_new.sh", "cleanup() {", "step_pass() {")
        setup = 'WORK_DIR="$PWD/owned"; mkdir "$WORK_DIR"; LOG_FILE=/dev/null; STEPS_FAILED=1; STEPS_PASSED=0; STEP_RESULTS=()\n'
        result = self.run_block(setup + block + "\nexit 0\n")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_configured_byoc_dns_is_exact(self):
        # Run the actual DNS assertion independently of provisioning.
        text = (HERE / SCRIPTS[1]).read_text()
        marker = '# Verify the managed DNS target'
        if marker in text:
            block = section(SCRIPTS[1], marker, '# Verify git remote was set')
        else:
            block = section(SCRIPTS[1], 'if ! echo "$INIT_OUTPUT" | grep -Eq \'DNS target:', '# Extract resource ID')
        for suffix in ("apps.caution.sh", "apps.example.test"):
            with self.subTest(suffix=suffix):
                values = dict(RESOURCE_ID="resource-123", CAUTION_APPS_DNS_SUFFIX=suffix,
                              INIT_OUTPUT=f"DNS target: resource-123.{suffix}")
                self.assertEqual(self.run_block(block, **values).returncode, 0)
                for wrong in (f"other.{suffix}", f"resource-123.{suffix}.evil.test", ""):
                    values["INIT_OUTPUT"] = "DNS target: " + wrong
                    self.assertNotEqual(self.run_block(block, **values).returncode, 0)


if __name__ == "__main__":
    unittest.main()
