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


if __name__ == "__main__":
    unittest.main()
