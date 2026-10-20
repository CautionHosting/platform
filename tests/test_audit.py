# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
"""Exercise the deployment audit gate without network access or live services."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class AuditGateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name)
        self.log = self.work / "calls.jsonl"
        self.bin = self.work / "bin"
        self.bin.mkdir()
        recorder = self.bin / "recorder"
        recorder.write_text("""#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

command = Path(sys.argv[0]).name
args = sys.argv[1:]
if command == "git":
    sys.exit(0)
with open(os.environ["AUDIT_TEST_LOG"], "a") as stream:
    stream.write(json.dumps([command, *args]) + "\\n")
if command == "docker":
    check = ""
    if args[:2] == ["run", "--rm"]:
        if args[2] == "caution-npm-audit":
            check = "npm"
        elif args[2] == "caution-cargo-audit":
            check = args[-1]
    elif args and args[0] == "build":
        check = "build"
    if check and check == os.environ.get("AUDIT_TEST_FAILURE"):
        sys.exit(int(os.environ["AUDIT_TEST_STATUS"]))
""")
        recorder.chmod(0o755)
        for name in ("docker", "git", "systemctl", "test-event"):
            (self.bin / name).symlink_to(recorder)
        makefile = (ROOT / "Makefile").read_text()
        for target in ("build-api", "build-gateway", "build-email", "build-metering",
                       "prepare-components", "migrate", "network", "postgres",
                       "fetch/opentofu-$(TOFU_VERSION).tar.gz"):
            makefile += f"\n{target}:\n\t@test-event {target}\n"
        (self.work / "Makefile").write_text(makefile)
        (self.work / "src/cli").mkdir(parents=True)
        shutil.copyfile(ROOT / "src/cli/Cargo.toml", self.work / "src/cli/Cargo.toml")
        self.env = {
            "PATH": f"{self.bin}:{os.defpath}",
            "HOME": str(self.work),
            "AUDIT_TEST_LOG": str(self.log),
        }

    def invoke(self, *targets, failure="", status=1):
        self.log.write_text("")
        result = subprocess.run(
            ["make", "--no-print-directory", "-j4", *targets], cwd=self.work,
            env={**self.env, "AUDIT_TEST_FAILURE": failure, "AUDIT_TEST_STATUS": str(status)},
            capture_output=True, text=True, timeout=15,
        )
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        return result, calls

    def test_audit_failure_blocks_all_deployment_work_even_with_parallel_make(self):
        for failure in ("build", "npm", "Cargo.lock", "src/tap-framer/Cargo.lock"):
            for status in (1, 2, 124):
                with self.subTest(failure=failure, status=status):
                    result, calls = self.invoke("up", failure=failure, status=status)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertTrue(calls)
                    self.assertTrue(all(call[0] == "docker" for call in calls), calls)
                    self.assertTrue(all(
                        "caution-npm-audit" in call or "caution-cargo-audit" in call
                        for call in calls), calls)


if __name__ == "__main__":
    unittest.main()
