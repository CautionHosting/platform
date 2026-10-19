#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
"""Regression guard for per-command startup cost; runs real offline fixture."""
import importlib.util
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(os.environ.get("PLATFORM_TEST_ROOT", Path(__file__).resolve().parents[1]))
spec = importlib.util.spec_from_file_location(
    "ports_contracts", ROOT / "tests/e2e/test_platform_ports_contracts.py"
)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class HelperImports(unittest.TestCase):
    def test_command_double_does_not_load_unittest(self):
        fixture = module.PlatformPortsContracts("test_success_remains_success")
        self.addCleanup(fixture.doCleanups)
        result, _, work = fixture.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        root = work.parent.parent
        probe = subprocess.run([str(root / "bin/sleep"), "0"], env={
            "FAKE_ROOT": str(root), "PYTHONPROFILEIMPORTTIME": "1",
        }, capture_output=True, text=True, timeout=10)
        self.assertEqual(probe.returncode, 0, probe.stderr)
        loaded = [line.rsplit("|", 1)[-1].strip() for line in probe.stderr.splitlines()
                  if line.startswith("import time:")]
        self.assertNotIn("unittest", loaded, "Every command double should avoid loading the test framework")


if __name__ == "__main__":
    unittest.main(verbosity=2)
