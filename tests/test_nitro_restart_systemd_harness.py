#!/usr/bin/env python3
"""Offline safety regressions for the fake-Nitro systemd harness."""
import os
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import test_nitro_restart_systemd as harness


class ReachedExercise(Exception):
    """Stop at the first exercise before creating files or user units."""


class HarnessTests(unittest.TestCase):
    def run_until_exercise(self, query_result):
        def manager_query(args, **kwargs):
            if args == ("systemctl", "--user", "is-system-running"):
                return subprocess.CompletedProcess(args, 1, "degraded\n", "")
            self.assertEqual(args, ("systemctl", "--user", "show", "--property=Version", "--value"))
            if isinstance(query_result, Exception):
                raise query_result
            return subprocess.CompletedProcess(args, *query_result)

        with patch.object(sys, "argv", [harness.__file__, "/unused-artifacts"]), \
                patch.object(subprocess, "run", side_effect=manager_query) as query, \
                patch.object(tempfile, "TemporaryDirectory", side_effect=ReachedExercise) as exercise:
            try:
                runpy.run_path(harness.__file__, run_name="__main__")
            except Exception as error:
                return error, query, exercise
        self.fail("Harness returned without reaching an exercise or rejecting the manager")

    def test_degraded_but_responsive_manager_reaches_exercise(self):
        error, query, exercise = self.run_until_exercise((0, "252\n", ""))
        self.assertIsInstance(error, ReachedExercise, str(error))
        query.assert_called_once()
        exercise.assert_called_once()


    def test_unavailable_or_nonfunctional_manager_aborts_before_exercise(self):
        for result, expected in [
            ((1, "", "Failed to connect to bus: No medium found"), AssertionError),
            ((1, "", "Failed to get properties: Access denied"), AssertionError),
            (subprocess.TimeoutExpired("systemctl", 20), subprocess.TimeoutExpired),
            (FileNotFoundError("systemctl"), FileNotFoundError),
        ]:
            with self.subTest(result=result):
                error, query, exercise = self.run_until_exercise(result)
                self.assertIsInstance(error, expected)
                if isinstance(result, tuple):
                    self.assertIn(result[2], str(error))
                query.assert_called_once()
                exercise.assert_not_called()

    def make_artifacts(self, directory):
        for name in ("start-nitro-enclave", "stop-nitro-enclave", "capture-enclave-console.sh"):
            (directory / name).write_text("#!/bin/sh\nexit 0\n")
        blocks = []
        for name, dependencies in [
            ("nitro-enclave.service", "nitro-enclaves-allocator.service caution-network-policy.service"),
            ("nitro-enclave-console.service", "nitro-enclave.service"),
            ("vsock-proxy-http.service", "caution-network-policy.service"),
        ]:
            blocks.append(f"cat > /etc/systemd/system/{name} <<EOF\n"
                          f"[Unit]\nRequires={dependencies}\nAfter={dependencies}\n"
                          "[Service]\nExecStart=/usr/bin/true\nEOF\n")
        (directory / "user-data.sh").write_text("".join(blocks))

    def test_failed_first_link_does_not_run_unscoped_cleanup(self):
        calls = []

        def systemctl(*args, **kwargs):
            calls.append(args)
            if args[0] == "link":
                raise RuntimeError("link failed")
            return subprocess.CompletedProcess(args, 0, "", "")

        with tempfile.TemporaryDirectory(prefix="caution-restart-harness-") as temp:
            directory = Path(temp)
            self.make_artifacts(directory)
            with patch.dict(os.environ, XDG_RUNTIME_DIR=temp), \
                    patch.object(harness, "systemctl", side_effect=systemctl), \
                    self.assertRaisesRegex(RuntimeError, "link failed"):
                harness.exercise(directory, "no", False)
        self.assertEqual([args[0] for args in calls], ["link"], calls)

    def test_network_policy_dependency_is_isolated_and_cleaned_up(self):
        bodies = {}
        calls = []

        def systemctl(*args, **kwargs):
            calls.append(args)
            if args[0] == "link":
                path = Path(args[2])
                bodies[path.name] = path.read_text()
            elif args[0] == "start":
                raise RuntimeError("stop before starting units")
            return subprocess.CompletedProcess(args, 0, "", "")

        with tempfile.TemporaryDirectory(prefix="caution-restart-harness-") as temp:
            directory = Path(temp)
            self.make_artifacts(directory)
            with patch.dict(os.environ, XDG_RUNTIME_DIR=temp), \
                    patch.object(harness, "systemctl", side_effect=systemctl), \
                    patch.object(harness, "run") as verify, \
                    patch("builtins.print"), \
                    self.assertRaisesRegex(RuntimeError, "stop before starting units"):
                harness.exercise(directory, "no", False)
            self.assertEqual(verify.call_args.args[:3], ("systemd-analyze", "--user", "verify"))
        for name, body in bodies.items():
            self.assertNotIn("caution-network-policy.service", body, name)
            for line in body.splitlines():
                if line.startswith(("Requires=", "After=")):
                    for dependency in line.split("=", 1)[1].split():
                        self.assertIn(dependency, bodies, name)
        policy = [name for name in bodies if name.endswith("-policy.service")]
        self.assertEqual(len(policy), 1)
        self.assertIn("ExecStart=/usr/bin/true\n", bodies[policy[0]])
        self.assertIn("RemainAfterExit=yes\n", bodies[policy[0]])
        for command in ("stop", "reset-failed"):
            cleanup = [args[1:] for args in calls if args[0] == command]
            self.assertEqual(cleanup, [tuple(bodies)])


if __name__ == "__main__":
    unittest.main(verbosity=2)
