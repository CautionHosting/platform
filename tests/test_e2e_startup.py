#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
"""Offline startup contracts; no Docker daemon, builds, credentials, or cloud.

The ignore test checks source boundaries, not Docker COPY cache behavior.
"""
import fnmatch
import http.server
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class DockerContextTests(unittest.TestCase):
    def test_only_generated_e2e_directories_are_excluded(self):
        patterns = [line.strip().strip("/") for line in
                    (ROOT / ".dockerignore").read_text().splitlines()
                    if line.strip() and not line.startswith("#")]

        def excluded(path):
            parts = Path(path).parts
            ancestors = ["/".join(parts[:i]) for i in range(1, len(parts) + 1)]
            return any(fnmatch.fnmatchcase(part, pattern)
                       for pattern in patterns for part in ancestors)

        for path in ("tests/e2e/logs/run/output.log",
                     "tests/e2e/browser-authenticator/node_modules/pkg/index.js"):
            with self.subTest(path=path):
                self.assertTrue(excluded(path), f"generated content enters context: {path}")
        for path in ("tests/e2e/browser-authenticator/package.json",
                     "tests/e2e/browser-authenticator/package-lock.json",
                     "tests/e2e/browser-authenticator/app-deployments.mjs",
                     "tests/e2e/fixtures/prices-billing.json",
                     "tests/e2e/test_happy_path.sh", "Cargo.toml", "Cargo.lock",
                     "src/api/Cargo.toml", "src/api/src/main.rs"):
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).is_file(), path)
                self.assertFalse(excluded(path), f"source excluded: {path}")
        self.assertEqual([p for p in patterns if p.startswith("tests/")], [
            "tests/e2e/logs", "tests/e2e/browser-authenticator/node_modules"])


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        path = ROOT / "scripts/wait-ready.py"
        self.assertTrue(path.is_file(), "bounded readiness helper is missing")
        spec = importlib.util.spec_from_file_location("wait_ready", path)
        assert spec is not None and spec.loader is not None
        self.ready = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.ready)
        self.clock = FakeClock()
        self.addCleanup(patch.stopall)
        patch.object(self.ready.time, "monotonic", self.clock.monotonic).start()
        patch.object(self.ready.time, "sleep", self.clock.sleep).start()

    def test_immediate_probe_has_no_initial_sleep(self):
        budgets = []
        self.assertTrue(self.ready.wait_ready(lambda budget: budgets.append(budget) or True))
        self.assertEqual(budgets, [2.0])
        self.assertEqual(self.clock.sleeps, [])

    def test_delayed_readiness_retries_without_fixed_delay(self):
        attempts = []

        def probe(budget):
            attempts.append((self.clock.now, budget))
            return len(attempts) == 3

        self.assertTrue(self.ready.wait_ready(probe, timeout=0.75))
        self.assertEqual([t for t, _ in attempts], [0.0, 0.2, 0.4])
        for started, budget in attempts:
            self.assertAlmostEqual(budget, min(2.0, 0.75 - started))

    def test_never_ready_uses_bounded_default_total(self):
        attempts = []
        self.assertFalse(self.ready.wait_ready(lambda budget: attempts.append(budget) or False))
        self.assertAlmostEqual(self.clock.now, 60.0)
        self.assertGreater(len(attempts), 1)
        self.assertTrue(all(0 < budget <= 2.0 for budget in attempts))
        self.assertTrue(all(0 < delay <= 0.2 for delay in self.clock.sleeps))

    def test_hung_probe_uses_remaining_budget(self):
        budgets = []

        def probe(budget):
            budgets.append(budget)
            self.clock.now += budget
            raise subprocess.TimeoutExpired("offline-probe", budget)

        self.assertFalse(self.ready.wait_ready(probe, timeout=2.5))
        self.assertEqual(len(budgets), 2)
        self.assertEqual(budgets[0], 2.0)
        self.assertAlmostEqual(budgets[1], 0.3)
        self.assertAlmostEqual(self.clock.now, 2.5)

    def test_success_at_or_after_deadline_is_rejected(self):
        for elapsed in (0.5, 0.51):
            with self.subTest(elapsed=elapsed):
                self.clock.now = 0

                def probe(budget):
                    self.clock.now += elapsed
                    return True

                self.assertFalse(self.ready.wait_ready(probe, timeout=0.5))

    def test_oversleep_does_not_start_a_late_probe(self):
        attempts = []

        def oversleep(delay):
            self.clock.now += 1

        with patch.object(self.ready.time, "sleep", oversleep):
            self.assertFalse(self.ready.wait_ready(
                lambda budget: attempts.append(budget) or False, timeout=0.5))
        self.assertEqual(attempts, [0.5])

    def test_invalid_timeout_fails_before_probe(self):
        for timeout in (0, -1, float("nan"), float("inf")):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                self.ready.wait_ready(lambda budget: self.fail("unexpected probe"), timeout)


class ProbeTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("wait_ready", ROOT / "scripts/wait-ready.py")
        assert spec is not None and spec.loader is not None
        self.ready = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.ready)

    def test_http_requires_successful_curl_and_exact_200(self):
        self.assertTrue(hasattr(self.ready, "http_ready"), "HTTP probe is missing")
        for code, output, expected in ((0, b"200", True), (28, b"200", False),
                                       (0, b"302", False), (0, b"204", False),
                                       (0, b"200200", False)):
            with self.subTest(code=code, output=output), patch.object(
                    self.ready.subprocess, "run",
                    return_value=subprocess.CompletedProcess([], code, output)) as run:
                self.assertEqual(self.ready.http_ready("http://127.0.0.1/health", 0.4), expected)
                argv = run.call_args.args[0]
                self.assertEqual(argv[:2], ["curl", "--disable"])
                self.assertNotIn("--location", argv)
                self.assertEqual(float(argv[argv.index("--max-time") + 1]), 0.4)
                self.assertEqual(run.call_args.kwargs["timeout"], 0.4)
                self.assertEqual(run.call_args.kwargs["stderr"], subprocess.DEVNULL)

    def test_submillisecond_curl_budget_is_plain_decimal(self):
        with patch.object(self.ready.subprocess, "run",
                          return_value=subprocess.CompletedProcess([], 0, b"200")) as run:
            self.ready.http_ready("http://127.0.0.1/health", 0.00001)
        argv = run.call_args.args[0]
        value = argv[argv.index("--max-time") + 1]
        self.assertNotIn("e", value.lower(), "curl rejects scientific-notation timeouts")
        self.assertAlmostEqual(float(value), 0.00001)

    def test_postgres_checks_tcp_configured_database_with_complete_timeout(self):
        self.assertTrue(hasattr(self.ready, "postgres_ready"), "Postgres probe is missing")
        for code in (0, 1, 2):
            with self.subTest(code=code), patch.object(
                    self.ready.subprocess, "run",
                    return_value=subprocess.CompletedProcess([], code)) as run:
                self.assertEqual(self.ready.postgres_ready("test-owned-db", "custom_db", 0.3), code == 0)
                self.assertEqual(run.call_args.args[0], [
                    "docker", "exec", "test-owned-db", "pg_isready", "-h", "127.0.0.1",
                    "-U", "postgres", "-d", "custom_db", "-t", "1"])
                self.assertEqual(run.call_args.kwargs["timeout"], 0.3)

    def test_invalid_probe_invocation_is_not_retried(self):
        self.assertTrue(hasattr(self.ready, "http_ready"), "HTTP probe is missing")
        self.assertTrue(hasattr(self.ready, "postgres_ready"), "Postgres probe is missing")
        for probe, args, codes in ((self.ready.http_ready, ("http://localhost/health",), (2, 3, 4)),
                                  (self.ready.postgres_ready, ("test-db", "test"), (3, 125, 126, 127))):
            for code in codes:
                with self.subTest(code=code, probe=probe.__name__), patch.object(
                        self.ready.subprocess, "run",
                        return_value=subprocess.CompletedProcess([], code, b"")) as run:
                    with self.assertRaises((ValueError, OSError)):
                        self.ready.wait_ready(lambda budget: probe(*args, budget), timeout=0.5)
                    self.assertEqual(run.call_count, 1)


class ReadinessProcessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix=".startup-test-", dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.env = {"PATH": os.defpath, "HOME": str(self.work), "PYTHONDONTWRITEBYTECODE": "1"}

    def invoke(self, *args, timeout="0.35", env=None):
        started = time.monotonic()
        result = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/wait-ready.py"),
                                 "--timeout", timeout, *args], cwd=ROOT,
                                env=self.env if env is None else env,
                                capture_output=True, text=True, timeout=4)
        self.assertLess(time.monotonic() - started, 2.0, result.stderr)
        return result

    def server(self, statuses=(200,), stalled=False):
        paths = []
        release = threading.Event()

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                paths.append(self.path)
                status = statuses[min(len(paths) - 1, len(statuses) - 1)]
                self.send_response(status)
                self.send_header("Content-Length", "10" if stalled else "0")
                if status in (301, 302):
                    self.send_header("Location", "/redirect-destination")
                self.end_headers()
                if stalled:
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    release.wait(4)

            def log_message(self, format, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
        thread.start()

        def stop():
            release.set()
            server.shutdown()
            server.server_close()
            thread.join(1)

        self.addCleanup(stop)
        return f"http://127.0.0.1:{server.server_port}/health", paths

    def test_local_http_immediate_and_delayed(self):
        self.assertIsNotNone(shutil.which("curl", path=self.env["PATH"]), "tests require curl")
        for statuses in ((200,), (503, 200)):
            with self.subTest(statuses=statuses):
                url, paths = self.server(statuses)
                result = self.invoke("http", url, timeout="1")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(paths), len(statuses), "helper did not actually probe HTTP")

    def test_redirects_and_non_200_are_not_ready(self):
        # Even an operator curlrc must not turn a redirect into success.
        (self.work / ".curlrc").write_text("location\n")
        for status in (204, 301, 302, 404, 503):
            with self.subTest(status=status):
                url, paths = self.server((status,))
                result = self.invoke("http", url)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertTrue(paths)
                self.assertNotIn("/redirect-destination", paths)

    def test_http_200_with_stalled_body_is_not_ready(self):
        url, paths = self.server(stalled=True)
        result = self.invoke("http", url)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertTrue(paths)

    def test_missing_tools_fail_promptly(self):
        for args in (("http", "http://127.0.0.1/health"), ("postgres", "test-db", "test")):
            with self.subTest(args=args):
                result = self.invoke(*args, timeout="60", env={**self.env, "PATH": str(self.work)})
                self.assertEqual(result.returncode, 127, result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_invalid_arguments_fail_promptly(self):
        cases = [("0", ("http", "http://127.0.0.1/health")),
                 ("nan", ("http", "http://127.0.0.1/health")),
                 ("inf", ("http", "http://127.0.0.1/health")),
                 ("60", ("http", "bad-url")), ("60", ("http", "ftp://localhost/file")),
                 ("60", ("http", "http://localhost:bad/health")),
                 ("60", ("postgres", "test-db", "")), ("60", ("unknown",))]
        for timeout, args in cases:
            with self.subTest(timeout=timeout, args=args):
                result = self.invoke(*args, timeout=timeout)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_hung_executables_are_killed_by_outer_timeout(self):
        # These are local stand-ins, never the Docker CLI or daemon.
        for executable, args in (("curl", ("http", "http://127.0.0.1/health")),
                                 ("docker", ("postgres", "test-db", "test"))):
            with self.subTest(executable=executable):
                fake = self.work / executable
                fake.write_text(f"#!{sys.executable}\nimport time\ntime.sleep(60)\n")
                fake.chmod(0o755)
                result = self.invoke(*args, env={**self.env, "PATH": str(self.work)})
                self.assertEqual(result.returncode, 1, result.stderr)


class MakeStartupTests(unittest.TestCase):
    """Execute unchanged consumer recipes, with every Docker/build command faked.

    No production Makefile is invoked: only the selected recipes/macros are copied
    to a disposable offline Makefile; prerequisites outside the test are inert.
    """
    def setUp(self):
        self.source = (ROOT / "Makefile").read_text()
        self.temp = tempfile.TemporaryDirectory(prefix=".startup-make-", dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.trace = self.work / "trace.jsonl"
        self.fake = self.work / "fake-command"
        self.fake.write_text(f"#!{sys.executable}\n" + '''import json, os, sys, time
from pathlib import Path
name = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["OFFLINE_TRACE"], "a") as log:
    log.write(json.dumps([name, *args]) + "\\n")
if name == "timeout":
    os.execv(os.environ["REAL_TIMEOUT"], ["timeout", *args])
if name == "curl":
    print(os.environ.get("HTTP_STATUS", "503"), end="")
    sys.exit(int(os.environ.get("CURL_EXIT", "0")))
if name == "docker":
    if args[0] == "exec":
        sys.exit(int(os.environ.get("PG_EXIT", "1")))
    if args[0] == "logs":
        if os.environ.get("HANG_LOGS") == "1":
            time.sleep(60)
        os.write(1, b"L" * 65536)
    if args[0] == "rm" or args[:2] == ["volume", "rm"]:
        sys.exit(int(os.environ.get("CLEANUP_EXIT", "0")))
sys.exit(0)
''')
        self.fake.chmod(0o755)
        for name in ("docker", "curl", "make-stage", "timeout"):
            (self.work / name).symlink_to(self.fake)
        self.env = {"PATH": f"{self.work}:{os.defpath}", "HOME": str(self.work),
                    "PYTHONDONTWRITEBYTECODE": "1", "OFFLINE_TRACE": str(self.trace),
                    "REAL_TIMEOUT": shutil.which("timeout", path=os.defpath) or ""}
        self.assertTrue(self.env["REAL_TIMEOUT"], "tests require GNU timeout")

    def recipe(self, target):
        match = re.search(rf"^{re.escape(target)}:[^\n]*\n(?:\t[^\n]*\n)+", self.source, re.M)
        self.assertIsNotNone(match, f"missing actual consumer: {target}")
        assert match is not None
        return match.group(0)

    def run_target(self, target, **environment):
        consumer = "postgres-test" if target == "migrate-test" else target
        self.assertIn("scripts/wait-ready.py", self.recipe(consumer),
                      f"{consumer} still has an unbounded/fixed wait")
        self.assertRegex(self.source, r"(?m)^TEST_STARTUP_TIMEOUT \?= 60$")
        macros = re.findall(r"^define [^\n]+\n.*?^endef$", self.source, re.M | re.S)
        makefile = self.work / "Makefile.offline"
        text = "\n".join(macros) + "\n"
        text += "TEST_DB_HOST := owned-test-db\nTEST_DB_NAME := custom_db\n"
        text += "TEST_DB_VOLUME := owned-test-volume\nTEST_STARTUP_TIMEOUT := 0.15\n"
        text += "NETWORK := offline-network\n.PHONY: network down down-test-billing\n"
        text += "network down down-test-billing:\n\t@:\n"
        if target == "migrate-test":
            text += self.recipe("postgres-test") + self.recipe("migrate-test")
        else:
            text += "migrate-test:\n\t@:\n" + self.recipe(target)
        makefile.write_text(text)
        make = shutil.which("make", path=os.defpath)
        assert make is not None, "tests require make"
        result = subprocess.run([make, "--no-builtin-rules",
                                 "--no-print-directory", "-f", str(makefile), target,
                                 f"MAKE={self.work / 'make-stage'}"], cwd=ROOT,
                                env={**self.env, **environment}, capture_output=True,
                                text=True, timeout=12)
        events = [json.loads(line) for line in self.trace.read_text().splitlines()]
        self.trace.unlink()
        return result, events

    def assert_cleanup(self, events, expected):
        # The initial postgres reset precedes probing; only inspect failure cleanup.
        probe_index = max(i for i, event in enumerate(events)
                          if event[0] == "curl" or event[:2] == ["docker", "exec"])
        cleanup = events[probe_index + 1:]
        self.assertIn(["docker", "rm", "-f", *expected], cleanup)
        self.assertIn(["docker", "volume", "rm", "owned-test-volume"], cleanup)
        logs = [e for e in cleanup if e[:2] == ["docker", "logs"]]
        self.assertEqual(logs, [["docker", "logs", "--tail", "40", expected[0]]])
        timeouts = [e for e in cleanup if e[0] == "timeout"]
        self.assertEqual(len(timeouts), 3, cleanup)
        for event in timeouts:
            self.assertEqual(event[1], "--signal=KILL")
            self.assertLessEqual(float(event[2].rstrip("s")), 5)
        self.assertFalse(any(e[:2] == ["docker", "network"] for e in cleanup))

    def test_postgres_timeout_prevents_migration_and_cleans_only_owned_db(self):
        result, events = self.run_target("migrate-test")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Error 1", result.stderr)
        self.assertFalse(any("/makefile-run-migrations.sh" in event for event in events))
        self.assert_cleanup(events, ["owned-test-db"])
        probes = [e for e in events if e[:2] == ["docker", "exec"]]
        self.assertEqual(probes[0][2:], ["owned-test-db", "pg_isready", "-h", "127.0.0.1",
                                       "-U", "postgres", "-d", "custom_db", "-t", "1"])

    def test_api_timeouts_prevent_gateway_and_cleanup_only_started_services(self):
        for target, owned in (("up-test", ["api", "email", "owned-test-db"]),
                              ("up-test-billing", ["api", "email", "metering", "owned-test-db"])):
            with self.subTest(target=target):
                result, events = self.run_target(target)
                self.assertIn("Error 1", result.stderr)
                self.assertNotIn(["make-stage", "run-gateway-test"], events)
                self.assert_cleanup(events, owned)
                curls = [e for e in events if e[0] == "curl"]
                self.assertIn("http://127.0.0.1:8080/health", curls[0])
                self.assertLess(len(result.stderr), 10000, "diagnostic bytes must be bounded")

    def test_cleanup_failure_does_not_replace_original_status(self):
        for target in ("migrate-test", "up-test", "up-test-billing"):
            with self.subTest(target=target):
                result, events = self.run_target(target, CLEANUP_EXIT="97")
                self.assertIn("Error 1", result.stderr)
                self.assertNotIn("Error 97", result.stderr)
                self.assertIn(["docker", "volume", "rm", "owned-test-volume"], events)

    def test_missing_probe_tool_status_survives_cleanup_failure(self):
        result, events = self.run_target("migrate-test", PG_EXIT="127", CLEANUP_EXIT="97")
        self.assertIn("Error 127", result.stderr)
        self.assert_cleanup(events, ["owned-test-db"])

    def test_hung_diagnostics_are_bounded_and_cleanup_still_runs(self):
        started = time.monotonic()
        result, events = self.run_target("up-test", HANG_LOGS="1")
        self.assertLess(time.monotonic() - started, 6)
        self.assertIn("Error 1", result.stderr)
        self.assert_cleanup(events, ["api", "email", "owned-test-db"])

    def test_success_reaches_downstream_without_failure_cleanup(self):
        for target in ("migrate-test", "up-test", "up-test-billing"):
            with self.subTest(target=target):
                result, events = self.run_target(target, PG_EXIT="0", HTTP_STATUS="200")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(any(e[:2] == ["docker", "logs"] for e in events))
                if target == "migrate-test":
                    self.assertTrue(any("/makefile-run-migrations.sh" in e for e in events))
                else:
                    self.assertIn(["make-stage", "run-gateway-test"], events)
                    self.assertFalse(any(e[:2] == ["docker", "rm"] for e in events))


if __name__ == "__main__":
    unittest.main()
