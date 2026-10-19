#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
"""Real GNU Make scheduling contracts, with offline processes instead of live suites.

Only the full test-e2e recipe and its internal suite targets/macros are copied.
Build/start/stop are inert and no live script body is executed. The Python fixture
owns a disposable flock outside Make, like the live observer; bare full Make
does not lock. File gates prove overlap and cleanup ordering, not elapsed speed.
"""
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SUITES = ("happy_path", "platform_ports", "env_parity", "ssh_units", "pgp_units",
          "pgp_audit_constraints")

# Shared by separate fake suite processes and fake lifecycle prerequisites.
# The lock serializes observations only; it never schedules suite execution.
OBSERVER = r'''
import fcntl, json, os, sys, time
from pathlib import Path
work = Path(os.environ["OFFLINE_WORK"])
action, name = sys.argv[1:3]

def record(event, **fields):
    with (work / "test.lock").open("a") as lock:
        try:
            # Shared probes coexist; only the observer's exclusive ownership
            # lock should make this fail, not another concurrent suite probe.
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            fields["lock_held"] = False
        except BlockingIOError:
            fields["lock_held"] = True
    with (work / "events.jsonl").open("a") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        stream.write(json.dumps(dict(event=event, name=name, **fields)) + "\n")
        stream.flush()

def wait_for(path):
    deadline = time.monotonic() + 15
    while not path.exists():
        if time.monotonic() >= deadline:
            raise SystemExit("offline file gate timed out: " + str(path))
        time.sleep(0.01)

config = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")))
config_file = config / "caution-cli/config.json"
if action == "start":
    config_file.parent.mkdir(parents=True, exist_ok=True)
    config_file.write_text(name)
    record("start", config=str(config), home=os.environ["HOME"],
           cli=os.environ.get("CAUTION_BIN"), api=os.environ.get("API_URL"),
           gateway=os.environ.get("GATEWAY_URL"), aws=os.environ.get("AWS_PROFILE"),
           aws_region=os.environ.get("AWS_REGION"),
           aws_config=os.environ.get("AWS_CONFIG_FILE"))
elif action == "body":
    record("body-ready")
    wait_for(work / ("release-" + name))
    raise SystemExit(23 if name == os.environ.get("FAIL_SUITE") else 0)
elif action == "cleanup":
    record("cleanup-start", config_exists=config_file.exists())
    if name in os.environ.get("HOLD_CLEANUP", "").split(","):
        wait_for(work / "release-cleanup")
    record("cleanup-end", config_exists=config_file.exists(),
           config_value=config_file.read_text() if config_file.exists() else None)
elif action == "stage":
    record(name)
    if name == "build-cli":
        raise SystemExit(int(os.environ.get("BUILD_CLI_EXIT", "0")))
    if name == "up-test":
        raise SystemExit(int(os.environ.get("STARTUP_EXIT", "0")))
    if name == "down-test" and os.environ.get("LEAK_CHILD") == "1":
        import subprocess
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        record("leftover-child", pid=child.pid)
else:
    raise SystemExit("unknown offline action")
'''


class SchedulingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="e2e-scheduling-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.make = shutil.which("make", path=os.defpath)
        self.assertIsNotNone(self.make, "GNU Make is required")
        assert self.make is not None
        version = subprocess.check_output([self.make, "--version"], text=True)
        self.assertIn("GNU Make", version)
        self.source = (ROOT / "Makefile").read_text()
        section = re.search(r"^test-e2e:\n.*?(?=^test-e2e-ssh-units:)",
                            self.source, re.M | re.S)
        self.assertIsNotNone(section, "full test-e2e consumer is missing")
        assert section is not None
        # The explicit allowlist excludes every real build/service prerequisite.
        variables = re.findall(r"^E2E_JOBS[^\n]*", self.source, re.M)
        macros = re.findall(r"^define [^\n]+\n.*?^endef$", self.source, re.M | re.S)
        fixture = "\n".join(variables + macros) + "\n" + section.group(0)
        fixture += "\nCLI_OUT_DIR := out/cli\nCLI_BINARY := caution-test\n"
        fixture += "E2E_LOCK_FILE := $(CURDIR)/test.lock\n"
        fixture += ".PHONY: test-e2e build-cli up-test down-test\n"
        fixture += "build-cli up-test down-test:\n\t@python3 observer.py stage $@\n"
        (self.work / "Makefile").write_text(fixture)
        (self.work / "observer.py").write_text(OBSERVER)
        scripts = self.work / "tests/e2e"
        scripts.mkdir(parents=True)
        for suite in SUITES:
            (scripts / f"test_{suite}.sh").write_text(
                "#!/bin/bash\nset -euo pipefail\n"
                f"trap 'python3 observer.py cleanup {suite}' EXIT\n"
                f"python3 observer.py start {suite}\n"
                f"python3 observer.py body {suite}\n")
        self.operator = self.work / "operator-config/caution-cli/config.json"
        self.operator.parent.mkdir(parents=True)
        self.operator.write_text("operator-session-do-not-change\n")
        self.home = self.work / "operator-home"
        self.home.mkdir()
        self.tmpdir = self.work / "owned-temp"
        self.tmpdir.mkdir()
        self.sentinel = self.tmpdir / "unowned"
        self.sentinel.write_text("keep me")
        binaries = self.work / "bin"
        binaries.mkdir()
        (binaries / "python3").symlink_to(sys.executable)
        # Fail closed even if a future copied recipe accidentally calls infra tools.
        for tool in ("docker", "aws", "curl", "ssh", "cargo", "terraform", "tofu"):
            fake = binaries / tool
            fake.write_text('#!/bin/sh\nprintf "forbidden offline command: %s\\n" "$0" >&2\nexit 99\n')
            fake.chmod(0o755)
        self.env = {"PATH": f"{binaries}:{os.defpath}", "HOME": str(self.home),
                    "PWD": str(self.work), "TMPDIR": str(self.tmpdir),
                    "XDG_CONFIG_HOME": str(self.operator.parent.parent),
                    "OFFLINE_WORK": str(self.work), "PYTHONDONTWRITEBYTECODE": "1",
                    "API_URL": "http://api.invalid", "GATEWAY_URL": "http://gateway.invalid",
                    "AWS_PROFILE": "offline-profile", "AWS_REGION": "offline-region",
                    "AWS_CONFIG_FILE": str(self.home / "offline-aws-config")}
        self.process = None
        self.processes = []
        self.lock = (self.work / "test.lock").open("a")
        self.addCleanup(self.lock.close)
        # LIFO: drain owned groups before releasing the observer lock or temp tree.
        self.addCleanup(self.stop_process)

    def events(self):
        path = self.work / "events.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()]

    def starts(self):
        return [e for e in self.events() if e["event"] == "start"]

    def output(self):
        return (self.work / "output.log").read_text()

    def start(self, *args, external_lock=True, **environment):
        if external_lock:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        (self.work / "events.jsonl").unlink(missing_ok=True)
        output = (self.work / "output.log").open("w")
        self.addCleanup(output.close)
        self.process = subprocess.Popen(
            [self.make, "--no-builtin-rules", "--no-print-directory", "-j1", *args, "test-e2e"],
            cwd=self.work, env={**self.env, **environment}, stdout=output,
            stderr=subprocess.STDOUT, start_new_session=True)
        self.processes.append(self.process)

    def wait_for(self, predicate, description):
        assert self.process is not None
        deadline = time.monotonic() + 5
        while not predicate():
            if self.process.poll() is not None or time.monotonic() >= deadline:
                self.fail(f"{description}\nevents: {self.events()}\n{self.output()}")
            time.sleep(0.01)

    def release(self, suite):
        (self.work / ("release-" + suite)).touch()

    def finish(self, timeout=10):
        assert self.process is not None
        status = self.process.wait(timeout=timeout)
        self.assertTrue(self.sentinel.exists(), "unowned temporary file removed")
        return status

    def stop_process(self):
        for suite in SUITES:
            self.release(suite)
        (self.work / "release-cleanup").touch()
        # Every registered PID is also the PGID of our start_new_session child.
        # Leader exit alone says nothing about its remaining group members.
        for process in self.processes[:]:
            deadline = time.monotonic() + 3
            while True:
                process.poll()
                try:
                    os.killpg(process.pid, 0)
                    if time.monotonic() >= deadline:
                        os.killpg(process.pid, signal.SIGKILL)
                        break
                except ProcessLookupError:
                    break
                time.sleep(0.01)
            process.wait(timeout=3)
            self.processes.remove(process)

    def run_success(self, width=2, args=(), **environment):
        self.start(*args, **environment)
        # Hold the first wave so sequential execution cannot masquerade as parallel.
        self.wait_for(lambda: len(self.starts()) >= width,
                      f"expected {width} simultaneous suites before any release")
        for suite in SUITES:
            self.release(suite)
        self.assertEqual(self.finish(), 0, self.output())
        events = self.events()
        active = peak = 0
        for event in events:
            self.assertTrue(event["lock_held"], event)
            if event["event"] == "start":
                active += 1
                peak = max(peak, active)
            elif event["event"] == "cleanup-end":
                active -= 1
        self.assertEqual(peak, width, events)
        self.assertEqual(active, 0, events)
        self.assertCountEqual([e["name"] for e in self.starts()], SUITES)
        self.assertEqual([e["event"] for e in events[:2]], ["build-cli", "up-test"])
        self.assertEqual(events[-1]["event"], "down-test")
        for stage in ("build-cli", "up-test", "down-test"):
            self.assertEqual(sum(e["event"] == stage for e in events), 1)
        return events

    def test_default_six_workers_runs_all_six_once_after_setup(self):
        self.run_success(width=6)

    def test_external_lock_does_not_block_full_lifecycle(self):
        for suite in SUITES:
            self.release(suite)
        self.start()
        try:
            status = self.finish(timeout=3)
        except subprocess.TimeoutExpired:
            self.fail(f"Make blocked with all gates released and observer lock held: "
                      f"{self.events()}\n{self.output()}")
        self.assertEqual(status, 0, self.output())
        self.assertCountEqual([e["name"] for e in self.starts()], SUITES)
        self.assertEqual(self.events()[-1]["event"], "down-test")
        for event in self.events():
            self.assertTrue(event["lock_held"], event)
        self.stop_process()
        with (self.work / "test.lock").open("a") as probe:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_bare_full_make_does_not_acquire_its_own_lock(self):
        # Hold a peer observation open: readers must not impersonate an
        # exclusive lifecycle owner when several suite processes probe at once.
        fcntl.flock(self.lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        for suite in SUITES:
            self.release(suite)
        self.start(external_lock=False)
        self.assertEqual(self.finish(), 0, self.output())
        self.assertCountEqual([e["name"] for e in self.starts()], SUITES)
        self.assertEqual(self.events()[-1]["event"], "down-test")
        for event in self.events():
            self.assertFalse(event["lock_held"], event)

    def test_serial_fallback(self):
        self.run_success(width=1, args=("E2E_JOBS=1",))

    def test_parent_jobs_and_makeflags_cannot_exceed_two(self):
        self.run_success(args=("-j8", "E2E_JOBS=2"), MAKEFLAGS="-k -j12")

    def test_command_line_makeflags_cannot_exceed_two(self):
        self.run_success(args=("MAKEFLAGS=-k -j12",), E2E_JOBS="2")

    def test_environment_serial_fallback_ignores_parent_parallelism(self):
        self.run_success(width=1, args=("-j8",), E2E_JOBS="1", MAKEFLAGS="-j12")

    def test_three_workers_command_line_cap_and_private_configs(self):
        events = self.run_success(width=3, args=("-j8", "E2E_JOBS=3"),
                                  MAKEFLAGS="-k -j12")
        self.assert_suite_configs(events)

    def test_three_workers_environment_cap_and_private_configs(self):
        events = self.run_success(width=3, args=("-j8", "MAKEFLAGS=-k -j12"),
                                  E2E_JOBS="3")
        self.assert_suite_configs(events)

    def test_four_workers_command_line_cap_and_private_configs(self):
        events = self.run_success(width=4, args=("-j8", "E2E_JOBS=4"),
                                  MAKEFLAGS="-k -j12")
        self.assert_suite_configs(events)

    def test_four_workers_environment_cap_and_private_configs(self):
        events = self.run_success(width=4, args=("-j8", "MAKEFLAGS=-k -j12"),
                                  E2E_JOBS="4")
        self.assert_suite_configs(events)

    def test_five_workers_command_line_cap_and_private_configs(self):
        events = self.run_success(width=5, args=("-j8", "E2E_JOBS=5"),
                                  MAKEFLAGS="-k -j12")
        self.assert_suite_configs(events)

    def test_six_workers_environment_cap_and_private_configs(self):
        events = self.run_success(width=6, args=("-j8", "MAKEFLAGS=-k -j12"),
                                  E2E_JOBS="6")
        self.assert_suite_configs(events)

    def test_suite_configs_are_private_until_exit_cleanup(self):
        events = self.run_success(width=6)
        self.assert_suite_configs(events)

    def assert_suite_configs(self, events, expected_count=6):
        configs = [e["config"] for e in self.starts()]
        self.assertEqual(len(set(configs)), expected_count)
        self.assertEqual(self.operator.read_text(), "operator-session-do-not-change\n")
        for event in events:
            if event["event"] == "start":
                self.assertEqual(event["home"], str(self.home))
                self.assertEqual(event["cli"], str(self.work / "out/cli/caution-test"))
                self.assertEqual(event["api"], self.env["API_URL"])
                self.assertEqual(event["gateway"], self.env["GATEWAY_URL"])
                self.assertEqual(event["aws"], self.env["AWS_PROFILE"])
                self.assertEqual(event["aws_region"], self.env["AWS_REGION"])
                self.assertEqual(event["aws_config"], self.env["AWS_CONFIG_FILE"])
            elif event["event"] == "cleanup-start":
                self.assertTrue(event["config_exists"], event)
            elif event["event"] == "cleanup-end":
                self.assertTrue(event["config_exists"], event)
                self.assertEqual(event["config_value"], event["name"])
        for config in configs:
            self.assertFalse(Path(config).exists(), f"suite config leaked: {config}")

    def test_failure_drains_peer_cleanup_and_cancels_queued_suites_even_with_keep_going(self):
        failed, peer = SUITES[:2]
        self.start("-k", "E2E_JOBS=2", FAIL_SUITE=failed, HOLD_CLEANUP=peer, MAKEFLAGS="-k -j8")
        self.wait_for(lambda: len(self.starts()) >= 2, "parallel peer never started")
        self.release(peer)
        self.wait_for(lambda: any(e["event"] == "cleanup-start" and e["name"] == peer
                                  for e in self.events()), "peer did not enter EXIT cleanup")
        self.release(failed)
        self.wait_for(lambda: "Waiting for unfinished jobs" in self.output(),
                      "GNU Make did not observe failure while draining peer")
        self.assertNotIn("down-test", [e["event"] for e in self.events()])
        self.assertCountEqual([e["name"] for e in self.starts()], [failed, peer])
        (self.work / "release-cleanup").touch()
        self.assertNotEqual(self.finish(), 0, self.output())
        events = self.events()
        self.assertEqual(events[-1]["event"], "down-test")
        self.assertCountEqual([e["name"] for e in self.starts()], [failed, peer])
        for event in events:
            self.assertTrue(event["lock_held"], event)
            if event["event"] == "cleanup-end":
                self.assertTrue(event["config_exists"], event)
        for event in self.starts():
            self.assertFalse(Path(event["config"]).exists())

    def assert_failed_wave_drains_all_peers(self, width, args=(), **environment):
        failed, *peers = SUITES[:width]
        self.start(*args, FAIL_SUITE=failed, HOLD_CLEANUP=",".join(peers), **environment)
        self.wait_for(lambda: len(self.starts()) >= width, "parallel peers never started")
        self.assertCountEqual([e["name"] for e in self.starts()], [failed, *peers])
        # Pin every peer, not just one: a free worker could otherwise start queued
        # work before Make observes the failure and mask a keep-going regression.
        for peer in peers:
            self.release(peer)
        self.wait_for(lambda: {e["name"] for e in self.events()
                               if e["event"] == "cleanup-start"} == set(peers),
                      "not every active peer reached held EXIT cleanup")
        for suite in SUITES[width:]:
            self.release(suite)
        self.release(failed)
        self.wait_for(lambda: "Waiting for unfinished jobs" in self.output(),
                      "GNU Make did not observe failure while draining all peers")
        events = self.events()
        self.assertIn("Error 23", self.output())
        self.assertNotIn("down-test", [e["event"] for e in events])
        self.assertCountEqual([e["name"] for e in self.starts()], [failed, *peers])
        self.assertEqual([e["name"] for e in events if e["event"] == "cleanup-end"],
                         [failed])
        for event in self.starts():
            if event["name"] in peers:
                config_file = Path(event["config"]) / "caution-cli/config.json"
                self.assertEqual(config_file.read_text(), event["name"])
        (self.work / "release-cleanup").touch()
        self.assertNotEqual(self.finish(), 0, self.output())
        events = self.events()
        self.assertCountEqual([e["name"] for e in self.starts()], [failed, *peers])
        self.assertCountEqual([e["name"] for e in events if e["event"] == "cleanup-end"],
                              [failed, *peers])
        self.assertEqual([e["event"] for e in events[:2]], ["build-cli", "up-test"])
        self.assertEqual(events[-1]["event"], "down-test")
        for stage in ("build-cli", "up-test", "down-test"):
            self.assertEqual(sum(e["event"] == stage for e in events), 1)
        for event in events:
            self.assertTrue(event["lock_held"], event)
        self.assert_suite_configs(events, expected_count=width)

    def test_three_workers_failure_drains_all_peers_with_environment_keep_going(self):
        self.assert_failed_wave_drains_all_peers(
            3, args=("-k", "-j8", "E2E_JOBS=3"), MAKEFLAGS="-k -j12")

    def test_three_workers_failure_drains_all_peers_with_command_line_keep_going(self):
        self.assert_failed_wave_drains_all_peers(
            3, args=("-j8", "MAKEFLAGS=-k -j12"), E2E_JOBS="3")

    def test_four_workers_failure_drains_all_peers_with_environment_keep_going(self):
        self.assert_failed_wave_drains_all_peers(
            4, args=("-k", "-j8", "E2E_JOBS=4"), MAKEFLAGS="-k -j12")

    def test_four_workers_failure_drains_all_peers_with_command_line_keep_going(self):
        self.assert_failed_wave_drains_all_peers(
            4, args=("-j8", "MAKEFLAGS=-k -j12"), E2E_JOBS="4")

    def test_five_workers_failure_cancels_queue_and_drains_peers(self):
        self.assert_failed_wave_drains_all_peers(
            5, args=("-k", "-j8", "E2E_JOBS=5"), MAKEFLAGS="-k -j12")

    def test_default_six_workers_failure_drains_all_peers(self):
        self.assert_failed_wave_drains_all_peers(
            6, args=("-j8", "MAKEFLAGS=-k -j12"))

    def test_interrupt_drains_exit_cleanup_before_teardown(self):
        self.start(HOLD_CLEANUP=SUITES[0])
        self.wait_for(lambda: sum(e["event"] == "body-ready" for e in self.events()) == len(SUITES),
                      "parallel suite bodies never became ready")
        assert self.process is not None
        os.killpg(self.process.pid, signal.SIGINT)
        self.wait_for(lambda: any(e["event"] == "cleanup-start" and e["name"] == SUITES[0]
                                  for e in self.events()), "interrupted suite skipped EXIT cleanup")
        self.assertNotIn("down-test", [e["event"] for e in self.events()])
        (self.work / "release-cleanup").touch()
        self.assertNotEqual(self.finish(), 0, self.output())
        events = self.events()
        self.assertEqual(events[-1]["event"], "down-test")
        self.assertCountEqual([e["name"] for e in self.starts()], SUITES)
        cleaned = [e for e in events if e["event"] == "cleanup-end"]
        self.assertEqual(len(cleaned), len(SUITES), events)
        for event in events:
            self.assertTrue(event["lock_held"], event)
        for event in cleaned:
            self.assertTrue(event["config_exists"], event)
        for event in self.starts():
            self.assertFalse(Path(event["config"]).exists())

    def test_startup_failure_never_starts_suites(self):
        self.start(STARTUP_EXIT="37")
        self.assertNotEqual(self.finish(), 0, self.output())
        self.assertEqual(self.starts(), [])
        self.assertIn("Error 37", self.output())
        self.assertEqual([e["event"] for e in self.events()],
                         ["build-cli", "up-test", "down-test"])
        for event in self.events():
            self.assertTrue(event["lock_held"], event)

    def test_cli_build_failure_does_not_touch_test_stack(self):
        self.start(BUILD_CLI_EXIT="37")
        self.assertNotEqual(self.finish(), 0, self.output())
        self.assertIn("Error 37", self.output())
        self.assertEqual([e["event"] for e in self.events()], ["build-cli"])
        self.assertTrue(self.events()[0]["lock_held"])

    def test_fixture_cleanup_terminates_owned_group_after_make_exits(self):
        self.start(LEAK_CHILD="1")
        for suite in SUITES:
            self.release(suite)
        self.assertEqual(self.finish(), 0, self.output())
        child = next(e["pid"] for e in self.events() if e["event"] == "leftover-child")

        def child_running():
            try:
                # A terminated orphan may await reaping by init; it is not running.
                return Path(f"/proc/{child}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
            except FileNotFoundError:
                return False

        assert self.process is not None
        try:
            self.assertTrue(child_running(), "fixture did not leave a child to drain")
            self.stop_process()
            deadline = time.monotonic() + 1
            while child_running() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertFalse(child_running(), "owned child survived fixture cleanup after Make exited")
        finally:
            # Keep the regression's RED run safe even with the old cleanup helper.
            if child_running():
                os.killpg(self.process.pid, signal.SIGKILL)

    def test_invalid_jobs_fail_before_any_setup(self):
        for suite in SUITES:
            self.release(suite)
        for value in ("0", "7", "8", "-1", "", "1 2", "01", "two"):
            with self.subTest(value=value):
                self.start(f"E2E_JOBS={value}")
                self.assertNotEqual(self.finish(), 0, self.output())
                self.assertEqual(self.events(), [], "invalid jobs reached setup")
                self.assertIn("E2E_JOBS", self.output())

    def test_default_suite_log_names_do_not_collide(self):
        names = []
        for suite in SUITES:
            text = (ROOT / f"tests/e2e/test_{suite}.sh").read_text()
            assignment = re.search(r"^LOG_FILE=.*$", text, re.M)
            self.assertIsNotNone(assignment)
            assert assignment is not None
            # Execute only the assignment with a fixed timestamp, never the script.
            result = subprocess.run(["bash", "-c", 'LOG_DIR=logs\ndate() { printf fixed; }\n'
                                     + assignment.group(0) + '\nprintf "%s" "$LOG_FILE"'],
                                    cwd=self.work, env=self.env, capture_output=True,
                                    text=True, check=True)
            names.append(result.stdout)
        self.assertEqual(len(set(names)), len(SUITES), names)


if __name__ == "__main__":
    unittest.main()
