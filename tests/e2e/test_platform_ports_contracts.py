#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
"""Offline lifecycle contracts for the complete, byte-for-byte ports E2E script.

Only external commands are faked. No services, credentials, cloud calls, or real
SSH agents are used. The private script copy cannot source the repository .env.
Run: python3 -B tests/e2e/test_platform_ports_contracts.py -v
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
RESOURCE = "11111111-1111-4111-8111-111111111111"


def fake_command():
    name = Path(sys.argv[0]).name
    args = sys.argv[1:]
    root = Path(os.environ["FAKE_ROOT"])
    with (root / "calls.jsonl").open("a") as stream:
        stream.write(json.dumps([name, args]) + "\n")

    if name == "git":
        if args == ["push", "caution", "main"]:
            print("mock push result")
            return int(os.environ.get("PUSH_STATUS", "0"))
        return 0
    if name == "ssh-keygen":
        key = Path(args[args.index("-f") + 1])
        key.write_text("offline private key fixture")
        key.with_suffix(".pub").write_text("ssh-ed25519 offline")
        (root / "work-dir").write_text(str(key.parent))
        return 0
    if name == "ssh-agent":
        if args == ["-s"]:
            if os.environ.get("AGENT_START_STATUS"):
                return int(os.environ["AGENT_START_STATUS"])
            print("SSH_AUTH_SOCK=/offline/owned; export SSH_AUTH_SOCK; "
                  "SSH_AGENT_PID=424242; export SSH_AGENT_PID;")
            return 0
        if args == ["-k"]:
            assert os.environ["SSH_AGENT_PID"] == "424242"
            assert os.environ["SSH_AUTH_SOCK"] == "/offline/owned"
            return int(os.environ.get("AGENT_KILL_STATUS", "0"))
    if name == "ssh-add":
        return int(os.environ.get("SSH_ADD_STATUS", "0"))
    if name == "sleep":
        return 0
    if name == "caution":
        assert args[:2] == ["-u", "http://gateway.invalid"]
        action = args[2:]
        if action[0] == "init":
            Path(".caution").mkdir()
            Path(".caution/deployment.json").write_text(json.dumps({"resource_id": RESOURCE}))
            return 0
        if action == ["apps", "get", RESOURCE]:
            print("App Details:\n  State: " + os.environ.get("APP_STATE", "running"))
            return 0
        if action == ["apps", "destroy", RESOURCE, "--force"]:
            counter = root / "destroy-count"
            count = int(counter.read_text()) + 1 if counter.exists() else 1
            counter.write_text(str(count))
            mode = os.environ.get("DESTROY_MODE", "success")
            if mode == "pending" or (mode == "settles" and count < 3):
                print("failed to destroy app (status 409 Conflict): resource is deploying [fixture]", file=sys.stderr)
                return 1
            if mode in ("timeout", "killed", "interrupted"):
                print("failed to destroy app (status 409 Conflict): resource is deploying [partial output]", file=sys.stderr)
                return {"timeout": 124, "killed": 137, "interrupted": 143}[mode]
            if mode == "auth":
                print("failed to fetch app (status 401 Unauthorized)", file=sys.stderr)
                return 1
            if mode == "lookalike":
                print("failed to destroy app (status 503 Service Unavailable): resource is deploying", file=sys.stderr)
                return 1
            if mode == "failed":
                print("failed to destroy app (status 503 Service Unavailable): app destroy failed [fixture]", file=sys.stderr)
                return 23
            print("App destroyed")
            return 0
    if name == "docker":
        if args[:1] == ["logs"]:
            print("offline service diagnostic")
            return 0
        if args[:2] == ["exec", "postgres-test"]:
            sql = args[-1]
            if "SELECT organization_id" in sql:
                print("offline-org")
            elif "SELECT provider_resource_id" in sql:
                print("i-offline|192.0.2.1|us-west-2")
            else:
                assert "UPDATE users" in sql or "INSERT INTO credit_ledger" in sql
            return 0
    if name == "aws":
        if args[:2] == ["ec2", "describe-instances"]:
            print("sg-offline")
            return 0
        if args[:2] == ["ec2", "describe-security-groups"]:
            print(json.dumps({"SecurityGroups": [{"IpPermissions": [{
                "IpProtocol": "tcp", "FromPort": 49500, "ToPort": 49500,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }]}]}))
            return 0
        if args[:2] == ["ec2", "describe-instance-attribute"]:
            print("")  # Empty user-data has no forbidden application proxy.
            return 0
    if name == "curl":
        url = next(arg for arg in args if arg.startswith("http://"))
        body, status = "", "200"
        if url.endswith("/auth/e2e-login"):
            body = json.dumps({"session_id": "offline-session", "user_id": "offline-user", "expires_at": "2099-01-01"})
        elif url.endswith("/ssh-keys"):
            body = '{"fingerprint":"offline-fingerprint"}'
        elif url.endswith("/e2p/v2/session"):
            body, status = '{"error":"protocol_error"}', "400"
        elif url.endswith("/attestation"):
            body = '{"document":"offline-not-real-attestation"}'
        elif "plaintext-probe" in url:
            body, status = '{"error":"e2e_required"}', "403"
        elif not (url.endswith("/health") or url.endswith("/user/username") or url.endswith("/resources")):
            raise AssertionError("Unexpected URL " + url)
        if "-o" in args:
            output = args[args.index("-o") + 1]
            if output != "/dev/null":
                Path(output).write_text(body)
        else:
            print(body, end="")
        if "-D" in args:
            Path(args[args.index("-D") + 1]).write_text("Cache-Control: no-store\r\n")
        if "-w" in args:
            print(status, end="")
        return 0
    raise AssertionError(f"Unexpected external command: {name} {args}")


class PlatformPortsContracts(unittest.TestCase):
    def run_script(self, **settings):
        temporary = tempfile.TemporaryDirectory(prefix="platform-ports-contract-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        script = root / "repo/tests/e2e/test_platform_ports.sh"
        script.parent.mkdir(parents=True)
        shutil.copyfile(HERE / script.name, script)
        shutil.copytree(HERE / "fixtures/demo-app-platform-ports",
                        script.parent / "fixtures/demo-app-platform-ports")
        bin_dir = root / "bin"
        bin_dir.mkdir()
        for name in ("git", "curl", "docker", "aws", "caution", "ssh", "ssh-keygen", "ssh-agent", "ssh-add", "sleep"):
            executable = bin_dir / name
            executable.write_text(f"#!{sys.executable}\n" + Path(__file__).read_text())
            executable.chmod(0o700)
        # Allow only known local utilities: no fallback to real network tools.
        for name in ("dirname", "mktemp", "date", "mkdir", "tee", "rm", "tail", "seq",
                     "jq", "head", "tr", "cat", "cp", "grep", "cut", "base64", "cmp", "timeout"):
            path = shutil.which(name)
            if path is None:
                self.fail(f"Required local test utility missing: {name}")
            (bin_dir / name).symlink_to(path)
        (root / "tmp").mkdir()
        env = {"PATH": str(bin_dir), "HOME": str(root), "XDG_CONFIG_HOME": str(root / "config"),
               "TMPDIR": str(root / "tmp"), "FAKE_ROOT": str(root), "LC_ALL": "C",
               "GATEWAY_URL": "http://gateway.invalid", "API_URL": "http://api.invalid",
               "CAUTION_BIN": str(bin_dir / "caution"),
               "SSH_AGENT_PID": "313131", "SSH_AUTH_SOCK": "/offline/inherited", **settings}
        result = subprocess.run(["/bin/bash", str(script)], cwd=root, env=env,
                                text=True, capture_output=True, timeout=20)
        self.assertNotIn("Traceback", result.stdout + result.stderr)
        calls = [json.loads(line) for line in (root / "calls.jsonl").read_text().splitlines()]
        work_dir = Path((root / "work-dir").read_text())
        return result, calls, work_dir

    def test_only_confirmed_pending_refusal_is_retried(self):
        for mode in ("auth", "lookalike", "timeout", "killed", "interrupted"):
            with self.subTest(mode=mode):
                result, calls, work = self.run_script(PUSH_STATUS="37", DESTROY_MODE=mode)
                self.assertEqual(result.returncode, 37, result.stdout + result.stderr)
                self.assertIn("Passed: 4  Failed: 2", result.stdout)
                self.assertEqual(sum(name == "caution" and "destroy" in args for name, args in calls), 1)
                self.assertFalse(any(name == "sleep" for name, _ in calls))
                self.assertTrue((work / "cleanup.log").is_file())
                self.assertIn(["ssh-agent", ["-k"]], calls)

    def test_owned_agent_is_stopped_on_success_and_failures(self):
        for settings in ({}, {"PUSH_STATUS": "37"}, {"SSH_ADD_STATUS": "42"}, {"DESTROY_MODE": "failed"}):
            with self.subTest(settings=settings):
                result, calls, _ = self.run_script(**settings)
                self.assertIn(["ssh-agent", ["-s"]], calls)
                self.assertEqual(calls.count(["ssh-agent", ["-k"]]), 1, result.stdout)

    def test_failed_agent_start_does_not_kill_inherited_agent(self):
        result, calls, _ = self.run_script(AGENT_START_STATUS="42")
        self.assertEqual(result.returncode, 42, result.stdout + result.stderr)
        self.assertIn("Passed: 2  Failed: 1", result.stdout)
        self.assertNotIn(["ssh-agent", ["-k"]], calls)

    def test_failed_agent_cleanup_is_reported_and_retained(self):
        result, _, work = self.run_script(AGENT_KILL_STATUS="1")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Passed: 8  Failed: 1", result.stdout)
        self.assertIn("Could not stop owned SSH agent", result.stdout)
        self.assertTrue(work.exists())

    def test_inflight_deployment_settles_before_canonical_cleanup(self):
        result, calls, work = self.run_script(PUSH_STATUS="37", DESTROY_MODE="settles")
        self.assertEqual(result.returncode, 37, result.stdout + result.stderr)
        self.assertIn("Passed: 4  Failed: 1", result.stdout)
        self.assertNotIn("[FAIL] Cleanup:", result.stdout)
        self.assertIn("resource is deploying", result.stdout)
        self.assertIn("App destroyed", result.stdout)
        self.assertEqual(sum(name == "caution" and "destroy" in args for name, args in calls), 3)
        self.assertEqual(sum(name == "sleep" for name, _ in calls), 2)
        self.assertFalse(work.exists())

    def test_permanently_pending_cleanup_is_bounded_and_retained(self):
        result, calls, work = self.run_script(PUSH_STATUS="37", DESTROY_MODE="pending")
        self.assertEqual(result.returncode, 37, result.stdout + result.stderr)
        self.assertIn("Passed: 4  Failed: 2", result.stdout)
        self.assertIn("[FAIL] Cleanup:", result.stdout)
        self.assertIn("Cleanup retry budget exhausted", result.stdout)
        self.assertEqual(sum(name == "caution" and "destroy" in args for name, args in calls), 60)
        self.assertTrue((work / "cleanup.log").is_file())
        self.assertEqual((work / "cleanup.log").read_text().count("resource is deploying"), 60)

    def test_failed_cleanup_fails_run_and_preserves_evidence(self):
        for push_status, passed, failed, expected_exit in (("0", 8, 1, 1), ("37", 4, 2, 37)):
            with self.subTest(push_status=push_status):
                result, calls, work = self.run_script(PUSH_STATUS=push_status, DESTROY_MODE="failed")
                self.assertEqual(result.returncode, expected_exit, result.stdout + result.stderr)
                self.assertIn(f"Passed: {passed}  Failed: {failed}", result.stdout)
                self.assertIn("[FAIL] Cleanup:", result.stdout)
                self.assertIn("app destroy failed", result.stdout)
                self.assertIn(str(work), result.stdout)
                self.assertTrue((work / "demo-app/.caution/deployment.json").is_file())
                self.assertEqual(sum(name == "caution" and "destroy" in args for name, args in calls), 1)

    def test_existing_step_failure_is_not_double_counted(self):
        result, _, _ = self.run_script(APP_STATE="failed")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Passed: 4  Failed: 1", result.stdout)
        self.assertIn("Deployment (", result.stdout)
        self.assertNotIn("Unexpected exit", result.stdout)

    def test_success_remains_success(self):
        result, _, work = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Passed: 8  Failed: 0", result.stdout)
        self.assertFalse(work.exists())

    def test_unexpected_git_failure_is_counted_and_preserves_exit(self):
        result, calls, work = self.run_script(PUSH_STATUS="37")
        self.assertEqual(result.returncode, 37, result.stdout + result.stderr)
        self.assertIn("Passed: 4  Failed: 1", result.stdout)
        self.assertIn("[FAIL] Step 5:", result.stdout)
        self.assertNotIn("Waiting for deployment to complete", result.stdout)
        self.assertFalse(work.exists())
        self.assertIn(["caution", ["-u", "http://gateway.invalid", "apps", "destroy", RESOURCE, "--force"]], calls)


if __name__ == "__main__":
    if Path(sys.argv[0]).name in ("git", "curl", "docker", "aws", "caution", "ssh", "ssh-keygen", "ssh-agent", "ssh-add", "sleep"):
        sys.exit(fake_command())
    unittest.main()
