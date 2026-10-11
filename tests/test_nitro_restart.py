#!/usr/bin/env python3
"""Render the real Terraform template and exercise its Nitro lifecycle helpers.

Requires terraform, bash, jq, and Python 3. No AWS access or host service changes.
Set NITRO_TEST_ARTIFACTS to retain rendered units/helpers for Linux validation.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "terraform/modules/aws/nitro-enclave/user-data.sh"
MOCK_CLI = '''#!/usr/bin/env python3
import json, os, pathlib, sys
state = pathlib.Path(os.environ["RUNTIME_DIRECTORY"])
args = sys.argv[1:]
with (state / "calls").open("a") as out:
    out.write(json.dumps(args) + "\\n")
mode = os.environ.get("MOCK_MODE", "")
if args[0] == "run-enclave":
    if mode == "launch-failure":
        sys.exit(7)
    print(os.environ["MOCK_LAUNCH"])
elif args[0] == "describe-enclaves":
    if mode == "describe-failure":
        sys.exit(8)
    print((state / "live.json").read_text())
elif args[0] == "terminate-enclave":
    assert args[1] == "--enclave-id" and len(args) == 3
    if mode != "terminate-failure":
        live = json.loads((state / "live.json").read_text())
        (state / "live.json").write_text(json.dumps([x for x in live if x["EnclaveID"] != args[2]]))
    if mode in ("terminate-failure", "termination-race"):
        sys.exit(9)
else:
    sys.exit(10)
'''


def heredoc(text, delimiter):
    return text.split("<<'" + delimiter + "'\n", 1)[1].split("\n" + delimiter, 1)[0] + "\n"


def render(policy="on-failure", delay=10, debug=False):
    variables = dict(eif_s3_path="s3://test/enclave.eif", memory_mb=512,
                     cpu_count=2, debug_mode=str(debug).lower(), ssh_keys=[],
                     ports=[8080], http_port=8080, e2e="false", e2e_mode="disabled",
                     locksmith="false", egress="false", domain="test.example.invalid",
                     restart_policy=policy, restart_delay_seconds=delay)
    expression = "jsonencode(templatefile(" + json.dumps(str(TEMPLATE)) + ", " + json.dumps(variables) + "))\n"
    with tempfile.TemporaryDirectory() as directory:
        result = subprocess.run(["terraform", "console", "-no-color"], input=expression,
                                cwd=directory, text=True, capture_output=True, timeout=30,
                                env={**os.environ, "CHECKPOINT_DISABLE": "1"})
    if result.returncode:
        raise AssertionError(result.stderr)
    return json.loads(json.loads(result.stdout))


class NitroRestartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rendered = {(policy, debug): render(policy, 0, debug)
                        for policy in ("never", "on-failure", "always")
                        for debug in (False, True)}
        artifacts = os.environ.get("NITRO_TEST_ARTIFACTS")
        if artifacts:
            directory = Path(artifacts)
            directory.mkdir(parents=True, exist_ok=True)
            text = cls.rendered["always", True]
            for name, delimiter in [("start-nitro-enclave", "START_ENCLAVE"),
                                    ("stop-nitro-enclave", "STOP_ENCLAVE"),
                                    ("capture-enclave-console.sh", "CONSOLE_CAPTURE")]:
                (directory / name).write_text(heredoc(text, delimiter))
                (directory / name).chmod(0o755)
            (directory / "user-data.sh").write_text(text)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.env = dict(os.environ, RUNTIME_DIRECTORY=str(self.path),
                        PATH=str(self.path) + os.pathsep + os.environ["PATH"],
                        MOCK_LAUNCH=json.dumps({"EnclaveID": "i-test-enc001", "ProcessID": os.getpid()}))
        for name, delimiter in [("start", "START_ENCLAVE"), ("stop", "STOP_ENCLAVE")]:
            (self.path / name).write_text(heredoc(self.rendered["always", False], delimiter))
        (self.path / "nitro-cli").write_text(MOCK_CLI)
        (self.path / "nitro-cli").chmod(0o755)
        (self.path / "live.json").write_text(json.dumps([
            {"EnclaveID": "i-test-enc001"}, {"EnclaveID": "i-other-enc002"}]))

    def helper(self, name, *args):
        return subprocess.run(["bash", str(self.path / name), *args], env=self.env,
                              capture_output=True, text=True, timeout=10)

    def bootstrap(self, text, launch_status=0, caddy_status=0):
        # Run the actual remainder of user-data, with host writes redirected and
        # package/network/service operations mocked. Keep `set -e` active.
        script = text.split("systemctl daemon-reload\nsystemctl enable nitro-enclave.service", 1)[1]
        script = "systemctl daemon-reload\nsystemctl enable nitro-enclave.service" + script
        script = re.sub(r"/(?:etc|var|usr/local|tmp)/",
                        lambda match: str(self.path) + match.group(), script)
        (self.path / "etc/systemd/system").mkdir(parents=True, exist_ok=True)
        prelude = '''set -e
standard_ports="49500 49501 49502"
systemctl() {
  printf '%s\\n' "$*" >> "$RUNTIME_DIRECTORY/bootstrap-calls"
  case "$*" in
    "start nitro-enclave.service") return "$MOCK_START_STATUS" ;;
    "start caddy") return "$MOCK_CADDY_STATUS" ;;
  esac
  return 0
}
sleep() { :; }
curl() { :; }
tar() { :; }
chmod() { :; }
rm() { :; }
useradd() { :; }
chown() { :; }
journalctl() { :; }
'''
        (self.path / "bootstrap-calls").write_text("")
        env = dict(self.env, MOCK_START_STATUS=str(launch_status),
                   MOCK_CADDY_STATUS=str(caddy_status))
        return subprocess.run(["bash"], input=prelude + script, env=env,
                              capture_output=True, text=True, timeout=10)

    def test_bootstrap_completes_even_if_initial_enclave_start_fails(self):
        for (policy, debug), text in self.rendered.items():
            for status in (0, 1):
                with self.subTest(policy=policy, debug=debug, launch_status=status):
                    result = self.bootstrap(text, launch_status=status)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    calls = (self.path / "bootstrap-calls").read_text().splitlines()
                    for service in ("vsock-proxy-49500.service", "vsock-proxy-49501.service",
                                    "vsock-proxy-49502.service", "vsock-proxy-http.service",
                                    "vsock-proxy-8080.service", "caddy"):
                        self.assertIn("start " + service, calls)
                    self.assertEqual(calls.count("start nitro-enclave.service"), 1)
                    self.assertTrue((self.path / "etc/caddy/Caddyfile").is_file())
                    self.assertTrue((self.path / "etc/systemd/system/caddy.service").is_file())
                    self.assertIn("=== Nitro Enclave Setup Complete ===", result.stdout)
                    self.assertEqual("WARNING: initial enclave launch failed" in result.stderr, status != 0)

    def test_bootstrap_still_aborts_on_caddy_failure(self):
        result = self.bootstrap(self.rendered["on-failure", False], launch_status=1, caddy_status=7)
        self.assertEqual(result.returncode, 7)
        self.assertIn("start caddy", (self.path / "bootstrap-calls").read_text())
        self.assertNotIn("=== Nitro Enclave Setup Complete ===", result.stdout)

    def test_rendered_units_and_shell(self):
        for (policy, debug), text in self.rendered.items():
            with self.subTest(policy=policy, debug=debug):
                check = subprocess.run(["bash", "-n"], input=text, text=True, capture_output=True)
                self.assertEqual(check.returncode, 0, check.stderr)
                unit = text.split("/etc/systemd/system/nitro-enclave.service <<EOF\n", 1)[1].split("\nEOF", 1)[0]
                expected = "no" if policy == "never" else policy
                self.assertIn("Restart=" + expected + "\n", unit)
                self.assertIn("RestartSec=0s", unit)
                self.assertIn("Type=forking", unit)
                self.assertIn("PIDFile=/run/nitro-enclave/enclave.pid", unit)
                self.assertIn("KillMode=control-group", unit)
                self.assertEqual("ExecStartPost=" in unit, debug)
                self.assertEqual("--debug-mode" in unit, debug)
                self.assertNotIn("tail -f", unit)
                self.assertNotIn("terminate-enclave --all", text)
                for block in text.split("Description=VSock Proxy")[1:]:
                    self.assertNotIn("Requires=nitro-enclave", block.split("\nEOF", 1)[0])
        self.assertIn("RestartSec=10s", render())

    def test_start_records_pid_id_and_preserves_arguments(self):
        result = self.helper("start", "--enclave-cid", "16", "--debug-mode")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.path / "enclave.pid").read_text().strip(), str(os.getpid()))
        self.assertEqual((self.path / "enclave.id").read_text().strip(), "i-test-enc001")
        self.assertEqual(json.loads((self.path / "calls").read_text().splitlines()[0]),
                         ["run-enclave", "--enclave-cid", "16", "--debug-mode"])

    def test_launch_failure_removes_stale_identity(self):
        (self.path / "enclave.pid").write_text("999999")
        (self.path / "enclave.id").write_text("i-old-enc001")
        self.env["MOCK_MODE"] = "launch-failure"
        self.assertNotEqual(self.helper("start").returncode, 0)
        self.assertFalse((self.path / "enclave.pid").exists())
        self.assertFalse((self.path / "enclave.id").exists())
        self.assertEqual(self.helper("stop").returncode, 0)

    def test_invalid_launch_json_is_rejected(self):
        for output in ["not json", "{}", '{"EnclaveID":"--all","ProcessID":42}',
                       '{"EnclaveID":"i-test-enc001","ProcessID":0}',
                       '{"EnclaveID":"i-test-enc001","ProcessID":2.5}',
                       '{"EnclaveID":"i-test-enc001","ProcessID":"42"}']:
            with self.subTest(output=output):
                self.env["MOCK_LAUNCH"] = output
                self.assertNotEqual(self.helper("start").returncode, 0)
                self.assertFalse((self.path / "enclave.pid").exists())

    def test_stop_targets_only_recorded_enclave(self):
        self.assertEqual(self.helper("start").returncode, 0)
        result = self.helper("stop")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads((self.path / "live.json").read_text()), [{"EnclaveID": "i-other-enc002"}])
        self.assertFalse((self.path / "enclave.id").exists())
        self.assertEqual(self.helper("stop").returncode, 0)

    def test_already_gone_and_termination_race_succeed(self):
        for mode in ["already-gone", "termination-race"]:
            with self.subTest(mode=mode):
                self.assertEqual(self.helper("start").returncode, 0)
                live = [] if mode == "already-gone" else [{"EnclaveID": "i-test-enc001"}]
                (self.path / "live.json").write_text(json.dumps(live))
                self.env["MOCK_MODE"] = mode
                self.assertEqual(self.helper("stop").returncode, 0)
                self.assertFalse((self.path / "enclave.id").exists())

    def test_real_shutdown_errors_are_not_suppressed(self):
        self.assertEqual(self.helper("start").returncode, 0)
        for mode in ["terminate-failure", "describe-failure"]:
            self.env["MOCK_MODE"] = mode
            self.assertNotEqual(self.helper("stop").returncode, 0)
            self.assertTrue((self.path / "enclave.id").exists())
        self.env["MOCK_MODE"] = ""
        for invalid in ["not json", "{}", "[1]"]:
            (self.path / "live.json").write_text(invalid)
            self.assertNotEqual(self.helper("stop").returncode, 0)
            self.assertTrue((self.path / "enclave.id").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
