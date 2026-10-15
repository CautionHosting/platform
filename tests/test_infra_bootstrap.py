# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
"""Run real setup/bootstrap scripts with isolated HOME and fake external commands.

No AWS, Docker, systemd or database operations; this is not cloud/native-login e2e.
Run with: make test-bootstrap
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
STUB = r'''
import json, os, sys
from pathlib import Path
name, args = Path(sys.argv[0]).name, sys.argv[1:]
plan = Path("tfplan")
with open(os.environ["HARNESS_LOG"], "a") as log:
    log.write(json.dumps({"tool": name, "args": args,
        "env": {k: v for k, v in os.environ.items() if k.startswith("AWS_") or k == "PGPASSWORD"},
        "plan_mode": plan.stat().st_mode & 0o777 if plan.exists() else None}) + "\n")
command = args[-1] if name == "systemctl" else args[0]
if os.environ.get("FAIL") == f"{name}:{command}":
    sys.exit(17)
if name == "aws":
    assert args[:2] in (["sts", "get-caller-identity"], ["s3", "ls"]), args
    print("000000000000")
elif name in ("tofu", "terraform"):
    values = {"aws_access_key_id": "SYNTHETIC-PLATFORM-KEY",
              "aws_secret_access_key": "synthetic-platform-secret",
              "aws_region": "eu-central-1", "s3_bucket_name": "synthetic-state",
              "eif_bucket_name": "synthetic-eif", "apps_dns_zone_id": "SYNTHETIC-ZONE",
              "apps_dns_zone_name": "apps.example.invalid", "apps_dns_name_servers": []}
    for key in ("aws_access_key_id", "aws_secret_access_key"):
        if os.environ.get("NO_KEY") == "null":
            values[key] = None
        elif os.environ.get("NO_KEY") == "omitted":
            del values[key]
    if command == "plan":
        plan.write_text("synthetic saved plan")
    elif command == "output":
        if args[-1] == os.environ.get("FAIL_OUTPUT"):
            sys.exit(18)
        if args == ["output", "-json"]:
            print(json.dumps({k: {"value": v} for k, v in values.items()}))
        else:
            print(json.dumps(values[args[-1]]) if args[1] == "-json" else values[args[-1]])
    else:
        assert command in ("init", "apply"), args
elif name == "docker":
    assert command in ("images", "run", "info"), args
    if command == "images":
        print("infra-bootstrap latest SYNTHETIC")
elif name == "systemctl":
    assert args in (["--user", "show-environment"], ["--user", "daemon-reload"]), args
else:
    assert name == "psql", name
'''


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="bootstrap tests ")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.home, self.workspace, bin_dir = (self.root / p for p in ("home", "workspace", "bin"))
        for path in (self.home, self.workspace, bin_dir):
            path.mkdir()
        for name in ("aws", "tofu", "terraform", "docker", "systemctl", "psql"):
            executable = bin_dir / name
            executable.write_text(f"#!{sys.executable}\n" + STUB)
            executable.chmod(0o755)
        self.log = self.root / "calls.jsonl"
        self.env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(self.home),
                    "HARNESS_LOG": str(self.log), "AWS_ACCESS_KEY_ID": "SYNTHETIC-ADMIN-KEY",
                    "AWS_SECRET_ACCESS_KEY": "synthetic secret *", "AWS_SESSION_TOKEN": "synthetic session /+="}

    def run_script(self, script="infra-bootstrap/entrypoint.sh", args=(), stdin="yes\n", **env):
        self.log.unlink(missing_ok=True)
        shell = "sh" if script == "utils/makefile-run-migrations.sh" else "bash"
        result = subprocess.run([shell, str(ROOT / script), *args], cwd=self.workspace,
                                env={**self.env, **env}, input=stdin, text=True,
                                capture_output=True, timeout=10)
        self.calls = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        return result

    def args(self, tool):
        return [call["args"] for call in self.calls if call["tool"] == tool]

    def test_plan_forwards_variables_without_applying(self):
        variables = ["-var", "state_bucket_name=unique", "-var-file=settings with spaces.tfvars"]
        plan = self.workspace / "tfplan"
        plan.write_text("stale plan")
        plan.chmod(0o644)
        result = self.run_script(args=["plan", *variables])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.args("tofu"), [["init"], ["plan", "-out=tfplan", *variables]])
        self.assertEqual(next(c["plan_mode"] for c in self.calls if c["args"][0] == "plan"), 0o600)
        self.assertFalse((self.workspace / "outputs.json").exists())

    def test_apply_uses_saved_plan_and_private_exports(self):
        variables = ["-var=state_bucket_name=unique", "-var-file", "my vars.tfvars"]
        for args in ([], variables, ["apply", *variables]):
            with self.subTest(args=args):
                result = self.run_script(args=args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.args("tofu")[:3], [["init"],
                    ["plan", "-out=tfplan", *(variables if args else [])], ["apply", "tfplan"]])
                for filename in ("tfplan", "outputs.json", "aws-credentials.env"):
                    self.assertEqual((self.workspace / filename).stat().st_mode & 0o777, 0o600)
                credentials = (self.workspace / "aws-credentials.env").read_text()
                self.assertIn("AWS_REGION=eu-central-1\n", credentials)
                self.assertIn("AWS_SECRET_ACCESS_KEY=synthetic-platform-secret\n", credentials)
                for secret in ("SYNTHETIC-PLATFORM-KEY", "synthetic-platform-secret"):
                    self.assertNotIn(secret, result.stdout + result.stderr)
                buckets = [c for c in self.calls if c["tool"] == "aws" and c["args"][:2] == ["s3", "ls"]]
                self.assertEqual(len(buckets), 2)
                for call in buckets:
                    self.assertEqual(call["env"], {k: v for k, v in self.env.items() if k.startswith("AWS_")})

    def test_invalid_arguments_and_unconfirmed_apply_do_not_mutate(self):
        for args in (["destroy"], ["apply", "-out=other"], ["apply", "-auto-approve"],
                     ["plan", "unexpected.tfplan"], ["plan", "-var"], ["plan", "-var-file="]):
            with self.subTest(args=args):
                self.assertNotEqual(self.run_script(args=args).returncode, 0)
                self.assertEqual(self.calls, [])
        for stdin in ("no\n", "YES\n", "yes please\n", ""):
            with self.subTest(stdin=stdin):
                self.run_script(stdin=stdin)
                self.assertEqual(self.args("tofu"), [["init"], ["plan", "-out=tfplan"]])
                self.assertFalse((self.workspace / "outputs.json").exists())

    def test_failures_stop_before_later_steps_and_preserve_exports(self):
        exports = [self.workspace / p for p in ("outputs.json", "aws-credentials.env")]
        for path in exports:
            path.write_text("previous output")
        for failure, steps in (("aws:sts", []), ("tofu:init", ["init"]),
                               ("tofu:plan", ["init", "plan"]), ("tofu:apply", ["init", "plan", "apply"])):
            with self.subTest(failure=failure):
                (self.workspace / "tfplan").write_text("stale plan")
                result = self.run_script(FAIL=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual([args[0] for args in self.args("tofu")], steps)
                self.assertEqual([p.read_text() for p in exports], ["previous output"] * 2)
        for output in ("aws_region", "aws_access_key_id"):
            with self.subTest(output=output):
                result = self.run_script(FAIL_OUTPUT=output)
                self.assertEqual(result.returncode, 18, result.stderr)
                self.assertEqual([p.read_text() for p in exports], ["previous output"] * 2)
                self.assertNotIn("Bootstrap complete!", result.stdout)
                self.assertEqual(list(self.workspace.glob(".*.??????")), [])

    def test_absent_optional_platform_key_is_not_an_output_failure(self):
        for representation in ("null", "omitted"):
            with self.subTest(representation=representation):
                result = self.run_script(NO_KEY=representation)
                self.assertEqual(result.returncode, 0, result.stderr)
                credentials = (self.workspace / "aws-credentials.env").read_text()
                self.assertNotIn("AWS_ACCESS_KEY_ID=", credentials)
                self.assertNotIn("AWS_SECRET_ACCESS_KEY=", credentials)

    def test_docker_preserves_arguments_identity_and_authentication(self):
        aws_dir = self.home / ".aws"
        cache = aws_dir / "login/cache"
        cache.mkdir(parents=True)
        caller_args = ["plan", "-var-file", "file with spaces.tfvars", "-var=tag=literal * $(false)"]
        for environment_credentials in (True, False):
            with self.subTest(environment_credentials=environment_credentials):
                if not environment_credentials:
                    self.env = {k: v for k, v in self.env.items() if not k.startswith("AWS_")}
                result = self.run_script("infra-bootstrap/run.sh", caller_args,
                                         AWS_PROFILE="synthetic-profile", AWS_REGION="eu-central-1")
                self.assertEqual(result.returncode, 0, result.stderr)
                runs = [c for c in self.calls if c["tool"] == "docker" and c["args"][0] == "run"]
                self.assertEqual(len(runs), 1)
                args = runs[0]["args"]
                self.assertEqual(args[args.index("infra-bootstrap") + 1:], caller_args)
                self.assertEqual(args[args.index("--user") + 1], f"{os.getuid()}:{os.getgid()}")
                self.assertIn("HOME=/tmp", args)
                self.assertEqual([args[i + 1] for i, arg in enumerate(args) if arg == "-v"],
                    [f"{aws_dir}:/tmp/.aws:ro", f"{cache}:/tmp/.aws/login/cache:rw", f"{self.workspace}:/workspace"])
                for key, value in runs[0]["env"].items():
                    self.assertIn(key, args)
                    self.assertNotIn(value, " ".join(args))
                    self.assertEqual(value, {**self.env, "AWS_PROFILE": "synthetic-profile", "AWS_REGION": "eu-central-1"}[key])

    def test_setup_installs_and_preserves_configuration_without_starting_services(self):
        config = self.home / ".config/caution"
        self.env["XDG_CONFIG_HOME"] = str(self.home / "custom config")
        units = Path(self.env["XDG_CONFIG_HOME"]) / "systemd/user"
        result = self.run_script("scripts/setup-platform.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.args("docker"), [["info"]])
        self.assertEqual(self.args("systemctl"), [["--user", "show-environment"], ["--user", "daemon-reload"]])
        for name, example in ((".env", "env.example"), ("prices.json", "prices.json.example"), ("config.json", "config.json.example")):
            path = config / name
            self.assertEqual(path.read_bytes(), (ROOT / example).read_bytes())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            path.write_text("operator configuration")
            path.chmod(0o640)
        target = self.home / "operator-config.json"
        (config / "config.json").rename(target)
        (config / "config.json").symlink_to(target)
        for source in (ROOT / "systemd").glob("*.service"):
            self.assertEqual((units / source.name).read_bytes(), source.read_bytes())
            (units / source.name).write_text("stale unit")
        result = self.run_script("scripts/setup-platform.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        for path in config.iterdir():
            self.assertEqual(path.read_text(), "operator configuration")
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)
        self.assertTrue((config / "config.json").is_symlink())
        for source in (ROOT / "systemd").glob("*.service"):
            self.assertEqual((units / source.name).read_bytes(), source.read_bytes())
        (config / "prices.json").unlink()
        result = self.run_script("scripts/setup-platform.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((config / "prices.json").read_bytes(), (ROOT / "prices.json.example").read_bytes())
        self.assertEqual((config / ".env").read_text(), "operator configuration")

    def test_setup_reports_prerequisite_and_reload_failures(self):
        for failure in ("systemctl:show-environment", "docker:info"):
            with self.subTest(failure=failure):
                self.assertNotEqual(self.run_script("scripts/setup-platform.sh", FAIL=failure).returncode, 0)
                self.assertFalse((self.home / ".config").exists())
        result = self.run_script("scripts/setup-platform.sh", FAIL="systemctl:daemon-reload")
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertNotIn("Setup complete", result.stdout)

    def test_setup_rejects_invalid_existing_config_without_replacing_it(self):
        config = self.home / ".config/caution/.env"
        config.mkdir(parents=True)
        for kind in ("directory", "dangling symlink"):
            with self.subTest(kind=kind):
                result = self.run_script("scripts/setup-platform.sh")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("readable regular file", result.stderr)
                self.assertNotIn(["--user", "daemon-reload"], self.args("systemctl"))
                self.assertTrue(config.is_dir() if kind == "directory" else config.is_symlink())
                self.assertFalse((self.home / "absent").exists())
                if kind == "directory":
                    config.rmdir()
                    config.symlink_to(self.home / "absent")

    def test_migrations_honor_postgres_settings_and_explicit_overrides(self):
        postgres = {"POSTGRES_USER": "pg-user", "POSTGRES_DB": "pg-db", "POSTGRES_PASSWORD": "pg-password"}
        overrides = {"MIGRATION_DB_HOST": "db-host", "MIGRATION_DB_USER": "migration-user",
                     "MIGRATION_DB_NAME": "migration-db", "PGPASSWORD": "migration-password"}
        for settings, expected in (({}, ["postgres", "postgres", "caution", ""]),
                (postgres, ["postgres", "pg-user", "pg-db", "pg-password"]),
                ({**postgres, **overrides}, ["db-host", "migration-user", "migration-db", "migration-password"])):
            with self.subTest(settings=settings):
                result = self.run_script("utils/makefile-run-migrations.sh", **settings)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.args("psql")[0][:8], ["-v", "ON_ERROR_STOP=1", "-h", expected[0], "-U", expected[1], "-d", expected[2]])
                self.assertEqual(self.calls[0]["env"]["PGPASSWORD"], expected[3])
        result = self.run_script("utils/makefile-run-migrations.sh", FAIL="psql:-v")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(len(self.args("psql")), 1)
