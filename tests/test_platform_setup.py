# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
"""Run real local setup/migration scripts with isolated HOME and fake commands.

No AWS, Docker, systemd or database operations; this is not cloud/native-login e2e.
Run with: make test-setup
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
with open(os.environ["HARNESS_LOG"], "a") as log:
    log.write(json.dumps({"tool": name, "args": args,
        "env": {k: v for k, v in os.environ.items() if k == "PGPASSWORD"}}) + "\n")
command = args[-1] if name == "systemctl" else args[0]
if os.environ.get("FAIL") == f"{name}:{command}":
    sys.exit(17)
if name == "docker":
    assert args == ["info"], args
elif name == "systemctl":
    assert args in (["--user", "show-environment"], ["--user", "daemon-reload"]), args
else:
    assert name == "psql", name
'''


class PlatformSetupTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="platform setup tests ")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.home, self.workspace, bin_dir = (self.root / p for p in ("home", "workspace", "bin"))
        for path in (self.home, self.workspace, bin_dir):
            path.mkdir()
        for name in ("docker", "systemctl", "psql"):
            executable = bin_dir / name
            executable.write_text(f"#!{sys.executable}\n" + STUB)
            executable.chmod(0o755)
        self.log = self.root / "calls.jsonl"
        self.env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(self.home),
                    "HARNESS_LOG": str(self.log)}

    def run_script(self, script, args=(), stdin="", **env):
        self.log.unlink(missing_ok=True)
        shell = "sh" if script == "utils/makefile-run-migrations.sh" else "bash"
        result = subprocess.run([shell, str(ROOT / script), *args], cwd=self.workspace,
                                env={**self.env, **env}, input=stdin, text=True,
                                capture_output=True, timeout=10)
        self.calls = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        return result

    def args(self, tool):
        return [call["args"] for call in self.calls if call["tool"] == tool]

    def test_setup_installs_and_preserves_configuration_without_starting_services(self):
        self.addCleanup(os.umask, os.umask(0o077))
        config = self.home / ".config/caution"
        self.env["XDG_CONFIG_HOME"] = str(self.home / "custom config")
        units = Path(self.env["XDG_CONFIG_HOME"]) / "systemd/user"
        result = self.run_script("scripts/setup-platform.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        for directory in (config, units):
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.args("docker"), [["info"]])
        self.assertEqual(self.args("systemctl"), [["--user", "show-environment"], ["--user", "daemon-reload"]])
        for name, example in ((".env", "env.example"), ("prices.json", "prices.json.example"), ("config.json", "config.json.example")):
            path = config / name
            self.assertEqual(path.read_bytes(), (ROOT / example).read_bytes())
            self.assertEqual(path.stat().st_mode & 0o777, 0o644 if name == "prices.json" else 0o600)
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
            self.assertEqual(path.stat().st_mode & 0o777, 0o644 if path.name == "prices.json" else 0o640)
        self.assertTrue((config / "config.json").is_symlink())
        for source in (ROOT / "systemd").glob("*.service"):
            self.assertEqual((units / source.name).read_bytes(), source.read_bytes())
        (config / "prices.json").unlink()
        result = self.run_script("scripts/setup-platform.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((config / "prices.json").read_bytes(), (ROOT / "prices.json.example").read_bytes())
        self.assertEqual((config / ".env").read_text(), "operator configuration")

    def test_setup_repairs_private_pricing_without_replacing_custom_configuration(self):
        self.addCleanup(os.umask, os.umask(0o077))
        config = self.home / ".config/caution"
        units = self.home / ".config/systemd/user"
        for directory in (config, units):
            directory.mkdir(parents=True)
            directory.chmod(0o750)
        contents = {".env": b"OPERATOR_SETTING=custom\n", "config.json": b'{"operator":"custom"}\n',
                    "prices.json": b'{"operator":"custom prices"}\n'}
        for name, content in contents.items():
            (config / name).write_bytes(content)
            (config / name).chmod(0o600)
        pricing_inode = (config / "prices.json").stat().st_ino
        for _ in range(2):
            result = self.run_script("scripts/setup-platform.sh")
            self.assertEqual(result.returncode, 0, result.stderr)
            for name, content in contents.items():
                self.assertEqual((config / name).read_bytes(), content)
                self.assertEqual((config / name).stat().st_mode & 0o777,
                                 0o644 if name == "prices.json" else 0o600)
            self.assertEqual((config / "prices.json").stat().st_ino, pricing_inode)
            for directory in (config, units):
                self.assertEqual(directory.stat().st_mode & 0o777, 0o750)

    def test_setup_preserves_linked_pricing_targets(self):
        config = self.home / ".config/caution"
        config.mkdir(parents=True)
        prices = config / "prices.json"
        for kind in ("symlink", "hardlink"):
            for mode in (0o600, 0o644):
                with self.subTest(kind=kind, mode=oct(mode)):
                    prices.unlink(missing_ok=True)
                    target = config / (".env" if mode == 0o600 else "operator-prices.json")
                    content = b"OPERATOR_SETTING=private\n" if mode == 0o600 else b'{"operator":"prices"}\n'
                    target.write_bytes(content)
                    target.chmod(mode)
                    if kind == "symlink":
                        prices.symlink_to(target)
                    else:
                        prices.hardlink_to(target)
                    inode = prices.lstat().st_ino
                    for _ in range(2):
                        result = self.run_script("scripts/setup-platform.sh")
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(target.stat().st_mode & 0o777, mode)
                        self.assertEqual(target.read_bytes(), content)
                        self.assertEqual(prices.lstat().st_ino, inode)
                        self.assertTrue(prices.samefile(target))
                        self.assertIn("permissions left unchanged", result.stderr)

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
