# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
"""Real hosted Make/scripts; external commands are inert, isolated adapters.

These tests never operate Docker, systemd, AWS or a live database. Run with
python3 -B tests/test_hosted_platform.py (standard library only).
"""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
UNITS = tuple('caution-' + name + '.service' for name in
              ('network', 'postgres', 'email', 'metering', 'api', 'gateway'))
ADAPTER = r'''
import json, os, sys
from pathlib import Path
name, args = Path(sys.argv[0]).name, sys.argv[1:]
with open(os.environ['HOSTED_TEST_LOG'], 'a') as log:
    log.write(json.dumps({'tool': name, 'args': args}) + '\n')
if os.environ.get('FAIL_TOOL') == name and os.environ.get('FAIL_ARG') in args:
    sys.exit(19)
if name == 'systemctl':
    assert '--user' in args, args
    if 'is-active' in args:
        units = [arg for arg in args if arg.endswith('.service')]
        assert units, args
        # Real systemctl returns success if ANY of multiple units is active.
        sys.exit(0 if any(unit != os.environ.get('INACTIVE_UNIT') for unit in units) else 3)
    assert any(action in args for action in ('show-environment', 'daemon-reload', 'enable', 'restart')), args
elif name == 'docker':
    assert args[0] in ('info', 'network', 'volume', 'build', 'rmi', 'image', 'exec', 'run', 'rm'), args
    if args[:3] == ['exec', 'postgres', 'pg_isready']:
        sys.exit(1 if os.environ.get('POSTGRES_DOWN') else 0)
    if args[:2] == ['image', 'inspect']:
        print('sha256:' + 'b' * 64 if '{{.Id}}' in args else json.dumps(['PLATFORM_GIT_SHA=' + 'a' * 40]))
    if '--print-inputs' in args:
        print(json.dumps({name: {'commit': str(i) * 40, 'repo': 'https://fixture.invalid/' + name}
                          for i, name in enumerate(('enclaveos', 'bootproof', 'steve', 'locksmith'), 1)}))
elif name == 'curl':
    url = args[-1]
    assert url in ('http://127.0.0.1:8000/api/legal/active-documents', 'http://127.0.0.1:8000/'), args
    backend = url.endswith('active-documents')
    failure = os.environ.get('HTTP_FAILURE', '')
    if failure == ('backend-down' if backend else 'frontend-down'):
        sys.exit(7)
    body = '[]' if backend else '<!doctype html><html><body>frontend</body></html>'
    if backend and failure == 'backend-html':
        body = '<!doctype html><html>wrong route</html>'
    if backend and failure == 'backend-object':
        body = '{}'
    if backend and failure == 'backend-malformed':
        body = 'not-json'
    if not backend and failure == 'frontend-empty':
        body = ''
    if not backend and failure == 'frontend-json':
        body = '{"status":"ok"}'
    print(body)
    print('302' if failure == 'redirect' else '200')
elif name == 'git':
    if args == ['rev-parse', 'HEAD'] or args[:2] == ['log', '-1']:
        print('a' * 40)
    else:
        assert args[:2] in (['diff', '--quiet'], ['status', '--porcelain=v1']), args
else:
    raise AssertionError((name, args))
'''


class HostedTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='hosted-platform-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.home, self.repo, self.bin = (self.root / name for name in ('home', 'repo', 'bin'))
        for directory in (self.home, self.repo, self.bin):
            directory.mkdir()
        for name in ('Makefile', 'env.example', 'prices.json.example', 'config.json.example'):
            shutil.copyfile(ROOT / name, self.repo / name)
        for name in ('scripts', 'systemd'):
            shutil.copytree(ROOT / name, self.repo / name, ignore=shutil.ignore_patterns('__pycache__'))
        (self.repo / 'src/cli').mkdir(parents=True)
        shutil.copyfile(ROOT / 'src/cli/Cargo.toml', self.repo / 'src/cli/Cargo.toml')
        (self.repo / 'fetch').mkdir()
        (self.repo / 'fetch/opentofu-1.12.4.tar.gz').touch()
        self.config = self.home / '.config/caution'
        self.units = self.home / '.config/systemd/user'
        self.log = self.root / 'calls.jsonl'
        for name in ('docker', 'systemctl', 'git', 'curl'):
            executable = self.bin / name
            executable.write_text(f'#!{sys.executable}\n' + ADAPTER)
            executable.chmod(0o755)
        self.env = {'PATH': f'{self.bin}:/usr/bin:/bin', 'HOME': str(self.home),
                    'HOSTED_TEST_LOG': str(self.log), 'PYTHONDONTWRITEBYTECODE': '1',
                    'CAUTION_HOSTED': '1', 'CAUTION_DNS_MODE': 'deferred', 'CAUTION_MAIL_MODE': 'test'}

    def make(self, *args, deadline=15, **env):
        self.log.unlink(missing_ok=True)
        command = ['make', '--no-print-directory', '-s', *args]
        with subprocess.Popen(command, cwd=self.repo, env={**self.env, **env}, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True) as child:
            try:
                stdout, stderr = child.communicate(timeout=deadline)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                stdout, stderr = child.communicate()
                stderr += '\nExceeded test harness deadline (production did not stop).'
            result = subprocess.CompletedProcess(command, child.returncode, stdout, stderr)
        self.calls = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        return result

    def args(self, tool):
        return [call['args'] for call in self.calls if call['tool'] == tool]

    def configure(self):
        self.config.mkdir(parents=True, exist_ok=True)
        (self.config / '.env').write_text('ENVIRONMENT=production\nCOMPONENT_BUILD_MODE=source\n'
                                        f'SYNTHETIC_SECRET=$(touch {self.home}/dotenv-executed)\n')
        (self.config / '.env').chmod(0o600)

    def test_generated_opentofu_archive_keeps_checkout_clean_without_hiding_other_files(self):
        # Real Git, isolated repository: no commit or remote operations needed.
        shutil.copyfile(ROOT / '.gitignore', self.repo / '.gitignore')
        git = shutil.which('git', path='/usr/bin:/bin')
        assert git is not None, 'Git is required for the isolated checkout regression'
        env = {**self.env, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}

        def run_git(*args):
            return subprocess.run([git, *args], cwd=self.repo, env=env, check=True,
                                  text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

        run_git('init', '-q')
        # Stage existing fixture sources, excluding the generated archive.
        for path in self.repo.iterdir():
            if path.name not in ('.git', 'fetch'):
                run_git('add', '--', path.name)
        self.assertEqual(run_git('ls-files', '--others', '--exclude-standard'), '')
        for name in ('fetch/operator-notes.txt', 'fetch/other.tar.gz',
                     'opentofu-1.12.4.tar.gz', 'operator-notes.txt'):
            (self.repo / name).touch()
            self.assertIn(name, run_git('ls-files', '--others', '--exclude-standard').splitlines())
        (self.repo / 'env.example').write_text('operator change\n')
        self.assertIn('env.example', run_git('diff', '--name-only'))

    def test_hosted_setup_requires_existing_dotenv(self):
        result = self.make('setup')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('hosted setup requires', result.stderr.lower())
        self.assertFalse((self.config / '.env').exists())
        self.assertFalse(self.units.exists())
        self.assertFalse(any('daemon-reload' in args or 'enable' in args for args in self.args('systemctl')))

    def test_hosted_setup_renders_copies_for_each_mode_without_touching_source_or_config(self):
        self.configure()
        original_env = (self.config / '.env').read_bytes()
        source_units = {p.name: p.read_bytes() for p in (self.repo / 'systemd').glob('*.service')}
        operator_config = self.home / 'operator-config.json'
        operator_config.write_text('{"operator":true}\n')
        operator_config.chmod(0o640)
        (self.config / 'config.json').symlink_to(operator_config)
        for dns in ('deferred', 'manual', 'delegated'):
            for mail in ('test', 'smtp'):
                with self.subTest(dns=dns, mail=mail):
                    result = self.make('setup', CAUTION_DNS_MODE=dns, CAUTION_MAIL_MODE=mail)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    gateway = (self.units / 'caution-gateway.service').read_text()
                    self.assertIn('-p 127.0.0.1:8000:8080 ', gateway)
                    self.assertIn('-p 127.0.0.1:2222:2222 ' if dns == 'deferred' else '-p 2222:2222 ', gateway)
                    email = (self.units / 'caution-email.service').read_text()
                    if mail == 'test':
                        self.assertIn('-e EMAIL_TEST_MODE=true -e ENVIRONMENT=development ', email)
                    else:
                        self.assertNotIn('EMAIL_TEST_MODE=', email)
                        self.assertNotIn('ENVIRONMENT=development', email)
                    for name in UNITS:
                        unit = self.units / name
                        self.assertEqual(unit.stat().st_mode & 0o777, 0o644)
                        self.assertIn('Restart=on-failure\n', unit.read_text())
                        self.assertIn('RestartSec=5\n', unit.read_text())
                    self.assertEqual(self.args('systemctl')[-2:], [
                        ['--user', 'daemon-reload'], ['--user', 'enable', *UNITS]])
                    self.assertFalse(any('restart' in args for args in self.args('systemctl')))
                    self.assertEqual((self.config / '.env').read_bytes(), original_env)
                    self.assertEqual((self.config / '.env').stat().st_mode & 0o777, 0o600)
                    self.assertTrue((self.config / 'config.json').is_symlink())
                    self.assertEqual(operator_config.read_text(), '{"operator":true}\n')
                    self.assertEqual(operator_config.stat().st_mode & 0o777, 0o640)
                    self.assertFalse((self.home / 'dotenv-executed').exists())
                    self.assertEqual({p.name: p.read_bytes() for p in (self.repo / 'systemd').glob('*.service')}, source_units)
                    self.assertEqual((self.config / 'prices.json').read_bytes(), (ROOT / 'prices.json.example').read_bytes())
                    self.assertEqual((self.config / 'prices.json').stat().st_mode & 0o777, 0o600)
                    self.assertEqual((self.units / 'caution-api.service').read_text().replace(
                        'Restart=on-failure\nRestartSec=5\n', ''), source_units['caution-api.service'].decode())

    def test_invalid_modes_fail_before_writing_files_or_enabling_services(self):
        self.configure()
        for key, value in (('CAUTION_DNS_MODE', ''), ('CAUTION_DNS_MODE', 'typo'),
                           ('CAUTION_MAIL_MODE', ''), ('CAUTION_MAIL_MODE', 'typo')):
            with self.subTest(key=key, value=value):
                result = self.make('setup', **{key: value})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(key, result.stderr)
                self.assertFalse(self.units.exists())
                self.assertEqual(list(self.config.iterdir()), [self.config / '.env'])
                self.assertFalse(any('enable' in args for args in self.args('systemctl')))

    def test_gateway_build_passes_requested_sandbox_arg_and_keeps_default(self):
        for value in ('true', ''):
            with self.subTest(value=value):
                result = self.make('build-gateway', VITE_PADDLE_SANDBOX=value)
                self.assertEqual(result.returncode, 0, result.stderr)
                build, = [args for args in self.args('docker') if args[0] == 'build']
                if value:
                    self.assertIn('--build-arg', build)
                    self.assertIn('VITE_PADDLE_SANDBOX=true', build)
                else:
                    self.assertNotIn('--build-arg', build)

    def test_hosted_postgres_wait_is_bounded(self):
        self.configure()
        result = self.make('postgres', POSTGRES_DOWN='1', CAUTION_HOSTED_WAIT_SECONDS='0.3', deadline=4)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Timed out waiting for postgres', result.stderr)
        self.assertNotIn('Exceeded test harness deadline', result.stderr)
        self.assertNotIn('Postgres ready', result.stdout)
        result = self.make('postgres', CAUTION_HOSTED_WAIT_SECONDS='2')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Postgres ready', result.stdout)

    def test_hosted_up_preserves_build_prepare_migrate_restart_then_checks_each_unit_and_http(self):
        self.configure()
        result = self.make('up', CAUTION_HOSTED_WAIT_SECONDS='2', VITE_PADDLE_SANDBOX='true')
        self.assertEqual(result.returncode, 0, result.stderr)
        active = [args for args in self.args('systemctl') if 'is-active' in args]
        self.assertEqual(active, [['--user', 'is-active', '--quiet', unit] for unit in UNITS])
        builds = [args for args in self.args('docker') if args[0] == 'build']
        self.assertEqual([args[args.index('-t') + 1] for args in builds],
                         ['caution-api-components', 'caution-gateway', 'caution-email', 'caution-metering'])
        self.assertIn('VITE_PADDLE_SANDBOX=true', builds[1])
        selection = (self.config / 'components.env').read_text()
        self.assertIn('API_COMPONENT_IMAGE=sha256:' + 'b' * 64, selection)
        self.assertIn('COMPONENT_BUILD_MODE=source', selection)
        calls = [call['args'] for call in self.calls]
        prepare = next(i for i, args in enumerate(calls) if '--check-components' in args)
        migrate = next(i for i, args in enumerate(calls) if '/makefile-run-migrations.sh' in args)
        restart = next(i for i, args in enumerate(calls) if 'restart' in args and 'caution-api' in args)
        health = next(i for i, args in enumerate(calls) if 'is-active' in args)
        self.assertLess(prepare, migrate)
        self.assertLess(migrate, restart)
        self.assertLess(restart, health)
        self.assertEqual([args[-1] for args in self.args('curl')],
                         ['http://127.0.0.1:8000/api/legal/active-documents', 'http://127.0.0.1:8000/'])
        self.assertIn('All services running', result.stdout)
        self.assertFalse((self.home / 'dotenv-executed').exists())

    def test_hosted_up_fails_closed_when_each_required_unit_is_inactive(self):
        self.configure()
        for unit in UNITS:
            with self.subTest(unit=unit):
                result = self.make('up', CAUTION_HOSTED_WAIT_SECONDS='0.5', INACTIVE_UNIT=unit)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Timed out waiting for', result.stderr)
                self.assertNotIn('All services running', result.stdout)
                active = [args for args in self.args('systemctl') if 'is-active' in args]
                self.assertIn(['--user', 'is-active', '--quiet', unit], active)
                self.assertTrue(all(len(args) == 4 for args in active))
                self.assertEqual(self.args('curl'), [])

    def test_hosted_up_requires_backend_and_frontend_not_just_http_success(self):
        self.configure()
        for failure in ('backend-down', 'frontend-down', 'redirect', 'backend-html',
                        'backend-object', 'backend-malformed', 'frontend-empty', 'frontend-json'):
            with self.subTest(failure=failure):
                result = self.make('up', CAUTION_HOSTED_WAIT_SECONDS='0.5', HTTP_FAILURE=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Timed out waiting for', result.stderr)
                self.assertNotIn('All services running', result.stdout)

    def test_template_drift_is_rejected_before_installing_any_unit(self):
        self.configure()
        gateway = self.repo / 'systemd/caution-gateway.service'
        gateway.write_text(gateway.read_text().replace('-p 8000:8080 ', '-p 9000:8080 '))
        result = self.make('setup')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Unexpected unit template', result.stderr)
        self.assertEqual(list(self.units.glob('*.service')), [])
        self.assertFalse(any('enable' in args or 'daemon-reload' in args for args in self.args('systemctl')))

    def test_hosted_setup_respects_xdg_location_including_empty_default(self):
        self.configure()
        for xdg in ('', str(self.home / 'custom config')):
            with self.subTest(xdg=xdg):
                result = self.make('setup', XDG_CONFIG_HOME=xdg)
                self.assertEqual(result.returncode, 0, result.stderr)
                target = Path(xdg) if xdg else self.home / '.config'
                self.assertEqual(len(list((target / 'systemd/user').glob('*.service'))), len(UNITS))

    def test_hosted_setup_replaces_unit_symlink_without_rewriting_source(self):
        self.configure()
        self.units.mkdir(parents=True)
        source = self.repo / 'systemd/caution-gateway.service'
        original = source.read_bytes()
        (self.units / source.name).symlink_to(source)
        result = self.make('setup')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.units / source.name).is_symlink())
        self.assertEqual(source.read_bytes(), original)

    def test_hosted_setup_propagates_reload_and_enable_errors(self):
        self.configure()
        for action in ('daemon-reload', 'enable'):
            with self.subTest(action=action):
                result = self.make('setup', FAIL_TOOL='systemctl', FAIL_ARG=action)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('Setup complete', result.stdout)

    def test_hosted_up_never_reports_success_after_build_prepare_migration_or_restart_failure(self):
        self.configure()
        for tool, argument in (('docker', 'build'), ('docker', '--check-components'),
                               ('docker', '/makefile-run-migrations.sh'), ('systemctl', 'caution-api')):
            with self.subTest(tool=tool, argument=argument):
                result = self.make('up', FAIL_TOOL=tool, FAIL_ARG=argument, CAUTION_HOSTED_WAIT_SECONDS='2')
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('All services running', result.stdout)
                self.assertEqual(self.args('curl'), [])
                self.assertFalse(any('is-active' in args for args in self.args('systemctl')))

    def test_normal_up_does_not_apply_hosted_checks(self):
        self.configure()
        result = self.make('up', CAUTION_HOSTED='0', POSTGRES_DOWN='', INACTIVE_UNIT=UNITS[-1])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any('is-active' in args for args in self.args('systemctl')))
        self.assertEqual(self.args('curl'), [])

    def test_hosted_capability_is_exactly_version_one(self):
        result = self.make('hosted-bootstrap-version')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '1\n')
        self.assertEqual(self.calls, [call for call in self.calls if call['tool'] == 'git'])


if __name__ == '__main__':
    unittest.main()
