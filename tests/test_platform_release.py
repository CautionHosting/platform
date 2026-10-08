#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
"""Behavioral release tests; command fakes are not Docker/AWS acceptance."""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1]

FAKE = r'''#!/usr/bin/env python3
import json, os, pathlib, subprocess, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ['COMMAND_LOG'], 'a') as out:
    out.write(json.dumps([name, *args]) + '\n')
services = ('api', 'gateway', 'email', 'metering')
def runtime_path(service):
    return pathlib.Path(os.environ['COMMAND_LOG']).with_name('runtime-' + service + '.json')
if name == 'systemctl':
    if 'is-active' in args:
        active = pathlib.Path.home().joinpath('.config/caution/releases/current').exists()
        sys.exit(0 if active and not os.environ.get('APP_UNITS_INACTIVE') else 3)
    if 'restart' in args:
        apps = [s for s in services if 'caution-' + s in args or 'caution-' + s + '.service' in args]
        if apps and os.environ.get('FAIL_RESTART'):
            sys.exit(24)
        launcher = pathlib.Path.home() / '.config/caution/releases/current/launch-service.py'
        for service in apps:
            result = subprocess.run([sys.executable, str(launcher), service])
            if result.returncode:
                sys.exit(result.returncode)
    sys.exit(0)
if name == 'docker':
    if args[0] in ('build', 'buildx'):
        sys.exit(23 if os.environ.get('FAIL_BUILD') else 0)
    if args[:2] == ['context', 'inspect']:
        print(os.environ['DOCKER_HOST'])
    elif args[0] == 'inspect' and args[-1] in services:
        state_file = runtime_path(args[-1])
        if not state_file.is_file():
            sys.exit(1)
        state = json.loads(state_file.read_text())
        fmt = args[args.index('--format') + 1]
        if 'Config.Env' in fmt:
            values = state['environment']
            print(json.dumps([key + '=' + value for key, value in values.items()]))
        elif '.Image' in fmt:
            print(state['image'])
        elif 'Running' in fmt:
            print('true')
    elif args[0] == 'run' and '--name' in args:
        service = args[args.index('--name') + 1]
        values = {}
        for i, arg in enumerate(args):
            if arg == '--env-file':
                for line in pathlib.Path(args[i + 1]).read_text().splitlines():
                    if line and not line.startswith('#'):
                        key, value = line.split('=', 1)
                        values[key] = value
            elif arg == '-e':
                key, value = args[i + 1].split('=', 1)
                values[key] = value
        runtime_path(service).write_text(json.dumps({'image': args[-1], 'environment': values}))
    elif args[0] == 'rm' and args[-1] in services:
        runtime_path(args[-1]).unlink(missing_ok=True)
    elif 'inspect' in args:
        fmt = args[args.index('--format') + 1] if '--format' in args else ''
        if 'Config.Env' in fmt:
            sha = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
            print(json.dumps(['PLATFORM_GIT_SHA=' + sha]))
        elif '.Id' in fmt:
            service = next((s for s in services if s in args[-1]), 'api')
            print('sha256:' + str(services.index(service) + 1) * 64)
    elif '--print-inputs' in args:
        print(json.dumps({s: {'commit': str(i) * 40, 'repo': 'https://codeberg.org/caution/' + s}
                          for i, s in enumerate(('enclaveos', 'bootproof', 'steve', 'locksmith'), 1)}))
    elif '--output-lock' in args:
        if os.environ.get('FAIL_PUBLISH'):
            sys.exit(25)
        pathlib.Path(args[args.index('--output-lock') + 1]).write_text('{"synthetic_unit_fixture":true}')
    elif '--entrypoint' in args and args[args.index('--entrypoint') + 1] == 'git' and 'clone' in args:
        pathlib.Path(args[-1]).mkdir(parents=True, exist_ok=True)
    sys.exit(0)
raise SystemExit('Unexpected test command: ' + name)
'''


class PlatformReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='caution-release-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        for name in ('Makefile', 'scripts', 'systemd', 'containerfiles', 'utils'):
            source = SOURCE / name
            if source.is_dir():
                shutil.copytree(source, self.repo / name)
            else:
                shutil.copy2(source, self.repo / name)
        manifest = self.repo / 'src/cli/Cargo.toml'
        manifest.parent.mkdir(parents=True)
        manifest.write_text('[package]\nname = "cli"\nversion = "0.0.0"\n')
        self.home = self.root / 'home'
        self.config = self.home / '.config/caution'
        self.config.mkdir(parents=True)
        self.config.joinpath('.env').write_text('EIF_S3_BUCKET=release-test-bucket\n')
        for name in ('prices.json', 'config.json'):
            self.config.joinpath(name).write_text('{}\n')
        self.log = self.root / 'commands.jsonl'
        self.log.touch()
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        for name in ('docker', 'systemctl'):
            executable = self.bin / name
            executable.write_text(FAKE)
            executable.chmod(0o755)
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.bind(str(self.root / 'docker.sock'))
        self.addCleanup(self.sock.close)
        self.env = {
            'PATH': str(self.bin) + ':' + os.environ['PATH'],
            'DOCKER_HOST': 'unix://' + str(self.root / 'docker.sock'),
            'HOME': str(self.home),
            'PWD': str(self.repo),
            'COMMAND_LOG': str(self.log),
            'GIT_CONFIG_NOSYSTEM': '1',
            'GIT_CONFIG_GLOBAL': '/dev/null',
        }
        for args in (['init', '-q'], ['add', '.'],
                     ['-c', 'user.name=Release Test', '-c', 'user.email=test@example.invalid',
                      '-c', 'commit.gpgsign=false', 'commit', '-qm', 'release fixture']):
            subprocess.run(['git', *args], cwd=self.repo, env=self.env, check=True,
                           capture_output=True)

    def commands(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def make(self, *args):
        return subprocess.run(['make', '--no-print-directory', *args], cwd=self.repo,
                              env=self.env, text=True, capture_output=True, timeout=30)

    def test_preparation_failure_does_not_migrate_or_restart(self):
        self.env['FAIL_BUILD'] = '1'
        result = self.make('up')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        commands = self.commands()
        self.assertTrue(any(c[:2] == ['docker', 'build'] for c in commands), commands)
        self.assertFalse(any(c[0] == 'systemctl' and 'restart' in c for c in commands), commands)
        self.assertFalse(any(c[:2] == ['docker', 'run'] and
                             any('migration' in arg for arg in c) for c in commands), commands)
        self.assertFalse((self.config / 'releases/current').exists())
        self.assertEqual(self.config.joinpath('.env').read_text(),
                         'EIF_S3_BUCKET=release-test-bucket\n')

    def current(self):
        current = self.config / 'releases/current'
        self.assertTrue(current.is_symlink(), 'make up must activate a persisted release')
        return current.resolve(strict=True)

    def test_cold_release_pins_images_and_components_before_migration(self):
        result = self.make('up')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        release = self.current()
        record = json.loads(release.joinpath('release.json').read_text())
        self.assertEqual(set(record['images']), {'api', 'gateway', 'email', 'metering'})
        self.assertTrue(all(value.startswith('sha256:') for value in record['images'].values()))
        generated = release.joinpath('components.env').read_text()
        self.assertIn('COMPONENT_BUILD_MODE=prebuilt\n', generated)
        self.assertIn('COMPONENTS_S3_BUCKET=release-test-bucket\n', generated)
        import hashlib
        digest = hashlib.sha256(release.joinpath('components.lock.json').read_bytes()).hexdigest()
        self.assertIn('COMPONENT_SET_SHA256=' + digest + '\n', generated)
        self.assertEqual(record['component_set_sha256'], digest)
        commands = self.commands()
        publish = next(i for i, c in enumerate(commands) if '--output-lock' in c)
        self.assertIn('--framework-source', commands[publish], 'use the supported publisher CLI')
        migrate = next(i for i, c in enumerate(commands) if any('makefile-run-migrations' in a for a in c))
        self.assertLess(publish, migrate)
        for c in commands:
            if c[:2] == ['docker', 'build']:
                self.assertIn(':release-', c[c.index('-t') + 1], c)
        for service in record['images']:
            dropin = self.home / '.config/systemd/user' / ('caution-' + service + '.service.d/90-caution-release.conf')
            self.assertIn('launch-service.py ' + service, dropin.read_text())
            self.assert_release_launch(service, self.launch_argv(service))

    def test_warm_release_passes_retained_accepted_lock_to_publisher(self):
        first = self.make('up')
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        previous = self.current()
        self.log.write_text('')
        second = self.make('up')
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertNotEqual(previous, self.current())
        publish = next(c for c in self.commands() if '--output-lock' in c)
        self.assertIn('--accepted-lock', publish)
        self.assertEqual((self.config / 'releases/previous').resolve(), previous)
        self.assertTrue(previous.joinpath('components.lock.json').is_file())

    def test_publication_failure_leaves_active_pair_and_units_untouched(self):
        first = self.make('up')
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        previous = self.current()
        self.log.write_text('')
        self.env['FAIL_PUBLISH'] = '1'
        result = self.make('up')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.current(), previous)
        self.assertFalse(any(c[0] == 'systemctl' and 'restart' in c for c in self.commands()))
        self.assertFalse(any(any('makefile-run-migrations' in a for a in c) for c in self.commands()))

    def test_explicit_source_release_clears_legacy_selection(self):
        self.config.joinpath('.env').write_text('COMPONENT_SET_SHA256=' + 'a' * 64 + '\nCOMPONENTS_S3_BUCKET=legacy-bucket\n')
        result = self.make('up', 'COMPONENT_BUILD_MODE=source')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        release = self.current()
        generated = release.joinpath('components.env').read_text()
        self.assertIn('COMPONENT_BUILD_MODE=source\n', generated)
        self.assertIn('COMPONENT_SET_SHA256=\n', generated)
        self.assertIn('COMPONENTS_S3_BUCKET=\n', generated)
        self.assertFalse(release.joinpath('components.lock.json').exists())
        self.assertFalse(any('--output-lock' in c for c in self.commands()))
        command = self.launch_argv('api')
        self.assert_release_launch('api', command)
        result = subprocess.run(['docker', 'inspect', '--format', '{{json .Config.Env}}', 'api'],
                                cwd=self.repo, env=self.env, text=True, capture_output=True, check=True)
        actual = dict(entry.split('=', 1) for entry in json.loads(result.stdout))
        self.assertEqual(actual['COMPONENT_BUILD_MODE'], 'source')
        self.assertEqual(actual['COMPONENT_SET_SHA256'], '')
        self.assertEqual(actual['COMPONENTS_S3_BUCKET'], '')

    def test_release_metadata_never_persists_publisher_credentials(self):
        self.config.joinpath('.env').write_text('EIF_S3_BUCKET=release-test-bucket\nAWS_SECRET_ACCESS_KEY=unit-fixture-not-a-real-secret\n')
        result = self.make('up')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.current()
        for path in self.config.joinpath('releases').rglob('*'):
            if path.is_file():
                self.assertNotIn(b'unit-fixture-not-a-real-secret', path.read_bytes(), str(path))

    def test_readiness_checks_runtime_selection_not_just_image_and_http(self):
        import importlib.util
        from unittest.mock import patch
        result = self.make('up')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = json.loads(self.current().joinpath('release.json').read_text())
        launch = self.launch_argv('api')
        subprocess.run([*launch[:-1], '-e', 'COMPONENT_BUILD_MODE=source', launch[-1]],
                       cwd=self.repo, env=self.env, check=True, capture_output=True)
        with patch.dict(os.environ, self.env, clear=True):
            spec = importlib.util.spec_from_file_location('platform_release_test',
                                                         self.repo / 'scripts/platform-release.py')
            assert spec is not None and spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            with patch.object(module.time, 'monotonic', side_effect=[0, 0, 121]), \
                    patch.object(module.time, 'sleep'):
                with self.assertRaises(RuntimeError):
                    module.ready(record['images'])

    def test_release_lock_rejects_concurrent_invocation(self):
        import fcntl
        state = self.config / 'releases'
        state.mkdir()
        with state.joinpath('release.lock').open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.make('up')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('already running', result.stderr)
        self.assertFalse(self.commands())

    def launch(self, service, *args):
        return subprocess.run(['python3', str(self.current() / 'launch-service.py'),
                               service, *args], cwd=self.repo, env=self.env,
                              text=True, capture_output=True, timeout=30)

    def launch_argv(self, service):
        launches = [c for c in self.commands() if c[:2] == ['docker', 'run']
                    and '--name' in c and c[c.index('--name') + 1] == service]
        self.assertEqual(len(launches), 1, launches)
        return launches[0]

    def option_values(self, command, option):
        return [command[i + 1] for i, value in enumerate(command) if value == option]

    def assert_release_launch(self, service, command, detach=False):
        release = self.current()
        record = json.loads(release.joinpath('release.json').read_text())
        self.assertEqual(command[-1], record['images'][service])
        self.assertEqual(self.option_values(command, '--env-file'),
                         [str(self.config / '.env'), str(release / 'components.env')])
        self.assertEqual(self.option_values(command, '--network'), ['caution-network'])
        self.assertEqual('--detach' in command, detach)
        self.assertNotIn('/var/run/docker.sock:/var/run/docker.sock', command)
        self.assertFalse(any(':/app/terraform' in arg for arg in command), command)

    def test_installed_launchers_preserve_shared_repository_volume(self):
        result = self.make('up')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.log.write_text('')
        for service in ('api', 'gateway'):
            with self.subTest(service=service):
                result = self.launch(service)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                command = self.launch_argv(service)
                self.assert_release_launch(service, command)
                data_mounts = [v for v in self.option_values(command, '-v')
                               if v.endswith(':/var/cache/caution')]
                self.assertEqual(data_mounts, ['caution-data-dir:/var/cache/caution'])
                self.assertIn('CAUTION_DATA_DIR=/var/cache/caution',
                              self.option_values(command, '-e'))
                self.assertEqual(self.option_values(command, '-p'),
                                 ['8000:8080', '2222:2222'] if service == 'gateway' else [])
                if service == 'api':
                    self.assertIn('TF_PLUGIN_CACHE_DIR=/var/cache/caution/terraform', command)
                    self.assertIn(f'{self.config}/prices.json:/app/prices.json:ro', command)
                    self.assertIn(f'{self.config}/config.json:/app/config.json:ro', command)

    def test_direct_make_launches_preserve_shared_bind_and_custom_prices(self):
        prices = self.repo / 'custom prices.json'
        prices.write_text('{}\n')
        for mode in ('prebuilt', 'source'):
            with self.subTest(mode=mode):
                self.env.pop('APP_UNITS_INACTIVE', None)
                result = self.make('up', 'COMPONENT_BUILD_MODE=' + mode)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.env['APP_UNITS_INACTIVE'] = '1'
                self.log.write_text('')
                data = self.repo / ('shared cache ' + mode)
                result = self.make('run-api', 'run-gateway', 'run-metering',
                                   'CAUTION_DATA_DIR=' + data.name,
                                   'PRICES_FILE=' + prices.name,
                                   'API_IMAGE=must-not-use-mutable-tag')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for service in ('api', 'gateway', 'metering'):
                    with self.subTest(service=service):
                        command = self.launch_argv(service)
                        self.assert_release_launch(service, command, detach=True)
                        mounts = self.option_values(command, '-v')
                        if service in ('api', 'gateway'):
                            self.assertIn(f'{data}:/var/cache/caution', mounts)
                            self.assertNotIn('caution-data-dir:/var/cache/caution', mounts)
                        if service in ('api', 'metering'):
                            self.assertIn(f'{prices}:/app/prices.json:ro', mounts)
                            self.assertIn(f'{self.config}/config.json:/app/config.json:ro', mounts)
                for directory in ('git-repos', 'build', 'terraform'):
                    self.assertTrue((data / directory).is_dir(), data / directory)

        blocked = self.repo / 'blocked cache'
        blocked.write_text('not a directory')
        for service in ('api', 'gateway'):
            with self.subTest(blocked_data_dir=service):
                self.log.write_text('')
                result = self.launch(service, '--data-dir', blocked.name)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(self.commands(), 'data creation must succeed before container removal')

    def test_email_launches_preserve_loopback_port(self):
        result = self.make('up')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.env['APP_UNITS_INACTIVE'] = '1'
        for direct in (False, True):
            with self.subTest(direct_make=direct):
                self.log.write_text('')
                result = self.make('run-email') if direct else self.launch('email')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                command = self.launch_argv('email')
                self.assert_release_launch('email', command, detach=direct)
                self.assertIn('EMAIL_BIND_ADDR=0.0.0.0:8082',
                              self.option_values(command, '-e'))
                self.assertEqual(self.option_values(command, '-p'), ['127.0.0.1:8082:8082'])
                self.assertEqual(self.option_values(command, '-v'), [])

    def test_direct_make_network_override_keeps_installed_default(self):
        result = self.make('up')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.env['APP_UNITS_INACTIVE'] = '1'
        for network in ('caution-network', 'custom'):
            self.log.write_text('')
            result = self.make('run-api', 'run-gateway', 'run-email', 'run-metering',
                               'NETWORK=' + network)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for service in ('api', 'gateway', 'email', 'metering'):
                with self.subTest(network=network, service=service):
                    self.assertEqual(self.option_values(self.launch_argv(service), '--network'),
                                     [network])
        self.log.write_text('')
        for service in ('api', 'gateway', 'email', 'metering'):
            result = self.launch(service)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assert_release_launch(service, self.launch_argv(service))

    def test_direct_api_dns_keeps_installed_resolver_default(self):
        result = self.make('up')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.env['APP_UNITS_INACTIVE'] = '1'
        for direct in (False, True):
            with self.subTest(direct_make=direct):
                self.log.write_text('')
                result = self.make('run-api') if direct else self.launch('api')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.option_values(self.launch_argv('api'), '--dns'),
                                 ['8.8.8.8', '8.8.4.4'] if direct else [])

    def test_direct_metering_interval_overrides_only_direct_env_file(self):
        result = self.make('up')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.env['APP_UNITS_INACTIVE'] = '1'
        for interval in (None, '777'):
            self.config.joinpath('.env').write_text(
                '' if interval is None else 'METERING_INTERVAL_SECS=' + interval + '\n')
            for direct in (False, True):
                with self.subTest(env_interval=interval, direct_make=direct):
                    self.log.write_text('')
                    result = self.make('run-metering') if direct else self.launch('metering')
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    command = self.launch_argv('metering')
                    overrides = [v for v in self.option_values(command, '-e')
                                 if v.startswith('METERING_INTERVAL_SECS=')]
                    self.assertEqual(overrides, ['METERING_INTERVAL_SECS=60'] if direct else [])
                    if direct:
                        self.assertGreater(command.index('METERING_INTERVAL_SECS=60'),
                                           max(i for i, arg in enumerate(command) if arg == '--env-file'))
                    runtime = json.loads(self.root.joinpath('runtime-metering.json').read_text())
                    self.assertEqual(runtime['environment'].get('METERING_INTERVAL_SECS'),
                                     '60' if direct else interval)

    def test_invalid_launch_options_fail_before_container_removal(self):
        result = self.make('up')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        cases = [('api', '--network', value) for value in ('', 'bad network', '-invalid')]
        cases += [('api', '--dns', value) for value in ('', 'not-an-ip', '999.8.8.8')]
        cases += [('metering', '--metering-interval-secs', value)
                  for value in ('', 'abc', '-1', '0', '1.5', '18446744073709551616')]
        cases += [('api', '--metering-interval-secs', '60')]
        for service, option, value in cases:
            with self.subTest(service=service, option=option, value=value):
                self.log.write_text('')
                result = self.launch(service, option + '=' + value)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(self.commands(), 'invalid options must not remove a container')

    def test_launch_rejects_modified_pair_before_removing_container(self):
        result = self.make('up')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        release = self.current()
        environment = release / 'components.env'
        environment.write_text(environment.read_text() + 'COMPONENT_SET_SHA256=' + 'f' * 64 + '\n')
        self.log.write_text('')
        result = subprocess.run(['python3', 'scripts/launch-service.py', 'api', '--detach'],
                                cwd=self.repo, env=self.env, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.commands(), 'invalid release must not remove an existing container')

    def test_launch_rejects_modified_lock_before_removing_container(self):
        result = self.make('up')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.current().joinpath('components.lock.json').write_text('{}')
        self.log.write_text('')
        result = subprocess.run(['python3', 'scripts/launch-service.py', 'api', '--detach'],
                                cwd=self.repo, env=self.env, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.commands())

    def test_invalid_mode_fails_without_docker_or_service_mutations(self):
        result = self.make('up', 'COMPONENT_BUILD_MODE=typo')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.commands(), self.commands())


if __name__ == '__main__':
    unittest.main()
