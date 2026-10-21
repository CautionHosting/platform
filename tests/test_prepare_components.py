# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
"""Component selection regressions; all Git/Docker/provider outputs are fixtures."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
SPEC = importlib.util.spec_from_file_location('prepare_components', ROOT / 'scripts/prepare-components.py')
assert SPEC is not None and SPEC.loader is not None
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)
HEAD, IMAGE = 'a' * 40, 'sha256:' + 'b' * 64
PINS = dict(zip(('enclaveos', 'bootproof', 'steve', 'locksmith'), (c * 40 for c in '1234')))
ACCEPTED, PUBLISHED = b'{"fixture":"independently accepted"}\n', b'{"fixture":"published"}\n'
OPERATOR_VALUES = {'AWS_ACCESS_KEY_ID': 'reader', 'AWS_SECRET_ACCESS_KEY': 'reader-secret',
                   'EIF_S3_BUCKET': 'fixture-bucket', 'STEVE_COMMIT': '9' * 40}
OPERATOR = ''.join(f'{key}={value}\n' for key, value in OPERATOR_VALUES.items())
OLD = 'COMPONENT_SET_SHA256=old-digest\nCOMPONENTS_S3_BUCKET=old-bucket\n'


def options(argv, flag):
    return [argv[i + 1] for i, arg in enumerate(argv) if arg == flag]


class PrepareComponentsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config = Path(self.directory.name)
        (self.config / '.env').write_text(OPERATOR)
        (self.config / '.env').chmod(0o600)
        self.selection = self.config / 'components.env'
        self.selection.write_text(OLD)
        self.accepted = self.config / 'components/accepted'
        self.accepted.mkdir(parents=True)
        self.lock = self.accepted / (hashlib.sha256(ACCEPTED).hexdigest() + '.json')
        self.lock.write_bytes(ACCEPTED)
        sock = socket.socket(socket.AF_UNIX)
        self.addCleanup(sock.close)
        sock.bind(str(self.config / 'docker.sock'))
        self.calls, self.failure, self.dirty = [], '', ''
        self.image_head, self.image_id = HEAD, IMAGE
        self.inputs = {name: {'commit': pin, 'repo': f'https://fixture.invalid/{name}'}
                       for name, pin in PINS.items()}
        self.addCleanup(os.umask, os.umask(0o022))
        for context in (patch.object(PREP, 'CONFIG', self.config),
                        patch.object(PREP, 'run', side_effect=self.fake_run),
                        patch.object(subprocess, 'run', side_effect=AssertionError('Unmocked subprocess')),
                        patch.dict(os.environ, {'DOCKER_HOST': f'unix://{self.config}/docker.sock',
                                   'AWS_ACCESS_KEY_ID': 'publisher',
                                   'AWS_SECRET_ACCESS_KEY': 'publisher-secret', 'STEVE_COMMIT': PINS['steve']}, clear=True),
                        patch.object(sys, 'argv', ['prepare-components', '--network', 'fixture-network'])):
            context.start()
            self.addCleanup(context.stop)

    def fake_run(self, *args, **kwargs):
        argv = tuple(map(str, args))
        self.calls.append(argv)
        if argv == ('git', 'rev-parse', 'HEAD'):
            return HEAD
        if argv == ('git', 'status', '--porcelain=v1', '--untracked-files=no'):
            return self.dirty
        if argv[:3] == ('docker', 'image', 'inspect'):
            return self.image_id if argv[4] == '{{.Id}}' else json.dumps([
                f'PLATFORM_GIT_SHA={self.image_head}'])
        if argv[:2] == ('git', 'clone') or argv[:3] == ('git', '-c', 'core.hooksPath=/dev/null'):
            return ''
        self.assertEqual(argv[:2], ('docker', 'run'))
        self.assertIn(IMAGE, argv)
        if '--print-inputs' in argv:
            path = Path(options(argv, '--env-file')[0])
            self.publisher = PREP.read_env(path)
            self.publisher_mode = stat.S_IMODE(path.stat().st_mode)
            self.assertEqual(options(argv, '--network'), ['none'])
            return json.dumps(self.inputs)
        if '--output-lock' in argv:
            self.trusted = [(Path(p).name, Path(p).read_bytes()) for p in options(argv, '--accepted-lock')]
            if self.failure == 'publish':
                raise subprocess.CalledProcessError(1, argv)
            Path(options(argv, '--output-lock')[0]).write_bytes(PUBLISHED)
            return ''
        if '--check-components' in argv:
            self.assertEqual(self.selection.read_text(), OLD)
            self.reader = argv
            self.reader_env = {}
            for path in options(argv, '--env-file'):
                self.reader_env.update(PREP.read_env(Path(path)))
            if self.failure == 'read':
                raise subprocess.CalledProcessError(1, argv)
            return ''
        self.assertEqual(options(argv, '--entrypoint'), ['git'])
        return ''

    def test_prebuilt_selection_uses_accepted_locks_pins_and_immutable_image(self):
        PREP.main()
        digest = hashlib.sha256(PUBLISHED).hexdigest()
        expected = {'API_COMPONENT_IMAGE': IMAGE, 'PLATFORM_GIT_SHA': HEAD,
                    'COMPONENT_BUILD_MODE': 'prebuilt', 'COMPONENT_SET_SHA256': digest,
                    'COMPONENTS_S3_BUCKET': 'fixture-bucket',
                    **{name.upper() + '_COMMIT': pin for name, pin in PINS.items()}}
        self.assertEqual(PREP.read_env(self.selection), expected)
        self.assertEqual(self.trusted, [(self.lock.name, ACCEPTED)])
        self.assertEqual((self.accepted / f'{digest}.json').read_bytes(), PUBLISHED)
        publication = next(argv for argv in self.calls if '--output-lock' in argv)
        for flag, value in {'bucket': 'fixture-bucket', 'framework-commit': HEAD,
                            **{('enclave' if n == 'enclaveos' else n) + '-commit': p
                               for n, p in PINS.items()}}.items():
            self.assertEqual(options(publication, '--' + flag), [value])
        self.assertEqual(self.publisher['AWS_ACCESS_KEY_ID'], 'publisher')
        self.assertEqual(self.publisher['AWS_SECRET_ACCESS_KEY'], 'publisher-secret')
        self.assertEqual(self.publisher['STEVE_COMMIT'], PINS['steve'])
        self.assertEqual(self.reader, ('docker', 'run', '--rm', '--network', 'fixture-network',
                         '--env-file', options(self.reader, '--env-file')[0], '--env-file',
                         options(self.reader, '--env-file')[1], IMAGE, '--check-components'))
        self.assertEqual(self.reader_env, {**OPERATOR_VALUES, **expected})
        self.assertEqual((self.config / '.env').read_text(), OPERATOR)
        self.assertEqual(stat.S_IMODE(self.selection.stat().st_mode), 0o600)
        self.assertEqual(self.publisher_mode, 0o600)

    def test_source_mode_clears_stale_digest_and_bucket_without_publication(self):
        os.environ['COMPONENT_BUILD_MODE'] = 'source'
        PREP.main()
        selected = PREP.read_env(self.selection)
        self.assertEqual(selected['COMPONENT_BUILD_MODE'], 'source')
        self.assertEqual((selected['COMPONENT_SET_SHA256'], selected['COMPONENTS_S3_BUCKET']), ('', ''))
        self.assertFalse(any('--output-lock' in argv or 'clone' in argv for argv in self.calls))
        self.assertEqual(list(self.accepted.iterdir()), [self.lock])

    def test_publisher_receives_only_provider_and_component_settings(self):
        secrets = {'DATABASE_URL': 'private-db', 'INTERNAL_SERVICE_SECRET': 'private-auth',
                   'PADDLE_API_KEY': 'private-billing', 'AWS_UNRELATED_SECRET': 'private-extra'}
        provider = {'AWS_SESSION_TOKEN': 'temporary-session', 'AWS_PROFILE': 'publisher',
                    'AWS_WEB_IDENTITY_TOKEN_FILE': '/token', 'AWS_ROLE_ARN': 'fixture-role',
                    'AWS_CONTAINER_CREDENTIALS_FULL_URI': 'http://127.0.0.1/credentials',
                    'AWS_EC2_METADATA_DISABLED': 'false', 'AWS_REGION': 'us-west-2',
                    'AWS_ENDPOINT_URL_S3': 'http://fixture.invalid'}
        PREP.write_env(self.config / '.env', {**OPERATOR_VALUES, **provider, **secrets})
        os.environ.update(AWS_SESSION_TOKEN='exported-session', PADDLE_API_KEY='exported-secret')
        PREP.main()
        self.assertEqual(self.publisher, {**OPERATOR_VALUES, **provider,
                         'AWS_ACCESS_KEY_ID': 'publisher', 'AWS_SECRET_ACCESS_KEY': 'publisher-secret',
                         'AWS_SESSION_TOKEN': 'exported-session', 'STEVE_COMMIT': PINS['steve']})
        self.assertEqual(self.reader_env['PADDLE_API_KEY'], 'private-billing')

    def test_e2e_selection_does_not_replace_service_selection(self):
        selected = self.config / 'components-e2e.env'
        with patch.object(sys, 'argv', ['prepare-components', '--selection-file', str(selected),
                                       '--network', 'fixture-network']):
            PREP.main()
        self.assertEqual(PREP.read_env(selected)['API_COMPONENT_IMAGE'], IMAGE)
        self.assertEqual(self.selection.read_text(), OLD)

    def test_failed_publication_or_reader_preserves_previous_selection(self):
        for failure, flag in (('publish', '--output-lock'), ('read', '--check-components')):
            with self.subTest(failure=failure):
                self.failure = failure
                with self.assertRaises(subprocess.CalledProcessError) as error:
                    PREP.main()
                self.assertIn(flag, error.exception.cmd)
                self.assertEqual(self.selection.read_text(), OLD)
                self.assertEqual((self.config / '.env').read_text(), OPERATOR)

    def test_stale_image_dirty_repo_or_mutable_image_fail_before_publication(self):
        for attribute, bad, message in (('image_head', 'c' * 40, 'Build the API image'),
                                       ('dirty', ' M tracked.rs', 'Commit tracked changes'),
                                       ('image_id', 'caution-api', 'immutable API image ID')):
            with self.subTest(attribute=attribute), patch.object(self, attribute, bad):
                self.calls.clear()
                with self.assertRaisesRegex(ValueError, message):
                    PREP.main()
                self.assertFalse(any(argv[:2] == ('docker', 'run') for argv in self.calls))
                self.assertEqual(self.selection.read_text(), OLD)

    def test_corrupt_accepted_lock_fails_without_publication(self):
        self.lock.write_bytes(b'fixture corruption')
        with self.assertRaisesRegex(ValueError, 'Accepted local lock was modified'):
            PREP.main()
        self.assertFalse(any('--output-lock' in argv for argv in self.calls))
        self.assertEqual(self.selection.read_text(), OLD)

    def test_missing_extra_or_noncanonical_pins_fail_closed(self):
        valid = self.inputs
        invalid = [{k: v for k, v in valid.items() if k != 'steve'}, {**valid, 'extra': valid['steve']}]
        invalid += [{**valid, 'steve': {**valid['steve'], 'commit': pin}}
                    for pin in ('main', 'A' * 40, '1' * 40 + '\n')]
        for inputs in invalid:
            with self.subTest(inputs=inputs):
                self.inputs = inputs
                with self.assertRaisesRegex(ValueError, 'incomplete or unpinned'):
                    PREP.main()
                self.assertEqual(self.selection.read_text(), OLD)
        self.assertFalse(any('--output-lock' in argv or '--check-components' in argv for argv in self.calls))

    def test_make_order_and_api_only_unit_selection_literal_contract(self):
        make = (ROOT / 'Makefile').read_text()
        up = make.split('\nup-components:\n', 1)[1].split('\n\n', 1)[0]
        self.assertLess(up.index('$(MAKE) prepare-components'), up.index('$(MAKE) migrate'))
        self.assertLess(up.index('$(MAKE) migrate'), up.index('systemctl restart'))
        direct = make.split('\nrun-api:', 1)[1].split('\n\n', 1)[0]
        before, after = direct.split('--check-components', 1)
        self.assertEqual(re.findall(r'-e AWS_REGION=\S+', before), ['-e AWS_REGION=us-west-2'])
        self.assertEqual(re.findall(r'-e AWS_REGION=\S+', after), ['-e AWS_REGION=us-west-2'])
        units = {p.name: p.read_text() for p in (ROOT / 'systemd').glob('*.service')}
        self.assertEqual([name for name, text in units.items() if any(
            token in text for token in ('components.env', 'API_COMPONENT_IMAGE', 'COMPONENT_SET_SHA256'))],
            ['caution-api.service'])
        api = units['caution-api.service']
        self.assertIn('EnvironmentFile=-%h/.config/caution/components.env', api)
        self.assertLess(api.index('--check-components'), api.index('docker rm -f api'))
        for line in api.splitlines():
            if 'platform_env.py run' in line:
                self.assertIn('${API_COMPONENT_IMAGE}', line)
                for key in ('PLATFORM_GIT_SHA', 'COMPONENT_BUILD_MODE', 'COMPONENT_SET_SHA256',
                            'COMPONENTS_S3_BUCKET', *(n.upper() + '_COMMIT' for n in PINS)):
                    self.assertIn('-e ' + key, line)


class LaunchSelectionTests(unittest.TestCase):
    def test_isolated_quorum_mock_explicitly_selects_source_mode(self):
        script = (ROOT / 'tests/e2e/test_quorum_mock.sh').read_text()
        api_launches = re.findall(
            r'^"\$\{COMMON\[@\]\}"(?:[^\n]*\\\n)*[^\n]*"\$CARGO_TARGET_DIR/debug/api"[^\n]*$',
            script, re.M)
        self.assertEqual(len(api_launches), 2)
        for api_launch in api_launches:
            self.assertIn('COMPONENT_BUILD_MODE=source', api_launch)
            self.assertIn('AWS_ENDPOINT_URL=http://127.0.0.1:9', api_launch)

    def test_build_and_launch_targets_prepare_the_just_built_candidate(self):
        make = (ROOT / 'Makefile').read_text()
        checked = set()
        for match in re.finditer(r'^([a-zA-Z0-9_-]+):[^\n]*\n((?:\t.*\n)+)', make, re.M):
            target, recipe = match.groups()
            if 'build-api-e2e' not in recipe or 'run-api-test' not in recipe:
                continue
            with self.subTest(target=target):
                preparation = [line for line in recipe.splitlines() if '$(MAKE) prepare-components ' in line]
                self.assertEqual(len(preparation), 1, 'prepare this candidate, not a stale selection')
                self.assertIn('COMPONENT_ENV_FILE="$(TEST_COMPONENT_ENV_FILE)"', preparation[0])
                self.assertIn('COMPONENT_BUILD_MODE="$(TEST_COMPONENT_BUILD_MODE)"', preparation[0])
                self.assertLess(recipe.index('build-api-e2e'), recipe.index('prepare-components'))
                self.assertLess(recipe.index('prepare-components'), recipe.index('run-api-test'))
                checked.add(target)
        self.assertEqual(checked, {'up-test', 'up-test-billing', 'test-e2e-org-user-quorum'})

    def launch(self, target, selection, **variables):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            checkout = home / 'checkout'
            checkout.mkdir()
            (checkout / 'scripts').symlink_to(ROOT / 'scripts', target_is_directory=True)
            (checkout / '.env').write_text('')
            (checkout / '.env').chmod(0o600)
            config = home / '.config/caution'
            config.mkdir(parents=True)
            (config / '.env').write_text('DATABASE_URL=fixture-runtime\n')
            (config / '.env').chmod(0o600)
            if selection is not None:
                (config / 'components.env').write_text(selection)
            log = home / 'docker-calls'
            plan = subprocess.run(['make', '-sn', '-o', 'network', '-o', 'postgres',
                                   '-o', 'guard-direct-api', target, f'HOME={home}',
                                   f'CAUTION_DATA_DIR={home}/cache', f'KEYMAKER_POLICY_DIR={home}/policies',
                                   *[f'{key}={value}' for key, value in variables.items()]],
                                  cwd=ROOT, text=True, capture_output=True, check=True)
            commands = home / 'bin'
            commands.mkdir()
            docker = commands / 'docker'
            docker.write_text('''#!/bin/sh
printf '%s\\n' "$*" >> "$CALLS"
case "$*" in *--check-components*) exit "${CHECK_STATUS:-0}";; esac
''')
            docker.chmod(0o755)
            functions = "stat() { printf '0'; }\n"
            result = None
            for command in plan.stdout.replace('\\\n', '').splitlines():
                result = subprocess.run(['bash', '-c', functions + command], cwd=checkout,
                                        env={'PATH': f'{commands}:/usr/bin:/bin',
                                             'HOME': str(home), 'CAUTION_ENV_FILE': str(config / '.env'),
                                             'CALLS': str(log),
                                             'API_COMPONENT_IMAGE': 'must-not-use-inherited-image',
                                             'CHECK_STATUS': variables.get('CHECK_STATUS', '0')},
                                        text=True, capture_output=True)
                if result.returncode:
                    break
            assert result is not None, 'Make must produce a launch recipe'
            return result, log.read_text().splitlines() if log.exists() else []

    def test_e2e_prebuilt_uses_selected_candidate_and_preflights_before_removal(self):
        selection = f'API_COMPONENT_IMAGE={IMAGE}\nCOMPONENT_BUILD_MODE=prebuilt\n'
        selection += 'COMPONENT_SET_SHA256=' + 'd' * 64 + '\nCOMPONENTS_S3_BUCKET=fixture\n'
        result, calls = self.launch('run-api-test', selection, TEST_COMPONENT_ENV_FILE='$(HOME)/.config/caution/components.env')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('--check-components', calls[0])
        self.assertEqual(calls[1], 'rm -f api')
        self.assertEqual(shlex.split(calls[2])[0], 'run')
        self.assertIn('-d', shlex.split(calls[2]))
        for command in (calls[0], calls[2]):
            self.assertIn(IMAGE, command)
            for name in ('PLATFORM_GIT_SHA', 'COMPONENT_BUILD_MODE', 'COMPONENT_SET_SHA256',
                         'COMPONENTS_S3_BUCKET', *(n.upper() + '_COMMIT' for n in PINS)):
                self.assertIn('-e ' + name, command)
            self.assertNotIn('COMPONENT_SET_SHA256=', command)

    def test_e2e_prebuilt_cannot_fallback_or_replace_api_after_failed_check(self):
        for selection in (None, 'API_COMPONENT_IMAGE=\n',
                          f'API_COMPONENT_IMAGE={IMAGE}\nCOMPONENT_BUILD_MODE=source\n'):
            with self.subTest(selection=selection):
                result, calls = self.launch('run-api-test', selection, TEST_COMPONENT_ENV_FILE='$(HOME)/.config/caution/components.env')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])
        selection = f'API_COMPONENT_IMAGE={IMAGE}\nCOMPONENT_BUILD_MODE=prebuilt\n'
        result, calls = self.launch('run-api-test', selection, CHECK_STATUS='1',
                                   TEST_COMPONENT_ENV_FILE='$(HOME)/.config/caution/components.env')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 1)
        self.assertIn('--check-components', calls[0])

    def test_e2e_explicit_source_mode_uses_candidate_and_clears_prebuilt_selection(self):
        result, calls = self.launch('run-api-test', None, TEST_COMPONENT_BUILD_MODE='source',
                                   API_IMAGE='candidate-e2e')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for command in (calls[0], calls[-1]):
            self.assertIn('candidate-e2e', command)
            self.assertIn('-e COMPONENT_BUILD_MODE=source', command)
            self.assertIn('-e COMPONENT_SET_SHA256=', command)
            self.assertIn('-e COMPONENTS_S3_BUCKET=', command)

    def test_direct_launch_missing_or_empty_selection_has_actionable_error(self):
        for selection in (None, '', 'API_COMPONENT_IMAGE=\n', 'COMPONENT_BUILD_MODE=prebuilt\n'):
            with self.subTest(selection=selection):
                result, calls = self.launch('run-api', selection)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('make prepare-components', result.stdout + result.stderr)
                self.assertEqual(calls, [])

    def test_unit_missing_selection_fails_before_docker_with_diagnostic(self):
        unit = (ROOT / 'systemd/caution-api.service').read_text()
        self.assertIn('EnvironmentFile=-%h/.config/caution/components.env', unit)
        guard = next(line.split('=', 1)[1] for line in unit.splitlines()
                     if line.startswith('ExecStartPre='))
        self.assertTrue(guard.startswith('/bin/sh -c '))
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / '.config/caution'
            config.mkdir(parents=True)
            for exists, image in ((False, ''), (True, ''), (True, IMAGE)):
                if exists:
                    (config / 'components.env').write_text('fixture\n')
                command = shlex.split(guard.replace('%h', directory).replace('$$', '$'))
                result = subprocess.run(command, env={'API_COMPONENT_IMAGE': image},
                                        text=True, capture_output=True)
                if exists and image:
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('make prepare-components', result.stdout + result.stderr)


class ProcessCleanupTests(unittest.TestCase):
    def test_only_owned_container_is_removed_after_success_failure_or_signal(self):
        done = subprocess.CompletedProcess([], 0, stdout='fixture output')
        for outcome in (done, subprocess.CalledProcessError(1, []), SystemExit(143)):
            with self.subTest(outcome=type(outcome).__name__), patch.object(
                    subprocess, 'run', side_effect=[outcome, done]) as execute:
                if isinstance(outcome, BaseException):
                    with self.assertRaises(type(outcome)):
                        PREP.run('docker', 'run', '--rm', 'fixture-image', capture=True)
                else:
                    self.assertEqual(PREP.run('docker', 'run', '--rm', 'fixture-image', capture=True),
                                     'fixture output')
                command = execute.call_args_list[0].args[0]
                self.assertEqual(command[:3], ['docker', 'run', '--name'])
                self.assertRegex(command[3], '^caution-prepare-[0-9a-f]{32}$')
                self.assertEqual(execute.call_args_list[1].args[0], ['docker', 'rm', '-f', command[3]])

    def test_termination_cleans_secret_directory_and_releases_lock(self):
        previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        old_umask = os.umask(0o077)
        self.addCleanup(os.umask, old_umask)
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory)
            def stop(_image, _network, work, _selection_file):
                (work / 'publisher.env').write_text('AWS_SECRET_ACCESS_KEY=fixture\n')
                PREP.interrupted(signal.SIGTERM, None)
            with patch.object(PREP, 'CONFIG', config), patch.object(PREP, 'prepare', side_effect=stop), \
                    patch.object(sys, 'argv', ['prepare-components']):
                with self.assertRaises(SystemExit) as error:
                    PREP.main()
                self.assertEqual(error.exception.code, 143)
            self.assertEqual(list(config.glob('.components-*')), [])
            with (config / 'components.prepare.lock').open('a') as lock:
                PREP.fcntl.flock(lock, PREP.fcntl.LOCK_EX | PREP.fcntl.LOCK_NB)
            self.assertEqual({sig: signal.getsignal(sig) for sig in previous}, previous)


if __name__ == '__main__':
    unittest.main()
