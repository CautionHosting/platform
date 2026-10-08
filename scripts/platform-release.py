#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
"""Prepare immutable platform releases before changing the running services."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid

SERVICES = ('email', 'metering', 'api', 'gateway')
PINS = ('enclaveos', 'bootproof', 'steve', 'locksmith')
CONFIG = Path.home() / '.config/caution'
STATE = CONFIG / 'releases'
UNITS = Path.home() / '.config/systemd/user'
ROOT = Path(__file__).resolve().parents[1]
LOCK_FD = None


def run(*args, cwd=None, capture=False, check=True):
    env = dict(os.environ, GIT_TERMINAL_PROMPT='0', GIT_NO_REPLACE_OBJECTS='1')
    # Recursive Make must not inherit caller overrides capable of changing pins,
    # service tags, build recipes, or the frozen source directory.
    for key in ('MAKEFLAGS', 'MAKEOVERRIDES', 'MFLAGS'):
        env.pop(key, None)
    if cwd:
        env['PWD'] = str(cwd)
    return subprocess.run([str(a) for a in args], cwd=cwd or ROOT, env=env,
                          check=check, text=True, stdout=subprocess.PIPE if capture else None,
                          pass_fds=() if LOCK_FD is None else (LOCK_FD,))


def text(*args, **kwargs):
    return run(*args, capture=True, **kwargs).stdout.strip()


def env_values(path):
    values = {}
    for line in path.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        key, separator, value = line.partition('=')
        if not separator or not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', key):
            raise ValueError(f'{path}: expected Docker KEY=value syntax (not shell expressions)')
        values[key] = value
    return values


def write_env(path, values):
    if any('\n' in value or '\r' in value for value in values.values()):
        raise ValueError('Multiline environment values are not supported')
    atomic_bytes(path, ''.join(f'{key}={value}\n' for key, value in values.items()).encode())


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_bytes(path, value):
    temporary = path.with_name(path.name + '.tmp')
    with temporary.open('wb') as out:
        out.write(value)
        out.flush()
        os.fsync(out.fileno())
    temporary.replace(path)
    sync_directory(path.parent)


def atomic_json(path, value):
    atomic_bytes(path, (json.dumps(value, sort_keys=True, indent=2) + '\n').encode())


def point(name, target):
    path = STATE / name
    temporary = STATE / ('.' + name + '.tmp')
    temporary.unlink(missing_ok=True)
    if target is None:
        path.unlink(missing_ok=True)
    else:
        temporary.symlink_to(target)
        temporary.replace(path)
    sync_directory(STATE)


def current():
    path = STATE / 'current'
    if not path.is_symlink():
        if path.exists():
            raise ValueError('Release current must be a managed symlink')
        return None
    resolved = path.resolve(strict=True)
    if resolved.parent != STATE or not (resolved / 'release.json').is_file():
        raise ValueError('Active release is outside the managed release directory or incomplete')
    return resolved.name


def dropin(service):
    return UNITS / f'caution-{service}.service.d/90-caution-release.conf'


def unit_override(service):
    return ('# Managed by make up; use a separate drop-in for operator settings.\n'
            '[Service]\nExecStartPre=\nExecStart=\n'
            'ExecStart=/usr/bin/python3 %h/.config/caution/releases/current/launch-service.py '
            + service + '\n')


def verify_dropins():
    for service in SERVICES:
        path = dropin(service)
        if path.exists() and path.read_text() != unit_override(service):
            raise ValueError(f'Refusing to overwrite modified managed unit drop-in: {path}')
        installed = text('systemctl', '--user', 'cat', f'caution-{service}.service')
        for line in installed.splitlines():
            key, separator, value = line.partition('=')
            if separator and key.strip() == 'ExecStartPre' and value.strip() not in (
                    '', f'-/usr/bin/docker rm -f {service}'):
                raise ValueError(f'Custom ExecStartPre in caution-{service}.service is not supported; '
                                 'refusing to clear operator hooks')


def recover():
    pending = STATE / 'pending.json'
    if not pending.exists():
        raise ValueError('No incomplete release activation to recover')
    journal = json.loads(pending.read_text())
    if current() not in (journal['candidate'], journal['previous']):
        raise ValueError('Active release changed outside this transaction; inspect pending.json')
    verify_dropins()
    print('Recovering service images/configuration only; database migrations are NOT rolled back.', flush=True)
    run('systemctl', '--user', 'stop', *(f'caution-{s}.service' for s in SERVICES))
    point('current', journal['previous'])
    for service in SERVICES:
        if not journal['dropins'][service] and dropin(service).exists():
            dropin(service).unlink(missing_ok=True)
            sync_directory(dropin(service).parent)
    run('systemctl', '--user', 'daemon-reload')
    if journal['active']:
        run('systemctl', '--user', 'restart', *journal['active'])
        if journal['previous']:
            record = json.loads((STATE / journal['previous'] / 'release.json').read_text())
            services = [s for s in SERVICES if f'caution-{s}.service' in journal['active']]
            ready(record['images'], services)
    pending.unlink()
    sync_directory(STATE)


def docker_socket():
    endpoint = os.environ.get('DOCKER_HOST') or text(
        'docker', 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}')
    if not endpoint.startswith('unix://'):
        raise ValueError('make up must run on the Docker host (a local Unix socket is required)')
    path = Path(endpoint.removeprefix('unix://'))
    if not stat.S_ISSOCK(path.stat().st_mode):
        raise ValueError('Docker endpoint is not a Unix socket')
    return path


def prepare(work, settings, mode):
    head = text('git', 'rev-parse', 'HEAD')
    if not re.fullmatch('[0-9a-f]{40}', head):
        raise ValueError('Expected a full platform Git commit')
    if text('git', 'status', '--porcelain=v1', '--untracked-files=no'):
        raise ValueError('Commit tracked changes before make up: release inputs must be frozen')
    source = work / 'platform'
    run('git', 'clone', '--quiet', '--no-hardlinks', '--no-checkout', ROOT, source)
    run('git', '-c', 'core.hooksPath=/dev/null', 'checkout', '--quiet', '--detach', head, cwd=source)
    release_id = f'{head[:12]}-{uuid.uuid4().hex[:12]}'
    release = STATE / release_id
    release.mkdir()
    tags = {s: f'caution-{s}:release-{release_id}' for s in SERVICES}
    run('make', '-j4', *(f'build-{s}' for s in SERVICES),
        *(f'{s.upper()}_IMAGE={image}' for s, image in tags.items()),
        f'PLATFORM_GIT_SHA={head}', cwd=source)
    images = {s: text('docker', 'image', 'inspect', '--format', '{{.Id}}', tag)
              for s, tag in tags.items()}
    if any(not re.fullmatch(r'sha256:[0-9a-f]{64}', image) for image in images.values()):
        raise ValueError('A candidate service image has no immutable Docker image ID')
    image_env = dict(entry.split('=', 1) for entry in json.loads(text(
        'docker', 'image', 'inspect', '--format', '{{json .Config.Env}}', images['api'])))
    if image_env.get('PLATFORM_GIT_SHA') != head:
        raise ValueError('Candidate API image differs from the captured platform revision')
    private_env = work / 'publisher.env'
    write_env(private_env, settings)
    base = ['docker', 'run', '--rm', '--user', f'{os.getuid()}:{os.getgid()}',
            '--env-file', str(private_env)]
    inputs = json.loads(text(*base, '--network', 'none', '--entrypoint', 'prepare-components',
                             images['api'], '--print-inputs'))
    if set(inputs) != set(PINS) or any(
            not re.fullmatch('[0-9a-f]{40}', inputs[name]['commit']) for name in PINS):
        raise ValueError('Candidate publisher returned incomplete or unpinned source inputs')
    generated = {'PLATFORM_GIT_SHA': head, 'COMPONENT_BUILD_MODE': mode,
                 **{name.upper() + '_COMMIT': inputs[name]['commit'] for name in PINS},
                 'COMPONENT_SET_SHA256': '', 'COMPONENTS_S3_BUCKET': ''}
    digest = None
    if mode == 'prebuilt':
        bucket = settings.get('COMPONENTS_S3_BUCKET') or settings.get('EIF_S3_BUCKET')
        if not bucket and re.fullmatch('[0-9]{12}', settings.get('AWS_ACCOUNT_ID', '')):
            bucket = 'caution-eif-storage-' + settings['AWS_ACCOUNT_ID']
        if not bucket:
            raise ValueError('Set EIF_S3_BUCKET or AWS_ACCOUNT_ID (or an existing COMPONENTS_S3_BUCKET)')
        socket = docker_socket()
        mounted = [*base, '--group-add', str(socket.stat().st_gid),
                   '-e', 'HOME=/tmp', '-e', 'DOCKER_HOST=unix:///var/run/docker.sock',
                   '-v', f'{socket}:/var/run/docker.sock', '-v', f'{work}:{work}',
                   '-v', f'{release}:{release}']
        enclave = work / 'enclaveos'
        run(*mounted, '--entrypoint', 'git', images['api'], 'clone', '--quiet', '--no-checkout',
            inputs['enclaveos']['repo'], enclave)
        run(*mounted, '--entrypoint', 'git', images['api'], '-C', enclave, 'checkout', '--quiet',
            '--detach', inputs['enclaveos']['commit'])
        accepted = STATE / 'accepted'
        accepted.mkdir(exist_ok=True)
        trusted = work / 'accepted'
        trusted.mkdir()
        arguments = []
        for path in sorted(accepted.glob('*.json')):
            if hashlib.sha256(path.read_bytes()).hexdigest() != path.stem:
                raise ValueError(f'Accepted local lock was modified: {path}')
            copy = trusted / path.name
            shutil.copyfile(path, copy)
            arguments.extend(('--accepted-lock', str(copy)))
        lock = work / 'components.lock.json'
        try:
            run(*mounted, '--entrypoint', 'prepare-components', images['api'],
                '--bucket', bucket, '--framework-source', source, '--framework-commit', head,
                '--enclave-source', enclave, '--enclave-commit', inputs['enclaveos']['commit'],
                '--bootproof-commit', inputs['bootproof']['commit'],
                '--steve-commit', inputs['steve']['commit'], '--locksmith-commit', inputs['locksmith']['commit'],
                '--output-lock', lock, '--build-log-dir', release / 'component-build-logs', *arguments)
        except subprocess.CalledProcessError:
            print('Component publication failed. Check source/build errors and existing publisher '
                  'ListBucket/GetObject/PutObject permissions for components/v1/. '
                  'No IAM changes were attempted and no release was activated.', file=sys.stderr)
            raise
        canonical = lock.read_bytes()
        digest = hashlib.sha256(canonical).hexdigest()
        saved = accepted / f'{digest}.json'
        if not saved.exists():
            atomic_bytes(saved, canonical)
        atomic_bytes(release / 'components.lock.json', canonical)
        generated.update(COMPONENT_SET_SHA256=digest, COMPONENTS_S3_BUCKET=bucket)
    write_env(release / 'components.env', generated)
    atomic_bytes(release / 'launch-service.py', (source / 'scripts/launch-service.py').read_bytes())
    atomic_json(release / 'release.json', {'schema_version': 1, 'framework_commit': head,
                'images': images, 'inputs': inputs, 'environment': generated, 'component_set_sha256': digest,
                'component_build_mode': mode, 'component_bucket': generated['COMPONENTS_S3_BUCKET']})
    return source, release, images


def ready(images, services=SERVICES):
    active = current()
    if active is None:
        raise ValueError('No active release to verify')
    expected = json.loads((STATE / active / 'release.json').read_text())['environment']
    deadline = time.monotonic() + 120
    ports = {'api': 8080, 'gateway': 8080, 'email': 8082, 'metering': 8083}
    while time.monotonic() < deadline:
        healthy = True
        for service, port in ports.items():
            if service not in services:
                continue
            result = run('docker', 'inspect', '--format', '{{.Image}}', service,
                         capture=True, check=False)
            if result.returncode or result.stdout.strip() != images[service]:
                healthy = False
                break
            if service == 'api':
                result = run('docker', 'inspect', '--format', '{{json .Config.Env}}', service,
                             capture=True, check=False)
                if result.returncode:
                    healthy = False
                    break
                actual = dict(entry.split('=', 1) for entry in json.loads(result.stdout))
                if any(actual.get(key) != value for key, value in expected.items()):
                    healthy = False
                    break
            result = run('docker', 'run', '--rm', '--network', 'caution-network',
                         '--entrypoint', 'curl', images['api'], '--fail', '--silent',
                         '--connect-timeout', '2', '--max-time', '5',
                         f'http://{service}:{port}/health', capture=True, check=False)
            if result.returncode:
                healthy = False
                break
        if healthy:
            return
        time.sleep(2)
    raise RuntimeError('Services did not become healthy with the expected images and component selection')


def up():
    if (STATE / 'pending.json').exists():
        raise ValueError('An incomplete activation exists. Inspect it and run make recover-release first')
    settings = env_values(CONFIG / '.env')
    for key, value in os.environ.items():
        if key.startswith('AWS_') or key in ('EIF_S3_BUCKET', 'COMPONENTS_S3_BUCKET',
                                            'COMPONENT_BUILD_MODE', *(p.upper() + '_COMMIT' for p in PINS)):
            settings[key] = value
    mode = settings.get('COMPONENT_BUILD_MODE', 'prebuilt')
    if mode not in ('prebuilt', 'source'):
        raise ValueError('COMPONENT_BUILD_MODE must be prebuilt or source')
    verify_dropins()
    previous = current()
    with tempfile.TemporaryDirectory(prefix='caution-release-') as directory:
        source, release, images = prepare(Path(directory), settings, mode)
        run('make', 'network', cwd=source)
        run('docker', 'run', '--rm', '--network', 'caution-network',
            '--env-file', CONFIG / '.env', '--env-file', release / 'components.env',
            images['api'], '--check-components')
        journal = {'candidate': release.name, 'previous': previous,
                   'dropins': {s: dropin(s).exists() for s in SERVICES},
                   'active': [f'caution-{s}.service' for s in SERVICES if not run(
                       'systemctl', '--user', 'is-active', '--quiet', f'caution-{s}.service',
                       check=False).returncode]}
        atomic_json(STATE / 'pending.json', journal)
        try:
            run('make', 'migrate', cwd=source)
            for service in SERVICES:
                path = dropin(service)
                path.parent.mkdir(parents=True, exist_ok=True)
                atomic_bytes(path, unit_override(service).encode())
            point('current', release.name)
            run('systemctl', '--user', 'daemon-reload')
            run('systemctl', '--user', 'restart', *(f'caution-{s}.service' for s in SERVICES))
            ready(images)
        except (Exception, KeyboardInterrupt):
            print('Activation did not complete. Previous images and configuration are retained. '
                  'Inspect pending.json and use make recover-release; database changes are not undone.',
                  file=sys.stderr)
            raise
        point('previous', previous)
        (STATE / 'pending.json').unlink()
        sync_directory(STATE)
        print(f'Release {release.name} active ({mode}; component set {digest_label(release)}).')


def digest_label(release):
    return json.loads((release / 'release.json').read_text())['component_set_sha256'] or 'source'


def main():
    global LOCK_FD
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('up', 'recover'))
    args = parser.parse_args()
    os.umask(0o077)
    STATE.mkdir(parents=True, exist_ok=True)
    with (STATE / 'release.lock').open('a') as lock:
        LOCK_FD = lock.fileno()
        try:
            fcntl.flock(LOCK_FD, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Another platform release is already running') from None
        if args.action == 'up':
            up()
        else:
            recover()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f'Release failed: {error}', file=sys.stderr)
        sys.exit(1)
