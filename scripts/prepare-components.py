#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
"""Prepare and check enclave components for an already-built API image."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import uuid

PINS = ('enclaveos', 'bootproof', 'steve', 'locksmith')
ROOT = Path(__file__).resolve().parents[1]
CONFIG = Path.home() / '.config/caution'


def run(*args, capture=False, cwd=ROOT):
    command = [str(arg) for arg in args]
    container = None
    if command[:2] == ['docker', 'run']:
        container = 'caution-prepare-' + uuid.uuid4().hex
        command[2:2] = ['--name', container]
    try:
        return subprocess.run(command, cwd=cwd, check=True, text=True,
                              env=dict(os.environ, GIT_TERMINAL_PROMPT='0', GIT_NO_REPLACE_OBJECTS='1'),
                              stdout=subprocess.PIPE if capture else None).stdout
    finally:
        if container:
            # Killing the Docker client alone does not stop its container.
            subprocess.run(['docker', 'rm', '-f', container], check=False, timeout=30,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def interrupted(signum, _frame):
    # Let the first interruption unwind subprocess/tempfile/lock contexts. Do not
    # allow a second normal termination signal to interrupt that cleanup.
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, signal.SIG_IGN)
    raise SystemExit(128 + signum)


def text(*args, **kwargs):
    return run(*args, capture=True, **kwargs).strip()


def read_env(path):
    values = {}
    for line in path.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        key, separator, value = line.partition('=')
        if not separator or not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', key):
            raise ValueError(f'{path}: expected literal Docker KEY=value syntax')
        values[key] = value
    return values


def write_env(path, values):
    if any('\n' in value or '\r' in value for value in values.values()):
        raise ValueError('Multiline environment values are not supported')
    path.write_text(''.join(f'{key}={value}\n' for key, value in values.items()))


def prepare(image, network, work):
    head = text('git', 'rev-parse', 'HEAD')
    if not re.fullmatch('[0-9a-f]{40}', head) or text(
            'git', 'status', '--porcelain=v1', '--untracked-files=no'):
        raise ValueError('Commit tracked changes before preparing components')
    image = text('docker', 'image', 'inspect', '--format', '{{.Id}}', image)
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
        raise ValueError('Expected an immutable API image ID')
    image_env = dict(entry.split('=', 1) for entry in json.loads(text(
        'docker', 'image', 'inspect', '--format', '{{json .Config.Env}}', image)))
    if image_env.get('PLATFORM_GIT_SHA') != head:
        raise ValueError('Build the API image from the selected platform commit first')
    settings = read_env(CONFIG / '.env')
    for key, value in os.environ.items():
        if key.startswith('AWS_') or key in ('EIF_S3_BUCKET', 'COMPONENTS_S3_BUCKET',
                                            'COMPONENT_BUILD_MODE', *(p.upper() + '_COMMIT' for p in PINS)):
            settings[key] = value
    mode = settings.get('COMPONENT_BUILD_MODE', 'prebuilt')
    if mode not in ('prebuilt', 'source'):
        raise ValueError('COMPONENT_BUILD_MODE must be prebuilt or source')
    publisher_env = work / 'publisher.env'
    write_env(publisher_env, settings)
    base = ['docker', 'run', '--rm', '--user', f'{os.getuid()}:{os.getgid()}',
            '--env-file', str(publisher_env)]
    inputs = json.loads(text(*base, '--network', 'none', '--entrypoint',
                            'prepare-components', image, '--print-inputs'))
    if set(inputs) != set(PINS) or any(
            not re.fullmatch('[0-9a-f]{40}', inputs[name]['commit']) for name in PINS):
        raise ValueError('Publisher returned incomplete or unpinned source inputs')
    generated = {'API_COMPONENT_IMAGE': image, 'PLATFORM_GIT_SHA': head,
                 'COMPONENT_BUILD_MODE': mode,
                 **{name.upper() + '_COMMIT': inputs[name]['commit'] for name in PINS},
                 'COMPONENT_SET_SHA256': '', 'COMPONENTS_S3_BUCKET': ''}
    if mode == 'prebuilt':
        bucket = settings.get('COMPONENTS_S3_BUCKET') or settings.get('EIF_S3_BUCKET')
        if not bucket and re.fullmatch('[0-9]{12}', settings.get('AWS_ACCOUNT_ID', '')):
            bucket = 'caution-eif-storage-' + settings['AWS_ACCOUNT_ID']
        if not bucket or not re.fullmatch('[a-z0-9.-]+', bucket):
            raise ValueError('Set an existing COMPONENTS_S3_BUCKET, EIF_S3_BUCKET or AWS_ACCOUNT_ID')
        endpoint = os.environ.get('DOCKER_HOST') or text(
            'docker', 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}')
        if not endpoint.startswith('unix://'):
            raise ValueError('Component preparation requires a local Docker Unix socket')
        socket = Path(endpoint.removeprefix('unix://'))
        if not stat.S_ISSOCK(socket.stat().st_mode):
            raise ValueError('Docker endpoint is not a Unix socket')
        source = work / 'platform'
        run('git', 'clone', '--quiet', '--no-hardlinks', '--no-checkout', ROOT, source)
        run('git', '-c', 'core.hooksPath=/dev/null', 'checkout', '--quiet', '--detach', head, cwd=source)
        mounted = [*base, '--group-add', str(socket.stat().st_gid),
                   '-e', 'HOME=/tmp', '-e', 'DOCKER_HOST=unix:///var/run/docker.sock',
                   '-v', f'{socket}:/var/run/docker.sock', '-v', f'{work}:{work}']
        enclave = work / 'enclaveos'
        run(*mounted, '--entrypoint', 'git', image, 'clone', '--quiet', '--no-checkout',
            inputs['enclaveos']['repo'], enclave)
        run(*mounted, '--entrypoint', 'git', image, '-C', enclave, 'checkout', '--quiet',
            '--detach', inputs['enclaveos']['commit'])
        accepted = CONFIG / 'components/accepted'
        accepted.mkdir(parents=True, exist_ok=True)
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
        logs = Path(tempfile.mkdtemp(prefix='build-', dir=accepted.parent))
        run(*mounted, '-v', f'{logs}:{logs}', '--entrypoint', 'prepare-components', image,
            '--bucket', bucket, '--framework-source', source, '--framework-commit', head,
            '--enclave-source', enclave, '--enclave-commit', inputs['enclaveos']['commit'],
            '--bootproof-commit', inputs['bootproof']['commit'],
            '--steve-commit', inputs['steve']['commit'], '--locksmith-commit', inputs['locksmith']['commit'],
            '--output-lock', lock, '--build-log-dir', logs, *arguments)
        canonical = lock.read_bytes()
        digest = hashlib.sha256(canonical).hexdigest()
        saved = accepted / f'{digest}.json'
        if not saved.exists():
            lock.replace(saved)
        generated.update(COMPONENT_SET_SHA256=digest, COMPONENTS_S3_BUCKET=bucket)
    overlay = work / 'components.env'
    write_env(overlay, generated)
    run('docker', 'run', '--rm', '--network', network, '--env-file', CONFIG / '.env',
        '--env-file', overlay, image, '--check-components')
    overlay.replace(CONFIG / 'components.env')
    print(f'Prepared API components ({mode}); no migrations or services changed.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default='caution-api')
    parser.add_argument('--network', default='caution-network')
    args = parser.parse_args()
    os.umask(0o077)
    CONFIG.mkdir(parents=True, exist_ok=True)
    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        with (CONFIG / 'components.prepare.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            with tempfile.TemporaryDirectory(prefix='.components-', dir=CONFIG) as directory:
                prepare(args.image, args.network, Path(directory))
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == '__main__':
    main()
