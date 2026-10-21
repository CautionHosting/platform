#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
"""Build, validate and upload a private frontend release before gateway packaging."""
import argparse
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import uuid
from platform_env import PUBLIC_KEYS, UPLOAD_KEYS, generated_files

ROOT = Path(__file__).resolve().parents[1]


def settings(path, keys, *, private=False):
    values = {}
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f'{path}: expected a regular configuration file')
        if private and (info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise ValueError(f'{path}: upload credentials require owner-only permissions (chmod 600)')
        lines = path.read_text().splitlines()
    except FileNotFoundError:
        lines = []
    for line in lines:
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        key, separator, value = line.partition('=')
        if not separator or key not in keys:
            raise ValueError(f'{path}: expected only documented literal KEY=value settings')
        values[key] = value
    values.update({key: os.environ[key] for key in keys if key in os.environ})
    return values


def run(*args, env, capture=False):
    return subprocess.run(args, cwd=ROOT, env=env, check=True, text=True,
                          stdout=subprocess.PIPE if capture else None).stdout


def container(image, retained, script, values, env, *, upload=False):
    name = 'caution-frontend-' + uuid.uuid4().hex
    command = ['docker', 'run', '--rm', '--name', name, '--read-only',
               '--tmpfs', '/tmp', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
               '--user', f'{os.getuid()}:{os.getgid()}', '--env', 'HOME=/tmp',
               '--mount', f'type=bind,source={retained},target=/release,readonly',
               '--entrypoint', '/usr/bin/node']
    if not upload:
        command.extend(['--network', 'none'])
    for key in values:
        command.extend(['--env', key])
    command.extend([image, f'/app/scripts/{script}', '/release/dist', '/release/sentry-artifacts'])
    try:
        run(*command, env={**env, **values})
    finally:
        subprocess.run(['docker', 'rm', '-f', name], env=env, timeout=30,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def prepare(gateway=False):
    with generated_files(('frontend', 'frontend-sentry'), missing_ok=True) as files:
        prepare_release(gateway, files)


def prepare_release(gateway, files):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('SENTRY_', 'VITE_')) and key not in
           ('MAKEFLAGS', 'MFLAGS', 'MAKEOVERRIDES', 'NODE_OPTIONS')}
    public = settings(Path(os.environ.get('FRONTEND_ENV_FILE') or files['frontend']), PUBLIC_KEYS)
    if any('$' in value or '\x00' in value or '\n' in value or '\r' in value for value in public.values()):
        raise ValueError('Frontend build settings must be literal single-line values without Make expressions')
    head = run('git', 'rev-parse', 'HEAD', env=env, capture=True).strip()
    public['VITE_SENTRY_RELEASE'] = os.environ.get('VITE_SENTRY_RELEASE', head)
    if not re.fullmatch(r'[0-9a-f]{40}', public['VITE_SENTRY_RELEASE']):
        raise ValueError('VITE_SENTRY_RELEASE must be a full lowercase commit SHA')
    if not os.environ.get('FRONTEND_RELEASE_DIR') and public['VITE_SENTRY_RELEASE'] != head:
        raise ValueError('A fresh frontend build must use the current Git commit as its release')
    run('git', 'diff', '--quiet', 'HEAD', '--', env=env)
    enabled = bool(public.get('VITE_SENTRY_DSN', '').strip())
    private = {}
    if enabled:
        private = settings(Path(os.environ.get('FRONTEND_SENTRY_ENV_FILE') or files['frontend-sentry']), UPLOAD_KEYS, private=True)
        for key in ('SENTRY_ORG', 'SENTRY_PROJECT', 'SENTRY_AUTH_TOKEN'):
            if not private.get(key, '').strip():
                raise ValueError(f'Set {key} in .env, an explicit frontend-sentry.env, or the upload environment')
        private['SENTRY_RELEASE'] = public['VITE_SENTRY_RELEASE']
    retained = os.environ.get('FRONTEND_RELEASE_DIR')
    if retained:
        retained = Path(retained).resolve()
    else:
        directory = Path(os.environ.get('FRONTEND_RELEASES_DIR', ROOT / 'out/frontend-releases'))
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        retained = Path(tempfile.mkdtemp(prefix=f'{head}-', dir=directory)).resolve() / 'release'
        run('make', '--no-print-directory', 'build-frontend-artifacts',
            f'FRONTEND_ARTIFACTS_DIR={retained}', env={**env, **public})
    with tempfile.TemporaryDirectory(prefix='frontend-uploader-') as work:
        image_file = Path(work) / 'image-id'
        run('docker', 'build', '--target', 'sentry-uploader', '--iidfile', str(image_file),
            '-f', './containerfiles/Containerfile.frontend', '.', env=env)
        image = image_file.read_text().strip()
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
            raise ValueError('Expected an immutable frontend uploader image ID')
        container(image, retained, 'validate-sentry-artifacts.js', public, env)
        if enabled:
            container(image, retained, 'upload-sentry-sourcemaps.js', private, env, upload=True)
    if gateway:
        run('make', '--no-print-directory', 'build-gateway',
            f'FRONTEND_RELEASE_DIR={retained}', env={**env, **public})
    print(f'Frontend release retained privately at {retained}')
    if not enabled:
        print('Frontend Sentry is not configured; no source-map upload performed')


def interrupted(signum, _frame):
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, signal.SIG_IGN)
    raise SystemExit(128 + signum)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gateway', action='store_true', help='package the validated release into the gateway image')
    args = parser.parse_args()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)
    try:
        prepare(args.gateway)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'Frontend release failed: {error}', file=sys.stderr)
        sys.exit(1)
