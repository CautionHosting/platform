#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
"""Derive private, per-consumer env files from the operator's literal .env."""
from contextlib import contextmanager
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile

PUBLIC_KEYS = ('VITE_SENTRY_DSN', 'VITE_SENTRY_ENVIRONMENT', 'VITE_PADDLE_SANDBOX')
UPLOAD_KEYS = ('SENTRY_URL', 'SENTRY_ORG', 'SENTRY_PROJECT', 'SENTRY_AUTH_TOKEN')


def source_path():
    return Path(os.environ.get('CAUTION_ENV_FILE', Path.home() / '.config/caution/.env'))


def read_env(path, *, missing_ok=False):
    path = Path(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    except FileNotFoundError:
        if missing_ok:
            return {}
        raise
    with os.fdopen(fd, encoding='utf-8', newline='') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f'{path}: expected a regular configuration file')
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError(f'{path}: configuration requires owner-only permissions (chmod 600)')
        text = source.read()
    values = {}
    for line in text.split('\n'):
        line = line.removesuffix('\r')
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        key, separator, value = line.partition('=')
        if not separator or not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', key) or any(c in value for c in '\x00\r'):
            raise ValueError(f'{path}: expected literal single-line KEY=value settings')
        values[key] = value
    return values


def runtime_key(key):
    return not key.startswith('VITE_') and key not in (*UPLOAD_KEYS, 'SENTRY_RELEASE')


@contextmanager
def generated_files(scopes, *, source=None, missing_ok=False, base=None):
    values = read_env(base) if base is not None else {}
    values.update(read_env(source if source is not None else source_path(), missing_ok=missing_ok))
    selections = {
        'frontend': {key: values[key] for key in PUBLIC_KEYS if key in values},
        'frontend-sentry': {key: values[key] for key in UPLOAD_KEYS if key in values},
        'runtime': {key: value for key, value in values.items() if runtime_key(key)},
    }
    with tempfile.TemporaryDirectory(prefix='caution-env-') as work:
        files = {}
        for scope in scopes:
            path = Path(work) / f'{scope}.env'
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as output:
                output.write(''.join(f'{key}={value}\n' for key, value in selections[scope].items()))
            files[scope] = path
        yield files


def run_runtime(arguments):
    base = None
    if arguments[:1] == ['--base-env-file']:
        if len(arguments) < 3:
            raise ValueError('--base-env-file requires a path followed by Docker run arguments')
        base, arguments = Path(arguments[1]), arguments[2:]
    child = None

    def interrupted(signum, _frame):
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, signal.SIG_IGN)
        if child is not None:
            child.send_signal(signum)
        raise SystemExit(128 + signum)

    handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        with generated_files(('runtime',), base=base) as files:
            env = {key: value for key, value in os.environ.items() if runtime_key(key)
                   and key not in ('MAKEFLAGS', 'MFLAGS', 'MAKEOVERRIDES')}
            with subprocess.Popen(['docker', 'run', '--env-file', str(files['runtime']), *arguments], env=env) as child:
                status = child.wait()
                return status if status >= 0 else 128 - status
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)


def exec_aws(args):
    """Import only literal AWS settings; never expose upload or Make overrides."""
    values = read_env(source_path())
    env = {key: value for key, value in os.environ.items()
           if key not in (*UPLOAD_KEYS, 'SENTRY_RELEASE', 'MAKEFLAGS', 'MFLAGS', 'MAKEOVERRIDES')}
    env.update({key: value for key, value in values.items() if key.startswith('AWS_')})
    os.execvpe(args[0], args, env)


if __name__ == '__main__':
    if len(sys.argv) < 3 or sys.argv[1] not in ('run', 'aws-exec'):
        sys.exit('Usage: platform_env.py run <docker-run arguments> | aws-exec <command> [arguments]')
    try:
        if sys.argv[1] == 'aws-exec':
            exec_aws(sys.argv[2:])
        else:
            sys.exit(run_runtime(sys.argv[2:]))
    except (OSError, ValueError) as error:
        print(f'Environment preparation failed: {error}', file=sys.stderr)
        sys.exit(1)
