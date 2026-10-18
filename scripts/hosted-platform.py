#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
"""Hosted user-service rendering and readiness; never interpret dotenv as shell."""
import argparse
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
UNITS = tuple('caution-' + name + '.service' for name in
              ('network', 'postgres', 'email', 'metering', 'api', 'gateway'))


def replace_once(content, old, new):
    if content.count(old) != 1:
        raise ValueError(f'Unexpected unit template: expected one {old.strip()!r}')
    return content.replace(old, new)


def setup():
    units = Path(os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config') / 'systemd/user'
    rendered = {}
    for name in UNITS:
        content = (ROOT / 'systemd' / name).read_text()
        content = replace_once(content, '[Service]\n', '[Service]\nRestart=on-failure\nRestartSec=5\n')
        if name == 'caution-gateway.service':
            content = replace_once(content, '-p 8000:8080 ', '-p 127.0.0.1:8000:8080 ')
            ssh = '127.0.0.1:2222:2222' if os.environ['CAUTION_DNS_MODE'] == 'deferred' else '2222:2222'
            content = replace_once(content, '-p 2222:2222 ', f'-p {ssh} ')
        if name == 'caution-email.service' and os.environ['CAUTION_MAIL_MODE'] == 'test':
            content = replace_once(content, ' caution-email\n',
                                   ' -e EMAIL_TEST_MODE=true -e ENVIRONMENT=development caution-email\n')
        rendered[name] = content
    for name, content in rendered.items():
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', dir=units, prefix='.hosted-', delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(content)
                os.fchmod(stream.fileno(), 0o644)
            temporary.replace(units / name)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    subprocess.run(['systemctl', '--user', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', '--user', 'enable', *UNITS], check=True)


def wait_for(label, probe):
    seconds = float(os.environ.get('CAUTION_HOSTED_WAIT_SECONDS', '120'))
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError('CAUTION_HOSTED_WAIT_SECONDS must be finite and positive')
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if probe(deadline):
                return
        except subprocess.TimeoutExpired:
            pass
        time.sleep(min(1, max(0, deadline - time.monotonic())))
    raise ValueError(f'Timed out waiting for {label}')


def postgres_ready(deadline):
    result = subprocess.run(['docker', 'exec', 'postgres', 'pg_isready', '-U', 'postgres'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=max(0.001, min(5, deadline - time.monotonic())))
    return result.returncode == 0


def services_ready(deadline):
    for unit in UNITS:
        result = subprocess.run(['systemctl', '--user', 'is-active', '--quiet', unit],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=max(0.001, min(5, deadline - time.monotonic())))
        if result.returncode != 0:
            return False
    for path in ('/api/legal/active-documents', '/'):
        result = subprocess.run(['curl', '--fail', '--silent', '--show-error', '--noproxy', '*',
                                 '--connect-timeout', '2', '--max-time', '5', '--max-filesize', '1048576',
                                 '--write-out', '\n%{http_code}', 'http://127.0.0.1:8000' + path],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                                timeout=max(0.001, min(5, deadline - time.monotonic())))
        if result.returncode != 0:
            return False
        body, separator, status = result.stdout.rstrip('\n').rpartition('\n')
        if not separator or status != '200':
            return False
        if path == '/api/legal/active-documents':
            try:
                if not isinstance(json.loads(body), list):
                    return False
            except ValueError:
                return False
        elif '<html' not in body.lower():
            return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('setup', 'wait-postgres', 'health'))
    args = parser.parse_args()
    if args.action == 'setup':
        setup()
    elif args.action == 'wait-postgres':
        wait_for('postgres', postgres_ready)
        print('Postgres ready')
    else:
        wait_for('all hosted services and HTTP readiness', services_ready)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'Hosted platform: {error}', file=sys.stderr)
        sys.exit(1)
