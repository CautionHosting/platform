#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
"""Launch one service using an atomically selected, immutable release pair."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess


def command(service, detach=False, data_dir=None, prices_file=None,
            network='caution-network', dns=(), metering_interval_secs=None):
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]*', network):
        raise ValueError('Network must be a valid Docker network name')
    for resolver in dns:
        ipaddress.ip_address(resolver)
    if metering_interval_secs is not None:
        if service != 'metering' or not 0 < metering_interval_secs < (1 << 64):
            raise ValueError('Metering interval must be a positive u64 for the metering service')
    config = Path.home() / '.config/caution'
    releases = config / 'releases'
    release = (releases / 'current').resolve(strict=True)
    if release.parent != releases:
        raise ValueError('Active release is outside the managed release directory')
    record = json.loads((release / 'release.json').read_text())
    image = record['images'][service]
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
        raise ValueError('Release must reference immutable service image IDs')
    environment = release / 'components.env'
    if not environment.is_file():
        raise ValueError('Release configuration is missing; run make up first')
    lines = environment.read_text().splitlines()
    values = dict(line.split('=', 1) for line in lines)
    if len(values) != len(lines) or values != record['environment']:
        raise ValueError('Release environment differs from the accepted image/configuration pair')
    if record['component_build_mode'] == 'prebuilt':
        digest = hashlib.sha256((release / 'components.lock.json').read_bytes()).hexdigest()
        if digest != record['component_set_sha256']:
            raise ValueError('Release component lock differs from its accepted digest')
    args = ['docker', 'run', '--name', service, '--network', network,
            '--env-file', str(config / '.env'), '--env-file', str(environment)]
    for resolver in dns:
        args += ['--dns', resolver]
    if detach:
        args.append('--detach')
    if service in ('api', 'gateway'):
        data = 'caution-data-dir'
        if data_dir is not None:
            data = Path(data_dir).expanduser().resolve()
            if ':' in str(data):
                raise ValueError('Data directory cannot contain a Docker mount separator')
            directories = ('git-repos', 'build', 'terraform') if service == 'api' else ('git-repos',)
            for directory in directories:
                (data / directory).mkdir(parents=True, exist_ok=True)
        args += ['-v', f'{data}:/var/cache/caution',
                 '-e', 'CAUTION_DATA_DIR=/var/cache/caution']
    if service in ('api', 'metering'):
        prices = Path(prices_file).expanduser().resolve() if prices_file is not None else config / 'prices.json'
        args += ['-v', f'{prices}:/app/prices.json:ro',
                 '-v', f'{config}/config.json:/app/config.json:ro']
    if service == 'api':
        args += ['-e', 'TF_PLUGIN_CACHE_DIR=/var/cache/caution/terraform']
    elif service == 'gateway':
        args += ['-p', '8000:8080', '-p', '2222:2222']
    elif service == 'email':
        args += ['-e', 'EMAIL_BIND_ADDR=0.0.0.0:8082', '-p', '127.0.0.1:8082:8082']
    if metering_interval_secs is not None:
        args += ['-e', f'METERING_INTERVAL_SECS={metering_interval_secs}']
    return [*args, image]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('service', choices=('api', 'gateway', 'email', 'metering'))
    parser.add_argument('--detach', action='store_true')
    parser.add_argument('--data-dir', help='Shared host data directory (default: caution-data-dir volume)')
    parser.add_argument('--prices-file', help='Host prices file (default: ~/.config/caution/prices.json)')
    parser.add_argument('--network', default='caution-network', help='Docker network name')
    parser.add_argument('--dns', action='append', default=[], help='DNS server IP (repeatable)')
    parser.add_argument('--metering-interval-secs', type=int,
                        help='Explicit metering interval override (default: retain env-file/image setting)')
    args = parser.parse_args()
    launch = command(args.service, args.detach, args.data_dir, args.prices_file,
                     network=args.network, dns=args.dns,
                     metering_interval_secs=args.metering_interval_secs)
    # Validate the complete pair before touching an existing container.
    subprocess.run(['docker', 'rm', '--force', args.service], check=False,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.execvp(launch[0], launch)


if __name__ == '__main__':
    main()
