#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
"""Guard shared Cargo cache locking in concurrent service-image builds."""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICES = ('api', 'gateway', 'email-service', 'metering')

class CargoCacheSynchronization(unittest.TestCase):
    def test_all_cargo_steps_exclusively_share_caches_in_same_order(self):
        for service in SERVICES:
            with self.subTest(service=service):
                text = (ROOT / 'containerfiles' / ('Containerfile.' + service)).read_text()
                instructions = text.replace('\\\n', ' ').splitlines()
                steps = [line for line in instructions if line.startswith('RUN ') and re.search(r'cargo (fetch|build)\b', line)]
                self.assertEqual(len(steps), 2)
                for step in steps:
                    mounts = [dict(part.split('=', 1) for part in spec.split(',')) for spec in re.findall(r'--mount=(\S+)', step)]
                    deps = [m for m in mounts if m.get('target', '').startswith('/usr/local/cargo/')]
                    self.assertEqual([m['target'] for m in deps], ['/usr/local/cargo/registry', '/usr/local/cargo/git'])
                    for mount in deps:
                        self.assertEqual(mount.get('sharing'), 'locked', f'{service}: unsynchronized {mount}')
                        self.assertEqual(mount.get('id', mount['target']), mount['target'])
                self.assertIn('cargo fetch --locked --target $TARGET_ARCH', text)
                self.assertIn('--network=none', steps[1])
                self.assertIn('--frozen', steps[1])
                self.assertIn('x86_64-unknown-linux-musl', text)
                for flag in ('codegen-units=1', 'target-feature=+crt-static', 'link-arg=-Wl,--build-id=none'):
                    self.assertIn(flag, text)
                self.assertTrue('ARG CARGO_BUILD_FLAGS="--release"' in text or 'cargo build --release --frozen' in text)

if __name__ == "__main__":
    unittest.main(verbosity=2)
