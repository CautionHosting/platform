#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
"""Release preflight ordering; command fakes are not live Docker/S3 evidence."""
import unittest

import test_platform_release as release_tests


class ReleasePreflightTests(unittest.TestCase):
    def setUp(self):
        self.case = release_tests.PlatformReleaseTests()
        self.addCleanup(self.case.doCleanups)
        self.case.setUp()
        docker = self.case.bin / 'docker'
        original = docker.read_text()
        marker = "if name == 'docker':\n"
        self.assertIn(marker, original)
        docker.write_text(original.replace(marker, marker + "    if '--check-components' in args:\n        sys.exit(26 if os.environ.get('FAIL_READER') else 0)\n", 1))

    def test_reader_denial_preserves_active_services_before_migration(self):
        case = self.case
        initial = case.make('up')
        self.assertEqual(initial.returncode, 0, initial.stderr)
        active = (case.config / 'releases/current').resolve()
        case.log.write_text('')
        case.env['FAIL_READER'] = '1'
        failed = case.make('up')
        self.assertNotEqual(failed.returncode, 0, 'Runtime reader denial must abort preparation')
        self.assertEqual((case.config / 'releases/current').resolve(), active)
        commands = case.commands()
        self.assertTrue(any('--check-components' in command for command in commands))
        self.assertFalse(any(command[:3] == ['systemctl', '--user', 'restart'] for command in commands), commands)
        self.assertFalse((case.config / 'releases/pending.json').exists())


    def test_custom_pre_start_hook_rejected_before_preparation(self):
        case = self.case
        systemctl = case.bin / 'systemctl'
        original = systemctl.read_text()
        marker = "if name == 'systemctl':\n"
        self.assertIn(marker, original)
        addition = "    if 'cat' in args and args[-1] == 'caution-api.service':\n        print('[Service]\\nExecStartPre=/usr/local/bin/operator-ready-check')\n        sys.exit(0)\n"
        systemctl.write_text(original.replace(marker, marker + addition, 1))
        failed = case.make('up')
        self.assertNotEqual(failed.returncode, 0, 'Custom pre-start hooks must not be silently cleared')
        self.assertIn('ExecStartPre', failed.stderr)
        self.assertFalse(any(command[0] == 'docker' for command in case.commands()))
        self.assertFalse((case.config / 'releases/pending.json').exists())


if __name__ == '__main__':
    unittest.main()
