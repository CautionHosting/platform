#!/usr/bin/env python3
"""Behavior tests for the benchmark runner; injected fixtures are not platform results."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

RUNNER = Path(__file__).with_name('run_local_tests.py')


class RunnerContracts(unittest.TestCase):
    def test_failed_suite_makes_batch_fail_but_keeps_other_results(self):
        self.assertTrue(RUNNER.is_file(), 'Local test runner must exist')
        spec = importlib.util.spec_from_file_location('runner', RUNNER)
        assert spec is not None and spec.loader is not None
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            tasks = [
                {'name': 'deliberate-failure', 'cwd': root, 'command': [sys.executable, '-c', 'raise SystemExit(37)'], 'expected': None},
                {'name': 'sentinel', 'cwd': root, 'command': [sys.executable, '-c', 'print("SENTINEL-RAN")'], 'expected': None},
            ]
            result = runner.run_batch(tasks, workers=2, output=root / 'logs', env={})
            self.assertFalse(result['passed'])
            rows = {r['name']: r for r in result['tasks']}
            self.assertEqual(rows['deliberate-failure']['exit_code'], 37)
            self.assertEqual(rows['sentinel']['exit_code'], 0)
            self.assertIn('SENTINEL-RAN', Path(rows['sentinel']['log']).read_text())


    def test_launch_errors_preserve_all_result_rows(self):
        spec = importlib.util.spec_from_file_location('runner', RUNNER)
        assert spec is not None and spec.loader is not None
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            tasks = [
                {'name': 'missing-executable', 'cwd': root,
                 'command': [str(root/'no-such-executable')], 'expected': None},
                {'name': 'missing-cwd', 'cwd': root/'no-such-directory',
                 'command': [sys.executable, '-c', 'print("UNREACHABLE")'], 'expected': None},
                {'name': 'sentinel', 'cwd': root,
                 'command': [sys.executable, '-c', 'print("SENTINEL-RAN")'], 'expected': None},
            ]
            try:
                result = runner.run_batch(tasks, workers=2, output=root/'logs', env={})
            except OSError as error:
                self.fail(f'Launch failure aborted aggregate diagnostics: {error}')
            self.assertFalse(result['passed'])
            rows = {row['name']: row for row in result['tasks']}
            self.assertEqual(len(rows), 3)
            for name in ('missing-executable', 'missing-cwd'):
                self.assertFalse(rows[name]['passed'])
                self.assertEqual(rows[name]['exit_code'], 125)
                self.assertIn('FileNotFoundError', rows[name]['launch_error'])
                self.assertIn('LAUNCH ERROR', Path(rows[name]['log']).read_text())
            self.assertTrue(rows['sentinel']['passed'])


    def test_zero_exit_requires_complete_passing_counts(self):
        spec = importlib.util.spec_from_file_location('runner', RUNNER)
        assert spec is not None and spec.loader is not None
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        cases = [
            ('python', 'Ran 2 tests in 0.001s\n\nOK\n', True),
            ('python', '', False),
            ('python', 'Ran 1 test in 0.001s\n\nOK\n', False),
            ('python', 'Ran 2 tests in 0.001s\n\nOK (skipped=1)\n', False),
            ('node', '# tests 2\n# pass 2\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n', True),
            ('node', '# tests 2\n# pass 1\n# fail 0\n# cancelled 0\n# skipped 1\n# todo 0\n', False),
            ('installer', 'Testing first...\nTesting second...\nCLI installer tests passed\n', True),
            ('installer', 'Testing first...\nCLI installer tests passed\n', False),
        ]
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for index, (kind, text, passed) in enumerate(cases):
                with self.subTest(kind=kind, index=index):
                    task = {'name': 'counts', 'cwd': root,
                            'command': [sys.executable, '-c', 'print(' + repr(text) + ')'],
                            'expected': {'kind': kind, 'tests': 2}}
                    result = runner.run_batch([task], workers=1, output=root / str(index), env={})
                    self.assertEqual(result['passed'], passed)


    def test_exit_during_signaling_preserves_failure_and_other_suite(self):
        from unittest.mock import patch
        spec = importlib.util.spec_from_file_location('runner', RUNNER)
        assert spec is not None and spec.loader is not None
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        original_send = runner.signal.pidfd_send_signal

        def exits_during_signal(fd, sig):
            original_send(fd, sig)
            if sig == runner.signal.SIGTERM:
                raise ProcessLookupError('Controlled exit/signaling race')

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            tasks = [
                {'name': 'timeout-race', 'cwd': root, 'expected': None, 'timeout': 0.2,
                 'command': [sys.executable, '-c', 'import time; print("PARTIAL", flush=True); time.sleep(5)']},
                {'name': 'other-suite', 'cwd': root, 'expected': None,
                 'command': [sys.executable, '-c', 'import time; time.sleep(0.8); print("OTHER-SUITE-FINISHED")']},
            ]
            with patch.object(runner.signal, 'pidfd_send_signal', side_effect=exits_during_signal) as send:
                result = runner.run_batch(tasks, workers=2, output=root/'logs', env={})
            self.assertTrue(any(call.args[1] == runner.signal.SIGTERM for call in send.call_args_list))
            rows = {row['name']: row for row in result['tasks']}
            self.assertFalse(result['passed'])
            self.assertEqual(rows['timeout-race']['exit_code'], 124)
            self.assertTrue(rows['timeout-race']['timed_out'])
            self.assertEqual(rows['timeout-race']['cleanup_errors'], [])
            self.assertIn('PARTIAL', Path(rows['timeout-race']['log']).read_text())
            self.assertTrue(rows['other-suite']['passed'])
            self.assertIn('OTHER-SUITE-FINISHED', Path(rows['other-suite']['log']).read_text())


    def test_timeout_fails_and_preserves_partial_log(self):
        spec = importlib.util.spec_from_file_location('runner', RUNNER)
        assert spec is not None and spec.loader is not None
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            task = {'name': 'timeout', 'cwd': root, 'expected': None, 'timeout': 0.1,
                    'command': [sys.executable, '-c', 'import time; print("BEFORE-TIMEOUT", flush=True); time.sleep(2)']}
            result = runner.run_batch([task], workers=1, output=root / 'logs', env={})
            self.assertFalse(result['passed'])
            self.assertEqual(result['tasks'][0]['exit_code'], 124)
            self.assertTrue(result['tasks'][0]['timed_out'])
            self.assertIn('BEFORE-TIMEOUT', Path(result['tasks'][0]['log']).read_text())


if __name__ == '__main__':
    unittest.main(verbosity=2)
