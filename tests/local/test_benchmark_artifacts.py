#!/usr/bin/env python3
"""Synthetic artifact fixtures: all fixture timings are never performance evidence."""
import json
import platform
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


class BenchmarkArtifacts(unittest.TestCase):
    def test_success_records_suite_runtimes_not_harness_runtimes(self):
        with tempfile.TemporaryDirectory(prefix='synthetic-runtime-artifacts-') as folder:
            root = Path(folder)
            scripts = root / 'scripts'
            scripts.mkdir()
            output = root / 'synthetic-artifacts-not-performance-evidence'
            suite_bin = root / 'suite-bin'
            harness_bin = root / 'harness-bin'
            probes = root / 'runtime-probes.jsonl'
            suite_env = {'PATH': str(suite_bin), 'LC_ALL': 'C.UTF-8',
                         'NODE_OPTIONS': '--experimental-global-webcrypto',
                         'SUITE_ONLY': 'synthetic-suite-sentinel'}
            for directory, label in ((suite_bin, 'suite'), (harness_bin, 'harness')):
                directory.mkdir()
                for name, version in (('python3', f'Python 0.0.1-{label}-fixture'),
                                      ('node', f'v0.0.2-{label}-fixture')):
                    executable = directory / name
                    executable.write_text(
                        f'#!{sys.executable}\n'
                        'import json, os, sys\n'
                        f'with open({str(probes)!r}, "a") as stream:\n'
                        '    stream.write(json.dumps({"executable": sys.argv[0],\n'
                        f'        "isolated_env": dict(os.environ) == {suite_env!r},\n'
                        '        "arguments": sys.argv[1:]}) + "\\n")\n'
                        f'print({version!r})\n'
                    )
                    executable.chmod(0o755)
            shutil.copy2(Path(__file__).with_name('benchmark.py'), scripts / 'benchmark.py')
            (scripts / 'run_local_tests.py').write_text(
                '"""Synthetic fixture timings only; never performance evidence."""\n'
                'import subprocess\n'
                'def platform_tasks(root):\n'
                '    return [{"name": "synthetic-runtime-fixture", "expected": None}]\n'
                f'def isolated_env(output): return {suite_env!r}\n'
                'def run_batch(tasks, *, workers, output, env):\n'
                f'    assert env == {suite_env!r}\n'
                '    versions = {name: subprocess.check_output([command, "--version"],\n'
                '        env=env, text=True, timeout=2).strip().removeprefix("Python ")\n'
                '        for name, command in (("python", "python3"), ("node", "node"))}\n'
                '    return {"passed": True, "seconds": 1.0, "workers": workers,\n'
                '        "timing_kind": "synthetic fixture; never performance evidence",\n'
                '        "tasks": [{"name": "synthetic-runtime-fixture", "counts": None,\n'
                '                   **versions}]}\n'
            )
            result = subprocess.run(
                [sys.executable, '-B', str(scripts / 'benchmark.py'),
                 '--baseline', str(root), '--candidate', str(root),
                 '--output', str(output)],
                cwd=root, env={'PATH': str(harness_bin), 'LC_ALL': 'C.UTF-8',
                               'HARNESS_ONLY': 'synthetic-harness-sentinel'},
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            current = json.loads((output / 'benchmark-current.json').read_text())
            self.assertTrue(current['complete'])
            invocation = output / 'benchmark-invocations' / current['run_id']
            self.assertEqual(Path(current['output']), invocation)
            metadata = json.loads((output / 'benchmark-results.json').read_text())
            self.assertEqual(metadata['run_id'], current['run_id'])
            self.assertEqual(metadata, json.loads((invocation / 'benchmark-results.json').read_text()))
            self.assertTrue(metadata['all_runs_passed'])
            rows = json.loads((output / 'benchmark-runs.json').read_text())
            self.assertEqual(rows, json.loads((invocation / 'benchmark-runs.json').read_text()))
            self.assertEqual([row['label'] for row in rows], [
                'warmup-baseline', 'warmup-candidate',
                'measured-1-baseline', 'measured-1-candidate',
                'measured-2-candidate', 'measured-2-baseline',
                'measured-3-baseline', 'measured-3-candidate',
                'ablation-helper-only', 'ablation-parallel-only',
            ])
            for row in rows:
                self.assertEqual(row['timing_kind'], 'synthetic fixture; never performance evidence')
                self.assertTrue(row['passed'])
            for mode, summary in metadata['summary'].items():
                times = [row['seconds'] for row in rows if row['mode'] == mode and row['measured']]
                self.assertEqual(summary, {'runs': len(times), 'seconds': times,
                                          'median_seconds': 1.0, 'min_seconds': 1.0, 'max_seconds': 1.0})
            for runtime, command, version in (('python', 'python3', '0.0.1-suite-fixture'),
                                              ('node', 'node', 'v0.0.2-suite-fixture')):
                with self.subTest(runtime=runtime):
                    self.assertTrue(all(row['tasks'][0][runtime] == version for row in rows))
                    self.assertEqual(metadata[runtime], version,
                                     'Runtime metadata must describe the isolated suites, not the harness')
                    self.assertEqual(metadata[runtime + '_executable'], str(suite_bin / command))
            self.assertEqual(metadata.get('harness_python'), platform.python_version())
            self.assertEqual(metadata.get('harness_python_executable'), sys.executable)
            calls = [json.loads(line) for line in probes.read_text().splitlines()]
            self.assertEqual(len(calls), 22)
            for call in calls:
                self.assertTrue(call['isolated_env'], call)
                self.assertEqual(call['arguments'], ['--version'])
                self.assertIn(call['executable'], [str(suite_bin / 'python3'), str(suite_bin / 'node')])
            self.assertNotIn('synthetic-harness-sentinel', (output / 'benchmark-results.json').read_text())

    def test_failed_and_interrupted_reruns_invalidate_success_and_preserve_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            scripts = root / 'scripts'
            scripts.mkdir()
            output = root / 'external-evidence'
            output.mkdir()
            shutil.copy2(Path(__file__).with_name('benchmark.py'), scripts / 'benchmark.py')
            previous = None
            invocation_ids = []
            for mode in ('failed', 'exception', 'interrupt'):
                with self.subTest(mode=mode):
                    failure = {
                        'failed': "return {'passed': False, 'seconds': 0, 'tasks': []}",
                        'exception': "raise RuntimeError('CONTROLLED-EXCEPTION')",
                        'interrupt': 'raise KeyboardInterrupt()',
                    }[mode]
                    (scripts / 'run_local_tests.py').write_text(
                        'def platform_tasks(root): return []\n'
                        'def isolated_env(output): return {}\n'
                        f'def run_batch(*args, **kwargs):\n    {failure}\n'
                    )
                    # A stale marker is deliberately seeded, not a claimed real run.
                    (output / 'benchmark-results.json').write_text('{"stale_success_fixture": true}\n')
                    result = subprocess.run(
                        [sys.executable, '-B', str(scripts / 'benchmark.py'),
                         '--baseline', str(root), '--candidate', str(root),
                         '--output', str(output)],
                        cwd=root, env={}, capture_output=True, text=True, timeout=5,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse((output / 'benchmark-results.json').exists(),
                                     'A failed rerun left the previous success looking current')
                    self.assertFalse((scripts / 'benchmark-current.json').exists(),
                                     'Evidence must go to --output, not alongside source')
                    current = json.loads((output / 'benchmark-current.json').read_text())
                    self.assertFalse(current['complete'])
                    invocation_ids.append(current['run_id'])
                    self.assertTrue(Path(current['output']).is_dir())
                    if previous:
                        previous_dir, contents = previous
                        self.assertEqual({p.name: p.read_bytes() for p in previous_dir.iterdir()}, contents)
                    if mode == 'failed':
                        self.assertIn('failed or incomplete suite', result.stderr)
                        invocation = Path(current['output'])
                        self.assertTrue((invocation / 'benchmark-runs.json').is_file())
                        previous = invocation, {p.name: p.read_bytes() for p in invocation.iterdir()}
                    elif mode == 'exception':
                        self.assertIn('CONTROLLED-EXCEPTION', result.stderr)
                    else:
                        self.assertIn('KeyboardInterrupt', result.stderr)
            self.assertEqual(len(set(invocation_ids)), 3)


if __name__ == '__main__':
    unittest.main(verbosity=2)
