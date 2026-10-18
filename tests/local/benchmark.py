#!/usr/bin/env python3
"""Repeated matched local benchmark. Cloud E2E and Rust compilation excluded."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import uuid
from run_local_tests import platform_tasks, run_batch, isolated_env

SCRIPTS = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--baseline', type=Path, required=True)
parser.add_argument('--candidate', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--source-commit', default='unspecified')
args = parser.parse_args()
ROOT = args.output.resolve()
RUN_ID = uuid.uuid4().hex
OUTPUT = ROOT / 'benchmark-invocations' / RUN_ID
OUTPUT.mkdir(parents=True, exist_ok=False)
# Do not let an interrupted/failed new invocation look like an old success.
(ROOT / 'benchmark-results.json').unlink(missing_ok=True)
(ROOT / 'benchmark-runs.json').write_text('[]\n')
CURRENT = {'run_id': RUN_ID, 'output': str(OUTPUT), 'complete': False}
(ROOT / 'benchmark-current.json').write_text(json.dumps(CURRENT, indent=2) + '\n')
MODES = {
    'baseline': (args.baseline.resolve(), 1),
    'candidate': (args.candidate.resolve(), 2),
    'helper-only': (args.candidate.resolve(), 1),
    'parallel-only': (args.baseline.resolve(), 2),
}
rows = []


def run(mode, label, measured):
    source, workers = MODES[mode]
    output = OUTPUT / 'logs' / label
    result = run_batch(platform_tasks(source), workers=workers,
                       output=output, env=isolated_env(output))
    result.update(mode=mode, label=label, measured=measured)
    rows.append(result)
    (OUTPUT / 'benchmark-runs.json').write_text(json.dumps(rows, indent=2) + '\n')
    (ROOT / 'benchmark-runs.json').write_text(json.dumps(rows, indent=2) + '\n')
    print(json.dumps({'label': label, 'seconds': result['seconds'], 'passed': result['passed'],
                      'counts': {t['name']: t['counts'] for t in result['tasks']}}), flush=True)
    if not result['passed']:
        raise SystemExit('Benchmark invalid: failed or incomplete suite in ' + label)


# One complete warm-up per configuration; neither is included in statistics.
run('baseline', 'warmup-baseline', False)
run('candidate', 'warmup-candidate', False)
# Alternate pair order to reduce order/drift bias. No baseline/candidate overlap.
for pair in range(1, 4):
    order = ('baseline', 'candidate') if pair % 2 else ('candidate', 'baseline')
    for mode in order:
        run(mode, f'measured-{pair}-{mode}', True)
# Single-run ablations are informative, not equally precise estimates.
run('helper-only', 'ablation-helper-only', True)
run('parallel-only', 'ablation-parallel-only', True)
summary = {}
for mode in MODES:
    times = [r['seconds'] for r in rows if r['mode'] == mode and r['measured']]
    summary[mode] = {'runs': len(times), 'seconds': times,
                     'median_seconds': statistics.median(times),
                     'min_seconds': min(times), 'max_seconds': max(times)}
baseline = summary['baseline']['median_seconds']
candidate = summary['candidate']['median_seconds']
runtime_env = isolated_env(OUTPUT / 'runtime-metadata')
runtimes = {}
for name, command in (('python', 'python3'), ('node', 'node')):
    executable = shutil.which(command, path=runtime_env['PATH'])
    if executable is None:
        raise SystemExit('Benchmark invalid: runtime not found: ' + command)
    version = subprocess.check_output([executable, '--version'], env=runtime_env,
                                      stdin=subprocess.DEVNULL, text=True, timeout=5).strip()
    runtimes[name] = version.removeprefix('Python ') if name == 'python' else version
    runtimes[name + '_executable'] = executable
result = {'scope': 'Selected offline suites; not full make test or live E2E',
          'suite_manifest': {task['name']: task['expected'] for task in platform_tasks(args.candidate)},
          'run_id': RUN_ID,
          'runner_sha256': hashlib.sha256((SCRIPTS / 'run_local_tests.py').read_bytes()).hexdigest(),
          'benchmark_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
          'concurrency_scope': 'two concurrent suites, not a two-process or two-CPU ceiling',
          'source_commit': args.source_commit,
          **runtimes,
          'harness_python': platform.python_version(),
          'harness_python_executable': sys.executable,
          'node_options': '--experimental-global-webcrypto',
          'setup_and_dependency_install_excluded': True,
          'summary': summary, 'seconds_saved': baseline - candidate,
          'wall_clock_reduction_percent': (baseline - candidate) / baseline * 100,
          'speedup': baseline / candidate, 'all_runs_passed': all(r['passed'] for r in rows)}
(OUTPUT / 'benchmark-results.json').write_text(json.dumps(result, indent=2) + '\n')
(ROOT / 'benchmark-results.json').write_text(json.dumps(result, indent=2) + '\n')
CURRENT['complete'] = True
(ROOT / 'benchmark-current.json').write_text(json.dumps(CURRENT, indent=2) + '\n')
print(json.dumps(result, indent=2), flush=True)
