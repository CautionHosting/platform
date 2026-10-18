#!/usr/bin/env python3
"""Real-process timeout regressions; fixtures are offline and always cleaned up."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

RUNNER = Path(os.environ.get('RUNNER_UNDER_TEST', Path(__file__).with_name('run_local_tests.py'))).resolve()


def identity(pid):
    try:
        fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        return {'pid': pid, 'start': fields[19], 'state': fields[0]}
    except FileNotFoundError:
        return None


def still_running(record):
    current = identity(record['pid'])
    return current is not None and current['start'] == record['start'] and current['state'] != 'Z'


def cleanup_record(record):
    if not still_running(record):
        return
    try:
        fd = os.pidfd_open(record['pid'])
    except OSError:
        if not still_running(record):
            return
        raise
    try:
        if still_running(record):
            signal.pidfd_send_signal(fd, signal.SIGKILL)
    except ProcessLookupError:
        pass
    finally:
        os.close(fd)


RECORD = """
def record(name):
    fields = Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()
    (root / name).write_text(json.dumps({'pid': os.getpid(), 'start': fields[19]}))
"""
CHILD = """
import json, os, signal, time
from pathlib import Path
root = Path(ROOT)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
""" + RECORD + "record('child.json')\ntime.sleep(60)\n"


class TimeoutCleanup(unittest.TestCase):
    def test_timeout_bounds_execution_and_kills_owned_descendants(self):
        for mode in ('redirected-output', 'separate-process-group'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                child = CHILD.replace('ROOT', repr(folder))
                leader = """
import json, os, signal, subprocess, sys, time
from pathlib import Path
root = Path(ROOT)
""".replace('ROOT', repr(folder)) + RECORD + "record('leader.json')\n"
                if mode == 'separate-process-group':
                    leader += "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                    options = ', process_group=0'
                else:
                    options = ', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL'
                leader += f"subprocess.Popen([sys.executable, '-c', {child!r}]{options})\n"
                leader += "while not (root/'child.json').exists(): time.sleep(0.01)\nprint('FIXTURE-READY', flush=True)\ntime.sleep(60)\n"
                driver = f"""
import importlib.util, json
from pathlib import Path
spec = importlib.util.spec_from_file_location('runner', {str(RUNNER)!r})
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
root = Path({folder!r})
task = {{'name': 'timeout', 'cwd': root, 'expected': None, 'timeout': 0.6,
         'command': [{sys.executable!r}, '-c', {leader!r}]}}
result = runner.run_batch([task], workers=1, output=root/'logs', env={{}})
(root/'result.json').write_text(json.dumps(result))
"""
                with (root/'driver.log').open('w') as log:
                    process = subprocess.Popen([sys.executable, '-B', '-c', driver],
                                               stdout=log, stderr=subprocess.STDOUT,
                                               start_new_session=True, env={})
                    driver_record = identity(process.pid)
                    started = time.monotonic()
                    try:
                        try:
                            process.wait(timeout=8)
                        except subprocess.TimeoutExpired:
                            self.fail('run_batch exceeded its bounded cleanup deadline; output collection is stuck')
                        self.assertEqual(process.returncode, 0, (root/'driver.log').read_text())
                        self.assertLess(time.monotonic()-started, 4)
                        result = json.loads((root/'result.json').read_text())
                        row = result['tasks'][0]
                        self.assertFalse(result['passed'])
                        self.assertTrue(row['timed_out'])
                        self.assertEqual(row['exit_code'], 124)
                        self.assertIn('FIXTURE-READY', Path(row['log']).read_text())
                        child_record = json.loads((root/'child.json').read_text())
                        self.assertFalse(still_running(child_record), 'timeout returned with a live SIGTERM-resistant descendant')
                    finally:
                        for name in ('child.json', 'leader.json'):
                            if (root/name).exists():
                                cleanup_record(json.loads((root/name).read_text()))
                        if driver_record:
                            cleanup_record(driver_record)
                        process.wait(timeout=2)

    def test_successful_leader_cleans_lingering_descendant_without_stopping_concurrent_suite(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            child = CHILD.replace('ROOT', repr(folder))
            leader = """
import json, os, subprocess, sys, time
from pathlib import Path
root = Path(ROOT)
""".replace('ROOT', repr(folder)) + RECORD + "record('leader.json')\n"
            leader += f"child = subprocess.Popen([sys.executable, '-c', {child!r}], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
            leader += """
while not (root/'child.json').exists() or not (root/'concurrent.json').exists():
    time.sleep(0.01)
assert os.getsid(child.pid) == os.getsid(0)
(root/'leader-ready').touch()
print('LEADER-SUCCEEDED', flush=True)
"""
            # The handshake proves the unrelated suite overlaps the leader; it
            # remains alive during descendant cleanup, in its own session.
            concurrent = """
import json, os, time
from pathlib import Path
root = Path(ROOT)
""".replace('ROOT', repr(folder)) + RECORD + "record('concurrent.json')\n"
            concurrent += """
while not (root/'leader-ready').exists():
    time.sleep(0.01)
time.sleep(0.6)
print('UNRELATED-COMPLETE', flush=True)
"""
            driver = f"""
import importlib.util, json
from pathlib import Path
spec = importlib.util.spec_from_file_location('runner', {str(RUNNER)!r})
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
root = Path({folder!r})
tasks = [
    {{'name': 'successful-leader', 'cwd': root, 'expected': None, 'timeout': 3,
      'command': [{sys.executable!r}, '-c', {leader!r}]}},
    {{'name': 'unrelated', 'cwd': root, 'expected': None, 'timeout': 3,
      'command': [{sys.executable!r}, '-c', {concurrent!r}]}},
]
result = runner.run_batch(tasks, workers=2, output=root/'logs', env={{}})
(root/'result.json').write_text(json.dumps(result))
"""
            with (root/'driver.log').open('w') as log:
                process = subprocess.Popen([sys.executable, '-B', '-c', driver],
                                           stdout=log, stderr=subprocess.STDOUT,
                                           start_new_session=True, env={})
                driver_record = identity(process.pid)
                started = time.monotonic()
                try:
                    try:
                        process.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        self.fail('run_batch exceeded its bounded cleanup deadline after successful leader exit')
                    self.assertEqual(process.returncode, 0, (root/'driver.log').read_text())
                    self.assertLess(time.monotonic()-started, 4)
                    result = json.loads((root/'result.json').read_text())
                    self.assertEqual(len(result['tasks']), 2)
                    row, unrelated = result['tasks']
                    self.assertEqual(row['name'], 'successful-leader')
                    self.assertEqual(row['exit_code'], 0)
                    self.assertFalse(row['timed_out'])
                    self.assertIsNone(row['launch_error'])
                    self.assertIn('LEADER-SUCCEEDED', Path(row['log']).read_text())
                    child_record = json.loads((root/'child.json').read_text())
                    self.assertFalse(still_running(child_record),
                                     'successful leader returned with a live SIGTERM-resistant descendant')
                    self.assertFalse(row['passed'])
                    self.assertEqual(row['cleanup_errors'], ['Live descendants remained after leader exit'])
                    self.assertFalse(result['passed'])
                    self.assertEqual(unrelated['name'], 'unrelated')
                    self.assertTrue(unrelated['passed'])
                    self.assertEqual(unrelated['exit_code'], 0)
                    self.assertFalse(unrelated['timed_out'])
                    self.assertEqual(unrelated['cleanup_errors'], [])
                    self.assertIsNone(unrelated['launch_error'])
                    self.assertIn('UNRELATED-COMPLETE', Path(unrelated['log']).read_text())
                finally:
                    # Stop producers before descendants, including on a mutant
                    # runner's failure, and verify fallback SIGKILL has completed.
                    records = [driver_record] if driver_record else []
                    if driver_record:
                        cleanup_record(driver_record)
                    for name in ('leader.json', 'concurrent.json', 'child.json'):
                        if (root/name).exists():
                            record = json.loads((root/name).read_text())
                            records.append(record)
                            cleanup_record(record)
                    process.wait(timeout=2)
                    deadline = time.monotonic() + 2
                    while any(still_running(record) for record in records) and time.monotonic() < deadline:
                        time.sleep(0.01)
                    for record in records:
                        self.assertFalse(still_running(record), f'fixture cleanup left a live process: {record}')


if __name__ == '__main__':
    unittest.main(verbosity=2)
