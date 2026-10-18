#!/usr/bin/env python3
"""Run explicitly independent offline suites; never invoke stack lifecycle targets."""
import concurrent.futures
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time


def check_counts(text, expected):
    if expected is None:
        return True, None
    kind, count = expected['kind'], expected['tests']
    if kind == 'python':
        matches = re.findall(r'^Ran (\d+) tests? in ', text, re.MULTILINE)
        valid = matches == [str(count)] and '\nOK\n' in text and 'skipped=' not in text and 'FAILED' not in text
        return valid, {'kind': kind, 'tests': int(matches[0]) if len(matches) == 1 else None}
    if kind == 'node':
        counts = {key: int(value) for key, value in re.findall(r'^# (tests|pass|fail|cancelled|skipped|todo) (\d+)$', text, re.MULTILINE)}
        valid = counts == {'tests': count, 'pass': count, 'fail': 0, 'cancelled': 0, 'skipped': 0, 'todo': 0}
        return valid, {'kind': kind, **counts}
    if kind == 'installer':
        cases = len(re.findall(r'^Testing .+\.\.\.$', text, re.MULTILINE))
        return cases == count and 'CLI installer tests passed\n' in text, {'kind': kind, 'tests': cases}
    raise ValueError('Unknown expected result kind: ' + kind)


def session_members(session_id):
    """Live members of a run-owned Linux session, including other process groups.

    The selected offline suites must not daemonize into unrelated sessions. This
    is lifecycle supervision for these known tests, not a hostile-code sandbox.
    """
    members = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            fields = (entry / 'stat').read_text().rsplit(')', 1)[1].split()
        except (OSError, IndexError):
            continue
        if int(fields[3]) == session_id and fields[0] != 'Z':
            members.append((int(entry.name), fields[19]))
    return members


def signal_session(session_id, sig):
    errors = []
    for pid, start in session_members(session_id):
        fd = None
        try:
            fd = os.pidfd_open(pid)
            # Recheck after opening: never signal a recycled PID.
            fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
            if int(fields[3]) == session_id and fields[19] == start:
                signal.pidfd_send_signal(fd, sig)
        except (ProcessLookupError, FileNotFoundError):
            pass
        except OSError as error:
            if (pid, start) in session_members(session_id):
                errors.append(f'Cannot signal owned PID {pid}: {error}')
        finally:
            if fd is not None:
                os.close(fd)
    return errors


def stop_session(process):
    """TERM then KILL owned session members, independent of leader/pipe exit."""
    errors = signal_session(process.pid, signal.SIGTERM)
    grace = time.monotonic() + 0.25
    while session_members(process.pid) and time.monotonic() < grace:
        time.sleep(0.01)
    # Always escalate surviving members, even when the leader has already exited.
    deadline = time.monotonic() + 1
    while True:
        errors.extend(signal_session(process.pid, signal.SIGKILL))
        if not session_members(process.pid):
            break
        if time.monotonic() >= deadline:
            errors.append('Owned session still has live processes after SIGKILL')
            break
        time.sleep(0.01)
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        errors.append('Leader did not exit within the bounded reap deadline')
    return errors


def run_batch(tasks, *, workers, output, env):
    if not Path('/proc/self/stat').is_file() or not hasattr(os, 'pidfd_open'):
        raise RuntimeError('This scoped runner requires Linux procfs and pidfd support')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)

    def run_task(task):
        started = time.perf_counter()
        log = output / (task['name'] + '.log')
        timed_out = False
        cleanup_errors = []
        launch_error = None
        # A regular file cannot be held open as an undrainable inherited pipe.
        with log.open('w') as stream:
            try:
                process = subprocess.Popen(task['command'], cwd=task['cwd'], env=env,
                                           stdout=stream, stderr=subprocess.STDOUT,
                                           stdin=subprocess.DEVNULL, start_new_session=True)
            except OSError as error:
                launch_error = f'{type(error).__name__}: {error}'
                stream.write('LAUNCH ERROR: ' + launch_error + '\n')
                exit_code = 125
            else:
                try:
                    process.wait(timeout=task.get('timeout', 180))
                except subprocess.TimeoutExpired:
                    timed_out = True
                    cleanup_errors = stop_session(process)
                else:
                    if session_members(process.pid):
                        cleanup_errors = ['Live descendants remained after leader exit']
                        cleanup_errors.extend(stop_session(process))
                exit_code = 124 if timed_out else process.returncode
        text = log.read_text(errors='replace')
        counts_ok, counts = check_counts(text, task['expected'])
        row = {'name': task['name'], 'seconds': time.perf_counter() - started,
               'exit_code': exit_code, 'passed': exit_code == 0 and counts_ok and not cleanup_errors,
               'counts': counts, 'timed_out': timed_out,
               'cleanup_errors': cleanup_errors, 'launch_error': launch_error,
               'log': str(log)}
        (output / (task['name'] + '.json')).write_text(json.dumps(row, indent=2) + '\n')
        return row

    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(run_task, tasks))
    return {'seconds': time.perf_counter() - started, 'workers': workers,
            'passed': all(row['passed'] for row in results), 'tasks': results}


def platform_tasks(root):
    root = Path(root).resolve()
    # Fail closed when the selected inventory changes; review counts with tests.
    definitions = [
        ('acceptance', root, ['python3', '-B', 'tests/e2e/test_acceptance_contracts.py', '-v'], 'python', 13),
        ('ports', root, ['python3', '-B', 'tests/e2e/test_platform_ports_contracts.py', '-v'], 'python', 10),
        ('bootstrap', root, ['python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_infra_bootstrap.py', '-v'], 'python', 13),
        ('components', root, ['python3', '-B', 'tests/test_prepare_components.py', '-v'], 'python', 18),
        ('frontend', root / 'frontend', ['npm', 'test'], 'node', 164),
        ('cli-installer', root, ['bash', 'tests/test_cli_install.sh'], 'installer', 11),
    ]
    return [{'name': name, 'cwd': cwd, 'command': command, 'expected': {'kind': kind, 'tests': tests}}
            for name, cwd, command, kind, tests in definitions]


def isolated_env(output):
    home = Path(output).resolve() / 'home'
    home.mkdir(parents=True, exist_ok=True)
    return {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(home),
            'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1',
            'NODE_OPTIONS': '--experimental-global-webcrypto'}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--workers', type=int, choices=(1, 2), default=2)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = run_batch(platform_tasks(args.root), workers=args.workers,
                       output=args.output, env=isolated_env(args.output))
    (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['passed'] else 1)
