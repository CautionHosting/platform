# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
"""Opt-in runner tests against real PostgreSQL, never shared platform services.

RUN_MIGRATION_DOCKER_TESTS=1 python3 -m unittest discover -s tests \
    -p test_migration_runner_docker.py -v

Requires a locally available postgres:16-alpine image (override with
MIGRATION_POSTGRES_IMAGE). No pulls, host ports, host management, or shared
networks/volumes. All Docker writes target a UUID-named disposable fixture.
Tests can run in the tools image with a read-only source mount and Docker socket;
fixture files use docker cp rather than host-path bind mounts.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import time
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / 'utils/makefile-run-migrations.sh'
MIGRATIONS = ROOT / 'src/api/migrations'


@unittest.skipUnless(os.environ.get('RUN_MIGRATION_DOCKER_TESTS') == '1',
                     'opt-in real Docker/PostgreSQL integration')
class MigrationRunnerTests(unittest.TestCase):
    def setUp(self):
        self.container = 'platform-migrations-test-' + uuid.uuid4().hex[:16]
        self.addCleanup(self.cleanup)
        image = os.environ.get('MIGRATION_POSTGRES_IMAGE', 'postgres:16-alpine')
        self.docker('image', 'inspect', image)
        self.docker('run', '-d', '--pull=never', '--name', self.container,
                    '--label', 'caution.test=platform-migrations',
                    '--network', 'none', '--cpus', '2', '--memory', '512m',
                    '--mount', 'type=tmpfs,destination=/var/lib/postgresql/data',
                    '-e', 'POSTGRES_DB=caution', '-e', 'POSTGRES_USER=postgres',
                    '-e', 'POSTGRES_PASSWORD=synthetic-migration-fixture', image)
        print('fixture:', self.container, flush=True)
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            ready = self.docker('exec', self.container, 'pg_isready', '-h', '127.0.0.1',
                                '-U', 'postgres', '-d', 'caution', check=False)
            if ready.returncode == 0:
                break
            time.sleep(0.1)
        else:
            self.fail('disposable PostgreSQL did not become ready')
        state = json.loads(self.docker('inspect', self.container).stdout)[0]
        self.assertEqual(state['HostConfig']['NetworkMode'], 'none')
        self.assertFalse(state['HostConfig']['PortBindings'])
        self.assertFalse(any(m['Type'] == 'volume' for m in state['Mounts']))
        self.copy_files({'makefile-run-migrations.sh': RUNNER.read_bytes()})
        self.docker('exec', self.container, 'mkdir', '/migrations')

    def docker(self, *args, check=True, input=None, timeout=90):
        result = subprocess.run(['docker', *args], input=input, capture_output=True,
                                timeout=timeout)
        if check:
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        return result

    def cleanup(self):
        self.docker('rm', '-fv', self.container, check=False)
        result = self.docker('container', 'inspect', self.container, check=False)
        self.assertNotEqual(result.returncode, 0, 'fixture container survived cleanup')
        self.assertIn(b'No such', result.stderr)
        print('teardown verified:', self.container, flush=True)

    def copy_files(self, files):
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w') as tar:
            for name, data in files.items():
                if isinstance(data, str):
                    data = data.encode()
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                entry.mode = 0o755 if name.endswith('/psql') else 0o644
                tar.addfile(entry, io.BytesIO(data))
        self.docker('cp', '-', self.container + ':/', input=archive.getvalue())

    def migrations(self, files):
        self.copy_files({'migrations/' + name: data for name, data in files.items()})

    def run_migrations(self, *, env=None, check=True):
        args = ['exec', '-e', 'MIGRATION_DB_HOST=127.0.0.1']
        for name, value in (env or {}).items():
            args += ['-e', name + '=' + value]
        return self.docker(*args, self.container, 'sh', '/makefile-run-migrations.sh', check=check)

    def sql(self, query):
        return self.docker('exec', '-i', self.container, 'psql', '-X', '-At',
                           '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'caution',
                           input=query.encode()).stdout.decode().strip()

    def ledger(self):
        self.assertEqual(self.sql("SELECT to_regclass('public.caution_bootstrap_migrations') IS NOT NULL;"),
                         't', 'runner must create the shared migration ledger')
        rows = self.sql('SELECT filename, sha256 FROM caution_bootstrap_migrations ORDER BY filename;')
        return dict(line.split('|', 1) for line in rows.splitlines())

    def test_applies_once_and_records_original_file_sha256(self):
        sql = 'CREATE TABLE replay_probe (id integer); INSERT INTO replay_probe VALUES (1);\n'
        self.migrations({'001_probe.sql': sql})
        self.run_migrations()
        expected = {'001_probe.sql': hashlib.sha256(sql.encode()).hexdigest()}
        self.assertEqual(self.ledger(), expected)
        self.run_migrations()
        self.assertEqual(self.ledger(), expected)
        self.assertEqual(self.sql('SELECT count(*) FROM replay_probe;'), '1')

    def assert_control_filename_is_atomic(self, filename):
        # Fail before any recursive control-file include on the broken runner.
        sql = 'CREATE TABLE filename_probe (id integer); SELECT 1/0;'
        self.migrations({filename: sql})
        result = self.run_migrations(check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'division by zero', result.stderr)
        self.assertEqual(self.sql("SELECT to_regclass('public.filename_probe');"), '',
                         filename + ': failed migration DDL must roll back')
        self.assertEqual(self.ledger(), {})

        sql = 'CREATE TABLE filename_probe (id integer); INSERT INTO filename_probe VALUES (1);'
        self.migrations({filename: sql})
        self.run_migrations()
        expected = {filename: hashlib.sha256(sql.encode()).hexdigest()}
        self.assertEqual(self.ledger(), expected)
        self.run_migrations()
        self.assertEqual(self.ledger(), expected)
        self.assertEqual(self.sql('SELECT count(*) FROM filename_probe;'), '1')

    def test_run_sql_filename_is_atomic_and_replayable(self):
        self.assert_control_filename_is_atomic('run.sql')

    def test_steps_sql_filename_is_atomic_and_replayable(self):
        self.assert_control_filename_is_atomic('steps.sql')

    def test_failed_file_rolls_back_and_retry_resumes_after_applied_prefix(self):
        files = {
            '001_prefix.sql': 'CREATE TABLE prefix_probe (id integer); INSERT INTO prefix_probe VALUES (1);',
            '002_broken.sql': 'CREATE TABLE rollback_probe (id integer); SELECT 1/0;',
            '003_later.sql': 'CREATE TABLE later_probe (id integer);',
        }
        self.migrations(files)
        result = self.run_migrations(check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'division by zero', result.stderr)
        self.assertEqual(self.sql("SELECT to_regclass('public.rollback_probe');"), '',
                         'DDL from a failed SQL file must roll back')
        self.assertEqual(self.sql("SELECT to_regclass('public.later_probe');"), '')
        self.assertEqual(self.ledger(), {'001_prefix.sql': hashlib.sha256(files['001_prefix.sql'].encode()).hexdigest()})
        files['002_broken.sql'] = 'CREATE TABLE rollback_probe (id integer);'
        self.migrations({'002_broken.sql': files['002_broken.sql']})
        self.run_migrations()
        self.assertEqual(self.ledger(), {n: hashlib.sha256(sql.encode()).hexdigest() for n, sql in files.items()})
        self.assertEqual(self.sql('SELECT count(*) FROM prefix_probe;'), '1')
        self.assertEqual(self.sql("SELECT to_regclass('public.later_probe');"), 'later_probe')
        self.run_migrations()

    def test_history_changes_are_rejected_before_any_pending_sql(self):
        applied = 'CREATE TABLE applied_probe (id integer);'
        self.migrations({'002_applied.sql': applied})
        self.run_migrations()
        original = self.ledger()
        self.migrations({'001_pending.sql': 'CREATE TABLE must_not_run (id integer);'})
        for mutation in ('checksum', 'removed'):
            with self.subTest(mutation=mutation):
                if mutation == 'checksum':
                    self.migrations({'002_applied.sql': applied + '\n-- changed bytes\n'})
                else:
                    self.docker('exec', self.container, 'rm', '/migrations/002_applied.sql')
                result = self.run_migrations(check=False)
                self.assertNotEqual(result.returncode, 0, 'changed applied history must be rejected')
                self.assertIn(b'applied migration history differs', result.stderr)
                self.assertEqual(self.sql("SELECT to_regclass('public.must_not_run');"), '')
                self.assertEqual(self.ledger(), original)
        self.migrations({'002_applied.sql': applied})
        self.run_migrations()
        self.assertEqual(self.sql("SELECT to_regclass('public.must_not_run');"), 'must_not_run')

    def test_real_migrations_recover_from_051_ledger_failure_and_rerun(self):
        files = {p.name: p.read_bytes() for p in MIGRATIONS.glob('*.sql')}
        enum_file = '051_managed_app_endpoints.sql'
        expected = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
        self.assertEqual(expected[enum_file],
                         'ead9734cb5cda9d25f68e9781d0b470273225e87c617199d88f7666b2a1ab84d')
        self.migrations(files)
        # The existing infrastructure ledger has exactly these two columns.
        self.sql("CREATE TABLE caution_bootstrap_migrations (filename text PRIMARY KEY, sha256 text NOT NULL); "
                 "CREATE FUNCTION reject_enum_migration() RETURNS trigger LANGUAGE plpgsql AS $$ "
                 "BEGIN IF NEW.filename = '051_managed_app_endpoints.sql' THEN "
                 "RAISE EXCEPTION 'fixture migration 051 ledger failure'; END IF; RETURN NEW; END $$; "
                 "CREATE TRIGGER reject_enum_migration BEFORE INSERT ON caution_bootstrap_migrations "
                 "FOR EACH ROW EXECUTE FUNCTION reject_enum_migration();")
        result = self.run_migrations(check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'fixture migration 051 ledger failure', result.stderr)
        self.assertEqual(self.sql("SELECT count(*) FROM pg_enum e JOIN pg_type t ON t.oid=e.enumtypid "
                                  "WHERE t.typname='resource_state' AND e.enumlabel='terminating';"), '1')
        columns = ("SELECT count(*) FROM information_schema.columns WHERE table_schema='public' "
                   "AND table_name='compute_resources' AND column_name IN "
                   "('dns_status','dns_error','dns_change_id','dns_release_not_before');")
        self.assertEqual(self.sql(columns), '0')
        self.assertEqual(self.sql("SELECT to_regclass('public.idx_compute_resources_dns_reconcile');"), '')
        self.assertEqual(self.ledger(), {name: checksum for name, checksum in expected.items() if name < enum_file})
        self.sql('DROP TRIGGER reject_enum_migration ON caution_bootstrap_migrations; DROP FUNCTION reject_enum_migration();')
        self.run_migrations()
        self.assertEqual(self.sql(columns), '4')
        self.assertEqual(self.sql("SELECT to_regclass('public.idx_compute_resources_dns_reconcile') IS NOT NULL;"), 't')
        self.assertEqual(self.ledger(), expected)
        self.run_migrations()
        self.assertEqual(self.ledger(), expected)
        print('real repository migrations applied and replayed:', len(expected), flush=True)

    def test_modified_051_has_no_nontransactional_exception(self):
        filename = '051_managed_app_endpoints.sql'
        self.sql("CREATE TYPE resource_state AS ENUM ('pending'); "
                 "CREATE TABLE compute_resources (state resource_state);")
        self.migrations({filename: (MIGRATIONS / filename).read_bytes() + b'\n-- not audited bytes\n'})
        result = self.run_migrations(check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'unsafe use of new value', result.stderr)
        self.assertEqual(self.ledger(), {})
        self.assertEqual(self.sql("SELECT count(*) FROM pg_enum e JOIN pg_type t ON t.oid=e.enumtypid "
                                  "WHERE t.typname='resource_state' AND e.enumlabel='terminating';"), '0')

    def test_concurrent_runners_serialize_through_database_session(self):
        self.migrations({'001_concurrent.sql':
                         'SELECT pg_sleep(3); CREATE TABLE concurrent_probe (id integer);'})
        command = ['docker', 'exec', '-e', 'MIGRATION_DB_HOST=127.0.0.1',
                   '-e', 'PGAPPNAME=migration-concurrency-first', self.container,
                   'sh', '/makefile-run-migrations.sh']
        processes = []
        try:
            first = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            processes.append(first)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if self.sql("SELECT count(*) FROM pg_stat_activity WHERE application_name="
                            "'migration-concurrency-first' AND wait_event='PgSleep';") == '1':
                    break
                time.sleep(0.05)
            else:
                self.fail('first runner did not enter migration sleep')
            command[5] = 'PGAPPNAME=migration-concurrency-second'
            second = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            processes.append(second)
            for process in processes:
                _, stderr = process.communicate(timeout=30)
                self.assertEqual(process.returncode, 0, stderr.decode())
            self.assertEqual(len(self.ledger()), 1)
            self.assertEqual(self.sql("SELECT to_regclass('public.concurrent_probe');"), 'concurrent_probe')
            self.assertEqual(self.sql("SELECT count(*) FROM pg_locks WHERE locktype='advisory';"), '0')
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=10)

    def test_legacy_infrastructure_single_file_adapter_remains_atomic(self):
        self.sql("CREATE TABLE caution_bootstrap_migrations (filename text PRIMARY KEY, sha256 text NOT NULL); "
                 "INSERT INTO caution_bootstrap_migrations VALUES ('001_previous.sql', repeat('a', 64));")
        self.docker('exec', self.container, 'mkdir', '/bootstrap')
        self.copy_files({'bootstrap/psql': '#!/bin/sh\nexec /usr/local/bin/psql --single-transaction "$@" '
                         '-v ON_ERROR_STOP=1 -c "$BOOTSTRAP_LEDGER_SQL"\n'})
        filename = '002_legacy.sql'
        sql = 'CREATE TABLE legacy_probe (id integer); SELECT 1/0;'
        for failing in (True, False):
            if not failing:
                sql = 'CREATE TABLE legacy_probe (id integer);'
            checksum = hashlib.sha256(sql.encode()).hexdigest()
            self.migrations({filename: sql})
            env = {'PATH': '/bootstrap:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                   'BOOTSTRAP_LEDGER_SQL': "INSERT INTO caution_bootstrap_migrations VALUES "
                   f"('{filename}', '{checksum}');"}
            result = self.run_migrations(env=env, check=False)
            if failing:
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b'division by zero', result.stderr)
                self.assertEqual(self.sql("SELECT to_regclass('public.legacy_probe');"), '')
                self.assertEqual(self.ledger(), {'001_previous.sql': 'a' * 64})
            else:
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual(self.ledger(), {'001_previous.sql': 'a' * 64, filename: checksum})

    def test_applied_bytes_are_the_bytes_hashed_before_waiting(self):
        files = {'001_wait.sql': 'SELECT pg_sleep(3);',
                 '002_bytes.sql': 'CREATE TABLE original_bytes_probe (id integer);'}
        self.migrations(files)
        command = ['docker', 'exec', '-e', 'MIGRATION_DB_HOST=127.0.0.1',
                   '-e', 'PGAPPNAME=migration-bytes-fixture', self.container,
                   'sh', '/makefile-run-migrations.sh']
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if self.sql("SELECT count(*) FROM pg_stat_activity WHERE application_name="
                            "'migration-bytes-fixture' AND wait_event='PgSleep';") == '1':
                    break
                time.sleep(0.05)
            else:
                self.fail('runner did not enter migration sleep')
            self.migrations({'002_bytes.sql': 'CREATE TABLE changed_bytes_probe (id integer);'})
            _, stderr = process.communicate(timeout=30)
            self.assertEqual(process.returncode, 0, stderr.decode())
            self.assertEqual(self.sql("SELECT to_regclass('public.original_bytes_probe');"), 'original_bytes_probe',
                             'ledger checksum must describe the SQL actually executed')
            self.assertEqual(self.sql("SELECT to_regclass('public.changed_bytes_probe');"), '')
            self.assertEqual(self.ledger(), {n: hashlib.sha256(sql.encode()).hexdigest() for n, sql in files.items()})
            self.assertNotEqual(self.run_migrations(check=False).returncode, 0)
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=10)


if __name__ == '__main__':
    unittest.main()
