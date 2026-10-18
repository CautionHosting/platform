# Selected offline tests and matched speed measurements

This is an **opt-in local lane**, not a replacement for `make test`, browser tests,
Rust tests, container builds, or live deployment/attestation E2E tests. It invokes
six existing independent suites without starting, stopping, or reusing a service
stack. No production code or live-E2E orchestration is changed.

## Run

Requirements: Linux with procfs and pidfds, Python 3.11+, Bash, Node and npm, and
the normal utilities used by the selected tests. Python dependencies are stdlib
only. Install the frontend lockfile dependencies first:

```sh
(cd frontend && npm ci --ignore-scripts --no-audit --no-fund)
python3 -B -m unittest discover -s tests/local -p 'test_*.py' -v
out=$(mktemp -d /tmp/platform-local.XXXXXX)
python3 -B tests/local/run_local_tests.py --root . --workers 2 --output "$out"
```

`--workers 1` runs the same manifest sequentially. Two workers means **two
concurrent suites**, not a two-process or two-CPU ceiling: suites may create
children and Node has its own scheduler.

The runner supplies a fresh HOME under the output directory, a small allowlisted
environment, and PATH `/usr/local/bin:/usr/bin:/bin`; ensure the desired runtimes
are on that PATH. Inherited cloud credentials, CLI configuration environment
variables, and Node options are not propagated. This is test-process isolation,
**not** a security sandbox against arbitrary tests, filesystem access, network
access, or descendants that daemonize into a different session. Use only the
reviewed non-daemonizing manifest, in disposable source snapshots for benchmarks.

The fixed inventory deliberately fails closed on drift:

| Suite | Expected passing inventory |
| --- | ---: |
| Acceptance contracts | 13 Python tests |
| Platform-port shell contracts | 10 Python tests |
| Infrastructure bootstrap | 13 Python tests |
| Component preparation | 18 Python tests |
| Frontend | 164 Node tests |
| CLI installer | 11 shell scenarios |

Counts are in `platform_tasks()`; review and update them when these suites change.
A zero exit with missing/incomplete summaries or skipped tests is not success.
The new helper/runner/lifecycle/artifact regression tests run separately and are
not included in these timing comparisons.

Each suite retains a log and JSON result, including exit status, observed counts,
timeout, launch-error and cleanup evidence. Missing executables/directories fail
the batch without losing other result rows. A suite's default deadline is 180s,
followed by bounded TERM/KILL/reap cleanup. Ownership checks use Linux sessions,
process start identity, and pidfds; a successful leader leaving live same-session
descendants is also a failure and triggers cleanup. Regular-file logging avoids
inherited-pipe EOF hangs but does **not** impose an output-size limit. Keep output
directories private and disposable; do not run multiple invocations in the same
output directory. Cleanup covers suite deadlines and leader exit; forced
termination of the supervisor itself is outside this runner's cleanup contract.

## What is optimized

The ports-contract suite previously copied its entire unittest controller into
each fake external command. The extracted `tests/e2e/helpers/platform_ports_command.py`
contains the same dispatcher and required constants, without importing unittest
or its controller. Only these verified stdlib-only command doubles use Python
`-S`; the real test runner still uses normal Python initialization. The original
10 test methods/assertions and the product shell script are unchanged.

The second intervention schedules the six independent suites with two workers.
The combined result must not be attributed solely to the helper or concurrency.

## Reproduce a matched comparison

Choose baseline and candidate source revisions with the **same selected test
inventory**. The recorded PR comparison uses baseline
`ba1190ea17b0236e8833ac78d5e000e0057040a0` and this PR's helper change. From the PR
checkout after committing, create disposable archives; don't modify an operator's
checkout, caches, credentials, or running services:

```sh
base=ba1190ea17b0236e8833ac78d5e000e0057040a0
work=$(mktemp -d /tmp/platform-local-benchmark.XXXXXX)
mkdir "$work/baseline" "$work/candidate"
git archive "$base" | tar -x -C "$work/baseline"
git archive HEAD | tar -x -C "$work/candidate"
(cd "$work/baseline/frontend" && npm ci --ignore-scripts --no-audit --no-fund)
(cd "$work/candidate/frontend" && npm ci --ignore-scripts --no-audit --no-fund)
python3 -B tests/local/benchmark.py \
  --baseline "$work/baseline" --candidate "$work/candidate" \
  --source-commit "$base" --output "$work/evidence"
```

Keep other builds, dependency installs, regression/mutation runs and benchmarks
out of the measured window. The harness performs:

1. A full warm-up of each configuration (not measured).
2. Three full baseline/candidate pairs, alternating order, without overlap.
3. One helper-only and one parallel-only ablation (less certain than paired results).

The baseline uses the original helper and one worker; the candidate uses the
extracted helper and two workers. Both invoke the same Python/Bash commands and
`npm test` with identical environments. Dependency installation, setup, native
builds and regressions are excluded from the timed window.

Each invocation gets a unique directory. A new invocation invalidates the prior
top-level success summary immediately and writes an incomplete current marker.
Failed, exception-raising or interrupted runs cannot present old success as
current; prior invocation evidence remains available. Rows are persisted after
each batch. Successful completion records runtime versions and executable paths
resolved under the suites' isolated environment, separately from the harness's
Python interpreter. It also records the suite manifest, runner/benchmark hashes,
individual timings, ranges and medians. The `--source-commit` value is a
caller-supplied label; archive and inspect the actual source diff as well. Use a
fresh output directory for independently owned runs. Synthetic artifact fixtures
check provenance/completion behavior but are never performance evidence.

The observed environment used Node 18 with `--experimental-global-webcrypto` for
unit tests. Its Vite/Rolldown packages warn that Node 18 is unsupported. A passing
unit run is **not** evidence that a production frontend build works on Node 18;
use the project's supported Node version for builds. Rust compilation and live
E2E were not validated by this local speed comparison.

## Recorded comparison at `ba1190ea`

[Machine-readable measurements](evidence/benchmark-results.json) contain the
individual sample times, manifest, runtime versions and measured-script hashes.

| Configuration | Measured batches | Median | Range |
| --- | ---: | ---: | ---: |
| Original helper, one worker | 3 | 54.30s | 53.60–54.38s |
| Extracted helper, two workers | 3 | 23.24s | 22.94–23.59s |
| Extracted helper, one worker | 1 | 38.81s | 38.81–38.81s |
| Original helper, two workers | 1 | 38.58s | 38.58–38.58s |

The combined candidate is **2.34× faster**, a
**57.19% wall-time reduction**, across three
alternating full-batch pairs. Both warm-ups and all eight measured/ablation
batches passed: **218 tests plus 11 installer scenarios per batch**, with no
skips or cleanup errors. The two single-run ablations are exploratory, not
equally precise estimates. Source snapshot fingerprints and measured-script
hashes were checked again after execution.

Separately, all **ten helper/runner/lifecycle/artifact regressions** passed.
These cover missing executables/cwds, nonzero exits, incomplete/skipped counts,
timeouts, signal/exit races, resistant descendants in separate process groups,
successful leaders leaving children, unrelated concurrent-suite survival,
failed/exception-raising/interrupted benchmark reruns, and successful artifact
consistency with deliberately different caller/suite runtime environments. The
runtime-provenance regression fails against the original benchmark for both
Python and Node, and passes after the fix; its synthetic timings are not used
above. The helper startup guard fails against the original implementation. The
original ten ports-test method ASTs and the relocated dispatcher AST are identical.

These are revision- and machine-specific warm local results. This fresh run
replaces the initial PR measurements after correcting runtime provenance, and
also supersedes the older 147-frontend-test experiment. No full-suite or cloud-E2E
speedup is claimed.
