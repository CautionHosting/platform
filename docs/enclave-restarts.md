# Enclave restart policy

An optional enclave-level block controls host supervision:

```hcl
enclave "default" {
  restart {
    policy        = "always"
    delay_seconds = 0
  }

  unit "default" {
    command = "/keymaker"
  }
}
```

Policies are `never`, `on-failure`, and `always`. Missing fields default to
`on-failure` and 10 seconds, including when the block is absent. Legacy Procfiles
use those defaults. Delay is an unsigned 32-bit number of whole seconds; zero is
valid. Unknown fields and policies, negative values, and fractional delays fail
configuration parsing. `never` ignores the delay.

On Nitro, `on-failure` observes the launcher and host management process. Guest
termination, including crashes and Keymaker selfnuke, can result in a successful
management-process exit. Services requiring replacement after any termination
must opt into `always`. This does not restart healthy enclaves periodically or
following ordinary HTTP requests. Explicit service stops and Platform destroy
operations do not trigger replacement.

The Nitro unit supervises the returned `ProcessID` using `Type=forking` and a
PID file under `/run/nitro-enclave`. It records the corresponding `EnclaveID` for
targeted shutdown. Startup failures are cleaned up through the service cgroup;
an already-terminated enclave is not a shutdown error. Ingress proxies keep
running across replacement. Debug console capture reconnects to the recorded ID
on each launch. The egress network service is unchanged.

If the first enclave launch fails, bootstrap logs a warning and still completes
ingress proxy and Caddy setup, so a later systemd retry can restore connectivity.
The service retains its failure status and selected restart policy; `never` does
not acquire retries. Unrelated setup failures still abort bootstrap. Completed
host setup does not mean the enclave is ready.

Systemd's start-rate limits and the existing two-second pre-start sleep remain.
Zero restart delay removes neither that sleep nor enclave boot time. For
Keymaker, its ten-second selfnuke deadline also remains. Requests during restart
can fail: there is no HTTP queue or automatic generation retry. Restarting a
Locksmith-backed application does not restore secrets; holders must unlock its
existing bundle again. Restart supervision is not proof of memory erasure.

## Rollout

Release compatible Platform and CLI configuration support before deploying an
application's new HCL. The default preserves the previous configured policy,
but correcting the supervised process changes failure detection.

User-data changes take effect on provisioned/replacement hosts. They do not patch
an existing host in place. Follow the managed/BYOC deployment replacement process
or explicitly update the host services. Do not treat local fake-Nitro tests as
live-Nitro acceptance.

## Validation

Run the configuration and deployment tests, using native build dependencies:

```bash
cargo test -p caution-config --lib
cargo test -p api deployment::tests
NITRO_TEST_ARTIFACTS=/tmp/nitro-restart-tests make test-nitro-restart
```

The last command requires Terraform, Bash, jq, and Python 3. It renders the actual
user-data template, checks shell syntax and units, and exercises the helpers with
a fake Nitro CLI. It also runs the remaining bootstrap with mocked host commands
to verify ingress/Caddy setup after an initial launch failure and continued
failure propagation from unrelated setup steps. It makes no AWS calls or host
service changes.

On Linux with a running user systemd manager, use the retained artifacts:

```bash
python3 tests/test_nitro_restart_systemd.py /tmp/nitro-restart-tests
```

This creates uniquely named, temporary user services and removes them afterward.
It checks clean/failed exits for all policies, explicit stop, proxy continuity,
console reattachment, and management-process cleanup after failed startup. The
proxy uses a sleeping process to isolate dependency behavior; this does not test
actual vsock connectivity.

On a disposable Nitro deployment, additionally verify:

1. Systemd `MainPID` matches `nitro-cli describe-enclaves` `ProcessID`.
2. `always`: a valid Keymaker generation returns its bundle, selfnuke terminates
   the enclave, and another generation succeeds through the same endpoint after
   replacement, without manually restarting proxies. Repeat several times.
3. Each replacement has a new enclave ID and console capture follows that ID.
4. `never`: enclave termination leaves the service stopped. `on-failure` retries
   a launcher/management-process failure but does not promise guest-crash recovery.
5. Explicit service stop/destroy does not relaunch. Targeted shutdown leaves any
   other enclave alone. An immediate launch/parsing failure leaves no daemon.

Do not automatically replay a generation POST after a timeout or lost response:
its outcome may already have taken effect.
