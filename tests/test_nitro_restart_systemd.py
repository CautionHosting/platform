#!/usr/bin/env python3
"""Linux-only integration check using isolated user services and a fake Nitro CLI.

First retain render artifacts with tests/test_nitro_restart.py, then run:
  python3 tests/test_nitro_restart_systemd.py /path/to/artifacts
No AWS, root, or existing service changes. Temporary units are removed on exit.
"""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import uuid

MOCK = '''#!/usr/bin/env python3
import json, os, pathlib, signal, subprocess, sys, time
state = pathlib.Path(os.environ["MOCK_STATE"])
live = state / "live.json"
args = sys.argv[1:]
if args[0] == "daemon":
    def finish(code):
        live.unlink(missing_ok=True)
        sys.exit(code)
    signal.signal(signal.SIGUSR1, lambda *_: finish(0))
    signal.signal(signal.SIGUSR2, lambda *_: finish(2))
    signal.signal(signal.SIGTERM, lambda *_: finish(0))
    (state / "ready").write_text(str(os.getpid()))
    while True:
        signal.pause()
elif args[0] == "run-enclave":
    (state / "ready").unlink(missing_ok=True)
    daemon = subprocess.Popen([sys.executable, __file__, "daemon"],
                              start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(200):
        if (state / "ready").exists():
            break
        time.sleep(.01)
    result = {"EnclaveID": "i-test-enc" + str(daemon.pid), "ProcessID": daemon.pid}
    live.write_text(json.dumps(result))
    (state / "last-pid").write_text(str(daemon.pid))
    print("bad JSON" if (state / "bad-launch").exists() else json.dumps(result))
elif args[0] == "describe-enclaves":
    print("[" + live.read_text() + "]" if live.exists() else "[]")
elif args[0] == "terminate-enclave":
    assert args[1] == "--enclave-id" and len(args) == 3
    if live.exists():
        item = json.loads(live.read_text())
        assert args[2] == item["EnclaveID"]
        os.kill(item["ProcessID"], signal.SIGTERM)
        for _ in range(200):
            if not live.exists():
                break
            time.sleep(.01)
elif args[0] == "console":
    with (state / "console-ids").open("a") as out:
        out.write(args[2] + "\\n")
    while live.exists() and json.loads(live.read_text())["EnclaveID"] == args[2]:
        time.sleep(.05)
else:
    sys.exit(3)
'''


def run(*args, check=True):
    result = subprocess.run(args, text=True, capture_output=True, timeout=20)
    if check and result.returncode:
        raise AssertionError(" ".join(args) + "\n" + result.stdout + result.stderr)
    return result


def systemctl(*args, check=True):
    return run("systemctl", "--user", *args, check=check)


def wait_for(predicate, description, seconds=12):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.1)
    raise AssertionError("Timed out: " + description)


def unit_block(text, name):
    marker = "/etc/systemd/system/" + name + " <<"
    tail = text.split(marker, 1)[1]
    return tail.split("\n", 1)[1].split("\nEOF", 1)[0] + "\n"


def exercise(artifacts, policy, failure, bad_launch=False):
    prefix = "caution-restart-test-" + uuid.uuid4().hex[:10]
    names = {"nitro-enclave.service": prefix + ".service",
             "nitro-enclave-console.service": prefix + "-console.service",
             "nitro-enclaves-allocator.service": prefix + "-allocator.service",
             "vsock-proxy-http.service": prefix + "-proxy.service"}
    main = names["nitro-enclave.service"]
    proxy = names["vsock-proxy-http.service"]
    console = names["nitro-enclave-console.service"]
    runtime_root = Path(os.environ.get("XDG_RUNTIME_DIR", "/run/user/" + str(os.getuid())))
    runtime = runtime_root / prefix
    linked = []
    with tempfile.TemporaryDirectory(prefix=prefix) as temporary:
        directory = Path(temporary)
        text = (artifacts / "user-data.sh").read_text()
        for name in ["start-nitro-enclave", "stop-nitro-enclave", "capture-enclave-console.sh"]:
            source = (artifacts / name).read_text()
            source = source.replace("/run/nitro-enclave/enclave.id", str(runtime / "enclave.id"))
            source = source.replace("LOG_FILE=/var/log/nitro_enclaves/enclave-console.log", "LOG_FILE=" + str(directory / "console.log"))
            source = source.replace("mkdir -p /var/log/nitro_enclaves", ":")
            (directory / name).write_text(source)
            (directory / name).chmod(0o755)
        (directory / "nitro-cli").write_text(MOCK)
        (directory / "nitro-cli").chmod(0o755)
        if bad_launch:
            (directory / "bad-launch").touch()
        try:
            for original, name in names.items():
                if original == "nitro-enclaves-allocator.service":
                    body = "[Service]\nType=oneshot\nExecStart=/usr/bin/true\nRemainAfterExit=yes\n"
                else:
                    body = unit_block(text, original)
                    for old, replacement in names.items():
                        body = body.replace(old, replacement)
                    body = body.replace("/usr/local/bin/", str(directory) + "/")
                    body = body.replace("RuntimeDirectory=nitro-enclave", "RuntimeDirectory=" + prefix)
                    body = body.replace("/run/nitro-enclave/enclave.pid", str(runtime / "enclave.pid"))
                    body = body.replace("/usr/bin/systemctl --no-block", "/usr/bin/systemctl --user --no-block")
                    if original == "nitro-enclave.service":
                        body = body.replace("Restart=always", "Restart=" + policy)
                    if original == "vsock-proxy-http.service":
                        # Test actual dependency behavior without using a host network port.
                        body = "\n".join("ExecStart=/usr/bin/sleep infinity" if line.startswith("ExecStart=") else line for line in body.splitlines()) + "\n"
                    body = body.replace("[Service]\n", "[Service]\nEnvironment=PATH=" + str(directory) + ":/usr/bin:/bin\nEnvironment=MOCK_STATE=" + str(directory) + "\n")
                path = directory / name
                path.write_text(body)
                systemctl("link", "--runtime", str(path))
                linked.append(name)
            run("systemd-analyze", "--user", "verify", *[str(directory / name) for name in names.values()])
            result = systemctl("start", main, check=not bad_launch)
            if bad_launch:
                assert result.returncode != 0
                pid = int((directory / "last-pid").read_text())
                wait_for(lambda: not Path("/proc/" + str(pid)).exists(), "failed startup cgroup cleanup")
                print("PASS failed startup leaves no management daemon", flush=True)
                return
            systemctl("start", proxy)
            pid = int(systemctl("show", main, "--property=MainPID", "--value").stdout)
            assert pid == int((runtime / "enclave.pid").read_text())
            proxy_pid = systemctl("show", proxy, "--property=MainPID", "--value").stdout
            wait_for(lambda: (directory / "console-ids").exists(), "initial console attachment")
            os.kill(pid, signal.SIGUSR2 if failure else signal.SIGUSR1)
            should_restart = policy == "always" or (policy == "on-failure" and failure)
            if should_restart:
                def replaced():
                    live = directory / "live.json"
                    return live.exists() and json.loads(live.read_text())["ProcessID"] != pid and systemctl("is-active", main, check=False).returncode == 0
                wait_for(replaced, "automatic replacement")
                assert int(systemctl("show", main, "--property=NRestarts", "--value").stdout) == 1
                wait_for(lambda: len((directory / "console-ids").read_text().splitlines()) >= 2, "replacement console attachment")
                assert len(set((directory / "console-ids").read_text().splitlines())) == 2
            else:
                wait_for(lambda: systemctl("show", main, "--property=ActiveState", "--value").stdout.strip() in ("inactive", "failed"), "stays stopped")
                time.sleep(.4)
                assert int(systemctl("show", main, "--property=NRestarts", "--value").stdout) == 0
            assert systemctl("is-active", proxy).returncode == 0
            assert systemctl("show", proxy, "--property=MainPID", "--value").stdout == proxy_pid
            systemctl("stop", main)
            time.sleep(.4)
            assert systemctl("show", main, "--property=ActiveState", "--value").stdout.strip() in ("inactive", "failed")
            assert not (directory / "live.json").exists()
            assert systemctl("is-active", console, check=False).returncode != 0
            assert systemctl("is-active", proxy).returncode == 0
            print("PASS " + policy + (" failed" if failure else " clean") + " exit, proxy continuity, console lifecycle, explicit stop", flush=True)
        except Exception:
            print(systemctl("status", *linked, "--no-pager", check=False).stdout, file=sys.stderr)
            raise
        finally:
            systemctl("stop", *linked, check=False)
            systemctl("reset-failed", *linked, check=False)
            for name in linked:
                (runtime_root / "systemd/user" / name).unlink(missing_ok=True)
            systemctl("daemon-reload")


if __name__ == "__main__":
    artifacts = Path(sys.argv[1]).resolve()
    systemctl("is-system-running")
    for policy in ["no", "on-failure", "always"]:
        for failure in [False, True]:
            exercise(artifacts, policy, failure)
    exercise(artifacts, "no", False, bad_launch=True)
