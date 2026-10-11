#!/usr/bin/env python3
"""Exercise production native approval cleanup in an isolated PTY, without USB."""
import errno
import os
import pty
import select
import signal
import sys
import termios
import time

binary = os.path.abspath(sys.argv[1])
driver = "share_release::native_approval::tests::terminal_driver"
scenarios = {
    "success": b"discard\x1565432x\x7f1\n",
    "selection_success": b"2\x7f1\n",
    "timeout": b"654",
    "disconnect": b"654",
    "selection_cancel": b"",
    "ctrl_c": b"654\x03",
    "sigint": b"654",
    "eof": b"\x04",
}

for scenario, typed in scenarios.items():
    pid, fd = pty.fork()
    if pid == 0:
        os.environ["CAUTION_NATIVE_APPROVAL_TEST"] = scenario
        os.execv(binary, [binary, driver, "--exact", "--ignored", "--nocapture"])
    original = termios.tcgetattr(fd)
    output = bytearray()
    sent = False
    deadline = time.monotonic() + 12
    try:
        while time.monotonic() < deadline:
            if select.select([fd], [], [], 0.05)[0]:
                try:
                    chunk = os.read(fd, 8192)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                if not chunk:
                    break
                output.extend(chunk)
            prompt = b"Selection: " if scenario.startswith("selection") else b"PIN: "
            if not sent and prompt in output:
                # No delay: catch a prompt being printed before echo is disabled.
                assert not termios.tcgetattr(fd)[3] & termios.ECHO, output
                os.write(fd, typed)
                if scenario == "sigint":
                    os.kill(pid, signal.SIGINT)
                sent = True
        else:
            raise AssertionError("native approval driver hung: " + scenario)
        restored = termios.tcgetattr(fd)
        _, status = os.waitpid(pid, 0)
        pid = None
        success = scenario in ("success", "selection_success")
        assert os.waitstatus_to_exitcode(status) == (0 if success else 1), output
        assert sent and b"Worker finished; terminal restored" in output, output
        assert (b"Submission reached" in output) == success, output
        assert b"Existing release summary" in output, output
        assert b"654" not in output and b"discard" not in output, "PIN was echoed"
        assert original == restored, "terminal attributes not restored: " + scenario
        print(scenario + ": worker joined, terminal restored, submission checked")
    finally:
        if pid is not None:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        termios.tcsetattr(fd, termios.TCSANOW, original)
        os.close(fd)
