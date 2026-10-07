"""Real Linux TAP regression tests (stdio transport, not vsock/Nitro).

Requires iproute2, /dev/net/tun, and unprivileged user/network namespaces:
    unshare --user --map-root-user --net python3 tests/test_tap_framer.py /absolute/path/to/tap-framer
"""

import contextlib
import fcntl
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest


TIMEOUT = 3
TAP = "framer-test0"
LOCAL_IP, PEER_IP = "198.18.0.1", "198.18.0.2"
LOCAL_MAC, PEER_MAC = "02:00:00:00:00:01", "02:00:00:00:00:02"
LOCAL_PORT, PEER_PORT = 24000, 24001


class TapFramerTests(unittest.TestCase):
    binary = ""

    @classmethod
    def setUpClass(cls):
        if not cls.binary:
            raise unittest.SkipTest("run this file explicitly with a tap-framer binary")
        mapping = Path("/proc/self/uid_map").read_text().split()
        if len(mapping) != 3 or mapping[0] != "0" or mapping[2] != "1" or os.geteuid() != 0:
            raise RuntimeError("requires unshare --user --map-root-user --net")
        with open("/proc/self/ns/net", "rb") as net:
            owner = fcntl.ioctl(net, 0xb701)  # NS_GET_USERNS: the network namespace's owner.
        try:
            if not os.path.samestat(os.fstat(owner), os.stat("/proc/self/ns/user")):
                raise RuntimeError("refusing a network namespace not owned by this user namespace")
        finally:
            os.close(owner)
        if {name for _, name in socket.if_nameindex()} != {"lo"}:
            raise RuntimeError("requires a fresh network namespace with only lo")
        if not Path(cls.binary).is_file() or not os.access(cls.binary, os.X_OK):
            raise RuntimeError(f"helper is not executable: {cls.binary}")

    @contextlib.contextmanager
    def helper(self, socket_stdio=False):
        with tempfile.TemporaryFile() as errors, socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM
        ) as self.udp:
            self.errors = errors
            if socket_stdio:
                peer, child = socket.socketpair()
                try:
                    child.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
                    peer.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
                    self.proc = subprocess.Popen(
                        [self.binary, TAP], stdin=child, stdout=child, stderr=errors,
                    )
                    stdin, stdout = peer.makefile("wb", buffering=0), peer.makefile("rb", buffering=0)
                finally:
                    child.close()
                    peer.close()
            else:
                self.proc = subprocess.Popen(
                    [self.binary, TAP], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=errors, bufsize=0,
                )
                stdin, stdout = self.proc.stdin, self.proc.stdout
            assert stdin is not None and stdout is not None
            self.stdin, self.stdout = stdin, stdout
            try:
                for pipe in (self.stdin, self.stdout):
                    if not socket_stdio:
                        fcntl.fcntl(pipe, fcntl.F_SETPIPE_SZ, 4096)
                    os.set_blocking(pipe.fileno(), False)
                deadline = time.monotonic() + TIMEOUT
                while TAP not in {name for _, name in socket.if_nameindex()}:
                    self.assertIsNone(self.proc.poll(), self.diagnostics())
                    self.assertLess(time.monotonic(), deadline, "helper did not create TAP")
                    time.sleep(0.01)
                for args in (
                    ["link", "set", TAP, "address", LOCAL_MAC, "mtu", "1500", "up"],
                    ["addr", "add", f"{LOCAL_IP}/24", "dev", TAP],
                    ["neigh", "replace", PEER_IP, "lladdr", PEER_MAC,
                     "nud", "permanent", "dev", TAP],
                ):
                    subprocess.run(["ip", *args], check=True, capture_output=True, timeout=TIMEOUT)
                self.udp.bind((LOCAL_IP, LOCAL_PORT))
                self.udp.settimeout(TIMEOUT)
                yield
            finally:
                if self.proc.poll() is None:
                    self.proc.kill()
                self.proc.wait(timeout=TIMEOUT)
                self.stdin.close()
                self.stdout.close()

    def diagnostics(self):
        self.errors.seek(0)
        return self.errors.read().decode(errors="replace")

    def write_chunk(self, data):
        self.assertLessEqual(len(data), 4096, "each chunk must fit an atomic pipe write")
        self.assertTrue(select.select([], [self.stdin], [], TIMEOUT)[1], "stdin stalled")
        self.assertEqual(os.write(self.stdin.fileno(), data), len(data))

    def read_exact(self, length, deadline):
        data = bytearray()
        while len(data) < length:
            remaining = deadline - time.monotonic()
            self.assertGreater(remaining, 0, "stdout record timed out")
            self.assertTrue(select.select([self.stdout], [], [], remaining)[0], "stdout stalled")
            chunk = os.read(self.stdout.fileno(), length - len(data))
            self.assertTrue(chunk, f"unexpected stdout EOF: {self.diagnostics()}")
            data.extend(chunk)
        return bytes(data)

    def record(self, payload):
        udp = struct.pack("!HHHH", PEER_PORT, LOCAL_PORT, 8 + len(payload), 0) + payload
        ip = struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
            socket.inet_aton(PEER_IP), socket.inet_aton(LOCAL_IP),
        )
        checksum = sum(struct.unpack("!10H", ip))
        while checksum >> 16:
            checksum = (checksum & 0xffff) + (checksum >> 16)
        ip = ip[:10] + struct.pack("!H", (~checksum) & 0xffff) + ip[12:]
        frame = (
            bytes.fromhex(LOCAL_MAC.replace(":", ""))
            + bytes.fromhex(PEER_MAC.replace(":", "")) + b"\x08\x00" + ip + udp
        ).ljust(60, b"\0")
        return struct.pack("!I", len(frame)) + frame

    def receive_udp(self, payload):
        self.assertEqual(self.udp.recvfrom(65535), (payload, (PEER_IP, PEER_PORT)))

    def receive_frame(self, payload):
        deadline = time.monotonic() + TIMEOUT
        while True:
            length = struct.unpack("!I", self.read_exact(4, deadline))[0]
            self.assertGreaterEqual(length, 14)
            self.assertLessEqual(length, 1518)
            frame = self.read_exact(length, deadline)
            if frame[12:14] != b"\x08\x00":
                continue  # Ignore kernel IPv6 discovery, not IPv4 test traffic.
            self.assertEqual(frame[:6], bytes.fromhex(PEER_MAC.replace(":", "")))
            self.assertEqual(frame[6:12], bytes.fromhex(LOCAL_MAC.replace(":", "")))
            ip = frame[14:]
            self.assertEqual(ip[0] >> 4, 4)
            self.assertEqual(ip[9], 17)
            self.assertEqual(ip[12:20], socket.inet_aton(LOCAL_IP) + socket.inet_aton(PEER_IP))
            self.assertEqual(struct.unpack("!H", ip[2:4])[0], len(ip))
            udp = ip[(ip[0] & 15) * 4:]
            self.assertEqual(struct.unpack("!HHH", udp[:6]), (LOCAL_PORT, PEER_PORT, len(udp)))
            self.assertEqual(udp[8:], payload)
            return

    def test_queued_frame_is_accepted_before_external_link_setup(self):
        result = subprocess.run(
            [self.binary, TAP], input=self.record(b"queued-before-link-setup"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=TIMEOUT,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))

    def test_coalesced_burst_delivers_each_udp_datagram(self):
        with self.helper():
            payloads = [bytes([i]) * size for i, size in enumerate((18, 61, 503, 1472))]
            self.write_chunk(b"".join(self.record(payload) for payload in payloads))
            for payload in payloads:
                self.receive_udp(payload)

    def test_split_records_allow_outbound_progress(self):
        with self.helper():
            payloads = [b"fragmented-first" * 5, b"fragmented-second" * 9]
            records = [self.record(payload) for payload in payloads]
            wire = b"".join(records)
            cuts = [0, 1, 3, 4, 5, 17, len(records[0]) - 1,
                    len(records[0]) + 2, len(records[0]) + 4, len(wire) - 1, len(wire)]
            for i, (start, end) in enumerate(zip(cuts, cuts[1:])):
                self.write_chunk(wire[start:end])
                outbound = bytes([i]) * (32 + i * 97)
                self.udp.sendto(outbound, (PEER_IP, PEER_PORT))
                self.receive_frame(outbound)
            for payload in payloads:
                self.receive_udp(payload)

    def test_full_duplex_with_bounded_stream_buffers(self):
        for socket_stdio in (False, True):
            with self.subTest(socket_stdio=socket_stdio), self.helper(socket_stdio=socket_stdio):
                outbound = [bytes([i]) * 1000 for i in range(12)]
                for payload in outbound:
                    self.udp.sendto(payload, (PEER_IP, PEER_PORT))
                incoming = [b"inbound-while-output-is-queued" * 8, b"second-inbound" * 13]
                self.write_chunk(b"".join(self.record(payload) for payload in incoming))
                for payload in incoming:
                    self.receive_udp(payload)
                for payload in outbound:
                    self.receive_frame(payload)

    def test_clean_stdin_disconnect_exits(self):
        with self.helper():
            self.stdin.close()
            self.assertEqual(self.proc.wait(timeout=TIMEOUT), 0, self.diagnostics())

    def test_truncated_records_fail(self):
        for wire in (b"\0", b"\0\0\0", struct.pack("!I", 60), struct.pack("!I", 60) + b"x" * 59):
            with self.subTest(wire_length=len(wire)), self.helper():
                self.write_chunk(wire)
                self.stdin.close()
                self.assertNotEqual(self.proc.wait(timeout=TIMEOUT), 0, "truncation accepted")
                self.assertTrue(self.diagnostics(), "missing framing error diagnostic")

    def test_invalid_lengths_fail_without_waiting_for_body(self):
        for length in (0, 13, 1519, 0xffffffff):
            with self.subTest(length=length), self.helper():
                self.write_chunk(struct.pack("!I", length))
                self.assertNotEqual(self.proc.wait(timeout=TIMEOUT), 0, "invalid length accepted")
                self.assertTrue(self.diagnostics(), "missing length error diagnostic")

    def test_stdout_disconnect_exits_while_stdin_remains_open(self):
        with self.helper():
            self.stdout.close()
            self.udp.sendto(b"trigger-broken-output-pipe", (PEER_IP, PEER_PORT))
            self.assertNotEqual(self.proc.wait(timeout=TIMEOUT), 0, "output disconnect accepted")


if __name__ == "__main__":
    if len(sys.argv) != 2 or not os.path.isabs(sys.argv[1]):
        sys.exit(f"usage: unshare --user --map-root-user --net python3 {sys.argv[0]} /absolute/path/to/tap-framer")
    TapFramerTests.binary = sys.argv[1]
    unittest.main(argv=[sys.argv[0]], verbosity=2)
