#!/usr/bin/env python3
"""Real packet tests of the Terraform-rendered guest firewall, never the host's.

Run: python3 tests/test_network_policy.py -v
Requires Linux unprivileged user/network namespaces, iproute2, iptables/ip6tables,
Terraform, and Python 3. Fails (does not silently skip) if isolation is unavailable.
No Docker, services, cloud access, or Internet access is needed.
"""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "terraform/modules/aws/nitro-enclave/network-policy.sh.tftpl"
PAYLOAD = b"isolated network-policy download fixture\n" * 100
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()
ENV = {**os.environ, "PATH": "/usr/sbin:/sbin:" + os.environ["PATH"],
       "CHECKPOINT_DISABLE": "1"}
ISOLATED = "--isolated" in sys.argv

SERVER = r'''
import selectors, socket, sys
selector = selectors.DefaultSelector()
for specification in sys.argv[1:]:
    address, port, protocol = specification.split(",")
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    sock = socket.socket(family, kind)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((address, int(port)))
    if protocol == "tcp":
        sock.listen()
    selector.register(sock, selectors.EVENT_READ, protocol)
print("ready", flush=True)
payload = b"isolated network-policy download fixture\n" * 100
while True:
    for key, _ in selector.select():
        if key.data == "tcp":
            connection, _ = key.fileobj.accept()
            with connection:
                connection.settimeout(1)
                connection.recv(4096)
                connection.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: " +
                                   str(len(payload)).encode() + b"\r\n\r\n" + payload)
        else:
            _, peer = key.fileobj.recvfrom(4096)
            key.fileobj.sendto(payload, peer)
'''
CLIENT = r'''
import hashlib, socket, sys
address, port, protocol, source, source_port = sys.argv[1:]
family = socket.AF_INET6 if ":" in address else socket.AF_INET
kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
with socket.socket(family, kind) as sock:
    sock.settimeout(0.35)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    if source or int(source_port):
        sock.bind((source, int(source_port)))
    try:
        if protocol == "tcp":
            sock.connect((address, int(port)))
            sock.sendall(b"GET /fixture HTTP/1.0\r\n\r\n")
            chunks = []
            while True:
                data = sock.recv(8192)
                if not data:
                    break
                chunks.append(data)
            data = b"".join(chunks).split(b"\r\n\r\n", 1)[1]
        else:
            sock.sendto(b"probe", (address, int(port)))
            data = sock.recv(8192)
    except (TimeoutError, ConnectionRefusedError, ConnectionResetError):
        sys.exit(10)
print(hashlib.sha256(data).hexdigest())
'''


def run(*args, **kwargs):
    return subprocess.run(args, env=ENV, text=True, capture_output=True,
                          timeout=15, **kwargs)


def render(forward="", dns="", ingress="", ingress_guard=""):
    if not TEMPLATE.is_file():
        raise AssertionError("guest firewall installer template is missing")
    variables = {"egress_forward_rules": forward, "egress_dns_rules": dns,
                 "ingress_input_rules": ingress, "ingress_guard_rules": ingress_guard,
                 "ingress_ipv6_rules": ingress_guard.replace("CAUTION_INGRESS_GUARD", "CAUTION_INGRESS")}
    expression = "jsonencode(templatefile(" + json.dumps(str(TEMPLATE)) + ", " + json.dumps(variables) + "))\n"
    with tempfile.TemporaryDirectory() as directory:
        result = run("terraform", "console", "-no-color", input=expression, cwd=directory)
    if result.returncode:
        raise AssertionError(result.stderr)
    return json.loads(json.loads(result.stdout))


def stop(process):
    if process.poll() is None:
        process.terminate()
    process.wait(timeout=5)
    if process.stdout:
        process.stdout.close()
    if process.stderr:
        process.stderr.close()


class NetworkPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not ISOLATED:
            raise unittest.SkipTest("run tests/test_network_policy.py directly for isolated packet tests")
        mapping = Path("/proc/self/uid_map").read_text().split()
        if len(mapping) != 3 or mapping[0] != "0" or mapping[2] != "1" or os.geteuid() != 0:
            raise RuntimeError("requires an unprivileged single-user namespace")
        with open("/proc/self/ns/net", "rb") as net:
            owner = fcntl.ioctl(net, 0xb701)  # NS_GET_USERNS
        try:
            if not os.path.samestat(os.fstat(owner), os.stat("/proc/self/ns/user")):
                raise RuntimeError("refusing a network namespace owned by another user namespace")
        finally:
            os.close(owner)
        if {name for _, name in socket.if_nameindex()} != {"lo"}:
            raise RuntimeError("requires a fresh outer network namespace")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.nodes = {}
        for name in ("parent", "guest", "external"):
            process = subprocess.Popen(
                ["unshare", "-n", sys.executable, "-c",
                 "import signal; print('ready', flush=True); signal.pause()"],
                env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.addCleanup(stop, process)
            self.ready(process)
            self.nodes[name] = process.pid
            self.command(name, "ip", "link", "set", "lo", "up")
        for node, interface, parent_ip, peer_ip in (
            ("guest", "enclave0", "10.0.100.1", "10.0.100.10"),
            ("external", "wan0", "203.0.113.254", "203.0.113.1"),
        ):
            self.command("parent", "ip", "link", "add", interface, "type", "veth", "peer", "name", "peer0")
            self.command("parent", "ip", "link", "set", "peer0", "netns", str(self.nodes[node]))
            self.command("parent", "ip", "addr", "add", parent_ip + "/24", "dev", interface)
            self.command("parent", "ip", "link", "set", interface, "up")
            self.command(node, "ip", "addr", "add", peer_ip + "/24", "dev", "peer0")
            self.command(node, "ip", "link", "set", "peer0", "up")
            self.command(node, "ip", "route", "add", "default", "via", parent_ip)
        self.command("external", "ip", "addr", "add", "203.0.113.2/24", "dev", "peer0")
        self.command("parent", "sysctl", "-qw", "net.ipv4.ip_forward=1")
        self.command("parent", "iptables", "-A", "FORWARD", "-j", "ACCEPT")
        self.serve("external", [f"{ip},{port},{proto}" for ip in ("203.0.113.1", "203.0.113.2")
                                for port in (8443, 8444, 5353) for proto in ("tcp", "udp")])

    def ready(self, process):
        self.assertTrue(select.select([process.stdout], [], [], 5)[0], "fixture did not become ready")
        line = process.stdout.readline()
        if line != "ready\n":
            process.wait(timeout=5)
            self.fail("fixture failed: " + process.stderr.read())

    def argv(self, node, *args):
        return ["nsenter", "-t", str(self.nodes[node]), "-n", *args]

    def command(self, node, *args, **kwargs):
        result = run(*self.argv(node, *args), **kwargs)
        self.assertEqual(result.returncode, 0, f"{args}: {result.stderr}")
        return result.stdout

    def serve(self, node, endpoints):
        process = subprocess.Popen(self.argv(node, sys.executable, "-c", SERVER, *endpoints),
                                   env=ENV, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(stop, process)
        self.ready(process)

    def probe(self, node="guest", address="203.0.113.1", port=8443, protocol="tcp",
              source="", source_port=0, allowed=True):
        result = run(*self.argv(node, sys.executable, "-c", CLIENT, address, str(port),
                               protocol, source, str(source_port)))
        if allowed:
            self.assertEqual(result.returncode, 0, f"{node} -> {address}:{port}/{protocol}: {result.stderr}")
            self.assertEqual(result.stdout.strip(), DIGEST, "download content hash mismatch")
        else:
            self.assertEqual(result.returncode, 10, f"unexpected packet outcome: {result.stdout} {result.stderr}")

    def install(self, forward="", dns="", *, ingress="", ingress_guard="", expected=0, env=None):
        script = self.path / "install-policy"
        script.write_text(render(forward, dns, ingress, ingress_guard))
        result = subprocess.run(self.argv("parent", "bash", str(script)), env=env or ENV,
                                text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def test_destination_protocol_port_and_interface_enforcement(self):
        for address, port, protocol in (("203.0.113.1", 8443, "tcp"),
                                        ("203.0.113.1", 5353, "udp"),
                                        ("203.0.113.1", 8444, "tcp"),
                                        ("203.0.113.2", 8443, "tcp"),
                                        ("203.0.113.1", 8443, "udp")):
            self.probe(address=address, port=port, protocol=protocol)
        self.install("-A CAUTION_EGRESS -d 203.0.113.1/32 -p tcp --dport 8443 -j ACCEPT\n"
                     "-A CAUTION_EGRESS -d 203.0.113.1/32 -p udp --dport 5353 -j ACCEPT")
        self.probe()
        self.probe(port=5353, protocol="udp")
        self.probe(port=8444, allowed=False)
        self.probe(address="203.0.113.2", allowed=False)
        self.probe(protocol="udp", allowed=False)
        self.probe(node="parent", port=8444)
        self.probe(node="parent", address="203.0.113.2")
        self.command("guest", "ip", "addr", "add", "198.51.100.10/32", "dev", "peer0")
        self.command("parent", "ip", "route", "add", "198.51.100.10/32", "dev", "enclave0")
        self.probe(source="198.51.100.10")
        self.probe(source="198.51.100.10", port=8444, allowed=False)

    def test_reverse_forwarding_allows_only_replies_to_guest_connections(self):
        self.serve("guest", ["10.0.100.10,8443,tcp", "10.0.100.10,5353,udp"])
        self.probe(node="external", address="10.0.100.10")
        self.probe(node="external", address="10.0.100.10", port=5353, protocol="udp")
        self.install("-A CAUTION_EGRESS -j ACCEPT")
        self.probe(node="external", address="10.0.100.10", allowed=False)
        self.probe(node="external", address="10.0.100.10", port=5353, protocol="udp", allowed=False)
        self.command("parent", "iptables", "-D", "FORWARD", "-j", "ACCEPT")
        self.command("parent", "iptables", "-P", "FORWARD", "DROP")
        self.probe()
        self.probe(port=5353, protocol="udp")
        self.probe(node="parent")

    def test_allow_all_cannot_reach_host_services_or_metadata(self):
        self.serve("parent", ["0.0.0.0,8443,tcp", "0.0.0.0,53,udp"])
        self.command("external", "ip", "addr", "add", "169.254.169.254/32", "dev", "peer0")
        self.command("parent", "ip", "route", "add", "169.254.169.254/32", "dev", "wan0")
        self.serve("external", ["169.254.169.254,8443,tcp"])
        for address in ("10.0.100.1", "203.0.113.254", "169.254.169.254"):
            self.probe(address=address)
        self.probe(address="10.0.100.1", port=53, protocol="udp")
        self.install("-A CAUTION_EGRESS -j ACCEPT",
                     "-A CAUTION_INPUT -d 10.0.100.1/32 -p udp --dport 53 -j ACCEPT")
        self.probe()
        self.probe(address="10.0.100.1", port=53, protocol="udp")
        for address in ("10.0.100.1", "203.0.113.254", "169.254.169.254"):
            self.probe(address=address, allowed=False)
        self.probe(address="203.0.113.254", port=53, protocol="udp", allowed=False)
        self.probe(node="parent", address="169.254.169.254")
        self.probe(node="external", address="203.0.113.254")

    def test_dns_requires_explicit_input_permission(self):
        self.serve("parent", ["10.0.100.1,53,tcp", "10.0.100.1,53,udp"])
        for protocol in ("tcp", "udp"):
            self.probe(address="10.0.100.1", port=53, protocol=protocol)
        self.install("-A CAUTION_EGRESS -d 203.0.113.1/32 -p tcp --dport 8443 -j ACCEPT")
        for protocol in ("tcp", "udp"):
            self.probe(address="10.0.100.1", port=53, protocol=protocol, allowed=False)
        self.probe()

    def test_dns_opt_in_allows_tcp_and_udp_only_at_resolver(self):
        self.serve("parent", ["0.0.0.0,53,tcp", "0.0.0.0,53,udp", "0.0.0.0,8443,tcp"])
        self.install(dns="-A CAUTION_INPUT -d 10.0.100.1/32 -p tcp --dport 53 -j ACCEPT\n"
                         "-A CAUTION_INPUT -d 10.0.100.1/32 -p udp --dport 53 -j ACCEPT")
        for protocol in ("tcp", "udp"):
            self.probe(address="10.0.100.1", port=53, protocol=protocol)
            self.probe(address="203.0.113.254", port=53, protocol=protocol, allowed=False)
        self.probe(address="10.0.100.1", allowed=False)
        self.probe(allowed=False)

    def test_dhcp_is_the_only_implicit_guest_local_exception(self):
        self.serve("parent", ["0.0.0.0,67,udp", "0.0.0.0,68,udp", "0.0.0.0,67,tcp"])
        self.probe(address="10.0.100.1", port=67, protocol="udp", source_port=68)
        self.probe(address="255.255.255.255", port=67, protocol="udp", source_port=68)
        self.install()
        self.probe(address="10.0.100.1", port=67, protocol="udp", source_port=68)
        self.probe(address="255.255.255.255", port=67, protocol="udp", source_port=68)
        self.probe(address="10.0.100.1", port=67, protocol="udp", allowed=False)
        self.probe(address="10.0.100.1", port=68, protocol="udp", source_port=68, allowed=False)
        self.probe(address="10.0.100.1", port=67, source_port=68, allowed=False)
        self.probe(address="203.0.113.254", port=67, protocol="udp", source_port=68, allowed=False)

    def ipv6_fixture(self):
        self.command("parent", "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")
        for node, interface, address in (("parent", "enclave0", "2001:db8:1::1"),
                                          ("guest", "peer0", "2001:db8:1::10"),
                                          ("parent", "wan0", "2001:db8:2::254"),
                                          ("external", "peer0", "2001:db8:2::1")):
            self.command(node, "ip", "-6", "addr", "add", address + "/64", "dev", interface, "nodad")
        for node, gateway in (("guest", "2001:db8:1::1"), ("external", "2001:db8:2::254")):
            self.command(node, "ip", "-6", "route", "add", "default", "via", gateway)
        for node, interface, peer, peer_interface, address in (
            ("parent", "enclave0", "guest", "peer0", "2001:db8:1::10"),
            ("guest", "peer0", "parent", "enclave0", "2001:db8:1::1"),
            ("parent", "wan0", "external", "peer0", "2001:db8:2::1"),
            ("external", "peer0", "parent", "wan0", "2001:db8:2::254"),
        ):
            link = json.loads(self.command(peer, "ip", "-j", "link", "show", peer_interface))[0]
            self.command(node, "ip", "-6", "neigh", "replace", address, "lladdr", link["address"],
                         "nud", "permanent", "dev", interface)
        self.command("parent", "ip6tables", "-A", "FORWARD", "-j", "ACCEPT")
        for node, address in (("parent", "2001:db8:1::1"), ("guest", "2001:db8:1::10"),
                              ("external", "2001:db8:2::1")):
            self.serve(node, [f"{address},8443,tcp", f"{address},5353,udp"])

    def test_ipv6_input_and_both_forward_directions_fail_closed(self):
        self.ipv6_fixture()
        for protocol, port in (("tcp", 8443), ("udp", 5353)):
            self.probe(address="2001:db8:2::1", port=port, protocol=protocol)
            self.probe(address="2001:db8:1::1", port=port, protocol=protocol)
            self.probe(node="external", address="2001:db8:1::10", port=port, protocol=protocol)
        self.install("-A CAUTION_EGRESS -j ACCEPT")
        for protocol, port in (("tcp", 8443), ("udp", 5353)):
            self.probe(address="2001:db8:2::1", port=port, protocol=protocol, allowed=False)
            self.probe(address="2001:db8:1::1", port=port, protocol=protocol, allowed=False)
            self.probe(node="external", address="2001:db8:1::10", port=port, protocol=protocol, allowed=False)
            self.probe(node="parent", address="2001:db8:2::1", port=port, protocol=protocol)

    def invalid_packet(self, node, address, port, *, received):
        marker = b"network-policy-invalid-tcp"
        capture = r'''
import socket, sys, time
with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as sock:
    sock.settimeout(0.5)
    print("ready", flush=True)
    deadline = time.monotonic() + 0.5
    while time.monotonic() < deadline:
        try:
            data = sock.recv(65535)
        except TimeoutError:
            sys.exit(10)
        if data.endswith(bytes.fromhex(sys.argv[1])):
            sys.exit(0)
sys.exit(10)
'''
        sender = r'''
import socket, struct, sys
source, destination, port, marker = sys.argv[1:]
payload = bytes.fromhex(marker)
tcp = struct.pack("!HHIIBBHHH", 55555, int(port), 1, 0, 5 << 4, 3, 4096, 0, 0)
pseudo = socket.inet_aton(source) + socket.inet_aton(destination) + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
data = pseudo + tcp + payload
if len(data) % 2:
    data += b"\0"
total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
while total >> 16:
    total = (total & 65535) + (total >> 16)
tcp = tcp[:16] + struct.pack("!H", (~total) & 65535) + tcp[18:]
header = struct.pack("!BBHHHBBH4s4s", 69, 0, 0, 1, 0, 64, 6, 0, socket.inet_aton(source), socket.inet_aton(destination))
with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as sock:
    sock.sendto(header + tcp + payload, (destination, 0))
'''
        process = subprocess.Popen(self.argv(node, sys.executable, "-c", capture, marker.hex()),
                                   env=ENV, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(stop, process)
        self.ready(process)
        self.command("guest", sys.executable, "-c", sender, "10.0.100.10", address, str(port), marker.hex())
        self.assertEqual(process.wait(timeout=3), 0 if received else 10, process.stderr.read())

    def test_invalid_packets_cannot_use_allow_all_or_dns_permissions(self):
        self.invalid_packet("external", "203.0.113.1", 8443, received=True)
        self.invalid_packet("parent", "10.0.100.1", 53, received=True)
        self.install("-A CAUTION_EGRESS -j ACCEPT",
                     "-A CAUTION_INPUT -d 10.0.100.1/32 -p tcp --dport 53 -j ACCEPT")
        self.invalid_packet("external", "203.0.113.1", 8443, received=False)
        self.invalid_packet("parent", "10.0.100.1", 53, received=False)

    def test_reinstall_is_idempotent_and_preserves_unrelated_rules(self):
        self.command("parent", "iptables", "-N", "UNRELATED")
        self.command("parent", "iptables", "-A", "UNRELATED", "-j", "RETURN")
        self.command("parent", "iptables", "-A", "OUTPUT", "-j", "UNRELATED")
        self.command("parent", "iptables", "-t", "nat", "-A", "POSTROUTING",
                     "-s", "198.51.100.0/24", "-j", "MASQUERADE")
        nat = self.command("parent", "iptables", "-t", "nat", "-S")
        policy = "-A CAUTION_EGRESS -d 203.0.113.1/32 -p tcp --dport 8443 -j ACCEPT"
        self.install(policy)
        first = [self.command("parent", tool, "-S") for tool in ("iptables", "ip6tables")]
        self.command("parent", "iptables", "-A", "CAUTION_EGRESS", "-j", "ACCEPT")
        for _ in range(2):
            self.install(policy)
            self.assertEqual([self.command("parent", tool, "-S") for tool in ("iptables", "ip6tables")], first)
            self.assertEqual(self.command("parent", "iptables", "-t", "nat", "-S"), nat)
            self.assertEqual(self.command("parent", "iptables", "-S", "UNRELATED"),
                             "-N UNRELATED\n-A UNRELATED -j RETURN\n")
            self.probe()
            self.probe(port=8444, allowed=False)
            self.probe(node="parent", port=8444)

    def test_installs_before_tunnel_interface_exists(self):
        self.command("parent", "ip", "link", "set", "enclave0", "down")
        self.command("parent", "ip", "link", "set", "enclave0", "name", "not-yet-enclave")
        self.install()
        self.command("parent", "ip", "link", "set", "not-yet-enclave", "name", "enclave0")
        self.command("parent", "ip", "link", "set", "enclave0", "up")
        self.probe(allowed=False)
        self.probe(node="parent")

    def interrupted_install(self, reinstall):
        self.ipv6_fixture()
        self.serve("parent", ["10.0.100.1,53,udp"])
        self.serve("guest", ["10.0.100.10,8443,tcp"])
        policy = "-A CAUTION_EGRESS -d 203.0.113.1/32 -p tcp --dport 8443 -j ACCEPT"
        dns = "-A CAUTION_INPUT -d 10.0.100.1/32 -p udp --dport 53 -j ACCEPT"
        ingress, guard = self.ingress_fixture()
        self.serve("parent", ["203.0.113.254,49500,tcp", "2001:db8:1::1,49500,tcp"])
        self.probe(node="external", address="203.0.113.254", port=49500)
        self.probe()
        self.probe(address="10.0.100.1", port=53, protocol="udp")
        if reinstall:
            self.install(policy, dns, ingress=ingress, ingress_guard=guard)
            self.probe()
        script = self.path / "interrupted-policy"
        script.write_text(render(policy, dns, ingress, guard))
        release = self.path / "release"
        wrapper = self.path / "iptables-restore"
        wrapper.write_text('''#!/usr/bin/env python3
import os, pathlib, subprocess, sys, time
rules = sys.stdin.read()
if "-A CAUTION_EGRESS " in rules:
    print("ready", flush=True)
    deadline = time.monotonic() + 20
    while not pathlib.Path(os.environ["POLICY_RELEASE"]).exists():
        if time.monotonic() > deadline:
            sys.exit(24)
        time.sleep(0.01)
    sys.exit(23)
sys.exit(subprocess.run(["/usr/sbin/iptables-restore", *sys.argv[1:]], input=rules, text=True).returncode)
''')
        wrapper.chmod(0o755)
        env = {**ENV, "PATH": str(self.path) + ":" + ENV["PATH"], "POLICY_RELEASE": str(release)}
        process = subprocess.Popen(self.argv("parent", "bash", str(script)), env=env,
                                   text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(stop, process)
        try:
            self.ready(process)
            self.probe(node="external", address="203.0.113.254", port=49500, allowed=False)
            self.probe(node="external", address="2001:db8:1::1", port=49500, allowed=False)
            self.probe(node="parent", source_port=49550)
            self.probe(allowed=False)
            self.probe(address="10.0.100.1", port=53, protocol="udp", allowed=False)
            self.probe(node="external", address="10.0.100.10", allowed=False)
            self.probe(address="2001:db8:2::1", allowed=False)
            self.probe(address="2001:db8:1::1", allowed=False)
            self.probe(node="parent")
        finally:
            release.write_text("fail")
            process.wait(timeout=5)
        self.assertEqual(process.returncode, 23, process.stderr.read())
        self.probe(node="external", address="203.0.113.254", port=49500, allowed=False)
        self.probe(node="parent", source_port=49551)
        self.probe(allowed=False)
        self.probe(address="10.0.100.1", port=53, protocol="udp", allowed=False)
        self.probe(node="parent")
        self.install(policy, dns, ingress=ingress, ingress_guard=guard)
        self.probe(node="external", address="203.0.113.254", port=49500)
        self.probe(node="external", address="203.0.113.254", port=49500, source="203.0.113.2", allowed=False)
        self.probe()
        self.probe(address="10.0.100.1", port=53, protocol="udp")
        self.probe(port=8444, allowed=False)
        for tool in ("iptables", "ip6tables"):
            self.assertNotIn("CAUTION_GUARD", self.command("parent", tool, "-S"))

    def test_initial_install_is_guarded_and_failure_stays_closed(self):
        self.interrupted_install(reinstall=False)

    def test_reinstall_is_guarded_and_failure_stays_closed(self):
        self.interrupted_install(reinstall=True)

    @staticmethod
    def ingress_fixture():
        rules = "-A CAUTION_INGRESS -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j RETURN\n"
        guard = "-A CAUTION_INGRESS_GUARD -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j RETURN\n"
        for ports, sources in (("8443:8444", ("203.0.113.1", "203.0.113.2")),
                               ("443", ("203.0.113.1",)), ("49500", ("203.0.113.1",)),
                               ("49504", ("203.0.113.2",))):
            for source in sources:
                rules += f"-A CAUTION_INGRESS -s {source}/32 -p tcp --dport {ports} -j ACCEPT\n"
        for ports in ("443", "8443:8444", "49500:49600"):
            rules += f"-A CAUTION_INGRESS -p tcp --dport {ports} -j DROP\n"
            guard += f"-A CAUTION_INGRESS_GUARD -p tcp --dport {ports} -j DROP\n"
        return rules, guard

    def test_direct_ingress_peer_sources_survive_permissive_outer_firewall(self):
        self.command("external", "ip", "addr", "add", "203.0.113.3/24", "dev", "peer0")
        ports = (443, 8443, 8444, 49500, 49501, 49502, 49503, 49504, 22, 80)
        self.serve("parent", [f"0.0.0.0,{port},tcp" for port in ports])
        for port in ports:
            self.probe(node="external", address="203.0.113.254", port=port, source="203.0.113.3")
        # No TAP and no guest egress: ingress must still install and enforce.
        self.command("parent", "ip", "link", "set", "enclave0", "down")
        self.command("parent", "ip", "link", "set", "enclave0", "name", "no-tunnel")
        rules, guard = self.ingress_fixture()
        self.install(ingress=rules, ingress_guard=guard)
        for source in ("203.0.113.1", "203.0.113.2", "203.0.113.3"):
            for port in ports:
                allowed = port in (22, 80) or (port in (8443, 8444) and source != "203.0.113.3")
                allowed |= port in (443, 49500) and source == "203.0.113.1"
                allowed |= port == 49504 and source == "203.0.113.2"
                self.probe(node="external", address="203.0.113.254", port=port,
                           source=source, allowed=allowed)
        self.probe(node="parent", address="127.0.0.1", port=8443)
        # Outbound host transfers can use the reserved ephemeral range. Their
        # conntrack REPLY direction is distinct from an external incoming flow.
        self.probe(node="parent", source_port=49550)
        first = [self.command("parent", tool, "-S") for tool in ("iptables", "ip6tables")]
        self.install(ingress=rules, ingress_guard=guard)
        self.assertEqual([self.command("parent", tool, "-S") for tool in ("iptables", "ip6tables")], first)
        self.command("parent", "ip", "link", "set", "no-tunnel", "name", "enclave0")
        self.command("parent", "ip", "link", "set", "enclave0", "up")
        self.install(ingress=rules.replace("203.0.113.1/32", "0.0.0.0/0"), ingress_guard=guard)
        self.probe(address="10.0.100.1", port=8443, allowed=False)

    def test_direct_ingress_ipv6_cannot_bypass_ipv4_policy(self):
        self.ipv6_fixture()
        self.serve("parent", [f"2001:db8:1::1,{port},tcp" for port in (443, 49500, 49504)])
        for port in (8443, 443, 49500, 49504):
            self.probe(node="external", address="2001:db8:1::1", port=port)
        rules, guard = self.ingress_fixture()
        self.install(ingress=rules, ingress_guard=guard)
        for port in (8443, 443, 49500, 49504):
            self.probe(node="external", address="2001:db8:1::1", port=port, allowed=False)
        self.probe(node="parent", address="2001:db8:2::1", source_port=49550)

    def test_empty_policy_blocks_guest_but_not_parent_download(self):
        self.probe()
        self.probe(node="parent")
        self.install()
        self.probe(allowed=False)
        self.probe(node="parent")


if __name__ == "__main__":
    if not ISOLATED:
        result = run("unshare", "-Urn", "true")
        if result.returncode:
            sys.exit("network-policy tests require isolated user/network namespaces: " + result.stderr)
        os.execvpe("unshare", ["unshare", "-Urn", sys.executable, str(Path(__file__).resolve()),
                               "--isolated", *sys.argv[1:]], ENV)
    sys.argv.remove("--isolated")
    unittest.main()
