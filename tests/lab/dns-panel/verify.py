"""Exercise production ARM64 DNS, HTTP policy and selectors inside an isolated Linux network namespace."""

import argparse
import contextlib
import json
import os
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request
from pathlib import Path


def write(path, value):
    """Create one lab JSON configuration file and its parent directories."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def api(path, payload=None, port=18080):
    """Read or replace state through the real loopback HTTP API."""
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="GET" if data is None else "PUT",
    )
    with urllib.request.urlopen(request, timeout=2) as response:
        return json.load(response) if response.status != 204 else None


def wait(predicate):
    """Return the first matching observation or fail within a bounded deadline."""
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        try:
            if result := predicate():
                return result
        except (OSError, ValueError):
            pass
        time.sleep(0.1)
    raise AssertionError("expected observation did not arrive")


def question(name, identifier):
    """Build a simple IN/A DNS question with the supplied transaction identifier."""
    labels = b"".join(bytes([len(label)]) + label.encode() for label in name.split("."))
    return (
        struct.pack("!6H", identifier, 256, 1, 0, 0, 0)
        + labels
        + b"\x00\x00\x01\x00\x01"
    )


def query(name, identifier):
    """Send a fresh DNS transaction from the simulated router and return its RCODE and address."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        client.bind(("127.0.0.2", 0))
        client.sendto(question(name, identifier), ("127.0.0.1", 1053))
        packet = client.recv(4096)
    rid, flags, _, answers, _, _ = struct.unpack("!6H", packet[:12])
    assert rid == identifier
    return flags & 15, socket.inet_ntoa(packet[-4:]) if answers else None


def upstream(sock, visits):
    """Provide positive A/AAAA replies with a two-second TTL and count actual upstream datagrams."""
    while True:
        try:
            msg, peer = sock.recvfrom(65535)
        except OSError:
            return
        labels, i = [], 12
        while msg[i]:
            labels.append(msg[i + 1 : i + 1 + msg[i]].decode("ascii"))
            i += msg[i] + 1
        name = ".".join(labels)
        kind = int.from_bytes(msg[i + 1 : i + 3], "big")
        visits.append((name, kind))
        data = (
            socket.inet_pton(socket.AF_INET6, "2001:db8::10")
            if kind == 28
            else socket.inet_aton("203.0.113.10")
        )
        answer = b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 2, len(data)) + data
        sock.sendto(
            msg[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + msg[12 : i + 5] + answer,
            peer,
        )


@contextlib.contextmanager
def running(args):
    """Start a lab process and terminate it on every exit path."""
    process = subprocess.Popen(args)
    try:
        yield process
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def scenario(root, bundle):
    """Run the shipped CLI and policy service in a chroot with a real sing-box selector and no default route."""
    etc = root / "etc/hestia"
    state = root / "run/hestia-dns"
    state.mkdir(parents=True)
    (root / "run/hestia-install.lock").touch()
    (root / "var/lib/hestia-dns").mkdir(parents=True)
    (root / "assets").mkdir()
    (root / "assets/index.html").write_text("<title>DNS lab</title>")
    for binary in ("hestia", "hestia-panel"):
        os.link(bundle / binary, root / binary)
    backend = {
        "experimental": {"clash_api": {"external_controller": "127.0.0.1:9090"}},
        "outbounds": [
            {
                "type": "selector",
                "tag": "group",
                "outbounds": ["direct-line", "deny"],
                "default": "direct-line",
            },
            {"type": "direct", "tag": "direct-line", "bind_interface": "lo"},
            {"type": "direct", "tag": "deny", "bind_interface": "lo"},
        ],
        "route": {"final": "group"},
    }
    write(etc / "sing-box.json", backend)
    write(
        etc / "snapshot.json",
        {
            "groups": [{"id": "group", "exits": ["direct-line"]}],
            "lists": [],
            "healthy": {"direct-line": True},
        },
    )
    write(
        etc / "dns.json",
        {
            "listen": "127.0.0.1:1053",
            "router": "127.0.0.2",
            "directResolvers": {"direct-line": "198.18.0.53"},
        },
    )
    subprocess.run(
        [
            "python3",
            "-I",
            bundle / "profile.py",
            "--dns-paths",
            etc / "sing-box.json",
            state,
        ],
        check=True,
    )
    prefix = ["chroot", root]
    panel = prefix + [
        "/hestia-panel",
        "-listen",
        "127.0.0.1:18080",
        "-assets",
        "/assets",
        "-snapshot",
        "/etc/hestia/snapshot.json",
        "-dns-policy",
        "/var/lib/hestia-dns-policy/policy.json",
        "-dns-report",
        "/run/hestia-dns/report.json",
    ]
    visits = []
    with (
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock,
        contextlib.ExitStack() as stack,
    ):
        sock.bind(("198.18.0.53", 53))
        threading.Thread(target=upstream, args=(sock, visits), daemon=True).start()
        stack.enter_context(
            running([bundle / "sing-box", "run", "-c", etc / "sing-box.json"])
        )
        stack.enter_context(running(panel))
        wait(lambda: api("/proxies/group", port=9090)["now"] == "direct-line")
        policy = wait(lambda: api("/api/dns/policy"))
        settings = policy["policy"]["settings"]
        settings["threshold"] = 2
        settings["retentionSeconds"] = 120
        put = lambda snap: api(
            "/api/dns/policy",
            {"expectedRevision": snap["revision"], "policy": snap["policy"]},
        )
        policy = put(policy)
        stack.enter_context(
            running(prefix + ["/hestia", "dns", "/etc/hestia/dns.json"])
        )
        report = lambda: api("/api/dns/warm")
        wait(lambda: report()["automatic"] == [])
        for rid in (101, 102):
            assert query("warm.example", rid) == (0, "203.0.113.10")
        wait(
            lambda: (
                report()["automatic"]
                == [{"domain": "warm.example", "clientRequests": 2}]
            )
        )
        print(
            "PASS: two router queries reached the threshold; HTTP report shows two client requests",
            flush=True,
        )
        policy["policy"]["manual"] = ["warm.example"]
        policy["policy"]["exclusions"] = ["warm.example"]
        policy = put(policy)
        wait(
            lambda: (
                report()["policyRevision"] == policy["revision"]
                and report()["automatic"] == []
            )
        )
        count = visits.count(("warm.example", 1))
        wait(lambda: visits.count(("warm.example", 1)) > count)
        print(
            "PASS: exclusion removed automatic membership; physical upstream received another manual refresh",
            flush=True,
        )
        policy["policy"]["exclusions"] = []
        policy = put(policy)
        wait(
            lambda: (
                report()["policyRevision"] == policy["revision"]
                and report()["automatic"]
                == [{"domain": "warm.example", "clientRequests": 2}]
            )
        )
        print(
            "PASS: removing exclusion restored automatic membership without counting background DNS",
            flush=True,
        )
        api("/proxies/group", {"name": "deny"}, port=9090)
        n = len(visits)
        assert query("denied.example", 103) == (2, None)
        assert len(visits) == n
        print(
            "PASS: selector denied; router received SERVFAIL; no upstream packet",
            flush=True,
        )


def main():
    """Require a dedicated network namespace before running the compiled binaries in a disposable root."""
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0 or os.readlink("/proc/self/ns/net") == os.readlink(
        "/proc/1/ns/net"
    ):
        raise RuntimeError("use sudo unshare --net on the isolated project VM")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    subprocess.run(["ip", "addr", "add", "198.18.0.53/32", "dev", "lo"], check=True)
    with tempfile.TemporaryDirectory(dir=args.bundle) as temp:
        scenario(Path(temp), args.bundle.resolve())


if __name__ == "__main__":
    main()
