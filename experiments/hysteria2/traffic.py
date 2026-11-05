"""Echo the peer address over TCP and UDP, or assert both transports from a lab client."""

import json
import time
import urllib.request
import socket
import sys
from pathlib import Path

HOST = "198.51.100.2"
PORT = 18543


def serve(kind: int, ready: Path) -> None:
    """Report each caller's observed source address and signal when the socket is bound."""
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind((HOST, PORT))
        if kind == socket.SOCK_STREAM:
            sock.listen()
        ready.touch()
        while True:
            if kind == socket.SOCK_STREAM:
                conn, peer = sock.accept()
                with conn:
                    conn.sendall(peer[0].encode())
            else:
                _, peer = sock.recvfrom(64)
                sock.sendto(peer[0].encode(), peer)


def check(kind: int, expected: str) -> None:
    """Assert the remote peer address, or require failure when the expected result is blocked."""
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.settimeout(4)
        try:
            sock.connect((HOST, PORT))
            if kind == socket.SOCK_DGRAM:
                sock.send(b"source")
            result = sock.recv(64).decode() or "blocked"
        except (TimeoutError, ConnectionError):
            result = "blocked"
    print(f"{kind.name}: {result}", flush=True)
    if result != expected:
        raise SystemExit(f"expected {expected}")


def answer_readiness() -> None:
    """Answer UDP readiness checks at the resolver address confined to this lab namespace."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("1.1.1.1", 53))
        while True:
            query, peer = sock.recvfrom(4096)
            if len(query) >= 12:
                sock.sendto(query[:2] + b"\x81\x80" + query[4:], peer)


def wait_selection(report: Path, wanted: str) -> None:
    """Wait for a confirmed available selector from the running gateway controller."""
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if report.is_file():
            groups = json.loads(report.read_text())["groups"]
            if any(row["id"] == wanted and row["available"] and row["active"]
                   for group in groups for row in group["connections"]):
                print(f"watch: {wanted}", flush=True)
                return
        time.sleep(0.2)
    raise SystemExit(f"controller failed to select {wanted}")


def wait_transport(wanted: str) -> None:
    """Require a confirmed switch of the Hysteria transport selector within eight probe rounds."""
    tag = "a1234567-1234-4123-8123-123456789abc"
    expected = "deny" if wanted == "deny" else f"_hy2/{tag}/{wanted}"
    active = None
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline:
        with urllib.request.urlopen(f"http://127.0.0.1:9090/proxies/{tag}", timeout=2) as reply:
            active = json.load(reply)["now"]
        if active == expected:
            print(f"transport: {wanted}", flush=True)
            return
        time.sleep(0.25)
    raise SystemExit(f"expected {expected}, got {active}")


if __name__ == "__main__":
    if sys.argv[1] == "check":
        for protocol in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            check(protocol, sys.argv[2])
    elif sys.argv[1] == "dns-ready":
        answer_readiness()
    elif sys.argv[1] == "transport":
        wait_transport(sys.argv[2])
    elif sys.argv[1] == "selected":
        wait_selection(Path(sys.argv[2]), sys.argv[3])
    else:
        serve(getattr(socket, sys.argv[1]), Path(sys.argv[2]))
