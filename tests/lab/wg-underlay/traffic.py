"""Generate and observe identifiable application flows inside the isolated WireGuard lab."""

import argparse
import os
import socket
import uuid

ADDRESS = ("10.77.0.1", 16001)
PAYLOAD_BYTES = 713


def serve_echo() -> None:
    """Echo each test datagram so the client can prove both directions through the selected tunnel."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(ADDRESS)
        while True:
            payload, origin = server.recvfrom(2048)
            server.sendto(payload, origin)


def test_echo(label: str, timeout: float) -> bool:
    """Return whether the named slot-zero tunnel carried exactly this fresh 713-byte request and its echo."""
    token = f"{label}-{uuid.uuid4()}".encode("ascii")
    payload = token + os.urandom(PAYLOAD_BYTES - len(token))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(timeout)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"awg0\0")
        client.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 514)
        client.connect(ADDRESS)
        client.send(payload)
        return client.recv(2048) == payload


def main() -> int:
    """Start the local echo peer or return success when the trial confirmed the requested result."""
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("serve", "trial"))
    parser.add_argument("--label", default="trial")
    parser.add_argument("--timeout", type=float, default=1.0)
    args = parser.parse_args()
    if args.mode == "serve":
        serve_echo()
        return 0
    try:
        return 0 if test_echo(args.label, args.timeout) else 1
    except OSError:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
