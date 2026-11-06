"""Exercise one persistent TLS connection through a selected interface and routing mark."""

import argparse
import http.client
import socket
import ssl
import time
from pathlib import Path


def main() -> None:
    """Check peer identity repeatedly on the original socket until the finish signal arrives."""
    parser = argparse.ArgumentParser()
    parser.add_argument("slot", type=int)
    parser.add_argument("--group", action="store_true")
    parser.add_argument("expected")
    parser.add_argument("certificate")
    parser.add_argument("signal_dir", type=Path)
    args = parser.parse_args()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(4)
        if args.group:
            sock.connect(("127.0.0.1", 20080 + args.slot))
            sock.sendall(b"\x05\x01\x00")
            if sock.recv(2, socket.MSG_WAITALL) != b"\x05\x00":
                raise RuntimeError("SOCKS authentication failed")
            sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("10.77.0.1") + (443).to_bytes(2, "big"))
            header = sock.recv(4, socket.MSG_WAITALL)
            if header[:3] != b"\x05\x00\x00" or header[3] not in (1, 4):
                raise RuntimeError("SOCKS connection failed")
            bound_length = (4 if header[3] == 1 else 16) + 2
            if len(sock.recv(bound_length, socket.MSG_WAITALL)) != bound_length:
                raise RuntimeError("incomplete SOCKS response")
        else:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, f"awg{args.slot}".encode() + b"\0")
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 0x202 + args.slot)
            sock.connect(("10.77.0.1", 443))
        tls = ssl.create_default_context(cafile=args.certificate)
        with tls.wrap_socket(sock, server_hostname="ya.ru") as conn:
            count = 0
            while True:
                conn.sendall(b"GET / HTTP/1.1\r\nHost: ya.ru\r\n\r\n")
                response = http.client.HTTPResponse(conn)
                response.begin()
                if response.status != 200 or response.read().decode().strip() != args.expected:
                    raise RuntimeError("unexpected peer")
                count += 1
                (args.signal_dir / "connected").touch()
                if (args.signal_dir / "finish").exists():
                    print(f"slot {args.slot} through_group={args.group} peer={args.expected} replies={count} single TLS connection")
                    return
                time.sleep(0.2)


if __name__ == "__main__":
    main()
