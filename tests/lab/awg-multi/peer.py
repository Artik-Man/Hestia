"""Serve peer-specific DNS and HTTPS responses inside one isolated tunnel endpoint."""

import argparse
import socket
import ssl
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import cast


class PeerServer(ThreadingHTTPServer):
    """Serve requests for one synthetic endpoint and retain its non-secret test identity."""

    peer: str


class Endpoint(BaseHTTPRequestHandler):
    """Respond with this peer's identity using a persistent HTTP connection."""

    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        """Return the peer ID so a client can distinguish the two independent tunnels."""
        body = (cast(PeerServer, self.server).peer + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        """Suppress ordinary test traffic logs to keep the evidence compact."""


def dns(peer: str) -> None:
    """Answer A queries at the tunnel endpoint; leave other address families empty."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("10.77.0.1", 53))
        while True:
            packet, sender = sock.recvfrom(1500)
            end = packet.index(b"\0", 12) + 5
            name = packet[12:end - 5]
            own_name = b"\x07group-" + peer[-1:].encode() + b"\x03lab"
            is_a = packet[end - 4 : end - 2] == b"\0\1" and name in (b"\x02ya\x02ru", own_name)
            header = packet[:2] + struct.pack("!5H", 0x8180, 1, int(is_a), 0, 0)
            answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton("10.77.0.1")
            sock.sendto(header + packet[12:end] + (answer if is_a else b""), sender)


def main() -> None:
    """Start the isolated DNS responder and TLS server for a named peer and test certificate."""
    parser = argparse.ArgumentParser()
    parser.add_argument("peer")
    parser.add_argument("certificate")
    parser.add_argument("key")
    args = parser.parse_args()
    threading.Thread(target=dns, args=(args.peer,), daemon=True).start()
    server = PeerServer(("10.77.0.1", 443), Endpoint)
    server.peer = args.peer
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(args.certificate, args.key)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
