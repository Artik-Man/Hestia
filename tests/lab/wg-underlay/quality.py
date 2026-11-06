"""Serve the fixture's underlay quality URL independently of the child WireGuard peer."""

import argparse
import ssl
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class QualityHandler(BaseHTTPRequestHandler):
    """Return a small successful response to the quality probe on either physical carrier."""

    def do_HEAD(self) -> None:
        """Report a successful empty response to an underlay reachability check."""
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        """Accept clients that probe the same endpoint using GET."""
        self.do_HEAD()

    def log_message(self, fmt: str, *args: object) -> None:
        """Suppress request logs so transient health probes do not fill the evidence."""


def serve_dns() -> None:
    """Resolve the quality host to the peer's common physical address from any candidate path."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("198.19.10.10", 53))
        while True:
            message, source = server.recvfrom(4096)
            name_end = message.index(b"\0", 12)
            query_end = name_end + 5
            valid = message[12:name_end] == b"\x02ya\x02ru" and message[name_end+1:query_end] == b"\0\1\0\1"
            header = message[:2] + struct.pack("!5H", 0x8180, 1, int(valid), 0, 0)
            response = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 10, 4) + socket.inet_aton("198.19.10.10")
            server.sendto(header + message[12:query_end] + (response if valid else b""), source)


def main() -> None:
    """Serve HTTPS on the floating address using the ephemeral lab certificate and key."""
    parser = argparse.ArgumentParser()
    parser.add_argument("certificate")
    parser.add_argument("key")
    args = parser.parse_args()
    threading.Thread(target=serve_dns, daemon=True).start()
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(args.certificate, args.key)
    server = ThreadingHTTPServer(("198.19.10.10", 443), QualityHandler)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
