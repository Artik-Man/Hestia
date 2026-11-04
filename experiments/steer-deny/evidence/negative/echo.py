"""Plain echo services and independent LAN controls for the observer acceptance lab."""

import argparse
import json
import socket
import socketserver
import threading

X = "203.0.113.77"
Y = "203.0.113.78"
PORT = 19092


def record(server, protocol, peer, payload):
    """Log the exact marker and addresses observed by a bound echo listener."""
    print(
        json.dumps(
            {
                "target": server.server_address[0],
                "protocol": protocol,
                "source": peer[0],
                "token": payload.decode("ascii").strip(),
            }
        ),
        flush=True,
    )


class Stream(socketserver.BaseRequestHandler):
    """Echo one complete newline-terminated TCP probe from the observer or client."""

    def handle(self):
        """Read and reflect the complete marker so split TCP writes remain comparable."""
        self.request.settimeout(2)
        with self.request.makefile("rb") as stream:
            payload = stream.readline(256)
        record(self.server, "tcp", self.client_address, payload)
        self.request.sendall(payload)


class Datagram(socketserver.BaseRequestHandler):
    """Echo each UDP datagram to its source and record it independently of gateway logs."""

    def handle(self):
        """Return the unchanged datagram and log its receiving service address."""
        payload, sock = self.request
        record(self.server, "udp", self.client_address, payload)
        sock.sendto(payload, self.client_address)


def serve():
    """Run TCP/X, UDP/X and UDP/Y listeners inside the controlled remote namespace."""
    servers = []
    for target, kind, handler in [
        (X, socketserver.ThreadingTCPServer, Stream),
        (X, socketserver.ThreadingUDPServer, Datagram),
        (Y, socketserver.ThreadingUDPServer, Datagram),
    ]:
        server = kind((target, PORT), handler)
        server.daemon_threads = True
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print("READY", flush=True)
    threading.Event().wait()


def control(stage):
    """Send independent LAN markers to detect any change in the actual forwarding route."""
    for target, proto in [(X, "tcp"), (Y, "udp"), (X, "udp")]:
        marker = f"client-{stage}-{proto}-{target}"
        payload = (marker + "\n").encode("ascii")
        kind = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
        with socket.socket(socket.AF_INET, kind) as sock:
            sock.settimeout(0.4)
            sock.connect((target, PORT))
            sock.sendall(payload)
            try:
                if proto == "tcp":
                    with sock.makefile("rb") as stream:
                        got = stream.readline(256)
                else:
                    got = sock.recv(256)
            except TimeoutError:
                if not (stage == "impaired" and proto == "udp" and target == X):
                    raise
                got = None
            if got is not None and got != payload:
                raise ValueError("incorrect control echo")
            print(
                json.dumps(
                    {
                        "phase": stage,
                        "target": target,
                        "protocol": proto,
                        "token": marker,
                        "received": got == payload,
                    }
                ),
                flush=True,
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("server", "control"))
    parser.add_argument("stage", nargs="?")
    args = parser.parse_args()
    if args.command == "server":
        serve()
    else:
        control(args.stage)
