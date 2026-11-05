"""Serve synthetic UDP DNS and TCP handshakes in a disconnected test namespace."""
import selectors
import socket
from pathlib import Path


def serve() -> None:
    """Return DNS replies unless the simulated fault flag exists; accept TCP on both control addresses."""
    poll = selectors.DefaultSelector()
    for address in ("1.1.1.1", "8.8.8.8"):
        for kind, port in ((socket.SOCK_DGRAM, 53), (socket.SOCK_STREAM, 443)):
            sock = socket.socket(socket.AF_INET, kind)
            sock.bind((address, port))
            if kind == socket.SOCK_STREAM:
                sock.listen()
            poll.register(sock, selectors.EVENT_READ)
    while True:
        for key, _ in poll.select():
            sock = key.fileobj
            if sock.type == socket.SOCK_STREAM:
                peer, _ = sock.accept()
                peer.close()
            else:
                query, sender = sock.recvfrom(4096)
                if not Path("drop-udp").exists():
                    if Path("dns-servfail").exists():
                        response = query[:2] + bytes.fromhex("8182") + query[4:]
                    else:
                        answer = bytes.fromhex("c00c000100010000001e0004") + socket.inet_aton("1.1.1.1")
                        response = query[:2] + bytes.fromhex("81800001000100000000") + query[12:] + answer
                    sock.sendto(response, sender)


if __name__ == "__main__":
    serve()
