#!/usr/bin/env python3
"""DNS probe, independent echo receiver and capture assertions for the FakeIP lab."""
import concurrent.futures
import ipaddress
import json
from pathlib import Path
import secrets
import select
import socket
import struct
import sys

PORT = 19091
GROUPS = {"RU": "10.88.1.1", "FI": "10.88.2.1"}
REAL = "203.0.113.77"
DNS_ADDRESS = "192.0.2.53"


def fake_address(name):
    """Resolve a test domain and validate that its sole A record belongs to the FakeIP range."""
    transaction = secrets.token_bytes(2)
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
    question = labels + b"\0" + struct.pack("!HH", 1, 1)
    query = transaction + struct.pack("!HHHHH", 0x100, 1, 0, 0, 0) + question
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(4)
        sock.connect((DNS_ADDRESS, 53))
        sock.send(query)
        reply = sock.recv(4096)
    header = struct.unpack("!HHHHHH", reply[:12])
    assert reply[:2] == transaction and header[1] & 0x8000 and not header[1] & 0xf
    assert header[2:4] == (1, 1) and reply[12:12 + len(question)] == question
    offset = 12 + len(question)
    if reply[offset] & 0xc0 == 0xc0:
        offset += 2
    else:
        while reply[offset]:
            offset += reply[offset] + 1
        offset += 1
    kind, cls, _, size = struct.unpack_from("!HHIH", reply, offset)
    assert (kind, cls, size) == (1, 1, 4)
    value = ipaddress.IPv4Address(reply[offset + 10:offset + 14])
    assert value in ipaddress.ip_network("198.18.0.0/15"), value
    return str(value)


def server(path=None):
    """Listen for TCP and UDP probes on the real service address and echo the observed path."""
    with socket.socket() as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        tcp.bind((REAL, PORT))
        tcp.listen()
        udp.bind((REAL, PORT))
        print('READY', flush=True)
        while True:
            for active in select.select([tcp, udp], [], [])[0]:
                if active is tcp:
                    conn, peer = tcp.accept()
                    with conn:
                        conn.settimeout(4)
                        data = conn.makefile("rb").readline(256)
                        conn.sendall(response(peer, data, 'tcp', path))
                else:
                    data, peer = udp.recvfrom(256)
                    udp.sendto(response(peer, data, 'udp', path), peer)


def response(peer, data, proto, path=None):
    """Record the actual source and token, optionally add the labelled server path, and encode the echo."""
    result = dict(proto=proto, peer=peer[0], target=REAL, token=data.decode().strip())
    if path is not None:
        result["server"] = path
    print(json.dumps(result), flush=True)
    return (json.dumps(result) + "\n").encode()


def probe(group, address, proto):
    """Send a tagged request to a FakeIP and verify the echo came from the expected group exit."""
    token = f"{group}-{proto}-{secrets.token_hex(6)}"
    kind = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.settimeout(5)
        sock.connect((address, PORT))
        sock.sendall((token + "\n").encode())
        data = sock.makefile("rb").readline() if proto == "tcp" else sock.recv(512)
        result = json.loads(data)
    assert result["peer"] == GROUPS[group] and result["proto"] == proto
    assert result["token"] == token and result["target"] == REAL
    return dict(group=group, domain=f"{group.lower()}.lab.test", fake=address, **result)


def client():
    """Resolve both domains once, concurrently probe each FakeIP over TCP and UDP, and report replies."""
    addresses = {g: fake_address(f"{g.lower()}.lab.test") for g in GROUPS}
    assert len(set(addresses.values())) == len(GROUPS)
    with concurrent.futures.ThreadPoolExecutor() as pool:
        futures = [pool.submit(probe, g, addresses[g], proto)
                   for g in GROUPS for proto in ("tcp", "udp")]
        records = [f.result() for f in futures]
    print(json.dumps(records, indent=2))


def verify(root):
    """Require all four distinct markers on their assigned interfaces and absent on the opposite exits."""
    records = json.loads((root / "client.json").read_text())
    expected = {(group, proto) for group in GROUPS for proto in ("tcp", "udp")}
    assert len(records) == 4 and {(r["group"], r["proto"]) for r in records} == expected
    assert len({r["token"] for r in records}) == 4
    for group in GROUPS:
        capture = (root / (group.lower() + ".txt")).read_bytes()
        for record in records:
            present = record['token'].encode() in capture
            assert present == (record['group'] == group), (group, record, present)
    print("PASS: distinct FakeIPs; TCP+UDP echoes from one real IP; all four markers on the correct uplink only.")


if __name__ == "__main__":
    if not __debug__:
        sys.exit("Run without python -O or PYTHONOPTIMIZE so lab assertions stay enabled")
    if sys.argv[1] == "server":
        server()
    elif sys.argv[1] == "client":
        client()
    else:
        verify(Path(sys.argv[2]))
