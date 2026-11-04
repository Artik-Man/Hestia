#!/usr/bin/env python3
"""Trace new LAN flows from a cached FakeIP to separately labelled SSTP echo servers."""
import argparse
import concurrent.futures
import errno
import ipaddress
import json
from pathlib import Path
import secrets
import socket
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fakeip"))
from traffic import DNS_ADDRESS, PORT, REAL, fake_address, server

NAME = "fi.lab.test"
LAN = "10.88.0.2"
INNER = "172.16.3.33"
PATHS = {"baseline": "FI1", "disconnected": None, "failover": "FI2"}
SERVERS = ("FI1", "FI2")
PROTOCOLS = ("tcp", "udp")


def probe(phase, proto, fake):
    token = f"{phase}-{proto}-{secrets.token_hex(8)}"
    kind = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
    port = 33100 + list(PATHS).index(phase) * 10 + PROTOCOLS.index(proto)
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind((LAN, port))
        sock.settimeout(2 if PATHS[phase] is None else 5)
        try:
            sock.connect((fake, PORT))
            sock.sendall((token + "\n").encode())
            data = sock.makefile("rb").readline(512) if proto == "tcp" else sock.recv(512)
        except OSError as exc:
            if PATHS[phase] or exc.errno not in (None, errno.ECONNRESET, errno.ECONNREFUSED,
                                                  errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EPIPE):
                raise
            data = b""
    reply = json.loads(data) if data else None
    expected = dict(proto=proto, peer=INNER, target=REAL, token=token, server=PATHS[phase])
    assert reply == (expected if PATHS[phase] else None), (phase, reply)
    return dict(phase=phase, proto=proto, token=token, fake=fake, source_port=port, reply=reply)


def read_pcap(path, expr):
    return subprocess.check_output(["tcpdump", "-nn", "-A", "-r", str(path), expr],
                                   stderr=subprocess.PIPE)


def verify(out):
    issued = json.loads((out / "state.json").read_text())
    fake = issued[NAME]
    assert ipaddress.ip_address(fake) in ipaddress.ip_network("198.18.0.0/15")
    lan = out / "ingress.pcap"
    queries = read_pcap(lan, f"udp and src host {LAN} and dst host {DNS_ADDRESS} and dst port 53")
    assert queries.count(f"A? {NAME}.".encode()) == 1, queries
    endpoints = {}
    servers = {}
    for path in SERVERS:
        pcap = out / f"{path}.pcap"
        lines = (out / f"server-{path}.jsonl").read_text().splitlines()
        assert lines[0] == "READY", path
        servers[path] = [json.loads(line) for line in lines[1:]]
        for proto in PROTOCOLS:
            endpoints[path, proto] = (
                read_pcap(pcap, f"{proto} and src host {INNER} and dst host {REAL} and dst port {PORT}"),
                read_pcap(pcap, f"{proto} and src host {REAL} and src port {PORT} and dst host {INNER}"))
    seen_tokens, seen_ports = set(), set()
    for phase, selected in PATHS.items():
        rows = [json.loads(line) for line in (out / f"{phase}.jsonl").read_text().splitlines()]
        assert len(rows) == len(PROTOCOLS) and {r["proto"] for r in rows} == set(PROTOCOLS)
        for row in rows:
            reply = row["reply"]
            proto, token, port = row["proto"], row["token"], row["source_port"]
            assert row["phase"] == phase and row["fake"] == fake
            assert token.startswith(f"{phase}-{proto}-") and token not in seen_tokens
            assert port not in seen_ports
            seen_tokens.add(token)
            seen_ports.add(port)
            expected = dict(proto=proto, token=token, target=REAL, peer=INNER, server=selected)
            assert reply == (expected if selected else None)
            marker = token.encode()
            for path in SERVERS:
                for dump in endpoints[path, proto]:
                    assert (marker in dump) == (path == selected), (path, token)
                hits = [r for r in servers[path] if r["token"] == token]
                assert hits == ([reply] if path == selected else []), (path, token, hits)
            tx = f"{proto} and src host {LAN} and src port {port} and dst host {fake} and dst port {PORT}"
            rx = f"{proto} and src host {fake} and src port {PORT} and dst host {LAN} and dst port {port}"
            if proto == "tcp":
                assert read_pcap(lan, tx + " and tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn")
            if selected or proto == "udp":
                assert marker in read_pcap(lan, tx)
            assert (marker in read_pcap(lan, rx)) == bool(selected)
        print(f"PASS {phase}: TCP and UDP used {selected or 'no exit'}, original FakeIP {fake}")
    # Exclude unmarked leaks, such as an attempted reserve TCP connection with no payload.
    for expr in ("tcp and tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn", "udp"):
        service = f"src host {INNER} and dst host {REAL} and dst port {PORT}"
        packets = subprocess.check_output(["tcpdump", "-nn", "-r", str(out / "FI2.pcap"),
                                           f"{service} and {expr}"], stderr=subprocess.PIPE)
        assert len(packets.splitlines()) == 1, packets
    assert all(row["token"] in seen_tokens for records in servers.values() for row in records)
    print("PASS: one client DNS query; each marker reached only its selected SSTP server")


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    sub = cli.add_subparsers(dest="command", required=True)
    sub.add_parser("server").add_argument("path", choices=SERVERS)
    sub.add_parser("init")
    phase = sub.add_parser("phase")
    phase.add_argument("phase", choices=PATHS)
    phase.add_argument("state", type=Path)
    sub.add_parser("verify").add_argument("out", type=Path)
    args = cli.parse_args()
    if not __debug__:
        cli.exit(2, "Enable assertions for the lab\n")
    if args.command == "server":
        server(args.path)
    elif args.command == "init":
        print(json.dumps({NAME: fake_address(NAME)}))
    elif args.command == "phase":
        fake = json.loads(args.state.read_text())[NAME]
        with concurrent.futures.ThreadPoolExecutor() as pool:
            jobs = [pool.submit(probe, args.phase, proto, fake) for proto in PROTOCOLS]
            for job in jobs:
                print(json.dumps(job.result()))
    else:
        verify(args.out)


if __name__ == "__main__":
    main()
