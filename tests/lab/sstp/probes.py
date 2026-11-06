#!/usr/bin/env python3
"""Compare equal IPv4/UDP five-tuples across isolated SSTP client namespaces."""
import argparse
import ipaddress
import json
from pathlib import Path
import secrets
import socket
import subprocess
import time

PATHS = ("FI1", "FI2")
PHASES = ("baseline", "impaired", "recovery")
SOURCE = "172.16.3.33"
SOURCE_PORT = 34000
PORT = 19091
COUNT = 5
INTERVAL_NS = 150_000_000


def emit(record):
    """Write a flushed JSON record for timing and later packet correlation."""
    print(json.dumps(record), flush=True)


def server(path, target):
    """Echo UDP markers from this SSTP server with its path ID and the observed client address."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((target, PORT))
        print("READY", flush=True)
        while True:
            data, peer = sock.recvfrom(256)
            record = dict(token=data.decode("ascii"), server=path, source=peer[0],
                          source_port=peer[1], target=target)
            emit(record)
            sock.sendto(json.dumps(record).encode(), peer)


def sample(phase, path, target):
    """Send a fixed-cadence five-tuple on one SSTP path and match replies within a bounded window."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((SOURCE, SOURCE_PORT))
        sock.connect((target, PORT))
        start = time.monotonic_ns()
        records = {}
        for index in range(COUNT):
            scheduled = start + index * INTERVAL_NS
            time.sleep(max(0, scheduled - time.monotonic_ns()) / 1e9)
            token = f"{phase}-{path}-{index}-{secrets.token_hex(8)}"
            records[token] = dict(token=token, sent_ns=time.monotonic_ns(), reply=None)
            sock.send(token.encode())

        # Both paths use the same send schedule and observation window.
        deadline = start + (COUNT - 1) * INTERVAL_NS + 600_000_000
        while (remaining := deadline - time.monotonic_ns()) > 0:
            sock.settimeout(remaining / 1e9)
            try:
                reply = json.loads(sock.recv(512))
            except socket.timeout:
                break
            if reply["token"] in records:
                records[reply["token"]]["reply"] = reply
    emit(dict(phase=phase, path=path, target=target, records=list(records.values())))


def read_capture(out, path, target, reply):
    """Extract test requests or replies with the exact UDP five-tuple for one PPP capture."""
    source, sport, dest, dport = SOURCE, SOURCE_PORT, target, PORT
    if reply:
        source, sport, dest, dport = dest, dport, source, sport
    expr = f"udp and src host {source} and src port {sport} and dst host {dest} and dst port {dport}"
    return subprocess.check_output(["tcpdump", "-nn", "-A", "-r", str(out / f"{path}.pcap"), expr],
                                   stderr=subprocess.PIPE)


def verify(out, target):
    """Prove both SSTP paths are distinguishable despite identical five-tuples and overlapping probes."""
    packets = {(path, reply): read_capture(out, path, target, reply) for path in PATHS for reply in (False, True)}
    servers = {}
    for path in PATHS:
        lines = (out / f"server-{path}.jsonl").read_text().splitlines()
        assert lines[0] == "READY", path
        servers[path] = [json.loads(line) for line in lines[1:]]
    known = set()
    for phase in PHASES:
        windows = []
        counts = {}
        for path in PATHS:
            sample_data = json.loads((out / f"{phase}-{path}.json").read_text())
            assert (sample_data["path"], sample_data["phase"], sample_data["target"]) == (path, phase, target)
            records = sample_data["records"]
            assert len(records) == COUNT
            times = [row["sent_ns"] for row in records]
            assert times == sorted(set(times))
            assert all(abs((t - times[0]) - i * INTERVAL_NS) < 100_000_000
                       for i, t in enumerate(times)), ("send schedule drift", times)
            windows.append((min(times), max(times)))
            delivered = (phase, path) != ("impaired", "FI1")
            counts[path] = sum(row["reply"] is not None for row in records)
            for index, row in enumerate(records):
                token = row["token"]
                assert token.startswith(f"{phase}-{path}-{index}-") and token not in known
                known.add(token)
                expected = dict(token=token, server=path, source=SOURCE, source_port=SOURCE_PORT, target=target)
                assert row["reply"] == (expected if delivered else None), (phase, path, token)
                for iface in PATHS:
                    hits = [event for event in servers[iface] if event["token"] == token]
                    assert hits == ([expected] if iface == path and delivered else [])
                    for reply in (False, True):
                        present = token.encode() in packets[iface, reply]
                        assert present == (iface == path and (not reply or delivered)), (iface, token, reply)
        assert max(start for start, _ in windows) < min(end for _, end in windows), "sampling windows did not overlap"
        print(f"PASS {phase}: FI1 {counts['FI1']}/{COUNT}, FI2 {counts['FI2']}/{COUNT}; same five-tuple, overlapping samples")
    assert all(event["token"] in known for events in servers.values() for event in events)


def main():
    """Run the SSTP server, sample one path, or replay a saved duplicate-address experiment."""
    cli = argparse.ArgumentParser(description=__doc__)
    cmds = cli.add_subparsers(dest="command", required=True)
    listener = cmds.add_parser("server")
    listener.add_argument("path", choices=PATHS)
    client = cmds.add_parser("sample")
    client.add_argument("phase", choices=PHASES)
    client.add_argument("path", choices=PATHS)
    check = cmds.add_parser("verify")
    check.add_argument("out", type=Path)
    for cmd in (listener, client, check):
        cmd.add_argument("target", type=lambda s: str(ipaddress.IPv4Address(s)))
    args = cli.parse_args()
    if not __debug__:
        cli.exit(2, "Enable assertions for the lab\n")
    if args.command == "server":
        server(args.path, args.target)
    elif args.command == "sample":
        sample(args.phase, args.path, args.target)
    else:
        verify(args.out, args.target)


if __name__ == "__main__":
    main()
