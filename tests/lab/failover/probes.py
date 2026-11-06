#!/usr/bin/env python3
"""Client and resolver fixtures and wire checks for the isolated failover experiment."""
import argparse
import concurrent.futures
import errno
import json
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fakeip"))
from traffic import PORT, REAL, fake_address, server

PHASES = ("warm", "gate", "failover", "blocked", "control", "recovery")
DENIED = {"gate", "blocked"}
FRESH_PHASES = {"warm", *DENIED}
RU = "10.88.1.1"
FI1 = "10.88.2.1"
FI2 = "10.88.3.1"
FI = {"warm": FI1, "gate": None, "failover": FI2, "blocked": None, "recovery": FI2}
INTERFACES = {"ru0": RU, "fi1": FI1, "fi2": FI2}


def report(**event):
    """Write one timestamped JSON Lines record describing a probe or fixture event."""
    print(json.dumps(dict(at_ns=time.time_ns(), **event)), flush=True)


def dns_answer(query):
    # This lab resolver accepts single uncompressed IN questions for our suffix.
    """Parse a lab DNS question and encode its test A record, empty answer or NXDOMAIN response."""
    if len(query) < 17 or query[4:6] != b"\x00\x01":
        raise ValueError("expected one DNS question")
    end = 12
    labels = []
    while query[end]:
        size = query[end]
        if size > 63 or end + 1 + size >= len(query):
            raise ValueError("invalid DNS label")
        labels.append(query[end + 1:end + 1 + size].decode("ascii"))
        end += size + 1
    question_end = end + 5
    kind, cls = struct.unpack("!HH", query[end + 1:question_end])
    qname = ".".join(labels).lower()
    in_zone = qname.endswith(".lab.test")
    positive = in_zone and kind == 1 and cls == 1
    flags = 0x8480 | (query[2] & 1) << 8 | (0 if in_zone else 3)
    header = query[:2] + struct.pack("!HHHHH", flags, 1, int(positive), 0, 0)
    reply = header + query[12:question_end]
    if positive:
        reply += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton(REAL)
    return reply, qname, kind


def dns_server():
    """Serve the test resolver on the real service address and log incoming DNS questions."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((REAL, 53))
        print("READY", flush=True)
        while True:
            query, peer = sock.recvfrom(4096)
            try:
                reply, name, kind = dns_answer(query)
            except (IndexError, ValueError, struct.error):
                continue
            report(qname=name, qtype=kind, peer=peer[0], peer_port=peer[1])
            sock.sendto(reply, peer)


def initialize(path):
    """Query and store the distinct RU and FI FakeIPs that the client will reuse after failover."""
    addresses = {name: fake_address(name) for name in ("ru.lab.test", "fi.lab.test")}
    assert len(set(addresses.values())) == 2, addresses
    with path.open("x") as stream:
        json.dump(addresses, stream)
    report(addresses=addresses)


def probe(phase, domain, fake, proto, expected, port):
    """Send a uniquely marked TCP or UDP flow and check delivery or expected blocking for one exit."""
    token = f"{phase}-{proto}-{secrets.token_hex(8)}"
    event = dict(phase=phase, domain=domain, fake=fake, proto=proto,
                 expected_peer=expected, token=token, source_port=port)
    stream = proto == "tcp"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if stream else socket.SOCK_DGRAM) as sock:
        sock.settimeout(4)
        sock.bind(("", port))
        try:
            sock.connect((fake, PORT))
            sock.sendall((token + "\n").encode())
            data = sock.makefile("rb").readline(512) if stream else sock.recv(512)
        except OSError as exc:
            if expected or exc.errno not in (None, errno.ECONNRESET, errno.ECONNREFUSED,
                                              errno.EPIPE, errno.EHOSTUNREACH, errno.ENETUNREACH):
                raise
            report(**event, outcome="blocked", error=str(exc))
            return
    if not data and expected is None and stream:
        report(**event, outcome="blocked", error="EOF")
        return
    assert expected is not None, ("unexpected reply to blocked flow", event, data)
    result = json.loads(data)
    assert result == dict(peer=expected, proto=proto, target=REAL, token=token), (event, result)
    report(**event, outcome="echo", peer=result["peer"])


def phase_probes(state, phase):
    """Issue the phase's control and test flows, including fresh DNS queries in selected phases."""
    addresses = json.loads(state.read_text())
    if phase in DENIED:
        del addresses["ru.lab.test"]
    elif phase == "control":
        del addresses["fi.lab.test"]
    if phase in FRESH_PHASES:
        name = f"{phase}-{secrets.token_hex(8)}.fi.lab.test"
        addresses[name] = fake_address(name)
        report(phase=phase, fresh_domain=name, fake=addresses[name])
    with concurrent.futures.ThreadPoolExecutor() as pool:
        futures = []
        port = 24000 + PHASES.index(phase) * 100
        for domain, fake in addresses.items():
            expected = RU if domain == "ru.lab.test" else FI[phase]
            for proto in ("tcp", "udp"):
                futures.append(pool.submit(probe, phase, domain, fake, proto, expected, port))
                port += 1
        for future in futures:
            future.result()


def captured(path, expr, *, ascii=False):
    # -S retains original sequence numbers to distinguish independent TCP attempts.
    """Read packets matching an expression from a saved capture, optionally including their payload."""
    args = ["tcpdump", "-nn", "-S", "-r", str(path)]
    if ascii:
        args.append("-A")
    return subprocess.check_output([*args, expr], stderr=subprocess.PIPE)


def verify(out):
    """Verify per-phase routing, blocked data and DNS, and RU control traffic against all three captures."""
    issued = json.loads((out / "state.json").read_text())
    assert set(issued) == {"ru.lab.test", "fi.lab.test"} and len(set(issued.values())) == 2
    seen_ports = set()
    dns = [json.loads(line) for line in (out / "dns.log").read_text().splitlines() if line.startswith("{")]
    for phase in PHASES:
        rows = [json.loads(line) for line in (out / f"{phase}.jsonl").read_text().splitlines()]
        fresh = [row["fresh_domain"] for row in rows if "fresh_domain" in row]
        assert len(fresh) == int(phase in FRESH_PHASES), (phase, fresh)
        flows = [row for row in rows if "token" in row]
        domains = {"ru.lab.test", "fi.lab.test", *fresh}
        if phase in DENIED:
            domains.remove("ru.lab.test")
        elif phase == "control":
            domains.remove("fi.lab.test")
        assert {(r["domain"], r["proto"]) for r in flows} == {
            (domain, proto) for domain in domains for proto in ("tcp", "udp")}
        assert len(flows) == 2 * len(domains)
        for row in flows:
            if row["domain"] in issued:
                assert row["fake"] == issued[row["domain"]], (phase, row, issued)
            assert row["source_port"] not in seen_ports, (phase, row)
            seen_ports.add(row["source_port"])
        for dev, peer in INTERFACES.items():
            path = out / f"{phase}-{dev}.pcap"
            data = captured(path, f"dst host {REAL} and dst port {PORT}", ascii=True)
            for row in flows:
                expected = RU if row["domain"] == "ru.lab.test" else FI[phase]
                assert row["expected_peer"] == expected
                assert row["outcome"] == ("echo" if expected else "blocked"), row
                assert (row["token"].encode() in data) == (peer == expected), (dev, row)
            if fresh:
                expected_dns_peer = FI1 if phase == "warm" else None
                requests = captured(path, f"udp and dst host {REAL} and dst port 53").lower()
                found = fresh[0].encode() + b"." in requests
                assert found == (peer == expected_dns_peer), (phase, dev, fresh, requests)
            if dev == "ru0":
                witness = captured(path, "udp and dst host 10.88.1.2 and dst port 19092", ascii=True)
                assert f"capture-live-{phase}".encode() in witness, (phase, "missing capture control")
            if phase in DENIED:
                # No FI traffic can appear on any uplink, even a SYN without its marker.
                wires = captured(path, f"dst host {REAL} and (dst port {PORT} or dst port 53)")
                assert not wires, (phase, dev, wires)
        if fresh:
            peers = {r["peer"] for r in dns if r["qname"] == fresh[0] and r["qtype"] == 1}
            assert peers == ({FI1} if phase == "warm" else set()), (phase, fresh, peers)
        print(f"PASS {phase}: verified {len(flows)} probe outcomes on three uplinks")


def main():
    """Run a selected client, echo/DNS server, or saved-capture verification command."""
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    subs.add_parser("dns-server")
    subs.add_parser("echo-server")
    subs.add_parser("init").add_argument("state", type=Path)
    phase = subs.add_parser("phase")
    phase.add_argument("state", type=Path)
    phase.add_argument("phase", choices=PHASES)
    subs.add_parser("verify").add_argument("out", type=Path)
    args = parser.parse_args()
    if not __debug__:
        sys.exit("Assertions must be enabled")
    if args.command == "dns-server":
        dns_server()
    elif args.command == "echo-server":
        server()
    elif args.command == "init":
        initialize(args.state)
    elif args.command == "phase":
        phase_probes(args.state, args.phase)
    else:
        verify(args.out)


if __name__ == "__main__":
    main()
