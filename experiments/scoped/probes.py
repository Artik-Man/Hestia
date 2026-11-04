#!/usr/bin/env python3
"""Isolated IPv4 traffic, comparable per-interface UDP probes, and capture checks."""
import argparse
import concurrent.futures
import contextlib
import json
from pathlib import Path
import secrets
import selectors
import socket
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fakeip"))
from traffic import fake_address

PORT = 19091
TARGETS = dict(x="203.0.113.77", y="203.0.113.78", z="203.0.113.79")
DESTINATIONS = {**TARGETS, "ru": TARGETS["x"]}
INTERFACES = dict(fi1="10.88.2.1", fi2="10.88.3.1")
SOURCES = {**INTERFACES, "ru0": "10.88.1.1"}
PHASES = ("baseline", "impaired", "switched")
PROBES = [(name, proto, mode) for mode in ("ip", "fake")
          for name, proto in (("x", "udp"), ("x", "tcp"), ("y", "udp"), ("z", "udp"))]
PROBES += [("ru", "tcp", "fake"), ("ru", "udp", "fake")]


def emit(record):
    """Write one flushed JSON record so the lab can correlate observations while captures are active."""
    print(json.dumps(record), flush=True)


def server():
    """Listen at each real test address over TCP and UDP and echo address, token and observed source."""
    with contextlib.ExitStack() as stack:
        poll = stack.enter_context(selectors.DefaultSelector())
        for address in TARGETS.values():
            for proto, kind in (("udp", socket.SOCK_DGRAM), ("tcp", socket.SOCK_STREAM)):
                sock = stack.enter_context(socket.socket(socket.AF_INET, kind))
                sock.bind((address, PORT))
                if proto == "tcp":
                    sock.listen()
                poll.register(sock, selectors.EVENT_READ, (address, proto))
        print("READY", flush=True)
        while True:
            for key, _ in poll.select():
                address, proto = key.data
                listener = key.fileobj
                with contextlib.ExitStack() as connection:
                    if proto == "tcp":
                        sock, peer = listener.accept()
                        connection.enter_context(sock)
                        sock.settimeout(2)
                        reader = connection.enter_context(sock.makefile("rb"))
                        data = reader.readline(256)
                    else:
                        data, peer = listener.recvfrom(256)
                        sock = listener
                    reply = dict(token=data.decode().strip(), peer=peer[0], target=address, proto=proto)
                    emit(reply)
                    payload = (json.dumps(reply) + "\n").encode()
                    if proto == "tcp":
                        sock.sendall(payload)
                    else:
                        sock.sendto(payload, peer)


def exchange(token, address, proto, *, iface=None, port=0, timeout=1.5):
    """Send a marked TCP or UDP request, optionally pin its interface and port, then decode its reply."""
    kind = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.settimeout(timeout)
        if iface:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode() + b"\0")
        sock.bind(("", port))
        sock.connect((address, PORT))
        sock.sendall((token + "\n").encode())
        if proto == "udp":
            data = sock.recv(1024)
        else:
            with sock.makefile("rb") as stream:
                data = stream.readline(1024)
    return json.loads(data)


def expected(phase, name, proto):
    """Return the required interface and delivery expectation for a phase, domain and protocol."""
    if name == "ru":
        return "ru0", True
    override = name == "x" and proto == "udp"
    iface = "fi2" if override and phase == "switched" else "fi1"
    return iface, not (override and phase == "impaired")


def probe(phase, state, index, name, proto, mode):
    """Test one new raw-IP or FakeIP flow and record its unique port, marker and observed response."""
    real = DESTINATIONS[name]
    address = real if mode == "ip" else state[name]
    token = f"flow-{phase}-{mode}-{proto}-{secrets.token_hex(8)}"
    port = 34000 + 100 * PHASES.index(phase) + index
    iface, allowed = expected(phase, name, proto)
    try:
        reply = exchange(token, address, proto, port=port)
    except socket.timeout:
        assert not allowed, (phase, token, address)
        reply = None
    else:
        assert allowed and reply == dict(peer=SOURCES[iface], target=real, proto=proto, token=token), reply
    return dict(phase=phase, name=name, proto=proto, mode=mode, real=real, address=address,
                token=token, source_port=port, reply=reply)


def sample(iface):
    """Send comparable UDP probes to X on a single interface and collect sent and received markers."""
    tokens, received = [], []
    for i in range(5):
        token = f"health-{iface}-{i}-{secrets.token_hex(8)}"
        tokens.append(token)
        try:
            reply = exchange(token, TARGETS["x"], "udp", iface=iface, timeout=0.35)
        except socket.timeout:
            continue
        assert reply == dict(peer=INTERFACES[iface], target=TARGETS["x"], proto="udp", token=token), reply
        received.append(token)
    return dict(iface=iface, target=TARGETS["x"], sent=tokens, received=received)


def choose(rows):
    """Rank the two measured paths by lost probes, preferring the primary on ties."""
    losses = {}
    assert len(rows) == len(INTERFACES)
    for row in rows:
        iface = row["iface"]
        assert iface in INTERFACES and iface not in losses and row["target"] == TARGETS["x"]
        sent, received = set(row["sent"]), set(row["received"])
        assert len(sent) == len(row["sent"]) == 5 and len(received) == len(row["received"])
        assert received <= sent
        losses[iface] = len(sent - received)
    if min(losses.values()) == 5:
        raise RuntimeError("no reachable FI outbound for UDP to X")
    return min(INTERFACES, key=losses.get) + "-out"


def wires(out, iface, real, proto):
    """Extract payload-bearing capture bytes for one real destination, protocol and interface."""
    expr = f"{proto} and dst host {real} and dst port {PORT}"
    return subprocess.check_output(["tcpdump", "-nn", "-A", "-r", str(out / f"continuous-{iface}.pcap"),
                                    expr], stderr=subprocess.PIPE)


def verify(out):
    """Replay measurements and client flows against server records and captures on FI and RU."""
    state = json.loads((out / "state.json").read_text())
    assert set(state) == set(DESTINATIONS) and len(set(state.values())) == len(DESTINATIONS)
    server_rows = [json.loads(line) for line in (out / "server.log").read_text().splitlines()
                   if line.startswith("{")]
    captures = {(iface, name, proto): wires(out, iface, DESTINATIONS[name], proto)
                for iface in (*INTERFACES, "ru0") for name, proto in {(n, p) for n, p, _ in PROBES}}
    seen_ports, seen_tokens = set(), set()
    for phase, winner in (("baseline", "fi1-out"), ("impaired", "fi2-out")):
        samples = json.loads((out / f"{phase}-measure.json").read_text())
        assert choose(samples) == winner
        for row in samples:
            iface = row["iface"]
            delivered = phase == "baseline" or iface == "fi2"
            assert row["received"] == (row["sent"] if delivered else []), row
            for token in row["sent"]:
                assert token not in seen_tokens
                seen_tokens.add(token)
                received = [r for r in server_rows if r["token"] == token]
                reply = dict(token=token, proto="udp", peer=SOURCES[iface], target=TARGETS["x"])
                assert received == ([reply] if delivered else []), (phase, iface, token)
                for dev in SOURCES:
                    assert (token.encode() in captures[dev, "x", "udp"]) == (dev == iface), (token, dev)
        print(f"PASS {phase} health: both interfaces sampled, selected {winner}")
    for phase in PHASES:
        flows = [json.loads(line) for line in (out / f"{phase}.jsonl").read_text().splitlines()]
        assert sorted((r["name"], r["proto"], r["mode"]) for r in flows) == sorted(PROBES)
        for row in flows:
            name, proto, mode = row["name"], row["proto"], row["mode"]
            iface, allowed = expected(phase, name, proto)
            token = row["token"]
            assert row["phase"] == phase and row["real"] == DESTINATIONS[name]
            assert row["address"] == (DESTINATIONS[name] if mode == "ip" else state[name])
            assert row["source_port"] not in seen_ports and token not in seen_tokens
            seen_ports.add(row["source_port"])
            seen_tokens.add(token)
            matches = [r for r in server_rows if r["token"] == token]
            reply = dict(token=token, proto=proto, peer=SOURCES[iface], target=DESTINATIONS[name])
            assert matches == ([reply] if allowed else []) and row["reply"] == (reply if allowed else None), row
            for dev in (*INTERFACES, "ru0"):
                present = token.encode() in captures[dev, name, proto]
                assert present == (dev == iface), (phase, token, dev, present)
        print(f"PASS {phase}: {len(PROBES)} new flows verified by server and captures")


def main():
    """Dispatch sample, selection, server, client phase and offline verification commands."""
    cli = argparse.ArgumentParser(description=__doc__)
    commands = cli.add_subparsers(dest="command", required=True)
    for cmd in ("server", "init", "measure"):
        commands.add_parser(cmd)
    phase = commands.add_parser("phase")
    phase.add_argument("phase", choices=PHASES)
    phase.add_argument("state", type=Path)
    commands.add_parser("choose").add_argument("sample", type=Path)
    commands.add_parser("verify").add_argument("out", type=Path)
    args = cli.parse_args()
    if not __debug__:
        sys.exit("Enable assertions for the lab")
    if args.command == "server":
        server()
    elif args.command == "init":
        state = {name: fake_address(f"{name}.lab.test") for name in DESTINATIONS}
        assert len(set(state.values())) == len(DESTINATIONS)
        emit(state)
    elif args.command == "phase":
        state = json.loads(args.state.read_text())
        with concurrent.futures.ThreadPoolExecutor() as pool:
            futures = [pool.submit(probe, args.phase, state, i, *case) for i, case in enumerate(PROBES)]
            for future in futures:
                emit(future.result())
    elif args.command == "measure":
        with concurrent.futures.ThreadPoolExecutor() as pool:
            emit(list(pool.map(sample, INTERFACES)))
    elif args.command == "choose":
        print(choose(json.loads(args.sample.read_text())))
    elif args.command == "verify":
        verify(args.out)


if __name__ == "__main__":
    main()
