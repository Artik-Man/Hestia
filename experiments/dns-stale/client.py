"""Issue real DNS requests and fresh TCP/UDP flows across failure, denial and authoritative recovery."""

import concurrent.futures
import json
import socket
import sys
import time
from pathlib import Path

import dns.message
from authority import TTL, peer

TIMED = "wait.only-fi.lab.test"
NX = "missing.only-fi.lab.test"
EMPTY = "empty.only-fi.lab.test"
RU = "control.lab.test"
TESTED = (TIMED, NX, EMPTY)
STAGES = (
    "seed",
    "failed",
    "no-revival",
    "fi-down",
    "ru-control",
    "reseed",
    "second",
    "beyond",
    "recovered",
)


def change(out: Path, values: dict) -> None:
    """Atomically select per-domain authoritative response modes for the next phase."""
    temp = out / "authority-next"
    temp.write_text(json.dumps(values) + "\n")
    temp.replace(out / "authority-state.json")


def mark(out: Path, phase: str, side: str) -> None:
    """Capture both monotonic and wall time to compare original TTL with wire-level events."""
    with (out / "events.jsonl").open("a") as stream:
        print(
            json.dumps(
                {
                    "phase": phase,
                    "side": side,
                    "ns": time.monotonic_ns(),
                    "wall_ns": time.time_ns(),
                }
            ),
            file=stream,
        )


def query(name: str) -> dict:
    """Query the LAN DNS with a client deadline longer than the upstream timeout and decode rcode, TTL and A."""
    msg = dns.message.make_query(name, "A")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(6)
        sock.connect(("10.85.0.1", 53))
        sock.send(msg.to_wire())
        reply = dns.message.from_wire(sock.recv(4096))
    assert msg.is_response(reply)
    return {
        "name": name,
        "rcode": reply.rcode(),
        "fake": peer.fixture.unpack(reply),
        "ttl": reply.answer[0].ttl if reply.answer else None,
    }


def flow(name: str, fake: str, phase: str, proto: str, source_port: int) -> dict:
    """Send a unique TCP/UDP token to an earlier FakeIP and record actual socket-level delivery or denial."""
    token = f"{phase}-{name}-{proto}"
    kind = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.settimeout(4.5)
        sock.bind(("", source_port))
        try:
            sock.connect((fake, peer.PORT))
            sock.sendall((token + "\n").encode())
            data = sock.makefile("rb").readline() if proto == "tcp" else sock.recv(512)
            reply = json.loads(data) if data else None
            error = None if data else "EOF"
        except OSError as exc:
            reply, error = None, str(exc)
    return {
        "name": name,
        "fake": fake,
        "phase": phase,
        "proto": proto,
        "port": source_port,
        "token": token,
        "reply": reply,
        "error": error,
    }


def stage(out: Path, phase: str, names: tuple, initial: dict) -> None:
    """Launch a LAN DNS query and two independent data probes per name, using only previously issued FakeIPs."""
    mark(out, phase, "begin")
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        requests = {n: pool.submit(query, n) for n in names}
        probes = []
        for i, n in enumerate(names):
            for j, proto in enumerate(("tcp", "udp")):
                port = 40000 + 100 * STAGES.index(phase) + i * 4 + j
                probes.append(pool.submit(flow, n, initial[n], phase, proto, port))
        dns_results = [f.result() for f in requests.values()]
        data_results = [f.result() for f in probes]
    (out / (phase + "-dns.json")).write_text(json.dumps(dns_results) + "\n")
    (out / (phase + "-flows.json")).write_text(json.dumps(data_results) + "\n")
    mark(out, phase, "end")


def exercise(out: Path) -> None:
    """Use two real time windows, an independent positive control, explicit-policy failure and fresh generation B."""
    config = json.loads((out / "settings.json").read_text())
    leases = {n: query(n) for n in TESTED + (RU,)}
    assert all(r["rcode"] == 0 and r["fake"] for r in leases.values())
    aliases = {n: r["fake"] for n, r in leases.items()}
    (out / "seed-answers.json").write_text(json.dumps(leases) + "\n")
    seeded = time.monotonic()
    stage(out, "seed", TESTED, aliases)
    time.sleep(max(0.0, seeded + TTL + 0.18 - time.monotonic()))
    change(out, {TIMED: "drop", NX: "nx", EMPTY: "empty"})
    stage(out, "failed", TESTED, aliases)
    change(out, {TIMED: "servfail", NX: "servfail", EMPTY: "servfail"})
    stage(out, "no-revival", (NX, EMPTY), aliases)
    stage(out, "second", (TIMED,), aliases)
    # Cross the original deadline, not a deadline relative to the latest stale read.
    (out / "seeded-ns").write_text(str(int(seeded * 10**9)) + "\n")
    due = seeded + TTL + max(0, config["stale_seconds"]) + 0.22
    time.sleep(max(0.0, due - time.monotonic()))
    stage(out, "beyond", (TIMED,), aliases)
    # Reseed A only after proving expiry, so the eligibility test cannot erase evidence needed for the cap.
    change(out, {TIMED: "old"})
    stage(out, "reseed", (TIMED,), aliases)
    time.sleep(TTL + 0.15)
    change(out, {TIMED: "servfail"})
    (out / "fi-unavailable").touch()
    stage(out, "fi-down", (TIMED,), aliases)
    stage(out, "ru-control", (RU,), aliases)
    (out / "fi-unavailable").unlink()
    change(out, {n: "new" for n in TESTED})
    stage(out, "recovered", TESTED, aliases)


if __name__ == "__main__":
    if not __debug__:
        sys.exit("Enable assertions")
    exercise(Path(sys.argv[2]))
