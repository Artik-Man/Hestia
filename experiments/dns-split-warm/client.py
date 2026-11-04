"""Inspect origin-specific FakeIP flows across two FI withdrawal/reentry cycles."""

import json
import socket
import sys
import time
from pathlib import Path

import dns.message
import dns.rcode
from authority import FI_A, RU_A, RU_B, TTLS, peer

HOT = "split.lab.test"
FIXED = "pinned.only-fi.lab.test"
COLD = "cold.lab.test"
NS = 10**9


def log(path: Path, **record) -> None:
    """Append a structured client observation with both clocks for later packet correlation."""
    with path.open("a") as stream:
        print(
            json.dumps(dict(ns=time.monotonic_ns(), wall=time.time_ns(), **record)),
            file=stream,
        )


def boundary(out: Path, name: str) -> None:
    """Record a named policy or authority change boundary."""
    log(out / "events.jsonl", event=name)


def query(out: Path, name: str, phase: str) -> dict:
    """Issue a fresh LAN IN/A DNS request and retain actual RCODE, FakeIP, TTL and request interval."""
    q = dns.message.make_query(name, "A")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        sock.connect(("10.85.0.1", 53))
        started = time.time_ns()
        sock.send(q.to_wire())
        reply = dns.message.from_wire(sock.recv(4096))
    assert q.is_response(reply)
    info = {
        "domain": name,
        "phase": phase,
        "code": reply.rcode(),
        "fake": peer.fixture.unpack(reply),
        "ttl": reply.answer[0].ttl if reply.answer else None,
        "start_wall": started,
        "txid": q.id,
    }
    log(out / "dns-client.jsonl", **info)
    return info


def streams(
    out: Path,
    aliases: dict,
    domain: str,
    phase: str,
    group: str | None,
    address: str | None,
) -> None:
    """Send unique new TCP and UDP flows to the originally issued FakeIP, requiring exact destination/egress or denial."""
    prior = (
        (out / "flows.jsonl").read_text().splitlines()
        if (out / "flows.jsonl").exists()
        else []
    )
    for i, proto in enumerate(("tcp", "udp")):
        port = 41500 + len(prior) + i
        token = f"{phase}-{domain}-{proto}"
        with socket.socket(
            socket.AF_INET, socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
        ) as sock:
            sock.settimeout(0.7)
            sock.bind(("", port))
            start = time.time_ns()
            try:
                sock.connect((aliases[domain], peer.PORT))
                sock.sendall((token + "\n").encode())
                b = sock.makefile("rb").readline() if proto == "tcp" else sock.recv(512)
                result = json.loads(b) if b else None
            except (OSError, TimeoutError):
                result = None
        log(
            out / "flows.jsonl",
            phase=phase,
            domain=domain,
            proto=proto,
            token=token,
            port=port,
            fake=aliases[domain],
            start_wall=start,
            reply=result,
        )
        if group is None:
            assert result is None, (domain, result)
        else:
            assert result == {
                "ip": address,
                "source": {"fi": "10.85.2.1", "ru": "10.85.1.1"}[group],
                "proto": proto,
                "group": group,
                "token": token,
            }, (phase, result, address)


def wait_warm(out: Path, since: int, address: str) -> None:
    """Wait for a completed background RU reply after the supplied boundary while the name remains hot."""
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        with (out / "decisions.log").open("rb") as f:
            completed = [
                json.loads(row)
                for row in f
                if row.startswith(b"{") and row.endswith(b"\n")
            ]
        if any(
            r["event"] == "warm-finish"
            and r.get("group") == "ru"
            and r.get("domain") == HOT
            and r.get("ip") == address
            and r["ns"] > since
            for r in completed
        ):
            return
        time.sleep(0.012)
    raise RuntimeError(f"expected RU background reply: {address}")


def state(out: Path, generation: str) -> None:
    """Atomically change only RU's authoritative A generation."""
    tmp = out / "next"
    tmp.write_text(generation + "\n")
    tmp.replace(out / "ru-state")
    boundary(out, generation)


def run(out: Path, mode: str) -> None:
    """Compare cold demand, earlier warm behavior, and corrected reuse under restored policy views."""
    aliases = {}
    for n in (HOT, FIXED, COLD):
        aliases[n] = query(out, n, "seed")["fake"]
        assert aliases[n]
    assert len(set(aliases.values())) == 3
    (out / "aliases.json").write_text(json.dumps(aliases) + "\n")
    for _ in range(2):
        for n in (HOT, FIXED):
            assert query(out, n, "frequency")["fake"] == aliases[n]
    streams(out, aliases, HOT, "initial", "fi", FI_A)
    streams(out, aliases, FIXED, "initial", "fi", FI_A)
    streams(out, aliases, COLD, "initial", "fi", FI_A)
    # Ensure the slower initial RU authority has returned generation one to HOT and COLD.
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        initial = [
            json.loads(r)
            for r in (out / "ru-peer.log").read_text().splitlines()
            if r.startswith("{")
        ]
        available = {
            r["domain"]
            for r in initial
            if r["event"] == "authority" and r["generation"] == "first"
        }
        if {HOT, COLD} <= available:
            break
        time.sleep(0.01)
    else:
        raise RuntimeError("initial RU authorities missing")
    state(out, "second")
    time.sleep(TTLS["ru"] + 0.15)
    if mode != "demand":
        wait_warm(out, time.monotonic_ns(), RU_A)
    first = query(out, HOT, "before-first-down")
    assert first["fake"] == aliases[HOT] and first["ttl"] > TTLS["ru"]
    streams(out, aliases, HOT, "before-first-down", "fi", FI_A)
    time.sleep(0.08)
    (out / "fi-down").touch()
    boundary(out, "down1")
    # No new LAN query precedes these data probes using the prior FakeIP.
    streams(out, aliases, HOT, "down1-hot", "ru", RU_A)
    hot = query(out, HOT, "down1-hot")
    assert hot["fake"] == aliases[HOT] and hot["ttl"] <= TTLS["ru"]
    streams(out, aliases, COLD, "down1-cold", "ru", RU_A)
    assert query(out, COLD, "down1-cold")["fake"] == aliases[COLD]
    denied = query(out, FIXED, "down1-denied")
    assert denied["code"] == dns.rcode.SERVFAIL and not denied["fake"]
    streams(out, aliases, FIXED, "down1-denied", None, None)
    if mode != "demand":
        wait_warm(out, time.monotonic_ns(), RU_A)
    else:
        time.sleep(0.45)
    boundary(out, "up1")
    (out / "fi-down").unlink()
    streams(out, aliases, HOT, "restored", "fi", FI_A)
    streams(out, aliases, FIXED, "restored", "fi", FI_A)
    restored = query(out, HOT, "restored")
    assert restored["fake"] == aliases[HOT] and restored["ttl"] > TTLS["ru"]
    state(out, "third")
    t = time.monotonic_ns()
    if mode != "demand":
        wait_warm(out, t, RU_B)
    else:
        time.sleep(0.40)
    (out / "fi-down").touch()
    boundary(out, "down2")
    # The same RU-only view reappears within its previous A's original lifetime.
    target = RU_B if mode == "warm" else RU_A
    streams(out, aliases, HOT, "down2-hot", "ru", target)
    last = query(out, HOT, "down2-hot")
    assert last["fake"] == aliases[HOT] and 0 <= last["ttl"] <= TTLS["ru"]
    denied = query(out, FIXED, "down2-denied")
    assert denied["code"] == dns.rcode.SERVFAIL and denied["fake"] is None
    streams(out, aliases, FIXED, "down2-denied", None, None)
    boundary(out, "finished")


if __name__ == "__main__":
    if not __debug__:
        sys.exit("Enable assertions")
    run(Path(sys.argv[2]), sys.argv[1])
