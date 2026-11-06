"""Drive isolated DNS/engine restart phases and record independent client attempts."""

import importlib
import ipaddress
import json
import socket
import sys
import time
from pathlib import Path

import dns.message

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
split = importlib.import_module("dns-split-warm.authority")
split.TTLS.update(ru=14, fi=29)
FIXED, HOT, CONTROL = "first.only-fi.lab.test", "hot.lab.test", "new-control.lab.test"
PORT = 19091


def rows(path: Path):
    """Read completed structured events from a possibly still-growing log."""
    with path.open() as stream:
        return [
            json.loads(line)
            for line in stream
            if line.startswith("{") and line.endswith("\n")
        ]


def append(path: Path, **data):
    """Append one event with monotonic and packet-capture wall clocks."""
    with path.open("a") as stream:
        print(
            json.dumps(dict(wall=time.time_ns(), ns=time.monotonic_ns(), **data)),
            file=stream,
        )


def query(out: Path, name: str, phase: str):
    """Obtain an IN/A answer on the real client-facing DNS socket and retain the transaction evidence."""
    request = dns.message.make_query(name, "A")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.connect(("10.85.0.1", 53))
        start = time.time_ns()
        sock.send(request.to_wire())
        response = dns.message.from_wire(sock.recv(4096))
    if not request.is_response(response):
        raise RuntimeError("mismatched client DNS transaction")
    fake = split.peer.fixture.unpack(response)
    append(
        out / "dns.jsonl",
        phase=phase,
        name=name,
        tx=request.id,
        start=start,
        code=response.rcode(),
        fake=fake,
        ttl=response.answer[0].ttl if response.answer else None,
    )
    return fake


def flow(out: Path, name: str, fake: str, phase: str):
    """Send distinguishable new TCP and UDP requests to an exact numeric alias, including expected denials."""
    count = len(rows(out / "flows.jsonl")) if (out / "flows.jsonl").exists() else 0
    for i, proto in enumerate(("tcp", "udp")):
        token = f"restart-{phase}-{name}-{proto}"
        port = 41200 + count + i
        result = None
        error = None
        with socket.socket(
            socket.AF_INET, socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
        ) as sock:
            sock.settimeout(0.85)
            sock.bind(("", port))
            start = time.time_ns()
            try:
                sock.connect((fake, PORT))
                sock.sendall((token + "\n").encode())
                data = (
                    sock.makefile("rb").readline(1024)
                    if proto == "tcp"
                    else sock.recv(1024)
                )
                if data:
                    result = json.loads(data)
            except OSError as exc:
                error = str(exc)
        append(
            out / "flows.jsonl",
            phase=phase,
            name=name,
            fake=fake,
            proto=proto,
            token=token,
            port=port,
            start=start,
            reply=result,
            error=error,
        )


def before(out: Path):
    """Seed two different FakeIP aliases in order, warm both resolver contexts and revoke FI prior to restart."""
    aliases = {}
    for name in (FIXED, HOT):
        aliases[name] = query(out, name, "initial")
        if not aliases[name] or ipaddress.ip_address(
            aliases[name]
        ) not in ipaddress.ip_network("198.18.0.0/15"):
            raise RuntimeError("seed name did not receive FakeIP")
        if query(out, name, "frequent") != aliases[name]:
            raise RuntimeError("warmup changed numeric alias")
    if aliases[FIXED] == aliases[HOT]:
        raise RuntimeError("domains share one alias")
    (out / "aliases.json").write_text(json.dumps(aliases))
    for name in (FIXED, HOT):
        flow(out, name, aliases[name], "initial")
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        records = rows(out / "cache-1.log")
        visits = {
            name: [
                r["ns"]
                for r in records
                if r.get("event") == "visit" and r["domain"] == name and r["counted"]
            ]
            for name in (FIXED, HOT)
        }
        warmed = {
            (r["domain"], r["group"])
            for r in records
            if r.get("event") == "warm-finish" and r["ip"]
        }
        if {(FIXED, "fi"), (HOT, "ru"), (HOT, "fi")} <= warmed:
            now = time.monotonic_ns()
            if not all(
                sum(now - t < 10_000_000_000 for t in visits[name]) >= 2
                for name in (FIXED, HOT)
            ):
                raise RuntimeError(
                    "warming finished after N fell below the threshold; retry an uncontended guest"
                )
            break
        time.sleep(0.04)
    else:
        raise RuntimeError(
            "both positive candidates did not refresh within the warmup deadline"
        )
    # Seed a real RU-only view while A is live. Both modes then start from identical DNS state.
    (out / "fi-down").touch()
    append(out / "events.jsonl", event="revoked")
    flow(out, HOT, aliases[HOT], "prime-ru")
    # Change the source without notifying either process; the cached A retains its original deadline.
    state = out / "ru-state.tmp"
    state.write_text("third\n")
    state.replace(out / "ru-state")
    append(out / "events.jsonl", event="restart-pending")


def after(out: Path):
    """Use old aliases before and after new allocation, then verify the path following actual upstream TTL expiry."""
    aliases = json.loads((out / "aliases.json").read_text())
    for name in (HOT, FIXED):
        flow(out, name, aliases[name], "old-before-dns")
    query(out, FIXED, "after-denied")
    fresh = {}
    for name in (CONTROL, HOT):
        fresh[name] = query(out, name, "reissued")
        if not fresh[name]:
            raise RuntimeError("allowed name could not be acquired after restart")
    for name in (HOT, CONTROL):
        flow(out, name, fresh[name], "fresh")
    for name in (FIXED, HOT):
        flow(out, name, aliases[name], "old-after-reissue")
    # The last response, not the restart instant, determines when the known RU A expires.
    answers = [
        r
        for r in rows(out / "ru-peer.log")
        if r.get("domain") == HOT and r.get("event") == "authority"
    ]
    if not answers:
        raise RuntimeError("missing logged RU response for deadline")
    last = answers[-1]
    deadline = last["ns"] / 1e9 + last["ttl"] + 0.25
    time.sleep(max(0, deadline - time.monotonic()))
    flow(out, HOT, fresh[HOT], "after-ttl")
    if query(out, HOT, "after-ttl") != fresh[HOT]:
        raise RuntimeError("alias changed within one engine process")
    append(out / "events.jsonl", event="finished")


if __name__ == "__main__":
    action, *args = sys.argv[1:]
    if action == "authority":
        import asyncio

        asyncio.run(split.serve(args[0], Path(args[1])))
    else:
        out = Path(args[0])
        if action == "before":
            before(out)
        elif action == "after":
            after(out)
        else:
            sys.exit("unknown phase")
