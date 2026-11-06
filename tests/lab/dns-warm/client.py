"""Apply controlled LAN DNS visits, authority rotation, cold data flows and quiet periods."""

import asyncio
import json
import socket
import sys
import time
from pathlib import Path

import dns.flags
import dns.message
import dns.opcode

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "dns-geo"))
import fixture

HOT = "hot.lab.test"
FIXED = "hot.only-fi.lab.test"
RARE = "rare.lab.test"
TTL = 4
NANO = 10**9


def authorities(out: Path) -> list[dict]:
    """Read complete independent authority responses while the two peers are running."""
    result = []
    for group in ("ru", "fi"):
        with (out / f"{group}-peer.log").open("rb") as stream:
            for row in stream:
                if row.startswith(b"{") and row.endswith(b"\n"):
                    obj = json.loads(row)
                    if obj.get("event") == "authority":
                        result.append(obj)
    return result


def mark(out: Path, stage: str) -> None:
    """Record both packet-capture wall time and monotonic time at a phase boundary."""
    with (out / "events.jsonl").open("a") as stream:
        print(
            json.dumps(
                {"stage": stage, "ns": time.monotonic_ns(), "wall_ns": time.time_ns()}
            ),
            file=stream,
        )


async def query(out: Path, name: str, stage: str) -> str:
    """Issue one genuine LAN A visit and record its full wire-time interval."""
    started_ns = time.time_ns()
    started = time.monotonic_ns()
    answer = await fixture.ask(dns.message.make_query(name, "A"), "10.85.0.1")
    fake = fixture.unpack(answer)
    assert fake and fake.startswith("198.18."), (name, answer)
    with (out / "visits.jsonl").open("a") as stream:
        print(
            json.dumps(
                {
                    "stage": stage,
                    "name": name,
                    "fake": fake,
                    "begin_ns": started,
                    "end_ns": time.monotonic_ns(),
                    "wall_begin_ns": started_ns,
                    "wall_end_ns": time.time_ns(),
                }
            ),
            file=stream,
        )
    return fake


def flow(
    out: Path, name: str, fake: str, proto: str, index: int, expected: str
) -> None:
    """Open a new connection to an existing FakeIP and require the expected actual endpoint."""
    port = 39000 + index
    token = f"data-{name}-{proto}-{index}"
    typ = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET, typ) as sock:
        sock.settimeout(2)
        sock.bind(("", port))
        sock.connect((fake, 19091))
        sock.sendall((token + "\n").encode())
        reply = json.loads(
            sock.makefile("rb").readline() if proto == "tcp" else sock.recv(512)
        )
    assert (
        reply["ip"] == expected and reply["token"] == token and reply["proto"] == proto
    ), reply
    with (out / "flows.jsonl").open("a") as stream:
        print(
            json.dumps(
                {
                    "name": name,
                    "fake": fake,
                    "token": token,
                    "proto": proto,
                    "port": port,
                    "reply": reply,
                }
            ),
            file=stream,
        )


def invalid_inputs() -> None:
    """Inject six DNS messages that must never count as client visits or trigger external traffic."""
    for index in range(6):
        msg = dns.message.make_query("invalid.lab.test", "A")
        if index < 3:
            msg.flags |= dns.flags.QR
        else:
            msg.set_opcode(dns.opcode.UPDATE)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("", 40600 + index))
            sock.sendto(msg.to_wire(), ("10.85.0.1", 53))


async def exercise(mode: str, out: Path) -> None:
    """Warm the hot set, change authority inside TTL, trigger a late hit, then test independent expiry."""
    invalid_inputs()
    settings = json.loads((out / "settings.json").read_text())
    window, refresh = settings["window_seconds"], settings["refresh_seconds"]
    aliases = {name: await query(out, name, "first") for name in (HOT, FIXED, RARE)}
    for i in range(2):
        for name in (HOT, FIXED):
            assert aliases[name] == await query(out, name, "repeat")
    for i in range(4):
        flow(out, RARE, aliases[RARE], ("tcp", "udp")[i % 2], i, fixture.IPS[0])
    expected = {(name, g) for name in (HOT, RARE) for g in ("ru", "fi")} | {
        (FIXED, "fi")
    }
    for _ in range(100):
        peer = authorities(out)
        if {(r["domain"], r["group"]) for r in peer} == expected:
            break
        await asyncio.sleep(0.01)
    else:
        raise RuntimeError("initial DNS candidates incomplete")
    initial = max(row["ns"] for row in peer)
    new = out / "record-next"
    new.write_text("new\n")
    new.replace(out / "record-state")
    mark(out, "rotation")
    # Wait past the previously returned TTL. For the warm run, issue the user hit directly
    # after a later periodic wave so periodic and demand-triggered wire queries can be distinguished.
    await asyncio.sleep(
        max(0.0, (initial + int((TTL + 0.17) * NANO) - time.monotonic_ns()) / NANO)
    )
    if mode == "warm":
        minimum = time.monotonic_ns()
        for _ in range(190):
            seen = {
                (r["domain"], r["group"])
                for r in authorities(out)
                if r["ns"] > minimum and r["ip"] == fixture.IPS[1]
            }
            if {(HOT, "ru"), (HOT, "fi"), (FIXED, "fi")} <= seen:
                break
            await asyncio.sleep(0.01)
        else:
            raise RuntimeError("periodic refresh waves missing")
        await asyncio.sleep(0.025)
    for i, name in enumerate((HOT, FIXED)):
        assert aliases[name] == await query(out, name, "after-original-ttl")
        for j, proto in enumerate(("tcp", "udp")):
            flow(out, name, aliases[name], proto, 10 + i * 2 + j, fixture.IPS[1])
    mark(out, "last-active")
    await asyncio.sleep(window + 0.20)
    mark(out, "quiet-start")
    await asyncio.sleep(2.25 * refresh)
    mark(out, "quiet-end")
    assert aliases[HOT] == await query(out, HOT, "single-late")
    await asyncio.sleep(0.15)
    mark(out, "one-only-start")
    await asyncio.sleep(2.5 * refresh)
    mark(out, "one-only-end")


if __name__ == "__main__":
    if not __debug__:
        sys.exit("Enable assertions")
    asyncio.run(exercise(sys.argv[1], Path(sys.argv[2])))
