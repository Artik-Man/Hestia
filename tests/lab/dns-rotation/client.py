"""Acquire one FakeIP per name and reuse it on fresh flows while the authoritative TTL expires."""

import asyncio
import concurrent.futures
import ipaddress
import json
import socket
import sys
import time
from pathlib import Path

import dns.message

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "dns-geo"))
import fixture
from peer import NEW, OLD, PORT, TTL

NAMES = ("moving.lab.test", "pinned.only-fi.lab.test")
PHASES = ("initial", "warm", "expired", "post-hit")


def flow(fake: str, phase: str, name: str, proto: str, port: int) -> dict:
    """Send one unique TCP or UDP flow using only the already acquired FakeIP and return its observation."""
    nonce = f"client-{phase}-{name}-{proto}"
    kind = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
    started = time.monotonic_ns()
    reply = None
    error = None
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.settimeout(0.8)
        sock.bind(("", port))
        try:
            sock.connect((fake, PORT))
            sock.sendall((nonce + "\n").encode())
            data = sock.makefile("rb").readline() if proto == "tcp" else sock.recv(512)
            if data:
                reply = json.loads(data)
            else:
                error = "EOF"
        except OSError as exc:
            error = str(exc)
    return {
        "phase": phase,
        "name": name,
        "proto": proto,
        "token": nonce,
        "source_port": port,
        "fake": fake,
        "reply": reply,
        "error": error,
        "began": started,
        "ended": time.monotonic_ns(),
    }


async def client(out: Path, mode: str) -> None:
    """Change authority after the initial flow, exercise valid cached addresses, and wait beyond real expiry."""
    fakes = {}
    for name in NAMES:
        response = await fixture.ask(dns.message.make_query(name, "A"), "10.85.0.1")
        fake = fixture.unpack(response)
        assert fake is not None and ipaddress.ip_address(fake) in ipaddress.ip_network(
            "198.18.0.0/15"
        )
        fakes[name] = fake
    assert len(set(fakes.values())) == len(NAMES)
    (out / "fakeips.json").write_text(json.dumps(fakes) + "\n")
    with (
        (out / "clients.jsonl").open("w") as journal,
        concurrent.futures.ThreadPoolExecutor() as pool,
    ):
        for phase_num, phase in enumerate(PHASES):
            if phase == "warm":
                # The first positive answer may return before a competing resolver finishes.
                # Change authority only after all initial responders have seen the old record.
                for _ in range(100):
                    arrived = {
                        (entry["group"], entry["domain"])
                        for group in ("ru", "fi")
                        for raw in (out / (group + "-peer.log"))
                        .read_text()
                        .splitlines()
                        if raw.startswith("{")
                        for entry in [json.loads(raw)]
                        if entry.get("event") == "authority"
                    }
                    if {
                        ("ru", NAMES[0]),
                        ("fi", NAMES[0]),
                        ("fi", NAMES[1]),
                    } <= arrived:
                        break
                    await asyncio.sleep(0.01)
                else:
                    raise RuntimeError(
                        "initial DNS responders did not complete before rotation"
                    )
                newpath = out / "record-temp"
                newpath.write_text("new\n")
                newpath.replace(out / "record-state")
                rotation = time.monotonic_ns()
                (out / "rotated-ns.txt").write_text(str(rotation) + "\n")
            if phase == "expired":
                due = rotation / 1e9 + TTL + 0.20
                await asyncio.sleep(max(0.0, due - time.monotonic()))
            jobs = []
            for index, name in enumerate(NAMES):
                for j, proto in enumerate(("tcp", "udp")):
                    sport = 38100 + phase_num * 16 + index * 4 + j
                    jobs.append(
                        pool.submit(flow, fakes[name], phase, name, proto, sport)
                    )
            for job in jobs:
                row = job.result()
                journal.write(json.dumps(row) + "\n")
                expired = phase in ("expired", "post-hit")
                if expired and mode == "old":
                    assert row["reply"] is None, row
                else:
                    wanted_ip = NEW if expired else OLD
                    wanted_group = "fi" if expired or row["name"] == NAMES[1] else "ru"
                    expected = {
                        "token": row["token"],
                        "group": wanted_group,
                        "ip": wanted_ip,
                        "source": {"ru": "10.85.1.1", "fi": "10.85.2.1"}[wanted_group],
                        "proto": row["proto"],
                    }
                    assert row["reply"] == expected, row
    # Allow outstanding slower upstream attempts to appear in the evidence before terminating capture.
    await asyncio.sleep(0.15)


if __name__ == "__main__":
    if not __debug__:
        sys.exit("Enable assertions")
    asyncio.run(client(Path(sys.argv[2]), sys.argv[1]))
