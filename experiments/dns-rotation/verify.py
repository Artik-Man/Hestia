"""Verify A-generation boundaries and matched client tokens on LAN and each independent WAN capture."""

import json
import subprocess
import sys
from pathlib import Path

from client import NAMES, NEW, OLD, PHASES, PORT, TTL


def records(path: Path) -> list[dict]:
    """Decode newline-terminated JSON events written by a namespace-local component."""
    return [
        json.loads(line)
        for line in path.read_text().splitlines()
        if line.startswith("{")
    ]


def packets(path: Path, expression: str, *, ascii: bool = False) -> bytes:
    """Read packets matching a numeric tcpdump expression, optionally including application bytes."""
    args = ["tcpdump", "-nn", "-r", str(path), *(["-A"] if ascii else []), expression]
    return subprocess.check_output(args, stderr=subprocess.PIPE)


def verify(out: Path, mode: str) -> None:
    """Check TTL timing, one client DNS per name, resolver provenance and exact destination/interface per flow."""
    clients = records(out / "clients.jsonl")
    aliases = json.loads((out / "fakeips.json").read_text())
    rotate = int((out / "rotated-ns.txt").read_text())
    assert (out / "pid-before").read_text() == (out / "pid-after").read_text()
    assert len(clients) == 16 and len({r["source_port"] for r in clients}) == 16
    assert {(r["phase"], r["name"], r["proto"]) for r in clients} == {
        (p, n, proto) for p in PHASES for n in NAMES for proto in ("udp", "tcp")
    }
    peernodes = {g: records(out / (g + "-peer.log")) for g in ("ru", "fi")}
    for name in NAMES:
        request = ("A? " + name + ".").encode()
        assert packets(out / "lan0.pcap", "udp dst port 53").count(request) == 1
        for group in ("ru", "fi"):
            replies = [
                e
                for e in peernodes[group]
                if e.get("event") == "authority" and e["domain"] == name
            ]
            addresses = [e["ip"] for e in replies]
            eligible = group == "fi" or name == NAMES[0]
            expected = ([OLD, NEW] if mode == "refresh" else [OLD]) if eligible else []
            assert addresses == expected, (name, group, addresses, expected)
            wire = packets(out / (group + "0.pcap"), "udp dst port 53")
            assert wire.count(request) == len(replies)
            assert all(
                e["ttl"] == TTL
                and e["source"] == {"ru": "10.85.1.1", "fi": "10.85.2.1"}[group]
                for e in replies
            )
            if len(replies) == 2:
                assert replies[1]["ns"] - replies[0]["ns"] >= TTL * 10**9
    for row in clients:
        fake = row["fake"]
        assert fake == aliases[row["name"]]
        token = row["token"].encode()
        sent = packets(
            out / "lan0.pcap",
            f"{row['proto']} and src port {row['source_port']} and dst host {fake} and dst port {PORT}",
            ascii=True,
        )
        assert sent, row
        late = row["phase"] in ("expired", "post-hit")
        if row["phase"] == "warm":
            assert rotate <= row["began"] < rotate + (TTL - 0.5) * 1e9
        if late:
            assert row["began"] >= rotate + TTL * 1e9
        if late and mode == "old":
            assert row["reply"] is None, row
            expected_group = None
        else:
            expected_group = "fi" if late or row["name"] == NAMES[1] else "ru"
            expected_ip = NEW if late else OLD
            assert token in sent
            assert (
                row["reply"]["group"] == expected_group
                and row["reply"]["ip"] == expected_ip
            )
        for group in ("ru", "fi"):
            arrivals = [
                e
                for e in peernodes[group]
                if e.get("event") == "peer" and e.get("token") == row["token"]
            ]
            assert len(arrivals) == int(group == expected_group)
            for addr in (OLD, NEW):
                wire = packets(
                    out / (group + "0.pcap"),
                    f"{row['proto']} and dst host {addr} and dst port {PORT}",
                    ascii=True,
                )
                assert (token in wire) == (
                    expected_group == group and row["reply"]["ip"] == addr
                ), (row, group, addr)
    print(
        f"PASS {mode}: 16 fresh flows, reused exactly one FakeIP per domain, LAN DNS=A once each"
    )
    if mode == "refresh":
        print(
            "PASS cached .11 before authoritative TTL; fresh UDP/TCP after expiry reached .22, free name RU→FI; explicit FI→FI"
        )
        print(
            "PASS one old and one new A per eligible resolver; concurrent TCP/UDP refresh produced one upstream wave"
        )
    else:
        print(
            "PASS negative control: no external refresh; post-expiry TCP/UDP attempts to original FakeIPs failed"
        )


if __name__ == "__main__":
    if not __debug__:
        sys.exit("Enable assertions")
    verify(Path(sys.argv[2]), sys.argv[1])
