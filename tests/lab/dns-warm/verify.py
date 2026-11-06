"""Independently verify warm vs demand DNS from actual LAN/WAN captures and authoritative server records."""

import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

from client import FIXED, HOT, NANO, RARE, TTL


def records(path: Path) -> list[dict]:
    """Read JSON event lines, skipping process diagnostics and READY text."""
    return [
        json.loads(line)
        for line in path.read_text().splitlines()
        if line.startswith("{")
    ]


def packets(path: Path, expr: str, *, ascii: bool = False) -> bytes:
    """Decode packet records, retaining epoch timestamps and optional user tokens."""
    return subprocess.check_output(
        ["tcpdump", "-tt", "-nn", "-r", str(path), *(["-A"] if ascii else []), expr],
        stderr=subprocess.DEVNULL,
    )


def queries(path: Path) -> dict[str, list[int]]:
    """Extract query times from wire captures at microsecond resolution, excluding all DNS responses."""
    results = {k: [] for k in (HOT, FIXED, RARE)}
    for line in packets(path, "udp dst port 53").decode().splitlines():
        m = re.search(r"^(\d+\.\d+) .*\bA\? ([A-Za-z0-9.-]+)\. ", line)
        if m:
            domain = m[2].lower()
            if domain in results:
                results[domain].append(int(float(m[1]) * NANO))
    return results


def verify(mode: str, out: Path) -> None:
    """Require observed sources, DNS waves, non-extending history, and actual warm cached service addresses."""
    visits = records(out / "visits.jsonl")
    events = {row["stage"]: row for row in records(out / "events.jsonl")}
    decisions = records(out / "decisions.log")
    peers = {g: records(out / (g + "-peer.log")) for g in ("ru", "fi")}
    wire = {iface: queries(out / (iface + ".pcap")) for iface in ("lan0", "ru0", "fi0")}
    counts = {HOT: 5, FIXED: 4, RARE: 1}
    assert {k: len(v) for k, v in wire["lan0"].items()} == counts
    assert Counter(r["name"] for r in visits) == counts
    assert all(
        len({r["fake"] for r in visits if r["name"] == name}) == 1 for name in counts
    )
    assert (out / "pid-before").read_text() == (out / "pid-after").read_text()
    malformed = packets(
        out / "lan0.pcap", "udp dst port 53 and src portrange 40600-40605"
    )
    assert len(malformed.splitlines()) == 6
    for g in ("ru", "fi"):
        assert b"invalid.lab.test." not in packets(
            out / (g + "0.pcap"), "udp dst port 53"
        )
        assert not any(r.get("domain") == "invalid.lab.test" for r in peers[g])
    assert not any(
        r.get("domain") == "invalid.lab.test"
        and r["event"] in ("visit", "warm-start", "start")
        for r in decisions
    )
    print(
        "PASS three QR responses and three UPDATE messages on LAN caused zero external DNS queries or recorded visits"
    )
    report = {}
    for group in ("ru", "fi"):
        source = {"ru": "10.85.1.1", "fi": "10.85.2.1"}[group]
        authority = [r for r in peers[group] if r["event"] == "authority"]
        for name in counts:
            calls = wire[group + "0"][name]
            answers = [r for r in authority if r["domain"] == name]
            assert len(calls) == len(answers) and all(
                r["source"] == source and r["ttl"] == TTL for r in answers
            )
            eligible = name != FIXED or group == "fi"
            if not eligible:
                assert not calls
                continue
            assert answers[0]["ip"] == "203.0.113.11"
            if name == RARE:
                assert len(calls) == 1, "data-only access warmed rare name"
                continue
            assert any(r["ip"] == "203.0.113.22" for r in answers)
            hit = next(
                r
                for r in visits
                if r["stage"] == "after-original-ttl" and r["name"] == name
            )
            initial = answers[0]["ns"]
            assert hit["begin_ns"] >= initial + TTL * NANO
            proactive = [
                r
                for r in answers
                if r["ip"] == "203.0.113.22" and r["ns"] < hit["begin_ns"]
            ]
            if mode == "warm":
                assert proactive and proactive[0]["ns"] - initial < TTL * NANO, (
                    name,
                    group,
                    proactive,
                )
            else:
                assert not proactive, (name, group)
            demand = sum(
                hit["wall_begin_ns"] - 1_000_000 <= t <= hit["wall_end_ns"] + 1_000_000
                for t in calls
            )
            assert demand == (0 if mode == "warm" else 1), (name, group, demand)
            for left, right in (
                ("quiet-start", "quiet-end"),
                ("one-only-start", "one-only-end"),
            ):
                assert not any(
                    events[left]["wall_ns"] <= t <= events[right]["wall_ns"]
                    for t in calls
                )
            active_visits = [
                r for r in visits if r["name"] == name and r["stage"] != "single-late"
            ]
            cutoff = sorted(r["wall_end_ns"] for r in active_visits)[-3] + 8 * NANO
            assert not any(
                cutoff + 100_000_000 <= t < events["quiet-end"]["wall_ns"]
                for t in calls
            )
            report[group, name] = len(proactive)
    flows_read = records(out / "flows.jsonl")
    assert len(flows_read) == 8
    for row in flows_read:
        n, token = row["name"], row["token"]
        group, ip = ("ru", "203.0.113.11") if n == RARE else ("fi", "203.0.113.22")
        assert row["reply"] == {
            "group": group,
            "ip": ip,
            "source": {"ru": "10.85.1.1", "fi": "10.85.2.1"}[group],
            "token": token,
            "proto": row["proto"],
        }
        assert token.encode() in packets(
            out / "lan0.pcap",
            f"{row['proto']} and dst host {row['fake']} and dst port 19091",
            ascii=True,
        )
        for g in peers:
            delivered = packets(
                out / (g + "0.pcap"),
                f"{row['proto']} and dst host {ip} and dst port 19091",
                ascii=True,
            )
            assert (token.encode() in delivered) == (g == group)
    if mode == "warm":
        starts = Counter(
            (r["group"], r["domain"]) for r in decisions if r["event"] == "warm-start"
        )
        for group, name in report:
            calls = len(wire[group + "0"][name])
            # Initial wave per name, plus exactly one late ordinary visit to the unrestricted hot name.
            regular = 1 + int(name == HOT)
            assert starts[group, name] == calls - regular, (
                group,
                name,
                calls,
                starts[group, name],
            )
        assert not any(n == RARE for _, n in starts)
        print(f"PASS background requests over entire run {dict(starts)}")
        counted = Counter(r.get("domain") for r in decisions if r["event"] == "visit")
        assert counted == counts, (counted, counts)
    print(
        f"PASS {mode}: LAN DNS hot={counts[HOT]}, explicit={counts[FIXED]}, rare=1; 8 real FakeIP TCP/UDP flows"
    )
    print(f"PASS proactive new-generation responses before user hit: {report}")
    print(
        "PASS rare DNS asked once per eligible upstream; data-only flows never increased visits"
    )
    print(
        "PASS no wire queries throughout two multi-interval quiet periods; one later visit did not restart background work"
    )


if __name__ == "__main__":
    if not __debug__:
        sys.exit("Enable assertions")
    verify(sys.argv[1], Path(sys.argv[2]))
