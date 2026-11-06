"""Independently reconstruct FakeIP, resolver deadlines and marked user routes from LAN/WAN captures."""

import json
import re
import subprocess
import sys
from pathlib import Path

from authority import FI_A, RU_A, RU_B, TTLS, peer
from client import COLD, FIXED, HOT, NS


def records(path: Path) -> list[dict]:
    """Read JSON event records while ignoring fixture diagnostic text."""
    return [json.loads(s) for s in path.read_text().splitlines() if s.startswith("{")]


def wire(path: Path, expr: str, *, text: bool = False) -> bytes:
    """Decode captured packets, retaining epoch timestamps and optional ASCII payload markers."""
    args = [
        "tcpdump",
        "-tt",
        "-nn",
        "-vvv",
        "-r",
        str(path),
        *(["-A"] if text else []),
        expr,
    ]
    return subprocess.check_output(args, stderr=subprocess.DEVNULL)


def entries(path: Path, expr: str) -> list[tuple[int, bytes]]:
    """Split numeric tcpdump records into capture times and their header/application details."""
    data = wire(path, expr)
    starts = list(re.finditer(rb"(?m)^(\d+)\.(\d+) IP ", data))
    return [
        (
            int(item[1]) * NS + int(item[2].ljust(9, b"0")),
            data[
                item.start() : starts[i + 1].start()
                if i + 1 < len(starts)
                else len(data)
            ],
        )
        for i, item in enumerate(starts)
    ]


def before_deadline(ttl: int, remaining: float) -> bool:
    """Allow integer DNS TTL flooring and a small capture-to-resolver processing delay."""
    return remaining > -0.025 and ttl - 0.03 <= remaining < ttl + 1.05


def verify(out: Path, mode: str) -> None:
    """Check each upstream candidate independently, then compare client DNS and data to actual wire paths."""
    assert (out / "pid-before").read_text() == (out / "pid-after").read_text()
    aliases = json.loads((out / "aliases.json").read_text())
    assert len(set(aliases.values())) == 3
    phases = {r["event"]: r for r in records(out / "events.jsonl")}
    clients = records(out / "dns-client.jsonl")
    flows = records(out / "flows.jsonl")
    names = (HOT, FIXED, COLD)
    wire_queries = {}
    source_replies = {}
    peers = {}
    for group in ("ru", "fi"):
        path = out / (group + "0.pcap")
        peers[group] = records(out / (group + "-peer.log"))
        req = entries(path, "udp dst port 53")
        resp = entries(path, "udp src port 53")
        for n in names:
            marker = ("A? " + n + ". ").encode()
            wire_queries[group, n] = [ts for ts, detail in req if marker in detail]
            got = [
                (ts, re.search(rb"\[(\d+)s\] A ([0-9.]+)", detail))
                for ts, detail in resp
                if marker in detail
            ]
            checks = [(ts, int(m[1]), m[2].decode()) for ts, m in got if m]
            authority = [
                r
                for r in peers[group]
                if r.get("domain") == n and r["event"] == "authority"
            ]
            assert [(ttl, ip) for _, ttl, ip in checks] == [
                (r["ttl"], r["ip"]) for r in authority
            ], (group, n, checks, authority)
            assert len(checks) == len(wire_queries[group, n])
            source_replies[group, n] = checks
            for r in authority:
                assert r["source"] == {"fi": "10.85.2.1", "ru": "10.85.1.1"}[group]
                assert r["ttl"] == TTLS[group]
                expected = (
                    FI_A
                    if group == "fi"
                    else {"first": RU_B, "second": RU_A, "third": RU_B}[r["generation"]]
                )
                assert r["ip"] == expected
    assert not wire_queries["ru", FIXED]
    assert source_replies["ru", HOT][0][2] == RU_B
    lan_req = entries(out / "lan0.pcap", "udp dst port 53")
    lan_reply = entries(out / "lan0.pcap", "udp src port 53")
    assert len(lan_req) == len(clients) == len(lan_reply)
    ttl_table = []
    for row in clients:
        name, stage = row["domain"], row["phase"]
        key = (row["txid"], name)
        match = [
            (ts, d)
            for ts, d in lan_reply
            if re.search(
                rb"(?<!\d)"
                + str(key[0]).encode()
                + rb"[^\d]* q: A\? "
                + re.escape(name.encode())
                + rb"\. ",
                d,
            )
        ]
        assert len(match) == 1, (key, match)
        stamp, detail = match[0]
        if stage.endswith("-denied"):
            assert row["code"] == 2 and row["fake"] is None and b"ServFail" in detail, (
                row,
                detail,
            )
            continue
        assert row["code"] == 0 and row["fake"] == aliases[name]
        m = re.search(rb"\[(\d+)s\] A ([0-9.]+)", detail)
        assert m and int(m[1]) == row["ttl"] and m[2].decode() == aliases[name], (
            row,
            detail,
        )
        group = "ru" if stage.startswith("down") else "fi"
        ip = FI_A if group == "fi" else RU_A
        if stage == "down2-hot" and mode == "warm":
            ip = RU_B
        options = [
            (t, ttl)
            for t, ttl, addr in source_replies[group, name]
            if addr == ip and t <= stamp
        ]
        assert options
        t, ttl = options[-1]
        remaining = (t + ttl * NS - stamp) / NS
        assert before_deadline(row["ttl"], remaining), (
            mode,
            stage,
            name,
            ip,
            remaining,
            row,
        )
        if stage in ("before-first-down", "down1-hot", "restored", "down2-hot"):
            ttl_table.append((stage, row["ttl"], round(remaining, 2)))
    for begin, end in (("down1", "up1"), ("down2", "finished")):
        start = phases[begin]["wall"]
        stop = phases[end]["wall"]
        assert not any(
            start <= t <= stop
            for t, _ in entries(out / "fi0.pcap", "port 53 or port 19091")
        ), begin
    expected = {
        "initial": ("fi", FI_A),
        "before-first-down": ("fi", FI_A),
        "down1-hot": ("ru", RU_A),
        "down1-cold": ("ru", RU_A),
        "restored": ("fi", FI_A),
        "down2-hot": ("ru", RU_B if mode == "warm" else RU_A),
    }
    assert len(flows) == 22 and len({r["port"] for r in flows}) == 22
    for row in flows:
        token = row["token"].encode()
        flow_filter = f"{row['proto']} and src port {row['port']} and dst host {row['fake']} and dst port {peer.PORT}"
        sent = wire(out / "lan0.pcap", flow_filter, text=True)
        assert sent and row["fake"] == aliases[row["domain"]]
        choice = expected.get(row["phase"])
        if choice is None:
            assert row["phase"].endswith("-denied") and row["reply"] is None
            for dev in ("ru0", "fi0"):
                attempts = entries(
                    out / (dev + ".pcap"),
                    f"udp dst port {peer.PORT} or (tcp dst port {peer.PORT} and tcp[tcpflags] & tcp-syn != 0)",
                )
                assert not any(
                    row["start_wall"] <= t <= row["wall"] for t, _ in attempts
                ), (row, dev, "denied flow emitted SYN or UDP")

        else:
            assert (
                token in sent and (row["reply"]["group"], row["reply"]["ip"]) == choice
            )
        for dev, observations in peers.items():
            for addr in (FI_A, RU_A, RU_B):
                outgoing = wire(
                    out / (dev + "0.pcap"),
                    f"{row['proto']} and dst host {addr} and dst port {peer.PORT}",
                    text=True,
                )
                assert (token in outgoing) == (choice == (dev, addr)), (row, dev, addr)
            received = [r for r in observations if r.get("token") == row["token"]]
            assert len(received) == int(choice is not None and choice[0] == dev)
    assert all(
        sum(t < phases["down1"]["wall"] for t in wire_queries[g, COLD]) == 1
        for g in ("ru", "fi")
    ), "cold control was prefetched"
    assert (
        phases["down1"]["wall"] < source_replies["fi", HOT][0][0] + TTLS["fi"] * NS
    ), "original FI answer not live at revocation"
    for b in ("down1", "down2"):
        hot = next(r for r in clients if r["phase"] == b + "-hot")
        group_requests = [
            t for t in wire_queries["ru", HOT] if phases[b]["wall"] <= t <= hot["wall"]
        ]
        assert len(group_requests) == int(mode == "demand" and b == "down1"), (
            mode,
            b,
            group_requests,
        )
        old_time = source_replies["ru", HOT][0][0]
        assert phases[b]["wall"] > old_time + TTLS["ru"] * NS
    prior = [
        r
        for r in source_replies["ru", HOT]
        if r[2] == RU_A and r[0] < phases["up1"]["wall"]
    ]
    assert prior and phases["down2"]["wall"] < prior[-1][0] + TTLS["ru"] * NS
    assert any(
        phases["down1"]["wall"] <= t <= phases["up1"]["wall"]
        for t in wire_queries["ru", COLD]
    ), "expired rare candidate was reused"
    if mode != "demand":
        for g, n in (("ru", HOT), ("fi", HOT), ("fi", FIXED)):
            assert (
                len(
                    [
                        t
                        for t in wire_queries[g, n]
                        if phases["second"]["wall"] < t < phases["down1"]["wall"]
                    ]
                )
                >= 1
            )
        assert any(
            phases["third"]["wall"] < t < phases["down2"]["wall"] and ip == RU_B
            for t, _, ip in source_replies["ru", HOT]
        )
    print(
        f"PASS {mode}: {len(flows)} new TCP/UDP flows wire-checked, original FakeIPs; zero FI DNS/data in both prohibitions"
    )
    print(
        f"PASS source TTL RU={TTLS['ru']} FI={TTLS['fi']}; phase,wire LAN TTL, remaining at actual egress receipt: {ttl_table}"
    )
    print(
        "PASS winner FI to eligible RU, cold RU refreshed after its own deadline, FI-only member denied; FI restored"
    )
    print(
        f"PASS RU-only view reused before former RU deadline: delivered {expected['down2-hot'][1]}"
    )


if __name__ == "__main__":
    if not __debug__:
        sys.exit("Enable assertions")
    verify(Path(sys.argv[2]), sys.argv[1])
