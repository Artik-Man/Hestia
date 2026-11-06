"""Offline proof for preserved process identity, resolver TTLs, FakeIP reuse and actual packet paths."""

import importlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "dns-split-warm"))
packet = importlib.import_module("dns-split-warm.verify")
FIXED = "first.only-fi.lab.test"
HOT = "hot.lab.test"
CONTROL = "new-control.lab.test"
RU_A, RU_B, FI_A = "203.0.113.11", "203.0.113.33", "203.0.113.22"
NSEC = 10**9


def match_question(detail: bytes, name: str) -> bool:
    """Identify the exact question name in a decoded resolver or client packet."""
    return ("A? " + name + ". ").encode() in detail


def packet_rows(path: Path, expr: str):
    """Keep payload text and the actual IPv4 socket tuple of each outbound service packet."""
    raw = packet.wire(path, expr, text=True)
    starts = list(re.finditer(rb"(?m)^(\d+)\.(\d+) IP ", raw))
    result = []
    for i, m in enumerate(starts):
        detail = raw[
            m.start() : starts[i + 1].start() if i + 1 < len(starts) else len(raw)
        ]
        conn = re.search(
            rb"(?m)^\s*((?:\d+\.){3}\d+)\.(\d+) > ((?:\d+\.){3}\d+)\.(\d+):", detail
        )
        assert conn, detail
        result.append(
            (int(m[1]) * NSEC + int(m[2].ljust(9, b"0")), conn.groups(), detail)
        )
    return result


def audit_ru(out, revoked, flows):
    """Attribute every post-barrier RU UDP attempt or TCP SYN to a tagged successful permitted stream."""
    path = out / "ru0.pcap"
    data = packet_rows(path, "dst port 19091")
    attempts = packet_rows(
        path,
        "udp dst port 19091 or (tcp dst port 19091 and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn)",
    )
    permits = {}
    for row in flows:
        if (
            row["start"] < revoked
            or row["name"] == FIXED
            or not row["reply"]
            or row["reply"]["group"] != "ru"
        ):
            continue
        token = row["token"].encode()
        tuples = {sock for _, sock, raw in data if token in raw}
        assert len(tuples) == 1, (row, tuples)
        conn = tuples.pop()
        assert conn[0] == b"10.85.1.1" and conn[2] == row["reply"]["ip"].encode()
        permits[row["token"]] = (row, conn)
    earliest = {}
    unsafe = []
    for ts, conn, raw in attempts:
        if ts < revoked:
            continue
        proto = "tcp" if b"proto TCP" in raw else "udp"
        matches = [
            row
            for row, allowed in permits.values()
            if conn == allowed
            and row["proto"] == proto
            and row["start"] <= ts <= row["wall"]
            and (proto == "tcp" or row["token"].encode() in raw)
        ]
        if len(matches) != 1:
            unsafe.append(f"unattributed RU {proto} attempt at {ts} from {conn!r}")
            continue
        r = matches[0]
        earliest.setdefault(r["token"], ts)
    for token in permits:
        assert token in earliest, (token, "missing outbound SYN or UDP payload")
    return unsafe, earliest


def verify(out: Path):
    """Derive deadlines and endpoint receipts independently and fail explicitly on any forbidden delivery."""
    mode = (out / "mode").read_text().strip()
    assert mode in ("dns", "engine", "engine-persist")
    before = (out / "process-before.txt").read_text().splitlines()
    after = (out / "process-after.txt").read_text().splitlines()
    assert len(before) == len(after) == 2
    assert (before[0] == after[0]) == (mode == "dns")
    assert (before[1] != after[1]) == (mode == "dns")
    assert (out / "aliases.db").is_file() == (mode == "engine-persist")
    aliases = json.loads((out / "aliases.json").read_text())
    assert set(aliases) == {HOT, FIXED} and aliases[HOT] != aliases[FIXED]
    phases = {r["event"]: r["wall"] for r in packet.records(out / "events.jsonl")}
    revoked = phases["revoked"]
    transition = phases["restart-pending"]
    assert phases["finished"] > transition > revoked
    assert not any(
        revoked <= t
        for t, _ in packet.entries(out / "fi0.pcap", "port 53 or port 19091")
    ), "FI packet after withdrawal"
    peer_data = {}
    authorities = {}
    lookups = {}
    for group in ("fi", "ru"):
        capture = out / (group + "0.pcap")
        peer = packet.records(out / (group + "-peer.log"))
        peer_data[group] = {r["token"]: r for r in peer if r.get("event") == "peer"}
        outgoing = packet.entries(capture, "udp dst port 53")
        replies = packet.entries(capture, "udp src port 53")
        for name in (HOT, FIXED, CONTROL):
            lookups[group, name] = [t for t, d in outgoing if match_question(d, name)]
            answers = []
            for t, d in replies:
                if not match_question(d, name):
                    continue
                a = re.search(rb"\[(\d+)s\] A ([0-9.]+)", d)
                assert a, (group, name, d)
                answers.append((t, int(a[1]), a[2].decode()))
            logs = [
                r for r in peer if r.get("event") == "authority" and r["domain"] == name
            ]
            assert [(ttl, ip) for _, ttl, ip in answers] == [
                (r["ttl"], r["ip"]) for r in logs
            ]
            assert len(answers) == len(lookups[group, name])
            assert all(ttl == {"ru": 14, "fi": 29}[group] for _, ttl, _ in answers)
            authorities[group, name] = answers
    assert not lookups["ru", FIXED], "explicit FI DNS escaped via RU"
    for group in ("fi", "ru"):
        assert len([t for t, _, _ in authorities[group, HOT] if t < revoked]) >= 2, (
            "hot source was not warmed"
        )
    assert all(
        revoked
        < next(
            t + ttl * NSEC for t, ttl, _ in reversed(authorities[g, HOT]) if t < revoked
        )
        for g in ("fi", "ru")
    ), "original records not fresh at withdrawal"
    clients = packet.records(out / "dns.jsonl")
    expected_dns = {(p, n) for p in ("initial", "frequent") for n in (FIXED, HOT)}
    expected_dns.update(
        {
            ("after-denied", FIXED),
            ("reissued", CONTROL),
            ("reissued", HOT),
            ("after-ttl", HOT),
        }
    )
    assert (
        len(clients) == len(expected_dns)
        and {(r["phase"], r["name"]) for r in clients} == expected_dns
    ), clients
    lan_requests = packet.entries(
        out / "lan0.pcap",
        "udp and src host 10.85.0.2 and dst host 10.85.0.1 and dst port 53",
    )
    lan_replies = packet.entries(out / "lan0.pcap", "udp src port 53")
    assert len(lan_requests) == len(lan_replies) == len(clients)
    ttls = []
    for row in clients:
        group = "fi" if row["phase"] in ("initial", "frequent") else "ru"
        requests = [
            (t, d)
            for t, d in lan_requests
            if row["start"] <= t <= row["wall"]
            and match_question(d, row["name"])
            and re.search(rb"(?<!\d)" + str(row["tx"]).encode() + rb"\+? A\? ", d)
        ]
        assert len(requests) == 1, (row, requests)
        stamp, detail = next(
            (t, d)
            for t, d in lan_replies
            if row["start"] <= t <= row["wall"]
            and re.search(
                rb"(?<!\d)"
                + str(row["tx"]).encode()
                + rb"[^\d]* q: A\? "
                + re.escape(row["name"].encode())
                + rb"\. ",
                d,
            )
        )
        if row["phase"] == "after-denied":
            assert row["code"] == 2 and row["fake"] is None and b"ServFail" in detail
            continue
        ans = re.search(rb"\[(\d+)s\] A ([0-9.]+)", detail)
        assert (
            ans
            and row["code"] == 0
            and (int(ans[1]), ans[2].decode()) == (row["ttl"], row["fake"])
        )
        choices = [
            (t, ttl, ip) for t, ttl, ip in authorities[group, row["name"]] if t <= stamp
        ]
        assert choices, row
        t, ttl, ip = choices[-1]
        remaining = (t + ttl * NSEC - stamp) / NSEC
        assert packet.before_deadline(row["ttl"], remaining), (row, remaining, choices)
        ttls.append((row["name"], row["phase"], row["ttl"], round(remaining, 2), ip))
    reissued = {r["name"]: r["fake"] for r in clients if r["phase"] == "reissued"}
    assert set(reissued) == {HOT, CONTROL} and len(set(reissued.values())) == 2
    reissue = next(
        r["wall"] for r in clients if r["phase"] == "reissued" and r["name"] == HOT
    )
    assert not [t for t in lookups["ru", HOT] if revoked < t <= transition], (
        "a fresh RU-only lookup was needed despite the live RU candidate"
    )
    event_rows = {r["event"]: r for r in packet.records(out / "events.jsonl")}
    before_restart = packet.records(out / "cache-1.log")
    for name in (FIXED, HOT):
        trigger = event_rows["restart-pending"]["ns"]
        visits = [
            r["ns"]
            for r in before_restart
            if r.get("event") == "visit"
            and r["domain"] == name
            and r["counted"]
            and trigger - 10 * NSEC < r["ns"] <= trigger
        ]
        assert len(visits) >= 2, (
            name,
            "eligibility had expired at restart marker",
            visits,
        )
    reuse = [
        r
        for r in before_restart
        if r.get("event") == "reuse-candidate"
        and r["domain"] == HOT
        and r["group"] == "ru"
        and r["ip"] == RU_A
        and event_rows["revoked"]["ns"] < r["ns"] < event_rows["restart-pending"]["ns"]
    ]
    assert reuse, "expected the already warmed per-resolver RU candidate before restart"
    assert len([t for t in lookups["ru", HOT] if transition < t <= reissue]) == int(
        mode == "dns"
    ), "unexpected pre-expiry RU renewal"
    assert len([t for t in lookups["ru", HOT] if t > reissue]) == 1, (
        "expected single RU renewal after deadline"
    )
    logs = packet.records(out / ("cache-2.log" if mode == "dns" else "cache-1.log"))
    if mode == "dns":
        assert not any(r.get("event") == "warm-start" for r in logs), (
            "old LAN activity crossed DNS restart"
        )
    attempts = {
        g: packet.entries(
            out / (g + "0.pcap"),
            "udp dst port 19091 or (tcp dst port 19091 and tcp[tcpflags] & tcp-syn != 0)",
        )
        for g in ("ru", "fi")
    }
    wire = {
        g: packet.wire(out / (g + "0.pcap"), "dst port 19091", text=True)
        for g in ("ru", "fi")
    }
    flows = packet.records(out / "flows.jsonl")
    assert len(flows) == 20 and len({r["port"] for r in flows}) == 20
    expected = {
        (phase, name, proto)
        for phase, names in (
            ("initial", (FIXED, HOT)),
            ("prime-ru", (HOT,)),
            ("old-before-dns", (HOT, FIXED)),
            ("fresh", (HOT, CONTROL)),
            ("old-after-reissue", (FIXED, HOT)),
            ("after-ttl", (HOT,)),
        )
        for name in names
        for proto in ("tcp", "udp")
    }
    assert {(r["phase"], r["name"], r["proto"]) for r in flows} == expected
    assert len({r["token"] for r in flows}) == len(expected)
    unsafe, first_attempt = audit_ru(out, revoked, flows)
    for row in flows:
        phase, name, token = row["phase"], row["name"], row["token"]
        assert token == f"restart-{phase}-{name}-{row['proto']}"
        expected_alias = (reissued if phase in ("fresh", "after-ttl") else aliases)[
            name
        ]
        assert row["fake"] == expected_alias, (row, expected_alias)
        lan = packet.wire(
            out / "lan0.pcap",
            f"{row['proto']} and src host 10.85.0.2 and src port {row['port']} and dst host {row['fake']} and dst port 19091",
            text=True,
        )
        assert lan, row
        seen = [g for g in ("ru", "fi") if token.encode() in wire[g]]
        received = [g for g in ("ru", "fi") if token in peer_data[g]]
        assert seen == received, row
        actual = row["reply"]
        if actual:
            group = actual["group"]
            assert seen == [group] and token.encode() in lan
            assert all(
                actual[key] == peer_data[group][token][key]
                for key in ("proto", "ip", "source", "token", "group")
            )
            assert actual["source"] == {"fi": "10.85.2.1", "ru": "10.85.1.1"}[group]
            assert token.encode() in packet.wire(
                out / (group + "0.pcap"),
                f"{row['proto']} and dst host {actual['ip']} and dst port 19091",
                text=True,
            )
        else:
            assert not seen, row
        if phase == "initial":
            assert actual and (actual["group"], actual["ip"]) == ("fi", FI_A), row
            continue
        if phase == "prime-ru":
            assert actual and (actual["group"], actual["ip"]) == ("ru", RU_A)
            continue
        if name == FIXED:
            outbound = [
                g
                for g, items in attempts.items()
                if any(row["start"] <= t <= row["wall"] for t, _ in items)
            ]
            if seen or outbound:
                unsafe.append(
                    f"{phase} {row['proto']} explicit alias {row['fake']} escaped via {seen or outbound}"
                )
            continue
        if name == HOT and phase.startswith("old-") and mode == "engine" and not actual:
            continue
        want = (
            RU_B if mode == "dns" or name == CONTROL or phase == "after-ttl" else RU_A
        )
        if not actual or (actual["group"], actual["ip"]) != ("ru", want):
            unsafe.append(f"{phase} {row['proto']} {name} expected RU {want}: {actual}")
    last_before = next(
        (t, ttl, addr)
        for t, ttl, addr in reversed(authorities["ru", HOT])
        if t <= reissue
    )
    deadline = last_before[0] + last_before[1] * NSEC
    renewed = [(t, addr) for t, _, addr in authorities["ru", HOT] if t > reissue]
    assert len(renewed) == 1
    fresh_query = next(t for t in lookups["ru", HOT] if t > reissue)
    response_t, response_ip = renewed[0]
    after_ttl = [r for r in flows if r["phase"] == "after-ttl"]
    assert deadline < fresh_query <= response_t, (deadline, fresh_query, response_t)
    for row in after_ttl:
        assert row["reply"] and row["reply"]["ip"] == response_ip
        assert response_t <= first_attempt[row["token"]], (
            row,
            response_t,
            first_attempt,
        )
    print(
        f"{mode}: engine/cache PID+ticks {before} -> {after}; old {aliases}; fresh {reissued}"
    )
    print(f"TTL compared to actual source expiries: {ttls}")
    print(f"{len(flows)} tagged new TCP/UDP flows checked on LAN and both uplinks")
    if unsafe:
        for failure in unsafe:
            print("FAIL", failure)
        raise SystemExit(1)
    print(
        "PASS explicit FI isolated, permitted RU verified before and after actual expiry"
    )


if __name__ == "__main__":
    if not __debug__:
        sys.exit("Run without -O")
    verify(Path(sys.argv[1]))
