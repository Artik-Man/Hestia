#!/usr/bin/env python3
"""Offline wire/client/peer checks; uses tcpdump, no third-party modules."""
import ipaddress
import json
import re
from pathlib import Path
import subprocess
import sys

o = Path(sys.argv[1])
def rows(file):
    """Read JSON Lines evidence from the selected DNS experiment output directory."""
    return [json.loads(line) for line in (o / file).read_text().splitlines()]

def packets(iface, filt, ascii=False):
    """Read matching packets from an interface capture, optionally including printable payloads."""
    args = ["tcpdump", "-nn", "-r", str(o / (iface + ".pcap"))]
    return subprocess.check_output([*args, *(["-A"] if ascii else []), filt], stderr=subprocess.PIPE)

clients = {r["case"]: r for r in rows("clients.jsonl")}
decisions = rows("decisions.log")
# Tuple is (positive resolver, real IP, service egress).
cases = {
    "fast-fi": ("fi", ".11", "ru"), "fast-ru": ("ru", ".22", "fi"),
    "negative": ("fi", ".11", "ru"), "explicit": ("fi", ".11", "fi"),
    "unknown": ("fi", ".33", "ru"), "warm": ("fi", ".11", "ru"),
    "ru-control": ("ru", ".11", "ru"), "apex": ("fi", ".11", "fi")}
assert set(clients) == set(cases) | {"blocked", "cached-down", "apex-down"}
peers = {g: rows(g + "-peer.log") for g in ("ru", "fi")}
for case, (resolver, suffix, via) in cases.items():
    client = clients[case]
    domain, token, fake = client["domain"], client["token"], client["fake"]
    actual = "203.0.113" + suffix
    assert ipaddress.ip_address(fake) in ipaddress.ip_network("198.18.0.0/15")
    ev = [r for r in decisions if r.get("domain") == domain]
    sel = next(r for r in ev if r["event"] == "selected")
    assert (sel["group"], sel["ip"]) == (resolver, actual)
    assert client["response"] == {"group":via, "ip":actual, "token":token,
                                 "source":"10.85.1.1" if via == "ru" else "10.85.2.1"}
    assert token.encode() in packets("lan0", f"udp and dst host {fake} and dst port 19091", True)
    for g in peers:
        data = packets(g+"0", f"udp and dst host {actual} and dst port 19091", True)
        assert (token.encode() in data) == (g == via)
        assert sum(r.get("token") == token for r in peers[g]) == (g == via)
        dns = packets(g+"0", "udp dst port 53").lower()
        times = dns.count(("A? "+domain+".").lower().encode())
        expected_dns = {"explicit": {"fi"}, "apex":{"fi"}, "ru-control": {"ru"}}.get(case, {"ru","fi"})
        assert times == int(g in expected_dns), (case, g, times)
        upstream = [r for r in peers[g] if r.get("event") == "resolver" and r.get("domain") == domain]
        assert len(upstream) == times
        if upstream:
            assert upstream[0]["peer"] == ("10.85.1.1" if g == "ru" else "10.85.2.1")
            finish = next(r for r in ev if r["event"] == "finish" and r["group"] == g)
            assert finish["ip"] == upstream[0]["ip"]
            assert finish["ttl"] == (45 if upstream[0]["ip"] else None)
    if case in ("fast-fi", "fast-ru", "unknown", "negative"):
        started = [r["ns"] for r in ev if r["event"] == "start"]
        finished = [r for r in ev if r["event"] == "finish"]
        assert len(started) == len(finished) == 2 and max(started) < min(r["ns"] for r in finished)
        if case == "negative":
            assert [(r["group"], r["code"]) for r in sorted(finished, key=lambda v:v["ns"])] == [("ru",3),("fi",0)]
        else:
            assert client["dns_done_ns"] < max(r["ns"] for r in finished), case
            assert len({r["ip"] for r in finished}) == (1 if case == "unknown" else 2)
    print(f"PASS {case}: selected {resolver}/{actual}, data via {via}, DNS {client['dns_ms']:.2f} ms")
assert clients["warm"]["fake"] == clients["fast-fi"]["fake"]
assert len([r for r in decisions if r["event"] == "hit" and r["domain"] == "fast-fi.lab.test"]) == 1
for case in ("blocked", "apex-down"):
    assert clients[case]["code"] == 2 and not clients[case]["fake"]
    assert any(r.get("domain") == clients[case]["domain"] and r["event"] == "blocked" for r in decisions)
assert packets("lan0", "udp dst port 53").count(b"A? ONLY-FI.LAB.TEST.") == 2
assert clients["cached-down"]["fake"] == clients["explicit"]["fake"] and not clients["cached-down"]["response"]
assert b"probe-cached-down" in packets("lan0", "udp dst port 19091", True)
for g in peers:
    assert b"probe-cached-down" not in packets(g+"0", "udp dst port 19091", True)
    assert b"cold.only-fi.lab.test." not in packets(g+"0", "udp dst port 53")
guard = re.search(r"^\s*(\d+)\s+\d+\s+REJECT", (o / "down-guard.txt").read_text(), re.M)
assert guard and int(guard[1]) > 0
assert any(r.get("domain") == "cold.only-fi.lab.test" and r["event"] == "blocked" for r in decisions)
print("PASS unavailable FI: fresh DNS SERVFAIL; cached FakeIP data absent on both exits, RU control succeeded")
