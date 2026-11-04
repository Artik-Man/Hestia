"""Verify a live service's PID, selector PUTs and real client packet evidence."""
from collections import Counter
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "failover"))
from probes import captured, verify


def check(out):
    """Correlate service PIDs, selector PUTs, controller logs, and client markers across updates and restart."""
    verify(out)
    states = [line.split() for line in (out / "states.txt").read_text().splitlines()]
    expected = [
        ("initial", "fi1-out"), ("failover", "fi2-out"), ("invalid", "fi2-out"),
        ("outage", "deny"), ("gate", "deny"), ("recovery", "fi2-out"), ("restart", "fi1-out"),
    ]
    assert [(stage, fi) for stage, pid, fi, ru in states] == expected
    assert all(ru == "ru" and int(pid) > 0 for _, pid, _, ru in states)
    assert len({s[1] for s in states[:-1]}) == 1 and states[-1][1] != states[0][1]
    api = captured(out / "api.pcap", "tcp dst port 9090", ascii=True).decode(errors="replace")
    puts = re.findall(r"PUT /proxies/([^ ]+) HTTP/1\.1", api)
    assert Counter(puts) == {"russia": 1, "finland": 5}, puts
    log = (out / "service.log").read_text()
    entries = [json.loads(line) for line in log.splitlines() if line.startswith("{")]
    fi = [r["selector_target"] for r in entries if r.get("group") == "finland"]
    assert fi == ["fi1-out", "fi2-out", "deny", "fi2-out", "fi1-out"], fi
    assert re.search(r"invalid|unknown group", log, re.I)
    print("PASS single PID through health changes and invalid file, restart reload, RU selector written once")
    print("PASS correlated service decisions and loopback API captures (FI 5 PUTs, RU 1 PUT)")
    fake = json.loads((out / "state.json").read_text())["fi.lab.test"]
    lan = out / "ingress.pcap"
    assert captured(lan, "udp and dst port 53").count(b"A? fi.lab.test.") == 1
    for stage in ("blocked", "gate"):
        for line in (out / f"{stage}.jsonl").read_text().splitlines():
            row = json.loads(line)
            if row.get("domain") == "fi.lab.test":
                assert row["fake"] == fake
                expr = f"{row['proto']} and src port {row['source_port']} and dst host {fake} and dst port 19091"
                assert captured(lan, expr), (stage, expr)
            if "fresh_domain" in row:
                for iface in ("fi1", "fi2", "ru0"):
                    dns = captured(out / f"continuous-{iface}.pcap", "udp and dst port 53")
                    assert row["fresh_domain"].encode() not in dns
    print("PASS initial LAN DNS queried once, blocked TCP/UDP attempted on LAN, DNS absent on external paths")


if __name__ == "__main__":
    if not __debug__:
        sys.exit("Enable assertions")
    check(Path(sys.argv[1]))
