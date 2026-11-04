"""Compare observer recommendations with independent peer records, packet captures and kernel routes."""

import argparse
import json
import re
import subprocess
from collections import Counter, defaultdict, deque
from datetime import datetime
from pathlib import Path

from fixture import PORT, X, Y


def rows(path):
    """Decode each JSON line, excluding the echo server's READY signal."""
    return [
        json.loads(line) for line in path.read_text().splitlines() if line != "READY"
    ]


def markers(path, expression):
    """Extract distinct test tokens from packets matching the specified wire-level filter."""
    data = subprocess.check_output(
        ["tcpdump", "-nn", "-A", "-r", str(path), expression],
        stderr=subprocess.PIPE,
    )
    return set(
        re.findall(rb"hestia-[a-f0-9]{32}|client-[a-z]+-(?:tcp|udp)-[0-9.]+", data)
    )


def report_ns(value):
    """Convert a Go UTC RFC3339 timestamp to exact nanoseconds without float rounding."""
    match = re.fullmatch(r"(.*?)(?:\.(\d{1,9}))?Z", value)
    stamp = int(datetime.fromisoformat(match[1] + "+00:00").timestamp())
    return stamp * 10**9 + int((match[2] or "").ljust(9, "0"))


def check(out):
    """Replay each paired round against PCAP and independently recomputed rolling counts."""
    cfg = json.loads((out / "config.json").read_text())
    long = cfg["window"] == "60m"
    window_ns = (3600 if long else 3) * 10**9
    expected_rounds = (8 + 24 + 732) if long else (16 + 35 + 32)
    targets = {("udp", X), ("tcp", X), ("udp", Y)}
    docs = rows(out / "recommendations.jsonl")
    assert len(docs) == expected_rounds * len(targets)
    peer = rows(out / "peer.jsonl")
    arrivals = {row["token"]: row for row in peer}
    assert len(arrivals) == len(peer), "duplicate peer event"
    events = {
        stage: (float(ts), int(count))
        for stage, ts, count in (
            line.split() for line in (out / "events.txt").read_text().splitlines()
        )
    }
    wire = {}
    for iface in ("fi1", "fi2"):
        capture = out / f"{iface}.pcap"
        assert (
            "0 packets dropped by kernel" in (out / f"{iface}.capture.log").read_text()
        )
        for protocol, address in targets:
            for direction in ("src", "dst"):
                expr = f"{protocol} and {direction} host {address} and {direction} port {PORT}"
                wire[iface, protocol, address, direction] = markers(capture, expr)
    rolling = defaultdict(deque)
    current = {scope: "FI1" for scope in targets}
    seen = set()
    losses = Counter()
    changes = []
    final = {}
    first_loss = None
    for index, r in enumerate(docs):
        scope = (r["protocol"], r["address"])
        assert scope in targets and r["port"] == PORT and r["group"] == "FI"
        assert r["current"] == current[scope]
        ts = report_ns(r["time"])
        paired = []
        for i in (1, 2):
            conn = f"FI{i}"
            p = r["latest"][conn]
            token = p["token"]
            assert token not in seen
            seen.add(token)
            key = token.encode()
            ok = p["status"] == "received"
            assert p["status"] in ("received", "lost"), (r, p)
            assert (token in arrivals) == ok, (r, arrivals.get(token))
            if ok:
                assert arrivals[token] == {
                    "target": scope[1],
                    "protocol": scope[0],
                    "source": f"10.88.{i}.1",
                    "token": token,
                }
            else:
                losses[conn, scope] += 1
                first_loss = ts if first_loss is None else min(ts, first_loss)
            for dev in ("fi1", "fi2"):
                assert (key in wire[dev, *scope, "dst"]) == (dev == conn.lower()), (
                    dev,
                    p,
                )
                assert (key in wire[dev, *scope, "src"]) == (
                    dev == conn.lower() and ok
                ), (dev, p)
            paired.append(ok)
        history = rolling[scope]
        history.append((ts, paired))
        while history and history[0][0] <= ts - window_ns:
            history.popleft()
        assert r["samples"] == len(history) and set(r["counts"]) == {"FI1", "FI2"}
        for i, conn in enumerate(("FI1", "FI2")):
            received = sum(h[1][i] for h in history)
            assert r["counts"][conn] == {
                "sent": len(history),
                "received": received,
                "lost": len(history) - received,
            }
        if r["recommended"] != r["current"]:
            assert r["reason"] == "better_delivery" and scope == ("udp", X)
            changes.append((index, r))
        current[scope] = r["recommended"]
        final[scope] = r
    assert len(changes) == 1
    at, changed = changes[0]
    assert events["impaired"][1] <= at < events["recovered"][1], (at, events)
    assert changed["recommended"] == "FI2"
    assert losses.keys() == {("FI1", ("udp", X))} and next(iter(losses.values())) > 1, (
        losses
    )
    assert all(pair["lost"] == 0 for pair in final["udp", X]["counts"].values())
    assert final["udp", X]["recommended"] == "FI2"
    if long:
        assert (report_ns(final["udp", X]["time"]) - first_loss) > window_ns
    controls = rows(out / "clients.jsonl")
    assert len(controls) == 9
    for c in controls:
        token = c["token"]
        scope = (c["protocol"], c["target"])
        marker = token.encode()
        assert (
            marker in wire["fi1", *scope, "dst"]
            and marker not in wire["fi2", *scope, "dst"]
        )
        assert (token in arrivals) == c["received"]
        assert c["received"] or (c["phase"] == "impaired" and scope == ("udp", X))
    assert set(arrivals) <= seen | {c["token"] for c in controls}
    route = (out / "route-before.txt").read_bytes()
    assert (
        route
        == (out / "route-impaired.txt").read_bytes()
        == (out / "route-after.txt").read_bytes()
    )
    seconds = events["finished"][0] - events["begin"][0]
    print(
        f"PASS {expected_rounds} real rounds in {seconds:.2f}s; window={cfg['window']}, {len(seen)} wire-verified probes"
    )
    print(
        f"PASS FI1 UDP/X lost {sum(losses.values())} probes; all other path/target pairs returned every probe"
    )
    print(
        f"PASS UDP/X recommended FI2 once, after {report_ns(changed['time']) / 1e9 - events['impaired'][0]:.2f}s; held FI2 at equal quality after expiry"
    )
    print(
        "PASS nine LAN control flows stayed on FI1; routes and policy rules identical"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    if not __debug__:
        parser.exit(2, "Enable assertions")
    check(args.directory)
