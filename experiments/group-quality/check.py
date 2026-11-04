"""Cross-check default-group selection against independent UDP receivers and physical client paths."""

import importlib.util
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "failover"))
sys.path.insert(0, str(ROOT / "observer"))
import fixture as echo
import probes

X, Y = "203.0.113.88", "203.0.113.99"
Z = probes.REAL
PHASES = ("baseline", "switched", "equal", "shared", "restored")
EXPECTED = {
    "baseline": "fi1",
    "switched": "fi2",
    "equal": "fi2",
    "shared": "fi2",
    "restored": "fi1",
}


def config(out: Path) -> None:
    """Prepare the guarded sing-box topology and the two-IP measurement definition."""
    spec = importlib.util.spec_from_file_location(
        "guard_lab", ROOT / "steer-deny/check.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("missing guarded fixture")
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)
    guard.config(out, "positive")
    settings = {
        "group": "fi",
        "connections": [{"id": i, "interface": i} for i in ("fi1", "fi2")],
        "targets": [{"address": ip, "port": 19092, "protocol": "udp"} for ip in (X, Y)],
        "interval": "200ms",
        "timeout": "100ms",
        "window": "2s",
        "min_samples": 5,
        "margin_percent": 15,
    }
    (out / "measure.json").write_text(json.dumps(settings, indent=2) + "\n")
    snapshot = {
        "groups": [{"id": "fi", "exits": ["fi1", "fi2"]}],
        "lists": [],
        "healthy": {"fi1": True, "fi2": True},
    }
    (out / "initial.json").write_text(json.dumps(snapshot) + "\n")


def records(path: Path) -> list[dict]:
    """Decode full JSON log records while tolerating an in-progress line and service READY markers."""
    with path.open("rb") as stream:
        return [
            json.loads(line)
            for line in stream
            if line.startswith(b"{") and line.endswith(b"\n")
        ]


def wait(out: Path, phase: str, wanted: str) -> None:
    """Wait for selector confirmation and fresh independent per-target counts that match this phase."""
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        rows = records(out / "decisions.jsonl")
        if rows:
            row = rows[-1]
            reports = row["probes"]
            if (
                row["applied"] == wanted
                and len(reports) == 2
                and min(p["samples"] for p in reports) >= 5
            ):
                losses = {
                    p["address"]: [p["counts"][dev]["lost"] for dev in ("fi1", "fi2")]
                    for p in reports
                }
                size = {p["address"]: p["samples"] for p in reports}
                valid = (
                    (
                        phase in ("baseline", "equal")
                        and not any(sum(v) for v in losses.values())
                    )
                    or (phase == "switched" and all(a > b for a, b in losses.values()))
                    or (phase == "restored" and all(b > a for a, b in losses.values()))
                    or (
                        phase == "shared"
                        and losses[X] == [size[X]] * 2
                        and losses[Y] == [0, 0]
                    )
                )
                if valid:
                    (out / (phase + "-decision.json")).write_text(
                        json.dumps(row) + "\n"
                    )
                    return
        time.sleep(0.04)
    raise RuntimeError(f"expected {phase}: {wanted}")


def flows(phase: str, wanted: str) -> None:
    """Exercise an unmeasured destination by raw IP, FI FakeIP and independent RU name for both protocols."""
    idx = PHASES.index(phase)
    query = {country: f"{phase}.{country}.lab.test" for country in ("ru", "fi")}
    addrs = {g: probes.fake_address(domain) for g, domain in query.items()}
    addrs["raw"] = Z
    for k, (g, addr) in enumerate(addrs.items()):
        for j, proto in enumerate(("tcp", "udp")):
            peer = probes.RU if g == "ru" else probes.INTERFACES[wanted]
            probes.probe(phase, g, addr, proto, peer, 37000 + 100 * idx + k * 2 + j)


def verify(out: Path) -> None:
    """Require packet captures, independent receiver replies and confirmed decisions to agree for every phase."""
    rows = records(out / "decisions.jsonl")
    recv = records(out / "echo.jsonl")
    peer = {r["token"]: r for r in recv}
    assert len(peer) == len(recv)
    wire = {
        d: probes.captured(
            out / f"quality-{d}.pcap",
            f"dst port {probes.PORT} or dst port 19092",
            ascii=True,
        )
        for d in ("fi1", "fi2", "ru0")
    }
    changes = []
    current = "fi1"
    seen = set()
    for r in rows:
        assert r["current"] == current
        if r["applied"] != current:
            changes.append((current, r["applied"]))
            assert r["reason"] == "better_delivery" and set(r["votes"]) == {X, Y}
        current = r["applied"]
        for p in r["probes"]:
            assert p["address"] in (X, Y) and p["protocol"] == "udp"
            for dev, probe in p["latest"].items():
                token = probe["token"]
                assert token not in seen
                seen.add(token)
                for d, packets in wire.items():
                    assert (token.encode() in packets) == (dev == d)
                if probe["status"] == "received":
                    assert peer.get(token) == {
                        "target": p["address"],
                        "protocol": "udp",
                        "source": probes.INTERFACES[dev],
                        "token": token,
                    }
                else:
                    assert probe["status"] == "lost" and token not in peer
    assert changes == [("fi1", "fi2"), ("fi2", "fi1")], changes
    client_count = 0
    for phase in PHASES:
        flows_read = records(out / (phase + ".jsonl"))
        assert len(flows_read) == 6 and {
            (r["domain"], r["proto"]) for r in flows_read
        } == {(k, p) for k in ("raw", "fi", "ru") for p in ("tcp", "udp")}
        for r in flows_read:
            expected = "ru0" if r["domain"] == "ru" else EXPECTED[phase]
            assert r["peer"] == probes.INTERFACES[expected]
            for d, packets in wire.items():
                assert (r["token"].encode() in packets) == (d == expected)
            client_count += 1
    print(
        f"PASS {len(rows)} rounds, {len(seen)} probes independently traced; switches {changes}"
    )
    print(
        f"PASS {client_count} new flows to unmeasured Z across five phases; RU control stays RU"
    )
    api = probes.captured(out / "shared-api.pcap", "tcp dst port 9090", ascii=True)
    assert b"GET /proxies/fi" in api and b"PUT " not in api
    print(
        "PASS complete X outage via both paths while Y delivered every probe preserved FI2 and actual traffic"
    )


if __name__ == "__main__":
    if not __debug__:
        sys.exit("Enable assertions")
    action, path, *args = sys.argv[1:]
    out = Path(path)
    if action == "config":
        config(out)
    elif action == "echo":
        echo.X, echo.Y, echo.PORT = X, Y, 19092
        echo.serve()
    elif action == "wait":
        wait(out, *args)
    elif action == "flows":
        flows(*args)
    elif action == "verify":
        verify(out)
    else:
        sys.exit("unknown lab action")
