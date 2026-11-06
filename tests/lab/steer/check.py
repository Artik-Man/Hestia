"""Verify live steering independently using client packets, per-path echo probes and rule snapshots."""

import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "observer"))
import fixture as echo

PORT = 19092
PEERS = {"fi1": "10.88.2.1", "fi2": "10.88.3.1"}


def addresses(out: Path) -> tuple[str, str]:
    """Read the real destinations corresponding to the original client FakeIPs."""
    record = json.loads((out / "records.json").read_text())
    return record["x.lab.test"], record["y.lab.test"]


def config(out: Path) -> None:
    """Write the observer config for independent, equivalent probes through both exits."""
    x, y = addresses(out)
    payload = {
        "group": "FI",
        "connections": [{"id": name, "interface": name} for name in PEERS],
        "targets": [
            {"address": address, "port": PORT, "protocol": proto}
            for address, proto in [(x, "udp"), (x, "tcp"), (y, "udp")]
        ],
        "interval": "200ms",
        "timeout": "120ms",
        "window": "3s",
        "min_samples": 5,
        "margin_percent": 15,
    }
    (out / "measure.json").write_text(json.dumps(payload, indent=2) + "\n")


def decisions(out: Path) -> list[dict]:
    """Read only complete newline-terminated report records from the live output."""
    with (out / "decisions.jsonl").open("rb") as stream:
        return [json.loads(line) for line in stream if line.endswith(b"\n")]


def wait(out: Path, selected: str, condition: str, action: str) -> None:
    """Wait until the specified scoped recommendation, window counts and publication agree."""
    x, _ = addresses(out)
    deadline = time.monotonic() + 13
    while time.monotonic() < deadline:
        for row in decisions(out):
            if (
                row["address"],
                row["protocol"],
                row["recommended"],
                row["rule_action"],
            ) != (
                x,
                "udp",
                selected,
                action,
            ):
                continue
            if row["samples"] < 5:
                continue
            losses = [entry["lost"] for entry in row["counts"].values()]
            if (condition == "equal" and max(losses) == 0) or (
                condition == "loss" and max(losses) > 0
            ):
                return
        time.sleep(0.05)
    raise RuntimeError(f"expected {selected} {condition} {action}")


def verify(out: Path) -> None:
    """Require all routed decisions and probe tokens to match the independent peer and physical interface."""
    x, y = addresses(out)
    rows = decisions(out)
    peer_rows = [
        json.loads(line)
        for line in (out / "echo.log").read_text().splitlines()
        if line.startswith("{")
    ]
    seen_peer = {entry["token"]: entry for entry in peer_rows}
    assert len(seen_peer) == len(peer_rows)
    captures = {}
    for iface in ("fi1", "fi2", "ru0"):
        captures[iface] = subprocess.check_output(
            ["tcpdump", "-nnA", "-r", str(out / (iface + ".pcap")), f"dst port {PORT}"],
            stderr=subprocess.PIPE,
        )
    changes, probes, lost = [], set(), {"fi1": 0, "fi2": 0}
    for row in rows:
        scope = (row["address"], row["protocol"])
        assert scope in {(x, "udp"), (x, "tcp"), (y, "udp")}
        if row["rule_action"] in {"added", "removed"}:
            assert scope == (x, "udp")
            changes.append((row["rule_action"], row["recommended"]))
        if scope != (x, "udp"):
            assert row["recommended"] == "fi1"
        for iface, sample in row["latest"].items():
            token = sample["token"]
            assert token not in probes
            probes.add(token)
            for dev, capture in captures.items():
                assert (token.encode() in capture) == (dev == iface)
            reply = seen_peer.get(token)
            if sample["status"] == "lost":
                assert reply is None and scope == (x, "udp")
                lost[iface] += 1
            else:
                assert sample["status"] == "received"
                assert reply == {
                    "target": scope[0],
                    "protocol": scope[1],
                    "source": PEERS[iface],
                    "token": token,
                }
    assert (
        changes == [("added", "fi2"), ("removed", "fi1")] and min(lost.values()) > 0
    ), (changes, lost)
    print(
        f"PASS {len(rows)} decisions, {len(probes)} matched probes; selective UDP/X losses {lost}"
    )
    print(
        "PASS Go added FI2 exception, held at equal delivery, removed only after inverse impairment"
    )


if __name__ == "__main__":
    if not __debug__:
        sys.exit("Enable assertions")
    command, out = sys.argv[1], Path(sys.argv[2])
    if command == "echo":
        echo.X, echo.Y = addresses(out)
        echo.PORT = PORT
        echo.serve()
    elif command == "config":
        config(out)
    elif command == "wait":
        wait(out, *sys.argv[3:])
    elif command == "verify":
        verify(out)
    else:
        sys.exit("unknown command")
