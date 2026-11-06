"""Replay controller decisions against saved LAN, exit and DNS evidence."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "failover"))
from probes import captured, verify


def check(out):
    """Verify Go selector decisions against phase captures, including cached-FakeIP denial and invalid snapshot rejection."""
    verify(out)
    expected = {"ru": "ru", "warm": "fi1-out", "failover": "fi2-out",
                "blocked": "deny", "recovery": "fi2-out"}
    for phase, target in expected.items():
        decision = json.loads((out / f"{phase}-decision.json").read_text())
        assert decision["selector_target"] == target
        assert decision["group"] == ("russia" if phase == "ru" else "finland")
        assert decision["reason"] == ("default_group" if phase == "ru" else "domain_rule")
        if target == "deny":
            assert decision["outcome"] == "block_no_available_exit" and not decision.get("exit")
        else:
            assert decision["exit"] == target and decision["outcome"] == "forward"
    state = json.loads((out / "state.json").read_text())
    lan = out / "ingress.pcap"
    questions = captured(lan, "udp and dst port 53")
    assert questions.count(b"A? fi.lab.test.") == 1
    for phase in ("blocked", "gate"):
        rows = [json.loads(line) for line in (out / f"{phase}.jsonl").read_text().splitlines()]
        for row in rows:
            if row.get("domain") == "fi.lab.test":
                assert row["fake"] == state[row["domain"]]
                expr = f"{row['proto']} and src port {row['source_port']} and dst host {row['fake']} and dst port 19091"
                assert captured(lan, expr), (phase, expr)
            if "fresh_domain" in row:
                for iface in ("fi1", "fi2", "ru0"):
                    attempts = captured(out / f"continuous-{iface}.pcap", "udp and dst port 53")
                    assert row["fresh_domain"].encode() not in attempts, (phase, iface)
    assert (out / "invalid.stderr").stat().st_size > 0
    assert "invalid config rejected; selector still fi2-out" in (out / "events.log").read_text()
    print("PASS Go decisions, invalid snapshot, single original FI DNS query, LAN attempts and external DNS denial")


if __name__ == "__main__":
    if not __debug__:
        sys.exit("Assertions must be enabled")
    check(Path(sys.argv[1]))
