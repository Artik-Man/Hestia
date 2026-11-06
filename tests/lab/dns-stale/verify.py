"""Correlate DNS response codes, TTL-generation boundaries and client flows with raw packets and peer logs."""

import json
import struct
import subprocess
import sys
from pathlib import Path

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
from authority import TTL, peer
from client import EMPTY, NX, RU, STAGES, TIMED

NS = 10**9


def records(path: Path) -> list[dict]:
    """Read JSON records emitted by asynchronous lab services."""
    return [
        json.loads(line)
        for line in path.read_text().splitlines()
        if line.startswith("{")
    ]


def capture(path: Path, expr: str) -> bytes:
    """Decode matching packets and payload markers, including capture timestamps."""
    return subprocess.check_output(
        ["tcpdump", "-tt", "-nnA", "-r", str(path), expr], stderr=subprocess.DEVNULL
    )


def dns_wire(path: Path) -> list[tuple]:
    """Decode UDP DNS directly from Linux Ethernet PCAP and retain time, transaction, question, rcode and answer."""
    packets = []
    with path.open("rb") as file:
        header = file.read(24)
        order, scale = {
            b"\xd4\xc3\xb2\xa1": ("<", 1000),
            b"\xa1\xb2\xc3\xd4": (">", 1000),
            b"\x4d\x3c\xb2\xa1": ("<", 1),
            b"\xa1\xb2\x3c\x4d": (">", 1),
        }[header[:4]]
        assert struct.unpack(order + "I", header[20:24])[0] == 1
        while raw := file.read(16):
            sec, frac, caplen, _ = struct.unpack(order + "IIII", raw)
            frame = file.read(caplen)
            if frame[12:14] != b"\x08\x00" or frame[23] != 17:
                continue
            udp = 14 + 4 * (frame[14] & 15)
            sport, dport, length, _ = struct.unpack("!HHHH", frame[udp : udp + 8])
            if 53 not in (sport, dport):
                continue
            msg = dns.message.from_wire(frame[udp + 8 : udp + length])
            packets.append((sec * NS + frac * scale, msg))
    return packets


def phase_dns(
    packets: list[tuple], start: int, end: int, name: str, response: bool
) -> list:
    """Select DNS requests or responses for a single phase by qname, QR bit and capture time."""
    return [
        msg
        for ts, msg in packets
        if start <= ts <= end
        and bool(msg.flags & dns.flags.QR) == response
        and msg.question
        and peer.fixture.name(msg) == name
    ]


def verify(out: Path, mode: str) -> None:
    """Verify actual TTL-zero stale use, strict/negative/ineligible denial, fixed cap and generation B recovery."""
    stale = mode == "stale"
    dns_pcap = {d: dns_wire(out / (d + ".pcap")) for d in ("lan0", "ru0", "fi0")}
    settings = json.loads((out / "settings.json").read_text())
    seed = json.loads((out / "seed-answers.json").read_text())
    epochs = {(r["phase"], r["side"]): r for r in records(out / "events.jsonl")}
    total = 0
    assert (out / "pid-before").read_text() == (out / "pid-after").read_text()
    for phase in STAGES:
        start = epochs[phase, "begin"]["wall_ns"]
        end = epochs[phase, "end"]["wall_ns"]
        dns_results = json.loads((out / (phase + "-dns.json")).read_text())
        data = json.loads((out / (phase + "-flows.json")).read_text())
        assert len(data) == 2 * len(dns_results)
        for result in dns_results:
            n = result["name"]
            good = phase in ("seed", "ru-control", "recovered", "reseed") or (
                stale and n == TIMED and phase in ("failed", "second")
            )
            wanted_rcode = (
                dns.rcode.NOERROR
                if good or phase == "failed" and n == EMPTY
                else dns.rcode.NXDOMAIN
                if phase == "failed" and n == NX
                else dns.rcode.SERVFAIL
            )
            assert result["rcode"] == wanted_rcode, (mode, phase, result)
            assert result["fake"] == (seed[n]["fake"] if good else None), (
                mode,
                phase,
                result,
            )
            expected_stale = good and phase in ("failed", "second")
            received = phase_dns(dns_pcap["lan0"], start, end, n, True)
            assert received and any(
                msg.rcode() == wanted_rcode
                and (not expected_stale or msg.answer and msg.answer[0].ttl == 0)
                for msg in received
            ), (phase, n)
            if n in (NX, EMPTY) and phase == "failed":
                assert any(
                    any(rr.rdtype == dns.rdatatype.SOA for rr in msg.authority)
                    and not msg.answer
                    for msg in received
                )
                reply = phase_dns(dns_pcap["fi0"], start, end, n, True)
                assert any(
                    msg.rcode() == wanted_rcode
                    and not msg.answer
                    and msg.flags & dns.flags.AA
                    and msg.authority
                    for msg in reply
                )
            if n == TIMED and phase == "failed":
                assert phase_dns(
                    dns_pcap["fi0"], start, end, n, False
                ) and not phase_dns(dns_pcap["fi0"], start, end, n, True)
            if phase in ("second", "no-revival", "beyond"):
                aws = phase_dns(dns_pcap["fi0"], start, end, n, True)
                assert aws and all(m.rcode() == dns.rcode.SERVFAIL for m in aws), (
                    phase,
                    n,
                )
            if n != RU:
                assert not phase_dns(dns_pcap["ru0"], start, end, n, False), (
                    phase,
                    n,
                    "FI leaked to RU DNS",
                )
            if phase == "fi-down":
                assert not phase_dns(dns_pcap["fi0"], start, end, n, False)
            for flow in (r for r in data if r["name"] == n):
                total += 1
                group = "ru" if n == RU else "fi"
                ip = peer.NEW if phase == "recovered" else peer.OLD
                assert flow["fake"] == seed[n]["fake"]
                lan = capture(
                    out / "lan0.pcap",
                    f"{flow['proto']} and src port {flow['port']} and dst host {flow['fake']} and dst port {peer.PORT}",
                )
                assert lan
                if good:
                    assert flow["reply"] == {
                        "token": flow["token"],
                        "proto": flow["proto"],
                        "group": group,
                        "ip": ip,
                        "source": {"ru": "10.85.1.1", "fi": "10.85.2.1"}[group],
                    }
                else:
                    assert flow["reply"] is None
                for dev in ("ru", "fi"):
                    trace = capture(
                        out / (dev + "0.pcap"),
                        f"{flow['proto']} and dst port {peer.PORT}",
                    )
                    assert (flow["token"].encode() in trace) == (good and dev == group)
        if phase in ("fi-down", "no-revival", "beyond"):
            for dev in ("ru", "fi"):
                metadata = subprocess.check_output(
                    [
                        "tcpdump",
                        "-tt",
                        "-nn",
                        "-r",
                        str(out / (dev + "0.pcap")),
                        (
                            f"dst port 53 or dst port {peer.PORT}"
                            if phase == "fi-down"
                            else f"dst port {peer.PORT}"
                        ),
                    ],
                    stderr=subprocess.DEVNULL,
                )
                assert not any(
                    start <= int(float(line.split()[0]) * NS) <= end
                    for line in metadata.splitlines()
                )
        print(
            f"PASS {phase}: checked {len(dns_results)} LAN DNS responses and {len(data)} fresh flows against both WANs"
        )
    start_ns = int((out / "seeded-ns").read_text())
    if stale:
        assert (
            epochs["second", "begin"]["ns"]
            < start_ns + (TTL + settings["stale_seconds"]) * NS
            <= epochs["beyond", "begin"]["ns"]
        )
        assert (
            epochs["beyond", "begin"]["ns"]
            < epochs["second", "begin"]["ns"] + settings["stale_seconds"] * NS
        )
    outcomes = records(out / "decisions.log")
    served = [r for r in outcomes if r.get("event") == "stale-served"]
    if stale:
        deadlines = {r["original_expiry_ns"] for r in served}
        assert len(deadlines) == 1, deadlines
        expiry = next(iter(deadlines))
        assert all(
            r["ttl"] == 0
            and r["group"] == "fi"
            and r["domain"] == TIMED
            and r["ip"] == peer.OLD
            and r["reason"] == "all_temporary"
            for r in served
        )
        assert all(
            0 <= r["ns"] - expiry < settings["stale_seconds"] * NS
            and abs(r["age"] - (r["ns"] - expiry) / NS) < 0.02
            for r in served
        )
        assert any(
            r.get("reason") == "outside_window"
            and r["domain"] == TIMED
            and r["ns"] >= expiry + settings["stale_seconds"] * NS
            for r in outcomes
        )
        print(
            f"PASS stale responses age {min(r['age'] for r in served):.2f}..{max(r['age'] for r in served):.2f}s; all retain original deadline {expiry}, TTL=0"
        )
    else:
        assert not served
    print(
        f"PASS {mode}: {total} flows, stable FakeIPs and PID; absolute stale limit, authoritative negatives, FI denial, generation B recovery"
    )


if __name__ == "__main__":
    if not __debug__:
        sys.exit("Enable assertions")
    verify(Path(sys.argv[2]), sys.argv[1])
