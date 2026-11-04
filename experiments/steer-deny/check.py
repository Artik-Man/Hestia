"""Build both lab topologies and verify flows against independent WAN captures."""

import concurrent.futures
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "failover"))
import probes

X = probes.REAL
PORT = probes.PORT


def config(out: Path, mode: str) -> None:
    """Place the group gate before FI resolution and shortcuts, or reproduce the unsafe ordering."""
    root = Path(__file__).resolve().parents[1]
    cfg = json.loads((root / "failover/config.json").read_text())
    outs = [o for o in cfg["outbounds"] if o["type"] == "direct"]
    for o in outs:
        o["tag"] = {"fi1-out": "fi1", "fi2-out": "fi2"}.get(o["tag"], o["tag"])
    for name, members, default in (
        ("fi", ["deny", "fi1", "fi2"], "fi1"),
        ("fi-alt", ["deny", "fi1", "fi2"], "fi2"),
        ("fi-gate", ["deny", "fi-dispatch"], "deny"),
    ):
        outs.append(
            {
                "type": "selector",
                "tag": name,
                "outbounds": members,
                "default": default if mode == "negative" else "deny",
                "interrupt_exist_connections": True,
            }
        )
    outs.append(
        {
            "type": "socks",
            "tag": "fi-dispatch",
            "server": "127.0.0.1",
            "server_port": 11088,
            "version": "5",
        }
    )
    cfg["outbounds"] = outs
    cfg["inbounds"].append(
        {
            "type": "socks",
            "tag": "fi-inner",
            "listen": "127.0.0.1",
            "listen_port": 11088,
        }
    )
    route = cfg["route"]
    route["rule_set"] = [
        {
            "type": "local",
            "format": "source",
            "tag": "fi-udp",
            "path": str(out / "fi-udp.json"),
        }
    ]
    ru = {"domain_suffix": "ru.lab.test", "action": "route", "outbound": "ru"}
    if mode == "positive":
        cfg["dns"]["servers"].append(
            {"type": "udp", "tag": "dns-fi-active", "server": X, "detour": "fi"}
        )
    resolve = {
        "domain_suffix": "fi.lab.test",
        "action": "resolve",
        "server": "dns-fi-active" if mode == "positive" else "dns-fi1",
    }
    alternate = {
        "network": "udp",
        "rule_set": "fi-udp",
        "action": "route",
        "outbound": "fi-alt",
    }
    outer = [
        {"inbound": "lan-tun", "port": 53, "action": "hijack-dns"},
        dict(inbound="lan-tun", **ru),
    ]
    if mode == "negative":
        outer.extend(
            [dict(inbound="lan-tun", **resolve), dict(inbound="lan-tun", **alternate)]
        )
    outer.extend(
        [
            {
                "inbound": "lan-tun",
                "domain_suffix": "fi.lab.test",
                "action": "route",
                "outbound": "fi-gate",
            },
            {
                "inbound": "lan-tun",
                "ip_cidr": X + "/32",
                "action": "route",
                "outbound": "fi-gate",
            },
        ]
    )
    route["rules"] = outer + [
        dict(inbound="fi-inner", **resolve),
        dict(inbound="fi-inner", **alternate),
        {
            "inbound": "fi-inner",
            "ip_cidr": X + "/32",
            "action": "route",
            "outbound": "fi",
        },
        {"action": "reject"},
    ]
    (out / "sing-box.json").write_text(json.dumps(cfg, indent=2) + "\n")
    (out / "fi-udp.json").write_text('{"version":3,"rules":[]}\n')


def flows(phase: str, mode: str) -> None:
    """Issue fresh FI FakeIP, raw-IP and RU FakeIP flows for both protocols; compare server responses."""
    n = {"warm": 0, "blocked": 1, "restored": 2, "audit": 3, "partial": 4}[phase]
    names = {"fi": f"{phase}.fi.lab.test", "ru": f"{phase}.ru.lab.test"}
    targets = {
        "fi": probes.fake_address(names["fi"]),
        "raw": X,
    }
    if phase != "audit":
        targets["ru"] = probes.fake_address(names["ru"])
    probes.report(query_names=names, targets=targets)
    with concurrent.futures.ThreadPoolExecutor() as pool:
        futures = []
        for i, (kind, dest) in enumerate(targets.items()):
            for j, proto in enumerate(("tcp", "udp")):
                wanted = (
                    probes.RU
                    if kind == "ru"
                    else probes.FI2
                    if proto == "udp"
                    else probes.FI1
                )
                if phase == "partial" and kind != "ru":
                    wanted = probes.FI2
                if (
                    phase in ("blocked", "audit")
                    and kind != "ru"
                    and (mode != "negative" or proto != "udp")
                ):
                    wanted = None
                futures.append(
                    pool.submit(
                        probes.probe,
                        phase,
                        kind,
                        dest,
                        proto,
                        wanted,
                        35000 + n * 100 + 2 * i + j,
                    )
                )
        for f in futures:
            f.result()


def verify(out: Path, mode: str) -> None:
    """Require marked WAN delivery only on the selected egress and deny both FI data and FI DNS."""
    dns = [
        json.loads(line)
        for line in (out / "dns.log").read_text().splitlines()
        if line.startswith("{")
    ]
    phases = (
        ("warm", "blocked", "partial", "restored")
        if mode == "positive"
        else ("warm", "blocked", "restored")
    )
    for phase in phases:
        rows = [
            json.loads(line)
            for line in (out / (phase + ".jsonl")).read_text().splitlines()
        ]
        names = rows[0]["query_names"]
        sent = rows[1:]
        assert len(sent) == 6 and len({(r["domain"], r["proto"]) for r in sent}) == 6
        for dev, ip in probes.INTERFACES.items():
            p = out / f"{phase}-{dev}.pcap"
            payload = probes.captured(p, f"dst port {PORT}", ascii=True)
            dns_wire = probes.captured(p, "udp and dst port 53")
            for r in sent:
                assert (r["token"].encode() in payload) == (r["expected_peer"] == ip)
            if phase == "partial":
                assert (names["fi"].encode() in dns_wire) == (dev == "fi2")
                if dev == "fi1":
                    assert not payload and not dns_wire
            if phase == "blocked" and mode == "positive":
                assert names["fi"].encode() not in dns_wire
                if dev != "ru0":
                    assert not payload and not dns_wire, (dev, phase, payload, dns_wire)
            assert (names["ru"].encode() in dns_wire) == (dev == "ru0")
        assert any(r["qname"] == names["ru"] and r["peer"] == probes.RU for r in dns)
        queried_fi = any(r["qname"] == names["fi"] for r in dns)
        assert queried_fi == (phase != "blocked" or mode == "negative"), (phase, dns)
        print(f"PASS {phase}: 6 client flows and independent WAN DNS checks")
    audit_rows = [
        json.loads(line) for line in (out / "audit.jsonl").read_text().splitlines()
    ]
    assert len(audit_rows) == 5
    for dev, ip in probes.INTERFACES.items():
        capture = out / f"audit-{dev}.pcap"
        marker = f"capture-witness-{dev}".encode()
        assert marker in probes.captured(capture, "udp and dst port 19112", ascii=True)
        assert (out / f"blocked-{dev}.carrier").read_text().strip() == "1"
        data = probes.captured(capture, f"dst port {PORT} or dst port 53")
        if mode == "positive" or dev == "ru0":
            assert not data, (mode, dev, data)
    print("PASS isolated FI-only window: capture witnesses on all three live uplinks")
    assert (out / "pid-before.txt").read_bytes() == (out / "pid-after.txt").read_bytes()
    for stage in phases:
        assert json.loads((out / (stage + "-rules.json")).read_text()) == {
            "version": 3,
            "rules": [{"ip_cidr": [X + "/32"]}],
        }
    print(
        f"PASS {mode}: active X exception preserved across gate and restore; engine unchanged"
    )


if __name__ == "__main__":
    if not __debug__:
        sys.exit("Enable assertions")
    action, path, mode = sys.argv[1:]
    if action == "config":
        config(Path(path), mode)
    elif action == "flows":
        flows(path, mode)
    elif action == "verify":
        verify(Path(path), mode)
    else:
        sys.exit("unexpected action")
