"""Check the public quality API against the live selector while injecting a path-specific UDP fault."""
import json
import time
import subprocess
from pathlib import Path
from urllib.request import Request, urlopen


def read(url: str) -> dict:
    """Read a JSON response from a loopback HTTP service in the test network namespace."""
    with urlopen("http://127.0.0.1:" + url, timeout=2) as response:
        return json.load(response)


def wait_for(active: str, degraded: bool) -> None:
    """Wait for matching probe scores, public ranking, available reserve, and confirmed sing-box choice."""
    end = time.monotonic() + 25
    last = {}
    while time.monotonic() < end:
        report = read("8080/api/quality")
        group, empty = report["groups"]
        rows = group["connections"]
        last = {row["id"]: row["result"] for row in rows}
        if all(last[key]["overall"] is not None for key in ("one", "two")):
            if (rows[0]["id"] == active and rows[0]["active"] and last["two"]["overall"] == 100
                    and not rows[1]["active"] and empty["connections"] == []
                    and (last["one"]["overall"] < 100) == degraded
                    and read("9090/proxies/finland")["now"] == active):
                print(json.dumps({"active": active, "rows": rows}, ensure_ascii=False), flush=True)
                return
        time.sleep(.25)
    raise ValueError(f"missing confirmed {active} selection: {last}")


def add_check(protocol: str, targets: list[str], **fields: str) -> None:
    """Configure one independent check through the same scoped operation as its editor."""
    body = dict(protocol=protocol, targets=targets, intervalSeconds=4, timeoutSeconds=2, **fields)
    req = Request("http://127.0.0.1:8080/api/quality/checks/" + protocol,
                  data=json.dumps(body).encode(), method="PUT", headers={"Content-Type": "application/json"})
    with urlopen(req, timeout=3) as response:
        assert body in json.load(response)["checks"]


def verify_services(fault: bool) -> None:
    """Confirm real ICMP, DNS, HTTPS and HTTP/3 results on both paths, including protocol-specific failures."""
    end = time.monotonic() + 30
    observed = {}
    while time.monotonic() < end:
        rows = read("8080/api/quality")["groups"][0]["connections"]
        observed = {row["id"]: {c["protocol"]: c for c in row["result"]["checks"]} for row in rows}
        ready = True
        for path, checks in observed.items():
            for name in ("ICMP", "DNS", "HTTPS", "HTTP3"):
                c = checks.get(name)
                expect_fail = fault and path == "one" and name != "HTTPS"
                if not c or c["successes"] == 0 or c["localErrors"] or (c["successes"] < c["samples"]) != expect_fail:
                    ready = False
        if ready and len(observed) == 2:
            print(json.dumps({"fault": fault, "completed": {p: {n: [c["successes"], c["samples"]] for n, c in cs.items()} for p, cs in observed.items()}}), flush=True)
            return
        time.sleep(.25)
    raise ValueError(f"missing scoped service observations (fault={fault}): {observed}")


def wait_link_order(active: str, order: list[str], available: set[str]) -> None:
    """Observe the next ranked table and live selector while the previous high score is still in the hour window."""
    end = time.monotonic() + 5
    last = []
    while time.monotonic() < end:
        rows = read("8080/api/quality")["groups"][0]["connections"]
        last = [(x["id"], x["available"], x["active"], x["result"]["overall"]) for x in rows]
        ids = [r[0] for r in last]
        if ((not order or ids == order)
                and {r[0] for r in last if r[1]} == available
                and [r[0] for r in last if r[2]] == ([] if active == "deny" else [active])
                and read("9090/proxies/finland")["now"] == active
                and all(r[3] is not None for r in last)):
            print(json.dumps({"carrier": sorted(available), "selector": active, "rank": last}), flush=True)
            return
        time.sleep(.1)
    raise ValueError(f"carrier failover {active} missing: {last}")


def test_carrier() -> None:
    """Drop each remote veth carrier with both exits enabled; verify immediate failover, deny and recovery."""
    for device, state, target, order, available in (
        ("two", "down", "one", ["one", "two"], {"one"}),
        ("one", "down", "deny", [], set()),
        ("two", "up", "two", ["two", "one"], {"two"}),
    ):
        subprocess.run(["ip", "netns", "exec", device, "ip", "link", "set", "dest", state], check=True)
        wait_link_order(target, order, available)


if __name__ == "__main__":
    wait_for("one", False)
    Path("one/drop-udp").touch()
    wait_for("two", True)
    Path("one/drop-udp").unlink()
    add_check("ICMP", ["1.1.1.1", "8.8.8.8"])
    add_check("DNS", ["1.1.1.1:53", "8.8.8.8:53"], dnsName="quality.test")
    for protocol in ("HTTPS", "HTTP3"):
        add_check(protocol, ["1.1.1.1:8443", "8.8.8.8:8443"], serverName="quality.test", requestPath="/health")
    verify_services(False)
    Path("one/dns-servfail").touch()
    Path("one/fail-http3").touch()
    subprocess.run(["ip", "netns", "exec", "one", "sysctl", "-q", "-w", "net.ipv4.icmp_echo_ignore_all=1"], check=True)
    verify_services(True)
    test_carrier()
