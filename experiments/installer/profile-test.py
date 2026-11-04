"""Validate the effective, private runtime without writing VPN keys to test output."""

import json
import os
import sys
from pathlib import Path
from urllib.request import urlopen

base = Path("/etc/hestia")
profile_file = Path(sys.argv[1])
profile = json.loads(profile_file.read_text())
core = json.loads((base / "sing-box.json").read_text())
state = json.loads((base / "snapshot.json").read_text())

assert state["groups"] == profile["groups"]
assert state["lists"] == profile["lists"]
assert state["healthy"] == profile["healthy"]
assert [g["id"] for g in state["groups"]] == ["russia", "finland"]
assert {e["tag"] for e in core["endpoints"]} == {"ru-wg", "fi-wg"}
for endpoint in core["endpoints"]:
    assert endpoint["type"] == "wireguard" and endpoint["system"] is False
    assert len(endpoint["peers"]) == 1 and endpoint["private_key"]
    print("PASS userspace WireGuard endpoint", endpoint["tag"])
socks = [i for i in core["inbounds"] if i["type"] == "socks"]
assert len(socks) == 1 and (socks[0]["listen"], socks[0]["listen_port"]) == (
    "127.0.0.1",
    1080,
)
rules = [
    (rule["domain_suffix"], rule["outbound"])
    for rule in core["route"]["rules"]
    if "domain_suffix" in rule
]
assert rules == [("deepseek.com", "russia"), ("com", "finland")], rules
assert core["route"]["final"] == "russia"
print(
    "PASS more specific domain precedes com; detached example.com omitted; default is russia"
)
for g in state["groups"]:
    wanted = next((t for t in g["exits"] if state["healthy"].get(t)), "deny")
    with urlopen("http://127.0.0.1:9090/proxies/" + g["id"], timeout=2) as resp:
        runtime = json.load(resp)
    assert runtime["now"] == wanted and set(runtime["all"]) == {*g["exits"], "deny"}
    print("PASS selector", g["id"], "selected", wanted)
assert os.stat(base / "sing-box.json").st_mode & 0o077 == 0
print("PASS sing-box runtime containing VPN material is root-private")
