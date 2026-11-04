#!/usr/bin/env python3
"""Ephemeral DNS fixture, client traffic and wire checks for a live rule-set."""
import argparse
import json
from pathlib import Path
import secrets
import ipaddress
import socket
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scoped"))
import probes as scoped

PORT = scoped.PORT
PEERS = scoped.SOURCES
CASES = (("x","udp","fake"), ("x","udp","ip"), ("x","tcp","fake"), ("x","tcp","ip"),
         ("y","udp","fake"), ("y","udp","ip"), ("ru","udp","fake"))
STATES = {"baseline":"fi1", "added":"fi2", "removed":"fi1", "automatic":"fi2", "retired":"fi1"}

def dns(records):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1",15353))
    print("READY", flush=True)
    while True:
        data, address = sock.recvfrom(512)
        labels, off = [], 12
        while data[off]:
            n = data[off]
            labels.append(data[off+1:off+1+n].decode())
            off += n + 1
        qtype, cls = struct.unpack_from("!HH", data, off+1)
        ip = json.loads(records.read_text()).get(".".join(labels))
        positive = bool(ip and qtype == cls == 1)
        header = data[:2] + struct.pack("!HHHHH", 0x8180 if ip else 0x8183, 1, int(positive), 0, 0)
        answer = b""
        if positive:
            answer = b"\xc0\x0c" + struct.pack("!HHIH",1,1,60,4) + socket.inet_aton(ip)
        sock.sendto(header + data[12:off+5] + answer, address)

def flow(phase, index, name, proto, mode, records, state):
    address = state[name] if mode == "fake" else records[name+".lab.test"]
    token = f"{phase}-{index}-{secrets.token_hex(5)}"
    number = list(STATES).index(phase)
    source_port = 30000 + 100 * number + index
    reply = scoped.exchange(token,address,proto,port=source_port)
    want = "ru0" if name == "ru" else STATES[phase] if (name,proto)==("x","udp") else "fi1"
    assert reply == dict(peer=PEERS[want],target=records[name+".lab.test"],proto=proto,token=token), reply
    return dict(phase=phase,name=name,mode=mode,proto=proto,address=address,token=token,source_port=source_port,reply=reply)

def capture(path, expr):
    return subprocess.check_output(["tcpdump","-nnA","-r",str(path),expr],stderr=subprocess.PIPE)

def verify(out):
    state = json.loads((out/"state.json").read_text())
    records = json.loads((out/"records.json").read_text())
    server = [json.loads(s) for s in (out/"server.log").read_text().splitlines() if s.startswith("{")]
    phases = ("baseline","automatic","retired") if (out/"automatic.jsonl").exists() else ("baseline","added","removed")
    markers = set()
    for phase in phases:
        rows = [json.loads(s) for s in (out/(phase+".jsonl")).read_text().splitlines()]
        assert [(r["name"],r["proto"],r["mode"]) for r in rows] == list(CASES)
        snapshot = json.loads((out/(phase+"-rules.json")).read_text())
        x = records["x.lab.test"]
        assert snapshot == rules([x] if STATES[phase]=="fi2" else [])
        for row in rows:
            name,proto,mode = row["name"],row["proto"],row["mode"]
            token = row["token"]
            assert token not in markers and row["phase"]==phase
            markers.add(token)
            addr = records[name+".lab.test"]
            dest = state[name] if mode=="fake" else addr
            assert row["address"] == dest
            lan = out/"lan0.pcap"
            src = row["source_port"]
            assert token.encode() in capture(lan,f"{proto} and src port {src} and dst host {dest} and dst port {PORT}")
            want = "ru0" if name=="ru" else STATES[phase] if (name,proto)==("x","udp") else "fi1"
            expected=dict(peer=PEERS[want],target=addr,proto=proto,token=token)
            assert row["reply"]==expected and [e for e in server if e["token"] == token] == [expected]
            for iface in PEERS:
                seen = token.encode() in capture(out/(iface+".pcap"),f"{proto} and dst host {addr} and dst port {PORT}")
                assert seen == (iface==want),(iface,row)
        print(f"PASS {phase}: {len(rows)} client flows and rule-set checked")
    queries = capture(out/"lan0.pcap","udp and dst port 53")
    assert all(queries.count(("A? "+n+".lab.test.").encode())==1 for n in state)
    assert (out/"pid-before.txt").read_text() == (out/"pid-after.txt").read_text()
    discovered = (out/"discovered.txt").read_text().strip()
    assert discovered == records["x.lab.test"] and discovered not in (out/"config.json").read_text()
    print("PASS preexisting FakeIPs; same process; previously unseen exception learned on wire")

def rules(addresses):
    return {"version":3,"rules":[{"ip_cidr":[ip+"/32"]} for ip in addresses]}

def apply(path, target):
    value = [] if target == "empty" else [str(ipaddress.IPv4Address(target))]
    temp = path.with_name(path.name+".new")
    temp.write_text(json.dumps(rules(value))+"\n")
    temp.replace(path)

def main():
    op, *args = sys.argv[1:]
    if op=="apply": apply(Path(args[0]),args[1]); return
    if op=="verify": verify(Path(args[0])); return
    if op=="dns": dns(Path(args[0])); return
    records=json.loads(Path(args[0]).read_text())
    if op=="server":
        scoped.TARGETS = {k:v for k,v in records.items() if not k.startswith("ru.")}
        scoped.server()
    elif op=="init":
        print(json.dumps({n:scoped.fake_address(n+".lab.test") for n in ("x","y","ru")}))
    elif op=="discover":
        scoped.exchange("discover-"+secrets.token_hex(8),json.loads(Path(args[1]).read_text())["x"],"udp")
    elif op=="await":
        state=json.loads(Path(args[1]).read_text())
        want=args[2]
        started=time.monotonic()
        while time.monotonic()-started < 8:
            token="barrier-"+secrets.token_hex(8)
            try:
                reply=scoped.exchange(token,state["x"],"udp",timeout=.2)
            except socket.timeout:
                reply=None
            print(json.dumps(dict(token=token,elapsed_ms=round(1000*(time.monotonic()-started)),reply=reply)),flush=True)
            if reply and reply["peer"]==PEERS[want]: break
            time.sleep(.025)
        else: raise RuntimeError("rule change not observed on wire")
    elif op=="phase":
        state=json.loads(Path(args[1]).read_text())
        for index,(name,proto,mode) in enumerate(CASES):
            print(json.dumps(flow(args[2],index,name,proto,mode,records,state)),flush=True)
    else:
        raise ValueError(op)
if __name__=="__main__":
    if not __debug__: raise SystemExit("Python assertions required")
    main()
