"""Check every request token on the three egress captures and independently replay policy."""
import json
import re
import subprocess
import sys
from pathlib import Path
from policy import evaluate

out=Path(sys.argv[1])
def read(name):
    """Read JSON Lines records for a named partial-loss evidence file."""
    return [json.loads(l) for l in (out/name).read_text().splitlines()]
rows=read("rounds.jsonl")
controls=read("clients.jsonl")
assert len(rows)==440 and len(controls)==9
wires={}
for iface in ("fi1","fi2","ru0"):
    for proto in ("udp","tcp"):
        for target in ("203.0.113.77","203.0.113.78"):
            cmd=["tcpdump","-nn","-A","-r",str(out/f"continuous-{iface}.pcap"),f"{proto} and dst host {target} and dst port 19091"]
            data=subprocess.check_output(cmd,stderr=subprocess.DEVNULL).decode("ascii",errors="replace")
            wires[iface,proto,target]=set(re.findall(r"(?:health-fi[12]-[0-9]{4}|user-(?:baseline|switched|recovered)-(?:ux|tx|uy))",data))
expected={k:set() for k in wires}
for seq,r in enumerate(rows):
    assert seq==r["seq"]
    for iface in ("fi1","fi2"):
        expected[iface,"udp","203.0.113.77"].add(f"health-{iface}-{seq:04}")
for c in controls: expected[c["iface"],c["proto"],c["target"]].add(c["token"])
assert wires==expected,{str(k):v^expected[k] for k,v in wires.items() if v!=expected[k]}
# Destination-server ledger is an independent witness of delivery, in addition to client echoes.
server={r["token"]:r for r in (json.loads(l) for l in (out/"server.log").read_text().splitlines() if l.startswith("{"))}
seen=set()
for r in rows:
    for iface,peer in [("fi1","10.88.2.1"),("fi2","10.88.3.1")]:
        token=f'health-{iface}-{r["seq"]:04}'
        if r[iface]:
            assert server[token]["peer"]==peer
            seen.add(token)
for c in controls:
    assert server[c["token"]]["peer"]==c["peer"]
    seen.add(c["token"])
assert set(server)==seen
phase_losses={}
for phase in dict.fromkeys(r["phase"] for r in rows):
    part=[r for r in rows if r["phase"]==phase]
    phase_losses[phase]=[sum(not r[k] for r in part) for k in ("fi1","fi2")]
    print(f"{phase}: {len(part)} pairs, losses FI1/FI2={phase_losses[phase]}, last-first={part[-1]['ts']-part[0]['ts']:.2f}s")
assert phase_losses==dict(baseline=[0,0],burst=[3,0],clean=[0,0],partial=[22,0],recovered=[0,0]),phase_losses
changes=[d for d in read("decisions.jsonl") if d["event"]=="switch"]
assert len(changes)==1 and changes[0]["phase"]=="partial" and changes[0]["selected"]=="fi2"
change=changes[0]; start=next(r["ts"] for r in rows if r["phase"]=="partial")
print(f"Switch after {change['index']} sustained pairs, {change['ts']-start:.2f}s since impairment; p={change['paired_p']}, losses={change['losses']}.")
print("Wire PASS: 880 health requests on assigned interfaces, 9 client flows on expected egress; RU captured none of these tokens. Server matches echo observations.")
print(f"Max in-block start lag: {max(r['start_lag_ms'] for r in rows):.3f} ms.")
current="fi1"; replay=[]; switches=[]
for i,row in enumerate(rows):
    replay.append(dict(row,ts=i*36))
    decision=evaluate(replay,current)
    if decision["selected"]!=current:
        switches.append((i,row["phase"],decision["selected"]))
        current=decision["selected"]
assert len(switches)==1 and switches[0][1:]==("partial","fi2")
assert decision["pairs"]==100 and decision["losses"]=={"fi1":0,"fi2":0} and current=="fi2"
print(f"Replay at 36s spacing: 3600s window, switch={switches}, final equal 100/100 healthy pairs, FI2 held.")
