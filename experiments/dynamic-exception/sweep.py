"""Lab measurements for the runtime rule-set; reuse the partial-loss experiment policy."""
import ipaddress
import json
from pathlib import Path
import selectors
import socket
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1] / "partial-loss"))
from policy import evaluate
from fixture import PEERS, PORT, capture

def sweep(out, batch, count):
    target = str(ipaddress.IPv4Address((out/"discovered.txt").read_text().strip()))
    rows = []
    sockets = {}
    with selectors.DefaultSelector() as poll:
        for iface in ("fi1","fi2"):
            sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            sockets[iface]=sock
            sock.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,iface.encode()+b"\0")
            sock.connect((target,PORT))
            poll.register(sock,selectors.EVENT_READ,iface)
        try:
            start=time.monotonic()
            for i in range(count):
                next_send=start + i*.02
                time.sleep(max(0,next_send-time.monotonic()))
                rows.append(dict(ts=time.time(),fi1=False,fi2=False))
                for iface,sock in sockets.items():
                    sock.send(f"quality-{batch}-{iface}-{i}\n".encode())
                end = next_send + (.6 if i==count-1 else .02)
                while time.monotonic() < end:
                    for key,_ in poll.select(max(0,end-time.monotonic())):
                        record=json.loads(key.fileobj.recv(512))
                        prefix=f"quality-{batch}-{key.data}-"
                        assert record["token"].startswith(prefix)
                        idx=int(record["token"][len(prefix):])
                        assert 0<=idx<=i and record["peer"]==PEERS[key.data]
                        assert record["target"]==target and record["proto"]=="udp"
                        rows[idx][key.data]=True
        finally:
            for sock in sockets.values(): sock.close()
    (out/(batch+"-samples.json")).write_text(json.dumps(rows)+"\n")
    return rows

def verify(out):
    target=(out/"discovered.txt").read_text().strip()
    pcaps={iface:capture(out/(iface+".pcap"),f"udp and dst host {target} and dst port {PORT}") for iface in PEERS}
    server={r["token"]:r for r in (json.loads(l) for l in (out/"server.log").read_text().splitlines() if l.startswith("{"))}
    current="fi1"
    history=[]
    for batch in ("equal","loss","reverse"):
        rows=json.loads((out/(batch+"-samples.json")).read_text())
        for i,row in enumerate(rows):
            for iface in ("fi1","fi2"):
                token=f"quality-{batch}-{iface}-{i}"
                assert (token in server) == row[iface]
                if row[iface]: assert server[token]==dict(token=token,peer=PEERS[iface],target=target,proto="udp")
                for dev,data in pcaps.items():
                    assert ((token+"\n").encode() in data)==(dev==iface)
        history.extend(rows)
        decision=json.loads((out/(batch+"-decision.json")).read_text())
        assert decision==evaluate(history,current)
        current=decision["selected"]
        assert current=={"equal":"fi1","loss":"fi2","reverse":"fi1"}[batch]
        print(f"PASS {batch}: {len(rows)} measured pairs, cumulative losses {decision['losses']}, {current}")
if __name__=="__main__":
    if not __debug__: raise SystemExit("Assertions must be enabled")
    out=Path(sys.argv[2])
    if sys.argv[1]=="verify": verify(out)
    else:
        batch,n,current=sys.argv[3:]
        rows=sweep(out,batch,int(n))
        with (out/"history.jsonl").open("a") as f:
            for row in rows: print(json.dumps(row),file=f)
        result=evaluate([json.loads(s) for s in (out/"history.jsonl").read_text().splitlines()],current)
        (out/(batch+"-decision.json")).write_text(json.dumps(result)+"\n")
        print(result["selected"])
