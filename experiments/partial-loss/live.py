"""Real paired UDP probes in isolated gateway namespace; client controls use fresh sockets."""
import concurrent.futures
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

from policy import evaluate
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scoped"))
from probes import exchange, INTERFACES, TARGETS

PERIOD=.12
TIMEOUT=.08
PHASES=[("baseline",100),("burst",3),("clean",17),("partial",220),("recovered",100)]


def write(out, filename, item):
    with (out/filename).open("a") as f:
        print(json.dumps(item),file=f)


def probe(seq, iface):
    token=f"health-{iface}-{seq:04}"
    start=time.monotonic()
    try:
        reply=exchange(token,TARGETS["x"],"udp",iface=iface,timeout=TIMEOUT)
    except TimeoutError:
        return False,None
    assert reply==dict(token=token, target=TARGETS["x"], proto="udp", peer=INTERFACES[iface]),reply
    return True,round((time.monotonic()-start)*1000,3)


def controls(phase, selector):
    for mode, proto, target in [("ux","udp","x"),("tx","tcp","x"),("uy","udp","y")]:
        token=f"user-{phase}-{mode}"
        reply=exchange(token,TARGETS[target],proto)
        expected=selector if mode=="ux" else "fi1"
        assert reply == dict(token=token,target=TARGETS[target],proto=proto,peer=INTERFACES[expected]),reply
        print(json.dumps(dict(phase=phase,iface=expected,**reply)))


def main(out,client,server):
    rows=[]
    current="fi1"
    switches=[]
    def check(phase):
        result=subprocess.check_output(["ip","netns","exec",client,sys.executable,__file__,"controls",phase,current],text=True)
        for line in result.splitlines(): write(out,"clients.jsonl",json.loads(line))

    def rule(op,phase):
        args=["ip","netns","exec",server,"iptables",op,"INPUT","-i","via-fi1","-p","udp","-d",TARGETS["x"],"--dport","19091"]
        if phase=="partial": args += ["-m","statistic","--mode","nth","--every","10","--packet","0"]
        subprocess.run(args+["-j","DROP"],check=True)

    def selectors(tag):
        return "http://127.0.0.1:9090/proxies/"+tag

    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def selected(tag):
        with opener.open(selectors(tag),timeout=1) as f: return json.load(f)["now"]

    check("baseline")
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        for phase,count in PHASES:
            impaired=phase in ("partial","burst")
            if impaired: rule("-A",phase)
            # Each phase is its own fixed-cadence block; injection is outside the block.
            started=time.monotonic()
            for i in range(count):
                due=started+i*PERIOD
                time.sleep(max(0,due-time.monotonic()))
                seq=len(rows); ts=time.time()
                jobs={iface:pool.submit(probe,seq,iface) for iface in INTERFACES}
                obs={k:f.result() for k,f in jobs.items()}
                row={"ts":ts,"phase":phase,"seq":seq,**{k:v[0] for k,v in obs.items()},
                     "rtt_ms":{k:v[1] for k,v in obs.items()},"start_lag_ms":round((ts-(wall_due if i else ts))*1000,3)}
                wall_due=ts+PERIOD if not i else wall_due+PERIOD
                rows.append(row)
                write(out,"rounds.jsonl",row)
                res=evaluate(rows,current)
                if res["selected"]!=current:
                    req=urllib.request.Request(selectors("udp-x"),method="PUT",
                        data=json.dumps({"name":res["selected"]+"-out"}).encode(),headers={"Content-Type":"application/json"})
                    with opener.open(req,timeout=1) as f: assert f.status==204
                    current=res["selected"]
                    assert selected("udp-x")==current+"-out" and selected("finland")=="fi1-out"
                    switches.append(phase)
                    write(out,"decisions.jsonl",dict(phase=phase,index=i+1,event="switch",**res))
            write(out,"decisions.jsonl",dict(phase=phase,index=count,event="phase_end",**res))
            if impaired:
                with (out/"impairment.txt").open("a") as f:
                    print(phase,file=f,flush=True)
                    subprocess.run(["ip","netns","exec",server,"iptables","-nvxL","INPUT"],stdout=f,check=True)
                if phase=="partial": check("switched")
                rule("-D",phase)
    check("recovered")
    assert switches==["partial"],switches


if __name__=="__main__":
    if sys.argv[1]=="controls": controls(*sys.argv[2:])
    else: main(Path(sys.argv[1]),*sys.argv[2:])
