#!/usr/bin/env bash
# Isolated ARM64 guest. Arguments: binary, negative|positive, unused output directory.
set -euo pipefail
umask 077
[[ $# == 3 && $EUID == 0 && -c /dev/net/tun ]]
ctl=$(realpath "$1")
mode=$2
OUT=$(realpath -m "$3")
[[ $mode == negative || $mode == positive ]]
mkdir -p "$OUT"
[[ -z $(ls -A "$OUT") ]]
LAB=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$LAB/../failover" && pwd)
CONFIG="$OUT/sing-box.json"
BIN=$(command -v sing-box)
python3 "$LAB/check.py" config "$OUT" "$mode"
# shellcheck source=../failover/fixture.sh
source "$ROOT/fixture.sh"
gw ip route add table 180 203.0.113.0/24 dev hestia0
gw ip rule add iif lan0 lookup 180
# gate emits a state transition using the old controller for the bypass witness or the guarded orchestrator.
gate() {
    local name=$1 healthy=$2 alt=${3:-$2}
    if [[ $mode == negative ]]; then
        printf '{"groups":[{"id":"fi-gate","exits":["fi-dispatch"]}],"lists":[],"healthy":{"fi-dispatch":%s}}\n' "$healthy" >"$OUT/$name-state.json"
        gw "$ctl" -config "$OUT/$name-state.json" >"$OUT/$name-gate.json"
    else
        printf '{"groups":[{"id":"fi","exits":["fi1","fi2"]}],"lists":[],"healthy":{"fi1":%s,"fi2":%s}}\n' "$healthy" "$alt" >"$OUT/$name-state.json"
        gw "$ctl" guard -config "$OUT/$name-state.json" -group "fi" >"$OUT/$name-gate.json"
    fi
    gw curl --noproxy '*' -fsS http://127.0.0.1:9090/proxies/fi-gate >"$OUT/$name-selector.json"
    python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["now"]==("fi-dispatch" if sys.argv[2]=="true" else "deny")' "$OUT/$name-selector.json" "$alt"
}
# check_phase records phase-scoped WAN captures and exercises FI and RU client traffic concurrently.
check_phase() {
    local phase=$1
    # shellcheck disable=SC2034
    local -a caps=()
    start_captures "$phase" caps
    if [[ $phase == audit ]]; then
        gw python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); [s.sendto(b"capture-witness-"+dev.encode(),(f"10.88.{i}.2",19112)) for i,dev in enumerate(("ru0","fi1","fi2"),1)]'
    fi
    cp "$OUT/fi-udp.json" "$OUT/$phase-rules.json"
    ip netns exec "$C" python3 "$LAB/check.py" flows "$phase" "$mode" >"$OUT/$phase.jsonl"
    stop_captures "$phase" caps
}
awk '{print $1,$22}' "/proc/$engine/stat" >"$OUT/pid-before.txt"
gate initial true
# Use the actual Go steer process and external echo; stop probes before checking DNS/data isolation.
ip netns exec "$S" ip addr add 203.0.113.78/32 dev lo
cp "$LAB/../observer/fixture.py" "$OUT/echo.py"
sed -i 's/PORT = 19091/PORT = 19092/' "$OUT/echo.py"
ip netns exec "$S" python3 -u "$OUT/echo.py" server >"$OUT/steer-echo.log" 2>&1 &
for _ in {1..100}; do
    grep -qs READY "$OUT/steer-echo.log" && break
    sleep .05
done
grep -q READY "$OUT/steer-echo.log"
cat >"$OUT/measure.json" <<'JSON'
{"group":"fi","connections":[{"id":"fi1","interface":"fi1"},{"id":"fi2","interface":"fi2"}],"targets":[{"address":"203.0.113.77","protocol":"udp","port":19092}],"interval":"100ms","timeout":"50ms","window":"2s","min_samples":3,"margin_percent":15}
JSON
loss=(-i via-fi1 -p udp --dport 19092 -j DROP)
ip netns exec "$S" iptables -I INPUT "${loss[@]}"
gw "$ctl" steer -config "$OUT/measure.json" -rules "$OUT/fi-udp.json" -rounds 8 >"$OUT/steer.jsonl"
ip netns exec "$S" iptables -D INPUT "${loss[@]}"
grep -q '"rule_action":"added"' "$OUT/steer.jsonl"
check_phase warm
gate blocked false
for dev in fi1 fi2 ru0; do gw cat "/sys/class/net/$dev/carrier" >"$OUT/blocked-$dev.carrier"; done
check_phase audit
check_phase blocked
if [[ $mode == positive ]]; then
    gate partial false true
    check_phase partial
fi
gate restored true
check_phase restored
awk '{print $1,$22}' "/proc/$engine/stat" >"$OUT/pid-after.txt"
sha256sum "$ctl" | cut -d' ' -f1 >"$OUT/controller.sha256"
python3 "$LAB/check.py" verify "$OUT" "$mode" | tee "$OUT/verification.txt"
