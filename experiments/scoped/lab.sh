#!/usr/bin/env bash
# Run only in a disposable Linux guest. All routes and interfaces are confined to namespaces.
set -euo pipefail
umask 077
ROOT=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-$(mktemp -d)}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
[[ -z $(ls -A "$OUT") && $EUID == 0 && -c /dev/net/tun ]]
BIN=${SING_BOX:-$(command -v sing-box)}
C=hs-c-$$; G=hs-g-$$; S=hs-s-$$
namespaces=()
cleanup() {
    local n pid
    for n in "${namespaces[@]}"; do
        for pid in $(ip netns pids "$n"); do kill "$pid" 2>/dev/null || true; done
    done
    for n in "${namespaces[@]}"; do ip netns del "$n"; done
}
trap cleanup EXIT
trap 'exit 130' INT TERM
for n in "$C" "$G" "$S"; do
    ip netns add "$n"
    namespaces+=("$n")
    ip -n "$n" link set lo up
done
link() {
    local left=$1 iface=$2 net=$3 right=$4 peer=$5
    ip -n "$left" link add "$iface" type veth peer name "$peer" netns "$right"
    ip -n "$left" addr add "10.88.$net.1/30" dev "$iface"
    ip -n "$right" addr add "10.88.$net.2/30" dev "$peer"
    ip -n "$left" link set "$iface" up
    ip -n "$right" link set "$peer" up
}
link "$G" lan0 0 "$C" eth0
link "$G" ru0 1 "$S" via-ru0
link "$G" fi1 2 "$S" via-fi1
link "$G" fi2 3 "$S" via-fi2
ip -n "$C" route add default via 10.88.0.1

for target in 203.0.113.77 203.0.113.78 203.0.113.79; do ip -n "$S" addr add "$target/32" dev lo; done
gw() { ip netns exec "$G" "$@"; }
svc() { ip netns exec "$S" "$@"; }
client() { ip netns exec "$C" python3 "$ROOT/probes.py" "$@"; }
gw sysctl -qw net.ipv4.ip_forward=1
n=0
uplinks=(ru0 fi1 fi2)
for iface in "${uplinks[@]}"; do
    n=$((n+1))
    ip -n "$G" route add table "$((100+n))" default via "10.88.$n.2" dev "$iface" onlink
    ip -n "$G" rule add oif "$iface" lookup "$((100+n))"
done
# A live main default via RU makes an escaped connection observable.
ip -n "$G" route add default via 10.88.1.2 dev ru0
for iface in all default lan0 ru0 fi1 fi2; do gw sysctl -qw "net.ipv4.conf.$iface.rp_filter=0"; done
{ uname -srmo; "$BIN" version; } > "$OUT/version.txt"
gw "$BIN" check -c "$ROOT/config.json"
ip netns exec "$G" "$BIN" run -c "$ROOT/config.json" >"$OUT/sing-box.log" 2>&1 &
engine=$!

ip netns exec "$S" python3 "$ROOT/probes.py" server >"$OUT/server.log" 2>&1 &
for _ in {1..100}; do
    kill -0 "$engine" || { cat "$OUT/sing-box.log"; exit 1; }
    if ip -n "$G" link show hestia0 >/dev/null 2>&1 && grep -q READY "$OUT/server.log"; then break; fi
    sleep 0.05
done
grep -q READY "$OUT/server.log"
ip -n "$G" route add 198.18.0.0/15 dev hestia0
ip -n "$G" route add 192.0.2.53/32 dev hestia0
# Limit raw-IP interception to forwarded client packets; avoid recapturing sing-box egress.
ip -n "$G" route add table 180 203.0.113.0/24 dev hestia0
ip -n "$G" rule add iif lan0 lookup 180
event() { echo "$(date -u --iso-8601=ns) $*" >> "$OUT/events.log"; }
selector() {
    gw curl --noproxy '*' --fail --silent --show-error --max-time 3 "http://127.0.0.1:9090/proxies/$1" |
        python3 -c 'import json,sys; print(json.load(sys.stdin)["now"])'
}
phase() {
    local phase=$1 expected=$2 group scoped
    group=$(selector finland)
    scoped=$(selector udp-x)
    [[ $group == fi1-out && $scoped == "$expected" ]]
    event "phase=$phase group=$group udp_x=$scoped"
    client phase "$phase" "$OUT/state.json" > "$OUT/$phase.jsonl"
}
measure() { gw python3 "$ROOT/probes.py" measure > "$OUT/$1-measure.json"; }
start_captures() {
    local prefix=$1 iface log
    local -n captures=$2
    for iface in "${uplinks[@]}"; do
        log="$OUT/$prefix-$iface.capture.log"
        ip netns exec "$G" tcpdump --immediate-mode -Z root -nUi "$iface" -s0 -w "$OUT/$prefix-$iface.pcap" 2>"$log" &
        captures+=("$!")
        for _ in {1..100}; do grep -q 'listening on' "$log" && break; sleep .05; done
        grep -q 'listening on' "$log" || { cat "$log"; exit 1; }
    done
}
stop_captures() {
    local prefix=$1 iface pid
    local -n captures=$2
    kill -INT "${captures[@]}"
    for pid in "${captures[@]}"; do wait "$pid"; done
    for iface in "${uplinks[@]}"; do grep -qx '0 packets dropped by kernel' "$OUT/$prefix-$iface.capture.log"; done
}

continuous=()
start_captures continuous continuous
client init > "$OUT/state.json"
measure baseline
initial=$(python3 "$ROOT/probes.py" choose "$OUT/baseline-measure.json")
[[ $initial == fi1-out ]]
phase baseline fi1-out
svc iptables -A INPUT -i via-fi1 -p udp -d 203.0.113.77 -j DROP
event "impairment=drop protocol=udp destination=203.0.113.77 input=via-fi1"
phase impaired fi1-out
measure impaired
choice=$(python3 "$ROOT/probes.py" choose "$OUT/impaired-measure.json")
[[ $choice == fi2-out ]]
event "decision=$choice selector=udp-x reason=measured_udp_loss destination=203.0.113.77 data=impaired-measure.json"
gw curl --noproxy '*' --fail --silent --show-error --max-time 3 -X PUT \
    -H 'Content-Type: application/json' -d "{\"name\":\"$choice\"}" http://127.0.0.1:9090/proxies/udp-x
phase switched fi2-out
svc iptables -nvxL INPUT > "$OUT/impairment.txt"
kill -0 "$engine"
stop_captures continuous continuous
python3 "$ROOT/probes.py" verify "$OUT" | tee "$OUT/verification.txt"
