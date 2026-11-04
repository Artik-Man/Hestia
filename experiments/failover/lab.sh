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
C=hf-c-$$; G=hf-g-$$; S=hf-s-$$
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
ip -n "$S" addr add 203.0.113.77/32 dev lo
gw() { ip netns exec "$G" "$@"; }
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
ip -n "$G" link add deny0 type dummy
ip -n "$G" link set deny0 up
ip -n "$G" route add prohibit default table 199
ip -n "$G" rule add oif deny0 lookup 199
{ uname -srmo; "$BIN" version; } > "$OUT/version.txt"
gw "$BIN" check -c "$ROOT/config.json"
ip netns exec "$G" "$BIN" run -c "$ROOT/config.json" >"$OUT/sing-box.log" 2>&1 &
engine=$!
ip netns exec "$S" python3 "$ROOT/probes.py" echo-server >"$OUT/server.log" 2>&1 &
ip netns exec "$S" python3 "$ROOT/probes.py" dns-server >"$OUT/dns.log" 2>&1 &
for _ in {1..100}; do
    kill -0 "$engine" || { cat "$OUT/sing-box.log"; exit 1; }
    if ip -n "$G" link show hestia0 >/dev/null 2>&1 && grep -q READY "$OUT/server.log" && grep -q READY "$OUT/dns.log"; then break; fi
    sleep 0.05
done
grep -q READY "$OUT/dns.log"
grep -q READY "$OUT/server.log"
ip -n "$G" route add 198.18.0.0/15 dev hestia0
ip -n "$G" route add 192.0.2.53/32 dev hestia0
event() { echo "$(date -u --iso-8601=ns) $*" >> "$OUT/events.log"; }
select_exit() {
    local name=$1 reason=$2 current
    event "select requested=$name reason=$reason"
    gw curl --noproxy '*' --fail --silent --show-error --max-time 3 -X PUT \
        -H 'Content-Type: application/json' -d "{\"name\":\"$name\"}" http://127.0.0.1:9090/proxies/finland
    current=$(gw curl --noproxy '*' --fail --silent --show-error --max-time 3 http://127.0.0.1:9090/proxies/finland | python3 -c 'import json,sys; print(json.load(sys.stdin)["now"])')
    [[ $current == "$name" ]]
    event "select applied=$current"
}
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
phase() {
    local phase=$1
    local -a caps=()
    start_captures "$phase" caps
    event "begin phase=$phase"
    gw python3 -c 'import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(("capture-live-"+sys.argv[1]).encode(),("10.88.1.2",19092))' "$phase"
    client phase "$OUT/state.json" "$phase" > "$OUT/$phase.jsonl"
    event "end phase=$phase"
    stop_captures "$phase" caps
}
carrier() {
    ip -n "$S" link set "via-$1" "$2"
    event "peer=$1 state=$2"
}
continuous=()
start_captures continuous continuous
client init "$OUT/state.json" > "$OUT/init.log"
select_exit fi1-out initial_priority
phase warm
carrier fi1 down
select_exit fi2-out primary_unavailable
phase failover
carrier fi2 down
select_exit deny group_unavailable
phase blocked
phase control
carrier fi2 up
phase gate
select_exit fi2-out reserve_recovered
phase recovery
kill -0 "$engine"
stop_captures continuous continuous
python3 "$ROOT/probes.py" verify "$OUT" | tee "$OUT/verification.txt"
