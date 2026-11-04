#!/usr/bin/env bash
# Disposable Linux guest. All addresses, routes and sockets belong to this run.
set -euo pipefail
umask 077
ROOT=$(cd "$(dirname "$0")" && pwd)
OUT=${1:?empty evidence directory}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
[[ $EUID == 0 && -z $(ls -A "$OUT") && -c /dev/net/tun ]]
C=hd-c-$$
G=hd-g-$$
R=hd-r-$$
F=hd-f-$$
created=()
# cleanup terminates background processes and removes only the network namespaces created by this run.
cleanup() {
    local ns pid
    for ns in "${created[@]}"; do
        for pid in $(ip netns pids "$ns"); do kill "$pid" 2>/dev/null || true; done
    done
    for ns in "${created[@]}"; do ip netns del "$ns" || true; done
}
trap cleanup EXIT
trap 'exit 130' INT TERM
for ns in "$C" "$G" "$R" "$F"; do
    ip netns add "$ns"
    created+=("$ns")
    ip -n "$ns" link set lo up
done
# join attaches an addressed veth pair from the gateway to the named peer namespace.
join() {
    local iface=$1 other=$2 otherif=$3 net=$4
    ip -n "$G" link add "$iface" type veth peer name "$otherif" netns "$other"
    ip -n "$G" addr add "10.85.$net.1/30" dev "$iface"
    ip -n "$other" addr add "10.85.$net.2/30" dev "$otherif"
    ip -n "$G" link set "$iface" up
    ip -n "$other" link set "$otherif" up
}
join lan0 "$C" eth0 0
join ru0 "$R" wan 1
join fi0 "$F" wan 2
ip -n "$C" route add default via 10.85.0.1
# gw runs its arguments inside the lab gateway network namespace.
gw() { ip netns exec "$G" "$@"; }
gw sysctl -qw net.ipv4.ip_forward=1
for iface in all default lan0 fi0 ru0; do gw sysctl -qw "net.ipv4.conf.$iface.rp_filter=0"; done
for i in 1 2; do
    iface=ru0
    ns=$R
    group=ru
    if [[ $i == 2 ]]; then
        iface=fi0
        ns=$F
        group="fi"
    fi
    ip -n "$G" route add table "$((100 + i))" 203.0.113.0/24 via "10.85.$i.2" dev "$iface"
    ip -n "$G" rule add oif "$iface" table "$((100 + i))"
    for last in 11 22 33; do ip -n "$ns" addr add "203.0.113.$last/32" dev lo; done
    ip netns exec "$ns" python3 "$ROOT/fixture.py" peer "$group" >"$OUT/$group-peer.log" &
done
ip -n "$G" route add default via 10.85.1.2 dev ru0
{
    uname -srmo
    sing-box version
    dpkg-query -W python3-dnspython
} >"$OUT/version.txt"
gw sing-box check -c "$ROOT/config.json"
ip netns exec "$G" sing-box run -c "$ROOT/config.json" >"$OUT/engine.log" 2>&1 &
for _ in {1..80}; do
    ip -n "$G" link show hestia0 >/dev/null 2>&1 && break
    sleep .05
done
ip -n "$G" route add 198.18.0.0/15 dev hestia0
ip netns exec "$G" python3 "$ROOT/fixture.py" gateway "$OUT/fi-unavailable" >"$OUT/decisions.log" &
for log in ru-peer fi-peer decisions; do
    for _ in {1..80}; do
        grep -qs '"ready"' "$OUT/$log.log" && break
        sleep .05
    done
    grep -q '"ready"' "$OUT/$log.log"
done
caps=()
for iface in lan0 ru0 fi0; do
    ip netns exec "$G" tcpdump -U --immediate-mode -Z root -ni "$iface" -s0 -w "$OUT/$iface.pcap" 'udp port 53 or udp port 19091' 2>"$OUT/$iface.capture.log" &
    caps+=("$!")
    for _ in {1..100}; do
        grep -qs 'listening on' "$OUT/$iface.capture.log" && break
        sleep .05
    done
    grep -q 'listening on' "$OUT/$iface.capture.log"
done
# run runs one DNS/data scenario from the LAN client and appends its observations to the shared evidence log.
run() { ip netns exec "$C" python3 "$ROOT/fixture.py" client "$1" "$OUT/client-state.json" >>"$OUT/clients.jsonl"; }
run fast-fi
run fast-ru
run negative
run explicit
run apex
run unknown
sleep .8 # Complete late DNS attempts before exercising a cache hit.
run warm
touch "$OUT/fi-unavailable"
gw ip rule add pref 50 oif fi0 prohibit
gw iptables -I OUTPUT -o fi0 -j REJECT
gw ip rule list >"$OUT/down-rules.txt"
run blocked
run apex-down
run cached-down
run ru-control
gw iptables -nvxL OUTPUT >"$OUT/down-guard.txt"
kill -INT "${caps[@]}"
for pid in "${caps[@]}"; do wait "$pid"; done
for iface in lan0 ru0 fi0; do grep -qx '0 packets dropped by kernel' "$OUT/$iface.capture.log"; done
python3 "$ROOT/verify.py" "$OUT" | tee "$OUT/verification.txt"
