#!/usr/bin/env bash
# Discrete namespaces in a disposable Linux VM. Requires packages from the SSTP lab and sing-box.
set -euo pipefail
umask 077
ROOT=$(cd "$(dirname "$0")" && pwd)
OUT=${1:?pass an empty evidence directory}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
[[ $EUID == 0 && -z $(ls -A "$OUT") && -c /dev/net/tun ]]
BIN=${SING_BOX:-$(command -v sing-box)}
source "$ROOT/../sstp/sessions.sh"
G=hs-gw-$$
C=hs-user-$$
for ns in "$G" "$C"; do
    ip netns add "$ns"; namespaces+=("$ns"); ip -n "$ns" link set lo up
done
gw() { ip netns exec "$G" "$@"; }
user() { ip netns exec "$C" python3 "$ROOT/probes.py" "$@"; }
event() { echo "$(date -u --iso-8601=ns) $*" >> "$OUT/events.log"; }
join() {
    local localif=$1 remote=$2 remoteif=$3 net=$4
    ip -n "$G" link add "$localif" type veth peer name "$remoteif" netns "$remote"
    ip -n "$G" addr add "10.88.$net.1/30" dev "$localif"
    ip -n "$remote" addr add "10.88.$net.2/30" dev "$remoteif"
    ip -n "$G" link set "$localif" up
    ip -n "$remote" link set "$remoteif" up
}
join lan0 "$C" eth0 0
ip -n "$C" route add default via 10.88.0.1
gw sysctl -qw net.ipv4.ip_forward=1
for i in 1 2; do
    start_peer "$i"
    join "fi$i" "hs-c$i-$$" from-gw "$i"
    gw ip route add table "$((100+i))" "$target/32" via "10.88.$i.2" dev "fi$i"
    gw ip rule add oif "fi$i" lookup "$((100+i))"
    c "$i" sysctl -qw net.ipv4.ip_forward=1
    # Share the negotiated PPP address with forwarded traffic in this tunnel only.
    c "$i" iptables -t nat -A POSTROUTING -s "10.88.$i.1/32" -d "$target/32" -o "hs$i" \
        -j SNAT --to-source 172.16.3.33
    s "$i" python3 -u "$ROOT/probes.py" server "FI$i" > "$OUT/server-FI$i.jsonl" &
    for _ in {1..100}; do grep -qs READY "$OUT/server-FI$i.jsonl" && break; sleep .05; done
    grep -q READY "$OUT/server-FI$i.jsonl"
    { c "$i" ip -br addr; c "$i" ip route get "$target"; c "$i" ss -nt; } > "$OUT/FI$i-route.txt"
done
for iface in all default lan0 fi1 fi2; do gw sysctl -qw "net.ipv4.conf.$iface.rp_filter=0"; done
{ uname -srmo; dpkg-query -W sstp-client ppp; accel-pppd --version; "$BIN" version; } > "$OUT/version.txt"
gw "$BIN" check -c "$ROOT/config.json"
ip netns exec "$G" "$BIN" run -c "$ROOT/config.json" >"$OUT/sing-box.log" 2>&1 &
engine=$!
for _ in {1..120}; do
    kill -0 "$engine" || { cat "$OUT/sing-box.log"; exit 1; }
    ip -n "$G" link show hestia0 >/dev/null 2>&1 && break; sleep .05
done
ip -n "$G" route add 198.18.0.0/15 dev hestia0
ip -n "$G" route add 192.0.2.53/32 dev hestia0
capture() {
    local label=$1 ns=$2 iface=$3 filter=$4
    ip netns exec "$ns" tcpdump --immediate-mode -U -Z root -ni "$iface" -s0 \
       -w "$OUT/$label.pcap" "$filter" 2>"$OUT/$label.capture.log" &
    caps+=("$!")
    for _ in {1..100}; do grep -qs 'listening on' "$OUT/$label.capture.log" && break; sleep .05; done
    grep -q 'listening on' "$OUT/$label.capture.log"
}
capture ingress "$G" lan0 'port 53 or port 19091'
for i in 1 2; do capture "FI$i" "hs-c$i-$$" "hs$i" 'port 19091'; done
status() {
    gw curl --noproxy '*' -fsS --max-time 3 http://127.0.0.1:9090/proxies/finland |
        python3 -c 'import json,sys; print(json.load(sys.stdin)["now"])'
}
[[ $(status) == fi1-out ]]
user init > "$OUT/state.json"
event "selector=fi1-out primary=up reserve=up"
user phase baseline "$OUT/state.json" > "$OUT/baseline.jsonl"
event "terminate FI1 SSTP client"
kill "${client_pids[1]}"
for _ in {1..160}; do c 1 ip link show hs1 >/dev/null 2>&1 || break; sleep .05; done
! c 1 ip link show hs1 >/dev/null 2>&1 || { echo "FI1 PPP still present" >&2; exit 1; }
c 2 ip -4 -o addr show hs2 | grep -q 'inet 172.16.3.33 peer'
[[ $(status) == fi1-out ]]
{ c 1 ip -br link; c 1 ip route; c 1 ss -nt; c 2 ip -br addr; c 2 ss -nt; } > "$OUT/outage.txt"
event "primary PPP disappeared, reserve PPP present, selector=fi1-out"
user phase disconnected "$OUT/state.json" > "$OUT/disconnected.jsonl"
gw curl --noproxy '*' -fsS --max-time 3 -X PUT -H 'Content-Type: application/json' \
   -d '{"name":"fi2-out"}' http://127.0.0.1:9090/proxies/finland
[[ $(status) == fi2-out ]]
event "selector=fi2-out reason=primary_ppp_down"
user phase failover "$OUT/state.json" > "$OUT/failover.jsonl"
kill -0 "$engine"
for pid in "${caps[@]}"; do kill -INT "$pid" 2>/dev/null || true; done
for index in "${!caps[@]}"; do
    if ! wait "${caps[$index]}"; then
        # FI1 capture can exit when teardown removes its PPP interface.
        [[ $index == 1 ]] && grep -q 'The interface disappeared' "$OUT/FI1.capture.log" || exit 1
    fi
done
for label in ingress FI1 FI2; do grep -qx '0 packets dropped by kernel' "$OUT/$label.capture.log"; done
python3 "$ROOT/probes.py" verify "$OUT" | tee "$OUT/verification.txt"
