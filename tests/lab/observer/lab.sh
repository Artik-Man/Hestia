#!/usr/bin/env bash
# Only in a disposable Debian ARM64 guest. No sing-box or public network required.
set -euo pipefail
umask 077
[[ $# == 3 && $EUID == 0 ]]
observer=$(realpath "$1")
mode=$2
out=$(realpath -m "$3")
root=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$out"
[[ -z $(ls -A "$out") && -x $observer ]]
case $mode in
    fast)
        interval=250ms
        timeout=160ms
        window=3s
        base=16
        bad=35
        clean=32
        width=3
        ;;
    hour)
        interval=5s
        timeout=2s
        window=60m
        base=8
        bad=24
        clean=732
        width=2
        ;;
    *) exit 2 ;;
esac
total=$((base + bad + clean))
C=hov-c-$$
G=hov-g-$$
S=hov-s-$$
namespaces=()
caps=()
# Remove only the namespaces and processes owned by this test instance.
cleanup() {
    local ns pid
    for ns in "${namespaces[@]}"; do
        for pid in $(ip netns pids "$ns"); do kill "$pid" 2>/dev/null || true; done
    done
    for ns in "${namespaces[@]}"; do ip netns del "$ns" || true; done
}
trap cleanup EXIT
trap 'exit 130' INT TERM
for ns in "$C" "$G" "$S"; do
    ip netns add "$ns"
    namespaces+=("$ns")
    ip -n "$ns" link set lo up
done
# Join an isolated gateway interface to one remote namespace on a separate /30 link.
link() {
    local dev=$1 net=$2 ns=$3 peer=$4
    ip -n "$G" link add "$dev" type veth peer name "$peer" netns "$ns"
    ip -n "$G" addr add "10.88.$net.1/30" dev "$dev"
    ip -n "$ns" addr add "10.88.$net.2/30" dev "$peer"
    ip -n "$G" link set "$dev" up
    ip -n "$ns" link set "$peer" up
}
link lan0 0 "$C" eth0
link fi1 1 "$S" via-fi1
link fi2 2 "$S" via-fi2
ip -n "$S" addr add 203.0.113.77/32 dev lo
ip -n "$S" addr add 203.0.113.78/32 dev lo
ip -n "$C" route add default via 10.88.0.1
ip -n "$G" route add default via 10.88.1.2 dev fi1
ip -n "$S" route add 10.88.0.0/30 via 10.88.1.1 dev via-fi1
ip netns exec "$G" sysctl -qw net.ipv4.ip_forward=1
for ns in "$G" "$S"; do
    # Expand the sysctl paths only after entering the namespace.
    # shellcheck disable=SC2016
    ip netns exec "$ns" bash -c 'for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > "$f"; done'
done
for i in 1 2; do
    ip -n "$G" route add table "$((100 + i))" default via "10.88.$i.2" dev "fi$i"
    ip -n "$G" rule add oif "fi$i" lookup "$((100 + i))"
done
# Record all routing tables and rules independently of the observer.
route_state() {
    {
        ip -n "$G" -4 rule show
        ip -n "$G" -4 route show table all
    } >"$out/route-$1.txt"
}
# Wait for the requested paired round to finish for all three targets.
rounds() {
    local wanted=$1
    while [[ $(wc -l <"$out/recommendations.jsonl") -lt $((3 * wanted)) ]]; do
        kill -0 "$process" || {
            cat "$out/observer.stderr" >&2
            return 1
        }
        sleep .05
    done
}
# Mark a transition with real elapsed time and the number of prior results.
event() {
    printf '%s %s %s\n' "$1" "$(date +%s.%N)" "$(wc -l <"$out/recommendations.jsonl")" >>"$out/events.txt"
}
# Run labelled TCP and UDP traffic over the ordinary LAN forwarding path.
controls() {
    ip netns exec "$C" python3 -B "$root/fixture.py" control "$1" >>"$out/clients.jsonl"
}
route_state before
ip netns exec "$S" python3 -B "$root/fixture.py" server >"$out/peer.jsonl" &
for _ in {1..100}; do
    grep -qs READY "$out/peer.jsonl" && break
    sleep .05
done
grep -q READY "$out/peer.jsonl"
for dev in fi1 fi2; do
    ip netns exec "$G" tcpdump -Z root --immediate-mode -nUi "$dev" -s0 -w "$out/$dev.pcap" 'port 19091' 2>"$out/$dev.capture.log" &
    caps+=("$!")
    for _ in {1..100}; do
        grep -qs 'listening on' "$out/$dev.capture.log" && break
        sleep .05
    done
    grep -q 'listening on' "$out/$dev.capture.log"
done
cat >"$out/config.json" <<JSON
{"group":"FI","connections":[{"id":"FI1","interface":"fi1"},{"id":"FI2","interface":"fi2"}],"targets":[{"address":"203.0.113.77","port":19091,"protocol":"udp"},{"address":"203.0.113.77","port":19091,"protocol":"tcp"},{"address":"203.0.113.78","port":19091,"protocol":"udp"}],"interval":"$interval","timeout":"$timeout","window":"$window","min_samples":6,"margin_percent":15}
JSON
{
    uname -srm
    sha256sum "$observer" | cut -d' ' -f1
} >"$out/observer-version.txt"
: >"$out/recommendations.jsonl"
event begin
ip netns exec "$G" "$observer" observe -config "$out/config.json" -rounds "$total" >"$out/recommendations.jsonl" 2>"$out/observer.stderr" &
process=$!
rounds "$base"
controls baseline
drop=(-i via-fi1 -p udp -d 203.0.113.77 --dport 19091 -m statistic --mode nth --every "$width" --packet 0 -j DROP)
ip netns exec "$S" iptables -A INPUT "${drop[@]}"
event impaired
rounds "$((base + bad - 2))"
route_state impaired
controls impaired
rounds "$((base + bad))"
ip netns exec "$S" iptables -nvxL INPUT >"$out/drops.txt"
ip netns exec "$S" iptables -D INPUT "${drop[@]}"
event recovered
wait "$process"
event finished
controls recovered
route_state after
cmp "$out/route-before.txt" "$out/route-impaired.txt"
cmp "$out/route-before.txt" "$out/route-after.txt"
kill -INT "${caps[@]}"
for pid in "${caps[@]}"; do wait "$pid"; done
for dev in fi1 fi2; do grep -qx '0 packets dropped by kernel' "$out/$dev.capture.log"; done
python3 -B "$root/verify.py" "$out" | tee "$out/verification.txt"
