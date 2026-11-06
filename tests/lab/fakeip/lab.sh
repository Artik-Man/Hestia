#!/usr/bin/env bash
# Run inside a disposable Linux VM as root. No external network or public DNS is used.
set -euo pipefail
umask 077
ROOT=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-$(mktemp -d)}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
[[ -z "$(ls -A "$OUT")" ]] || {
    echo "Use an empty output directory" >&2
    exit 1
}
BIN=${SING_BOX:-$(command -v sing-box)}
[[ $EUID == 0 && -c /dev/net/tun && -x "$BIN" ]]
C=hx-c-$$
G=hx-g-$$
S=hx-s-$$
created=()
# cleanup terminates background processes and removes only the network namespaces created by this run.
cleanup() {
    for ns in "${created[@]}"; do
        local pid
        while IFS= read -r pid; do
            [[ -z $pid ]] || kill "$pid" 2>/dev/null || true
        done < <(ip netns pids "$ns")
    done
    for ns in "${created[@]}"; do ip netns del "$ns" || true; done
}
trap cleanup EXIT
trap 'exit 130' INT TERM
echo "Artifacts: $OUT"
for ns in "$C" "$G" "$S"; do
    ip netns add "$ns"
    created+=("$ns")
    ip -n "$ns" link set lo up
done
# link creates and addresses a veth pair between the two named network namespaces.
link() {
    local left=$1 dev1=$2 addr1=$3 right=$4 dev2=$5 addr2=$6
    ip -n "$left" link add "$dev1" type veth peer name "$dev2" netns "$right"
    ip -n "$left" addr add "$addr1" dev "$dev1"
    ip -n "$right" addr add "$addr2" dev "$dev2"
    ip -n "$left" link set "$dev1" up
    ip -n "$right" link set "$dev2" up
}
link "$C" eth0 10.88.0.2/30 "$G" lan0 10.88.0.1/30
link "$G" ru0 10.88.1.1/30 "$S" via-ru 10.88.1.2/30
link "$G" fi0 10.88.2.1/30 "$S" via-fi 10.88.2.2/30
ip -n "$C" route add default via 10.88.0.1
ip -n "$S" addr add 203.0.113.77/32 dev lo
ip netns exec "$G" sysctl -qw net.ipv4.ip_forward=1
for v in all default ru0 fi0 lan0; do
    ip netns exec "$G" sysctl -qw "net.ipv4.conf.$v.rp_filter=0"
done
for n in 1 2; do
    iface=ru0
    [[ $n == 1 ]] || iface=fi0
    # sing-box binds to the egress device; without this choice, the real IP has no default path.
    ip -n "$G" route add table "$((100 + n))" 203.0.113.77/32 via "10.88.$n.2" dev "$iface" onlink
    ip -n "$G" rule add oif "$iface" lookup "$((100 + n))"
done
"$BIN" version >"$OUT/sing-box.version"
"$BIN" check -c "$ROOT/config.json"
ip netns exec "$G" "$BIN" run -c "$ROOT/config.json" >"$OUT/sing-box.log" 2>&1 &
SB=$!
ip netns exec "$S" python3 "$ROOT/traffic.py" server >"$OUT/server.log" 2>&1 &
for _ in {1..100}; do
    if ! kill -0 "$SB" 2>/dev/null; then
        cat "$OUT/sing-box.log"
        exit 1
    fi
    if ip -n "$G" link show hestia0 >/dev/null 2>&1 && grep -q READY "$OUT/server.log"; then break; fi
    sleep 0.05
done
ip -n "$G" route add 198.18.0.0/15 dev hestia0
ip -n "$G" route add 192.0.2.53/32 dev hestia0
captures=()
for group in ru "fi"; do
    ip netns exec "$G" tcpdump -Z root -i "${group}0" -U -s0 -nn -w "$OUT/$group.pcap" \
        'host 203.0.113.77 and port 19091' 2>"$OUT/$group.capture.log" &
    captures+=("$!")
    for _ in {1..100}; do
        grep -q 'listening on' "$OUT/$group.capture.log" && break
        sleep 0.05
    done
    grep -q 'listening on' "$OUT/$group.capture.log"
done
ip netns exec "$C" python3 "$ROOT/traffic.py" client >"$OUT/client.json"
# Allow libpcap to deliver the last packet batch before closing the captures.
sleep 1
kill -INT "${captures[@]}"
for pid in "${captures[@]}"; do wait "$pid"; done
for group in ru "fi"; do tcpdump -nn -A -r "$OUT/$group.pcap" 'dst host 203.0.113.77 and dst port 19091' >"$OUT/$group.txt"; done
cat "$OUT/client.json"
python3 "$ROOT/traffic.py" verify "$OUT"
