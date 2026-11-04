# shellcheck shell=bash
# Shared playfield; source from a lab with ROOT, CONFIG, BIN and OUT set.
C=hf-c-$$
G=hf-g-$$
S=hf-s-$$
namespaces=()
# cleanup terminates namespaced processes and removes the namespaces created by this fixture.
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
# link creates, addresses and enables a veth pair connecting the two specified namespaces.
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
# gw runs its arguments inside the virtual gateway network namespace.
gw() { ip netns exec "$G" "$@"; }
# client runs a probe command in the LAN client namespace so traffic enters through the gateway.
client() { ip netns exec "$C" python3 "$ROOT/probes.py" "$@"; }
gw sysctl -qw net.ipv4.ip_forward=1
n=0
uplinks=(ru0 fi1 fi2)
for iface in "${uplinks[@]}"; do
    n=$((n + 1))
    ip -n "$G" route add table "$((100 + n))" default via "10.88.$n.2" dev "$iface" onlink
    ip -n "$G" rule add oif "$iface" lookup "$((100 + n))"
done
# A live main default via RU makes an escaped connection observable.
ip -n "$G" route add default via 10.88.1.2 dev ru0
for iface in all default lan0 ru0 fi1 fi2; do gw sysctl -qw "net.ipv4.conf.$iface.rp_filter=0"; done
ip -n "$G" link add deny0 type dummy
ip -n "$G" link set deny0 up
ip -n "$G" route add prohibit default table 199
ip -n "$G" rule add oif deny0 lookup 199
{
    uname -srmo
    "$BIN" version
} >"$OUT/version.txt"
gw "$BIN" check -c "$CONFIG"
ip netns exec "$G" "$BIN" run -c "$CONFIG" >"$OUT/sing-box.log" 2>&1 &
engine=$!
ip netns exec "$S" python3 "$ROOT/probes.py" echo-server >"$OUT/server.log" 2>&1 &
ip netns exec "$S" python3 "$ROOT/probes.py" dns-server >"$OUT/dns.log" 2>&1 &
for _ in {1..100}; do
    kill -0 "$engine" || {
        cat "$OUT/sing-box.log"
        exit 1
    }
    if ip -n "$G" link show hestia0 >/dev/null 2>&1 && grep -q READY "$OUT/server.log" && grep -q READY "$OUT/dns.log"; then break; fi
    sleep 0.05
done
grep -q READY "$OUT/dns.log"
grep -q READY "$OUT/server.log"
ip -n "$G" route add 198.18.0.0/15 dev hestia0
ip -n "$G" route add 192.0.2.53/32 dev hestia0
# event records a timestamped event for correlating packet captures with state transitions.
event() { echo "$(date -u --iso-8601=ns) $*" >>"$OUT/events.log"; }
# start_captures starts tcpdump on each uplink, waits for its listener and returns PIDs through the named array.
start_captures() {
    local prefix=$1 iface log
    local -n captures=$2
    for iface in "${uplinks[@]}"; do
        log="$OUT/$prefix-$iface.capture.log"
        ip netns exec "$G" tcpdump --immediate-mode -Z root -nUi "$iface" -s0 -w "$OUT/$prefix-$iface.pcap" 2>"$log" &
        captures+=("$!")
        for _ in {1..100}; do
            grep -qs 'listening on' "$log" && break
            sleep .05
        done
        grep -q 'listening on' "$log" || {
            cat "$log"
            exit 1
        }
    done
}
# stop_captures stops captures from the named PID array and verifies the kernel reported zero drops.
stop_captures() {
    local prefix=$1 iface pid
    local -n capture_pids=$2
    kill -INT "${capture_pids[@]}"
    for pid in "${capture_pids[@]}"; do wait "$pid"; done
    for iface in "${uplinks[@]}"; do grep -qx '0 packets dropped by kernel' "$OUT/$prefix-$iface.capture.log"; done
}
# phase runs the specified client probe phase with an RU capture witness and a separate capture set.
phase() {
    local phase=$1
    # Passed by name to start_captures.
    # shellcheck disable=SC2034
    local -a caps=()
    start_captures "$phase" caps
    event "begin phase=$phase"
    gw python3 -c 'import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(("capture-live-"+sys.argv[1]).encode(),("10.88.1.2",19092))' "$phase"
    client phase "$OUT/state.json" "$phase" >"$OUT/$phase.jsonl"
    event "end phase=$phase"
    stop_captures "$phase" caps
}
# carrier changes the remote peer’s veth link state to simulate physical failure or recovery.
carrier() {
    ip -n "$S" link set "via-$1" "$2"
    event "peer=$1 state=$2"
}
