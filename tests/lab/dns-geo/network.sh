# shellcheck shell=bash
# Shared isolated namespace topology for DNS/GeoIP experiments.
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
    if [[ $i == 2 ]]; then
        iface=fi0
        ns=$F
    fi
    ip -n "$G" route add table "$((100 + i))" 203.0.113.0/24 via "10.85.$i.2" dev "$iface"
    ip -n "$G" rule add oif "$iface" table "$((100 + i))"
    for last in 11 22 33; do ip -n "$ns" addr add "203.0.113.$last/32" dev lo; done
done
ip -n "$G" route add default via 10.85.1.2 dev ru0
