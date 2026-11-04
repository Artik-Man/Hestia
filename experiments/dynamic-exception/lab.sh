#!/usr/bin/env bash
# Run as root inside a disposable Linux guest; output directory must be empty.
set -euo pipefail
umask 077
ROOT=$(cd "$(dirname "$0")" && pwd)
OUT=$(realpath -m "${1:?empty output directory}")
mode=${2:-combined}; [[ $mode == manual || $mode == combined ]]
mkdir -p "$OUT"
[[ $EUID == 0 && -z $(ls -A "$OUT") && -c /dev/net/tun ]]
cd "$OUT"
BIN=${SING_BOX:-$(command -v sing-box)}
C=hd-c-$$; G=hd-g-$$; S=hd-s-$$
spaces=(); caps=()
cleanup() {
    local n p
    for n in "${spaces[@]}"; do
        for p in $(ip netns pids "$n"); do kill "$p" 2>/dev/null || true; done
    done
    for n in "${spaces[@]}"; do ip netns del "$n" || true; done
}
trap cleanup EXIT
trap 'exit 130' INT TERM
for n in "$G" "$S" "$C"; do ip netns add "$n"; spaces+=("$n"); ip -n "$n" link set lo up; done
gw() { ip netns exec "$G" "$@"; }
svc() { ip netns exec "$S" "$@"; }
client() { ip netns exec "$C" python3 "$ROOT/fixture.py" "$@"; }
event() { echo "$(date -u --iso-8601=ns) $*" >> "$OUT/events.log"; }
link() {
    local i=$1 dev=$2 right=$3 peer=$4
    ip -n "$G" link add "$dev" type veth peer name "$peer" netns "$right"
    ip -n "$G" addr add "10.88.$i.1/30" dev "$dev"
    ip -n "$right" addr add "10.88.$i.2/30" dev "$peer"
    ip -n "$G" link set "$dev" up; ip -n "$right" link set "$peer" up
}
link 0 lan0 "$C" eth0; link 1 ru0 "$S" via-ru0; link 2 fi1 "$S" via-fi1; link 3 fi2 "$S" via-fi2
ip -n "$C" route add default via 10.88.0.1
uplinks=(ru0 fi1 fi2)
for ix in 0 1 2; do
    iface=${uplinks[$ix]}; net=$((ix+1))
    gw ip route add table "$((101+ix))" default via "10.88.$net.2" dev "$iface"
    gw ip rule add oif "$iface" lookup "$((101+ix))"
done
gw ip route add default via 10.88.1.2 dev ru0
gw sysctl -qw net.ipv4.ip_forward=1
for dev in all default lan0 ru0 fi1 fi2; do gw sysctl -qw "net.ipv4.conf.$dev.rp_filter=0"; done
{ uname -srmo; "$BIN" version; } > version.txt
cp "$ROOT/config.json" .
python3 "$ROOT/fixture.py" apply fi-udp.json empty
cp fi-udp.json initial-rules.json
gw "$BIN" check -c config.json
ip netns exec "$G" "$BIN" run -c config.json > sing-box.log 2>&1 &
engine=$!
for _ in {1..100}; do gw ip link show hestia0 >/dev/null 2>&1 && break; sleep .05; done
gw ip route add 198.18.0.0/15 dev hestia0
gw ip route add 192.0.2.53/32 dev hestia0
gw ip route add table 180 203.0.113.0/24 dev hestia0
gw ip rule add iif lan0 lookup 180
identity() { awk '{print $1,$22}' "/proc/$engine/stat"; }
identity >pid-before.txt
# Generate the DNS fixture after the engine started. X is never used in config.json.
python3 - <<'PY' > records.json
import json,secrets
x="203.0.113."+str(20+secrets.randbelow(100))
print(json.dumps({"x.lab.test":x,"ru.lab.test":x,"y.lab.test":"203.0.113.200"}))
PY
for ip in $(python3 -c 'import json; print(*set(json.load(open("records.json")).values()))'); do svc ip addr add "$ip/32" dev lo; done
ip netns exec "$G" python3 -u "$ROOT/fixture.py" dns "$OUT/records.json" > dns.log 2>&1 &
ip netns exec "$S" python3 -u "$ROOT/fixture.py" server "$OUT/records.json" > server.log 2>&1 &
for log in dns server; do for _ in {1..100}; do grep -qs READY "$log.log" && break; sleep .05; done; grep -q READY "$log.log"; done
for dev in lan0 "${uplinks[@]}"; do
    ip netns exec "$G" tcpdump --immediate-mode -Z root -nUi "$dev" -s0 -w "$dev.pcap" 2>"$dev.capture.log" &
    caps+=("$!")
    for _ in {1..100}; do grep -qs 'listening on' "$dev.capture.log" && break; sleep .05; done
    grep -q 'listening on' "$dev.capture.log"
done
client init "$OUT/records.json" > state.json
ip netns exec "$G" tcpdump --immediate-mode -Z root -nc1 -i fi1 -w discover.pcap 'udp and dst port 19091' 2>discover.log &
observer=$!
for _ in {1..100}; do grep -qs 'listening on' discover.log && break; sleep .05; done
grep -q 'listening on' discover.log
client discover "$OUT/records.json" "$OUT/state.json"
wait "$observer"
x=$(tcpdump -ntqr discover.pcap 2>/dev/null | awk '{print $4}' | sed -E 's/\.19091:.*//')
# tcpdump -t -q output: IP src.port > dst.port: UDP,...
[[ $x == 203.0.113.* ]]
echo "$x" > discovered.txt
event "discovered group=FI proto=UDP dst=$x source=fi1-capture"
phase() {
    cp fi-udp.json "$1-rules.json"
    client phase "$OUT/records.json" "$OUT/state.json" "$1" > "$1.jsonl"
    event "confirmed phase=$1 via client and server"
}
apply() {
    local target=$1 want=fi1
    [[ $target == empty ]] || want=fi2
    python3 "$ROOT/fixture.py" apply fi-udp.json "$target"
    event "rule-file target=$target"
    client await "$OUT/records.json" "$OUT/state.json" "$want" >> barrier.jsonl
    event "rule-confirmed peer=$want"
}
phase baseline
if [[ $mode == manual ]]; then
    apply "$x"; phase added
    apply empty; phase removed
else
    decide() {
        gw python3 "$ROOT/sweep.py" sample "$OUT" "$1" "$2" "$3"
    }
    current=fi1
    actuate() {
        local next=$1
        if [[ $next != "$current" ]]; then
            case "$next" in
                fi2) apply "$x" ;;
                fi1) apply empty ;;
                *) return 1 ;;
            esac
        fi
        current=$next
    }
    actuate "$(decide equal 20 "$current")"
    [[ $current == fi1 ]]
    loss_rule=(-i via-fi1 -p udp -d "$x" --dport 19091 -m statistic --mode nth --every 10 --packet 0 -j DROP)
    svc iptables -I INPUT "${loss_rule[@]}"
    actuate "$(decide loss 120 "$current")"
    [[ $current == fi2 ]]
    phase automatic
    svc iptables -nvxL INPUT > loss-firewall.txt
    svc iptables -D INPUT "${loss_rule[@]}"
    # A repaired FI1 alone doesn't win a tie. Degrade FI2 until measured FI1 is better.
    reverse_rule=(-i via-fi2 -p udp -d "$x" --dport 19091 -m statistic --mode nth --every 2 --packet 0 -j DROP)
    svc iptables -I INPUT "${reverse_rule[@]}"
    actuate "$(decide reverse 100 "$current")"
    [[ $current == fi1 ]]
    phase retired
    svc iptables -nvxL INPUT > reverse-firewall.txt
fi
identity > pid-after.txt
kill -INT "${caps[@]}"
for pid in "${caps[@]}"; do wait "$pid"; done
for dev in lan0 "${uplinks[@]}"; do grep -qx '0 packets dropped by kernel' "$dev.capture.log"; done
python3 "$ROOT/fixture.py" verify "$OUT" | tee verification.txt
if [[ $mode == combined ]]; then python3 "$ROOT/sweep.py" verify "$OUT" | tee -a verification.txt; fi
