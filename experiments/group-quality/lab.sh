#!/usr/bin/env bash
# Isolated guest only. Supply an ARM64 binary and a fresh result directory.
set -euo pipefail
umask 077
[[ $# == 2 && $EUID == 0 && -c /dev/net/tun ]]
ctl=$(realpath "$1")
OUT=$(realpath -m "$2")
mkdir -p "$OUT"
[[ -z $(ls -A "$OUT") ]]
LAB=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$LAB/../failover" && pwd)
BIN=$(command -v sing-box)
CONFIG="$OUT/sing-box.json"
python3 "$LAB/check.py" config "$OUT"
# shellcheck source=../failover/fixture.sh
source "$ROOT/fixture.sh"
gw ip route add table 180 203.0.113.0/24 dev hestia0
gw ip rule add iif lan0 lookup 180
for target in 203.0.113.88 203.0.113.99; do
    ip -n "$S" addr add "$target/32" dev lo
done
ip netns exec "$S" python3 -u "$LAB/check.py" echo "$OUT" >"$OUT/echo.jsonl" 2>&1 &
for _ in {1..80}; do
    grep -qs READY "$OUT/echo.jsonl" && break
    sleep .05
done
grep -q READY "$OUT/echo.jsonl"
gw "$ctl" guard -config "$OUT/initial.json" -group "fi" >"$OUT/initial-gate.json"
# The capture arrays are assigned by reference inside the shared fixture.
# shellcheck disable=SC2034
qcaps=()
start_captures quality qcaps
ip netns exec "$G" "$ctl" balance -config "$OUT/measure.json" -confirm-rounds 3 >"$OUT/decisions.jsonl" 2>"$OUT/balance.stderr" &
balance_runner=$!
# barrier waits for the measurement condition particular to a phase and checks group handoff in the data plane.
barrier() {
    local phase=$1 wanted=$2
    python3 "$LAB/check.py" wait "$OUT" "$phase" "$wanted" || {
        cat "$OUT/balance.stderr" >&2
        return 1
    }
    gw curl --noproxy '*' -fsS http://127.0.0.1:9090/proxies/fi >"$OUT/$phase-selector.json"
    python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["now"]==sys.argv[2]' "$OUT/$phase-selector.json" "$wanted"
    ip netns exec "$C" python3 "$LAB/check.py" flows "$OUT" "$phase" "$wanted" >"$OUT/$phase.jsonl"
    event "verified $phase selector=$wanted"
}
# degrade adds or removes selective half-loss to each control destination on the named physical path.
degrade() {
    local action=$1 iface=$2 target
    for target in 203.0.113.88 203.0.113.99; do
        ip netns exec "$S" iptables "$action" INPUT -i "via-$iface" -p udp -d "$target" --dport 19092 -m statistic --mode nth --every 2 --packet 0 -j DROP
    done
}
barrier baseline fi1
degrade -I fi1
event 'partial loss both targets FI1'
barrier switched fi2
ip netns exec "$S" iptables -nvxL INPUT >"$OUT/forward-loss.txt"
degrade -D fi1
event 'both paths recovered'
barrier equal fi2
ip netns exec "$G" tcpdump --immediate-mode -Z root -nUi lo -s0 -w "$OUT/shared-api.pcap" 'tcp dst port 9090' 2>"$OUT/shared-api.capture.log" &
api_capture=$!
for _ in {1..100}; do
    grep -qs 'listening on' "$OUT/shared-api.capture.log" && break
    sleep .05
done
grep -q 'listening on' "$OUT/shared-api.capture.log"
outage=(-p udp -d 203.0.113.88 --dport 19092 -j DROP)
ip netns exec "$S" iptables -I INPUT "${outage[@]}"
event 'one target unreachable through both paths'
barrier shared fi2
kill -INT "$api_capture"
wait "$api_capture"
grep -qx "0 packets dropped by kernel" "$OUT/shared-api.capture.log"
ip netns exec "$S" iptables -nvxL INPUT >"$OUT/shared-outage.txt"
ip netns exec "$S" iptables -D INPUT "${outage[@]}"
degrade -I fi2
event 'partial loss both targets FI2'
barrier restored fi1
ip netns exec "$S" iptables -nvxL INPUT >"$OUT/reverse-loss.txt"
degrade -D fi2
kill -TERM "$balance_runner"
wait "$balance_runner"
stop_captures quality qcaps
sha256sum "$ctl" | cut -d' ' -f1 >"$OUT/controller.sha256"
python3 "$LAB/check.py" verify "$OUT" | tee "$OUT/verification.txt"
