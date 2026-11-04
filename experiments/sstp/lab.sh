#!/usr/bin/env bash
# Run as root in a disposable Debian guest with PPP support.
set -euo pipefail
umask 077
ROOT=$(cd "$(dirname "$0")" && pwd)
OUT=${1:?pass an empty evidence directory}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
[[ $EUID == 0 && -z $(ls -A "$OUT") ]]
source "$ROOT/sessions.sh"
for i in 1 2; do
    start_peer "$i"
    s "$i" python3 -u "$ROOT/probes.py" server "FI$i" "$target" > "$OUT/server-FI$i.jsonl" &
    for _ in {1..80}; do grep -q READY "$OUT/server-FI$i.jsonl" && break; sleep .05; done
    grep -q READY "$OUT/server-FI$i.jsonl"
done
{ uname -srmo; dpkg-query -W sstp-client ppp; accel-pppd --version; } > "$OUT/version.txt"
for i in 1 2; do
    { c "$i" ip -br addr; c "$i" ip route get "$target"; c "$i" ss -tn; s "$i" ip -br addr; } > "$OUT/FI$i-route.txt"
    ip netns exec "hs-c$i-$$" tcpdump --immediate-mode -U -n -Z root -s0 -i "hs$i" -w "$OUT/FI$i.pcap" 'udp port 19091' 2>"$OUT/FI$i-capture.log" &
    caps+=("$!")
    for _ in {1..100}; do grep -q 'listening on' "$OUT/FI$i-capture.log" && break; sleep .05; done
    grep -q 'listening on' "$OUT/FI$i-capture.log"
done
phase() {
    local phase=$1 p1 p2
    c 1 python3 "$ROOT/probes.py" sample "$phase" FI1 "$target" > "$OUT/$phase-FI1.json" & p1=$!
    c 2 python3 "$ROOT/probes.py" sample "$phase" FI2 "$target" > "$OUT/$phase-FI2.json" & p2=$!
    wait "$p1"; wait "$p2"
}
phase baseline
drop=(-i sstp0 -p udp -d "$target" --dport 19091 -j DROP)
s 1 iptables -I INPUT "${drop[@]}"
phase impaired
s 1 iptables -nvxL INPUT > "$OUT/impairment.txt"
s 1 iptables -D INPUT "${drop[@]}"
phase recovery
kill -INT "${caps[@]}"
for pid in "${caps[@]}"; do wait "$pid"; done
for i in 1 2; do grep -qx '0 packets dropped by kernel' "$OUT/FI$i-capture.log"; done
python3 "$ROOT/probes.py" verify "$OUT" "$target" | tee "$OUT/verification.txt"
